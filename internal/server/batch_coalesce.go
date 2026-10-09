package server

import (
	"context"
	"database/sql"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"netmonitor/internal/ingest"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

// errMonitorStopping — приём уже не берёт новые пачки: остановка ждёт публикацию.
var errMonitorStopping = errors.New("монитор останавливается")

// Обычная телеметрия (история и пульс) ждёт до секунды и садится в один коммит.
// Срочная лента и пакет без ленты писателя не ждут: подтверждение и так уходит
// только после коммита, а управление монитора в эту очередь не входит.
const (
	telemetryBatchWait = time.Second
	telemetryBatchMax  = 32
	// Пачка с таким числом событий и так крупная — это догон очереди агента.
	// Ждать соседей ей незачем: секунда на запрос растянула бы догон.
	telemetryBatchFull = 100
)

type batchJob struct {
	ag         ingest.Agent
	batch      protocol.Batch
	now        int64
	src        string
	ctx        context.Context
	queuedAt   time.Time
	immediate  bool
	res        ingest.Result
	err        error
	staged     []stagedEvent
	done       chan struct{}
	tracked    bool
	serviceSeq int64
	applied    []protocol.Event
}

type batchGate struct {
	s        *Server
	mu       sync.Mutex
	q        []*batchJob
	leader   bool
	stopping bool
	wake     chan struct{}
	inflight sync.WaitGroup
	commits  atomic.Int64
}

func batchImmediate(b protocol.Batch) bool {
	if len(b.Events) >= telemetryBatchFull {
		return true
	}
	switch b.Lane {
	case "history", "heartbeat":
		return false
	default:
		return true
	}
}

func (s *Server) batchGate() *batchGate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.gate == nil {
		s.gate = &batchGate{s: s, wake: make(chan struct{}, 1)}
	}
	return s.gate
}

func (s *Server) enqueueBatch(job *batchJob) {
	g := s.batchGate()
	g.mu.Lock()
	if g.stopping {
		g.mu.Unlock()
		job.err = errMonitorStopping
		close(job.done)
		return
	}
	g.inflight.Add(1)
	job.tracked = true
	job.queuedAt = time.Now()
	g.q = append(g.q, job)
	start := !g.leader
	if start {
		g.leader = true
	}
	wake := !start && (job.immediate || len(g.q) >= telemetryBatchMax)
	g.mu.Unlock()
	if wake {
		select {
		case g.wake <- struct{}{}:
		default:
		}
	}
	if start {
		go g.loop()
	}
}

func (g *batchGate) loop() {
	for {
		g.mu.Lock()
		if len(g.q) == 0 {
			g.leader = false
			g.mu.Unlock()
			return
		}
		wait := g.s.batchWait
		if wait < 0 {
			wait = 0
		}
		immediate := false
		for _, j := range g.q {
			if j.immediate {
				immediate = true
				break
			}
		}
		now := time.Now()
		// Time spent behind the previous commit already counts as waiting.
		deadline := g.q[0].queuedAt.Add(wait)
		ready := g.stopping || immediate || wait == 0 || len(g.q) >= telemetryBatchMax || !now.Before(deadline)
		if !ready {
			remaining := time.Until(deadline)
			g.mu.Unlock()
			timer := time.NewTimer(remaining)
			select {
			case <-timer.C:
			case <-g.wake:
			}
			timer.Stop()
			continue
		}
		jobs := g.takeLocked()
		g.mu.Unlock()
		g.commit(jobs)
	}
}

func (g *batchGate) takeLocked() []*batchJob {
	jobs := make([]*batchJob, 0, len(g.q))
	for _, j := range g.q {
		if j.ctx != nil && j.ctx.Err() != nil {
			j.err = j.ctx.Err()
			close(j.done)
			if j.tracked {
				j.tracked = false
				g.inflight.Done()
			}
			continue
		}
		jobs = append(jobs, j)
	}
	g.q = nil
	return jobs
}

func (g *batchGate) commit(jobs []*batchJob) {
	if len(jobs) == 0 {
		return
	}
	// Shutdown waits for memory publication as well as the database commit.
	// Прямой commit из теста в очередь остановки не входит.
	defer func() {
		for _, j := range jobs {
			if j != nil && j.tracked {
				j.tracked = false
				g.inflight.Done()
			}
		}
	}()
	// A deletion cannot clear the spool between this commit and its publication.
	// No extra database reads or persistent deleted-agent list are needed.
	g.s.agentStateMu.RLock()
	defer g.s.agentStateMu.RUnlock()
	g.commits.Add(1)
	// Окно SSH читается до транзакции: снимок не видит ещё не записанные
	// строки и не держит книгу, пока писатель занят.
	_ = g.s.ensureSSH()
	// Каждая пачка под своей точкой сохранения: битая пачка одного агента
	// (отозван, ошибка разбора) откатывается одна и не топит соседей.
	progress := map[string]int64{}
	err := g.s.st.Update(func(tx *sql.Tx) error {
		for _, j := range jobs {
			if _, err := tx.Exec("SAVEPOINT agent_batch"); err != nil {
				return err
			}
			key := j.ag.ID + "\n" + j.batch.Lane
			{
				j.serviceSeq = progress[key]
				if stream := g.s.streams[j.ag.ID]; stream != nil {
					j.serviceSeq = max(j.serviceSeq, stream.lanes[j.batch.Lane])
				}
			}
			mark := store.HookMark(tx)
			j.res, j.err = g.s.applyAgentBatch(tx, j)
			if j.err == nil {
				progress[key] = j.serviceSeq
			}
			if j.err != nil {
				j.res = ingest.Result{}
				j.staged = nil
				g.s.ssh.drop(j)
				store.RollbackHooks(tx, mark)
				if _, err := tx.Exec("ROLLBACK TO agent_batch"); err != nil {
					return err
				}
			}
			if _, err := tx.Exec("RELEASE agent_batch"); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		for _, j := range jobs {
			g.s.ssh.drop(j)
			j.res = ingest.Result{}
			j.staged = nil
			if j.err == nil {
				j.err = err
			}
		}
	} else {
		for _, j := range jobs {
			if j.err != nil {
				g.s.ssh.drop(j)
				continue
			}
			g.s.ssh.keep(j)
			{
				if stream := g.s.streams[j.ag.ID]; stream != nil {
					stream.lanes[j.batch.Lane] = max(stream.lanes[j.batch.Lane], j.serviceSeq)
				}
				g.s.publishPulse(j)
			}
		}
		// Publish live connections and the DROP feed only after successful commit.
		g.s.noteImmediateFirewall(jobs)
		g.s.liveAfterCommit(jobs)
	}
	for _, j := range jobs {
		close(j.done)
	}
}

// quiesce дожидается публикации уже принятых пачек и новые не берёт.
// flushMu здесь не держится: публикация сама его занимает.
func (g *batchGate) quiesce() {
	g.mu.Lock()
	g.stopping = true
	g.mu.Unlock()
	select {
	case g.wake <- struct{}{}:
	default:
	}
	g.inflight.Wait()
}
