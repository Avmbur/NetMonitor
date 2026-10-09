package agent

import (
	"database/sql"
	"encoding/json"
	"errors"
	"log"

	"sync"
	"time"

	"netmonitor/internal/collect"
	"netmonitor/internal/idgen"
	"netmonitor/internal/outbox"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

func laneFor(pri int) string {
	if pri >= 5 {
		return "urgent"
	}
	return "history"
}

// planMemLimit — потолок очереди памяти при известном сеансе. Монитор долго
// недоступен: старое выбрасывается, новое остаётся, ОЗУ не растёт.
const planMemLimit = 32 << 20

type planItem struct {
	id, kind, lane, payload string
	seq, created            int64
	pri                     int
}

type planQueue struct {
	mu    sync.Mutex
	items []planItem
	bytes int64
}

func (q *planQueue) add(it planItem) {
	q.mu.Lock()
	q.items = append(q.items, it)
	q.bytes += int64(len(it.payload)) + 256
	q.mu.Unlock()
}

func (q *planQueue) drop(ids []string) {
	if q == nil || len(ids) == 0 {
		return
	}
	gone := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		gone[id] = struct{}{}
	}
	q.mu.Lock()
	kept := make([]planItem, 0, len(q.items))
	for _, it := range q.items {
		if _, ok := gone[it.id]; !ok {
			kept = append(kept, it)
		} else {
			q.bytes -= int64(len(it.payload)) + 256
		}
	}
	q.items = kept
	q.mu.Unlock()
}

// trim снимает самое старое, пока очередь выше limit. Срезает до трёх четвертей,
// чтобы на пределе не копировать очередь на каждое событие.
func (q *planQueue) trim(limit int64) int {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.bytes <= limit {
		return 0
	}
	target := limit / 4 * 3
	n := 0
	for n < len(q.items) && q.bytes > target {
		q.bytes -= int64(len(q.items[n].payload)) + 256
		n++
	}
	q.items = append([]planItem(nil), q.items[n:]...)
	return n
}

func (q *planQueue) size() int64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.bytes
}

func (q *planQueue) copy() []planItem {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]planItem(nil), q.items...)
}

func (a *Agent) prepareSpool() *collect.Mem {
	a.spoolOnce.Do(func() {
		a.telemetrySince = store.NowMS()
		a.instance = idgen.NewV7()
		a.book = collect.NewMem()
		a.plan = &planQueue{}
		a.stop = make(chan struct{})
	})
	return a.book
}

func (a *Agent) halt() <-chan struct{} {
	a.prepareSpool()
	return a.stop
}

// Stop requests Run to return; Close waits for current queue publication.
func (a *Agent) Stop() {
	a.prepareSpool()
	a.stopOnce.Do(func() { close(a.stop) })
}

var errSpoolClosed = errors.New("agent spool is closed")

// collectMem keeps checkpoints, sequence allocation and queue publication atomic
// with respect to flush, delivery, acknowledgements and shutdown.
func (a *Agent) collectMem(apply func(*collect.Mem) error) error {
	book := a.prepareSpool()
	a.spoolMu.Lock()
	defer a.spoolMu.Unlock()
	if a.spoolClosed {
		return errSpoolClosed
	}
	book.Begin()
	if err := apply(book); err != nil {
		book.Rollback()
		return err
	}
	if err := a.acceptMemLocked(book.Take()); err != nil {
		book.Rollback()
		return err
	}
	book.Commit()
	return nil
}

func (a *Agent) acceptMem(ev []collect.MemEvent) error {
	a.prepareSpool()
	a.spoolMu.Lock()
	defer a.spoolMu.Unlock()
	if a.spoolClosed {
		return errSpoolClosed
	}
	return a.acceptMemLocked(ev)
}

func (a *Agent) acceptMemLocked(ev []collect.MemEvent) error {
	if len(ev) == 0 {
		return nil
	}
	a.prepareSpool()

	var disk []collect.MemEvent
	var memory []planItem
	next := a.memSeq
	for _, e := range ev {
		if !sessionKind(e.Kind) {
			disk = append(disk, e)
			continue
		}
		raw, err := json.Marshal(e.Payload)
		if err != nil {
			return err
		}
		lane := laneFor(e.Pri)
		if hp, ok := e.Payload.(protocol.HealthPayload); ok && e.Kind == "health" && hp.Kind == "alive" {
			lane = "heartbeat"
		}
		next++
		memory = append(memory, planItem{id: idgen.NewV7(), kind: e.Kind, lane: lane, payload: string(raw), seq: next, pri: e.Pri, created: e.Now})
	}
	if len(disk) > 0 {
		if err := a.st.Update(func(tx *sql.Tx) error {
			for _, e := range disk {
				if err := outbox.InsertUntrimmed(tx, e.Kind, e.Pri, e.Payload, e.Now); err != nil {
					return err
				}
			}
			return outbox.Trim(tx, store.NowMS())
		}); err != nil {
			return err
		}
		a.markDiskIdle(sessionDiskLane, false)
	}
	a.memSeq = next
	for _, it := range memory {
		a.plan.add(it)
	}
	if n := a.plan.trim(planMemLimit); n > 0 {
		// Lost closures require a new stream and fresh snapshot, not a partial replay.
		a.instance = idgen.NewV7()
		a.plan = &planQueue{}
		a.needDump = true
		log.Printf("telemetry overflow: discarded %d old events; requesting fresh stream", n)
	}
	return nil
}

func (a *Agent) planRowsLocked(lane string) []outboxRow {
	var rows []outboxRow
	for _, it := range a.plan.copy() {
		if lane != "" && it.lane != lane {
			continue
		}
		rows = append(rows, outboxRow{id: it.id, kind: it.kind, payload: it.payload, seq: it.seq, observed: it.created, pri: it.pri})
		if len(rows) == 200 {
			break
		}
	}
	return rows
}

func (a *Agent) planCoversLocked(ids []string) bool {
	if a.plan == nil {
		return false
	}
	have := map[string]struct{}{}
	for _, it := range a.plan.copy() {
		have[it.id] = struct{}{}
	}
	for _, id := range ids {
		if _, ok := have[id]; !ok {
			return false
		}
	}
	return true
}

func sessionKind(kind string) bool {
	switch kind {
	case "flow", "sample", "firewall", "dns", "health", "ssh", "scan":
		return true
	default:
		return false
	}
}

// sessionDiskLane — полоса, которая при известном сеансе забирает служебное с диска.
// Остальные полосы базу не открывают: там только память.
const sessionDiskLane = "urgent"

// sessionDiskRows — служебные строки базы (вопросы и прочее), без деления по возрасту:
// вопрос, не доставленный за 30 секунд, не должен застрять между полосами.
func sessionDiskRows(tx *sql.Tx, limit int) ([]outboxRow, error) {
	rows, err := serviceOutbox(tx, limit)
	if err != nil {
		return nil, err
	}
	var sent []string
	for _, r := range rows {
		if r.kind == "question" {
			sent = append(sent, r.id)
		}
	}
	return rows, outbox.MarkQuestionsSent(tx, sent)
}

// adoptSession выбрасывает телеметрию, когда монитор начал новый сеанс.
// Вопросы и политика в базе остаются.
func (a *Agent) adoptSession(id string) {
	if id == "" {
		return
	}
	a.prepareSpool()
	a.spoolMu.Lock()
	if id == a.session {
		a.spoolMu.Unlock()
		return
	}
	a.session = id
	a.plan = &planQueue{}
	// Номер от часов, не от нуля: новый процесс агента в том же сеансе монитора
	// идёт выше прежнего, и его закрытия и пробы не считаются запоздавшими.
	a.memSeq = time.Now().UnixMicro()
	a.needDump = true
	a.diskIdle = nil
	a.spoolMu.Unlock()

}

func (a *Agent) takeDump() bool {
	a.spoolMu.Lock()
	defer a.spoolMu.Unlock()
	if !a.needDump {
		return false
	}
	a.needDump = false
	return true
}

// updateQueue includes urgent rows and their cursors in the combined queue limit.
func (a *Agent) updateQueue(fn func(*sql.Tx) error) error {
	a.prepareSpool()
	a.spoolMu.Lock()
	defer a.spoolMu.Unlock()
	if a.spoolClosed {
		return errSpoolClosed
	}
	return a.st.Update(func(tx *sql.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return outbox.Trim(tx, store.NowMS())
	})
}

func (a *Agent) queueCapacity(free uint64) error {
	return a.updateQueue(func(tx *sql.Tx) error {
		return outbox.SetCapacity(tx, free)
	})
}

func (a *Agent) queueBytes() (int64, error) {
	a.prepareSpool()
	a.spoolMu.Lock()
	defer a.spoolMu.Unlock()
	var disk int64
	err := a.st.DB.QueryRow("SELECT COALESCE((SELECT CAST(v AS INTEGER) FROM meta WHERE k='queue_bytes'),0)").Scan(&disk)
	return disk + a.plan.size(), err
}

// recoverSpool доверяет checkpoints только после штатной остановки или сброса,
// догнавшего нумерацию. Иначе старый курсор сотрётся и байты не посчитаются второй раз.
// Первое открытие без spool_seq тоже недоверенное: прежние курсоры версии без спула сбрасываются один раз.
// Old agent databases may contain discarded telemetry and collector snapshots.
func (a *Agent) recoverSpool() error {
	a.prepareSpool()
	return a.st.Update(func(tx *sql.Tx) error {
		if _, err := tx.Exec("DELETE FROM checkpoints"); err != nil {
			return err
		}
		if _, err := tx.Exec("DELETE FROM meta WHERE k IN ('spool_seq','spool_clean')"); err != nil {
			return err
		}
		_, err := tx.Exec("DELETE FROM outbox WHERE kind IN ('flow','sample','firewall','dns','health','ssh','scan')")
		return err
	})
}

func serviceOutbox(tx *sql.Tx, limit int) ([]outboxRow, error) {
	rows, err := tx.Query("SELECT event_id,seq,kind,payload,created_at_ms,priority FROM outbox ORDER BY priority DESC,seq LIMIT ?", limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []outboxRow
	for rows.Next() {
		var r outboxRow
		if err := rows.Scan(&r.id, &r.seq, &r.kind, &r.payload, &r.observed, &r.pri); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
