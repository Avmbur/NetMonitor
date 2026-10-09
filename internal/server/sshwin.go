package server

import (
	"database/sql"
	"encoding/json"

	"sync"

	"netmonitor/internal/ingest"
	"netmonitor/internal/netipx"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
)

// sshWindowMS — скользящее окно автобана. Граница строгая, как прежний
// SQL `observed_at_ms > now-10мин`: попытка ровно на отметке уже снаружи.
const sshWindowMS int64 = 10 * 60 * 1000

// Bound recent attempt memory; durable evidence is stored separately in ssh_brute.
const sshRetainMS int64 = 86400000

// sshHit — одна принятая неудача. id события не даёт посчитать её дважды.
type sshHit struct {
	id   string
	host string
	ip   string
	at   int64
}

// sshBook publishes only committed attempts; pending batches participate in detection.
type sshBook struct {
	mu         sync.Mutex
	hits       map[string]sshHit
	saved      map[string]bool
	written    map[string]int64
	writing    map[*sql.Tx]map[string]int64
	pend       map[*batchJob][]sshHit
	ready      bool
	incomplete string
}

func (s *Server) ensureSSH() error {
	s.ssh.mu.Lock()
	defer s.ssh.mu.Unlock()
	if s.ssh.ready {
		return nil
	}
	{
		s.ssh.hits = map[string]sshHit{}
		s.ssh.ready = true
		return nil
	}

}

// noteSSH запоминает попытку до решения об автобане. Исключение политики
// бан не ставит, но из окна строку не выбрасывает: прежний COUNT по
// ssh_failures её тоже видел. Время — то же, что пишет insertSSH.
func (s *Server) noteSSH(job *batchJob, ag ingest.Agent, ev protocol.Event) error {
	if err := s.ensureSSH(); err != nil {
		return err
	}
	var p protocol.SSHPayload
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return err
	}
	addr, err := netipx.Parse(p.RemoteIP)
	if err != nil {
		return err
	}
	at := ev.ObservedAtMS
	if p.ObservedAtMS > 0 {
		at = p.ObservedAtMS
	}
	s.ssh.add(job, sshHit{id: ev.EventID, host: ag.HostID, ip: netipx.Canonical(addr), at: at})
	return nil
}

func (b *sshBook) add(job *batchJob, h sshHit) {
	if h.id == "" || job == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.hits[h.id]; ok {
		return
	}
	for _, list := range b.pend {
		for _, old := range list {
			if old.id == h.id {
				return
			}
		}
	}
	if b.pend == nil {
		b.pend = map[*batchJob][]sshHit{}
	}
	b.pend[job] = append(b.pend[job], h)
}

func (b *sshBook) count(host, ip string, now int64) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	cut := now - sshWindowMS
	n := 0
	see := func(h sshHit) {
		if h.host == host && h.ip == ip && h.at > cut {
			n++
		}
	}
	for _, h := range b.hits {
		see(h)
	}
	for _, list := range b.pend {
		for _, h := range list {
			see(h)
		}
	}
	return n
}

// keep переносит попытки пачки в окно после успешного коммита.
// drop снимает их, если транзакция или точка сохранения откатились.
func (b *sshBook) keep(job *batchJob) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.pend[job]) == 0 {
		delete(b.pend, job)
		return
	}
	if b.hits == nil {
		b.hits = map[string]sshHit{}
	}
	for _, h := range b.pend[job] {
		b.hits[h.id] = h
	}
	delete(b.pend, job)
	now := store.NowMS()
	if now <= sshRetainMS {
		return
	}
	for key, at := range b.written {
		if at < now-60000 {
			delete(b.written, key)
		}
	}
	cut := now - sshRetainMS
	for id, h := range b.hits {
		if h.at < cut {
			delete(b.hits, id)
			delete(b.saved, id)
		}
	}
}

func (b *sshBook) drop(job *batchJob) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.pend, job)
}

func (b *sshBook) committed() []sshHit {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]sshHit, 0, len(b.hits))
	for _, h := range b.hits {
		out = append(out, h)
	}
	return out
}

func (s *Server) moveSSHHost(from, to string) {
	if from == "" || to == "" || from == to {
		return
	}
	s.ssh.mu.Lock()
	defer s.ssh.mu.Unlock()
	for id, h := range s.ssh.hits {
		if h.host == from {
			h.host = to
			s.ssh.hits[id] = h
		}
	}
	for job, list := range s.ssh.pend {
		for i := range list {
			if list[i].host == from {
				list[i].host = to
			}
		}
		s.ssh.pend[job] = list
	}
}

// repSSH combines the current ten-minute window and remembered brute-force addresses.
func (s *Server) repSSH(from, to int64, host string) ([][]string, error) {
	if err := s.ensureSSH(); err != nil {
		return nil, err
	}
	{
		return s.repSSHMemory(from, to, host)
	}

}

func (s *Server) sshHostNames() (map[string]string, error) {
	rows, err := s.st.DB.Query(`SELECT host_id, COALESCE(hostname, host_id) FROM hosts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		names[id] = name
	}
	return names, rows.Err()
}
