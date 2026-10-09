package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/svcnet"
)

// admitWait — сколько ждать, пока агент этой машины впишет адрес. Тесты подменяют.
var admitWait = 4 * time.Second

// svcAdmitted — вписанные агентом адреса по серверам, со сроком. Оценка
// монитора видит их так же, как фильтр агента: без них соединение службы
// горит в активности и держит вопрос. После перезапуска монитора пусто
// до следующего допуска.
var svcAdmitted = struct {
	sync.Mutex
	until map[string]map[netip.Addr]int64
}{until: map[string]map[netip.Addr]int64{}}

func noteAdmitted(host string, ips []netip.Addr, ttl time.Duration) {
	until := store.NowMS() + ttl.Milliseconds()
	svcAdmitted.Lock()
	defer svcAdmitted.Unlock()
	m := svcAdmitted.until[host]
	if m == nil {
		m = map[netip.Addr]int64{}
		svcAdmitted.until[host] = m
	}
	for _, ip := range ips {
		m[ip.Unmap()] = until
	}
}

// Accept observations only for the authenticated agent's own trusted host.
// Merge, rather than clear: nft admissions survive an agent process restart.
func (s *Server) recordAdmitted(agentID string, entries []protocol.ServiceAdmission) error {
	if len(entries) == 0 {
		return nil
	}
	var host, trust string
	if err := s.st.DB.QueryRow(`SELECT host_id,trust_state FROM agents WHERE agent_id=?`, agentID).Scan(&host, &trust); err != nil {
		return err
	}
	if trust != "trusted" {
		return nil
	}
	now := store.NowMS()
	valid := make(map[netip.Addr]int64)
	for _, entry := range entries {
		ip, err := netip.ParseAddr(entry.IP)
		if err != nil || ip.Zone() != "" || entry.UntilMS > now+2*svcnet.AdmitTTL.Milliseconds() {
			return fmt.Errorf("invalid service admission")
		}
		if entry.UntilMS > now {
			valid[ip.Unmap()] = entry.UntilMS
		}
	}
	svcAdmitted.Lock()
	defer svcAdmitted.Unlock()
	m := svcAdmitted.until[host]
	if m == nil {
		m = map[netip.Addr]int64{}
		svcAdmitted.until[host] = m
	}
	for ip, until := range valid {
		m[ip] = until
	}
	return nil
}

func admittedFor(host string, now int64) []netip.Addr {
	svcAdmitted.Lock()
	defer svcAdmitted.Unlock()
	var out []netip.Addr
	for ip, until := range svcAdmitted.until[host] {
		if until <= now {
			delete(svcAdmitted.until[host], ip)
			continue
		}
		out = append(out, ip)
	}
	return out
}

// admitOnMonitor просит агента этой машины вписать адреса GitHub в фильтр до
// соединения nmserver: сам nmserver работает без root и nft не трогает.
// Команда идёт обычным опросом; соединение — только после подтверждения.
func (s *Server) admitOnMonitor(ctx context.Context, ips []netip.Addr) error {
	ag, ok, err := s.findMonitorAgent()
	if err != nil {
		return err
	}
	if !ok || ag.Trust != "trusted" {
		// Нет доверенного агента — политику парка здесь никто не исполняет.
		return nil
	}
	payload, err := svcnet.Payload(ips)
	if err != nil {
		return err
	}
	id := idgen.NewV7()
	now := store.NowMS()
	err = s.st.Update(func(tx *sql.Tx) error {
		// Старые просьбы не копятся. Выданную и не подтверждённую не трогаем:
		// агент ещё пришлёт по ней ответ.
		if _, err := tx.Exec(`DELETE FROM commands WHERE agent_id=? AND kind=? AND created_at_ms<? AND (acked_at_ms IS NOT NULL OR delivered_at_ms IS NULL)`,
			ag.AgentID, svcnet.AdmitKind, now-time.Minute.Milliseconds()); err != nil {
			return err
		}
		_, err := tx.Exec(`INSERT INTO commands(command_id,agent_id,kind,payload,created_at_ms) VALUES(?,?,?,?,?)`, id, ag.AgentID, svcnet.AdmitKind, payload, now)
		return err
	})
	if err != nil {
		return err
	}
	deadline := time.NewTimer(admitWait)
	defer deadline.Stop()
	tick := time.NewTicker(50 * time.Millisecond)
	defer tick.Stop()
	for {
		var acked sql.NullInt64
		if err := s.st.DB.QueryRow(`SELECT acked_at_ms FROM commands WHERE command_id=?`, id).Scan(&acked); err != nil {
			return err
		}
		if acked.Valid {
			noteAdmitted(ag.HostID, ips, svcnet.AdmitTTL)
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("агент монитора не вписал адрес за %s", admitWait)
		case <-tick.C:
		}
	}
}
