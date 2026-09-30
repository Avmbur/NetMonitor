package server

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/store"
	"netmonitor/internal/svcnet"
)

// admitWait — сколько ждать, пока агент этой машины впишет адрес. Тесты подменяют.
var admitWait = 4 * time.Second

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
