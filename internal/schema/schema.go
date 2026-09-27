package schema

import (
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"strings"
)

//go:embed monitor.sql
var MonitorSQL string

//go:embed agent.sql
var AgentSQL string

const version = 9
const agentVersion = 6
const monitorID = 0x4e4d4f4e // NMON
const agentID = 0x4e4d4147   // NMAG

func ApplyMonitor(db *sql.DB) error { return apply(db, MonitorSQL, monitorID, "hosts", "meta") }
func ApplyAgent(db *sql.DB) error   { return apply(db, AgentSQL, agentID, "meta", "hosts") }

func apply(db *sql.DB, script string, appID int, required, forbidden string) error {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	for _, pragma := range []string{"busy_timeout=5000", "synchronous=FULL", "foreign_keys=ON"} {
		if _, err := conn.ExecContext(ctx, "PRAGMA "+pragma); err != nil {
			return fmt.Errorf("%s: %w", pragma, err)
		}
	}
	var journal string
	if err := conn.QueryRowContext(ctx, `PRAGMA journal_mode=WAL`).Scan(&journal); err != nil {
		return err
	}
	if journal != "wal" {
		return fmt.Errorf("expected WAL, got %s", journal)
	}
	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var ver int
	if err := tx.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil {
		return err
	}
	supported := version
	if appID == agentID {
		supported = agentVersion
	}
	if ver > supported {
		return fmt.Errorf("database version %d is newer than supported %d", ver, supported)
	}
	var actualID, wrong, present int
	if err := tx.QueryRow(`PRAGMA application_id`).Scan(&actualID); err != nil {
		return err
	}
	if actualID != 0 && actualID != appID {
		return fmt.Errorf("wrong database application_id: %d", actualID)
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, forbidden).Scan(&wrong); err != nil {
		return err
	}
	if wrong != 0 {
		return fmt.Errorf("wrong database: unexpected table %s", forbidden)
	}
	if ver != 0 {
		if err := tx.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, required).Scan(&present); err != nil {
			return err
		}
		if present != 1 {
			return fmt.Errorf("database missing %s", required)
		}
	}
	if ver == 0 {
		// IF NOT EXISTS also recovers the old, nontransactional initial schema
		// if it was interrupted before setting user_version.
		for _, stmt := range splitSQL(script) {
			if strings.HasPrefix(stmt, "PRAGMA ") {
				continue
			}
			for _, kind := range []string{"TABLE", "UNIQUE INDEX", "INDEX", "VIEW", "TRIGGER"} {
				stmt = strings.Replace(stmt, "CREATE "+kind+" ", "CREATE "+kind+" IF NOT EXISTS ", 1)
			}
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("initial schema: %w", err)
			}
		}
	}
	if ver < 2 && appID == monitorID {
		_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS block_pause(
			agent_id TEXT NOT NULL,
			block_id TEXT NOT NULL,
			paused_at_ms INTEGER NOT NULL,
			PRIMARY KEY(agent_id, block_id))`)
		if err != nil {
			return err
		}
	}
	// v6: лента тревог — «видел», кто и как закрыл.
	if ver != 0 && ver < 6 && appID == monitorID {
		for _, stmt := range []string{
			`ALTER TABLE alerts ADD COLUMN seen_at_ms INTEGER`,
			`ALTER TABLE alerts ADD COLUMN closed_by TEXT`,
			`ALTER TABLE alerts ADD COLUMN close_note TEXT`,
			`CREATE INDEX IF NOT EXISTS alerts_opened ON alerts(opened_at_ms)`,
		} {
			if _, err := tx.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("v6: %w", err)
			}
		}
		// Закрытое до ленты уже разобрано: считаем увиденным.
		if _, err := tx.Exec(`UPDATE alerts SET seen_at_ms=closed_at_ms WHERE closed_at_ms IS NOT NULL AND seen_at_ms IS NULL`); err != nil {
			return err
		}
	}
	if ver < 8 && appID == monitorID {
		if _, err := tx.Exec("ALTER TABLE agents ADD COLUMN pending_from INTEGER NOT NULL DEFAULT 1"); err != nil {
			return fmt.Errorf("v8: %w", err)
		}
		// Version 7's monthly-archive bookkeeping is no longer used.
		if ver == 7 {
			if _, err := tx.Exec("ALTER TABLE traffic_1m DROP COLUMN archive_generation"); err != nil {
				return fmt.Errorf("v8: %w", err)
			}
		}
	}
	if ver < 9 && appID == monitorID {
		for _, stmt := range []string{
			`CREATE INDEX IF NOT EXISTS fw_rotation ON firewall_events(observed_at_ms)`,
			`CREATE INDEX IF NOT EXISTS flows_rotation ON flows(last_seen_at_ms) WHERE ended_at_ms IS NOT NULL`,
			`CREATE INDEX IF NOT EXISTS health_rotation ON collector_health(observed_at_ms) WHERE kind!='alive'`,
			`CREATE INDEX IF NOT EXISTS learn_rotation ON learn_questions(last_seen_ms) WHERE status!='open'`,
			`CREATE INDEX IF NOT EXISTS minute_rotation ON traffic_1m(bucket_start_ms)`,
			`CREATE INDEX IF NOT EXISTS hour_rotation ON traffic_1h(bucket_start_ms)`,
			`CREATE INDEX IF NOT EXISTS ssh_rotation ON ssh_failures(observed_at_ms)`,
		} {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("v9: %w", err)
			}
		}
	}
	// Collector and policy schema changes use a fresh test database; do not silently upgrade incompatible data.
	probe := "SELECT f.state_seq,f.zone,f.ns,r.payload,b.local_port,b.hosts_json,b.except_json,b.updated_at_ms,b.version,c.block_version,c.delivered_rev FROM flows f,policy_rules r,blocks b,commands c LIMIT 0"
	if appID == agentID {
		probe = "SELECT lane FROM outbox LIMIT 0"
	}
	if rows, err := tx.Query(probe); err != nil {
		return fmt.Errorf("collector/policy schema requires a fresh test database: %w", err)
	} else {
		rows.Close()
	}
	// Legacy agent v2 databases may contain an unused block_pause table.
	// Preserve it; new agent databases never receive monitor migrations.
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA application_id=%d", appID)); err != nil {
		return err
	}
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version=%d", supported)); err != nil {
		return err
	}
	return tx.Commit()
}

func splitSQL(script string) []string {
	var lines []string
	for _, line := range strings.Split(script, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(line), "--") {
			lines = append(lines, line)
		}
	}
	var out []string
	var trigger string
	for _, p := range strings.Split(strings.Join(lines, "\n"), ";") {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		if trigger != "" {
			trigger += ";" + s
			if strings.HasSuffix(s, "END") {
				out = append(out, trigger)
				trigger = ""
			}
			continue
		}
		if strings.HasPrefix(s, "CREATE TRIGGER ") && !strings.HasSuffix(s, "END") {
			trigger = s
			continue
		}
		out = append(out, s)
	}
	if trigger != "" {
		out = append(out, trigger)
	}
	return out
}
