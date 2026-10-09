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

const version = 16
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
	if ver != 0 && ver < 10 && appID == monitorID {
		for _, stmt := range []string{
			`ALTER TABLE flows ADD COLUMN container TEXT`,
			`ALTER TABLE learn_questions ADD COLUMN container TEXT`,
		} {
			if _, err := tx.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("v10: %w", err)
			}
		}
	}
	// v11: живой список и счётчик читают только открытые потоки.
	// flows_open — весь парк, flows_open_host — один сервер. Закрытая история в них не входит.
	if ver < 11 && appID == monitorID {
		for _, stmt := range []string{
			`CREATE INDEX IF NOT EXISTS flows_open ON flows(last_seen_at_ms, flow_uid) WHERE ended_at_ms IS NULL`,
			`CREATE INDEX IF NOT EXISTS flows_open_host ON flows(host_id, last_seen_at_ms, flow_uid) WHERE ended_at_ms IS NULL`,
		} {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("v11: %w", err)
			}
		}
	}
	// v12: доказательства скана лежат в самом бане. Старые строки без них по-прежнему читают firewall_events.
	if ver != 0 && ver < 12 && appID == monitorID {
		for _, stmt := range []string{
			`ALTER TABLE blocks ADD COLUMN scan_ports TEXT`,
			`ALTER TABLE blocks ADD COLUMN scan_seen_ms INTEGER`,
		} {
			if _, err := tx.Exec(stmt); err != nil && !strings.Contains(err.Error(), "duplicate column") {
				return fmt.Errorf("v12: %w", err)
			}
		}
	}
	// v13: снимок открытых отдельно от исторической таблицы flows.
	// Старые строки flows не переносятся и не удаляются.
	if ver < 13 && appID == monitorID {
		for _, stmt := range []string{
			`CREATE TABLE IF NOT EXISTS open_flows(
			  flow_uid TEXT PRIMARY KEY,
			  state_seq INTEGER NOT NULL DEFAULT 0,
			  host_id TEXT NOT NULL REFERENCES hosts(host_id),
			  agent_id TEXT NOT NULL,
			  boot_id TEXT NOT NULL,
			  ct_id INTEGER,
			  zone TEXT, ns TEXT,
			  started_at_ms INTEGER,
			  first_seen_at_ms INTEGER NOT NULL,
			  last_seen_at_ms INTEGER NOT NULL,
			  ip_version INTEGER NOT NULL,
			  protocol TEXT NOT NULL,
			  orig_src_ip TEXT NOT NULL, orig_src_ip_bin BLOB NOT NULL, orig_src_port INTEGER,
			  orig_dst_ip TEXT NOT NULL, orig_dst_ip_bin BLOB NOT NULL, orig_dst_port INTEGER,
			  reply_src_ip TEXT, reply_dst_ip TEXT,
			  direction TEXT NOT NULL,
			  local_ip TEXT NOT NULL, local_ip_bin BLOB NOT NULL, local_port INTEGER,
			  remote_ip TEXT NOT NULL, remote_ip_bin BLOB NOT NULL, remote_port INTEGER,
			  remote_scope TEXT NOT NULL,
			  origin TEXT NOT NULL DEFAULT 'host',
			  icmp_type INTEGER, icmp_code INTEGER,
			  state TEXT,
			  reply_seen INTEGER NOT NULL DEFAULT 0,
			  orig_bytes INTEGER, reply_bytes INTEGER,
			  orig_packets INTEGER, reply_packets INTEGER,
			  proc_path TEXT, proc_uid INTEGER, proc_cgroup TEXT, proc_comm TEXT,
			  container TEXT,
			  dns_name TEXT,
			  incomplete INTEGER NOT NULL DEFAULT 0,
			  received_at_ms INTEGER NOT NULL)`,
			`CREATE INDEX IF NOT EXISTS open_flows_local ON open_flows(host_id, local_ip)`,
			`CREATE INDEX IF NOT EXISTS open_flows_seen ON open_flows(last_seen_at_ms, flow_uid)`,
			`CREATE TABLE IF NOT EXISTS flow_owner(
			  flow_uid TEXT PRIMARY KEY,
			  agent_id TEXT NOT NULL,
			  host_id TEXT NOT NULL,
			  state_seq INTEGER NOT NULL,
			  closed_at_ms INTEGER NOT NULL)`,
			`CREATE INDEX IF NOT EXISTS flow_owner_closed ON flow_owner(closed_at_ms)`,
		} {
			if _, err := tx.Exec(stmt); err != nil {
				return fmt.Errorf("v13: %w", err)
			}
		}
	}
	// v14: агент сообщает последний занятый seq. Без этой границы монитор не знает,
	// что более поздняя проба ещё не приехала. Ноль — агент границу ещё не присылал.
	if ver < 14 && appID == monitorID {
		if _, err := tx.Exec("ALTER TABLE agents ADD COLUMN assigned_through INTEGER NOT NULL DEFAULT 0"); err != nil && !strings.Contains(err.Error(), "duplicate column") {
			return fmt.Errorf("v14: %w", err)
		}
	}
	// v15: адреса, дошедшие до порога перебора SSH. Срок отдельный не задаётся.
	if ver < 15 && appID == monitorID {
		if _, err := tx.Exec(`CREATE TABLE IF NOT EXISTS ssh_brute(
			remote_ip TEXT NOT NULL,
			host_id TEXT NOT NULL,
			attempts INTEGER NOT NULL,
			first_at_ms INTEGER NOT NULL,
			last_at_ms INTEGER NOT NULL,
			PRIMARY KEY(remote_ip, host_id))`); err != nil {
			return fmt.Errorf("v15: %w", err)
		}
	}
	// v16: discard cancelled telemetry once; retain all policy and service records.
	if ver < 16 && appID == monitorID {
		for _, table := range []string{"flow_samples", "flows", "open_flows", "flow_owner", "traffic_1m", "traffic_1h", "firewall_events", "collector_health", "ssh_failures", "remote_seen"} {
			if _, err := tx.Exec("DELETE FROM " + table); err != nil {
				return fmt.Errorf("v16 %s: %w", table, err)
			}
		}
		if _, err := tx.Exec(`DELETE FROM ingest_events WHERE kind NOT IN ('question','queue_drop')`); err != nil {
			return err
		}
		if _, err := tx.Exec(`DELETE FROM settings WHERE k IN ('samples_n','samples_u','flows_n','flows_u','hours_n','hours_u','cf') OR substr(k,1,3) IN ('am:','dp:','sh:','ln:','as:')`); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO settings(k,v) SELECT 'db_max_mb',CAST(MIN(99,MAX(1,CAST(v AS INTEGER)))*1024 AS TEXT) FROM settings WHERE k='db_max_gb'`); err != nil {
			return err
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
