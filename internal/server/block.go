package server

import (
	"database/sql"
	"fmt"
	"strconv"
	"time"

	"netmonitor/internal/netipx"
	"netmonitor/internal/store"
)

func TrustPending(dataDir, hostname string) (int, error) {
	st, err := store.OpenMonitor(dataDir)
	if err != nil {
		return 0, err
	}
	defer st.Close()
	now := store.NowMS()
	n := 0
	err = st.Update(func(tx *sql.Tx) error {
		q := `UPDATE agents SET trust_state='trusted', approved_at_ms=?, approved_by='cli' WHERE trust_state='pending'`
		args := []any{now}
		if hostname != "" {
			q += ` AND (display_name=? OR host_id IN (SELECT host_id FROM hosts WHERE hostname=?))`
			args = append(args, hostname, hostname)
		}
		res, err := tx.Exec(q, args...)
		if err != nil {
			return err
		}
		c, err := res.RowsAffected()
		if err != nil {
			return err
		}
		n = int(c)
		return nil
	})
	return n, err
}

// BlockIP is the CLI entry: a whole-address ban on the whole park. Exact
// conditions and a narrower server selection come from the API.
func BlockIP(dataDir, ip string, ttl time.Duration, allHosts bool) (string, error) {
	if ttl < 0 {
		return "", fmt.Errorf("неверная длительность бана")
	}
	if !allHosts {
		return "", fmt.Errorf("выбор серверов задаётся из интерфейса, не из CLI")
	}
	st, err := store.OpenMonitor(dataDir)
	if err != nil {
		return "", err
	}
	defer st.Close()
	now := store.NowMS()
	b := banSpec{RemoteIP: ip, Direction: "both", Reason: "manual", Source: "manual", CreatedBy: "cli"}
	if ttl > 0 {
		b.ExpiresAt = now + ttl.Milliseconds()
	}
	if err = validateBan(b, false); err != nil {
		return "", err
	}
	var id string
	err = st.Update(func(tx *sql.Tx) error {
		var e error
		id, e = writeBan(tx, b, now)
		if e != nil {
			return e
		}
		return auditBan(tx, "cli", "забанил", b, now)
	})
	return id, err
}

// UnblockIP lifts every active ban on the address; the API lifts one by id.
func UnblockIP(dataDir, ip string) error {
	addr, err := netipx.Parse(ip)
	if err != nil {
		return err
	}
	st, err := store.OpenMonitor(dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	canon := netipx.Canonical(addr)
	now := store.NowMS()
	return st.Update(func(tx *sql.Tx) error {
		bans, err := readBans(tx, "WHERE remote_ip=? AND state='active'", canon)
		if err != nil {
			return err
		}
		if len(bans) == 0 {
			return fmt.Errorf("активного бана нет")
		}
		for _, b := range bans {
			if err = removeBan(tx, b.ID, "cli", now); err != nil {
				return err
			}
		}
		return nil
	})
}

func AddNeverBlock(dataDir, cidr, reason string) error {
	st, err := store.OpenMonitor(dataDir)
	if err != nil {
		return err
	}
	defer st.Close()
	_, err = saveNever(st, "", cidr, reason, "cli")
	return err
}

func ParseTTL(s string) time.Duration {
	if s == "forever" {
		return 0
	}
	if s == "" || s == "0" {
		return time.Hour
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		n, _ := strconv.Atoi(s)
		if n > 0 {
			return time.Duration(n) * time.Second
		}
		return time.Hour
	}
	return d
}
