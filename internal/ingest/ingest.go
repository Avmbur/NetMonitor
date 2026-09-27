package ingest

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"netmonitor/internal/idgen"
	"netmonitor/internal/netipx"
	"netmonitor/internal/protocol"
)

type Agent struct {
	DeliveryLane string
	ID           string
	HostID       string
	Trust        string
}

var errForeignFlow = errors.New("foreign flow")

type Result struct {
	Ack []string
	Err string
	// Fatal requires rolling back the outer transaction; no ACK may be sent.
	Fatal error
}

func ApplyBatch(tx *sql.Tx, ag Agent, evs []protocol.Event, receivedMS int64) Result {
	return ApplyBatchWith(tx, ag, evs, receivedMS, nil)
}

// ApplyBatchWith applies each new event and its effects in the same savepoint.
// The caller must commit before publishing Ack, or discard it on any failure.
func ApplyBatchWith(tx *sql.Tx, ag Agent, evs []protocol.Event, receivedMS int64, effect func(protocol.Event) error) Result {
	result := Result{Ack: []string{}}
	var hostID string
	var pendingFrom int64
	if err := tx.QueryRow(`SELECT host_id,pending_from FROM agents WHERE agent_id=?`, ag.ID).Scan(&hostID, &pendingFrom); err != nil {
		result.Fatal = fmt.Errorf("event owner: %w", err)
		return result
	}
	if hostID != ag.HostID || hostID == "" {
		result.Err = "event owner does not match host"
		return result
	}
	for _, ev := range evs {
		if ev.EventID == "" || ev.Kind == "" || ev.Seq <= 0 || ev.ObservedAtMS <= 0 {
			result.Err = "event_id, kind, positive seq and observed_at_ms are required"
			break
		}
		if err := validatePayload(ev); err != nil {
			result.Err = fmt.Sprintf("%s: %v", ev.EventID, err)
			break
		}
		if _, err := tx.Exec(`SAVEPOINT ingest_event`); err != nil {
			result.Fatal = err
			return result
		}
		sha := idgen.SHA256Hex(ev.Payload)
		ok, err := insertMarker(tx, ev, ag.ID, sha, receivedMS, pendingFrom)
		if err == nil && ok {
			err = applyOne(tx, ag, ev, receivedMS)
			if err == nil {
				err = recordIPv6(tx, ag, ev)
			}
		}
		if err != nil {
			if _, rollbackErr := tx.Exec(`ROLLBACK TO ingest_event`); rollbackErr != nil {
				result.Fatal = fmt.Errorf("event %s/%s: %w; savepoint rollback: %v", ev.EventID, ev.Kind, err, rollbackErr)
				return result
			}
			if _, releaseErr := tx.Exec(`RELEASE ingest_event`); releaseErr != nil {
				result.Fatal = releaseErr
				return result
			}
			result.Err = fmt.Sprintf("%s: %v", ev.EventID, err)
			break
		}
		if ok && effect != nil {
			if err := effect(ev); err != nil {
				result.Fatal = err
				return result
			}
		}
		if _, err := tx.Exec(`RELEASE ingest_event`); err != nil {
			result.Fatal = err
			return result
		}
		result.Ack = append(result.Ack, ev.EventID)
	}

	return result
}

func insertMarker(tx *sql.Tx, ev protocol.Event, agentID, sha string, receivedMS, pendingFrom int64) (applied bool, err error) {
	var owner, kind, existSHA string
	var seq, observed int64
	err = tx.QueryRow(`SELECT agent_id, seq, kind, observed_at_ms, payload_sha256 FROM ingest_events WHERE event_id=?`, ev.EventID).Scan(&owner, &seq, &kind, &observed, &existSHA)
	if err == nil {
		if owner != agentID {
			return false, nil
		}
		if seq != ev.Seq || kind != ev.Kind || observed != ev.ObservedAtMS || existSHA != sha {
			return false, fmt.Errorf("event_id %s: то же id, другое тело", ev.EventID)
		}
		return false, nil
	}
	if err != sql.ErrNoRows {
		return false, err
	}
	// The sender has already removed these sequences from its durable queue.
	// A delayed in-flight batch must never apply them again.
	if ev.Seq < pendingFrom {
		return false, nil
	}
	var seqID string
	err = tx.QueryRow(`SELECT event_id FROM ingest_events WHERE agent_id=? AND seq=?`, agentID, ev.Seq).Scan(&seqID)
	if err == nil && seqID != ev.EventID {
		return false, fmt.Errorf("seq %d уже занят другим event_id", ev.Seq)
	}
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	_, err = tx.Exec(
		`INSERT INTO ingest_events(event_id, agent_id, seq, kind, payload_sha256, observed_at_ms, received_at_ms)
		 VALUES(?,?,?,?,?,?,?)`,
		ev.EventID, agentID, ev.Seq, ev.Kind, sha, ev.ObservedAtMS, receivedMS,
	)
	if err != nil {
		return false, err
	}
	return true, nil
}

func applyOne(tx *sql.Tx, ag Agent, ev protocol.Event, receivedMS int64) error {
	switch ev.Kind {
	case "flow":
		var p protocol.FlowPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return upsertFlow(tx, ag, p, receivedMS, ev.Seq)
	case "sample":
		var p protocol.SamplePayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return insertSample(tx, ag, ev.EventID, p, ev.ObservedAtMS, receivedMS, ev.Seq)
	case "queue_drop":
		var p protocol.HealthPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		p.Kind = "queue_drop"
		p.Note = string(ev.Payload)
		return insertHealth(tx, ag, ev, p, receivedMS)
	case "health":
		var p protocol.HealthPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if p.FWBackend != "" {
			if p.FWBackend != "nftables" && p.FWBackend != "iptables" && p.FWBackend != "unknown" {
				return fmt.Errorf("invalid firewall backend")
			}
			if _, err := tx.Exec("UPDATE agents SET fw_backend=?,scope_note=? WHERE agent_id=?", p.FWBackend, nullStr(p.ScopeNote), ag.ID); err != nil {
				return err
			}
		}
		if p.Version != "" {
			if _, err := tx.Exec("UPDATE agents SET version=? WHERE agent_id=?", p.Version, ag.ID); err != nil {
				return err
			}
		}
		if p.Kind == "alive" && (ag.DeliveryLane == "heartbeat" || ag.DeliveryLane == "" && receivedMS-ev.ObservedAtMS < 30000 && ev.ObservedAtMS-receivedMS < 30000) {
			if p.Addresses != nil || p.OpenPorts != nil {
				inventory, err := json.Marshal(p)
				if err != nil {
					return err
				}
				var old struct {
					SSHPort  *int  `json:"ssh_port"`
					SSHPorts []int `json:"ssh_ports"`
				}
				var oldRaw string
				if tx.QueryRow("SELECT v FROM settings WHERE k=?", "inventory:"+ag.HostID).Scan(&oldRaw) == nil {
					_ = json.Unmarshal([]byte(oldRaw), &old)
				}
				if _, err = tx.Exec("INSERT INTO settings(k,v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v=excluded.v", "inventory:"+ag.HostID, string(inventory)); err != nil {
					return err
				}
				// The starter SSH rule goes out with the host's sshd ports.
				if p.SSHPort != nil && (old.SSHPort == nil || *old.SSHPort != *p.SSHPort) || !slices.Equal(old.SSHPorts, p.SSHPorts) {
					if _, err = tx.Exec("UPDATE agents SET policy_rev=policy_rev+1 WHERE host_id=?", ag.HostID); err != nil {
						return err
					}
				}
			}
			if p.BootID != "" {
				if _, err := tx.Exec("UPDATE agents SET boot_id=? WHERE agent_id=?", p.BootID, ag.ID); err != nil {
					return err
				}
			}
			if _, err := tx.Exec("UPDATE hosts SET last_seen_ms=? WHERE host_id=?", receivedMS, ag.HostID); err != nil {
				return err
			}
		}
		return insertHealth(tx, ag, ev, p, receivedMS)
	case "dns":
		var p protocol.DNSPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return upsertDNS(tx, ag, p, ev.ObservedAtMS)
	case "firewall":
		var p protocol.FirewallPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return insertFW(tx, ag, ev, p, receivedMS)
	case "ssh":
		var p protocol.SSHPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if p.ObservedAtMS > 0 {
			ev.ObservedAtMS = p.ObservedAtMS
		}
		return insertSSH(tx, ag, ev, p)
	case "scan":
		return nil
	case "question":
		var p protocol.QuestionPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return upsertQuestion(tx, ag, p, ev.ObservedAtMS)
	default:
		return fmt.Errorf("неизвестный kind %s", ev.Kind)
	}
}

func upsertFlow(tx *sql.Tx, ag Agent, p protocol.FlowPayload, receivedMS, seq int64) error {
	if p.FlowUID == "" {
		return fmt.Errorf("flow_uid")
	}
	if err := checkFlowOwner(tx, ag, p.FlowUID, true); err != nil {
		if errors.Is(err, errForeignFlow) {
			return nil
		}
		return err
	}
	origSrc, err := netipx.Parse(p.OrigSrcIP)
	if err != nil {
		return fmt.Errorf("orig_src_ip: %w", err)
	}
	origDst, err := netipx.Parse(p.OrigDstIP)
	if err != nil {
		return fmt.Errorf("orig_dst_ip: %w", err)
	}
	local, err := netipx.Parse(p.LocalIP)
	if err != nil {
		return fmt.Errorf("local_ip: %w", err)
	}
	remote, err := netipx.Parse(p.RemoteIP)
	if err != nil {
		return fmt.Errorf("remote_ip: %w", err)
	}
	scope := p.RemoteScope
	if scope == "" {
		scope = netipx.Scope(remote, netipx.DefaultLAN(), nil, nil)
	}
	origin := p.Origin
	if origin == "" {
		origin = "host"
	}
	boot := p.BootID
	if boot == "" {
		boot = "unknown"
	}
	var existed int
	if err = tx.QueryRow("SELECT COUNT(*) FROM flows WHERE flow_uid=?", p.FlowUID).Scan(&existed); err != nil {
		return err
	}
	_, err = tx.Exec(`
INSERT INTO flows(
  flow_uid, host_id, agent_id, boot_id, ct_id, started_at_ms, first_seen_at_ms, last_seen_at_ms, ended_at_ms,
  ip_version, protocol,
  orig_src_ip, orig_src_ip_bin, orig_src_port, orig_dst_ip, orig_dst_ip_bin, orig_dst_port,
  reply_src_ip, reply_dst_ip, direction,
  local_ip, local_ip_bin, local_port, remote_ip, remote_ip_bin, remote_port,
  remote_scope, origin, state, reply_seen, close_reason,
  orig_bytes, reply_bytes, orig_packets, reply_packets,
  proc_path, proc_uid, proc_cgroup, proc_comm, dns_name, incomplete, received_at_ms, state_seq, icmp_type, icmp_code, zone, ns)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(flow_uid) DO UPDATE SET
  last_seen_at_ms=MAX(flows.last_seen_at_ms,excluded.last_seen_at_ms),
  ended_at_ms=COALESCE(excluded.ended_at_ms, flows.ended_at_ms),
  state=COALESCE(excluded.state, flows.state),
  reply_seen=MAX(flows.reply_seen, excluded.reply_seen),
  orig_bytes=excluded.orig_bytes,
  reply_bytes=excluded.reply_bytes,
  orig_packets=excluded.orig_packets,
  reply_packets=excluded.reply_packets,
  close_reason=COALESCE(excluded.close_reason, flows.close_reason),
  received_at_ms=excluded.received_at_ms,
 state_seq=excluded.state_seq,
 started_at_ms=COALESCE(flows.started_at_ms,excluded.started_at_ms),
 proc_comm=COALESCE(excluded.proc_comm,flows.proc_comm),
 proc_path=COALESCE(excluded.proc_path,flows.proc_path),
 proc_uid=COALESCE(excluded.proc_uid,flows.proc_uid),
 proc_cgroup=COALESCE(excluded.proc_cgroup,flows.proc_cgroup),
 dns_name=COALESCE(NULLIF(excluded.dns_name,''), flows.dns_name),
 incomplete=MAX(flows.incomplete,excluded.incomplete)
 WHERE excluded.state_seq>flows.state_seq`,
		p.FlowUID, ag.HostID, ag.ID, boot, p.CtID, p.StartedAtMS, p.FirstSeenMS, p.LastSeenMS, p.EndedAtMS,
		p.IPVersion, strings.ToLower(p.Protocol),
		netipx.Canonical(origSrc), netipx.Bin16(origSrc), p.OrigSrcPort,
		netipx.Canonical(origDst), netipx.Bin16(origDst), p.OrigDstPort,
		nullStr(p.ReplySrcIP), nullStr(p.ReplyDstIP), p.Direction,
		netipx.Canonical(local), netipx.Bin16(local), p.LocalPort,
		netipx.Canonical(remote), netipx.Bin16(remote), p.RemotePort,
		scope, origin, nullStr(p.State), p.ReplySeen, nullStr(p.CloseReason),
		p.OrigBytes, p.ReplyBytes, p.OrigPackets, p.ReplyPackets,
		nullStr(p.ProcPath), p.ProcUID, nullStr(p.ProcCgroup), nullStr(p.ProcComm), nullStr(p.DNSName),
		p.Incomplete, receivedMS, seq, p.ICMPType, p.ICMPCode, nullStr(p.Zone), nullStr(p.NS),
	)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`
INSERT INTO remote_seen(host_id, remote_ip_bin, remote_ip, first_seen_ms, last_seen_ms, flows)
VALUES(?,?,?,?,?,?)
ON CONFLICT(host_id, remote_ip_bin) DO UPDATE SET
  last_seen_ms=MAX(remote_seen.last_seen_ms,excluded.last_seen_ms),
  flows=remote_seen.flows+excluded.flows`,
		ag.HostID, netipx.Bin16(remote), netipx.Canonical(remote), p.FirstSeenMS, p.LastSeenMS, 1-existed)
	return err
}

func skipSamples(tx *sql.Tx) bool {
	var v string
	if err := tx.QueryRow(`SELECT v FROM settings WHERE k='disk_skip_samples'`).Scan(&v); err != nil {
		return false
	}
	return v == "1"
}

func insertSample(tx *sql.Tx, ag Agent, eventID string, p protocol.SamplePayload, observed, received, seq int64) error {
	if skipSamples(tx) {
		return nil
	}
	if p.Quality == "" {
		p.Quality = "ok"
	}
	if p.Flow != nil {
		if err := upsertFlow(tx, ag, *p.Flow, received, seq); err != nil {
			return err
		}
		if p.FlowUID == "" {
			p.FlowUID = p.Flow.FlowUID
		}
		if p.Direction == "" {
			p.Direction = p.Flow.Direction
		}
		if p.RemoteScope == "" {
			p.RemoteScope = p.Flow.RemoteScope
		}
	}
	if p.FlowUID == "" {
		return fmt.Errorf("sample без flow_uid")
	}
	if err := checkFlowOwner(tx, ag, p.FlowUID, false); err != nil {
		if errors.Is(err, errForeignFlow) {
			return nil
		}
		return err
	}
	if p.Incomplete == 1 || p.Quality == "counter_reset" {
		bout, bin, pout, pin := mapBytes(p.Direction, p.OrigBytesDelta, p.ReplyBytesDelta, p.OrigPacketsDelta, p.ReplyPacketsDelta)
		_, err := tx.Exec(`
INSERT INTO flow_samples(event_id, flow_uid, agent_id, t0_ms, t1_ms,
  orig_bytes_delta, reply_bytes_delta, orig_packets_delta, reply_packets_delta,
  bytes_out, bytes_in, pkts_out, pkts_in, quality, observed_at_ms, received_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			eventID, p.FlowUID, ag.ID, p.T0MS, p.T1MS,
			p.OrigBytesDelta, p.ReplyBytesDelta, p.OrigPacketsDelta, p.ReplyPacketsDelta,
			bout, bin, pout, pin, p.Quality, observed, received)
		return err
	}
	return splitSample(tx, ag, eventID, p, observed, received)
}

func checkFlowOwner(tx *sql.Tx, ag Agent, uid string, allowMissing bool) error {
	var owner, host string
	err := tx.QueryRow(`SELECT agent_id, host_id FROM flows WHERE flow_uid=?`, uid).Scan(&owner, &host)
	if err == sql.ErrNoRows && allowMissing {
		return nil
	}
	if err != nil {
		return fmt.Errorf("flow %s: %w", uid, err)
	}
	if owner == ag.ID && host == ag.HostID {
		return nil
	}
	if host == ag.HostID {
		_, err = tx.Exec(`UPDATE flows SET agent_id=? WHERE flow_uid=?`, ag.ID, uid)
		return err
	}
	return fmt.Errorf("flow %s: %w", uid, errForeignFlow)
}

func splitSample(tx *sql.Tx, ag Agent, eventID string, p protocol.SamplePayload, observed, received int64) error {
	dur := p.T1MS - p.T0MS
	if dur <= 0 {
		dur = 1
	}
	t := p.T0MS
	part := 0
	remainO, remainR := p.OrigBytesDelta, p.ReplyBytesDelta
	remainOP, remainRP := p.OrigPacketsDelta, p.ReplyPacketsDelta
	for t < p.T1MS {
		next := (t/60000 + 1) * 60000
		if next > p.T1MS {
			next = p.T1MS
		}
		slice := next - t
		last := next == p.T1MS
		var o, r, op, rp int64
		if last {
			o, r, op, rp = remainO, remainR, remainOP, remainRP
		} else {
			o = p.OrigBytesDelta * slice / dur
			r = p.ReplyBytesDelta * slice / dur
			op = p.OrigPacketsDelta * slice / dur
			rp = p.ReplyPacketsDelta * slice / dur
			remainO -= o
			remainR -= r
			remainOP -= op
			remainRP -= rp
		}
		eid := eventID
		if part > 0 {
			eid = eventID + fmt.Sprintf("#%d", part)
		}
		bout, bin, pout, pin := mapBytes(p.Direction, o, r, op, rp)
		if _, err := tx.Exec(`
INSERT INTO flow_samples(event_id, flow_uid, agent_id, t0_ms, t1_ms,
  orig_bytes_delta, reply_bytes_delta, orig_packets_delta, reply_packets_delta,
  bytes_out, bytes_in, pkts_out, pkts_in, quality, observed_at_ms, received_at_ms)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			eid, p.FlowUID, ag.ID, t, next, o, r, op, rp, bout, bin, pout, pin, p.Quality, observed, received); err != nil {
			return err
		}
		if p.Quality == "ok" && ag.Trust == "trusted" {
			bucket := t - (t % 60000)
			if _, err := tx.Exec(`
INSERT INTO traffic_1m(host_id, bucket_start_ms, direction, remote_scope, bytes_out, bytes_in, samples)
VALUES(?,?,?,?,?,?,1)
ON CONFLICT(host_id, bucket_start_ms, direction, remote_scope) DO UPDATE SET
  bytes_out=bytes_out+excluded.bytes_out,
  bytes_in=bytes_in+excluded.bytes_in,
  samples=samples+1`,
				ag.HostID, bucket, nz(p.Direction, "unknown"), nz(p.RemoteScope, "internet"), bout, bin); err != nil {
				return err
			}
		}
		t = next
		part++
	}
	return nil
}

func mapBytes(dir string, origB, replyB, origP, replyP int64) (outB, inB, outP, inP int64) {
	if dir == "in" {
		return replyB, origB, replyP, origP
	}
	return origB, replyB, origP, replyP
}

func insertHealth(tx *sql.Tx, ag Agent, ev protocol.Event, p protocol.HealthPayload, received int64) error {
	kind := p.Kind
	if kind == "" {
		kind = "alive"
	}
	if kind == "alive" {
		res, err := tx.Exec(
			`UPDATE collector_health SET event_id=?, host_id=?, observed_at_ms=?, received_at_ms=?, lost_events=?, queue_bytes=?, note=?
			 WHERE agent_id=? AND kind='alive'`,
			ev.EventID, ag.HostID, ev.ObservedAtMS, received, p.LostEvents, p.QueueBytes, nullStr(p.Note), ag.ID,
		)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		if n > 0 {
			return nil
		}
	}
	_, err := tx.Exec(
		`INSERT INTO collector_health(event_id, host_id, agent_id, observed_at_ms, received_at_ms, kind, lost_events, queue_bytes, note)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		ev.EventID, ag.HostID, ag.ID, ev.ObservedAtMS, received, kind, p.LostEvents, p.QueueBytes, nullStr(p.Note),
	)
	return err
}

func upsertDNS(tx *sql.Tx, ag Agent, p protocol.DNSPayload, observed int64) error {
	ip, err := netipx.Parse(p.IP)
	if err != nil {
		return err
	}
	name := strings.ToLower(strings.TrimSuffix(p.Name, "."))
	canon := netipx.Canonical(ip)
	bin := netipx.Bin16(ip)
	if p.Kind == "ptr" {
		_, err = tx.Exec(`
INSERT INTO ip_names(ip_bin, ip, ptr_name, ptr_confirmed, resolved_at_ms)
VALUES(?,?,?,0,?)
ON CONFLICT(ip_bin) DO UPDATE SET ptr_name=excluded.ptr_name, resolved_at_ms=excluded.resolved_at_ms`,
			bin, canon, name, observed)
		return err
	}
	_, err = tx.Exec(`
INSERT INTO dns_seen(host_id, name, ip_bin, ip, first_seen_ms, last_seen_ms)
VALUES(?,?,?,?,?,?)
ON CONFLICT(host_id, name, ip_bin) DO UPDATE SET last_seen_ms=excluded.last_seen_ms`,
		ag.HostID, name, bin, canon, observed, observed)
	return err
}

func insertFW(tx *sql.Tx, ag Agent, ev protocol.Event, p protocol.FirewallPayload, received int64) error {
	hits := p.Hits
	if hits <= 0 {
		hits = 1
	}
	var lip, rip any
	var lbin, rbin []byte
	if p.LocalIP != "" {
		a, err := netipx.Parse(p.LocalIP)
		if err != nil {
			return err
		}
		lip, lbin = netipx.Canonical(a), netipx.Bin16(a)
	}
	if p.RemoteIP != "" {
		a, err := netipx.Parse(p.RemoteIP)
		if err != nil {
			return err
		}
		rip, rbin = netipx.Canonical(a), netipx.Bin16(a)
	}
	group := ev.EventID
	if p.GroupID != "" {
		group = ag.ID + "/" + p.GroupID
	}
	_, err := tx.Exec(`
INSERT INTO firewall_events(event_id, host_id, observed_at_ms, received_at_ms, ip_version, protocol, direction,
  local_ip, local_ip_bin, local_port, remote_ip, remote_ip_bin, remote_port, remote_scope, verdict, chain, rule_tag, in_iface, hits)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(event_id) DO UPDATE SET hits=firewall_events.hits+excluded.hits,received_at_ms=excluded.received_at_ms`,
		group, ag.HostID, ev.ObservedAtMS, received, p.IPVersion, p.Protocol, p.Direction,
		lip, lbin, p.LocalPort, rip, rbin, p.RemotePort, p.RemoteScope, p.Verdict, p.Chain, p.RuleTag, p.InIface, hits)
	return err
}

func insertSSH(tx *sql.Tx, ag Agent, ev protocol.Event, p protocol.SSHPayload) error {
	ip, err := netipx.Parse(p.RemoteIP)
	if err != nil {
		return err
	}
	_, err = tx.Exec(
		`INSERT INTO ssh_failures(event_id, host_id, observed_at_ms, remote_ip, remote_ip_bin, user_name, note)
		 VALUES(?,?,?,?,?,?,?)`,
		ev.EventID, ag.HostID, ev.ObservedAtMS, netipx.Canonical(ip), netipx.Bin16(ip), nullStr(p.User), nullStr(p.Note),
	)
	return err
}

func upsertQuestion(tx *sql.Tx, ag Agent, p protocol.QuestionPayload, now int64) error {
	key := p.DedupKey
	if key == "" {
		key = strings.Join([]string{p.Direction, p.Protocol, p.RemoteIP, fmt.Sprint(p.RemotePort), p.ProcComm}, "|")
	}
	var id string
	err := tx.QueryRow(`SELECT question_id FROM learn_questions WHERE host_id=? AND dedup_key=? AND status='open'`, ag.HostID, key).Scan(&id)
	if err == nil {
		add := p.Repeats
		if add < 1 {
			add = 1
		}
		_, err = tx.Exec(`UPDATE learn_questions SET repeats=repeats+?, last_seen_ms=MAX(last_seen_ms,?),
			proc_comm=CASE WHEN COALESCE(proc_comm,'')='' THEN ? ELSE proc_comm END,
			proc_path=CASE WHEN COALESCE(proc_path,'')='' THEN ? ELSE proc_path END
			WHERE question_id=?`, add, now, nullStr(p.ProcComm), nullStr(p.ProcPath), id)
		return err
	}
	if err != sql.ErrNoRows {
		return err
	}
	qid := idgen.NewV7()
	n := p.Repeats
	if n < 1 {
		n = 1
	}
	_, err = tx.Exec(
		`INSERT INTO learn_questions(question_id, host_id, dedup_key, opened_at_ms, repeats, last_seen_ms, direction, protocol, local_port, remote_ip, remote_port, dns_name, proc_path, proc_comm, status)
		 VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'open')`,
		qid, ag.HostID, key, now, n, now, p.Direction, p.Protocol, p.LocalPort, p.RemoteIP, p.RemotePort, nullStr(p.DNSName), nullStr(p.ProcPath), nullStr(p.ProcComm),
	)
	return err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nz(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

func recordIPv6(tx *sql.Tx, ag Agent, ev protocol.Event) error {
	var p struct {
		IPVersion int                   `json:"ip_version"`
		RemoteIP  string                `json:"remote_ip"`
		Flow      *protocol.FlowPayload `json:"flow"`
	}
	switch ev.Kind {
	case "flow", "sample", "firewall", "question":
	default:
		return nil
	}
	if err := json.Unmarshal(ev.Payload, &p); err != nil {
		return err
	}
	seen := p.IPVersion == 6
	if p.Flow != nil && p.Flow.IPVersion == 6 {
		seen = true
	}
	if a, e := netipx.Parse(p.RemoteIP); e == nil && a.Unmap().Is6() {
		seen = true
	}
	if seen {
		_, err := tx.Exec("UPDATE agents SET ipv6_seen=1 WHERE agent_id=?", ag.ID)
		return err
	}
	return nil
}
