PRAGMA foreign_keys=ON;
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;

CREATE TABLE hosts(
  host_id TEXT PRIMARY KEY,
  hostname TEXT,
  note TEXT,
  first_seen_ms INTEGER,
  last_seen_ms INTEGER);

CREATE TABLE agents(
  agent_id TEXT PRIMARY KEY,
  host_id TEXT REFERENCES hosts(host_id),
  cert_fingerprint TEXT NOT NULL,
  trust_state TEXT NOT NULL,
  display_name TEXT,
  boot_id TEXT,
  version TEXT,
  fw_backend TEXT,
  ipv6_seen INTEGER NOT NULL DEFAULT 0,
  scope_note TEXT,
  started_at_ms INTEGER,
  first_seen_ms INTEGER NOT NULL,
  approved_at_ms INTEGER,
  approved_by TEXT,
  last_src_ip TEXT,
  policy_rev INTEGER NOT NULL DEFAULT 0);
CREATE INDEX agent_fp ON agents(cert_fingerprint);
CREATE INDEX agent_trust ON agents(trust_state);

CREATE TABLE ingest_events(
  event_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  seq INTEGER NOT NULL,
  kind TEXT NOT NULL,
  payload_sha256 TEXT,
  observed_at_ms INTEGER NOT NULL,
  received_at_ms INTEGER NOT NULL,
  UNIQUE(agent_id, seq));

CREATE TABLE flows(
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
  ended_at_ms INTEGER,
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
  nat_dst_ip TEXT, nat_dst_port INTEGER,
  state TEXT,
  reply_seen INTEGER NOT NULL DEFAULT 0,
  close_reason TEXT,
  orig_bytes INTEGER, reply_bytes INTEGER,
  orig_packets INTEGER, reply_packets INTEGER,
  proc_path TEXT, proc_uid INTEGER, proc_cgroup TEXT, proc_comm TEXT,
  container TEXT,
  dns_name TEXT,
  incomplete INTEGER NOT NULL DEFAULT 0,
  received_at_ms INTEGER NOT NULL);
CREATE INDEX flows_time ON flows(host_id, first_seen_at_ms);
CREATE INDEX flows_remote ON flows(host_id, remote_ip_bin, first_seen_at_ms);
CREATE INDEX flows_lport ON flows(host_id, direction, local_port, first_seen_at_ms);
CREATE INDEX flows_rport ON flows(host_id, direction, remote_port, first_seen_at_ms);
CREATE INDEX flows_noreply ON flows(host_id, first_seen_at_ms) WHERE reply_seen = 0;
CREATE INDEX flows_open ON flows(last_seen_at_ms, flow_uid) WHERE ended_at_ms IS NULL;
CREATE INDEX flows_open_host ON flows(host_id, last_seen_at_ms, flow_uid) WHERE ended_at_ms IS NULL;

-- Снимок ещё открытых соединений. Закрытие удаляет строку отсюда, а не дописывает историю flows.
CREATE TABLE open_flows(
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
  received_at_ms INTEGER NOT NULL);
CREATE INDEX open_flows_local ON open_flows(host_id, local_ip);
CREATE INDEX open_flows_seen ON open_flows(last_seen_at_ms, flow_uid);

-- Владелец закрытого соединения: чтобы проба после закрытия не зависала и не прилипла к чужому.
-- Это не история: нет адресов, байтов и процесса. Срок — как у закрытых flows.
CREATE TABLE flow_owner(
  flow_uid TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  host_id TEXT NOT NULL,
  state_seq INTEGER NOT NULL,
  closed_at_ms INTEGER NOT NULL);
CREATE INDEX flow_owner_closed ON flow_owner(closed_at_ms);

CREATE TABLE flow_samples(
  event_id TEXT PRIMARY KEY,
  flow_uid TEXT NOT NULL REFERENCES flows(flow_uid),
  agent_id TEXT NOT NULL,
  t0_ms INTEGER NOT NULL,
  t1_ms INTEGER NOT NULL,
  orig_bytes_delta INTEGER NOT NULL,
  reply_bytes_delta INTEGER NOT NULL,
  orig_packets_delta INTEGER NOT NULL,
  reply_packets_delta INTEGER NOT NULL,
  bytes_out INTEGER NOT NULL,
  bytes_in INTEGER NOT NULL,
  pkts_out INTEGER NOT NULL,
  pkts_in INTEGER NOT NULL,
  quality TEXT NOT NULL,
  observed_at_ms INTEGER NOT NULL,
  received_at_ms INTEGER NOT NULL);
CREATE INDEX fs_time ON flow_samples(t0_ms);
CREATE INDEX fs_flow ON flow_samples(flow_uid, t0_ms);

CREATE TABLE traffic_1m(
  host_id TEXT NOT NULL,
  bucket_start_ms INTEGER NOT NULL,
  direction TEXT NOT NULL,
  remote_scope TEXT NOT NULL,
  bytes_out INTEGER NOT NULL,
  bytes_in INTEGER NOT NULL,
  samples INTEGER NOT NULL,
  PRIMARY KEY(host_id, bucket_start_ms, direction, remote_scope)) WITHOUT ROWID;

CREATE TABLE traffic_1h(
  host_id TEXT NOT NULL,
  bucket_start_ms INTEGER NOT NULL,
  direction TEXT NOT NULL,
  remote_scope TEXT NOT NULL,
  bytes_out INTEGER NOT NULL,
  bytes_in INTEGER NOT NULL,
  flows INTEGER NOT NULL,
  dirty INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(host_id, bucket_start_ms, direction, remote_scope)) WITHOUT ROWID;

CREATE TABLE firewall_events(
  event_id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL REFERENCES hosts(host_id),
  observed_at_ms INTEGER NOT NULL,
  received_at_ms INTEGER NOT NULL,
  ip_version INTEGER, protocol TEXT, direction TEXT,
  local_ip TEXT, local_ip_bin BLOB, local_port INTEGER,
  remote_ip TEXT, remote_ip_bin BLOB, remote_port INTEGER,
  remote_scope TEXT,
  verdict TEXT,
  chain TEXT, rule_tag TEXT, in_iface TEXT,
  hits INTEGER NOT NULL DEFAULT 1);
CREATE INDEX fw_time ON firewall_events(host_id, observed_at_ms);
CREATE INDEX fw_remote ON firewall_events(remote_ip_bin, observed_at_ms);

CREATE TABLE collector_health(
  event_id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL,
  agent_id TEXT,
  observed_at_ms INTEGER NOT NULL,
  received_at_ms INTEGER NOT NULL,
  kind TEXT NOT NULL,
  lost_events INTEGER, queue_bytes INTEGER, note TEXT);

CREATE TABLE remote_seen(
  host_id TEXT NOT NULL,
  remote_ip_bin BLOB NOT NULL,
  remote_ip TEXT NOT NULL,
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms INTEGER NOT NULL,
  flows INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(host_id, remote_ip_bin)) WITHOUT ROWID;

CREATE TABLE dns_seen(
  host_id TEXT NOT NULL,
  name TEXT NOT NULL,
  ip_bin BLOB NOT NULL,
  ip TEXT NOT NULL,
  first_seen_ms INTEGER NOT NULL,
  last_seen_ms INTEGER NOT NULL,
  PRIMARY KEY(host_id, name, ip_bin)) WITHOUT ROWID;
CREATE INDEX dns_seen_name ON dns_seen(name, ip_bin);
CREATE INDEX dns_seen_ip ON dns_seen(ip);

CREATE TABLE ip_groups(
  hosts_json TEXT NOT NULL DEFAULT '"all"',
  group_id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  policy TEXT NOT NULL DEFAULT 'observe',
  sort_order INTEGER NOT NULL DEFAULT 0,
  mute_alerts INTEGER NOT NULL DEFAULT 0,
  note TEXT,
  created_at_ms INTEGER NOT NULL);

CREATE TABLE ip_group_members(
  group_id TEXT NOT NULL REFERENCES ip_groups(group_id),
  ip_lo_bin BLOB NOT NULL, ip_hi_bin BLOB NOT NULL,
  cidr TEXT NOT NULL,
  source TEXT NOT NULL,
  added_at_ms INTEGER NOT NULL,
  PRIMARY KEY(group_id, ip_lo_bin, ip_hi_bin)) WITHOUT ROWID;

CREATE TABLE ip_group_patterns(
  group_id TEXT NOT NULL REFERENCES ip_groups(group_id),
  pattern TEXT NOT NULL,
  PRIMARY KEY(group_id, pattern)) WITHOUT ROWID;

CREATE TABLE ip_group_host_excl(
  group_id TEXT NOT NULL REFERENCES ip_groups(group_id),
  host_id TEXT NOT NULL REFERENCES hosts(host_id),
  PRIMARY KEY(group_id, host_id)) WITHOUT ROWID;

CREATE TABLE ip_names(
  ip_bin BLOB PRIMARY KEY,
  ip TEXT NOT NULL,
  ptr_name TEXT,
  ptr_confirmed INTEGER NOT NULL DEFAULT 0,
  resolved_at_ms INTEGER,
  ttl_ms INTEGER) WITHOUT ROWID;

CREATE TABLE never_block(
  id TEXT PRIMARY KEY,
  cidr TEXT NOT NULL,
  ip_lo_bin BLOB NOT NULL,
  ip_hi_bin BLOB NOT NULL,
  reason TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL);

CREATE TABLE ssh_brute(
  remote_ip TEXT NOT NULL,
  host_id TEXT NOT NULL,
  attempts INTEGER NOT NULL,
  first_at_ms INTEGER NOT NULL,
  last_at_ms INTEGER NOT NULL,
  PRIMARY KEY(remote_ip, host_id));

CREATE TABLE blocks(
  block_id TEXT PRIMARY KEY,
  host_id TEXT,
  scope_kind TEXT NOT NULL,
  hosts_json TEXT, except_json TEXT,
  remote_ip TEXT, remote_ip_bin BLOB,
  protocol TEXT, port INTEGER, local_port INTEGER,
  direction TEXT NOT NULL DEFAULT 'both',
  state TEXT NOT NULL,
  reason TEXT NOT NULL,
  source TEXT NOT NULL,
  rule_id TEXT, alert_id TEXT,
  created_by TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  updated_at_ms INTEGER,
  version INTEGER NOT NULL DEFAULT 1,
  expires_at_ms INTEGER,
  escalate_step INTEGER NOT NULL DEFAULT 0,
  applied_at_ms INTEGER, removed_at_ms INTEGER,
  last_error TEXT,
  scan_ports TEXT,
  scan_seen_ms INTEGER);
CREATE INDEX blocks_state ON blocks(host_id, state, expires_at_ms);
CREATE INDEX blocks_ip ON blocks(remote_ip_bin);

CREATE TABLE commands(
  command_id TEXT PRIMARY KEY,
  agent_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  payload TEXT NOT NULL,
  block_id TEXT REFERENCES blocks(block_id),
  created_at_ms INTEGER NOT NULL,
  block_version INTEGER,
  delivered_rev INTEGER,
  delivered_at_ms INTEGER, acked_at_ms INTEGER,
  result TEXT, error TEXT);
CREATE INDEX commands_pending ON commands(agent_id, acked_at_ms, created_at_ms);
CREATE UNIQUE INDEX commands_ban_version ON commands(agent_id,block_id,block_version) WHERE kind='ban';


CREATE TABLE learn_questions(
  question_id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL REFERENCES hosts(host_id),
  dedup_key TEXT NOT NULL,
  opened_at_ms INTEGER NOT NULL,
  repeats INTEGER NOT NULL DEFAULT 1,
  last_seen_ms INTEGER NOT NULL,
  direction TEXT, protocol TEXT,
  local_port INTEGER, remote_ip TEXT, remote_port INTEGER,
  dns_name TEXT, proc_path TEXT, proc_comm TEXT, container TEXT,
  status TEXT NOT NULL,
  answer TEXT);
CREATE UNIQUE INDEX learn_open_dedup ON learn_questions(host_id, dedup_key) WHERE status = 'open';
CREATE INDEX learn_open ON learn_questions(host_id, status, opened_at_ms);

CREATE TABLE ssh_failures(
  event_id TEXT PRIMARY KEY,
  host_id TEXT NOT NULL,
  observed_at_ms INTEGER NOT NULL,
  remote_ip TEXT NOT NULL,
  remote_ip_bin BLOB NOT NULL,
  user_name TEXT,
  note TEXT);
CREATE INDEX sshf_ip ON ssh_failures(host_id, remote_ip_bin, observed_at_ms);

CREATE TABLE alert_rules(
  rule_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  scope_hosts TEXT,
  event_kind TEXT NOT NULL,
  match_spec TEXT NOT NULL,
  window_spec TEXT,
  severity TEXT NOT NULL,
  reaction TEXT NOT NULL,
  mute_sec INTEGER NOT NULL DEFAULT 600,
  autoban_cap_per_min INTEGER,
  version INTEGER NOT NULL DEFAULT 1,
  updated_at_ms INTEGER NOT NULL);

CREATE TABLE rule_nets(
  rule_id TEXT NOT NULL REFERENCES alert_rules(rule_id),
  cidr TEXT NOT NULL,
  ip_lo_bin BLOB NOT NULL, ip_hi_bin BLOB NOT NULL,
  negate INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY(rule_id, cidr, negate)) WITHOUT ROWID;

CREATE TABLE alerts(
  alert_id TEXT PRIMARY KEY,
  rule_id TEXT NOT NULL,
  rule_version INTEGER NOT NULL,
  host_id TEXT NOT NULL,
  dedup_key TEXT NOT NULL,
  opened_at_ms INTEGER NOT NULL,
  closed_at_ms INTEGER,
  severity TEXT NOT NULL,
  summary TEXT NOT NULL,
  backfill INTEGER NOT NULL DEFAULT 0,
  seen_at_ms INTEGER,
  closed_by TEXT,
  close_note TEXT);
CREATE INDEX alerts_dedup ON alerts(dedup_key, opened_at_ms);
CREATE INDEX alerts_opened ON alerts(opened_at_ms);

CREATE TABLE alert_refs(
  alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
  ref_kind TEXT NOT NULL,
  ref_id TEXT NOT NULL,
  PRIMARY KEY(alert_id, ref_kind, ref_id)) WITHOUT ROWID;

CREATE TABLE notifications(
  notif_id TEXT PRIMARY KEY,
  alert_id TEXT NOT NULL REFERENCES alerts(alert_id),
  channel TEXT NOT NULL,
  state TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at_ms INTEGER NOT NULL,
  sent_at_ms INTEGER,
  last_error TEXT);
CREATE INDEX notif_pending ON notifications(state, created_at_ms);

CREATE TABLE audit_log(
  audit_id TEXT PRIMARY KEY,
  at_ms INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  object TEXT, detail TEXT, src_ip TEXT);
CREATE INDEX audit_time ON audit_log(at_ms);

CREATE TABLE settings(
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL);

CREATE TABLE enroll_tokens(
  token_hash TEXT PRIMARY KEY,
  created_at_ms INTEGER NOT NULL,
  used_at_ms INTEGER,
  used_by_agent TEXT);

CREATE VIEW v_flows AS
SELECT flow_uid, host_id, direction, remote_scope, origin, protocol, state, reply_seen,
       incomplete, close_reason, proc_comm, proc_path, dns_name,
       datetime(first_seen_at_ms/1000,'unixepoch') AS first_seen_utc,
       datetime(started_at_ms/1000,'unixepoch')    AS started_utc,
       datetime(last_seen_at_ms/1000,'unixepoch')  AS last_seen_utc,
       datetime(ended_at_ms/1000,'unixepoch')      AS ended_utc,
       local_ip, local_port, remote_ip, remote_port,
       orig_src_ip, orig_src_port, orig_dst_ip, orig_dst_port
FROM flows;

CREATE VIEW v_traffic_minute AS
SELECT host_id,
       datetime(bucket_start_ms/1000,'unixepoch') AS minute_utc,
       direction, remote_scope, bytes_out, bytes_in, samples
FROM traffic_1m;

CREATE VIEW v_contacts_in AS
SELECT host_id, protocol, local_port, remote_ip, remote_port, remote_scope,
       COUNT(*) AS flows,
       MIN(datetime(first_seen_at_ms/1000,'unixepoch')) AS first_utc,
       MAX(datetime(last_seen_at_ms/1000,'unixepoch'))  AS last_utc
FROM flows
WHERE direction = 'in'
GROUP BY host_id, protocol, local_port, remote_ip, remote_port, remote_scope;

CREATE VIEW v_contacts_out AS
SELECT host_id, protocol, remote_ip, remote_port, local_port, remote_scope,
       COUNT(*) AS flows,
       MIN(datetime(first_seen_at_ms/1000,'unixepoch')) AS first_utc,
       MAX(datetime(last_seen_at_ms/1000,'unixepoch'))  AS last_utc
FROM flows
WHERE direction = 'out'
GROUP BY host_id, protocol, remote_ip, remote_port, local_port, remote_scope;

CREATE VIEW v_no_reply AS
SELECT host_id, protocol, local_ip, local_port, remote_ip, remote_port, remote_scope,
       COUNT(*) AS flows,
       MIN(datetime(first_seen_at_ms/1000,'unixepoch')) AS first_utc,
       MAX(datetime(last_seen_at_ms/1000,'unixepoch'))  AS last_utc
FROM flows
WHERE reply_seen = 0
GROUP BY host_id, protocol, local_ip, local_port, remote_ip, remote_port, remote_scope;

CREATE VIEW v_blocked AS
SELECT host_id, protocol, direction, local_ip, local_port, remote_ip, remote_port,
       verdict, SUM(hits) AS hits,
       MIN(datetime(observed_at_ms/1000,'unixepoch')) AS first_utc,
       MAX(datetime(observed_at_ms/1000,'unixepoch')) AS last_utc
FROM firewall_events
GROUP BY host_id, protocol, direction, local_ip, local_port, remote_ip, remote_port, verdict;

CREATE VIEW v_gaps AS
SELECT host_id, agent_id, kind, lost_events, queue_bytes, note,
       datetime(observed_at_ms/1000,'unixepoch') AS observed_utc
FROM collector_health
WHERE (lost_events IS NOT NULL AND lost_events > 0) OR kind IN ('conntrack_gap','nflog_gap','nflog_error','dump_error','dns_error');

CREATE VIEW v_new_remote_24h AS
SELECT host_id, remote_ip, flows,
       datetime(first_seen_ms/1000,'unixepoch') AS first_utc
FROM remote_seen
WHERE first_seen_ms >= (strftime('%s','now') - 86400) * 1000;

CREATE VIEW v_own AS
SELECT host_id, protocol, local_port, remote_ip, remote_port,
       COUNT(*) AS flows,
       MIN(datetime(first_seen_at_ms/1000,'unixepoch')) AS first_utc,
       MAX(datetime(last_seen_at_ms/1000,'unixepoch'))  AS last_utc
FROM flows
WHERE remote_scope = 'own'
GROUP BY host_id, protocol, local_port, remote_ip, remote_port;

CREATE TABLE policy_rules(rule_id TEXT PRIMARY KEY,version INTEGER NOT NULL,sort_order INTEGER NOT NULL,payload TEXT NOT NULL);
