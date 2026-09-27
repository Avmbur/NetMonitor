package protocol

import (
	"encoding/json"
	"netmonitor/internal/policy"
)

type Batch struct {
	PendingFrom *int64  `json:"pending_from,omitempty"`
	Lane        string  `json:"lane,omitempty"`
	Events      []Event `json:"events"`
}

type Event struct {
	EventID      string          `json:"event_id"`
	Seq          int64           `json:"seq"`
	Kind         string          `json:"kind"`
	ObservedAtMS int64           `json:"observed_at_ms"`
	Payload      json.RawMessage `json:"payload"`
}

type Ack struct {
	Ack   []string `json:"ack"`
	Error string   `json:"error,omitempty"`
}

type EnrollReq struct {
	Token    string `json:"token"`
	Hostname string `json:"hostname"`
	BootID   string `json:"boot_id"`
	Version  string `json:"version"`
}

type EnrollRes struct {
	AgentID string `json:"agent_id"`
	HostID  string `json:"host_id"`
	CAPEM   string `json:"ca_pem"`
	CertPEM string `json:"cert_pem"`
	KeyPEM  string `json:"key_pem"`
	Monitor string `json:"monitor"`
}

type FlowPayload struct {
	ICMPType     *int   `json:"icmp_type"`
	ICMPCode     *int   `json:"icmp_code"`
	FlowUID      string `json:"flow_uid"`
	BootID       string `json:"boot_id"`
	CtID         *int64 `json:"ct_id"`
	StartedAtMS  *int64 `json:"started_at_ms"`
	FirstSeenMS  int64  `json:"first_seen_at_ms"`
	LastSeenMS   int64  `json:"last_seen_at_ms"`
	EndedAtMS    *int64 `json:"ended_at_ms"`
	IPVersion    int    `json:"ip_version"`
	Protocol     string `json:"protocol"`
	OrigSrcIP    string `json:"orig_src_ip"`
	OrigSrcPort  *int   `json:"orig_src_port"`
	OrigDstIP    string `json:"orig_dst_ip"`
	OrigDstPort  *int   `json:"orig_dst_port"`
	ReplySrcIP   string `json:"reply_src_ip,omitempty"`
	ReplyDstIP   string `json:"reply_dst_ip,omitempty"`
	Direction    string `json:"direction"`
	LocalIP      string `json:"local_ip"`
	LocalPort    *int   `json:"local_port"`
	RemoteIP     string `json:"remote_ip"`
	RemotePort   *int   `json:"remote_port"`
	RemoteScope  string `json:"remote_scope"`
	Origin       string `json:"origin"`
	State        string `json:"state,omitempty"`
	ReplySeen    int    `json:"reply_seen"`
	CloseReason  string `json:"close_reason,omitempty"`
	OrigBytes    *int64 `json:"orig_bytes"`
	ReplyBytes   *int64 `json:"reply_bytes"`
	OrigPackets  *int64 `json:"orig_packets"`
	ReplyPackets *int64 `json:"reply_packets"`
	ProcPath     string `json:"proc_path,omitempty"`
	ProcUID      *int   `json:"proc_uid"`
	ProcCgroup   string `json:"proc_cgroup,omitempty"`
	ProcComm     string `json:"proc_comm,omitempty"`
	DNSName      string `json:"dns_name,omitempty"`
	Incomplete   int    `json:"incomplete"`
	NS           string `json:"ns,omitempty"`
	Zone         string `json:"zone,omitempty"`
}

type SamplePayload struct {
	FlowUID           string       `json:"flow_uid"`
	T0MS              int64        `json:"t0_ms"`
	T1MS              int64        `json:"t1_ms"`
	OrigBytesDelta    int64        `json:"orig_bytes_delta"`
	ReplyBytesDelta   int64        `json:"reply_bytes_delta"`
	OrigPacketsDelta  int64        `json:"orig_packets_delta"`
	ReplyPacketsDelta int64        `json:"reply_packets_delta"`
	Quality           string       `json:"quality"`
	Direction         string       `json:"direction"`
	RemoteScope       string       `json:"remote_scope"`
	Incomplete        int          `json:"incomplete"`
	Flow              *FlowPayload `json:"flow,omitempty"`
}

type ListenPort struct {
	Proto string `json:"proto"`
	Proc  string `json:"proc,omitempty"`
	Desc  string `json:"desc,omitempty"`
	Port  int    `json:"port"`
}

type HealthPayload struct {
	Addresses  []string     `json:"addresses,omitempty"`
	OpenPorts  *int         `json:"open_ports,omitempty"`
	SSHPort    *int         `json:"ssh_port,omitempty"`
	SSHPorts   []int        `json:"ssh_ports,omitempty"`
	Listeners  []ListenPort `json:"listeners,omitempty"`
	BootID     string       `json:"boot_id,omitempty"`
	FWBackend  string       `json:"fw_backend,omitempty"`
	ScopeNote  string       `json:"scope_note,omitempty"`
	Version    string       `json:"version,omitempty"`
	Kind       string       `json:"kind"`
	LostEvents *int64       `json:"lost_events"`
	QueueBytes *int64       `json:"queue_bytes"`
	Note       string       `json:"note,omitempty"`
	CPUPct     *int         `json:"cpu_pct,omitempty"`
	RAMPct     *int         `json:"ram_pct,omitempty"`
	DiskPct    *int         `json:"disk_pct,omitempty"`
}

type DNSPayload struct {
	Name string `json:"name"`
	IP   string `json:"ip"`
	Kind string `json:"kind,omitempty"`
}

type FirewallPayload struct {
	GroupID     string `json:"group_id,omitempty"`
	IPVersion   int    `json:"ip_version"`
	Protocol    string `json:"protocol"`
	Direction   string `json:"direction"`
	LocalIP     string `json:"local_ip"`
	LocalPort   *int   `json:"local_port"`
	RemoteIP    string `json:"remote_ip"`
	RemotePort  *int   `json:"remote_port"`
	RemoteScope string `json:"remote_scope"`
	Verdict     string `json:"verdict"`
	Chain       string `json:"chain"`
	RuleTag     string `json:"rule_tag"`
	InIface     string `json:"in_iface"`
	Hits        int    `json:"hits"`
}

type SSHPayload struct {
	RemoteIP     string `json:"remote_ip"`
	User         string `json:"user_name"`
	Note         string `json:"note"`
	ObservedAtMS int64  `json:"observed_at_ms,omitempty"`
}

type ScanAttempt struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
}
type ScanPayload struct {
	Attempts []ScanAttempt `json:"attempts,omitempty"`
	IP       string        `json:"ip"`
	Ports    []int         `json:"ports"`
}

type ApplyStatus struct {
	Backend    string   `json:"backend"`
	DesiredRev int64    `json:"desired_rev"`
	AppliedRev *int64   `json:"applied_rev"`
	Error      string   `json:"error,omitempty"`
	CommandIDs []string `json:"command_ids,omitempty"`
}

type PollReq struct {
	Status       *ApplyStatus `json:"status,omitempty"`
	Rev          int64        `json:"rev"`
	Ack          []string     `json:"ack"`
	ConsumedOnce []string     `json:"consumed_once,omitempty"`
}

type PollRes struct {
	Model         int           `json:"model"`
	Rules         []policy.Rule `json:"rules"`
	Groups        []policy.Rule `json:"groups"`
	LocalPauses   []string      `json:"local_pauses"`
	Authorized    bool          `json:"authorized"`
	PolicyRev     int64         `json:"policy_rev"`
	Commands      []Command     `json:"commands"`
	Blocks        []BlockView   `json:"blocks"`
	NeverBlock    []string      `json:"never_block"`
	BlockNets     []string      `json:"block_nets"`
	AllowNets     []string      `json:"allow_nets"`
	LAN           []string      `json:"lan,omitempty"`
	Own           []string      `json:"own,omitempty"`
	Mode          string        `json:"mode"`
	Full          bool          `json:"full"`
	ObserveDocker bool          `json:"observe_docker,omitempty"`
	ScanPorts     int           `json:"scan_ports,omitempty"`
	ScanWindowMS  int64         `json:"scan_window_ms,omitempty"`
}

type QuestionPayload struct {
	Direction  string `json:"direction"`
	Protocol   string `json:"protocol"`
	RemoteIP   string `json:"remote_ip"`
	RemotePort int    `json:"remote_port"`
	LocalPort  int    `json:"local_port"`
	DNSName    string `json:"dns_name"`
	ProcComm   string `json:"proc_comm"`
	ProcPath   string `json:"proc_path"`
	DedupKey   string `json:"dedup_key"`
	Repeats    int    `json:"repeats,omitempty"`
}

type Command struct {
	ID      string `json:"command_id"`
	Kind    string `json:"kind"`
	Payload string `json:"payload"`
	BlockID string `json:"block_id,omitempty"`
}

type BlockView struct {
	LocalPort int    `json:"local_port,omitempty"`
	BlockID   string `json:"block_id"`
	RemoteIP  string `json:"remote_ip"`
	Protocol  string `json:"protocol,omitempty"`
	Port      int    `json:"port,omitempty"`
	Direction string `json:"direction"`
	ExpiresAt int64  `json:"expires_at_ms"`
	State     string `json:"state"`
}

type LocalUnblock struct {
	RequestID string   `json:"request_id"`
	BlockIDs  []string `json:"block_ids"`
	// rollback — откат своего бана в первую минуту без связи. Пустая причина
	// бан не отключает: монитор ставит его снова.
	Reason string `json:"reason,omitempty"`
}
