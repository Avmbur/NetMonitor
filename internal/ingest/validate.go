package ingest

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"netmonitor/internal/protocol"
)

// ValidatePayload checks one event the same way a batch does, before any write.
func ValidatePayload(ev protocol.Event) error {
	return validatePayload(ev)
}

func validatePayload(ev protocol.Event) error {
	if raw := bytes.TrimSpace(ev.Payload); len(raw) == 0 || raw[0] != '{' || !json.Valid(raw) {
		return fmt.Errorf("payload must be a JSON object")
	}
	switch ev.Kind {
	case "flow":
		var p protocol.FlowPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return validateFlow(p)
	case "sample":
		var p protocol.SamplePayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if p.Flow != nil {
			if err := validateFlow(*p.Flow); err != nil {
				return err
			}
			if p.FlowUID != "" && p.FlowUID != p.Flow.FlowUID {
				return fmt.Errorf("sample flow_uid mismatch")
			}
		} else if p.FlowUID == "" {
			return fmt.Errorf("sample requires flow_uid")
		}
		if p.T0MS < 0 || p.T1MS <= p.T0MS {
			return fmt.Errorf("sample requires t1_ms > t0_ms >= 0")
		}
		if p.OrigBytesDelta < 0 || p.ReplyBytesDelta < 0 || p.OrigPacketsDelta < 0 || p.ReplyPacketsDelta < 0 {
			return fmt.Errorf("negative sample counters")
		}
		if p.Quality != "" && p.Quality != "ok" && p.Quality != "counter_reset" && p.Quality != "incomplete" {
			return fmt.Errorf("unknown sample quality")
		}
	case "health", "queue_drop":
		var p protocol.HealthPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if (p.LostEvents != nil && *p.LostEvents < 0) || (p.QueueBytes != nil && *p.QueueBytes < 0) {
			return fmt.Errorf("negative health counters")
		}
	case "dns":
		var p protocol.DNSPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if strings.TrimSpace(p.Name) == "" {
			return fmt.Errorf("DNS name is required")
		}
		return validIP(p.IP)
	case "firewall":
		var p protocol.FirewallPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if p.IPVersion != 4 && p.IPVersion != 6 {
			return fmt.Errorf("invalid IP version")
		}
		if p.Verdict != "drop" && p.Verdict != "reject" {
			return fmt.Errorf("invalid firewall verdict")
		}
		if err := validDirection(p.Direction); err != nil {
			return err
		}
		if p.Protocol == "" || p.Hits < 0 {
			return fmt.Errorf("invalid firewall protocol or hits")
		}
		if err := validPorts(p.LocalPort, p.RemotePort); err != nil {
			return err
		}
		if err := validIP(p.LocalIP); err != nil {
			return err
		}
		return validIP(p.RemoteIP)
	case "ssh":
		var p protocol.SSHPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		return validIP(p.RemoteIP)
	case "scan":
		var p protocol.ScanPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if err := validIP(p.IP); err != nil {
			return err
		}
		if len(p.Ports) == 0 {
			return fmt.Errorf("scan ports are required")
		}
		for _, port := range p.Ports {
			if port < 1 || port > 65535 {
				return fmt.Errorf("invalid scan port")
			}
		}
	case "question":
		var p protocol.QuestionPayload
		if err := json.Unmarshal(ev.Payload, &p); err != nil {
			return err
		}
		if err := validDirection(p.Direction); err != nil {
			return err
		}
		if p.Protocol == "" {
			return fmt.Errorf("question protocol is required")
		}
		if err := validPorts(&p.LocalPort, &p.RemotePort); err != nil {
			return err
		}
		return validIP(p.RemoteIP)
	default:
		return fmt.Errorf("unknown kind %s", ev.Kind)
	}
	return nil
}

func validateFlow(p protocol.FlowPayload) error {
	if p.FlowUID == "" || p.Protocol == "" {
		return fmt.Errorf("flow_uid and protocol are required")
	}
	if p.IPVersion != 4 && p.IPVersion != 6 {
		return fmt.Errorf("invalid IP version")
	}
	if p.FirstSeenMS < 0 || p.LastSeenMS < p.FirstSeenMS {
		return fmt.Errorf("invalid flow times")
	}
	if err := validDirection(p.Direction); err != nil {
		return err
	}
	for _, ip := range []string{p.OrigSrcIP, p.OrigDstIP, p.LocalIP, p.RemoteIP} {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return err
		}
		if a.Unmap().Is4() != (p.IPVersion == 4) {
			return fmt.Errorf("IP version mismatch")
		}
	}
	for _, counter := range []*int64{p.OrigBytes, p.ReplyBytes, p.OrigPackets, p.ReplyPackets} {
		if counter != nil && *counter < 0 {
			return fmt.Errorf("negative flow counter")
		}
	}
	return validPorts(p.OrigSrcPort, p.OrigDstPort, p.LocalPort, p.RemotePort)
}

func validIP(s string) error { _, err := netip.ParseAddr(s); return err }

func validDirection(s string) error {
	if s != "in" && s != "out" && s != "unknown" {
		return fmt.Errorf("invalid direction %q", s)
	}
	return nil
}

func validPorts(ports ...*int) error {
	for _, p := range ports {
		if p != nil && (*p < 0 || *p > 65535) {
			return fmt.Errorf("invalid port")
		}
	}
	return nil
}
