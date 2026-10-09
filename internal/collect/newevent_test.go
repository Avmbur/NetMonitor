package collect

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
)

// A kernel that omits CTA_TIMESTAMP in the NEW event must not turn every flow
// into an incomplete one with a random flow_uid tail.
func TestNewEventWithoutKernelTimestamp(t *testing.T) {
	st := NewMem()
	src := netip.MustParseAddr("192.168.10.180")
	dst := netip.MustParseAddr("1.1.1.1")
	sp, dp := 40100, 443
	ct := int64(7788)
	e := Entry{IPVersion: 4, Protocol: "tcp", State: "SYN_SENT", OrigSrc: src, OrigDst: dst,
		OrigSport: &sp, OrigDport: &dp, CTID: &ct, Unreplied: true}
	opt := DumpOpts{HostID: "h", BootID: "b", Local: []netip.Addr{src}, NowMS: 1_700_000_000_000, MonoMS: 1000}
	if err := st.ApplyEvent(e, "new", opt); err != nil {
		t.Fatal(err)
	}
	var payload string
	payload = eventPayload(t, st, "flow", false)
	var fp struct {
		FlowUID     string `json:"flow_uid"`
		Incomplete  int    `json:"incomplete"`
		StartedAtMS *int64 `json:"started_at_ms"`
	}
	if err := json.Unmarshal([]byte(payload), &fp); err != nil {
		t.Fatal(err)
	}
	if fp.Incomplete != 0 {
		t.Fatal("NEW without kernel timestamp marked incomplete:", payload)
	}
	if fp.StartedAtMS == nil || *fp.StartedAtMS != opt.NowMS {
		t.Fatal("start of the flow lost:", payload)
	}
	if !strings.HasSuffix(fp.FlowUID, "/7788/1700000000000000000") {
		t.Fatal("flow_uid is not derived from the conntrack id:", fp.FlowUID)
	}
	// A later dump must stay the same flow, not a second one.
	e2 := e
	e2.State = "ESTABLISHED"
	e2.CountersKnown = true
	e2.OrigBytes, e2.ReplyBytes = 120, 80
	opt.NowMS += 15000
	opt.MonoMS += 15000
	if err := st.ApplyDump([]Entry{e2}, opt); err != nil {
		t.Fatal(err)
	}
	uids := map[string]bool{}
	for _, p := range events(t, st, "flow") {
		var f struct {
			FlowUID string `json:"flow_uid"`
		}
		json.Unmarshal(p, &f)
		uids[f.FlowUID] = true
	}
	if len(uids) != 1 {
		t.Fatal("the same flow got several uids:", uids)
	}
}
