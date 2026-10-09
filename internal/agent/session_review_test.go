package agent

import (
	"testing"

	"netmonitor/internal/collect"
	"netmonitor/internal/protocol"
)

// Вопрос лежит в базе агента и при известном сеансе тоже доходит до монитора.
func TestSessionDeliversDiskQuestion(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s1")
	got := serveBatches(t, a, nil)
	if err := a.Enqueue("question", 7, protocol.QuestionPayload{Direction: "out", Protocol: "tcp", RemoteIP: "203.0.113.9", RemotePort: 443}); err != nil {
		t.Fatal(err)
	}
	if err := a.flushLane("urgent"); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, ev := range *got {
		if ev.Kind == "question" {
			found = true
		}
	}
	if !found {
		t.Fatalf("question not sent: %d events", len(*got))
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM outbox WHERE kind='question'`); n != 0 {
		t.Fatalf("question left on disk %d", n)
	}
}

// Новый процесс агента в том же сеансе монитора нумерует события выше прежнего.
func TestSessionSeqGrowsAcrossRestart(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s1")
	if err := a.Enqueue("sample", 0, map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	first := a.plan.copy()[0].seq
	b, st2, _ := newSpool(t)
	defer st2.Close()
	b.adoptSession("s1")
	if err := b.Enqueue("sample", 0, map[string]int{"n": 2}); err != nil {
		t.Fatal(err)
	}
	if next := b.plan.copy()[0].seq; next <= first {
		t.Fatalf("restart seq %d not above %d", next, first)
	}
}

// Сканы и вопросы дампа при известном сеансе: скан в памяти, вопрос в базе.
func TestSessionDumpNotesSplit(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s1")
	err := a.enqueueAll([]outItem{
		{kind: "scan", pri: 9, payload: protocol.ScanPayload{IP: "203.0.113.7", Ports: []int{1, 2, 3, 4, 5}}},
		{kind: "question", pri: 7, payload: protocol.QuestionPayload{Direction: "in", Protocol: "tcp", RemoteIP: "203.0.113.7", LocalPort: 22}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM outbox WHERE kind='scan'`); n != 0 {
		t.Fatalf("scan on disk %d", n)
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM outbox WHERE kind='question'`); n != 1 {
		t.Fatalf("question on disk %d", n)
	}
}

// Пока монитор недоступен, очередь памяти не растёт без предела.
func TestSessionPlanBounded(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s1")
	big := make([]byte, 64<<10)
	for i := range big {
		big[i] = 'x'
	}
	for i := 0; i < 1000; i++ {
		if err := a.Enqueue("sample", 0, map[string]string{"pad": string(big)}); err != nil {
			t.Fatal(err)
		}
	}
	if sz := a.plan.size(); sz > planMemLimit {
		t.Fatalf("plan %d above %d", sz, planMemLimit)
	}
}

// Снимок нового сеанса монитора шлёт и тихое соединение без перемен.
func TestSessionDumpResendsQuietFlow(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s1")
	dumpBytes(t, a, 100, 1000)
	a.plan = &planQueue{}
	e, opt := spoolObservation(100, 2000)
	if err := a.collectMem(func(book *collect.Mem) error { return book.ApplyDump([]collect.Entry{e}, opt) }); err != nil {
		t.Fatal(err)
	}
	for _, it := range a.plan.copy() {
		if it.kind == "flow" {
			t.Fatal("quiet flow sent by ordinary dump")
		}
	}
	opt.Resend = true
	opt.NowMS, opt.MonoMS = 3000, 3000
	if err := a.collectMem(func(book *collect.Mem) error { return book.ApplyDump([]collect.Entry{e}, opt) }); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, it := range a.plan.copy() {
		if it.kind == "flow" {
			found = true
		}
	}
	if !found {
		t.Fatal("resend dump skipped quiet flow")
	}
}

// Плановый сброс при известном сеансе телеметрию на диск не кладёт.
func TestSessionFlushSpoolKeepsTelemetryOffDisk(t *testing.T) {
	a, st, _ := newSpool(t)
	defer st.Close()
	a.adoptSession("s1")
	if err := a.Enqueue("sample", 0, map[string]int{"n": 1}); err != nil {
		t.Fatal(err)
	}
	if n := countSQL(t, st.DB, `SELECT COUNT(*) FROM outbox`); n != 0 {
		t.Fatalf("outbox %d", n)
	}
}
