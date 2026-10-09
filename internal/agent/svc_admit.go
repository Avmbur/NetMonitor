package agent

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"netmonitor/internal/fw"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/svcnet"
)

// admitAddrs вписывает адреса «по запросу» в фильтр. Тесты подменяют.
var admitAddrs = fw.Admit

// svcAdmitted — те же адреса со сроком, для проверки вопроса: фильтр их
// пропускает, значит и вопроса по ним быть не должно.
var svcAdmitted = struct {
	sync.Mutex
	until map[netip.Addr]int64
}{until: map[netip.Addr]int64{}}

func noteAdmitted(ips []netip.Addr, ttl time.Duration) {
	until := store.NowMS() + ttl.Milliseconds()
	svcAdmitted.Lock()
	defer svcAdmitted.Unlock()
	for _, ip := range ips {
		svcAdmitted.until[ip.Unmap()] = until
	}
}

// admittedNow — адреса, срок которых ещё не истёк. Истёкшие забываются.
func admittedNow(now int64) []netip.Addr {
	svcAdmitted.Lock()
	defer svcAdmitted.Unlock()
	var out []netip.Addr
	for ip, until := range svcAdmitted.until {
		if until <= now {
			delete(svcAdmitted.until, ip)
			continue
		}
		out = append(out, ip)
	}
	return out
}

// Report absolute expiries so retries and monitor restarts cannot renew admission.
func admittedReport(now int64) []protocol.ServiceAdmission {
	svcAdmitted.Lock()
	defer svcAdmitted.Unlock()
	var out []protocol.ServiceAdmission
	for ip, until := range svcAdmitted.until {
		if until <= now {
			delete(svcAdmitted.until, ip)
			continue
		}
		out = append(out, protocol.ServiceAdmission{IP: ip.String(), UntilMS: until})
	}
	return out
}

func admit(ips []netip.Addr, ttl time.Duration) error {
	if err := admitAddrs(ips, ttl); err != nil {
		return err
	}
	noteAdmitted(ips, ttl)
	return nil
}

// admitLocal — для своего скачивания: срок по умолчанию.
func (a *Agent) admitLocal(_ context.Context, ips []netip.Addr) error {
	if err := admit(ips, svcnet.AdmitTTL); err != nil {
		return err
	}
	// Report before connecting, even while the usual poll is executing an update.
	// Rev -1 returns immediately on both old and new monitors.
	_, err := a.exchangePoll(protocol.PollReq{Rev: -1})
	return err
}

// admitCommand выполняет просьбу монитора вписать адреса его службы. Без
// успеха команда не подтверждается, и монитор не соединяется вслепую.
func admitCommand(payload string) error {
	ips, ttl, err := svcnet.ParsePayload(payload)
	if err != nil {
		return err
	}
	return admit(ips, ttl)
}
