package agent

import (
	"context"
	"net/netip"

	"netmonitor/internal/fw"
	"netmonitor/internal/svcnet"
)

// admitAddrs вписывает адреса «по запросу» в фильтр. Тесты подменяют.
var admitAddrs = fw.Admit

// admitLocal — для своего скачивания: срок по умолчанию.
func admitLocal(_ context.Context, ips []netip.Addr) error {
	return admitAddrs(ips, svcnet.AdmitTTL)
}

// admitCommand выполняет просьбу монитора вписать адреса его службы. Без
// успеха команда не подтверждается, и монитор не соединяется вслепую.
func admitCommand(payload string) error {
	ips, ttl, err := svcnet.ParsePayload(payload)
	if err != nil {
		return err
	}
	return admitAddrs(ips, ttl)
}
