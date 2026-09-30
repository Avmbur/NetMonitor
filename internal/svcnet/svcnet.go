// Package svcnet — HTTPS служб NetMonitor к адресам обновления. Адрес попадает
// в фильтр до соединения: служба сама резолвит имя, вписывает адреса в набор
// правила «служебные · обновления» и соединяется ровно с ними.
package svcnet

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"netmonitor/internal/netipx"
)

// UpdateRuleID — служебное правило, которое пускает эти соединения.
const UpdateRuleID = "park-svc-update"

// UpdateHosts — куда ходят проверка релиза и скачивание комплекта: API, ссылка
// на файл релиза и хранилище файлов, куда GitHub переадресует. objects — прежнее
// имя хранилища, GitHub им ещё пользуется.
var UpdateHosts = []string{
	"api.github.com",
	"github.com",
	"release-assets.githubusercontent.com",
	"objects.githubusercontent.com",
}

// AdmitTTL — срок адреса в фильтре. Правило проверяет каждый пакет, поэтому
// срок длиннее любого таймаута клиента: скачивание не рвётся посередине.
const AdmitTTL = 24 * time.Hour

// AdmitKind — команда монитора своему агенту: вписать адреса в набор.
const AdmitKind = "svc-admit"

// AdmitPayload — содержимое команды AdmitKind.
type AdmitPayload struct {
	IPs   []string `json:"ips"`
	TTLMS int64    `json:"ttl_ms"`
}

// maxAdmit ограничивает одну команду: ответ DNS больше не бывает.
const maxAdmit = 32

// AdmitFunc вписывает адреса в фильтр. Ошибка — соединения не будет.
type AdmitFunc func(ctx context.Context, ips []netip.Addr) error

// lookup резолвит имя. Тесты подменяют.
var lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// dial соединяется с уже выбранным адресом. Тесты подменяют.
var dial = func(ctx context.Context, addr string) (net.Conn, error) {
	d := net.Dialer{Timeout: 15 * time.Second}
	return d.DialContext(ctx, "tcp", addr)
}

func Allowed(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, h := range UpdateHosts {
		if host == h {
			return true
		}
	}
	return false
}

// Client — HTTP-клиент только к UpdateHosts по HTTPS на 443, включая каждую
// переадресацию. Сертификат проверяется как обычно, по имени из адреса.
func Client(admit AdmitFunc, timeout time.Duration) *http.Client {
	tr := &http.Transport{
		Proxy:               nil,
		DialContext:         dialer(admit),
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: 15 * time.Second,
		// Новое соединение — новый резолв и новый срок в фильтре.
		DisableKeepAlives: true,
	}
	return &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: checkRedirect}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return fmt.Errorf("github: слишком много переадресаций")
	}
	if req.URL.Scheme != "https" || req.URL.Port() != "" && req.URL.Port() != "443" || !Allowed(req.URL.Hostname()) {
		return fmt.Errorf("github: переадресация на чужой адрес %s", req.URL.Host)
	}
	return nil
}

func dialer(admit AdmitFunc) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, _, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if port != "443" || !Allowed(host) {
			return nil, fmt.Errorf("github: чужой адрес %s", addr)
		}
		return admitDial(ctx, host, admit, "github")
	}
}

// ImportClient — для импорта списка группы по ссылке, которую задал админ.
// Имя любое; адрес HTTPS-ссылки вписывается в фильтр до соединения, как у
// GitHub. Прочие порты служебное правило и раньше не пускало: там как было.
func ImportClient(admit AdmitFunc, timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DisableKeepAlives = true
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if port == "443" && admit != nil {
			ip, e := netip.ParseAddr(host)
			if e != nil {
				return admitDial(ctx, host, admit, "импорт")
			}
			if netipx.UsableNameIP(ip) {
				if err := admit(ctx, []netip.Addr{ip.Unmap()}); err != nil {
					return nil, fmt.Errorf("импорт: адрес %s не вписан в фильтр: %w", host, err)
				}
			}
		}
		return dial(ctx, addr)
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

// admitDial резолвит имя, вписывает адреса в фильтр и соединяется ровно с ними.
func admitDial(ctx context.Context, host string, admit AdmitFunc, who string) (net.Conn, error) {
	found, err := lookup(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("%s: имя %s: %w", who, host, err)
	}
	var ips []netip.Addr
	seen := map[netip.Addr]bool{}
	for _, ip := range found {
		ip = ip.Unmap()
		if !netipx.UsableNameIP(ip) || seen[ip] {
			continue
		}
		seen[ip] = true
		ips = append(ips, ip)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%s: у имени %s нет адреса", who, host)
	}
	if len(ips) > maxAdmit {
		ips = ips[:maxAdmit]
	}
	if admit != nil {
		if err := admit(ctx, ips); err != nil {
			return nil, fmt.Errorf("%s: адрес %s не вписан в фильтр: %w", who, host, err)
		}
	}
	var last error
	for _, ip := range ips {
		c, err := dial(ctx, netip.AddrPortFrom(ip, 443).String())
		if err == nil {
			return c, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

// Payload собирает команду для агента.
func Payload(ips []netip.Addr) (string, error) {
	p := AdmitPayload{TTLMS: AdmitTTL.Milliseconds()}
	for _, ip := range ips {
		p.IPs = append(p.IPs, ip.Unmap().String())
	}
	raw, err := json.Marshal(p)
	return string(raw), err
}

// ParsePayload проверяет команду монитора: только годные адреса и разумный срок.
func ParsePayload(raw string) ([]netip.Addr, time.Duration, error) {
	var p AdmitPayload
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return nil, 0, fmt.Errorf("svc-admit: %w", err)
	}
	if len(p.IPs) == 0 || len(p.IPs) > maxAdmit {
		return nil, 0, fmt.Errorf("svc-admit: адресов %d", len(p.IPs))
	}
	ttl := time.Duration(p.TTLMS) * time.Millisecond
	if ttl < time.Minute || ttl > 2*AdmitTTL {
		return nil, 0, fmt.Errorf("svc-admit: срок %s", ttl)
	}
	var out []netip.Addr
	for _, s := range p.IPs {
		ip, err := netip.ParseAddr(s)
		if err != nil || ip.Zone() != "" || !netipx.UsableNameIP(ip) {
			return nil, 0, fmt.Errorf("svc-admit: адрес %q", s)
		}
		out = append(out, ip.Unmap())
	}
	return out, ttl, nil
}
