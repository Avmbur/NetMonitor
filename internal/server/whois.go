package server

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

var whoisDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout(network, address, timeout)
}

func parseWhoisRefer(body string) string {
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		low := strings.ToLower(line)
		var ref string
		switch {
		case strings.HasPrefix(low, "refer:"):
			ref = strings.TrimSpace(line[6:])
		case strings.HasPrefix(low, "whois:"):
			ref = strings.TrimSpace(line[6:])
		case strings.HasPrefix(low, "referralserver:"):
			ref = strings.TrimSpace(line[15:])
		}
		if ref == "" {
			continue
		}
		ref = strings.TrimPrefix(ref, "whois://")
		ref = strings.TrimPrefix(ref, "rwhois://")
		if i := strings.IndexByte(ref, '/'); i >= 0 {
			ref = ref[:i]
		}
		if i := strings.IndexByte(ref, ':'); i >= 0 {
			ref = ref[:i]
		}
		ref = strings.TrimSpace(ref)
		if ref != "" && !strings.EqualFold(ref, "whois.iana.org") {
			return strings.ToLower(ref)
		}
	}
	return ""
}

func whoisQuery(server, q string) (string, error) {
	c, err := whoisDial("tcp", net.JoinHostPort(server, "43"), 8*time.Second)
	if err != nil {
		return "", err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err = fmt.Fprintf(c, "%s\r\n", q); err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(c, 64<<10))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func lookupWhois(addr string) (string, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return "", fmt.Errorf("не адрес")
	}
	q := ip.Unmap().String()
	body, err := whoisQuery("whois.iana.org", q)
	if err != nil {
		return "", err
	}
	if ref := parseWhoisRefer(body); ref != "" {
		more, e := whoisQuery(ref, q)
		if e == nil && strings.TrimSpace(more) != "" {
			return more, nil
		}
	}
	if strings.TrimSpace(body) == "" {
		return "", fmt.Errorf("whois пуст")
	}
	return body, nil
}

func (s *Server) handleWhois(w http.ResponseWriter, r *http.Request) {
	addr := strings.TrimSpace(r.URL.Query().Get("addr"))
	if addr == "" {
		http.Error(w, "адрес", 400)
		return
	}
	text, err := lookupWhois(addr)
	if err != nil {
		writeJSON(w, map[string]string{"addr": addr, "text": err.Error()})
		return
	}
	writeJSON(w, map[string]string{"addr": addr, "text": text})
}

func (s *Server) handleDNSLookup(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if _, err := netip.ParseAddr(ip); err != nil {
		http.Error(w, "адрес", 400)
		return
	}
	db := &checkedRead{db: s.st.DB}
	name := s.lookupDNS(db, "", ip, "", 0)
	writeJSON(w, map[string]string{"ip": ip, "name": name})
}
