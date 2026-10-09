package server

import (
	"crypto/tls"
	"net"

	"netmonitor/internal/store"
	"netmonitor/internal/tlsutil"
)

// formerAgent — агент, который сам постучался после смены сертификата монитора.
type formerAgent struct {
	IP   string `json:"ip"`
	Name string `json:"name,omitempty"`
	FP   string `json:"-"`
	At   int64  `json:"at"`
}

func (s *Server) listenTLS(addr string) (net.Listener, error) {
	return tls.Listen("tcp", addr, tlsutil.ServerTLSConfig(s.bundle))
}

func (s *Server) noteFormer(ip, name, fp string) {
	ip = hostOnly(ip)
	if ip == "" {
		return
	}
	s.knockMu.Lock()
	defer s.knockMu.Unlock()
	if s.knocks == nil {
		s.knocks = map[string]formerAgent{}
	}
	prev := s.knocks[ip]
	if name == "" {
		name = prev.Name
	}
	if fp == "" {
		fp = prev.FP
	}
	s.knocks[ip] = formerAgent{IP: ip, Name: name, FP: fp, At: store.NowMS()}
	if len(s.knocks) <= 30 {
		return
	}
	var oldest string
	var at int64
	for ip, row := range s.knocks {
		if oldest == "" || row.At < at {
			oldest = ip
			at = row.At
		}
	}
	delete(s.knocks, oldest)
}

func (s *Server) dropFormer(fp string) {
	if fp == "" {
		return
	}
	s.knockMu.Lock()
	defer s.knockMu.Unlock()
	delete(s.rebindTok, fp)
	for ip, row := range s.knocks {
		if row.FP == fp {
			delete(s.knocks, ip)
		}
	}
}

func (s *Server) formerByIP(ip string) (formerAgent, bool) {
	s.knockMu.Lock()
	defer s.knockMu.Unlock()
	row, ok := s.knocks[ip]
	return row, ok
}

func (s *Server) formerAgents() []formerAgent {
	s.knockMu.Lock()
	defer s.knockMu.Unlock()
	out := make([]formerAgent, 0, len(s.knocks))
	for _, row := range s.knocks {
		out = append(out, row)
	}
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j].At > out[j-1].At {
			out[j], out[j-1] = out[j-1], out[j]
			j--
		}
	}
	return out
}

func hostOnly(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
