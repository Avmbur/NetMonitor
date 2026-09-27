package server

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"netmonitor/deploy"
	"netmonitor/internal/tlsutil"
	"os"
	"path/filepath"
	"strings"
)

func installCmd(endpoint, pin, token string) string {
	// The entire function is downloaded before its final invocation is parsed.
	return fmt.Sprintf("curl -fsSk --pinnedpubkey %s %s | sudo sh -s -- --monitor %s --pin %s --token %s", shellQuote(pin), shellQuote("https://"+endpoint+"/install/agent.sh"), shellQuote(endpoint), shellQuote(pin), shellQuote(token))
}
func (s *Server) installationCommand(token, requestHost string) (string, error) {
	host := s.cfg.ListenHost
	if host == "" || host == "0.0.0.0" || host == "::" {
		var err error
		host, _, err = net.SplitHostPort(requestHost)
		if err != nil {
			return "", fmt.Errorf("нужен адрес монитора с портом")
		}
		if net.ParseIP(host) == nil {
			return "", fmt.Errorf("для wildcard bind нужен IP монитора")
		}
	}
	pin, err := tlsutil.PublicKeyPin(s.bundle.ServerTLS.Certificate[0])
	if err != nil {
		return "", err
	}
	return installCmd(net.JoinHostPort(host, fmt.Sprint(s.cfg.ListenPort)), pin, token), nil
}
func (s *Server) installAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("asset")
	if name == "agent.sh" {
		w.Header().Set("Content-Type", "text/x-shellscript")
		w.Write([]byte(deploy.AgentInstaller))
		return
	}
	if name != "nmagent-linux-amd64" && name != "nmagent-linux-arm64" {
		http.NotFound(w, r)
		return
	}
	// The installation bundle owns this directory; never serve data or key paths.
	root := s.cfg.ArtifactDir
	if root == "" {
		root = "/usr/local/lib/netmonitor"
	}
	path := filepath.Join(root, name)
	if st, err := os.Stat(path); err != nil || !st.Mode().IsRegular() {
		http.Error(w, "пакет агента не установлен на мониторе", 503)
		return
	}
	http.ServeFile(w, r, path)
}
func privateWeb(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/ui/") {
			host, _, err := net.SplitHostPort(r.RemoteAddr)
			ip, e := netip.ParseAddr(host)
			if err != nil || e != nil || !(ip.Unmap().IsPrivate() || ip.Unmap().IsLoopback()) {
				http.Error(w, "интерфейс доступен из LAN/VPN", 403)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
