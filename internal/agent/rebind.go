package agent

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"netmonitor/internal/tlsutil"
)

// rebindIfReplaced просит монитор с тем же центром сертификации выдать новый ключ.
// Чужой сервер не принимается: соединение проверяется сохранённым ca.crt.
// Отпечаток из ответа должен совпасть с ключом, который только что проверил TLS.
func (a *Agent) rebindIfReplaced() error {
	cl, seen, err := a.rebindClient()
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{
		"hostname": hostname(),
		"agent_id": a.id,
	})
	req, err := http.NewRequest(http.MethodPost, a.monitorURL()+"/v1/rebind", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := cl.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("rebind %s: %s", res.Status, raw)
	}
	var out struct {
		Status string `json:"status"`
		Pin    string `json:"pin"`
		Token  string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if out.Status != "ready" || out.Pin == "" || out.Token == "" {
		return fmt.Errorf("ждёт переподключения")
	}
	if seen.cert == nil {
		return fmt.Errorf("нет сертификата монитора")
	}
	got, err := tlsutil.PublicKeyPin(seen.cert.Raw)
	if err != nil {
		return err
	}
	if got != out.Pin {
		return fmt.Errorf("отпечаток не от проверенного монитора")
	}
	a.cfg.Pin = out.Pin
	a.cfg.Token = out.Token
	a.cfg.ForceEnroll = true
	a.presentCert = true
	return a.enroll()
}

type seenCert struct {
	cert *x509.Certificate
}

func (a *Agent) rebindClient() (*http.Client, *seenCert, error) {
	dir := filepath.Join(a.cfg.DataDir, "tls")
	caPEM, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		return nil, nil, err
	}
	crt, err := os.ReadFile(filepath.Join(dir, "client.crt"))
	if err != nil {
		return nil, nil, err
	}
	key, err := os.ReadFile(filepath.Join(dir, "client.key"))
	if err != nil {
		return nil, nil, err
	}
	cfg, err := tlsutil.ClientTLSConfig(caPEM, crt, key)
	if err != nil {
		return nil, nil, err
	}
	if host, _, err := parseMonitor(a.cfg.Monitor); err == nil && host != "" {
		cfg.ServerName = host
	}
	seen := &seenCert{}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("нет сертификата монитора")
		}
		seen.cert = cs.PeerCertificates[0]
		return nil
	}
	cl := &http.Client{Transport: &http.Transport{
		TLSClientConfig:     cfg,
		ForceAttemptHTTP2:   false,
		TLSHandshakeTimeout: 8 * time.Second,
	}, Timeout: 12 * time.Second}
	return cl, seen, nil
}

func (a *Agent) clientPair() (tls.Certificate, error) {
	dir := filepath.Join(a.cfg.DataDir, "tls")
	crt, err := os.ReadFile(filepath.Join(dir, "client.crt"))
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := os.ReadFile(filepath.Join(dir, "client.key"))
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(crt, key)
}
