package tlsutil

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
)

func PublicKeyPin(der []byte) (string, error) {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return "sha256//" + base64.StdEncoding.EncodeToString(sum[:]), nil
}

// Bootstrap authenticates a key supplied by the administrator's installation
// context. After enrollment the agent uses the returned CA with normal TLS.
func PinnedTLSConfig(pin string) (*tls.Config, error) {
	if !strings.HasPrefix(pin, "sha256//") {
		return nil, fmt.Errorf("нужен отпечаток ключа монитора --pin")
	}
	want, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pin, "sha256//"))
	if err != nil || len(want) != sha256.Size {
		return nil, fmt.Errorf("неверный SHA256 pin")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, InsecureSkipVerify: true}
	cfg.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return fmt.Errorf("monitor certificate missing")
		}
		got := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return fmt.Errorf("ключ монитора не совпадает с установочным отпечатком")
		}
		return nil
	}
	return cfg, nil
}
