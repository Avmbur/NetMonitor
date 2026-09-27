package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Bundle struct {
	Dir       string
	CACert    *x509.Certificate
	CAKey     *ecdsa.PrivateKey
	CAPEM     []byte
	ServerTLS *tls.Certificate
}

func LoadOrCreateCA(dir string) (*Bundle, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	caCrt := filepath.Join(dir, "ca.crt")
	caKey := filepath.Join(dir, "ca.key")
	srvCrt := filepath.Join(dir, "server.crt")
	srvKey := filepath.Join(dir, "server.key")
	b := &Bundle{Dir: dir}
	if fileExists(caCrt) && fileExists(caKey) {
		cert, key, pemBytes, err := loadCertKey(caCrt, caKey)
		if err != nil {
			return nil, err
		}
		b.CACert, b.CAKey, b.CAPEM = cert, key, pemBytes
	} else {
		cert, key, pemBytes, err := createCA()
		if err != nil {
			return nil, err
		}
		if err := writeCertKey(caCrt, caKey, pemBytes, key); err != nil {
			return nil, err
		}
		b.CACert, b.CAKey, b.CAPEM = cert, key, pemBytes
	}
	if fileExists(srvCrt) && fileExists(srvKey) {
		tlsCert, err := tls.LoadX509KeyPair(srvCrt, srvKey)
		if err != nil {
			return nil, err
		}
		b.ServerTLS = &tlsCert
		return b, nil
	}
	tlsCert, err := b.IssueServer([]string{"localhost", "nmserver"}, []net.IP{net.ParseIP("127.0.0.1")})
	if err != nil {
		return nil, err
	}
	if err := writeTLSPair(srvCrt, srvKey, tlsCert); err != nil {
		return nil, err
	}
	b.ServerTLS = tlsCert
	return b, nil
}

func (b *Bundle) WriteServer(dns []string, ips []net.IP) error {
	seen := map[string]bool{}
	var all []net.IP
	for _, ip := range ips {
		if ip == nil {
			continue
		}
		s := ip.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		all = append(all, ip)
	}
	if !seen["127.0.0.1"] {
		all = append(all, net.ParseIP("127.0.0.1"))
	}
	names := append([]string{"localhost", "nmserver"}, dns...)
	if b.ServerTLS != nil {
		cert, err := x509.ParseCertificate(b.ServerTLS.Certificate[0])
		if err != nil {
			return err
		}
		matches := cert.NotAfter.After(time.Now().Add(24*time.Hour)) && cert.CheckSignatureFrom(b.CACert) == nil
		for _, ip := range all {
			if cert.VerifyHostname(ip.String()) != nil {
				matches = false
			}
		}
		for _, name := range names {
			if cert.VerifyHostname(name) != nil {
				matches = false
			}
		}
		if matches {
			return nil
		}
	}

	tlsCert, err := b.IssueServer(names, all)
	if err != nil {
		return err
	}
	if err := writeTLSPair(filepath.Join(b.Dir, "server.crt"), filepath.Join(b.Dir, "server.key"), tlsCert); err != nil {
		return err
	}
	b.ServerTLS = tlsCert
	return nil
}

func (b *Bundle) IssueServer(dns []string, ips []net.IP) (*tls.Certificate, error) {
	return b.issue("nmserver", dns, ips)
}

func (b *Bundle) IssueClient(cn string) (certPEM, keyPEM []byte, fp string, err error) {
	tlsCert, err := b.issue(cn, nil, nil)
	if err != nil {
		return nil, nil, "", err
	}
	certPEM, keyPEM, err = encodeTLS(tlsCert)
	if err != nil {
		return nil, nil, "", err
	}
	return certPEM, keyPEM, Fingerprint(tlsCert.Certificate[0]), nil
}

func (b *Bundle) issue(cn string, dns []string, ips []net.IP) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"NetMonitor"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     dns,
		IPAddresses:  ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, b.CACert, &key.PublicKey, b.CAKey)
	if err != nil {
		return nil, err
	}
	return tlsCertFromDER(der, key)
}

func Fingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

func ServerTLSConfig(b *Bundle) *tls.Config {
	pool := x509.NewCertPool()
	pool.AddCert(b.CACert)
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{*b.ServerTLS},
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		NextProtos:   []string{"http/1.1"},
	}
}

func ClientTLSConfig(caPEM, certPEM, keyPEM []byte) (*tls.Config, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("ca pem")
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: pool, NextProtos: []string{"http/1.1"}}
	if len(certPEM) > 0 {
		c, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{c}
	}
	return cfg, nil
}

func createCA() (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "netmonitor-ca", Organization: []string{"NetMonitor"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return cert, key, pemBytes, nil
}

func loadCertKey(crt, keyPath string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	pemBytes, err := os.ReadFile(crt)
	if err != nil {
		return nil, nil, nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, nil, nil, fmt.Errorf("ca crt pem")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	kb, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, nil, err
	}
	kblock, _ := pem.Decode(kb)
	if kblock == nil {
		return nil, nil, nil, fmt.Errorf("ca key pem")
	}
	key, err := x509.ParseECPrivateKey(kblock.Bytes)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, pemBytes, nil
}

func writeCertKey(crt, keyPath string, certPEM []byte, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(crt, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600)
}

func writeTLSPair(crt, keyPath string, c *tls.Certificate) error {
	certPEM, keyPEM, err := encodeTLS(c)
	if err != nil {
		return err
	}
	if err := os.WriteFile(crt, certPEM, 0o644); err != nil {
		return err
	}
	return os.WriteFile(keyPath, keyPEM, 0o600)
}

func encodeTLS(c *tls.Certificate) (certPEM, keyPEM []byte, err error) {
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
	switch k := c.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, nil, err
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	default:
		return nil, nil, fmt.Errorf("key type")
	}
	return certPEM, keyPEM, nil
}

func tlsCertFromDER(der []byte, key *ecdsa.PrivateKey) (*tls.Certificate, error) {
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
