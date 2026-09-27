package server

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseWhoisRefer(t *testing.T) {
	s := "refer:        whois.ripe.net\n"
	if got := parseWhoisRefer(s); got != "whois.ripe.net" {
		t.Fatal(got)
	}
	s = "ReferralServer: whois://whois.arin.net:43\n"
	if got := parseWhoisRefer(s); got != "whois.arin.net" {
		t.Fatal(got)
	}
	if parseWhoisRefer("refer: whois.iana.org\n") != "" {
		t.Fatal("iana loop")
	}
}

func TestLookupWhoisFollowsRefer(t *testing.T) {
	orig := whoisDial
	t.Cleanup(func() { whoisDial = orig })
	whoisDial = func(network, address string, timeout time.Duration) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			defer b.Close()
			_, _ = bufio.NewReader(b).ReadString('\n')
			if strings.Contains(address, "iana") {
				io.WriteString(b, "refer: whois.ripe.net\n")
			} else {
				io.WriteString(b, "inetnum: 8.8.8.0/24\norg-name: Test Org\n")
			}
		}()
		return a, nil
	}
	got, err := lookupWhois("8.8.8.8")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "Test Org") {
		t.Fatal(got)
	}
}

func TestLookupWhoisRejectsHost(t *testing.T) {
	if _, err := lookupWhois("example.com"); err == nil {
		t.Fatal("expected error")
	}
}

func TestLookupDNSFromSeen(t *testing.T) {
	s, _ := batchFixture(t)
	if _, err := s.st.DB.Exec(`INSERT INTO dns_seen(host_id,name,ip_bin,ip,first_seen_ms,last_seen_ms) VALUES('h','ntp.ubuntu.com',zeroblob(16),'185.125.190.36',1,2)`); err != nil {
		t.Fatal(err)
	}
	db := &checkedRead{db: s.st.DB}
	if got := lookupDNS(db, "h", "185.125.190.36", "", 0); got != "ntp.ubuntu.com" {
		t.Fatal(got)
	}
	if got := lookupDNS(db, "", "185.125.190.36", "", 0); got != "ntp.ubuntu.com" {
		t.Fatal(got)
	}
}
