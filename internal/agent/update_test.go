package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"testing"
)

func TestUpdateURLAndArchive(t *testing.T) {
	if err := allowedReleaseURL("https://evil.example/nmagent", "1.2", "amd64"); err == nil {
		t.Fatal("foreign url")
	}
	spec, err := parseUpdatePayload(`{"version":"1.2","assets":{"amd64":{"url":"https://github.com/Avmbur/NetMonitor/releases/download/v1.2/netmonitor-linux-amd64.tar.gz","sha256":""}}}`)
	if err != nil {
		t.Fatal(err)
	}
	url, _, err := spec.asset("amd64")
	if err != nil || url == "" {
		t.Fatal(err)
	}
	if _, _, err := spec.asset("arm64"); err == nil {
		t.Fatal("missing arch")
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := []byte("#!/bin/agent")
	hdr := &tar.Header{Name: "netmonitor-linux-amd64/nmagent-linux-amd64", Mode: 0o755, Size: int64(len(body))}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil || gz.Close() != nil {
		t.Fatal("close")
	}
	got, err := extractAgentBinary(&buf, "amd64")
	if err != nil || string(got) != string(body) {
		t.Fatal(err, got)
	}
	if updateVersionLess("1.2", "1.2") || !updateVersionLess("1.0", "1.2") {
		t.Fatal("compare")
	}
}
