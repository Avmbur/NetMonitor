package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"netmonitor/internal/protocol"
)

type updatePayload struct {
	Version string `json:"version"`
	Assets  map[string]struct {
		URL    string `json:"url"`
		SHA256 string `json:"sha256"`
	} `json:"assets"`
}

// updateScript меняет бинарник и проверяет, что новая сборка держится. Если
// служба не поднялась или перезапускалась, возвращает прежний nmagent и
// оставляет метку отката: вернувшийся агент сообщит монитору об ошибке.
const updateScript = `set -eu
bin=/usr/local/bin/nmagent
outcome=$1
replaced=0
publish() {
 printf '%s\n' "$1" > "$outcome.tmp"
 mv -f "$outcome.tmp" "$outcome"
}
finish() {
 rc=$?
 trap - EXIT
 if [ "$rc" -ne 0 ]; then
  if [ "$replaced" = 1 ]; then
   if systemctl stop nmagent.service && mv -f "$bin.prev" "$bin" && systemctl start nmagent.service; then
    publish rolledback
   else
    publish failed
   fi
  else
   publish failed
  fi
 fi
 exit "$rc"
}
trap finish EXIT
cp -f "$bin" "$bin.prev"
systemctl stop nmagent.service
replaced=1
mv -f "$bin.next" "$bin"
systemctl reset-failed nmagent.service
n0=$(systemctl show nmagent.service -p NRestarts --value)
systemctl start nmagent.service
p0=$(systemctl show nmagent.service -p MainPID --value)
sleep 20
n1=$(systemctl show nmagent.service -p NRestarts --value)
p1=$(systemctl show nmagent.service -p MainPID --value)
if ! systemctl is-active --quiet nmagent.service || [ "$n0" != "$n1" ] || [ "$p0" = 0 ] || [ "$p0" != "$p1" ]; then
 exit 1
fi
rm -f "$bin.prev"
publish verified
`

func parseUpdatePayload(raw string) (updatePayload, error) {
	var in updatePayload
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return in, fmt.Errorf("команда обновления")
	}
	if !updateVersionOK(in.Version) {
		return in, fmt.Errorf("версия обновления")
	}
	return in, nil
}

func (in updatePayload) asset(arch string) (string, string, error) {
	item, ok := in.Assets[arch]
	if !ok || item.URL == "" {
		return "", "", fmt.Errorf("в релизе нет сборки %s", arch)
	}
	if err := allowedReleaseURL(item.URL, in.Version, arch); err != nil {
		return "", "", err
	}
	if item.SHA256 != "" && !updateSumOK(item.SHA256) {
		return "", "", fmt.Errorf("контрольная сумма")
	}
	return item.URL, item.SHA256, nil
}

func allowedReleaseURL(raw, version, arch string) error {
	want := "https://github.com/Avmbur/NetMonitor/releases/download/v" + version + "/netmonitor-linux-" + arch + ".tar.gz"
	if raw != want {
		return fmt.Errorf("чужой адрес комплекта")
	}
	return nil
}

func updateVersionOK(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 6 {
			return false
		}
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

func updateSumOK(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func updateVersionLess(a, b string) bool {
	ap, bp := strings.Split(a, "."), strings.Split(b, ".")
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		av, bv := 0, 0
		if i < len(ap) {
			av, _ = strconv.Atoi(ap[i])
		}
		if i < len(bp) {
			bv, _ = strconv.Atoi(bp[i])
		}
		if av != bv {
			return av < bv
		}
	}
	return false
}

func extractAgentBinary(r io.Reader, arch string) ([]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	want := "netmonitor-linux-" + arch + "/nmagent-linux-" + arch
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if hdr.Name != want || hdr.Typeflag != tar.TypeReg {
			continue
		}
		if hdr.Size < 1 || hdr.Size > 80<<20 {
			return nil, fmt.Errorf("размер агента")
		}
		return io.ReadAll(io.LimitReader(tr, hdr.Size))
	}
	return nil, fmt.Errorf("в комплекте нет агента")
}

func checkSum(buf []byte, sum string) error {
	if sum == "" {
		return nil
	}
	got := sha256.Sum256(buf)
	if !strings.EqualFold(hex.EncodeToString(got[:]), sum) {
		return fmt.Errorf("контрольная сумма не сошлась")
	}
	return nil
}

func sendUpdateResult(client *http.Client, monitor string, in protocol.UpdateResult) error {
	raw, err := json.Marshal(in)
	if err != nil {
		return err
	}
	res, err := client.Post(monitor+"/v1/update-result", "application/json", bytes.NewReader(raw))
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("update report: HTTP %d", res.StatusCode)
	}
	var ack struct {
		OK bool `json:"ok"`
	}
	if err := json.NewDecoder(io.LimitReader(res.Body, 1024)).Decode(&ack); err != nil {
		return err
	}
	if !ack.OK {
		return fmt.Errorf("update was not acknowledged")
	}
	return nil
}
