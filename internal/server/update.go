package server

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"netmonitor/internal/idgen"
	"netmonitor/internal/protocol"
	"netmonitor/internal/store"
	"netmonitor/internal/svcnet"
	"netmonitor/internal/tlsutil"
)

// releaseAPI is the public GitHub release the monitor offers to install.
// Tests replace it.
var releaseAPI = "https://api.github.com/repos/Avmbur/NetMonitor/releases/latest"

const releaseOwner = "Avmbur/NetMonitor"

type releaseAsset struct {
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256,omitempty"`
}

type releaseInfo struct {
	Tag     string
	Version string
	Notes   string
	HTML    string
	Assets  map[string]releaseAsset
}

type updateAgent struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Behind  bool   `json:"behind"`
	Pending bool   `json:"pending"`
}

type updateView struct {
	Current string         `json:"current"`
	Latest  string         `json:"latest"`
	Newer   bool           `json:"newer"`
	Notes   string         `json:"notes,omitempty"`
	HTML    string         `json:"html,omitempty"`
	Arch    string         `json:"arch"`
	Manual  string         `json:"manual,omitempty"`
	Assets  []releaseAsset `json:"assets,omitempty"`
	Agents  []updateAgent  `json:"agents"`
	Error   string         `json:"error,omitempty"`
}

func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	rel, err := fetchRelease(r.Context(), s.admitOnMonitor)
	if err != nil {
		if r.Method == http.MethodGet {
			writeJSON(w, updateView{Current: Version, Arch: runtime.GOARCH, Error: err.Error(), Agents: []updateAgent{}})
			return
		}
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	switch r.Method {
	case http.MethodGet:
		view, err := s.updateView(rel)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, view)
	case http.MethodPost:
		var in struct {
			Target string `json:"target"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
			http.Error(w, "json", http.StatusBadRequest)
			return
		}
		switch in.Target {
		case "monitor":
			manual, err := s.stageMonitorUpdate(rel)
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			writeJSON(w, map[string]any{"ok": true, "manual": manual})
		case "agents":
			n, err := s.queueAgentUpdates(rel)
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			writeJSON(w, map[string]any{"ok": true, "queued": n})
		default:
			http.Error(w, "цель: monitor или agents", http.StatusBadRequest)
		}
	default:
		http.Error(w, "method", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleUpdateResult(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		http.Error(w, "client certificate required", http.StatusUnauthorized)
		return
	}
	var in protocol.UpdateResult
	if err := json.NewDecoder(io.LimitReader(r.Body, 8192)).Decode(&in); err != nil {
		http.Error(w, "invalid update result", http.StatusBadRequest)
		return
	}
	fp := tlsutil.Fingerprint(r.TLS.PeerCertificates[0].Raw)
	if err := s.recordUpdate(fp, in.CommandID, in.Phase, in.Error); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) recordUpdate(fp, commandID, phase, message string) error {
	if commandID == "" || len(commandID) > 128 || len(message) > 4096 {
		return fmt.Errorf("invalid update result")
	}
	if phase != "complete" && phase != "failed" {
		return fmt.Errorf("invalid update phase")
	}
	if phase == "complete" && message != "" || phase == "failed" && message == "" {
		return fmt.Errorf("invalid update error")
	}
	return s.st.Update(func(tx *sql.Tx) error {
		var trust, kind, owner, result, previousError string
		var delivered, acked sql.NullInt64
		err := tx.QueryRow(`SELECT a.trust_state,c.kind,a.cert_fingerprint,c.delivered_at_ms,c.acked_at_ms,COALESCE(c.result,''),COALESCE(c.error,'')
			FROM commands c JOIN agents a ON a.agent_id=c.agent_id WHERE c.command_id=?`, commandID).
			Scan(&trust, &kind, &owner, &delivered, &acked, &result, &previousError)
		if err != nil {
			return err
		}
		if owner != fp || trust != "trusted" || kind != "update" || !delivered.Valid {
			return fmt.Errorf("update was not delivered to this trusted agent")
		}
		if acked.Valid && (result == "applied" && phase == "complete" || result == "update_error" && phase == "failed" && message == previousError) {
			return nil
		}
		if acked.Valid {
			return fmt.Errorf("update already finished")
		}
		now := store.NowMS()
		if phase == "failed" {
			_, err = tx.Exec(`UPDATE commands SET acked_at_ms=?,result='update_error',error=? WHERE command_id=?`, now, message, commandID)
			return err
		}
		_, err = tx.Exec(`UPDATE commands SET acked_at_ms=?,result='applied',error=NULL WHERE command_id=?`, now, commandID)
		if err != nil {
			return err
		}
		_, err = tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), now, "agent", "обновил агента", commandID)
		return err
	})
}

func (s *Server) updateView(rel releaseInfo) (updateView, error) {
	asset, _ := rel.Assets[runtime.GOARCH]
	view := updateView{
		Current: Version, Latest: rel.Version, Newer: versionLess(Version, rel.Version),
		Notes: trimRunes(rel.Notes, 800), HTML: rel.HTML, Arch: runtime.GOARCH,
		Manual: manualMonitorCommand(asset.URL, runtime.GOARCH), Agents: []updateAgent{},
	}
	for arch, item := range rel.Assets {
		item.Arch = arch
		view.Assets = append(view.Assets, item)
	}
	rows, err := s.st.DB.Query(`SELECT a.agent_id, COALESCE(NULLIF(trim(a.display_name),''), a.agent_id), COALESCE(a.version,''),
		EXISTS(SELECT 1 FROM commands c WHERE c.agent_id=a.agent_id AND c.kind='update' AND c.acked_at_ms IS NULL)
		FROM agents a WHERE a.trust_state='trusted' ORDER BY a.first_seen_ms`)
	if err != nil {
		return view, err
	}
	defer rows.Close()
	for rows.Next() {
		var ag updateAgent
		if err := rows.Scan(&ag.ID, &ag.Name, &ag.Version, &ag.Pending); err != nil {
			return view, err
		}
		ag.Behind = ag.Version == "" || versionLess(ag.Version, rel.Version)
		view.Agents = append(view.Agents, ag)
	}
	return view, rows.Err()
}

func (s *Server) stageMonitorUpdate(rel releaseInfo) (string, error) {
	if !versionLess(Version, rel.Version) {
		return "", fmt.Errorf("уже последняя версия")
	}
	asset, ok := rel.Assets[runtime.GOARCH]
	if !ok {
		return "", fmt.Errorf("в релизе нет сборки %s", runtime.GOARCH)
	}
	sum := ""
	if sumOK(asset.SHA256) {
		sum = asset.SHA256
	}
	body := fmt.Sprintf("VERSION=%s\nARCH=%s\nURL=%s\nSHA256=%s\n", rel.Version, runtime.GOARCH, asset.URL, sum)
	path := filepath.Join(s.dataDir(), "update.request")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(body), 0o640); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	now := store.NowMS()
	_ = s.st.Update(func(tx *sql.Tx) error {
		_, err := tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), now, "adm", "запросил обновление монитора", rel.Version)
		return err
	})
	return manualMonitorCommand(asset.URL, runtime.GOARCH), nil
}

func (s *Server) queueAgentUpdates(rel releaseInfo) (int, error) {
	if !versionLess(Version, rel.Version) && !agentsBehind(s, rel.Version) {
		return 0, fmt.Errorf("уже последняя версия")
	}
	payload, err := json.Marshal(map[string]any{"version": rel.Version, "assets": rel.Assets})
	if err != nil {
		return 0, err
	}
	var n int
	err = s.st.Update(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT agent_id, COALESCE(version,'') FROM agents WHERE trust_state='trusted'`)
		if err != nil {
			return err
		}
		defer rows.Close()
		type item struct{ id, ver string }
		var list []item
		for rows.Next() {
			var it item
			if err := rows.Scan(&it.id, &it.ver); err != nil {
				return err
			}
			list = append(list, it)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		rows.Close()
		now := store.NowMS()
		for _, it := range list {
			if it.ver != "" && !versionLess(it.ver, rel.Version) {
				continue
			}
			var pending int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM commands WHERE agent_id=? AND kind='update' AND acked_at_ms IS NULL`, it.id).Scan(&pending); err != nil {
				return err
			}
			if pending > 0 {
				continue
			}
			if _, err := tx.Exec(`INSERT INTO commands(command_id,agent_id,kind,payload,created_at_ms) VALUES(?,?,?,?,?)`, idgen.NewV7(), it.id, "update", string(payload), now); err != nil {
				return err
			}
			n++
		}
		if n > 0 {
			_, err = tx.Exec("INSERT INTO audit_log(audit_id,at_ms,actor,action,object) VALUES(?,?,?,?,?)", idgen.NewV7(), now, "adm", "запросил обновление агентов", rel.Version)
		}
		return err
	})
	return n, err
}

func agentsBehind(s *Server, latest string) bool {
	rows, err := s.st.DB.Query(`SELECT COALESCE(version,'') FROM agents WHERE trust_state='trusted'`)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var ver string
		if rows.Scan(&ver) == nil && (ver == "" || versionLess(ver, latest)) {
			return true
		}
	}
	return false
}

func manualMonitorCommand(url, arch string) string {
	if url == "" {
		return ""
	}
	dir := "netmonitor-linux-" + arch
	inner := fmt.Sprintf("curl -fsSL -o /tmp/nm-update.tar.gz %s && rm -rf /tmp/%s && tar -xzf /tmp/nm-update.tar.gz -C /tmp && sh /tmp/%s/install.sh --mode monitor --self-agent no", url, dir, dir)
	return "sudo sh -c " + shellQuote(inner)
}

func fetchRelease(ctx context.Context, admit svcnet.AdmitFunc) (releaseInfo, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, releaseAPI, nil)
	if err != nil {
		return releaseInfo{}, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "netmonitor")
	client := svcnet.Client(admit, 20*time.Second)
	res, err := client.Do(req)
	if err != nil {
		return releaseInfo{}, fmt.Errorf("github: %w", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return releaseInfo{}, err
	}
	if res.StatusCode != http.StatusOK {
		return releaseInfo{}, fmt.Errorf("github: HTTP %d", res.StatusCode)
	}
	return parseRelease(body)
}

func parseRelease(body []byte) (releaseInfo, error) {
	var raw struct {
		Tag   string `json:"tag_name"`
		Body  string `json:"body"`
		HTML  string `json:"html_url"`
		Items []struct {
			Name   string `json:"name"`
			URL    string `json:"browser_download_url"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return releaseInfo{}, fmt.Errorf("github: ответ не разобрать")
	}
	ver := strings.TrimPrefix(raw.Tag, "v")
	if !versionOK(ver) {
		return releaseInfo{}, fmt.Errorf("github: метка %s", raw.Tag)
	}
	out := releaseInfo{Tag: raw.Tag, Version: ver, Notes: raw.Body, HTML: raw.HTML, Assets: map[string]releaseAsset{}}
	for _, arch := range []string{"amd64", "arm64"} {
		name := "netmonitor-linux-" + arch + ".tar.gz"
		want, err := releaseAssetURL(ver, arch)
		if err != nil {
			return releaseInfo{}, err
		}
		for _, item := range raw.Items {
			if item.Name != name {
				continue
			}
			if item.URL != want {
				return releaseInfo{}, fmt.Errorf("github: чужой адрес комплекта")
			}
			sum := ""
			if strings.HasPrefix(item.Digest, "sha256:") {
				sum = strings.TrimPrefix(item.Digest, "sha256:")
			}
			if sum != "" && !sumOK(sum) {
				return releaseInfo{}, fmt.Errorf("github: контрольная сумма")
			}
			out.Assets[arch] = releaseAsset{Arch: arch, URL: want, SHA256: sum}
		}
	}
	if len(out.Assets) == 0 {
		return releaseInfo{}, fmt.Errorf("github: в релизе нет комплекта")
	}
	return out, nil
}

func releaseAssetURL(version, arch string) (string, error) {
	if !versionOK(version) || (arch != "amd64" && arch != "arm64") {
		return "", fmt.Errorf("bad release")
	}
	return "https://github.com/" + releaseOwner + "/releases/download/v" + version + "/netmonitor-linux-" + arch + ".tar.gz", nil
}

func versionOK(v string) bool {
	parts := strings.Split(v, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 6 {
			return false
		}
		for _, r := range p {
			if r < '0' || r > '9' {
				return false
			}
		}
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

func sumOK(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}

func versionLess(a, b string) bool {
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

func trimRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
