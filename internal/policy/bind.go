package policy

import (
	"fmt"
	"strconv"
	"strings"
)

// Binding is one exact process identity observed on a host.
// Service/container uses Cgroup; an ordinary program uses Path and UID.
type Binding struct {
	UID    *int   `json:"uid,omitempty"`
	Host   string `json:"host,omitempty"`
	Name   string `json:"name,omitempty"`
	Cgroup string `json:"cgroup,omitempty"`
	Path   string `json:"path,omitempty"`
}

func (m Match) Bound() bool {
	return len(m.Bindings) > 0 || m.Process != "" || m.Cgroup != "" || m.UID != nil
}

func (r Rule) SpentOn(host string) bool {
	if !r.Once {
		return false
	}
	if r.OnceUsed {
		return true
	}
	for _, h := range r.OnceUsedHosts {
		if h == host {
			return true
		}
	}
	return false
}

func BindingsForHost(bs []Binding, host string) []Binding {
	var out []Binding
	for _, b := range bs {
		if b.Host == "" || b.Host == host {
			out = append(out, b)
		}
	}
	return out
}

func (b Binding) matches(c Contact) bool {
	if b.Host != "" && c.Host != "" && b.Host != c.Host {
		return false
	}
	if b.Cgroup != "" && !cgroupCovers(b.Cgroup, c.Cgroup) {
		return false
	}
	if b.Path != "" && b.Path != c.Process {
		return false
	}
	if b.UID != nil && (c.UID == nil || *b.UID != *c.UID) {
		return false
	}
	return b.Cgroup != "" || b.Path != "" || b.UID != nil
}

func cgroupCovers(want, have string) bool {
	w, h := NormalizeCgroup(want), NormalizeCgroup(have)
	if w == "" || h == "" {
		return false
	}
	return w == h || strings.HasPrefix(h, w+"/")
}

func NormalizeCgroup(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "::"); i >= 0 {
		s = s[i+2:]
	}
	s = strings.TrimPrefix(s, "/")
	s = strings.Trim(s, "/")
	if s == "" {
		return ""
	}
	if !strings.Contains(s, "/") && strings.HasSuffix(s, ".service") {
		s = "system.slice/" + s
	}
	return s
}

func DedicatedCgroup(s string) bool {
	p := strings.ToLower(NormalizeCgroup(s))
	if p == "" {
		return false
	}
	base := p
	if i := strings.LastIndex(p, "/"); i >= 0 {
		base = p[i+1:]
	}
	if base == "init.scope" || strings.HasPrefix(base, "session-") && strings.HasSuffix(base, ".scope") {
		return false
	}
	if strings.Contains(p, ".service") || strings.Contains(p, "docker") || strings.Contains(p, "libpod") || strings.Contains(p, "lxc") || strings.Contains(p, "containerd") || strings.Contains(p, "machine.slice") {
		return true
	}
	return strings.HasSuffix(base, ".scope")
}

// SystemService: обычная служба systemd (system.slice/<имя>.service). Имя такой
// службы одно на любом сервере, поэтому привязка к ней переносится на все
// выбранные серверы. Контейнеры, вложенные срезы и сеансы сюда не входят.
func SystemService(cgroup string) bool {
	slice, svc, ok := strings.Cut(NormalizeCgroup(cgroup), "/")
	return ok && slice == "system.slice" && !strings.Contains(svc, "/") && len(svc) > len(".service") && strings.HasSuffix(svc, ".service")
}

func CgroupMatch(path string) (string, error) {
	p := NormalizeCgroup(path)
	if p == "" || !DedicatedCgroup(p) {
		return "", fmt.Errorf("cgroup %q не является точной привязкой", path)
	}
	return fmt.Sprintf("socket cgroupv2 level %d %q", strings.Count(p, "/")+1, p), nil
}

func (b Binding) Enforceable() error {
	if DedicatedCgroup(b.Cgroup) {
		return nil
	}
	if b.Path != "" && b.UID != nil {
		return fmt.Errorf("привязка %s uid=%d без выделенной cgroup не исполняется: это разрешило бы все программы пользователя", b.Path, *b.UID)
	}
	if b.Path != "" {
		return fmt.Errorf("привязка пути без uid и cgroup не исполняется")
	}
	if b.UID != nil {
		return fmt.Errorf("привязка только uid не исполняется: это разрешило бы все программы пользователя")
	}
	if strings.TrimSpace(b.Cgroup) != "" {
		return fmt.Errorf("cgroup %s общая; точная привязка процесса не исполняется", NormalizeCgroup(b.Cgroup))
	}
	if b.Name != "" {
		return fmt.Errorf("привязка по имени процесса не исполняется; нужна cgroup или путь+uid")
	}
	return fmt.Errorf("пустая привязка процесса")
}

func Inert(r Rule) bool {
	if !r.Match.Bound() {
		return false
	}
	for _, b := range r.Match.Bindings {
		if b.Enforceable() == nil {
			return false
		}
	}
	return true
}

func ParseIdentity(s, host, name string) (Binding, error) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\t", " "))
	if s == "" {
		return Binding{}, fmt.Errorf("пустая привязка процесса")
	}
	b := Binding{Host: host, Name: name}
	var rest []string
	for _, part := range strings.Fields(s) {
		switch {
		case strings.HasPrefix(part, "cgroup="):
			b.Cgroup = NormalizeCgroup(strings.TrimPrefix(part, "cgroup="))
		case strings.HasPrefix(part, "uid="):
			raw := strings.TrimPrefix(part, "uid=")
			n, err := strconv.Atoi(raw)
			if err != nil {
				return Binding{}, fmt.Errorf("uid %q не число: имя пользователя не исполняется", raw)
			}
			b.UID = &n
		default:
			rest = append(rest, part)
		}
	}
	b.Path = strings.Join(rest, " ")
	if b.Cgroup == "" && b.UID == nil && (b.Path == "" || !strings.Contains(b.Path, "/") && !strings.HasPrefix(b.Path, ".")) {
		return Binding{}, fmt.Errorf("привязка по имени процесса не исполняется; нужна cgroup или путь+uid")
	}
	if b.Cgroup == "" && b.Path == "" && b.UID == nil {
		return Binding{}, fmt.Errorf("привязка по имени процесса не исполняется; нужна cgroup или путь+uid")
	}
	if b.Name == "" {
		if b.Path != "" {
			if i := strings.LastIndex(b.Path, "/"); i >= 0 {
				b.Name = b.Path[i+1:]
			} else {
				b.Name = b.Path
			}
		} else if b.Cgroup != "" {
			if i := strings.LastIndex(b.Cgroup, "/"); i >= 0 {
				b.Name = strings.TrimSuffix(b.Cgroup[i+1:], ".service")
			} else {
				b.Name = b.Cgroup
			}
		}
	}
	return b, nil
}

func FormatIdentity(path string, uid *int, cgroup string) string {
	var parts []string
	if path != "" {
		parts = append(parts, path)
	}
	if uid != nil {
		parts = append(parts, "uid="+strconv.Itoa(*uid))
	}
	if c := NormalizeCgroup(cgroup); c != "" {
		parts = append(parts, "cgroup="+c)
	}
	return strings.Join(parts, "  ")
}

func (r Rule) hasMatchCondition() bool {
	m := r.Match
	if len(m.Networks) > 0 || len(m.Names) > 0 || m.LocalPort > 0 || m.RemotePort > 0 || m.AnyPort > 0 || m.Bound() || r.GroupID != "" {
		return true
	}
	if m.Direction != "" && m.Direction != "any" && m.Direction != "both" {
		return true
	}
	return m.Protocol != "" && m.Protocol != "any"
}
