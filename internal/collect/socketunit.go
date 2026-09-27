package collect

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

var systemdUnitDirs = []string{
	"/etc/systemd/system",
	"/run/systemd/generator",
	"/usr/lib/systemd/system",
	"/lib/systemd/system",
}

var servicesPath = "/etc/services"

func isInitProc(comm string) bool {
	c := strings.ToLower(comm)
	return c == "systemd" || c == "init"
}

func socketService(proto string, port int) (name, path string) {
	want := strings.ToLower(proto)
	for _, dir := range systemdUnitDirs {
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, ent := range ents {
			if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".socket") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, ent.Name()))
			if err != nil {
				continue
			}
			svc, streams, dgrams := parseSocketUnit(string(b), ent.Name())
			hit := false
			if want == "tcp" {
				for _, p := range streams {
					if p == port {
						hit = true
						break
					}
				}
			} else if want == "udp" {
				for _, p := range dgrams {
					if p == port {
						hit = true
						break
					}
				}
			}
			if !hit {
				continue
			}
			bin, pth := serviceBinary(svc)
			if bin != "" {
				return bin, pth
			}
		}
	}
	return "", ""
}

func parseSocketUnit(text, file string) (service string, streams, dgrams []int) {
	service = strings.TrimSuffix(file, ".socket") + ".service"
	section := ""
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if section == "socket" && strings.EqualFold(k, "Service") && v != "" {
			service = v
			if !strings.HasSuffix(service, ".service") {
				service += ".service"
			}
		}
		if section != "socket" {
			continue
		}
		p := listenPortValue(v)
		if p <= 0 {
			continue
		}
		switch {
		case strings.EqualFold(k, "ListenStream"):
			streams = append(streams, p)
		case strings.EqualFold(k, "ListenDatagram"):
			dgrams = append(dgrams, p)
		}
	}
	return service, streams, dgrams
}

func listenPortValue(v string) int {
	v = strings.TrimSpace(v)
	if n, err := strconv.Atoi(v); err == nil {
		return n
	}
	if i := strings.LastIndex(v, ":"); i >= 0 {
		n, err := strconv.Atoi(v[i+1:])
		if err == nil {
			return n
		}
	}
	return 0
}

func serviceBinary(unit string) (name, path string) {
	if unit == "" {
		return "", ""
	}
	cands := []string{unit}
	base := strings.TrimSuffix(unit, ".service")
	if base == "ssh" {
		cands = append(cands, "sshd.service")
	}
	if base == "sshd" {
		cands = append(cands, "ssh.service")
	}
	for _, dir := range systemdUnitDirs {
		for _, u := range cands {
			b, err := os.ReadFile(filepath.Join(dir, u))
			if err != nil {
				continue
			}
			section := ""
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if i := strings.Index(line, "#"); i >= 0 {
					line = strings.TrimSpace(line[:i])
				}
				if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
					section = strings.ToLower(strings.Trim(line, "[]"))
					continue
				}
				if section != "service" {
					continue
				}
				k, v, ok := strings.Cut(line, "=")
				if !ok || !strings.EqualFold(strings.TrimSpace(k), "ExecStart") {
					continue
				}
				fields := strings.Fields(strings.TrimSpace(v))
				if len(fields) == 0 {
					continue
				}
				p := strings.TrimLeft(fields[0], "-@+:")
				if p == "" {
					continue
				}
				return filepath.Base(p), p
			}
		}
	}
	return "", ""
}

var (
	svcMu   sync.Mutex
	svcMap  map[string]string
	svcFile string
)

func resetServiceCache() {
	svcMu.Lock()
	svcMap, svcFile = nil, ""
	svcMu.Unlock()
}

func serviceName(proto string, port int) string {
	svcMu.Lock()
	defer svcMu.Unlock()
	if svcMap == nil || svcFile != servicesPath {
		svcMap = loadServices(servicesPath)
		svcFile = servicesPath
	}
	return svcMap[proto+"/"+strconv.Itoa(port)]
}

func loadServices(path string) map[string]string {
	b, err := os.ReadFile(path)
	if err != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		name, spec := f[0], f[1]
		portS, proto, ok := strings.Cut(spec, "/")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(portS)
		if err != nil || n <= 0 {
			continue
		}
		key := strings.ToLower(proto) + "/" + strconv.Itoa(n)
		if out[key] == "" {
			out[key] = name
		}
	}
	return out
}
