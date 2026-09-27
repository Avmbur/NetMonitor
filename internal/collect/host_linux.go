//go:build linux

package collect

import (
	"bufio"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

var (
	cpuMu    sync.Mutex
	cpuTotal uint64
	cpuIdle  uint64
)

func HostResources() Resources {
	r := Resources{OK: true}
	r.CPU = cpuPct()
	r.RAM = ramPct()
	r.Disk = diskPct("/")
	return r
}

func cpuPct() int {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if !sc.Scan() {
		return 0
	}
	fields := strings.Fields(sc.Text())
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0
	}
	var total, idle uint64
	for i, s := range fields[1:] {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0
		}
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	cpuMu.Lock()
	defer cpuMu.Unlock()
	if cpuTotal == 0 {
		cpuTotal, cpuIdle = total, idle
		return 0
	}
	dt := total - cpuTotal
	di := idle - cpuIdle
	cpuTotal, cpuIdle = total, idle
	if dt == 0 {
		return 0
	}
	used := 100 - int((100*di)/dt)
	if used < 0 {
		used = 0
	}
	if used > 100 {
		used = 100
	}
	return used
}

func ramPct() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	var total, avail uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "MemTotal:"):
			total = memKB(line)
		case strings.HasPrefix(line, "MemAvailable:"):
			avail = memKB(line)
		}
	}
	if total == 0 {
		return 0
	}
	used := int((100 * (total - avail)) / total)
	if used < 0 {
		used = 0
	}
	if used > 100 {
		used = 100
	}
	return used
}

func memKB(line string) uint64 {
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.ParseUint(f[1], 10, 64)
	return n
}

func diskPct(path string) int {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil || st.Blocks == 0 {
		return 0
	}
	used := st.Blocks - st.Bavail
	pct := int((100 * used) / st.Blocks)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}
