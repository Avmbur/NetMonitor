package collect

import (
	"bufio"
	"fmt"
	"os"
)

const ProcPath = "/proc/net/nf_conntrack"

func DumpAll() ([]Entry, error) {
	ents, err := DumpNetlink()
	if err == nil {
		return ents, nil
	}
	ents2, err2 := ReadConntrack(ProcPath)
	if err2 == nil {
		return ents2, nil
	}
	return nil, fmt.Errorf("ctnetlink: %v; proc: %v", err, err2)
}

func ReadConntrack(path string) ([]Entry, error) {
	if path == "" {
		path = ProcPath
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		e, ok := ParseLine(sc.Text())
		if !ok {
			return nil, fmt.Errorf("incomplete conntrack proc line")
		}
		out = append(out, e)
	}
	return out, sc.Err()
}
