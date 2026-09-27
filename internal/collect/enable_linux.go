//go:build linux

package collect

import (
	"fmt"
	"os/exec"
	"strings"
)

// Register conntrack with a counting expression only: collection must not accept traffic.
func EnableKernel() error {
	for _, name := range []string{"nf_conntrack", "nf_conntrack_netlink"} {
		_ = exec.Command("modprobe", name).Run()
	}
	for _, key := range []string{"net.netfilter.nf_conntrack_acct=1", "net.netfilter.nf_conntrack_timestamp=1"} {
		if b, e := exec.Command("sysctl", "-w", key).CombinedOutput(); e != nil {
			return fmt.Errorf("conntrack setup: %w: %s", e, b)
		}
	}
	if _, e := exec.LookPath("nft"); e == nil {
		if exec.Command("nft", "list", "table", "inet", "netmon_collect").Run() == nil {
			return nil
		}
		script := "add table inet netmon_collect\n"
		for _, h := range []string{"input", "output"} {
			script += "add chain inet netmon_collect " + h + " { type filter hook " + h + " priority -190; policy accept; }\nadd rule inet netmon_collect " + h + " ct state new,established,related counter\n"
		}
		cmd := exec.Command("nft", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if b, e := cmd.CombinedOutput(); e != nil {
			return fmt.Errorf("conntrack hooks: %w: %s", e, b)
		}
		return nil
	}
	for _, tool := range []string{"iptables", "ip6tables"} {
		for _, chain := range []string{"INPUT", "OUTPUT"} {
			args := []string{"-w", "5", "-C", chain, "-m", "conntrack", "--ctstate", "NEW,ESTABLISHED,RELATED", "-m", "comment", "--comment", "netmonitor-observe"}
			if exec.Command(tool, args...).Run() == nil {
				continue
			}
			args[2] = "-A"
			if b, e := exec.Command(tool, args...).CombinedOutput(); e != nil {
				return fmt.Errorf("conntrack hook: %w: %s", e, b)
			}
		}
	}
	return nil
}
