package fw

import (
	"context"
	"fmt"
	"net/netip"
	"netmonitor/internal/policy"
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"time"
)

type Desired struct {
	LocalPort   int
	BlockID     string
	Protocol    string
	Port        int
	IP          netip.Addr
	Timeout     time.Duration // Only for callers without an absolute expiry.
	ExpiresAtMS int64
	Direction   string
}
type LearnHit struct {
	Dir   string
	Proto string
	IP    netip.Addr
	Port  int
}

func LearnHits() []LearnHit { return listLearnHits() }

type Policy struct {
	Managed   bool
	Rules     []policy.Rule
	Groups    []policy.Rule
	Blocks    []Desired
	BlockNets []netip.Prefix
	AllowNets []netip.Prefix
	Never       []netip.Prefix
	Monitor     netip.Addr
	MonitorPort int
	Mode        string
}

// The backend is selected once. A failing/disappearing nft must not silently
// switch to a backend with weaker semantics.
type Controller struct {
	backend    string
	signature  string
	lastPolicy Policy
	cgroups    map[string]uint64
	execute    func(string, string, ...string) ([]byte, error)
}

// CgroupsMoved: a service bound by a rule restarted since the last apply, and
// nft still matches its old cgroup. The same policy has to be loaded again.
func (c *Controller) CgroupsMoved() bool { return cgroupsMoved(c.cgroups) }

func NewController() *Controller      { return &Controller{backend: Backend(), execute: command} }
func (c *Controller) Backend() string { return c.backend }
func Backend() string {
	if runtime.GOOS != "linux" {
		return "unknown"
	}
	if _, err := exec.LookPath("nft"); err == nil {
		return "nftables"
	}
	if _, err := exec.LookPath("iptables"); err == nil {
		return "iptables"
	}
	return "unknown"
}
func command(input, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
func (c *Controller) Apply(p Policy) error {
	if c.signature != "" && reflect.DeepEqual(c.lastPolicy, p) && c.Alive() && !c.CgroupsMoved() {
		return nil
	}

	if c.backend == "iptables" {
		if p.Managed {
			return fmt.Errorf("iptables: precise policy model requires nftables; previous policy retained")
		}
		for _, b := range p.Blocks {
			if preciseBlock(b) {
				return fmt.Errorf("iptables: precise ban requires nftables")
			}
		}
		err := c.applyIPTables(p)
		if err == nil {
			c.lastPolicy = clonePolicy(p)
			c.signature = "iptables"
		}
		return err
	}
	if c.backend != "nftables" {
		return fmt.Errorf("backend %s: reliable policy application is unavailable; existing firewall unchanged", c.backend)
	}
	cgroups, err := prepareNft(p)
	if err != nil {
		return err
	}
	script, err := nftScript(p, time.Now())
	if err != nil {
		return err
	}
	// nft -f commits the entire batch atomically, including both IP families.
	_, err = c.execute(script, "nft", "-f", "-")
	if err != nil {
		return err
	}
	signature, _, err := c.nftState()
	if err != nil {
		return fmt.Errorf("policy committed but verification failed: %w", err)
	}
	c.signature = signature
	c.lastPolicy = clonePolicy(p)
	c.cgroups = cgroups
	return nil
}
func (c *Controller) Alive() bool {
	if c.backend == "iptables" {
		return c.iptablesAlive()
	}
	if c.backend != "nftables" {
		return false
	}
	return c.nftAlive()
}
func Apply(p Policy) error { return NewController().Apply(p) }
func TableAlive() bool     { return NewController().Alive() }
func Reconcile(blocks []Desired, nets []netip.Prefix, never []netip.Prefix, monitor netip.Addr) error {
	return Apply(Policy{Blocks: blocks, BlockNets: nets, Never: never, Monitor: monitor, Mode: "allow"})
}
