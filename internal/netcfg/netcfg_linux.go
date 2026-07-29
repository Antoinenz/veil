//go:build linux

package netcfg

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// Linux configures host networking via the standard `ip`/`sysctl`/`iptables`
// tools. It is intentionally dependency-free (no netlink library) for M1; a
// pure-netlink implementation can replace it later without changing callers.
type Linux struct{}

// New returns the Linux Configurator.
func New() Configurator { return Linux{} }

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netcfg: %s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func (Linux) SetupInterface(iface string, addr netip.Prefix, mtu int) error {
	if err := run("ip", "addr", "add", addr.String(), "dev", iface); err != nil {
		return err
	}
	if mtu > 0 {
		if err := run("ip", "link", "set", "dev", iface, "mtu", strconv.Itoa(mtu)); err != nil {
			return err
		}
	}
	return run("ip", "link", "set", "dev", iface, "up")
}

func (Linux) EnableForwarding() error {
	return run("sysctl", "-w", "net.ipv4.ip_forward=1")
}

func (Linux) AddMasquerade(srcCIDR netip.Prefix, egressIface string) error {
	return run("iptables", "-t", "nat", "-A", "POSTROUTING",
		"-s", srcCIDR.String(), "-o", egressIface, "-j", "MASQUERADE")
}

func (Linux) RemoveMasquerade(srcCIDR netip.Prefix, egressIface string) error {
	return run("iptables", "-t", "nat", "-D", "POSTROUTING",
		"-s", srcCIDR.String(), "-o", egressIface, "-j", "MASQUERADE")
}
