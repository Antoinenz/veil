//go:build linux

package netcfg

import (
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

const (
	resolvConf   = "/etc/resolv.conf"
	resolvBackup = "/etc/resolv.conf.veil.bak"
	ksChain      = "VEIL_KS"
)

// TunnelRouting captures the host changes made for full-tunnel mode so they can
// be reverted on disconnect.
type TunnelRouting struct {
	iface      string
	serverIP   netip.Addr
	serverGW   string
	serverDev  string
	dnsChanged bool
	killSwitch bool
}

// FullTunnelUp routes all traffic through the tunnel:
//   - pins a /32 host route to the server via the original gateway, so the
//     tunnel's own encrypted packets don't get routed back into the tunnel;
//   - installs a split default (0.0.0.0/1 + 128.0.0.0/1) via the tunnel gateway,
//     which out-specifics the existing default without deleting it;
//   - points DNS at dns (if valid) to avoid leaks;
//   - optionally installs a kill-switch that drops any non-tunnel egress.
func FullTunnelUp(iface string, tunnelGW, serverIP, dns netip.Addr, killSwitch bool) (*TunnelRouting, error) {
	gw, dev, err := origRouteFor(serverIP)
	if err != nil {
		return nil, err
	}
	tr := &TunnelRouting{iface: iface, serverIP: serverIP, serverGW: gw, serverDev: dev}

	if err := serverRoute("add", serverIP, gw, dev); err != nil {
		return nil, err
	}
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		if err := run("ip", "route", "add", half, "via", tunnelGW.String(), "dev", iface); err != nil {
			tr.Down()
			return nil, err
		}
	}
	if dns.IsValid() {
		if err := setDNS(dns); err != nil {
			tr.Down()
			return nil, err
		}
		tr.dnsChanged = true
	}
	if killSwitch {
		if err := enableKillSwitch(iface, serverIP); err != nil {
			tr.Down()
			return nil, err
		}
		tr.killSwitch = true
	}
	return tr, nil
}

// Down reverts everything FullTunnelUp changed (best-effort).
func (t *TunnelRouting) Down() error {
	if t == nil {
		return nil
	}
	if t.killSwitch {
		disableKillSwitch()
	}
	if t.dnsChanged {
		restoreDNS()
	}
	for _, half := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		_ = run("ip", "route", "del", half)
	}
	_ = serverRoute("del", t.serverIP, t.serverGW, t.serverDev)
	return nil
}

func serverRoute(op string, ip netip.Addr, gw, dev string) error {
	args := []string{"route", op, ip.String() + "/32"}
	if gw != "" {
		args = append(args, "via", gw)
	}
	if dev != "" {
		args = append(args, "dev", dev)
	}
	return run("ip", args...)
}

// origRouteFor returns the gateway ("" if on-link) and device the kernel would
// currently use to reach ip — i.e. the physical path to the server.
func origRouteFor(ip netip.Addr) (gw, dev string, err error) {
	out, err := exec.Command("ip", "-o", "route", "get", ip.String()).CombinedOutput()
	if err != nil {
		return "", "", fmt.Errorf("netcfg: route get %s: %v: %s", ip, err, strings.TrimSpace(string(out)))
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		switch f {
		case "via":
			if i+1 < len(fields) {
				gw = fields[i+1]
			}
		case "dev":
			if i+1 < len(fields) {
				dev = fields[i+1]
			}
		}
	}
	if dev == "" {
		return "", "", fmt.Errorf("netcfg: could not parse route to %s: %s", ip, strings.TrimSpace(string(out)))
	}
	return gw, dev, nil
}

func setDNS(dns netip.Addr) error {
	if orig, err := os.ReadFile(resolvConf); err == nil {
		_ = os.WriteFile(resolvBackup, orig, 0o644)
	}
	// Replace resolv.conf (removing any symlink first, e.g. systemd-resolved).
	_ = os.Remove(resolvConf)
	return os.WriteFile(resolvConf, []byte("# managed by veil\nnameserver "+dns.String()+"\n"), 0o644)
}

func restoreDNS() {
	orig, err := os.ReadFile(resolvBackup)
	if err != nil {
		return
	}
	_ = os.Remove(resolvConf)
	_ = os.WriteFile(resolvConf, orig, 0o644)
	_ = os.Remove(resolvBackup)
}

// enableKillSwitch installs an OUTPUT chain that allows loopback, tunnel-device
// traffic, and encrypted packets to the server, and drops everything else — so
// if the tunnel drops, traffic fails closed instead of leaking.
func enableKillSwitch(iface string, serverIP netip.Addr) error {
	disableKillSwitch() // clear any stale chain first
	steps := [][]string{
		{"-N", ksChain},
		{"-A", ksChain, "-o", "lo", "-j", "ACCEPT"},
		{"-A", ksChain, "-o", iface, "-j", "ACCEPT"},
		{"-A", ksChain, "-d", serverIP.String(), "-j", "ACCEPT"},
		{"-A", ksChain, "-j", "DROP"},
		{"-I", "OUTPUT", "-j", ksChain},
	}
	for _, s := range steps {
		if err := run("iptables", s...); err != nil {
			disableKillSwitch()
			return err
		}
	}
	return nil
}

func disableKillSwitch() {
	_ = run("iptables", "-D", "OUTPUT", "-j", ksChain)
	_ = run("iptables", "-F", ksChain)
	_ = run("iptables", "-X", ksChain)
}
