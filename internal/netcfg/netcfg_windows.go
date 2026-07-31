//go:build windows

package netcfg

import (
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Windows configures a Wintun interface via netsh. Server-side operations
// (forwarding/NAT) are not supported — Windows is a client platform here.
type Windows struct{}

// New returns the Windows Configurator.
func New() Configurator { return Windows{} }

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netcfg: %s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// SetupInterface assigns addr to the Wintun interface and sets its MTU. The
// adapter can take a moment to register after creation, so the address set is
// retried briefly.
func (Windows) SetupInterface(iface string, addr netip.Prefix, mtu int) error {
	ip := addr.Addr().String()
	mask := ipv4Mask(addr.Bits())

	var err error
	for i := 0; i < 15; i++ {
		err = run("netsh", "interface", "ipv4", "set", "address",
			"name="+iface, "static", ip, mask)
		if err == nil {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if err != nil {
		return fmt.Errorf("assign %s to %s: %w", addr, iface, err)
	}
	if mtu > 0 {
		_ = run("netsh", "interface", "ipv4", "set", "subinterface",
			iface, "mtu="+strconv.Itoa(mtu), "store=active")
	}
	return nil
}

// EnableForwarding is a no-op on the Windows client.
func (Windows) EnableForwarding() error { return nil }

// AddMasquerade is unsupported: running the gateway on Windows isn't a target.
func (Windows) AddMasquerade(srcCIDR netip.Prefix, egressIface string) error {
	return ErrUnsupported
}

// RemoveMasquerade is unsupported on Windows.
func (Windows) RemoveMasquerade(srcCIDR netip.Prefix, egressIface string) error {
	return ErrUnsupported
}

// ipv4Mask renders a prefix length as a dotted-decimal netmask.
func ipv4Mask(bits int) string {
	var m [4]byte
	for i := 0; i < 4; i++ {
		if bits >= 8 {
			m[i] = 0xff
			bits -= 8
		} else if bits > 0 {
			m[i] = byte(0xff << uint(8-bits))
			bits = 0
		}
	}
	return fmt.Sprintf("%d.%d.%d.%d", m[0], m[1], m[2], m[3])
}
