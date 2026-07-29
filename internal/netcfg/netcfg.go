// Package netcfg configures host networking for the tunnel: assigning the TUN
// interface an address, bringing it up, enabling IP forwarding, and installing
// the NAT masquerade rule that lets client traffic egress to the internet.
//
// These operations require root/CAP_NET_ADMIN and are inherently
// platform-specific; the Linux implementation shells out to `ip`, `sysctl` and
// `iptables`. Non-Linux builds return ErrUnsupported.
package netcfg

import (
	"errors"
	"net/netip"
)

// ErrUnsupported is returned on platforms without a netcfg implementation.
var ErrUnsupported = errors.New("netcfg: not supported on this platform yet")

// Configurator applies and reverts host network configuration.
type Configurator interface {
	// SetupInterface assigns addr to iface, sets its MTU, and brings it up.
	SetupInterface(iface string, addr netip.Prefix, mtu int) error
	// EnableForwarding turns on IPv4 forwarding.
	EnableForwarding() error
	// AddMasquerade NATs traffic from srcCIDR out through egressIface.
	AddMasquerade(srcCIDR netip.Prefix, egressIface string) error
	// RemoveMasquerade removes the rule added by AddMasquerade.
	RemoveMasquerade(srcCIDR netip.Prefix, egressIface string) error
}
