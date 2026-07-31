//go:build !linux && !windows

package netcfg

import "net/netip"

// TunnelRouting is a no-op on platforms without a full-tunnel implementation.
type TunnelRouting struct{}

// FullTunnelUp is unsupported on non-Linux platforms (Windows arrives in M4).
func FullTunnelUp(iface string, tunnelGW, serverIP, dns netip.Addr, killSwitch bool) (*TunnelRouting, error) {
	return nil, ErrUnsupported
}

// Down is a no-op.
func (t *TunnelRouting) Down() error { return nil }
