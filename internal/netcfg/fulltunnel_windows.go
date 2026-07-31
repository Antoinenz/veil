//go:build windows

package netcfg

import (
	"errors"
	"net/netip"
)

// TunnelRouting is a no-op placeholder on Windows for now.
type TunnelRouting struct{}

// FullTunnelUp is not yet implemented on Windows. Split-tunnel (`veil up`
// without --full) works; full-tunnel route/DNS management is a follow-up so it
// can be validated on real hardware before shipping route-table changes.
func FullTunnelUp(iface string, tunnelGW, serverIP, dns netip.Addr, killSwitch bool) (*TunnelRouting, error) {
	return nil, errors.New("netcfg: --full is not supported on Windows yet (split-tunnel works); coming in a follow-up")
}

// Down is a no-op.
func (t *TunnelRouting) Down() error { return nil }
