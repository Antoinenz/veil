//go:build !linux && !windows

package netcfg

import "net/netip"

// unsupported is a Configurator that returns ErrUnsupported for every operation.
type unsupported struct{}

// New returns a Configurator that is unavailable on this platform.
func New() Configurator { return unsupported{} }

func (unsupported) SetupInterface(string, netip.Prefix, int) error { return ErrUnsupported }
func (unsupported) EnableForwarding() error                        { return ErrUnsupported }
func (unsupported) AddMasquerade(netip.Prefix, string) error       { return ErrUnsupported }
func (unsupported) RemoveMasquerade(netip.Prefix, string) error    { return ErrUnsupported }
