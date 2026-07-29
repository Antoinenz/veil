// Package tun provides a minimal layer-3 TUN device abstraction. The Linux
// implementation uses /dev/net/tun; other platforms return ErrUnsupported until
// their drivers land (Windows/Wintun in M4).
//
// A Device reads and writes raw IP packets (no link header), which the tunnel
// carries as data-frame payloads.
package tun

import "errors"

// ErrUnsupported is returned by Open on platforms without a TUN implementation.
var ErrUnsupported = errors.New("tun: not supported on this platform yet")

// Device is a TUN network interface.
type Device interface {
	// Read fills p with one inbound IP packet and returns its length.
	Read(p []byte) (int, error)
	// Write sends one IP packet.
	Write(p []byte) (int, error)
	// Name is the OS interface name (e.g. "veil0").
	Name() string
	// Close removes the interface.
	Close() error
}
