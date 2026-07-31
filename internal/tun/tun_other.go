//go:build !linux && !windows

package tun

const defaultName = "veil0"

// Open is unsupported on non-Linux platforms until their TUN drivers land
// (Windows/Wintun in M4). It always returns ErrUnsupported.
func Open(name string) (Device, error) {
	return nil, ErrUnsupported
}
