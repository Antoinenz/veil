//go:build !linux && !windows

package tun

// Open is unsupported on non-Linux platforms until their TUN drivers land
// (Windows/Wintun in M4). It always returns ErrUnsupported.
func Open(name string) (Device, error) {
	return nil, ErrUnsupported
}
