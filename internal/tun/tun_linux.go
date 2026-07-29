//go:build linux

package tun

import (
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ifreq mirrors the kernel's struct ifreq for the TUNSETIFF ioctl: a 16-byte
// interface name followed by a 16-bit flags field (padded to the union size).
type ifreq struct {
	name  [unix.IFNAMSIZ]byte
	flags uint16
	_     [22]byte
}

type linuxDevice struct {
	f    *os.File
	name string
}

// Open creates (or attaches to) a TUN interface named name (e.g. "veil0") and
// returns it ready for reading/writing IP packets. Requires CAP_NET_ADMIN.
func Open(name string) (Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("tun: open /dev/net/tun: %w", err)
	}

	var req ifreq
	copy(req.name[:unix.IFNAMSIZ-1], name)
	// IFF_TUN: layer-3 device. IFF_NO_PI: no 4-byte packet-info prefix, so reads
	// and writes are bare IP packets.
	req.flags = unix.IFF_TUN | unix.IFF_NO_PI

	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); errno != 0 {
		unix.Close(fd)
		return nil, fmt.Errorf("tun: TUNSETIFF: %w", errno)
	}

	// The kernel writes the actual (possibly normalized) name back into req.
	actual := string(req.name[:])
	if i := indexNUL(req.name[:]); i >= 0 {
		actual = string(req.name[:i])
	}

	return &linuxDevice{f: os.NewFile(uintptr(fd), "/dev/net/tun"), name: actual}, nil
}

func (d *linuxDevice) Read(p []byte) (int, error)  { return d.f.Read(p) }
func (d *linuxDevice) Write(p []byte) (int, error) { return d.f.Write(p) }
func (d *linuxDevice) Name() string                { return d.name }
func (d *linuxDevice) Close() error                { return d.f.Close() }

func indexNUL(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
