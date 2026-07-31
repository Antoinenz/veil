//go:build windows

package tun

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// sessionCapacity is the Wintun ring buffer size (power of two in
// [0x20000, 0x4000000]). 4 MiB is a good default.
const sessionCapacity = 0x400000

type windowsDevice struct {
	adapter *wintun.Adapter
	session wintun.Session
	name    string
	closed  bool
}

// Open creates a Wintun adapter named name and starts a session. Requires the
// wintun.dll (amd64) to be present next to the executable (or on the DLL search
// path) and the process to be running elevated (Administrator).
func Open(name string) (Device, error) {
	adapter, err := wintun.CreateAdapter(name, "veil", nil)
	if err != nil {
		return nil, fmt.Errorf("tun: create wintun adapter %q (is wintun.dll present and are you running as Administrator?): %w", name, err)
	}
	session, err := adapter.StartSession(sessionCapacity)
	if err != nil {
		_ = adapter.Close()
		return nil, fmt.Errorf("tun: start wintun session: %w", err)
	}
	return &windowsDevice{adapter: adapter, session: session, name: name}, nil
}

// Read returns the next outbound IP packet, blocking until one is available.
func (d *windowsDevice) Read(p []byte) (int, error) {
	for {
		packet, err := d.session.ReceivePacket()
		switch err {
		case nil:
			n := copy(p, packet)
			d.session.ReleaseReceivePacket(packet)
			return n, nil
		case windows.ERROR_NO_MORE_ITEMS:
			windows.WaitForSingleObject(d.session.ReadWaitEvent(), windows.INFINITE)
			continue
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		default:
			return 0, err
		}
	}
}

// Write injects one IP packet into the adapter.
func (d *windowsDevice) Write(p []byte) (int, error) {
	packet, err := d.session.AllocateSendPacket(len(p))
	if err != nil {
		if err == windows.ERROR_BUFFER_OVERFLOW {
			return len(p), nil // ring full: drop, like a datagram transport
		}
		return 0, err
	}
	copy(packet, p)
	d.session.SendPacket(packet)
	return len(p), nil
}

func (d *windowsDevice) Name() string { return d.name }

func (d *windowsDevice) Close() error {
	if d.closed {
		return nil
	}
	d.closed = true
	d.session.End()
	return d.adapter.Close()
}

// LUID exposes the adapter's Windows interface LUID for network configuration.
func (d *windowsDevice) LUID() uint64 { return d.adapter.LUID() }
