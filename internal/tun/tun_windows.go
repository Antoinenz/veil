//go:build windows

package tun

import (
	"fmt"
	"os"
	"sync"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// defaultName is user-visible on Windows (Network Connections / Task Manager).
const defaultName = "Veil"

// sessionCapacity is the Wintun ring buffer size (power of two in
// [0x20000, 0x4000000]). 4 MiB is a good default.
const sessionCapacity = 0x400000

type windowsDevice struct {
	adapter  *wintun.Adapter
	session  wintun.Session
	name     string
	closeEvt windows.Handle // manual-reset event, signaled on Close
	mu       sync.RWMutex   // Read holds RLock around ReceivePacket; Close holds Lock
	closed   bool
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
	// Manual-reset, initially non-signaled event used to wake a blocked Read on Close.
	evt, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		session.End()
		_ = adapter.Close()
		return nil, fmt.Errorf("tun: create close event: %w", err)
	}
	return &windowsDevice{adapter: adapter, session: session, name: name, closeEvt: evt}, nil
}

// Read returns the next outbound IP packet, blocking until one is available or
// the device is closed. It is safe against a concurrent Close: the read lock is
// held only around the (fast, non-blocking) ReceivePacket, never across the wait.
func (d *windowsDevice) Read(p []byte) (int, error) {
	for {
		d.mu.RLock()
		if d.closed {
			d.mu.RUnlock()
			return 0, os.ErrClosed
		}
		packet, err := d.session.ReceivePacket()
		if err == nil {
			n := copy(p, packet)
			d.session.ReleaseReceivePacket(packet)
			d.mu.RUnlock()
			return n, nil
		}
		d.mu.RUnlock()

		switch err {
		case windows.ERROR_NO_MORE_ITEMS:
			// Wait for a packet or for Close to signal closeEvt.
			handles := []windows.Handle{d.session.ReadWaitEvent(), d.closeEvt}
			_, _ = windows.WaitForMultipleObjects(handles, false, windows.INFINITE)
			// loop: the closed check at the top handles shutdown
		case windows.ERROR_HANDLE_EOF:
			return 0, os.ErrClosed
		default:
			return 0, err
		}
	}
}

// Write injects one IP packet into the adapter.
func (d *windowsDevice) Write(p []byte) (int, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return 0, os.ErrClosed
	}
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
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.closed {
		return nil
	}
	d.closed = true
	// Wake any Read blocked in WaitForMultipleObjects, then free the session and
	// adapter. Holding the write lock guarantees no ReceivePacket is in flight.
	_ = windows.SetEvent(d.closeEvt)
	d.session.End()
	err := d.adapter.Close()
	_ = windows.CloseHandle(d.closeEvt)
	return err
}

// LUID exposes the adapter's Windows interface LUID for network configuration.
func (d *windowsDevice) LUID() uint64 { return d.adapter.LUID() }
