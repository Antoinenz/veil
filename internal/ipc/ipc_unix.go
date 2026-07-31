//go:build !windows

package ipc

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

// socketPath is the unix socket the daemon listens on. Override with $VEIL_IPC
// (useful for tests and rootless/dev runs).
func socketPath() string {
	if p := os.Getenv("VEIL_IPC"); p != "" {
		return p
	}
	return "/run/veil/veil.sock"
}

// Listen creates the daemon's unix socket, replacing any stale one. The socket
// is group-accessible (0660) so an unprivileged GUI in the right group can talk
// to the root daemon.
func Listen() (net.Listener, error) {
	path := socketPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("ipc: mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("ipc: remove stale socket: %w", err)
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("ipc: listen %s: %w", path, err)
	}
	_ = os.Chmod(path, 0o660)
	return l, nil
}

// DialContext connects to the daemon's unix socket.
func DialContext(ctx context.Context) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", socketPath())
}
