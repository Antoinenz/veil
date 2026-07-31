//go:build windows

package ipc

import (
	"context"
	"net"

	"github.com/Microsoft/go-winio"
)

const pipeName = `\\.\pipe\veil`

// pipeSDDL grants SYSTEM and Administrators full control and Interactive Users
// read/write, so an unprivileged GUI can reach a daemon running as a service.
const pipeSDDL = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)"

// Listen creates the daemon's named pipe.
func Listen() (net.Listener, error) {
	return winio.ListenPipe(pipeName, &winio.PipeConfig{SecurityDescriptor: pipeSDDL})
}

// DialContext connects to the daemon's named pipe.
func DialContext(ctx context.Context) (net.Conn, error) {
	return winio.DialPipeContext(ctx, pipeName)
}
