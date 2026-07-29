// Package transport defines the pluggable wire transports veil can use to reach a
// server, plus the auto-selector that races them to find one that works on the
// current network.
//
// A Transport is responsible only for moving opaque byte messages between client
// and server; it knows nothing about Noise or IP packets. Concrete transports
// (udp, tcp, tls, wss) land in M1/M2. This file defines the contracts and the
// selection logic so the rest of the system can be built against stable types.
package transport

import (
	"context"
	"time"

	"github.com/veilvpn/veil/internal/config"
)

// Conn is a message-oriented, bidirectional connection over some transport.
//
// Send/Recv operate on whole messages (veil frames). For datagram transports
// (udp) a message maps to a datagram; for stream transports (tcp/tls/wss) the
// transport length-delimits messages internally.
type Conn interface {
	// Send transmits one message. Implementations must be safe for a single
	// writer goroutine.
	Send(b []byte) error
	// Recv returns the next message. The returned slice is owned by the caller.
	Recv() ([]byte, error)
	// Close tears the connection down.
	Close() error
	// Transport reports which transport produced this connection.
	Transport() config.TransportName
}

// Dialer establishes client-side connections for one transport.
type Dialer interface {
	// Name is the transport this dialer implements.
	Name() config.TransportName
	// Dial connects to endpoint (host:port or URL, transport-specific) and
	// returns a ready Conn, or an error if this transport can't reach the server
	// on the current network.
	Dial(ctx context.Context, endpoint string) (Conn, error)
}

// Endpoints maps each transport to the endpoint string used to dial it for a
// given server. Populated from the server hostname during login/config.
type Endpoints map[config.TransportName]string

// Result is the outcome of a single transport attempt during selection.
type Result struct {
	Transport config.TransportName
	Conn      Conn          // non-nil on success
	Err       error         // non-nil on failure
	Elapsed   time.Duration // how long the attempt took
}
