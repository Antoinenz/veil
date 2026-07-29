package transport

import (
	"context"
	"fmt"
	"net"

	"github.com/veilvpn/veil/internal/config"
)

// TCPDialer dials the server over plain TCP (a fallback where UDP is blocked but
// deep-packet inspection is not aggressive).
type TCPDialer struct{}

// Name implements Dialer.
func (TCPDialer) Name() config.TransportName { return config.TransportTCP }

// Dial connects a TCP stream to endpoint ("host:port").
func (TCPDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("tcp dial %s: %w", endpoint, err)
	}
	return newStreamConn(c, config.TransportTCP), nil
}

// ListenTCP binds a plain-TCP listener on addr.
func ListenTCP(addr string) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen tcp %s: %w", addr, err)
	}
	return &streamListener{ln: ln, name: config.TransportTCP}, nil
}
