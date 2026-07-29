package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/veilvpn/veil/internal/config"
)

// alpnVeilTLS is the ALPN protocol id for the raw-TLS veil transport, so a TLS
// terminator can distinguish tunnel connections from ordinary HTTPS.
const alpnVeilTLS = "veil-tls"

// TLSDialer dials the server over TLS, making the tunnel look like an HTTPS
// connection on the wire.
//
// TLS certificate verification is intentionally skipped: the tunnel's security
// is provided by the Noise handshake (which pins the server's static key), and
// the TLS layer here is transport camouflage. A pinned/real-cert mode arrives
// with autocert in M5.
type TLSDialer struct {
	// ServerName is sent via SNI so the connection blends in as traffic to a
	// specific site. Usually the server's domain.
	ServerName string
}

// Name implements Dialer.
func (TLSDialer) Name() config.TransportName { return config.TransportTLS }

// Dial establishes a TLS connection to endpoint ("host:port").
func (d TLSDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	var nd net.Dialer
	raw, err := nd.DialContext(ctx, "tcp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("tls dial %s: %w", endpoint, err)
	}
	tc := tls.Client(raw, &tls.Config{
		ServerName:         d.ServerName,
		InsecureSkipVerify: true, // security is the Noise layer; see doc comment
		NextProtos:         []string{alpnVeilTLS},
		MinVersion:         tls.VersionTLS12,
	})
	if err := tc.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("tls handshake %s: %w", endpoint, err)
	}
	return newStreamConn(tc, config.TransportTLS), nil
}

// ListenTLS binds a TLS listener on addr using cert. Accepted connections speak
// veil framing directly over TLS.
func ListenTLS(addr string, cert tls.Certificate) (Listener, error) {
	ln, err := tls.Listen("tcp", addr, &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{alpnVeilTLS},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		return nil, fmt.Errorf("listen tls %s: %w", addr, err)
	}
	return &streamListener{ln: ln, name: config.TransportTLS}, nil
}
