package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/coder/websocket"
	"github.com/veilvpn/veil/internal/config"
)

// wsReadLimit bounds a single inbound WebSocket message. A veil frame is at most
// ~64 KiB; 1 MiB leaves generous headroom.
const wsReadLimit = 1 << 20

// TunnelPath is the HTTP path that upgrades to the tunnel WebSocket. Any other
// path is served by the decoy site, so the server looks like an ordinary website.
const TunnelPath = "/veil"

// --- client side ---------------------------------------------------------

// WSSDialer tunnels veil frames inside a WebSocket over TLS on :443. This is the
// full-obfuscation transport: to a network observer it is indistinguishable from
// ordinary HTTPS/WebSocket web traffic, and it traverses HTTP proxies and most DPI.
type WSSDialer struct {
	// ServerName is the TLS SNI / Host used when dialing (usually the domain).
	ServerName string
}

// Name implements Dialer.
func (WSSDialer) Name() config.TransportName { return config.TransportWSS }

// Dial opens a WebSocket to endpoint, which must be a full URL
// (e.g. "wss://vpn.example.com:443/veil"). TLS verification is skipped because
// the tunnel's security is the Noise layer (see TLSDialer's note).
func (d WSSDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	httpClient := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // security is the Noise layer
				ServerName:         d.ServerName,
				MinVersion:         tls.VersionTLS12,
			},
		},
	}
	c, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPClient: httpClient})
	if err != nil {
		return nil, fmt.Errorf("wss dial %s: %w", endpoint, err)
	}
	c.SetReadLimit(wsReadLimit)
	return newWSConn(c), nil
}

// wsConn adapts a WebSocket (already message-oriented) to transport.Conn.
type wsConn struct {
	c      *websocket.Conn
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
	once   sync.Once
}

func newWSConn(c *websocket.Conn) *wsConn {
	ctx, cancel := context.WithCancel(context.Background())
	return &wsConn{c: c, ctx: ctx, cancel: cancel, done: make(chan struct{})}
}

func (w *wsConn) Send(b []byte) error {
	return w.c.Write(w.ctx, websocket.MessageBinary, b)
}

func (w *wsConn) Recv() ([]byte, error) {
	_, data, err := w.c.Read(w.ctx)
	return data, err
}

func (w *wsConn) Close() error {
	w.once.Do(func() {
		close(w.done)
		w.cancel()
		// CloseNow skips the WebSocket close handshake: the tunnel's own close
		// frame already handles graceful teardown, and we don't want to block on
		// a peer that has stopped reading.
		_ = w.c.CloseNow()
	})
	return nil
}

func (w *wsConn) Transport() config.TransportName { return config.TransportWSS }

// --- server side ---------------------------------------------------------

// WSSListener serves an HTTPS site that upgrades TunnelPath to a tunnel
// WebSocket and serves a decoy page everywhere else.
type WSSListener struct {
	ln     net.Listener
	srv    *http.Server
	accept chan Conn
	closed chan struct{}
	once   sync.Once
}

// ListenWSS binds an HTTPS listener on addr using cert. Requests to TunnelPath
// become tunnel connections returned by Accept; all other requests are handled
// by decoy (a default plausible page is used if decoy is nil).
func ListenWSS(addr string, cert tls.Certificate, decoy http.Handler) (*WSSListener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen wss %s: %w", addr, err)
	}
	tlsLn := tls.NewListener(ln, &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	})

	l := &WSSListener{
		ln:     ln,
		accept: make(chan Conn, 16),
		closed: make(chan struct{}),
	}
	if decoy == nil {
		decoy = http.HandlerFunc(defaultDecoy)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(TunnelPath, l.handleUpgrade)
	mux.Handle("/", decoy)
	l.srv = &http.Server{
		Handler: mux,
		// Silence per-connection TLS/HTTP noise (e.g. transport probes that
		// negotiate a different ALPN); these are expected on a public endpoint.
		ErrorLog: log.New(io.Discard, "", 0),
	}

	go l.srv.Serve(tlsLn)
	return l, nil
}

func (l *WSSListener) handleUpgrade(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	c.SetReadLimit(wsReadLimit)
	conn := newWSConn(c)

	select {
	case l.accept <- conn:
	case <-l.closed:
		conn.Close()
		return
	case <-r.Context().Done():
		conn.Close()
		return
	}

	// The HTTP handler goroutine owns the WebSocket for its lifetime; block until
	// the tunnel closes the connection (or the listener shuts down).
	select {
	case <-conn.done:
	case <-l.closed:
		conn.Close()
	}
}

// Accept returns the next tunnel connection.
func (l *WSSListener) Accept() (Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close shuts the HTTPS server down.
func (l *WSSListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.srv.Close()
}

// Addr returns the local listen address.
func (l *WSSListener) Addr() net.Addr { return l.ln.Addr() }

// DecoyHandler returns the built-in decoy site handler, so callers composing
// their own routes (e.g. a control-plane mux) can serve it at "/".
func DecoyHandler() http.Handler { return http.HandlerFunc(defaultDecoy) }

// defaultDecoy serves an innocuous page so that probing the server's root looks
// like an ordinary website rather than a VPN endpoint.
func defaultDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Server", "nginx")
	_, _ = w.Write([]byte(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>It works!</title></head>
<body><h1>It works!</h1><p>This is the default web page for this server.</p></body></html>
`))
}
