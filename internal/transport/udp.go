package transport

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/veilvpn/veil/internal/config"
)

// maxDatagram bounds a single UDP payload we will read: a full veil frame
// (header + max payload) plus a little slack. Frames larger than this are a bug.
const maxDatagram = 1 << 16 // 65536

// --- client side ---------------------------------------------------------

// UDPDialer dials the server over plain UDP (the fastest, default transport).
type UDPDialer struct{}

// Name implements Dialer.
func (UDPDialer) Name() config.TransportName { return config.TransportUDP }

// Dial connects a UDP socket to endpoint ("host:port").
func (UDPDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", endpoint)
	if err != nil {
		return nil, fmt.Errorf("udp dial %s: %w", endpoint, err)
	}
	return &udpClientConn{conn: c.(*net.UDPConn)}, nil
}

type udpClientConn struct {
	conn *net.UDPConn
}

func (c *udpClientConn) Send(b []byte) error {
	_, err := c.conn.Write(b)
	return err
}

func (c *udpClientConn) Recv() ([]byte, error) {
	buf := make([]byte, maxDatagram)
	n, err := c.conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (c *udpClientConn) Close() error                    { return c.conn.Close() }
func (c *udpClientConn) Transport() config.TransportName { return config.TransportUDP }

// --- server side ---------------------------------------------------------

// UDPListener owns one UDP socket and demultiplexes inbound datagrams into a
// per-remote-address Conn, so the rest of the server can treat each client as a
// connection even though UDP is connectionless.
type UDPListener struct {
	pc *net.UDPConn

	mu     sync.Mutex
	conns  map[string]*udpServerConn
	accept chan *udpServerConn
	closed chan struct{}
	once   sync.Once
}

// ListenUDP binds a UDP socket on addr (e.g. ":443") and starts demuxing.
func ListenUDP(addr string) (*UDPListener, error) {
	ua, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", addr, err)
	}
	pc, err := net.ListenUDP("udp", ua)
	if err != nil {
		return nil, fmt.Errorf("listen udp %s: %w", addr, err)
	}
	l := &UDPListener{
		pc:     pc,
		conns:  make(map[string]*udpServerConn),
		accept: make(chan *udpServerConn, 16),
		closed: make(chan struct{}),
	}
	go l.readLoop()
	return l, nil
}

// Addr returns the local listen address.
func (l *UDPListener) Addr() net.Addr { return l.pc.LocalAddr() }

// Accept returns the next newly-seen client connection.
func (l *UDPListener) Accept() (Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

// Close shuts the listener and all derived connections down.
func (l *UDPListener) Close() error {
	l.once.Do(func() { close(l.closed) })
	return l.pc.Close()
}

func (l *UDPListener) readLoop() {
	buf := make([]byte, maxDatagram)
	for {
		n, raddr, err := l.pc.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-l.closed:
			default:
				l.Close()
			}
			return
		}
		key := raddr.String()

		l.mu.Lock()
		c, ok := l.conns[key]
		if !ok {
			c = &udpServerConn{
				l:     l,
				raddr: raddr,
				in:    make(chan []byte, 64),
				dead:  make(chan struct{}),
			}
			l.conns[key] = c
			l.mu.Unlock()
			select {
			case l.accept <- c:
			case <-l.closed:
				return
			}
		} else {
			l.mu.Unlock()
		}

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case c.in <- pkt:
		case <-c.dead:
		case <-l.closed:
			return
		default:
			// Receiver is backed up; drop (UDP semantics — upper layers recover).
		}
	}
}

func (l *UDPListener) remove(key string) {
	l.mu.Lock()
	delete(l.conns, key)
	l.mu.Unlock()
}

type udpServerConn struct {
	l     *UDPListener
	raddr *net.UDPAddr
	in    chan []byte
	dead  chan struct{}
	once  sync.Once
}

func (c *udpServerConn) Send(b []byte) error {
	_, err := c.l.pc.WriteToUDP(b, c.raddr)
	return err
}

func (c *udpServerConn) Recv() ([]byte, error) {
	select {
	case pkt := <-c.in:
		return pkt, nil
	case <-c.dead:
		return nil, net.ErrClosed
	case <-c.l.closed:
		return nil, net.ErrClosed
	}
}

func (c *udpServerConn) Close() error {
	c.once.Do(func() {
		close(c.dead)
		c.l.remove(c.raddr.String())
	})
	return nil
}

func (c *udpServerConn) Transport() config.TransportName { return config.TransportUDP }

// RemoteAddr exposes the peer address (useful for logging / rate-limiting).
func (c *udpServerConn) RemoteAddr() net.Addr { return c.raddr }
