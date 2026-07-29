package transport

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/veilvpn/veil/internal/config"
)

// streamConn adapts a byte-stream (TCP/TLS/WebSocket) to the message-oriented
// transport.Conn by length-delimiting each message with a 2-byte big-endian
// prefix. This mirrors what datagram transports get for free.
type streamConn struct {
	rwc  io.ReadWriteCloser
	name config.TransportName

	wmu sync.Mutex // serialize writes (length prefix + payload must be atomic)
	rmu sync.Mutex
	hdr [2]byte
}

func newStreamConn(rwc io.ReadWriteCloser, name config.TransportName) *streamConn {
	return &streamConn{rwc: rwc, name: name}
}

func (c *streamConn) Send(b []byte) error {
	if len(b) > maxDatagram-1 {
		return fmt.Errorf("transport: message too large (%d bytes)", len(b))
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(b)))
	if _, err := c.rwc.Write(hdr[:]); err != nil {
		return err
	}
	_, err := c.rwc.Write(b)
	return err
}

func (c *streamConn) Recv() ([]byte, error) {
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if _, err := io.ReadFull(c.rwc, c.hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(c.hdr[:]))
	buf := make([]byte, n)
	if _, err := io.ReadFull(c.rwc, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func (c *streamConn) Close() error                    { return c.rwc.Close() }
func (c *streamConn) Transport() config.TransportName { return c.name }

// streamListener wraps a net.Listener, adapting accepted stream connections to
// message-oriented transport.Conns of the given transport name.
type streamListener struct {
	ln   net.Listener
	name config.TransportName
}

func (l *streamListener) Accept() (Conn, error) {
	c, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	return newStreamConn(c, l.name), nil
}

func (l *streamListener) Close() error   { return l.ln.Close() }
func (l *streamListener) Addr() net.Addr { return l.ln.Addr() }
