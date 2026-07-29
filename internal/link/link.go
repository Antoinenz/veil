// Package link ties the crypto (internal/noise), framing (internal/tunnel) and
// wire transports (internal/transport) into a single working tunnel: it performs
// the Noise IK handshake over a transport.Conn using veil frames, then carries
// encrypted IP packets as data frames.
//
// A Link is transport-agnostic — the same code runs over UDP today and over
// TCP/TLS/WSS once those transports land (M2).
package link

import (
	"errors"
	"fmt"

	"github.com/veilvpn/veil/internal/noise"
	"github.com/veilvpn/veil/internal/transport"
	"github.com/veilvpn/veil/internal/tunnel"
)

// ErrClosed is returned by ReadPacket when the peer sent a close frame.
var ErrClosed = errors.New("link: closed by peer")

// Link is an established, encrypted tunnel over one transport connection.
type Link struct {
	conn transport.Conn
	sess *noise.Session
	peer []byte // remote static public key
}

// Client performs the initiator (client) side of the handshake over conn.
//
// static is this device's keypair; serverStatic is the server's pinned static
// public key; psk is an optional 32-byte pre-shared key (nil to disable).
func Client(conn transport.Conn, static *noise.KeyPair, serverStatic, psk []byte) (*Link, error) {
	hs, err := noise.NewHandshake(noise.Config{
		Role:         noise.Initiator,
		Static:       static,
		RemoteStatic: serverStatic,
		PresharedKey: psk,
	})
	if err != nil {
		return nil, err
	}

	msg1, done, err := hs.WriteMessage(nil)
	if err != nil {
		return nil, err
	}
	if err := writeFrame(conn, tunnel.Frame{Type: tunnel.TypeHandshakeInit, Payload: msg1}); err != nil {
		return nil, fmt.Errorf("send handshake init: %w", err)
	}

	f, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("recv handshake resp: %w", err)
	}
	if f.Type != tunnel.TypeHandshakeResp {
		return nil, fmt.Errorf("link: expected handshake_resp, got %s", f.Type)
	}
	if _, done, err = hs.ReadMessage(f.Payload); err != nil {
		return nil, err
	}
	if !done {
		return nil, errors.New("link: handshake did not complete after resp")
	}

	sess, err := hs.Session()
	if err != nil {
		return nil, err
	}
	return &Link{conn: conn, sess: sess, peer: hs.PeerStatic()}, nil
}

// Server performs the responder (server) side of the handshake over conn and
// returns the Link. The authenticated client static key is available via Peer.
func Server(conn transport.Conn, static *noise.KeyPair, psk []byte) (*Link, error) {
	hs, err := noise.NewHandshake(noise.Config{
		Role:         noise.Responder,
		Static:       static,
		PresharedKey: psk,
	})
	if err != nil {
		return nil, err
	}

	f, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("recv handshake init: %w", err)
	}
	if f.Type != tunnel.TypeHandshakeInit {
		return nil, fmt.Errorf("link: expected handshake_init, got %s", f.Type)
	}
	if _, _, err = hs.ReadMessage(f.Payload); err != nil {
		return nil, err
	}

	msg2, done, err := hs.WriteMessage(nil)
	if err != nil {
		return nil, err
	}
	if !done {
		return nil, errors.New("link: handshake did not complete after resp")
	}
	if err := writeFrame(conn, tunnel.Frame{Type: tunnel.TypeHandshakeResp, Payload: msg2}); err != nil {
		return nil, fmt.Errorf("send handshake resp: %w", err)
	}

	sess, err := hs.Session()
	if err != nil {
		return nil, err
	}
	return &Link{conn: conn, sess: sess, peer: hs.PeerStatic()}, nil
}

// Peer returns the authenticated static public key of the remote endpoint.
func (l *Link) Peer() []byte { return l.peer }

// seal encrypts plaintext and sends it as a frame of the given type.
func (l *Link) seal(t tunnel.Type, plaintext []byte) error {
	ctr, ct, err := l.sess.Seal(plaintext)
	if err != nil {
		return err
	}
	return writeFrame(l.conn, tunnel.Frame{Type: t, Counter: ctr, Payload: ct})
}

// WritePacket seals an IP packet and sends it as a data frame.
func (l *Link) WritePacket(packet []byte) error {
	return l.seal(tunnel.TypeData, packet)
}

// SendConfig sends an encrypted control message (server -> client network
// configuration), delivered immediately after the handshake.
func (l *Link) SendConfig(b []byte) error {
	return l.seal(tunnel.TypeConfig, b)
}

// RecvConfig receives and decrypts the first control message. It must be called
// once by the client right after Client() returns, before reading packets.
func (l *Link) RecvConfig() ([]byte, error) {
	f, err := readFrame(l.conn)
	if err != nil {
		return nil, err
	}
	if f.Type != tunnel.TypeConfig {
		return nil, fmt.Errorf("link: expected config frame, got %s", f.Type)
	}
	return l.sess.Open(f.Counter, f.Payload)
}

// ReadPacket receives and decrypts the next IP packet. Keepalives are consumed
// transparently; a close frame yields ErrClosed.
func (l *Link) ReadPacket() ([]byte, error) {
	for {
		f, err := readFrame(l.conn)
		if err != nil {
			return nil, err
		}
		switch f.Type {
		case tunnel.TypeData:
			return l.sess.Open(f.Counter, f.Payload)
		case tunnel.TypeKeepalive, tunnel.TypeConfig:
			continue // liveness / late config: not IP data, skip
		case tunnel.TypeClose:
			return nil, ErrClosed
		default:
			return nil, fmt.Errorf("link: unexpected frame %s in data phase", f.Type)
		}
	}
}

// Keepalive sends an empty keepalive frame (NAT hole punching / liveness).
func (l *Link) Keepalive() error {
	return writeFrame(l.conn, tunnel.Frame{Type: tunnel.TypeKeepalive})
}

// Close sends a best-effort close frame and tears down the transport.
func (l *Link) Close() error {
	_ = writeFrame(l.conn, tunnel.Frame{Type: tunnel.TypeClose})
	return l.conn.Close()
}

// writeFrame encodes f and sends it as one transport message.
func writeFrame(conn transport.Conn, f tunnel.Frame) error {
	buf, err := f.Encode(nil)
	if err != nil {
		return err
	}
	return conn.Send(buf)
}

// readFrame receives one transport message and decodes a single frame from it.
// (Datagram transports carry exactly one frame per message.)
func readFrame(conn transport.Conn) (tunnel.Frame, error) {
	b, err := conn.Recv()
	if err != nil {
		return tunnel.Frame{}, err
	}
	f, _, err := tunnel.Decode(b)
	return f, err
}
