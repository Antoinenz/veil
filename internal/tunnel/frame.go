// Package tunnel implements veil's custom wire framing and the TUN device
// abstraction. Frames are the unit carried by every transport; their payload is
// (for data frames) a Noise-encrypted IP packet.
//
// Wire format (big-endian), fixed 12-byte header + payload:
//
//		 0        1        2 .. 9            10 .. 11     12 ..
//		+--------+--------+-----------------+-----------+-----------+
//		| ver=1  | type   | counter (u64)   | len (u16) | payload   |
//		+--------+--------+-----------------+-----------+-----------+
//
//	  - counter: monotonically increasing per-session nonce, used for replay
//	    protection and as the AEAD nonce basis in the crypto layer.
//	  - len: payload length in bytes (0..MaxPayload).
package tunnel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// Version is the current wire-format version.
	Version byte = 1
	// HeaderSize is the fixed frame header length in bytes.
	HeaderSize = 12
	// MaxPayload bounds a single frame's payload — the max a u16 length field can
	// express. Comfortably fits a jumbo MTU plus the AEAD tag.
	MaxPayload = (1 << 16) - 1 // 65535
)

// Type enumerates frame kinds.
type Type byte

const (
	TypeHandshakeInit Type = 1 // client -> server: Noise message 1
	TypeHandshakeResp Type = 2 // server -> client: Noise message 2
	TypeData          Type = 3 // encrypted IP packet
	TypeKeepalive     Type = 4 // liveness / NAT keepalive, empty payload
	TypeClose         Type = 5 // graceful teardown
	TypeConfig        Type = 6 // encrypted control message (server -> client net config)
)

func (t Type) String() string {
	switch t {
	case TypeHandshakeInit:
		return "handshake_init"
	case TypeHandshakeResp:
		return "handshake_resp"
	case TypeData:
		return "data"
	case TypeKeepalive:
		return "keepalive"
	case TypeClose:
		return "close"
	case TypeConfig:
		return "config"
	default:
		return fmt.Sprintf("unknown(%d)", byte(t))
	}
}

// Errors returned by the codec.
var (
	ErrShortHeader   = errors.New("tunnel: short frame header")
	ErrBadVersion    = errors.New("tunnel: unsupported frame version")
	ErrPayloadTooBig = errors.New("tunnel: payload exceeds MaxPayload")
)

// Frame is a decoded veil frame.
type Frame struct {
	Type    Type
	Counter uint64
	Payload []byte
}

// Encode appends the wire encoding of f to dst and returns the extended slice.
// Passing a reusable dst (e.g. dst[:0]) avoids per-frame allocation on hot paths.
func (f Frame) Encode(dst []byte) ([]byte, error) {
	if len(f.Payload) > MaxPayload {
		return nil, ErrPayloadTooBig
	}
	var hdr [HeaderSize]byte
	hdr[0] = Version
	hdr[1] = byte(f.Type)
	binary.BigEndian.PutUint64(hdr[2:10], f.Counter)
	binary.BigEndian.PutUint16(hdr[10:12], uint16(len(f.Payload)))
	dst = append(dst, hdr[:]...)
	dst = append(dst, f.Payload...)
	return dst, nil
}

// Decode parses a single frame from b. It returns the frame and the number of
// bytes consumed. Payload references b (no copy); copy it if b will be reused.
func Decode(b []byte) (Frame, int, error) {
	if len(b) < HeaderSize {
		return Frame{}, 0, ErrShortHeader
	}
	if b[0] != Version {
		return Frame{}, 0, ErrBadVersion
	}
	plen := int(binary.BigEndian.Uint16(b[10:12]))
	total := HeaderSize + plen
	if len(b) < total {
		return Frame{}, 0, ErrShortHeader
	}
	return Frame{
		Type:    Type(b[1]),
		Counter: binary.BigEndian.Uint64(b[2:10]),
		Payload: b[HeaderSize:total],
	}, total, nil
}

// WriteFrame encodes f and writes it to w in a single call.
func WriteFrame(w io.Writer, f Frame) error {
	buf, err := f.Encode(make([]byte, 0, HeaderSize+len(f.Payload)))
	if err != nil {
		return err
	}
	_, err = w.Write(buf)
	return err
}

// ReadFrame reads exactly one frame from r (header first, then payload).
// Suitable for stream transports (TCP/TLS/WSS); datagram transports decode whole
// datagrams with Decode instead.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Frame{}, err
	}
	if hdr[0] != Version {
		return Frame{}, ErrBadVersion
	}
	plen := int(binary.BigEndian.Uint16(hdr[10:12]))
	payload := make([]byte, plen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Frame{}, err
	}
	return Frame{
		Type:    Type(hdr[1]),
		Counter: binary.BigEndian.Uint64(hdr[2:10]),
		Payload: payload,
	}, nil
}
