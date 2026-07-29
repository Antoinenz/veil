package noise

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/flynn/noise"
)

// Role identifies the two ends of the Noise IK handshake.
type Role int

const (
	// Initiator is the client; it knows the responder's static public key.
	Initiator Role = iota
	// Responder is the server.
	Responder
)

// cipherSuite pins veil's primitives: X25519 + ChaCha20-Poly1305 + BLAKE2s.
var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)

// Config parameterizes a handshake.
type Config struct {
	Role Role
	// Static is this endpoint's long-term keypair.
	Static *KeyPair
	// RemoteStatic is the peer's static public key (32 bytes). Required for the
	// initiator (IK: the initiator knows the responder's key up front); the
	// responder learns it during the handshake and may leave this nil.
	RemoteStatic []byte
	// PresharedKey optionally hardens the handshake (WireGuard psk2-style). It
	// must be 32 bytes if set, or nil.
	PresharedKey []byte
}

// Handshake drives one side of the Noise IK exchange (2 messages total):
//
//	initiator: msg1 = WriteMessage();           ... ReadMessage(msg2) -> done
//	responder: ReadMessage(msg1); msg2 = WriteMessage() -> done
type Handshake struct {
	hs        *noise.HandshakeState
	initiator bool
	session   *Session
}

// NewHandshake constructs an IK handshake for the given config.
func NewHandshake(cfg Config) (*Handshake, error) {
	if cfg.Static == nil {
		return nil, fmt.Errorf("noise: static keypair required")
	}
	if len(cfg.PresharedKey) != 0 && len(cfg.PresharedKey) != 32 {
		return nil, fmt.Errorf("noise: preshared key must be 32 bytes, got %d", len(cfg.PresharedKey))
	}
	ncfg := noise.Config{
		CipherSuite:   cipherSuite,
		Random:        rand.Reader,
		Pattern:       noise.HandshakeIK,
		Initiator:     cfg.Role == Initiator,
		StaticKeypair: noise.DHKey{Private: cfg.Static.Private.Bytes(), Public: cfg.Static.Public.Bytes()},
	}
	if cfg.Role == Initiator {
		if len(cfg.RemoteStatic) == 0 {
			return nil, fmt.Errorf("noise: initiator requires the server's static public key")
		}
		ncfg.PeerStatic = cfg.RemoteStatic
	}
	if len(cfg.PresharedKey) == 32 {
		ncfg.PresharedKey = cfg.PresharedKey
		ncfg.PresharedKeyPlacement = 2 // psk2: after the second DH, WireGuard-style
	}
	hs, err := noise.NewHandshakeState(ncfg)
	if err != nil {
		return nil, fmt.Errorf("noise: init handshake: %w", err)
	}
	return &Handshake{hs: hs, initiator: cfg.Role == Initiator}, nil
}

// WriteMessage produces the next outbound handshake message. done is true once
// the handshake is complete (after which Session is available).
func (h *Handshake) WriteMessage(payload []byte) (msg []byte, done bool, err error) {
	out, cs1, cs2, err := h.hs.WriteMessage(nil, payload)
	if err != nil {
		return nil, false, fmt.Errorf("noise: write handshake message: %w", err)
	}
	if cs1 != nil && cs2 != nil {
		h.session = newSession(h.initiator, cs1, cs2)
	}
	return out, h.session != nil, nil
}

// ReadMessage consumes an inbound handshake message and returns any payload.
func (h *Handshake) ReadMessage(msg []byte) (payload []byte, done bool, err error) {
	out, cs1, cs2, err := h.hs.ReadMessage(nil, msg)
	if err != nil {
		return nil, false, fmt.Errorf("noise: read handshake message: %w", err)
	}
	if cs1 != nil && cs2 != nil {
		h.session = newSession(h.initiator, cs1, cs2)
	}
	return out, h.session != nil, nil
}

// PeerStatic returns the remote peer's static public key once known (the
// responder learns the initiator's key during the handshake). Returns nil if
// not yet available.
func (h *Handshake) PeerStatic() []byte {
	return h.hs.PeerStatic()
}

// Session returns the established Session, or an error if the handshake is
// incomplete.
func (h *Handshake) Session() (*Session, error) {
	if h.session == nil {
		return nil, fmt.Errorf("noise: handshake not complete")
	}
	return h.session, nil
}

// Session is a live, encrypted tunnel session. The AEAD nonce is driven
// explicitly by the caller-supplied frame counter so it tolerates the packet
// reordering/loss inherent to datagram transports (UDP).
type Session struct {
	send *noise.CipherState
	recv *noise.CipherState

	mu        sync.Mutex
	sendNonce uint64
}

// Split() returns (initiator->responder, responder->initiator); each side picks
// send/recv by role.
func newSession(initiator bool, cs1, cs2 *noise.CipherState) *Session {
	if initiator {
		return &Session{send: cs1, recv: cs2}
	}
	return &Session{send: cs2, recv: cs1}
}

// Seal encrypts plaintext and returns the counter that must be transmitted
// alongside the ciphertext (it becomes the AEAD nonce for Open on the far side).
func (s *Session) Seal(plaintext []byte) (counter uint64, ciphertext []byte, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := s.sendNonce
	s.send.SetNonce(n)
	ct, err := s.send.Encrypt(nil, nil, plaintext)
	if err != nil {
		return 0, nil, fmt.Errorf("noise: seal: %w", err)
	}
	s.sendNonce++
	return n, ct, nil
}

// Open decrypts ciphertext that arrived with the given counter.
func (s *Session) Open(counter uint64, ciphertext []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recv.SetNonce(counter)
	pt, err := s.recv.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("noise: open (counter %d): %w", counter, err)
	}
	return pt, nil
}
