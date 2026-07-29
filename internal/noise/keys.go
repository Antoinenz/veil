// Package noise wraps veil's cryptographic core. The tunnel handshake is the
// Noise Protocol Framework's IK pattern (mutual auth, forward secrecy, initiator
// identity hiding) over X25519 + ChaCha20-Poly1305 + BLAKE2s/SHA-256 — the same
// building blocks WireGuard uses. We deliberately do not implement ciphers
// ourselves; the full handshake state machine (M1) will be driven by a vetted
// Noise library.
//
// This file provides the pieces that are safe and useful now: static keypair
// generation and stable key fingerprints (used for TOFU pinning at enrollment).
package noise

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"
)

// KeyPair is a device/server static X25519 keypair.
type KeyPair struct {
	Private *ecdh.PrivateKey
	Public  *ecdh.PublicKey
}

// GenerateKeyPair creates a new X25519 static keypair using the system CSPRNG.
func GenerateKeyPair() (*KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("noise: generate key: %w", err)
	}
	return &KeyPair{Private: priv, Public: priv.PublicKey()}, nil
}

// PublicKeyFromBytes parses a 32-byte X25519 public key.
func PublicKeyFromBytes(b []byte) (*ecdh.PublicKey, error) {
	return ecdh.X25519().NewPublicKey(b)
}

// LoadKeyPair reconstructs a KeyPair from a 32-byte private key (as written to
// disk by `veil-server init` / `veil login`).
func LoadKeyPair(priv []byte) (*KeyPair, error) {
	p, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("noise: load key: %w", err)
	}
	return &KeyPair{Private: p, Public: p.PublicKey()}, nil
}

// fpEncoding is lowercase base32 without padding — short, unambiguous, and
// case-insensitive so fingerprints are easy to read aloud and compare.
var fpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Fingerprint returns a stable, human-verifiable identifier for a public key:
// a truncated SHA-256 rendered as grouped base32, e.g. "veil:AB4C-9K2M-...".
//
// Clients pin the server fingerprint at enrollment (trust-on-first-use); admins
// can read the printed fingerprint out-of-band to detect MITM.
func Fingerprint(pub *ecdh.PublicKey) string {
	sum := sha256.Sum256(pub.Bytes())
	enc := strings.ToLower(fpEncoding.EncodeToString(sum[:10])) // 80 bits
	var groups []string
	for i := 0; i < len(enc); i += 4 {
		end := i + 4
		if end > len(enc) {
			end = len(enc)
		}
		groups = append(groups, enc[i:end])
	}
	return "veil:" + strings.Join(groups, "-")
}
