package noise

import (
	"strings"
	"testing"
)

func TestFingerprintStableAndDistinct(t *testing.T) {
	a, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	fp := Fingerprint(a.Public)
	if !strings.HasPrefix(fp, "veil:") {
		t.Fatalf("fingerprint missing prefix: %s", fp)
	}
	if fp != Fingerprint(a.Public) {
		t.Fatal("fingerprint not stable across calls")
	}
	if fp == Fingerprint(b.Public) {
		t.Fatal("distinct keys produced identical fingerprints")
	}
}

func TestPublicKeyRoundTrip(t *testing.T) {
	kp, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	pub, err := PublicKeyFromBytes(kp.Public.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if Fingerprint(pub) != Fingerprint(kp.Public) {
		t.Fatal("round-tripped public key changed fingerprint")
	}
}
