package noise

import (
	"bytes"
	"crypto/rand"
	"testing"
)

// runHandshake completes an IK exchange and returns both sessions.
func runHandshake(t *testing.T, psk []byte) (*Session, *Session) {
	t.Helper()
	server, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	client, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	ini, err := NewHandshake(Config{
		Role:         Initiator,
		Static:       client,
		RemoteStatic: server.Public.Bytes(),
		PresharedKey: psk,
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := NewHandshake(Config{
		Role:         Responder,
		Static:       server,
		PresharedKey: psk,
	})
	if err != nil {
		t.Fatal(err)
	}

	msg1, done, err := ini.WriteMessage(nil)
	if err != nil || done {
		t.Fatalf("msg1: err=%v done=%v", err, done)
	}
	if _, done, err = res.ReadMessage(msg1); err != nil || done {
		t.Fatalf("read msg1: err=%v done=%v", err, done)
	}
	msg2, done, err := res.WriteMessage(nil)
	if err != nil || !done {
		t.Fatalf("msg2: err=%v done=%v (want done)", err, done)
	}
	if _, done, err = ini.ReadMessage(msg2); err != nil || !done {
		t.Fatalf("read msg2: err=%v done=%v (want done)", err, done)
	}

	// Responder must have learned the initiator's static key (mutual auth).
	if !bytes.Equal(res.PeerStatic(), client.Public.Bytes()) {
		t.Fatal("responder did not learn initiator static key")
	}

	cs, err := ini.Session()
	if err != nil {
		t.Fatal(err)
	}
	ss, err := res.Session()
	if err != nil {
		t.Fatal(err)
	}
	return cs, ss
}

func TestHandshakeAndTransport(t *testing.T) {
	clientSess, serverSess := runHandshake(t, nil)

	// client -> server
	payload := []byte("the quick brown fox")
	ctr, ct, err := clientSess.Seal(payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := serverSess.Open(ctr, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("client->server mismatch: %q", got)
	}

	// server -> client (opposite direction key)
	reply := []byte("jumps over the lazy dog")
	ctr, ct, err = serverSess.Seal(reply)
	if err != nil {
		t.Fatal(err)
	}
	got, err = clientSess.Open(ctr, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, reply) {
		t.Fatalf("server->client mismatch: %q", got)
	}
}

func TestTransportOutOfOrder(t *testing.T) {
	clientSess, serverSess := runHandshake(t, nil)

	// Seal three messages, then open them out of order — the explicit counter
	// must let the receiver decrypt regardless of arrival order.
	type pkt struct {
		ctr uint64
		ct  []byte
	}
	var pkts []pkt
	want := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	for _, m := range want {
		ctr, ct, err := clientSess.Seal(m)
		if err != nil {
			t.Fatal(err)
		}
		pkts = append(pkts, pkt{ctr, ct})
	}
	for i := len(pkts) - 1; i >= 0; i-- {
		got, err := serverSess.Open(pkts[i].ctr, pkts[i].ct)
		if err != nil {
			t.Fatalf("open reordered pkt %d: %v", i, err)
		}
		if !bytes.Equal(got, want[i]) {
			t.Fatalf("pkt %d mismatch: %q", i, got)
		}
	}
}

func TestHandshakeWithPSK(t *testing.T) {
	psk := make([]byte, 32)
	if _, err := rand.Read(psk); err != nil {
		t.Fatal(err)
	}
	clientSess, serverSess := runHandshake(t, psk)
	ctr, ct, err := clientSess.Seal([]byte("psk-protected"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := serverSess.Open(ctr, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, []byte("psk-protected")) {
		t.Fatalf("psk transport mismatch: %q", got)
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	clientSess, serverSess := runHandshake(t, nil)
	ctr, ct, err := clientSess.Seal([]byte("authentic"))
	if err != nil {
		t.Fatal(err)
	}
	ct[0] ^= 0xFF // flip a bit
	if _, err := serverSess.Open(ctr, ct); err == nil {
		t.Fatal("expected AEAD failure on tampered ciphertext")
	}
}
