package link

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/veilvpn/veil/internal/noise"
	"github.com/veilvpn/veil/internal/transport"
)

// TestEndToEndOverUDP is the M1 proof-of-core: a real UDP socket, the real Noise
// IK handshake carried in veil frames, then encrypted packets both directions —
// exercising noise + tunnel + transport + link together, no privileges required.
func TestEndToEndOverUDP(t *testing.T) {
	serverKP, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	clientKP, err := noise.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	lis, err := transport.ListenUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()

	type result struct {
		peer []byte
		got  []byte
		err  error
	}
	serverDone := make(chan result, 1)

	go func() {
		conn, err := lis.Accept()
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		srv, err := Server(conn, serverKP, nil)
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		// Echo one packet back, upper-cased-ish (prefix), to prove both directions.
		pkt, err := srv.ReadPacket()
		if err != nil {
			serverDone <- result{err: err}
			return
		}
		if err := srv.WritePacket(append([]byte("echo:"), pkt...)); err != nil {
			serverDone <- result{err: err}
			return
		}
		serverDone <- result{peer: srv.Peer(), got: pkt}
	}()

	dialer := transport.UDPDialer{}
	conn, err := dialer.Dial(context.Background(), lis.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	cli, err := Client(conn, clientKP, serverKP.Public.Bytes(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// Server must have authenticated us as the client's static key.
	if !bytes.Equal(cli.Peer(), serverKP.Public.Bytes()) {
		t.Fatalf("client saw wrong server key")
	}

	payload := []byte("hello through the tunnel")
	if err := cli.WritePacket(payload); err != nil {
		t.Fatal(err)
	}
	reply, err := cli.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte("echo:"), payload...); !bytes.Equal(reply, want) {
		t.Fatalf("reply mismatch: got %q want %q", reply, want)
	}

	select {
	case r := <-serverDone:
		if r.err != nil {
			t.Fatalf("server: %v", r.err)
		}
		if !bytes.Equal(r.got, payload) {
			t.Fatalf("server received %q, want %q", r.got, payload)
		}
		if !bytes.Equal(r.peer, clientKP.Public.Bytes()) {
			t.Fatalf("server authenticated wrong client key")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for server")
	}
}
