package link

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/veilvpn/veil/internal/certutil"
	"github.com/veilvpn/veil/internal/noise"
	"github.com/veilvpn/veil/internal/transport"
)

// runTunnelEcho runs the full handshake + a round-trip echo over the given
// listener/dialer pair, asserting the tunnel carries data both ways.
func runTunnelEcho(t *testing.T, lis transport.Listener, dial func(ctx context.Context) (transport.Conn, error)) {
	t.Helper()
	serverKP, _ := noise.GenerateKeyPair()
	clientKP, _ := noise.GenerateKeyPair()

	srvErr := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			srvErr <- err
			return
		}
		srv, err := Server(conn, serverKP, nil)
		if err != nil {
			srvErr <- err
			return
		}
		pkt, err := srv.ReadPacket()
		if err != nil {
			srvErr <- err
			return
		}
		srvErr <- srv.WritePacket(append([]byte("echo:"), pkt...))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	cli, err := Client(conn, clientKP, serverKP.Public.Bytes(), nil)
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	defer cli.Close()

	payload := []byte("payload over transport")
	if err := cli.WritePacket(payload); err != nil {
		t.Fatal(err)
	}
	reply, err := cli.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if want := append([]byte("echo:"), payload...); !bytes.Equal(reply, want) {
		t.Fatalf("reply = %q, want %q", reply, want)
	}
	if err := <-srvErr; err != nil {
		t.Fatalf("server: %v", err)
	}
}

func TestTunnelOverTCP(t *testing.T) {
	lis, err := transport.ListenTCP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	runTunnelEcho(t, lis, func(ctx context.Context) (transport.Conn, error) {
		return transport.TCPDialer{}.Dial(ctx, lis.Addr().String())
	})
}

func TestTunnelOverTLS(t *testing.T) {
	cert, err := certutil.SelfSigned("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	lis, err := transport.ListenTLS("127.0.0.1:0", cert)
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	runTunnelEcho(t, lis, func(ctx context.Context) (transport.Conn, error) {
		return transport.TLSDialer{ServerName: "127.0.0.1"}.Dial(ctx, lis.Addr().String())
	})
}

func TestTunnelOverWSS(t *testing.T) {
	tlsCfg, err := certutil.SelfSignedConfig("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	const token = "test-tunnel-token"
	lis, err := transport.ListenWSS("127.0.0.1:0", tlsCfg, nil, token)
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	runTunnelEcho(t, lis, func(ctx context.Context) (transport.Conn, error) {
		return transport.WSSDialer{ServerName: "127.0.0.1", AuthToken: token}.Dial(ctx, "wss://"+lis.Addr().String()+transport.TunnelPath)
	})
}
