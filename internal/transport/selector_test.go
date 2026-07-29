package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/veilvpn/veil/internal/config"
)

// fakeDialer succeeds after delay (if ok) or fails.
type fakeDialer struct {
	name  config.TransportName
	ok    bool
	delay time.Duration
}

func (d fakeDialer) Name() config.TransportName { return d.name }

func (d fakeDialer) Dial(ctx context.Context, endpoint string) (Conn, error) {
	select {
	case <-time.After(d.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if !d.ok {
		return nil, errors.New("blocked")
	}
	return fakeConn{name: d.name}, nil
}

type fakeConn struct{ name config.TransportName }

func (c fakeConn) Send([]byte) error               { return nil }
func (c fakeConn) Recv() ([]byte, error)           { return nil, nil }
func (c fakeConn) Close() error                    { return nil }
func (c fakeConn) Transport() config.TransportName { return c.name }

func allEndpoints() Endpoints {
	return Endpoints{
		config.TransportUDP: "udp",
		config.TransportTCP: "tcp",
		config.TransportTLS: "tls",
		config.TransportWSS: "wss",
	}
}

func TestSelectPrefersFasterAvailable(t *testing.T) {
	sel := NewSelector([]Dialer{
		fakeDialer{name: config.TransportUDP, ok: true, delay: 5 * time.Millisecond},
		fakeDialer{name: config.TransportWSS, ok: true, delay: 5 * time.Millisecond},
	}, WithStagger(2*time.Millisecond))

	conn, name, err := sel.Select(context.Background(), allEndpoints(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if name != config.TransportUDP {
		t.Fatalf("want udp to win, got %s", name)
	}
}

func TestSelectFallsBackWhenUDPBlocked(t *testing.T) {
	// UDP + TCP + TLS blocked, only WSS works — the hostile-network case.
	sel := NewSelector([]Dialer{
		fakeDialer{name: config.TransportUDP, ok: false, delay: time.Millisecond},
		fakeDialer{name: config.TransportTCP, ok: false, delay: time.Millisecond},
		fakeDialer{name: config.TransportTLS, ok: false, delay: time.Millisecond},
		fakeDialer{name: config.TransportWSS, ok: true, delay: 5 * time.Millisecond},
	}, WithStagger(time.Millisecond))

	conn, name, err := sel.Select(context.Background(), allEndpoints(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if name != config.TransportWSS {
		t.Fatalf("want wss fallback, got %s", name)
	}
}

func TestSelectAllBlocked(t *testing.T) {
	sel := NewSelector([]Dialer{
		fakeDialer{name: config.TransportUDP, ok: false, delay: time.Millisecond},
		fakeDialer{name: config.TransportWSS, ok: false, delay: time.Millisecond},
	}, WithStagger(time.Millisecond))

	if _, _, err := sel.Select(context.Background(), allEndpoints(), ""); !errors.Is(err, ErrNoTransport) {
		t.Fatalf("want ErrNoTransport, got %v", err)
	}
}

func TestSelectMemoryRecordsAndPrefers(t *testing.T) {
	mem := NewMemMemory()
	sel := NewSelector([]Dialer{
		fakeDialer{name: config.TransportUDP, ok: true, delay: 5 * time.Millisecond},
		fakeDialer{name: config.TransportWSS, ok: true, delay: 5 * time.Millisecond},
	}, WithStagger(2*time.Millisecond), WithMemory(mem))

	conn, _, err := sel.Select(context.Background(), allEndpoints(), "wifi-abc")
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if got, ok := mem.Preferred("wifi-abc"); !ok || got != config.TransportUDP {
		t.Fatalf("memory not recorded: got %s ok=%v", got, ok)
	}
}
