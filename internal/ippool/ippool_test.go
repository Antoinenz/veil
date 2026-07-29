package ippool

import (
	"net/netip"
	"testing"
)

func TestGatewayAndFirstAllocations(t *testing.T) {
	p, err := New("100.64.0.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Gateway().String(); got != "100.64.0.1" {
		t.Fatalf("gateway = %s, want 100.64.0.1", got)
	}
	a, err := p.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != "100.64.0.2" {
		t.Fatalf("first alloc = %s, want 100.64.0.2", a)
	}
	b, _ := p.Allocate()
	if b.String() != "100.64.0.3" {
		t.Fatalf("second alloc = %s, want 100.64.0.3", b)
	}
}

func TestStableAllocationPerKey(t *testing.T) {
	p, _ := New("10.0.0.0/24")
	a, _ := p.AllocateFor("deviceA")
	again, _ := p.AllocateFor("deviceA")
	if a != again {
		t.Fatalf("key not stable: %s vs %s", a, again)
	}
	b, _ := p.AllocateFor("deviceB")
	if a == b {
		t.Fatalf("distinct keys got same addr %s", a)
	}
}

func TestReleaseRecycles(t *testing.T) {
	p, _ := New("10.0.0.0/24")
	a, _ := p.Allocate()
	p.Release(a)
	b, _ := p.Allocate()
	if a != b {
		t.Fatalf("released addr not recycled: got %s want %s", b, a)
	}
}

func TestExhaustionSmallPrefix(t *testing.T) {
	// /30: .0 network, .1 gateway, .2 usable, .3 broadcast => exactly 1 client.
	p, err := New("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	if a.String() != "192.168.1.2" {
		t.Fatalf("got %s, want 192.168.1.2", a)
	}
	if _, err := p.Allocate(); err != ErrExhausted {
		t.Fatalf("expected ErrExhausted, got %v", err)
	}
	// After releasing, the address is available again.
	p.Release(a)
	if _, err := p.Allocate(); err != nil {
		t.Fatalf("post-release alloc failed: %v", err)
	}
}

func TestLastAddr(t *testing.T) {
	cases := map[string]string{
		"192.168.1.0/24": "192.168.1.255",
		"192.168.1.0/30": "192.168.1.3",
		"10.0.0.0/8":     "10.255.255.255",
		"100.64.0.0/10":  "100.127.255.255",
	}
	for cidr, want := range cases {
		p := netip.MustParsePrefix(cidr)
		if got := lastAddr(p).String(); got != want {
			t.Fatalf("lastAddr(%s) = %s, want %s", cidr, got, want)
		}
	}
}
