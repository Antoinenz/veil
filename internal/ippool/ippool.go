// Package ippool allocates virtual tunnel addresses to devices from a CIDR range
// (e.g. the CGNAT block 100.64.0.0/10). The first usable host is reserved as the
// server gateway; the rest are handed out to clients. Allocation can be stable
// per device key so a device keeps its address across reconnects.
package ippool

import (
	"fmt"
	"net/netip"
	"sync"
)

// Pool is a thread-safe allocator over an IPv4 prefix.
type Pool struct {
	mu      sync.Mutex
	prefix  netip.Prefix
	gateway netip.Addr
	last    netip.Addr // broadcast address (reserved)
	cursor  netip.Addr // next never-yet-used address
	free    []netip.Addr
	byKey   map[string]netip.Addr
	keyOf   map[netip.Addr]string
}

// New creates a pool over cidr. Only IPv4 is supported for now.
func New(cidr string) (*Pool, error) {
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, fmt.Errorf("ippool: parse %q: %w", cidr, err)
	}
	p = p.Masked()
	if !p.Addr().Is4() {
		return nil, fmt.Errorf("ippool: only IPv4 prefixes supported, got %s", cidr)
	}
	if p.Bits() > 30 {
		return nil, fmt.Errorf("ippool: prefix %s too small to host clients", cidr)
	}
	network := p.Addr()
	gateway := network.Next()
	pool := &Pool{
		prefix:  p,
		gateway: gateway,
		last:    lastAddr(p),
		cursor:  gateway.Next(),
		byKey:   make(map[string]netip.Addr),
		keyOf:   make(map[netip.Addr]string),
	}
	return pool, nil
}

// Gateway returns the server's reserved address (first usable host).
func (p *Pool) Gateway() netip.Addr { return p.gateway }

// Prefix returns the pool's network prefix.
func (p *Pool) Prefix() netip.Prefix { return p.prefix }

// ErrExhausted means every assignable address is in use.
var ErrExhausted = fmt.Errorf("ippool: address space exhausted")

// Allocate returns a fresh address not currently in use.
func (p *Pool) Allocate() (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.allocLocked()
}

// AllocateFor returns a stable address for key: the same address is returned on
// repeat calls (until Release), so a device keeps its IP across reconnects.
func (p *Pool) AllocateFor(key string) (netip.Addr, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if a, ok := p.byKey[key]; ok {
		return a, nil
	}
	a, err := p.allocLocked()
	if err != nil {
		return netip.Addr{}, err
	}
	p.byKey[key] = a
	p.keyOf[a] = key
	return a, nil
}

func (p *Pool) allocLocked() (netip.Addr, error) {
	if n := len(p.free); n > 0 {
		a := p.free[n-1]
		p.free = p.free[:n-1]
		return a, nil
	}
	// cursor walks toward (but excludes) the broadcast address.
	if p.cursor.Less(p.last) && p.prefix.Contains(p.cursor) {
		a := p.cursor
		p.cursor = p.cursor.Next()
		return a, nil
	}
	return netip.Addr{}, ErrExhausted
}

// Release returns addr to the pool and forgets any key binding.
func (p *Pool) Release(addr netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if key, ok := p.keyOf[addr]; ok {
		delete(p.byKey, key)
		delete(p.keyOf, addr)
	}
	p.free = append(p.free, addr)
}

// lastAddr returns the broadcast (all-ones host) address of an IPv4 prefix.
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr().As4()
	bits := p.Bits()
	for i := 0; i < 4; i++ {
		// Number of host bits within this byte.
		lo := i * 8
		if lo >= bits {
			a[i] = 0xff
			continue
		}
		if lo+8 <= bits {
			continue // fully network
		}
		hostBits := (lo + 8) - bits
		a[i] |= byte(0xff >> uint(8-hostBits))
	}
	return netip.AddrFrom4(a)
}
