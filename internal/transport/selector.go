package transport

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/veilvpn/veil/internal/config"
)

// ErrNoTransport means every candidate transport failed to connect.
var ErrNoTransport = errors.New("transport: no working transport found")

// Selector performs "Happy-Eyeballs"-style transport selection: it races the
// registered dialers in priority order (with a small stagger so the preferred,
// faster transports get a head start) and returns the first Conn that connects.
//
// It also consults/updates a Memory so that, on a network where we already know
// which transport works, we try that one first for an instant reconnect.
type Selector struct {
	dialers map[config.TransportName]Dialer
	order   []config.TransportName
	stagger time.Duration
	memory  Memory
}

// Memory persists the last transport that worked on a given network so we can
// prefer it next time. Implementations key by a caller-provided network
// fingerprint (gateway MAC / SSID / subnet). A nil Memory disables memory.
type Memory interface {
	Preferred(networkID string) (config.TransportName, bool)
	Remember(networkID string, t config.TransportName)
}

// Option configures a Selector.
type Option func(*Selector)

// WithStagger sets the delay between launching successive transport attempts.
// A larger stagger favors preferred transports; a smaller one lowers worst-case
// connect latency on networks where the preferred transport is blocked.
func WithStagger(d time.Duration) Option {
	return func(s *Selector) { s.stagger = d }
}

// WithMemory attaches per-network transport memory.
func WithMemory(m Memory) Option { return func(s *Selector) { s.memory = m } }

// WithOrder overrides the transport priority order.
func WithOrder(order []config.TransportName) Option {
	return func(s *Selector) { s.order = append([]config.TransportName(nil), order...) }
}

// NewSelector builds a Selector from the given dialers. The default order is
// config.DefaultTransportOrder filtered to dialers that were actually provided.
func NewSelector(dialers []Dialer, opts ...Option) *Selector {
	s := &Selector{
		dialers: make(map[config.TransportName]Dialer, len(dialers)),
		stagger: 300 * time.Millisecond,
	}
	for _, d := range dialers {
		s.dialers[d.Name()] = d
	}
	for _, name := range config.DefaultTransportOrder {
		if _, ok := s.dialers[name]; ok {
			s.order = append(s.order, name)
		}
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Select races the transports for the given endpoints and returns the winning
// Conn plus the transport that won. networkID identifies the current network for
// memory purposes ("" disables memory for this call). The provided ctx bounds
// the whole selection; per-attempt timeouts should be baked into ctx by the
// caller (e.g. config.ClientConfig.HandshakeTimeout).
func (s *Selector) Select(ctx context.Context, endpoints Endpoints, networkID string) (Conn, config.TransportName, error) {
	order := s.orderedCandidates(endpoints, networkID)
	if len(order) == 0 {
		return nil, "", fmt.Errorf("%w: no dialers for the configured endpoints", ErrNoTransport)
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan Result, len(order))
	var wg sync.WaitGroup

	for i, name := range order {
		wg.Add(1)
		go func(i int, name config.TransportName) {
			defer wg.Done()
			// Stagger launches so preferred transports get a head start, but
			// don't block the whole race if a preferred transport hangs.
			select {
			case <-time.After(time.Duration(i) * s.stagger):
			case <-ctx.Done():
				results <- Result{Transport: name, Err: ctx.Err()}
				return
			}
			start := time.Now()
			conn, err := s.dialers[name].Dial(ctx, endpoints[name])
			results <- Result{Transport: name, Conn: conn, Err: err, Elapsed: time.Since(start)}
		}(i, name)
	}

	go func() { wg.Wait(); close(results) }()

	var firstErr error
	for res := range results {
		if res.Err == nil && res.Conn != nil {
			if s.memory != nil && networkID != "" {
				s.memory.Remember(networkID, res.Transport)
			}
			cancel() // stop the losers; their Conns (if any) get closed below
			// Drain remaining results, closing any late winners.
			go drainAndClose(results, res.Conn)
			return res.Conn, res.Transport, nil
		}
		if firstErr == nil && res.Err != nil {
			firstErr = res.Err
		}
	}
	if firstErr == nil {
		firstErr = ErrNoTransport
	}
	return nil, "", fmt.Errorf("%w: %v", ErrNoTransport, firstErr)
}

// orderedCandidates returns the transports to try, filtered to those we have both
// a dialer and an endpoint for, with the memory-preferred transport moved first.
func (s *Selector) orderedCandidates(endpoints Endpoints, networkID string) []config.TransportName {
	var order []config.TransportName
	for _, name := range s.order {
		if _, ok := endpoints[name]; ok {
			order = append(order, name)
		}
	}
	if s.memory != nil && networkID != "" {
		if pref, ok := s.memory.Preferred(networkID); ok {
			order = moveFront(order, pref)
		}
	}
	return order
}

func moveFront(order []config.TransportName, pref config.TransportName) []config.TransportName {
	for i, n := range order {
		if n == pref {
			out := append([]config.TransportName{pref}, order[:i]...)
			return append(out, order[i+1:]...)
		}
	}
	return order
}

// drainAndClose consumes any straggler successful connections (that lost the
// race) and closes them, ignoring the chosen winner.
func drainAndClose(results <-chan Result, winner Conn) {
	for res := range results {
		if res.Conn != nil && res.Conn != winner {
			_ = res.Conn.Close()
		}
	}
}
