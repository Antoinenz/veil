package client

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/veilvpn/veil/internal/control"
	"github.com/veilvpn/veil/internal/netcfg"
	"github.com/veilvpn/veil/internal/tun"
)

// State is the connection state of the tunnel engine.
type State string

const (
	StateDisconnected  State = "disconnected"
	StateConnecting    State = "connecting"
	StateConnected     State = "connected"
	StateDisconnecting State = "disconnecting"
)

// Status is a snapshot of the engine, safe to copy and serialize.
type Status struct {
	State      State  `json:"state"`
	Transport  string `json:"transport,omitempty"`
	AssignedIP string `json:"assigned_ip,omitempty"`
	Server     string `json:"server,omitempty"`
	FullTunnel bool   `json:"full_tunnel,omitempty"`
	Since      string `json:"since,omitempty"` // RFC3339, when the current state began
	Err        string `json:"error,omitempty"`
}

// Engine owns at most one active tunnel and drives its lifecycle. It is safe for
// concurrent use: the daemon's IPC handlers and the internal session goroutine
// all go through it.
type Engine struct {
	mu     sync.Mutex
	status Status
	cancel context.CancelFunc // cancels the active session (disconnect request)
	done   chan struct{}      // closed when the active session has fully torn down

	subMu sync.Mutex
	subs  map[chan Status]struct{}
}

// NewEngine returns an idle engine.
func NewEngine() *Engine {
	return &Engine{
		status: Status{State: StateDisconnected, Since: now()},
		subs:   make(map[chan Status]struct{}),
	}
}

// Status returns the current status snapshot.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.status
}

// Subscribe returns a channel that receives a copy of the status on every
// change, plus a function to unsubscribe. The channel is buffered and lossy
// (slow consumers drop intermediate updates but always converge).
func (e *Engine) Subscribe() (<-chan Status, func()) {
	ch := make(chan Status, 8)
	e.subMu.Lock()
	e.subs[ch] = struct{}{}
	e.subMu.Unlock()
	// Prime with the current status.
	ch <- e.Status()
	return ch, func() {
		e.subMu.Lock()
		if _, ok := e.subs[ch]; ok {
			delete(e.subs, ch)
			close(ch)
		}
		e.subMu.Unlock()
	}
}

func (e *Engine) setStatus(mut func(s *Status)) {
	e.mu.Lock()
	mut(&e.status)
	e.status.Since = now()
	snap := e.status
	e.mu.Unlock()

	e.subMu.Lock()
	for ch := range e.subs {
		select {
		case ch <- snap:
		default: // drop if the subscriber is behind
		}
	}
	e.subMu.Unlock()
}

// Connect starts a tunnel using opt. It returns immediately; progress is
// reflected in Status()/Subscribe(). It errors only if a session is already
// active.
func (e *Engine) Connect(opt Options) error {
	e.mu.Lock()
	if e.status.State != StateDisconnected {
		st := e.status.State
		e.mu.Unlock()
		return fmt.Errorf("cannot connect while %s", st)
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan struct{})
	e.mu.Unlock()

	e.setStatus(func(s *Status) {
		*s = Status{State: StateConnecting, Server: opt.ServerHost, FullTunnel: opt.FullTunnel}
	})
	go e.session(ctx, opt)
	return nil
}

// Disconnect tears down the active tunnel (if any) and waits for teardown.
func (e *Engine) Disconnect() error {
	e.mu.Lock()
	cancel, done := e.cancel, e.done
	state := e.status.State
	e.mu.Unlock()
	if state == StateDisconnected || cancel == nil {
		return nil
	}
	cancel()
	if done != nil {
		<-done
	}
	return nil
}

// session runs one connection attempt and, on success, the tunnel until ctx is
// cancelled (disconnect) or a pump fails. Teardown is ordered so the TUN device
// is only closed after the pumps have stopped reading it.
func (e *Engine) session(ctx context.Context, opt Options) {
	defer func() {
		e.mu.Lock()
		close(e.done)
		e.cancel = nil
		e.done = nil
		e.mu.Unlock()
	}()

	if opt.HandshakeTimeout <= 0 {
		opt.HandshakeTimeout = 8 * time.Second
	}
	connCtx, cancelConn := context.WithTimeout(ctx, opt.HandshakeTimeout)
	l, chosen, err := connect(connCtx, opt)
	cancelConn()
	if err != nil {
		e.fail(fmt.Errorf("could not establish tunnel: %w", err))
		return
	}

	raw, err := l.RecvConfig()
	if err != nil {
		_ = l.Close()
		e.fail(fmt.Errorf("receive net config: %w", err))
		return
	}
	nc, err := control.ParseNetConfig(raw)
	if err != nil {
		_ = l.Close()
		e.fail(fmt.Errorf("parse net config: %w", err))
		return
	}

	dev, err := tun.Open(tun.DefaultName)
	if err != nil {
		_ = l.Close()
		e.fail(err)
		return
	}
	if err := netcfg.New().SetupInterface(dev.Name(), nc.AssignedIP, nc.MTU); err != nil {
		_ = dev.Close()
		_ = l.Close()
		e.fail(fmt.Errorf("configure %s: %w", dev.Name(), err))
		return
	}
	log.Printf("veil: connected via %s — %s is %s, gateway %s", chosen, dev.Name(), nc.AssignedIP, nc.ServerIP)

	var routing *netcfg.TunnelRouting
	if opt.FullTunnel {
		serverIP, err := resolveHost(opt.ServerHost)
		if err == nil {
			routing, err = netcfg.FullTunnelUp(dev.Name(), nc.ServerIP, serverIP, nc.DNS, opt.KillSwitch)
		}
		if err != nil {
			_ = dev.Close()
			_ = l.Close()
			e.fail(fmt.Errorf("full-tunnel setup: %w", err))
			return
		}
		log.Printf("veil: full-tunnel ON — all traffic via %s (dns %s, kill-switch %v)", dev.Name(), nc.DNS, opt.KillSwitch)
	}

	e.setStatus(func(s *Status) {
		*s = Status{
			State:      StateConnected,
			Transport:  string(chosen),
			AssignedIP: nc.AssignedIP.String(),
			Server:     opt.ServerHost,
			FullTunnel: opt.FullTunnel,
		}
	})

	// Run the pumps until disconnect or failure.
	var wg sync.WaitGroup
	errc := make(chan error, 2)
	wg.Add(2)
	go func() { defer wg.Done(); errc <- pumpTunToLink(dev, l) }()
	go func() { defer wg.Done(); errc <- pumpLinkToTun(l, dev) }()

	var pumpErr error
	select {
	case <-ctx.Done():
	case pumpErr = <-errc:
	}

	// Ordered teardown: close the link (unblocks link->tun), then the device
	// (unblocks tun->link), then wait for both pumps before reverting routing.
	e.setStatus(func(s *Status) { s.State = StateDisconnecting })
	_ = l.Close()
	_ = dev.Close()
	wg.Wait()
	if routing != nil {
		_ = routing.Down()
	}

	e.setStatus(func(s *Status) {
		*s = Status{State: StateDisconnected}
		if pumpErr != nil && ctx.Err() == nil {
			s.Err = pumpErr.Error()
		}
	})
}

// fail records a connection failure and returns to the disconnected state.
func (e *Engine) fail(err error) {
	log.Printf("veil: %v", err)
	e.setStatus(func(s *Status) { *s = Status{State: StateDisconnected, Err: err.Error()} })
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// Run connects using opt and blocks until ctx is cancelled or the tunnel ends,
// returning any terminal error. It preserves the original foreground `veil up`
// behavior on top of the engine.
func Run(ctx context.Context, opt Options) error {
	e := NewEngine()
	sub, unsub := e.Subscribe()
	defer unsub()
	<-sub // discard the primed initial (disconnected) status
	if err := e.Connect(opt); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return e.Disconnect()
		case st, ok := <-sub:
			if !ok {
				return nil
			}
			if st.State == StateDisconnected {
				if st.Err != "" {
					return errors.New(st.Err)
				}
				return nil
			}
		}
	}
}
