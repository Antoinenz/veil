// Package client implements the veil client data plane: it auto-selects the best
// working transport to the server, completes the handshake, applies the
// server-provided network configuration to a local TUN device, and pumps packets
// in both directions.
package client

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/veilvpn/veil/internal/config"
	"github.com/veilvpn/veil/internal/control"
	"github.com/veilvpn/veil/internal/link"
	"github.com/veilvpn/veil/internal/netcfg"
	"github.com/veilvpn/veil/internal/noise"
	"github.com/veilvpn/veil/internal/transport"
	"github.com/veilvpn/veil/internal/tun"
)

// staggerDelay is the head start given to higher-priority transports during
// auto-selection (Happy-Eyeballs style).
const staggerDelay = 350 * time.Millisecond

// Options controls a client connection.
type Options struct {
	// ServerHost is the server hostname or IP (no port).
	ServerHost string
	// ServerName is the TLS SNI to present (defaults to ServerHost).
	ServerName string
	// UDPPort / TLSPort are the server ports for the UDP and TLS-based transports.
	UDPPort string
	TLSPort string
	// Order is the transport priority order (defaults to config.DefaultTransportOrder).
	Order []config.TransportName
	// TunnelToken authenticates the WSS upgrade (empty = WSS unavailable).
	TunnelToken string
	// HandshakeTimeout bounds the whole auto-selection attempt.
	HandshakeTimeout time.Duration

	// FullTunnel routes all traffic through the server (default route + DNS).
	FullTunnel bool
	// KillSwitch (with FullTunnel) blocks non-tunnel egress if the tunnel drops.
	KillSwitch bool

	// Device is this client's static keypair.
	Device *noise.KeyPair
	// ServerStatic is the server's pinned static public key (32 bytes).
	ServerStatic []byte
	// PSK is an optional 32-byte pre-shared key.
	PSK []byte
}

// FromConfig builds Options from a loaded client config + device key.
func FromConfig(cfg config.ClientConfig, device *noise.KeyPair, serverStatic []byte) Options {
	order := cfg.TransportOrder
	if len(order) == 0 {
		// The default gateway serves UDP + WSS. Raw TCP/TLS transports exist and
		// can be selected via an explicit transport_order once a deployment
		// serves them (unified-on-443 ALPN muxing is a later milestone).
		order = []config.TransportName{config.TransportUDP, config.TransportWSS}
	}
	return Options{
		ServerHost:       cfg.Server,
		ServerName:       cfg.Server,
		UDPPort:          orDefault(cfg.UDPPort, "443"),
		TLSPort:          orDefault(cfg.TLSPort, "443"),
		Order:            order,
		TunnelToken:      cfg.TunnelToken,
		HandshakeTimeout: time.Duration(cfg.HandshakeTimeout),
		FullTunnel:       cfg.FullTunnel,
		KillSwitch:       cfg.KillSwitch,
		Device:           device,
		ServerStatic:     serverStatic,
	}
}

// Run connects and blocks until ctx is cancelled or the tunnel fails.
func Run(ctx context.Context, opt Options) error {
	if opt.HandshakeTimeout <= 0 {
		opt.HandshakeTimeout = 8 * time.Second
	}
	connCtx, cancel := context.WithTimeout(ctx, opt.HandshakeTimeout)
	defer cancel()

	l, chosen, err := connect(connCtx, opt)
	if err != nil {
		return fmt.Errorf("could not establish tunnel: %w", err)
	}
	defer l.Close()
	log.Printf("veil: connected via %s", chosen)

	raw, err := l.RecvConfig()
	if err != nil {
		return fmt.Errorf("receive net config: %w", err)
	}
	nc, err := control.ParseNetConfig(raw)
	if err != nil {
		return fmt.Errorf("parse net config: %w", err)
	}

	dev, err := tun.Open("veil0")
	if err != nil {
		return err
	}
	defer dev.Close()

	cfgr := netcfg.New()
	if err := cfgr.SetupInterface(dev.Name(), nc.AssignedIP, nc.MTU); err != nil {
		return fmt.Errorf("configure %s: %w", dev.Name(), err)
	}
	log.Printf("veil: %s is %s, gateway %s (transport %s)", dev.Name(), nc.AssignedIP, nc.ServerIP, chosen)

	if opt.FullTunnel {
		serverIP, err := resolveHost(opt.ServerHost)
		if err != nil {
			return fmt.Errorf("full-tunnel: resolve server %q: %w", opt.ServerHost, err)
		}
		tr, err := netcfg.FullTunnelUp(dev.Name(), nc.ServerIP, serverIP, nc.DNS, opt.KillSwitch)
		if err != nil {
			return fmt.Errorf("full-tunnel setup: %w", err)
		}
		defer tr.Down()
		log.Printf("veil: full-tunnel ON — all traffic via %s (dns %s, kill-switch %v)",
			dev.Name(), nc.DNS, opt.KillSwitch)
	}

	errc := make(chan error, 2)
	go func() { errc <- pumpTunToLink(dev, l) }()
	go func() { errc <- pumpLinkToTun(l, dev) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-errc:
		return err
	}
}

// candidate pairs a dialer with the endpoint used to reach the server.
type candidate struct {
	name     config.TransportName
	dialer   transport.Dialer
	endpoint string
}

// dialOutcome is the result of one transport attempt during auto-selection.
type dialOutcome struct {
	l    *link.Link
	name config.TransportName
	err  error
}

// connect races the configured transports and returns the first Link that
// completes a full handshake, giving preferred transports a staggered head start.
func connect(ctx context.Context, opt Options) (*link.Link, config.TransportName, error) {
	cands := candidates(opt)
	if len(cands) == 0 {
		return nil, "", fmt.Errorf("no usable transports configured")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan dialOutcome, len(cands))
	var wg sync.WaitGroup

	for i, c := range cands {
		wg.Add(1)
		go func(i int, c candidate) {
			defer wg.Done()
			select {
			case <-time.After(time.Duration(i) * staggerDelay):
			case <-ctx.Done():
				results <- dialOutcome{name: c.name, err: ctx.Err()}
				return
			}
			l, err := link.Dial(ctx, c.dialer, c.endpoint, opt.Device, opt.ServerStatic, opt.PSK)
			results <- dialOutcome{l: l, name: c.name, err: err}
		}(i, c)
	}
	go func() { wg.Wait(); close(results) }()

	var firstErr error
	for r := range results {
		if r.err == nil && r.l != nil {
			cancel()
			go drainClose(results, r.l)
			return r.l, r.name, nil
		}
		if firstErr == nil && r.err != nil {
			firstErr = r.err
		}
	}
	if firstErr == nil {
		firstErr = fmt.Errorf("all transports failed")
	}
	return nil, "", firstErr
}

// candidates builds the ordered dialer/endpoint list from options. Raw TCP is
// only included if a port is set (the default gateway serves UDP + WSS/TLS).
func candidates(opt Options) []candidate {
	sni := opt.ServerName
	if sni == "" {
		sni = opt.ServerHost
	}
	build := map[config.TransportName]candidate{
		config.TransportUDP: {config.TransportUDP, transport.UDPDialer{}, net.JoinHostPort(opt.ServerHost, opt.UDPPort)},
		config.TransportTLS: {config.TransportTLS, transport.TLSDialer{ServerName: sni}, net.JoinHostPort(opt.ServerHost, opt.TLSPort)},
		config.TransportWSS: {config.TransportWSS, transport.WSSDialer{ServerName: sni, AuthToken: opt.TunnelToken}, "wss://" + net.JoinHostPort(opt.ServerHost, opt.TLSPort) + transport.TunnelPath},
	}
	var out []candidate
	for _, name := range opt.Order {
		if c, ok := build[name]; ok {
			out = append(out, c)
		}
	}
	return out
}

func drainClose(results <-chan dialOutcome, winner *link.Link) {
	for r := range results {
		if r.l != nil && r.l != winner {
			_ = r.l.Close()
		}
	}
}

// resolveHost turns a host (IP or name) into an address, preferring IPv4.
func resolveHost(host string) (netip.Addr, error) {
	if a, err := netip.ParseAddr(host); err == nil {
		return a, nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			a, _ := netip.AddrFromSlice(v4)
			return a, nil
		}
	}
	if len(ips) > 0 {
		a, _ := netip.AddrFromSlice(ips[0])
		return a.Unmap(), nil
	}
	return netip.Addr{}, fmt.Errorf("no address for %s", host)
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

func pumpTunToLink(dev tun.Device, l *link.Link) error {
	buf := make([]byte, 65535)
	for {
		n, err := dev.Read(buf)
		if err != nil {
			return err
		}
		if err := l.WritePacket(buf[:n]); err != nil {
			return err
		}
	}
}

func pumpLinkToTun(l *link.Link, dev tun.Device) error {
	for {
		pkt, err := l.ReadPacket()
		if err != nil {
			return err
		}
		if _, err := dev.Write(pkt); err != nil {
			return err
		}
	}
}
