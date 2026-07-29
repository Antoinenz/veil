// Package client implements the veil client data plane: it dials the server,
// completes the handshake, applies the server-provided network configuration to
// a local TUN device, and pumps packets in both directions.
package client

import (
	"context"
	"fmt"
	"log"

	"github.com/veilvpn/veil/internal/config"
	"github.com/veilvpn/veil/internal/control"
	"github.com/veilvpn/veil/internal/link"
	"github.com/veilvpn/veil/internal/netcfg"
	"github.com/veilvpn/veil/internal/noise"
	"github.com/veilvpn/veil/internal/transport"
	"github.com/veilvpn/veil/internal/tun"
)

// Options controls a client connection.
type Options struct {
	// Endpoint is the server's transport address ("host:port"). M1 uses UDP; the
	// multi-transport selector arrives in M2.
	Endpoint string
	// Device is this client's static keypair.
	Device *noise.KeyPair
	// ServerStatic is the server's pinned static public key (32 bytes).
	ServerStatic []byte
	// PSK is an optional 32-byte pre-shared key (nil to disable).
	PSK []byte
}

// FromConfig builds Options from a loaded client config + device key.
func FromConfig(cfg config.ClientConfig, device *noise.KeyPair, serverStatic []byte) Options {
	return Options{
		Endpoint:     cfg.Server,
		Device:       device,
		ServerStatic: serverStatic,
	}
}

// Run connects and blocks until ctx is cancelled or the tunnel fails.
func Run(ctx context.Context, opt Options) error {
	dialer := transport.UDPDialer{}
	conn, err := dialer.Dial(ctx, opt.Endpoint)
	if err != nil {
		return err
	}

	l, err := link.Client(conn, opt.Device, opt.ServerStatic, opt.PSK)
	if err != nil {
		return fmt.Errorf("handshake: %w", err)
	}
	defer l.Close()

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
	log.Printf("veil: connected — %s is %s, gateway %s", dev.Name(), nc.AssignedIP, nc.ServerIP)

	// Two pumps; the first error tears the tunnel down.
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
