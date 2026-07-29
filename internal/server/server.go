// Package server implements the veil gateway data plane: it terminates client
// links, assigns each device a virtual IP, routes packets between the TUN device
// and the correct client link, and (optionally) NATs client traffic to the
// internet.
package server

import (
	"context"
	"encoding/base64"
	"log"
	"net/netip"
	"sync"

	"github.com/veilvpn/veil/internal/config"
	"github.com/veilvpn/veil/internal/control"
	"github.com/veilvpn/veil/internal/ippool"
	"github.com/veilvpn/veil/internal/link"
	"github.com/veilvpn/veil/internal/netcfg"
	"github.com/veilvpn/veil/internal/noise"
	"github.com/veilvpn/veil/internal/transport"
	"github.com/veilvpn/veil/internal/tun"
)

// DefaultMTU leaves headroom under a 1500-byte path for framing + AEAD overhead.
const DefaultMTU = 1380

// Server is a running gateway.
type Server struct {
	cfg   config.ServerConfig
	kp    *noise.KeyPair
	pool  *ippool.Pool
	dev   tun.Device
	nc    netcfg.Configurator
	ifOK  bool // whether NAT was installed (for cleanup)
	iface string

	mu     sync.RWMutex
	routes map[netip.Addr]*link.Link
}

// New builds a Server from config and the server's static keypair.
func New(cfg config.ServerConfig, kp *noise.KeyPair) (*Server, error) {
	pool, err := ippool.New(cfg.TunnelCIDR)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:    cfg,
		kp:     kp,
		pool:   pool,
		nc:     netcfg.New(),
		routes: make(map[netip.Addr]*link.Link),
	}, nil
}

// Run sets up host networking and serves clients until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	dev, err := tun.Open("veil0")
	if err != nil {
		return err
	}
	s.dev = dev
	s.iface = dev.Name()

	gwPrefix := netip.PrefixFrom(s.pool.Gateway(), s.pool.Prefix().Bits())
	if err := s.nc.SetupInterface(s.iface, gwPrefix, DefaultMTU); err != nil {
		return err
	}
	if err := s.nc.EnableForwarding(); err != nil {
		return err
	}
	if s.cfg.EgressInterface != "" {
		if err := s.nc.AddMasquerade(s.pool.Prefix(), s.cfg.EgressInterface); err != nil {
			return err
		}
		s.ifOK = true
	}

	lis, err := transport.ListenUDP(s.cfg.ListenUDP)
	if err != nil {
		return err
	}
	log.Printf("veil-server: %s up as %s, listening udp %s (egress %q)",
		s.iface, gwPrefix, lis.Addr(), s.cfg.EgressInterface)

	go s.tunToClients()

	go func() {
		<-ctx.Done()
		lis.Close()
		s.dev.Close()
		if s.ifOK {
			_ = s.nc.RemoveMasquerade(s.pool.Prefix(), s.cfg.EgressInterface)
		}
	}()

	for {
		conn, err := lis.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.handleConn(conn)
	}
}

// handleConn performs the responder handshake, assigns an address, pushes the
// NetConfig, and pumps client->TUN packets.
func (s *Server) handleConn(conn transport.Conn) {
	l, err := link.Server(conn, s.kp, nil)
	if err != nil {
		log.Printf("veil-server: handshake failed: %v", err)
		_ = conn.Close()
		return
	}

	key := base64.StdEncoding.EncodeToString(l.Peer())
	ip, err := s.pool.AllocateFor(key)
	if err != nil {
		log.Printf("veil-server: address allocation failed: %v", err)
		_ = l.Close()
		return
	}

	s.mu.Lock()
	s.routes[ip] = l
	s.mu.Unlock()
	log.Printf("veil-server: client %s… assigned %s", key[:8], ip)

	nc := control.NetConfig{
		AssignedIP: netip.PrefixFrom(ip, s.pool.Prefix().Bits()),
		ServerIP:   s.pool.Gateway(),
		DNS:        parseAddr(s.cfg.DNS),
		MTU:        DefaultMTU,
	}
	msg, err := nc.Marshal()
	if err == nil {
		err = l.SendConfig(msg)
	}
	if err != nil {
		log.Printf("veil-server: send config to %s failed: %v", ip, err)
		s.drop(ip)
		return
	}

	defer s.drop(ip)
	for {
		pkt, err := l.ReadPacket()
		if err != nil {
			log.Printf("veil-server: client %s disconnected: %v", ip, err)
			return
		}
		if _, err := s.dev.Write(pkt); err != nil {
			log.Printf("veil-server: tun write for %s failed: %v", ip, err)
			return
		}
	}
}

// tunToClients reads packets arriving on the TUN device and routes each to the
// client link that owns the destination address.
func (s *Server) tunToClients() {
	buf := make([]byte, 65535)
	for {
		n, err := s.dev.Read(buf)
		if err != nil {
			return
		}
		dst, ok := control.DstIPv4(buf[:n])
		if !ok {
			continue // non-IPv4 (e.g. IPv6) not routed in M1
		}
		s.mu.RLock()
		l := s.routes[dst]
		s.mu.RUnlock()
		if l == nil {
			continue // no client for this address; drop
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		if err := l.WritePacket(pkt); err != nil {
			log.Printf("veil-server: write to %s failed: %v", dst, err)
		}
	}
}

func (s *Server) drop(ip netip.Addr) {
	s.mu.Lock()
	l := s.routes[ip]
	delete(s.routes, ip)
	s.mu.Unlock()
	if l != nil {
		_ = l.Close()
	}
	s.pool.Release(ip)
}

func parseAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}
