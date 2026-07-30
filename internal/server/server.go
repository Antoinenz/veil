// Package server implements the veil gateway data plane: it terminates client
// links, assigns each device a virtual IP, routes packets between the TUN device
// and the correct client link, and (optionally) NATs client traffic to the
// internet.
package server

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"net/netip"
	"sync"

	"github.com/veilvpn/veil/internal/certutil"
	"github.com/veilvpn/veil/internal/config"
	"github.com/veilvpn/veil/internal/control"
	"github.com/veilvpn/veil/internal/ippool"
	"github.com/veilvpn/veil/internal/link"
	"github.com/veilvpn/veil/internal/netcfg"
	"github.com/veilvpn/veil/internal/noise"
	"github.com/veilvpn/veil/internal/store"
	"github.com/veilvpn/veil/internal/transport"
	"github.com/veilvpn/veil/internal/tun"
)

// DefaultMTU leaves headroom under a 1500-byte path for framing + AEAD overhead.
const DefaultMTU = 1380

// Server is a running gateway.
type Server struct {
	cfg   config.ServerConfig
	kp    *noise.KeyPair
	store *store.Store
	pool  *ippool.Pool
	dev   tun.Device
	nc    netcfg.Configurator
	ifOK  bool // whether NAT was installed (for cleanup)
	iface string

	fingerprint string

	mu     sync.RWMutex
	routes map[netip.Addr]*link.Link
}

// New builds a Server from config, the server's static keypair, and the device
// store (which holds enrollment invites and enrolled device keys).
func New(cfg config.ServerConfig, kp *noise.KeyPair, st *store.Store) (*Server, error) {
	pool, err := ippool.New(cfg.TunnelCIDR)
	if err != nil {
		return nil, err
	}
	return &Server{
		cfg:         cfg,
		kp:          kp,
		store:       st,
		pool:        pool,
		nc:          netcfg.New(),
		fingerprint: noise.Fingerprint(kp.Public),
		routes:      make(map[netip.Addr]*link.Link),
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

	// UDP transport (fastest) and the WSS/HTTPS transport (obfuscation + decoy
	// site) share the effort of accepting tunnels. Both feed the same handler.
	udpLis, err := transport.ListenUDP(s.cfg.ListenUDP)
	if err != nil {
		return err
	}
	cert, err := certutil.SelfSigned(s.cfg.Domain)
	if err != nil {
		return err
	}
	// Control plane + decoy share the HTTPS listener: /enroll handles device
	// enrollment, everything else (except the tunnel's own /veil) is the decoy.
	controlMux := http.NewServeMux()
	controlMux.HandleFunc(control.EnrollPath, s.handleEnroll)
	controlMux.Handle("/", transport.DecoyHandler())
	wssLis, err := transport.ListenWSS(s.cfg.ListenTLS, cert, controlMux)
	if err != nil {
		udpLis.Close()
		return err
	}
	listeners := []transport.Listener{udpLis, wssLis}

	log.Printf("veil-server: %s up as %s; udp %s + wss %s%s (egress %q)",
		s.iface, gwPrefix, udpLis.Addr(), wssLis.Addr(), transport.TunnelPath, s.cfg.EgressInterface)

	go s.tunToClients()

	go func() {
		<-ctx.Done()
		for _, l := range listeners {
			l.Close()
		}
		s.dev.Close()
		if s.ifOK {
			_ = s.nc.RemoveMasquerade(s.pool.Prefix(), s.cfg.EgressInterface)
		}
	}()

	var wg sync.WaitGroup
	for _, l := range listeners {
		wg.Add(1)
		go func(l transport.Listener) {
			defer wg.Done()
			s.acceptLoop(ctx, l)
		}(l)
	}
	wg.Wait()
	return nil
}

// acceptLoop accepts connections from one listener until it closes or ctx ends.
func (s *Server) acceptLoop(ctx context.Context, lis transport.Listener) {
	for {
		conn, err := lis.Accept()
		if err != nil {
			return // listener closed (shutdown) or fatal accept error
		}
		select {
		case <-ctx.Done():
			_ = conn.Close()
			return
		default:
			go s.handleConn(conn)
		}
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

	// Only enrolled devices may establish a tunnel.
	if enrolled, err := s.store.HasDevice(key); err != nil || !enrolled {
		log.Printf("veil-server: rejecting unenrolled device %s…", short(key))
		_ = l.Close()
		return
	}

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

// handleEnroll validates an invite and enrolls the presented device key,
// returning the server's static public key so the client can connect.
func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req control.EnrollRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Invite == "" || req.DevicePublicKey == "" {
		http.Error(w, "invite and device_public_key required", http.StatusBadRequest)
		return
	}
	// Validate the device key is a real 32-byte X25519 key before storing it.
	raw, err := base64.StdEncoding.DecodeString(req.DevicePublicKey)
	if err != nil || len(raw) != 32 {
		http.Error(w, "invalid device_public_key", http.StatusBadRequest)
		return
	}

	ok, err := s.store.ConsumeInvite(req.Invite)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Error(w, "invalid or used invite", http.StatusForbidden)
		return
	}
	if err := s.store.AddDevice(req.DevicePublicKey, req.Name); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	log.Printf("veil-server: enrolled device %s… (%q)", short(req.DevicePublicKey), req.Name)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(control.EnrollResponse{
		ServerPublicKey: base64.StdEncoding.EncodeToString(s.kp.Public.Bytes()),
		Fingerprint:     s.fingerprint,
	})
}

func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

func parseAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}
