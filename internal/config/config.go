// Package config defines and loads configuration for the veil client and server.
//
// Config is JSON on disk (no external deps for M0). Field names are stable and
// documented; unknown fields are rejected so typos surface early.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// TransportName identifies a wire transport the client may use to reach a server.
type TransportName string

const (
	TransportUDP TransportName = "udp" // fastest, default
	TransportTCP TransportName = "tcp" // fallback where UDP is blocked
	TransportTLS TransportName = "tls" // looks like HTTPS
	TransportWSS TransportName = "wss" // WebSocket-over-TLS on :443, full obfuscation
)

// DefaultTransportOrder is the priority the client races transports in when
// auto-selecting. Earlier = tried first / preferred.
var DefaultTransportOrder = []TransportName{
	TransportUDP, TransportTCP, TransportTLS, TransportWSS,
}

// ServerConfig configures the self-hosted gateway.
type ServerConfig struct {
	// Domain is the public hostname clients connect to (used for autocert + WSS Host).
	Domain string `json:"domain"`
	// ListenTLS is the address for TLS/WSS/control-plane (default ":443").
	ListenTLS string `json:"listen_tls"`
	// ListenUDP is the address for the UDP data-plane transport (default ":443").
	ListenUDP string `json:"listen_udp"`
	// TunnelCIDR is the virtual address pool assigned to devices (CGNAT range).
	TunnelCIDR string `json:"tunnel_cidr"`
	// DataDir holds the device store, keys, and autocert cache.
	DataDir string `json:"data_dir"`
	// EgressInterface is the NIC used to masquerade client traffic to the internet.
	EgressInterface string `json:"egress_interface"`
	// DNS is the upstream resolver offered to clients.
	DNS string `json:"dns"`
}

// ClientConfig configures a client/device.
type ClientConfig struct {
	// Server is the gateway hostname (e.g. "vpn.example.com").
	Server string `json:"server"`
	// ServerKeyFingerprint pins the server's static Noise key (TOFU at enrollment).
	ServerKeyFingerprint string `json:"server_key_fingerprint"`
	// ServerPublicKey is the server's static X25519 public key (base64 std),
	// required by the initiator for the Noise IK handshake. Learned at enrollment.
	ServerPublicKey string `json:"server_public_key"`
	// TransportOrder overrides DefaultTransportOrder if set.
	TransportOrder []TransportName `json:"transport_order,omitempty"`
	// HandshakeTimeout bounds each transport attempt during auto-selection.
	HandshakeTimeout Duration `json:"handshake_timeout"`
	// KillSwitch blocks all non-tunnel traffic while "connected" is engaged.
	KillSwitch bool `json:"kill_switch"`
	// DataDir holds the device key + cached per-network transport preference.
	DataDir string `json:"data_dir"`
}

// Duration is a JSON-friendly time.Duration ("30s", "1m", ...).
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(v)
	return nil
}

// DefaultServer returns a ServerConfig populated with sensible defaults.
func DefaultServer() ServerConfig {
	return ServerConfig{
		ListenTLS:  ":443",
		ListenUDP:  ":443",
		TunnelCIDR: "100.64.0.0/10",
		DataDir:    "/var/lib/veil",
		DNS:        "1.1.1.1",
	}
}

// DefaultClient returns a ClientConfig populated with sensible defaults.
func DefaultClient() ClientConfig {
	return ClientConfig{
		HandshakeTimeout: Duration(8 * time.Second),
		KillSwitch:       true,
		DataDir:          defaultClientDataDir(),
	}
}

// Validate checks required fields on the server config.
func (c ServerConfig) Validate() error {
	if c.Domain == "" {
		return fmt.Errorf("server.domain is required")
	}
	if c.TunnelCIDR == "" {
		return fmt.Errorf("server.tunnel_cidr is required")
	}
	return nil
}

// Validate checks required fields on the client config.
func (c ClientConfig) Validate() error {
	if c.Server == "" {
		return fmt.Errorf("client.server is required")
	}
	return nil
}

// LoadServer reads and validates a server config from path.
func LoadServer(path string) (ServerConfig, error) {
	c := DefaultServer()
	if err := loadJSON(path, &c); err != nil {
		return ServerConfig{}, err
	}
	return c, c.Validate()
}

// LoadClient reads and validates a client config from path.
func LoadClient(path string) (ClientConfig, error) {
	c := DefaultClient()
	if err := loadJSON(path, &c); err != nil {
		return ClientConfig{}, err
	}
	return c, c.Validate()
}

// Save writes v to path as indented JSON (0600, since configs hold secrets/pins).
func Save(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

func loadJSON(path string, v any) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open config %s: %w", path, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return fmt.Errorf("parse config %s: %w", path, err)
	}
	return nil
}
