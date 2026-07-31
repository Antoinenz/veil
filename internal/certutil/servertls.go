package certutil

import (
	"crypto/tls"
	"fmt"
	"net"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// SelfSignedConfig returns a *tls.Config serving a freshly generated self-signed
// certificate for host (an HTTPS listener suitable for dev / IP-only hosts).
func SelfSignedConfig(host string) (*tls.Config, error) {
	cert, err := SelfSigned(host)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

// ServerTLSConfig builds the gateway's HTTPS TLS config.
//
// If acme is true and host is a DNS name (not an IP), it provisions and renews a
// Let's Encrypt certificate automatically via autocert (TLS-ALPN-01 on :443,
// cached under cacheDir). Otherwise it falls back to a self-signed certificate,
// which is fine for dev and IP-only hosts because the tunnel's real trust comes
// from the pinned Noise key — TLS here is transport camouflage.
func ServerTLSConfig(host, cacheDir, email string, acmeEnabled bool) (*tls.Config, error) {
	if acmeEnabled && host != "" && net.ParseIP(host) == nil {
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(host),
			Cache:      autocert.DirCache(cacheDir),
			Email:      email,
		}
		cfg := m.TLSConfig()
		// WebSocket needs HTTP/1.1; keep acme-tls/1 so ALPN challenges still work.
		cfg.NextProtos = []string{"http/1.1", acme.ALPNProto}
		cfg.MinVersion = tls.VersionTLS12
		return cfg, nil
	}
	if acmeEnabled {
		return nil, fmt.Errorf("certutil: ACME requires a DNS domain, but %q is an IP", host)
	}
	return SelfSignedConfig(host)
}
