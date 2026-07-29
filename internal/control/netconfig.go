// Package control defines the small control messages exchanged over an
// established link, plus helpers for inspecting tunneled packets.
package control

import (
	"encoding/json"
	"net/netip"
)

// NetConfig is sent by the server to the client immediately after the handshake
// to tell the client how to configure its tunnel interface.
type NetConfig struct {
	// AssignedIP is the client's virtual tunnel address, as a prefix so the
	// client knows the on-link tunnel network (e.g. "100.64.0.2/10").
	AssignedIP netip.Prefix `json:"assigned_ip"`
	// ServerIP is the server's virtual (gateway) address inside the tunnel.
	ServerIP netip.Addr `json:"server_ip"`
	// DNS is the resolver the client should use while connected.
	DNS netip.Addr `json:"dns"`
	// MTU for the tunnel interface.
	MTU int `json:"mtu"`
}

// Marshal encodes the config as JSON.
func (c NetConfig) Marshal() ([]byte, error) { return json.Marshal(c) }

// ParseNetConfig decodes a NetConfig from JSON.
func ParseNetConfig(b []byte) (NetConfig, error) {
	var c NetConfig
	err := json.Unmarshal(b, &c)
	return c, err
}

// DstIPv4 extracts the destination address from a raw IPv4 packet. It returns
// false for non-IPv4 or too-short packets (e.g. IPv6, which M1 does not route).
func DstIPv4(pkt []byte) (netip.Addr, bool) {
	if len(pkt) < 20 || pkt[0]>>4 != 4 {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]}), true
}
