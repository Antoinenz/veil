# veil threat model (draft)

## Goals

1. **Confidentiality & integrity** of tunneled traffic against a network attacker
   who can observe and modify packets between client and server.
2. **Mutual authentication**: the client reaches *its* server (not a MITM), and the
   server only admits enrolled devices.
3. **Availability on hostile networks**: connect even where UDP VPNs are blocked and
   DPI tries to fingerprint/kill tunnels.
4. **Unlinkability / blend-in**: in obfuscated mode, traffic is hard to distinguish
   from ordinary HTTPS, and probing the server reveals only a normal website.

## In-scope adversaries

- **Passive network observer** — ISP, coffee-shop Wi-Fi. Mitigation: Noise `IK`
  AEAD; no plaintext metadata beyond what the chosen transport inherently exposes.
- **Active on-path attacker** — Mitigation: mutual auth + pinned server fingerprint
  (TOFU); replay protection via per-session counters.
- **Censor / DPI** — blocks UDP, fingerprints handshakes, actively probes servers.
  Mitigation: transport auto-fallback to TLS/WSS on :443, decoy site + auth-gated
  upgrade, optional length/timing padding.

## Out of scope (v1)

- Global passive adversary doing traffic-correlation across the whole internet.
- Endpoint compromise (malware on the client or server host).
- Anonymity from the **server operator** — a gateway VPN sees client egress by
  design; run your own server (that's the point).

## Known limitations (must fix before a security claim)

- **The custom protocol is unaudited.** Built on Noise to avoid hand-rolled crypto,
  but the framing/negotiation/obfuscation layers need independent review.
- Padding/obfuscation tuning against statistical DPI is still TODO (M5).
- Post-quantum hardening (beyond the optional PSK) is not yet addressed.
