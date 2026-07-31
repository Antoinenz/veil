# veil

> **Status: early scaffolding (M0).** Not yet usable, not yet secure. Do not use for
> anything real. See [ROADMAP](#roadmap).

An open-source (MIT), **self-hostable VPN** designed to feel like Cloudflare WARP and
Tailscale:

- **One button.** Click *Connect* — the client auto-configures and finds the best working
  transport on its own.
- **Works on hostile networks.** When plain UDP VPNs are blocked/throttled, veil
  automatically falls back through TCP → TLS → **WebSocket-over-TLS (WSS) on :443**, which
  blends in with ordinary HTTPS web traffic.
- **No client-side port forwarding.** Clients only ever dial *out* to the server.
- **Easy to self-host.** A single server binary (or `docker compose up`) on a VPS with a
  domain. Enrollment is one invite code.

## Architecture (short version)

```
client  ──►  [ obfuscated transport ]  ──►  self-hosted gateway server  ──►  internet
```

- **Crypto core:** the tunnel handshake is built on the **Noise Protocol Framework** (the
  same audited foundation WireGuard uses). We do **not** hand-roll ciphers.
- **Custom protocol** for framing, transport negotiation, multiplexing, and obfuscation.
- **Pluggable transports** (`udp`, `tcp`, `tls`, `wss`) selected automatically at connect
  time by a "Happy-Eyeballs"-style racer, with health-checked failover and per-network memory.

Full design lives in [`docs/`](docs/).

> ⚠️ **Security:** the cryptographic protocol is custom (built on Noise). It has **not** been
> audited. An independent review is required before any security-critical use.

## Repo layout

| Path | What |
|------|------|
| `cmd/veil` | client CLI + daemon |
| `cmd/veil-server` | gateway + control plane |
| `internal/transport` | transport interface + selector (udp/tcp/tls/wss) |
| `internal/tunnel` | frame codec + TUN abstraction |
| `internal/noise` | handshake / session crypto (Noise) |
| `internal/link` | ties crypto + framing + transport into a tunnel |
| `internal/server` / `internal/client` | gateway + client data planes |
| `internal/store` | embedded device/invite store (bbolt) |
| `internal/control` | enrollment + net-config messages |
| `internal/ippool` / `internal/tun` / `internal/netcfg` | IP pool, TUN device, host net config |
| `internal/config` | config loading |
| `deploy` | Dockerfile, docker-compose, systemd units |
| `docs` | protocol spec, threat model, self-hosting guide |

## Build

Requires **Go ≥ 1.23**.

```sh
make build          # builds ./bin/veil and ./bin/veil-server
make test
make vet
sudo make install   # optional: copy binaries to /usr/local/bin
```

## Quick start (self-host)

```sh
# on the server (a VPS or home box):
sudo ./bin/veil-server init --domain <host-or-ip> --data-dir /etc/veil   # prints an invite
sudo ./bin/veil-server run  --config /etc/veil/server.json

# on a client (Linux; Windows/Wintun is M4):
sudo ./bin/veil login --data-dir /etc/veil <host-or-ip> <invite>         # enrolls + pins server key
sudo ./bin/veil up    --data-dir /etc/veil
```

Or install with systemd: `sudo bash deploy/install.sh`, then
`sudo systemctl enable --now veil-server`.

**Production TLS:** with a real domain pointed at the server and `:443` publicly
reachable, set `"acme": true` (and optionally `"acme_email"`) in `server.json`
for automatic Let's Encrypt certificates. On an IP/dev host it uses a self-signed
cert — fine, since the tunnel's trust is the pinned Noise key (TLS is camouflage).

See [`docs/testing.md`](docs/testing.md) for a full two-machine walkthrough and the
automated network-namespace test.

## Roadmap

- [x] **M0** — scaffold, MIT license, config, core interfaces, CI
- [x] **M1** — end-to-end encrypted tunnel, verified live on real hardware
  - [x] real Noise `IK` handshake + session AEAD (`internal/noise`, on `flynn/noise`)
  - [x] UDP transport: dialer + per-remote demuxing listener (`internal/transport`)
  - [x] link layer: framed handshake + encrypted packet pump (`internal/link`)
  - [x] virtual-IP pool allocator (`internal/ippool`)
  - [x] Linux TUN device via `/dev/net/tun` (`internal/tun`)
  - [x] NAT/forwarding/interface config helper (`internal/netcfg`)
  - [x] daemon assembly: `veil-server run` gateway + `veil up` client
        (`internal/server`, `internal/client`) — TUN ⇄ link ⇄ pool ⇄ NAT
  - [x] **live tunnel verified**: `sudo bash deploy/scripts/e2e-netns.sh`
        pings across the encrypted tunnel between two network namespaces
- [x] **M2** — multi-transport + auto-selection, verified live
  - [x] stream framing + TCP / TLS / WSS transports (`internal/transport`)
  - [x] **WSS obfuscation** on :443 (WebSocket-over-TLS) + decoy website
  - [x] link-level Happy-Eyeballs auto-selection wired into `veil up`
        (races transports, first working handshake wins)
  - [x] multi-listener gateway (UDP + WSS) in `veil-server run`
  - [x] **hostile-network fallback verified**: `sudo MODE=blockudp bash
        deploy/scripts/e2e-netns.sh` drops UDP → client auto-falls back to
        WSS/443 and the tunnel still works
- [x] **M3** — control plane + full VPN, verified live
  - [x] embedded device store (bbolt) — invites + enrolled keys (`internal/store`)
  - [x] **invite enrollment** over the HTTPS control plane: `veil login <host>
        <invite>` fetches & pins the server key automatically (no manual key)
  - [x] gateway **rejects un-enrolled devices**; admin CLI `veil-server
        invite` / `veil-server devices [--revoke]`
  - [x] **full-tunnel mode** (`veil up --full`): split-default route through the
        tunnel, server-endpoint route pinning, DNS push, and a `--kill-switch`
        (`internal/netcfg` `FullTunnelUp`/`Down`)
  - [x] verified live via `deploy/scripts/e2e-netns.sh` (`MODE=normal|blockudp|full`):
        enroll → connect (udp/wss) → ping/full-tunnel egress → un-enrolled rejected
  - [ ] later: admin web UI, per-network transport memory persistence
- [~] **M4** — native Windows client (Wintun)
  - [x] Wintun TUN device (`internal/tun/tun_windows.go`)
  - [x] Windows netcfg via `netsh` (IP + MTU); **split-tunnel `veil up` works**
  - [x] CI builds a ready-to-run `veil.exe` + `wintun.dll` artifact (Actions)
  - [ ] full-tunnel routing/DNS on Windows; Windows service; firewall kill-switch
- [~] **M7 — GUI + daemon**
  - [x] privileged **daemon + local IPC** (unix socket / named pipe); unprivileged
        control (`internal/daemon`, `internal/ipc`) — `veil daemon`,
        `veil ctl connect|disconnect|status`
  - [x] tunnel **Engine** with ordered shutdown (`internal/client/engine.go`) —
        **fixes the Windows use-after-close crash**; adapter renamed **"Veil"**
  - [x] **Fyne desktop app** (`cmd/veil-gui`): one-button Connect + live status
  - [x] CI builds Windows (`veil.exe`+`veil-gui.exe`+`wintun.dll`) and Linux GUI artifacts
  - [x] daemon lifecycle verified live: `sudo MODE=daemon bash deploy/scripts/e2e-netns.sh`
        (connect→ping→disconnect→**reconnect**)
- [x] **M5** — hardening + packaging, verified live
  - [x] **Let's Encrypt autocert** for real domains, self-signed fallback for
        IP/dev (`internal/certutil` `ServerTLSConfig`)
  - [x] **active-probing resistance**: the `/veil` upgrade is gated by a secret
        tunnel token (issued at enrollment); token-less probes get only the
        decoy site (`internal/transport`, tested)
  - [x] **packaging**: systemd units + `deploy/install.sh` (one-command
        install); Docker/compose already present
- [ ] **M6** — QUIC/HTTP3, mesh + NAT hole-punching + relay, mobile, OIDC

## License

MIT — see [LICENSE](LICENSE).
