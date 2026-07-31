# Testing veil

Two ways to exercise a real tunnel: a fully-automated single-host test using
network namespaces, and a manual two-machine LAN test.

## 1. Automated: two network namespaces on one host

Runs the real binaries with a client and server in separate namespaces and pings
across the encrypted tunnel. Requires root (creates namespaces + TUN devices).

```bash
make build
sudo MODE=normal   bash deploy/scripts/e2e-netns.sh   # client selects udp
sudo MODE=blockudp bash deploy/scripts/e2e-netns.sh   # UDP dropped -> auto-falls back to wss
sudo MODE=full     bash deploy/scripts/e2e-netns.sh   # full-tunnel: reach a server-only IP
```

`blockudp` proves the censorship-resistance path: with UDP dropped, the client
transparently falls back to **WebSocket-over-TLS on :443** and the tunnel still works.

## 2. Manual: server on one machine, client on another (LAN)

Verified working: a Windows laptop (client, under WSL2) → a Raspberry Pi 5
(server) over the LAN, `ping` across the tunnel at ~2.6 ms, 0% loss.

### ⚠️ Address-range conflict with Tailscale
veil defaults its tunnel to the CGNAT block `100.64.0.0/10` — which is exactly
what **Tailscale** uses. If either machine also runs Tailscale, pick a different
range for `tunnel_cidr` (e.g. `10.66.0.0/16`) to avoid a routing conflict.

### Server (e.g. the Pi at 192.168.1.102)

```bash
sudo ./bin/veil-server init --domain 192.168.1.102 --data-dir /etc/veil

sudo tee /etc/veil/server.json >/dev/null <<'JSON'
{
  "domain": "192.168.1.102",
  "listen_tls": ":443",
  "listen_udp": ":443",
  "tunnel_cidr": "10.66.0.0/16",
  "data_dir": "/etc/veil",
  "egress_interface": "",
  "dns": "1.1.1.1"
}
JSON

sudo ./bin/veil-server run --config /etc/veil/server.json
# -> veil0 up as 10.66.0.1/16; udp [::]:443 + wss [::]:443/veil
```

### Client (the other machine)

With the control plane (M3+), enrollment fetches the server key automatically:

```bash
sudo ./bin/veil login --data-dir /tmp/veil-cli 192.168.1.102 <invite-code>
sudo ./bin/veil up   --data-dir /tmp/veil-cli
# then, from another shell:
ping 10.66.0.1     # the server's tunnel IP
```

The invite code is printed by `veil-server init` (and `veil-server invite`).
`login` prints the fetched server-key fingerprint — compare it with the
fingerprint `veil-server init` printed to detect a man-in-the-middle.

## Windows client (native, Wintun)

The Windows client is built by CI. From the repo's **Actions** tab, open the
latest run and download the **`veil-windows-amd64`** artifact — it contains
`veil.exe` and `wintun.dll` (keep them in the same folder).

Then, in **PowerShell running as Administrator**:

```powershell
.\veil.exe login --data-dir C:\veil <server-host> <invite>
.\veil.exe up    --data-dir C:\veil
# in another admin shell, ping the server's tunnel IP (e.g. 10.66.0.1)
```

Notes:
- Requires Administrator (Wintun adapter creation + `netsh`) and `wintun.dll`
  beside `veil.exe`.
- `--full` (route all traffic) is **not yet supported on Windows** — split-tunnel
  (reach the veil network + server + other peers) works today; full-tunnel is a
  follow-up so route/DNS changes can be validated before shipping.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `go: not found` | Install Go ≥ 1.23 (see README build section); `source ~/.bashrc`. |
| `command not found: ./veil-server` | Binaries live in `./bin/`; use `./bin/veil-server`. |
| Client can't reach server | First `ping <server-lan-ip>`. Under WSL2, confirm LAN reachability. |
| Port 443 in use | Set `":4443"` in server config + `"udp_port"/"tls_port": "4443"` in client config. |
| `tun: ... operation not permitted` | Run with `sudo` (needs `CAP_NET_ADMIN`). |
| Ping to tunnel IP fails but connect succeeds | Check the `tunnel_cidr` doesn't collide with an existing route (Tailscale/`100.64`, Docker `172.x`, WireGuard `10.x`). |

## Full-tunnel mode (route all traffic through the server)

Add `--full` to send **all** traffic through the tunnel (a real VPN), with DNS
pushed by the server and a kill-switch that fails closed if the tunnel drops:

```bash
sudo ./bin/veil up --data-dir /etc/veil --full            # kill-switch on by default
sudo ./bin/veil up --data-dir /etc/veil --full --kill-switch=false
```

For internet egress the **server** must have `egress_interface` set (e.g.
`"eth0"`) so it NATs client traffic out. Without it, full-tunnel still routes
through the server but only reaches what the server itself can reach.

> DNS handling replaces `/etc/resolv.conf` while connected and restores it on
> exit. On systemd-resolved hosts this is best-effort; a resolver integration is
> a later refinement.
