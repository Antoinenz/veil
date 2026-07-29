#!/usr/bin/env bash
# End-to-end live tunnel test using two network namespaces on one host.
#
#   [ veil-cli ns ] --veth-- [ veil-srv ns ]
#   client veil0 100.64.0.2  <== encrypted tunnel ==>  server veil0 100.64.0.1
#
# The server serves BOTH the UDP transport and the WSS (WebSocket-over-TLS)
# obfuscation transport on :443. The client auto-selects the best working one.
#
#   MODE=normal   (default) UDP is reachable -> client picks udp
#   MODE=blockudp           UDP is dropped   -> client auto-falls back to wss
#
# Usage: sudo MODE=blockudp bash e2e-netns.sh   (must be root: netns + TUN)
set -euo pipefail

MODE="${MODE:-normal}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BINDIR=/tmp/veil-e2e/bin
SRV=/tmp/veil-e2e/srv
CLI=/tmp/veil-e2e/cli
NS_S=veil-srv
NS_C=veil-cli
SRV_IP=10.55.0.1

log() { echo -e "\n\033[1;36m>>> $*\033[0m"; }

cleanup() {
  set +e
  pkill -f "$BINDIR/veil-server" 2>/dev/null
  pkill -f "$BINDIR/veil up"     2>/dev/null
  ip netns del "$NS_S" 2>/dev/null
  ip netns del "$NS_C" 2>/dev/null
}
trap cleanup EXIT

log "MODE=$MODE — preparing dirs + binaries"
rm -rf /tmp/veil-e2e && mkdir -p "$BINDIR" "$SRV" "$CLI"
cp "$REPO/bin/veil" "$REPO/bin/veil-server" "$BINDIR/"

log "Initializing server keys/config"
"$BINDIR/veil-server" init --domain e2e.local --data-dir "$SRV" >/dev/null
cat > "$SRV/server.json" <<JSON
{
  "domain": "e2e.local",
  "listen_tls": ":443",
  "listen_udp": ":443",
  "tunnel_cidr": "100.64.0.0/10",
  "data_dir": "$SRV",
  "egress_interface": "",
  "dns": "1.1.1.1"
}
JSON
SRVPUB="$(cat "$SRV/server.pub")"

log "Enrolling client (host $SRV_IP, ports default 443)"
"$BINDIR/veil" login --data-dir "$CLI" --server-key "$SRVPUB" "$SRV_IP" test-invite >/dev/null

log "Creating network namespaces + veth"
ip netns add "$NS_S"; ip netns add "$NS_C"
ip link add veth-s type veth peer name veth-c
ip link set veth-s netns "$NS_S"; ip link set veth-c netns "$NS_C"
ip -n "$NS_S" addr add $SRV_IP/24 dev veth-s
ip -n "$NS_C" addr add 10.55.0.2/24 dev veth-c
ip -n "$NS_S" link set veth-s up; ip -n "$NS_S" link set lo up
ip -n "$NS_C" link set veth-c up; ip -n "$NS_C" link set lo up

if [ "$MODE" = "blockudp" ]; then
  log "Simulating a hostile network: DROP all UDP to the server (forces obfuscated fallback)"
  ip netns exec "$NS_S" iptables -A INPUT -p udp -j DROP
fi

log "Starting server in $NS_S"
ip netns exec "$NS_S" "$BINDIR/veil-server" run --config "$SRV/server.json" >/tmp/veil-e2e/srv.log 2>&1 &
sleep 1.5

log "Starting client in $NS_C"
ip netns exec "$NS_C" "$BINDIR/veil" up --data-dir "$CLI" >/tmp/veil-e2e/cli.log 2>&1 &
sleep 4

log "Server log:"; sed 's/^/  [srv] /' /tmp/veil-e2e/srv.log || true
log "Client log:"; sed 's/^/  [cli] /' /tmp/veil-e2e/cli.log || true

CHOSEN="$(grep -o 'connected via [a-z]*' /tmp/veil-e2e/cli.log | head -1 | awk '{print $3}')"
log "Client selected transport: ${CHOSEN:-<none>}"

log "PING across the tunnel: client 100.64.0.2 -> server 100.64.0.1"
if ip netns exec "$NS_C" ping -c 3 -W 2 100.64.0.1; then
  log "RESULT: ✅ TUNNEL WORKS over '${CHOSEN}' (MODE=$MODE)"
  if [ "$MODE" = "blockudp" ] && [ "$CHOSEN" != "wss" ]; then
    log "WARNING: expected wss fallback but got '${CHOSEN}'"; exit 2
  fi
  exit 0
else
  log "RESULT: ❌ ping failed — see logs above"; exit 1
fi
