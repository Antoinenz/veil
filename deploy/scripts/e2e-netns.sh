#!/usr/bin/env bash
# End-to-end live tunnel test using two network namespaces on one host.
#
#   [ veil-cli ns ] --veth-- [ veil-srv ns ]
#   client veil0 10.66.0.2  <== encrypted tunnel ==>  server veil0 10.66.0.1
#
# Exercises the full M1–M3 stack: invite enrollment over the HTTPS control
# plane, transport auto-selection, and the encrypted tunnel.
#
#   MODE=normal   (default) UDP reachable   -> client picks udp
#   MODE=blockudp           UDP dropped     -> client auto-falls back to wss
#
# Usage: sudo MODE=blockudp bash e2e-netns.sh   (must be root: netns + TUN)
set -euo pipefail

MODE="${MODE:-normal}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BINDIR=/tmp/veil-e2e/bin
SRV=/tmp/veil-e2e/srv
CLI=/tmp/veil-e2e/cli
CLI2=/tmp/veil-e2e/cli2
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
rm -rf /tmp/veil-e2e && mkdir -p "$BINDIR" "$SRV" "$CLI" "$CLI2"
cp "$REPO/bin/veil" "$REPO/bin/veil-server" "$BINDIR/"

log "Initializing server (keys + store) and minting an invite"
"$BINDIR/veil-server" init --domain "$SRV_IP" --data-dir "$SRV" >/dev/null
cat > "$SRV/server.json" <<JSON
{
  "domain": "$SRV_IP",
  "listen_tls": ":443",
  "listen_udp": ":443",
  "tunnel_cidr": "10.66.0.0/16",
  "data_dir": "$SRV",
  "egress_interface": "",
  "dns": "1.1.1.1"
}
JSON
INVITE="$("$BINDIR/veil-server" invite --data-dir "$SRV" | awk '/new invite:/{print $3}')"
SRVPUB="$(cat "$SRV/server.pub")"
log "invite=$INVITE"

log "Creating network namespaces + veth"
ip netns add "$NS_S"; ip netns add "$NS_C"
ip link add veth-s type veth peer name veth-c
ip link set veth-s netns "$NS_S"; ip link set veth-c netns "$NS_C"
ip -n "$NS_S" addr add $SRV_IP/24 dev veth-s
ip -n "$NS_C" addr add 10.55.0.2/24 dev veth-c
ip -n "$NS_S" link set veth-s up; ip -n "$NS_S" link set lo up
ip -n "$NS_C" link set veth-c up; ip -n "$NS_C" link set lo up

if [ "$MODE" = "blockudp" ]; then
  log "Hostile network: DROP all UDP to the server (forces obfuscated fallback)"
  ip netns exec "$NS_S" iptables -A INPUT -p udp -j DROP
fi

log "Starting server in $NS_S"
ip netns exec "$NS_S" "$BINDIR/veil-server" run --config "$SRV/server.json" >/tmp/veil-e2e/srv.log 2>&1 &
sleep 1.5

log "Enrolling client over the HTTPS control plane (invite $INVITE)"
ip netns exec "$NS_C" "$BINDIR/veil" login --data-dir "$CLI" "$SRV_IP" "$INVITE"

log "Connecting client"
ip netns exec "$NS_C" "$BINDIR/veil" up --data-dir "$CLI" >/tmp/veil-e2e/cli.log 2>&1 &
sleep 4

log "Server log:"; sed 's/^/  [srv] /' /tmp/veil-e2e/srv.log || true
log "Client log:"; sed 's/^/  [cli] /' /tmp/veil-e2e/cli.log || true
CHOSEN="$(grep -o 'connected via [a-z]*' /tmp/veil-e2e/cli.log | head -1 | awk '{print $3}')"

log "PING across the tunnel: client 10.66.0.2 -> server 10.66.0.1"
if ! ip netns exec "$NS_C" ping -c 3 -W 2 10.66.0.1; then
  log "RESULT: ❌ ping failed — see logs above"; exit 1
fi
log "RESULT: ✅ TUNNEL WORKS over '${CHOSEN}' (MODE=$MODE)"
if [ "$MODE" = "blockudp" ] && [ "$CHOSEN" != "wss" ]; then
  log "WARNING: expected wss fallback but got '${CHOSEN}'"; exit 2
fi

# --- enforcement: an un-enrolled device must be refused ---------------------
log "Enrollment enforcement: a device that never enrolled must be REJECTED"
ip netns exec "$NS_C" "$BINDIR/veil" login --data-dir "$CLI2" --server-key "$SRVPUB" "$SRV_IP" bogus-invite >/dev/null
if ip netns exec "$NS_C" timeout 8 "$BINDIR/veil" up --data-dir "$CLI2" >/tmp/veil-e2e/cli2.log 2>&1; then
  log "RESULT: ❌ un-enrolled device was allowed to connect (should be rejected)"; exit 3
else
  log "RESULT: ✅ un-enrolled device correctly rejected"
fi
exit 0
