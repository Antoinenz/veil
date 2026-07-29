#!/usr/bin/env bash
# End-to-end live tunnel test using two network namespaces on one host.
#
#   [ veil-cli ns ] --veth-- [ veil-srv ns ]
#   client veil0 100.64.0.2  <== encrypted UDP tunnel ==>  server veil0 100.64.0.1
#
# Runs the real veil / veil-server binaries and pings across the tunnel.
# Must run as root (creates netns + TUN devices). Usage: sudo bash e2e-netns.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BINDIR=/tmp/veil-e2e/bin
SRV=/tmp/veil-e2e/srv
CLI=/tmp/veil-e2e/cli
PORT=5555
NS_S=veil-srv
NS_C=veil-cli

log() { echo -e "\n\033[1;36m>>> $*\033[0m"; }

cleanup() {
  set +e
  pkill -f "$BINDIR/veil-server" 2>/dev/null
  pkill -f "$BINDIR/veil up"     2>/dev/null
  ip netns del "$NS_S" 2>/dev/null
  ip netns del "$NS_C" 2>/dev/null
}
trap cleanup EXIT

log "Preparing dirs + binaries"
rm -rf /tmp/veil-e2e && mkdir -p "$BINDIR" "$SRV" "$CLI"
cp "$REPO/bin/veil" "$REPO/bin/veil-server" "$BINDIR/"

log "Initializing server keys/config"
"$BINDIR/veil-server" init --domain e2e.local --data-dir "$SRV" >/dev/null
# Overwrite server.json for the test: listen on all ifaces in its ns, no egress NAT.
cat > "$SRV/server.json" <<JSON
{
  "domain": "e2e.local",
  "listen_tls": ":443",
  "listen_udp": ":$PORT",
  "tunnel_cidr": "100.64.0.0/10",
  "data_dir": "$SRV",
  "egress_interface": "",
  "dns": "1.1.1.1"
}
JSON
SRVPUB="$(cat "$SRV/server.pub")"
log "Server public key: $SRVPUB"

log "Enrolling client (manual key pin)"
"$BINDIR/veil" login --data-dir "$CLI" --server-key "$SRVPUB" "10.55.0.1:$PORT" test-invite >/dev/null

log "Creating network namespaces + veth"
ip netns add "$NS_S"
ip netns add "$NS_C"
ip link add veth-s type veth peer name veth-c
ip link set veth-s netns "$NS_S"
ip link set veth-c netns "$NS_C"
ip -n "$NS_S" addr add 10.55.0.1/24 dev veth-s
ip -n "$NS_C" addr add 10.55.0.2/24 dev veth-c
ip -n "$NS_S" link set veth-s up; ip -n "$NS_S" link set lo up
ip -n "$NS_C" link set veth-c up; ip -n "$NS_C" link set lo up

log "Starting server in $NS_S"
ip netns exec "$NS_S" "$BINDIR/veil-server" run --config "$SRV/server.json" >/tmp/veil-e2e/srv.log 2>&1 &
sleep 1.5

log "Starting client in $NS_C"
ip netns exec "$NS_C" "$BINDIR/veil" up --data-dir "$CLI" >/tmp/veil-e2e/cli.log 2>&1 &
sleep 2

log "Server log:";  sed 's/^/  [srv] /' /tmp/veil-e2e/srv.log || true
log "Client log:";  sed 's/^/  [cli] /' /tmp/veil-e2e/cli.log || true

log "PING across the tunnel: client 100.64.0.2 -> server 100.64.0.1"
if ip netns exec "$NS_C" ping -c 3 -W 2 100.64.0.1; then
  log "RESULT: ✅ TUNNEL WORKS — encrypted packets flowed end to end"
  RC=0
else
  log "RESULT: ❌ ping failed — see logs above"
  RC=1
fi

exit $RC
