#!/usr/bin/env bash
# Install veil binaries + systemd units. Run from a checkout: sudo bash deploy/install.sh
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
REPO="$(cd "$(dirname "$0")/.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
  echo "please run as root (sudo bash deploy/install.sh)"; exit 1
fi

# Build if needed.
if [ ! -x "$REPO/bin/veil-server" ] || [ ! -x "$REPO/bin/veil" ]; then
  if command -v go >/dev/null 2>&1; then
    echo ">>> building..."; (cd "$REPO" && make build)
  else
    echo "binaries missing and Go not found — run 'make build' first (needs Go >= 1.23)"; exit 1
  fi
fi

echo ">>> installing binaries to $PREFIX/bin"
install -m0755 "$REPO/bin/veil"        "$PREFIX/bin/veil"
install -m0755 "$REPO/bin/veil-server" "$PREFIX/bin/veil-server"

echo ">>> installing systemd units"
install -d /etc/veil
install -m0644 "$REPO/deploy/systemd/veil-server.service" /etc/systemd/system/veil-server.service
install -m0644 "$REPO/deploy/systemd/veil.service"        /etc/systemd/system/veil.service
systemctl daemon-reload

cat <<'NEXT'

installed ✔

Server:
  sudo veil-server init --domain <host-or-ip> --data-dir /etc/veil   # prints an invite
  sudo systemctl enable --now veil-server

Client:
  sudo veil login --data-dir /etc/veil <host-or-ip> <invite>
  sudo veil up    --data-dir /etc/veil            # add --full for a full VPN
  # or run as a service: sudo systemctl enable --now veil
NEXT
