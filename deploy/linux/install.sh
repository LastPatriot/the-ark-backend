#!/usr/bin/env bash
# Installs Ark as a systemd service that starts on boot.
#
#   sudo ./deploy/linux/install.sh [path/to/ark-binary]
#
# Default binary: target/release/the-ark (or target/aarch64-unknown-linux-gnu/release/the-ark).
# Re-running upgrades the binary and keeps /etc/ark/ark.env and /var/lib/ark.
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../.." && pwd)
BIN=${1:-}
if [[ -z $BIN ]]; then
  for c in "$ROOT/target/release/the-ark" "$ROOT/target/aarch64-unknown-linux-gnu/release/the-ark"; do
    [[ -x $c ]] && BIN=$c && break
  done
fi
[[ -n $BIN && -x $BIN ]] || { echo "binary not found; build with: cargo build --release"; exit 1; }

id ark &>/dev/null || useradd --system --home-dir /var/lib/ark --shell /usr/sbin/nologin ark
install -d -o ark -g ark -m 750 /var/lib/ark
install -d -m 755 /etc/ark
[[ -f /etc/ark/ark.env ]] || install -m 640 -g ark "$HERE/ark.env" /etc/ark/ark.env
install -m 755 "$BIN" /usr/local/bin/ark
install -m 644 "$HERE/ark.service" /etc/systemd/system/ark.service

if grep -q '^ARK_DNS=true' /etc/ark/ark.env && systemctl is-active --quiet systemd-resolved; then
  if ! grep -qs '^DNSStubListener=no' /etc/systemd/resolved.conf; then
    read -rp "systemd-resolved holds port 53. Disable its stub listener? [y/N] " yn
    if [[ $yn == [yY] ]]; then
      mkdir -p /etc/systemd/resolved.conf.d
      printf '[Resolve]\nDNSStubListener=no\n' > /etc/systemd/resolved.conf.d/ark.conf
      ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
      systemctl restart systemd-resolved
    fi
  fi
fi

systemctl daemon-reload
systemctl enable ark.service
systemctl restart ark.service
sleep 2
systemctl --no-pager --lines=0 status ark.service || true
echo
echo "Ark installed. First run prints an admin setup code:"
echo "  journalctl -u ark -n 50 | grep 'setup code'"
echo "Config: /etc/ark/ark.env   Data: /var/lib/ark   Logs: journalctl -u ark -f"
