#!/usr/bin/env bash
# Stops and removes the Ark service. Keeps /var/lib/ark and /etc/ark unless --purge.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo "run with sudo"; exit 1; }
systemctl disable --now ark.service 2>/dev/null || true
rm -f /etc/systemd/system/ark.service /usr/local/bin/ark /etc/systemd/resolved.conf.d/ark.conf
systemctl daemon-reload
if [[ ${1:-} == --purge ]]; then
  rm -rf /var/lib/ark /etc/ark
  userdel ark 2>/dev/null || true
  echo "Ark removed, including all files."
else
  echo "Ark removed. Data kept in /var/lib/ark (use --purge to delete)."
fi
