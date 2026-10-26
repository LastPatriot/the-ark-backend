#!/usr/bin/env bash
# Simulates phones uploading at the same time. Each client unlocks its own session
# with the PIN, then all run a resumable tus upload (scripts/upload_test.sh) of a
# random file in parallel. Every file is downloaded again and its SHA-256 compared.
#
#   ./scripts/load_test.sh <base_url> <folder_slug> <pin> [clients=15] [size_mb=50]
#
# The PIN needs a role that can upload and download (contributor or editor).
set -euo pipefail

if (( $# < 3 )); then
  sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
BASE=${1%/} FOLDER=$2 PIN=$3 N=${4:-15} MB=${5:-50}
HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d "${TMPDIR:-/tmp}/ark-load.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

echo "preparing $N files of $MB MB"
for i in $(seq 1 "$N"); do
  head -c $(( MB * 1024 * 1024 )) /dev/urandom > "$WORK/phone-$i.bin"
done

SIDS=()
for i in $(seq 1 "$N"); do
  RESP=$(curl -sS -H 'content-type: application/json' "$BASE/api/v1/folders/$FOLDER/unlock" -d "{\"pin\":\"$PIN\"}")
  SID=$(sed -n 's/.*"session_id":"\([^"]*\)".*/\1/p' <<<"$RESP")
  [[ -n $SID ]] || { echo "unlock failed: $RESP"; exit 1; }
  SIDS+=("$SID")
done

echo "uploading from $N clients at once"
START=$(date +%s)
for i in $(seq 1 "$N"); do
  (
    rc=0
    VERIFY=1 "$HERE/upload_test.sh" "$BASE" "$FOLDER" "$WORK/phone-$i.bin" "${SIDS[$((i-1))]}" \
      > "$WORK/phone-$i.log" 2>&1 || rc=$?
    echo "$rc" > "$WORK/phone-$i.rc"
  ) &
done
wait
SECS=$(( $(date +%s) - START ))
(( SECS > 0 )) || SECS=1

OK=0
for i in $(seq 1 "$N"); do
  if [[ $(cat "$WORK/phone-$i.rc") == 0 ]] && grep -q "download matches" "$WORK/phone-$i.log"; then
    OK=$(( OK + 1 ))
  else
    echo "--- client $i failed:"; tr '\r' '\n' < "$WORK/phone-$i.log" | tail -5
  fi
done
RETRIES=$(cat "$WORK"/phone-*.log | tr '\r' '\n' | grep -c "retrying" || true)
TOTAL=$(( N * MB ))
echo "clients ok: $OK/$N   data: $TOTAL MB in ${SECS}s ($(( TOTAL / SECS )) MB/s, upload + verify download)   retried chunks: $RETRIES"
(( OK == N ))
