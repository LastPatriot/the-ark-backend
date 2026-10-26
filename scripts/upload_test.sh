#!/usr/bin/env bash
# Resumable tus upload with curl, in 8 MB chunks.
#
#   ./scripts/upload_test.sh <base_url> <folder_slug> <file> <session_id> [subfolder_path]
#
# Stalled or failed chunks are retried until the network comes back. If the script
# itself is killed, run the same command again and it resumes from the server's offset.
# Env: CHUNK_MB (default 8), VERIFY=1 to download the file afterwards and compare SHA-256.
set -euo pipefail

if (( $# < 4 )); then
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  exit 2
fi
BASE=${1%/} FOLDER=$2 FILE=$3 SID=$4 SUBPATH=${5:-}
CHUNK=$(( ${CHUNK_MB:-8} * 1024 * 1024 ))

b64() { printf %s "$1" | base64 | tr -d '\n'; }
filesize() { stat -f%z "$1" 2>/dev/null || stat -c%s "$1"; }
sha256() { if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi; }
hdr() { { grep -i "^$1:" || true; } | head -1 | cut -d' ' -f2- | tr -d '\r'; }

SIZE=$(filesize "$FILE")
NAME=$(basename "$FILE")
ABS="$(cd "$(dirname "$FILE")" && pwd)/$NAME"
STATE="${TMPDIR:-/tmp}/ark-upload-$(printf %s "$BASE|$FOLDER|$SUBPATH|$ABS|$SIZE|$SID" | sha256 | cut -c1-16)"
AUTH=(-H "Authorization: Bearer $SID" -H "Tus-Resumable: 1.0.0")
# Give up on a chunk that moves less than 1 KB/s for 15 s (e.g. Wi-Fi dropped).
NET=(--connect-timeout 5 --speed-limit 1024 --speed-time 15)

if [[ -f $STATE ]]; then
  URL=$(cat "$STATE")
  echo "resuming $URL"
else
  META="filename $(b64 "$NAME"),folder $(b64 "$FOLDER")"
  [[ -n $SUBPATH ]] && META+=",path $(b64 "$SUBPATH")"
  RESP=$(curl -sS -D - -o /dev/null -X POST "${AUTH[@]}" "${NET[@]}" \
    -H "Upload-Length: $SIZE" -H "Upload-Metadata: $META" "$BASE/api/v1/uploads")
  LOC=$(hdr location <<<"$RESP")
  if [[ -z $LOC ]]; then
    echo "create failed:"; echo "$RESP" | head -1; exit 1
  fi
  URL="$BASE$LOC"
  echo "$URL" > "$STATE"
  echo "created $URL ($SIZE bytes)"
fi

START=$(date +%s)
FILE_ID=""
while true; do
  if ! HEAD=$(curl -sS -I "${AUTH[@]}" "${NET[@]}" "$URL" 2>&1); then
    echo "HEAD failed ($HEAD); retrying in 2 s"; sleep 2; continue
  fi
  CODE=$(head -1 <<<"$HEAD" | awk '{print $2}')
  if [[ $CODE == 404 ]]; then
    rm -f "$STATE"; echo "server no longer has this upload; run again to start over"; exit 1
  elif [[ $CODE != 200 ]]; then
    echo "HEAD returned $CODE; retrying in 2 s"; sleep 2; continue
  fi
  OFFSET=$(hdr upload-offset <<<"$HEAD")
  FILE_ID=$(hdr ark-file-id <<<"$HEAD")
  (( OFFSET >= SIZE )) && break

  printf '\r%6.2f%%  %d / %d bytes  ' "$(bc -l <<<"100*$OFFSET/$SIZE")" "$OFFSET" "$SIZE"
  # tail is cut off by head (SIGPIPE); only curl's status matters.
  CODE=$( { tail -c +$(( OFFSET + 1 )) "$FILE" 2>/dev/null || true; } | head -c "$CHUNK" |
    curl -sS -o /dev/null -w '%{http_code}' -X PATCH "${AUTH[@]}" "${NET[@]}" \
      -H "Content-Type: application/offset+octet-stream" -H "Upload-Offset: $OFFSET" \
      --data-binary @- "$URL" 2>/dev/null) || CODE="network error"
  if [[ $CODE != 204 ]]; then
    printf '\nPATCH: %s; retrying in 2 s\n' "$CODE"; sleep 2
  fi
done

rm -f "$STATE"
LOCAL=$(sha256 < "$FILE")
printf '\rdone: %d bytes in %d s\nfile id: %s\nsha256:  %s\n' "$SIZE" "$(( $(date +%s) - START ))" "$FILE_ID" "$LOCAL"

if [[ ${VERIFY:-0} == 1 ]]; then
  REMOTE=$(curl -sS -H "Authorization: Bearer $SID" "$BASE/dl/$FILE_ID" | sha256)
  if [[ $REMOTE == "$LOCAL" ]]; then echo "verify:  download matches"; else echo "verify:  MISMATCH ($REMOTE)"; exit 1; fi
fi
