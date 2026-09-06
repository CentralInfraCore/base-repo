#!/usr/bin/env bash
set -euo pipefail

BIN="${BINARY:-}"
if [[ -z "${BIN}" ]]; then
  COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")
  CAND="./output/${COMMIT}/canonicalize"
  if [[ -x "${CAND}" ]]; then BIN="${CAND}"; fi
fi
if [[ -z "${BIN}" ]]; then
  echo "Adj meg BINARY-t vagy futtasd előbb: make build-canonicalize" >&2
  exit 2
fi

echo "== bench canonicalize =="
for f in GOLDEN/*.in; do
  sz=$(wc -c < "$f" | tr -d '[:space:]')
  printf "%-28s  %10s bytes  " "$(basename "$f")" "$sz"
  # portable timing (bash time output), fogjuk csak a real időt
  t=$( { TIMEFORMAT=%3R; time "$BIN" < "$f" > /dev/null; } 2>&1 )
  echo "time=${t}s"
done
