#!/usr/bin/env bash
set -euo pipefail

# Minimal gofmt helper:
# - alapértelmezés: csak listáz (gofmt -l)
# - ha FMT_WRITE=1, akkor ír is (gofmt -s -w)
# - kihagyjuk: vendor/, output/, tmp/, tar/, __pycache__/, .git/
WRITE=${FMT_WRITE:-0}

# find Go files, pruning scratch dirs
mapfile -d '' FILES < <(find . \
  -path './vendor' -prune -o \
  -path './output' -prune -o \
  -path './tmp' -prune -o \
  -path './tar' -prune -o \
  -path './__pycache__' -prune -o \
  -path './.git' -prune -o \
  -type f -name '*.go' -print0)

if [[ ${#FILES[@]} -eq 0 ]]; then
  echo "[fmt_local] no Go files"
  exit 0
fi

if [[ "$WRITE" == "1" ]]; then
  echo "[fmt_local] formatting ${#FILES[@]} files (gofmt -s -w)"
  gofmt -s -w "${FILES[@]}"
else
  echo "[fmt_local] checking format (gofmt -l)"
  UNFORMATTED=$(gofmt -l "${FILES[@]}")
  if [[ -n "$UNFORMATTED" ]]; then
    echo "[fmt_local] unformatted files:"
    echo "$UNFORMATTED"
    # do not fail the quality gate; user can run: FMT_WRITE=1 scripts/fmt_local.sh
  else
    echo "[fmt_local] all good"
  fi
fi
