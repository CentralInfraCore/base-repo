#!/usr/bin/env bash
set -euo pipefail

# Lightweight quality gate: fmt, lint, build-canonicalize (best-effort), verify
# Does not modify the Makefile; can be called from CI or local.
echo "== fmt =="
(make fmt) || scripts/fmt_local.sh || true

echo "== lint =="
# Prefer repo's lint; ha bukik, essünk vissza a lokális lintre (csak canonicalize).
(make lint) || scripts/lint_local.sh || true

echo "== build-canonicalize =="
(make build-canonicalize) || {
  echo "(fallback) local build canonicalize"
  mkdir -p output/dev
  go build -trimpath -o output/dev/canonicalize ./tools/canonicalize
}

echo "== verify =="
if [ -x ./output/dev/canonicalize ]; then
  BINARY=./output/dev/canonicalize make verify
else
  make verify
fi
