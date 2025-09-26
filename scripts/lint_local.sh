#!/usr/bin/env bash
set -euo pipefail

# Minimal, nem-intruzív lint fallback kifejezetten a canonicalize eszközre.
if command -v go >/dev/null 2>&1; then
  echo "[lint_local] go vet ./tools/canonicalize/..."
  go vet ./tools/canonicalize/... || true
else
  echo "[lint_local] go nem elérhető"
fi

if command -v staticcheck >/dev/null 2>&1; then
  echo "[lint_local] staticcheck ./tools/canonicalize/..."
  staticcheck ./tools/canonicalize/... || true
else
  echo "[lint_local] staticcheck nem elérhető (skip)"
fi
