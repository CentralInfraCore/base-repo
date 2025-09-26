#!/usr/bin/env bash
set -euo pipefail

# This verifier expects a CLI that reads from stdin and writes canonical JSON to stdout.
# Configure the path with BINARY=<path>. If empty, we suggest BUILD_DIR/output/<COMMIT>/canonicalize.
BIN="${BINARY:-}"

if [[ -z "${BIN}" ]]; then
  COMMIT=$(git rev-parse --short HEAD 2>/dev/null || echo "dev")
  CAND="./output/${COMMIT}/canonicalize"
  if [[ -x "${CAND}" ]]; then
    BIN="${CAND}"
  fi
fi

if [[ -z "${BIN}" ]]; then
  echo "✖ BINARY nincs megadva és a default nem található." >&2
  echo "  Tipp: make build-canonicalize && make verify" >&2
  echo "  vagy: BINARY=./output/$(git rev-parse --short HEAD)/canonicalize make verify" >&2
  exit 2
fi
if [[ ! -x "${BIN}" ]]; then
  echo "✖ A megadott BINARY nem futtatható: ${BIN}" >&2
  exit 2
fi

fail=0
tmpdir=$(mktemp -d)
trap 'rm -rf "${tmpdir}"' EXIT

for in_f in GOLDEN/*.in; do
  base=$(basename "$in_f" .in)
  out_f="${tmpdir}/${base}.out"
  # Run canonicalizer (stdin->stdout)
  if ! "${BIN}" < "$in_f" > "$out_f"; then
    echo "Run failed: ${base}" >&2
    fail=1
    continue
  fi
  if ! diff -u "GOLDEN/${base}.out" "$out_f"; then
    echo "Mismatch: ${base}" >&2
    fail=1
  fi
done

exit $fail
