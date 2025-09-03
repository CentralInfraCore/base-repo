#!/usr/bin/env bash
set -euo pipefail

# MANIFEST.sha256 generálása determinisztikus sorrendben.
# Hash-eld legalább a GOLDEN kimeneteket és az AI/context fájlokat.

ROOT="${1:-.}"
OUT="${2:-MANIFEST.sha256}"

# GNU find + sort; rendezett, relatív lista.
mapfile -t FILES < <(cd "$ROOT" &&   find ai context GOLDEN -type f -not -name ".keep" -print 2>/dev/null | LC_ALL=C sort)

{
  echo "# MANIFEST of critical/golden files (sha256)"
  echo "# generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")"
  for f in "${FILES[@]}"; do
    sha256sum "$ROOT/$f" | awk '{print $1, " *" $2}'
  done
} > "$OUT"

echo "Wrote $OUT"
