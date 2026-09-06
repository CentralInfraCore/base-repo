#!/usr/bin/env bash
set -euo pipefail

NOTE="${1:-}"

LOCK="llm.lock"
if [[ ! -f "$LOCK" ]]; then
  echo "version: 1" > "$LOCK"
  echo "canonical_definitions: true" >> "$LOCK"
fi

# Read current version (default 1)
CUR=$(grep -E '^version:\s*[0-9]+' "$LOCK" | awk '{print $2}' || true)
if [[ -z "$CUR" ]]; then CUR=1; fi
NEXT=$((CUR + 1))

ISO8601=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Rewrite file (idempotensen, egyszerűen)
{
  echo "version: $NEXT"
  if grep -q '^canonical_definitions:' "$LOCK"; then
    grep '^canonical_definitions:' "$LOCK"
  else
    echo "canonical_definitions: true"
  fi
  echo "last_changed: $ISO8601"
  if [[ -n "$NOTE" ]]; then
    echo "note: "$NOTE""
  fi
} > "$LOCK"

echo "llm.lock bumped to version $NEXT"
