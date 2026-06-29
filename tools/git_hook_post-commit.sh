#!/bin/sh
#
# post-commit hook: auto-update companion YAMLs for changed Go files.
#
# Behaviour:
#   - Runs go.meta.gen.py --merge only on Go files changed in the last commit.
#   - Only updates companion YAMLs that already exist (never creates new ones).
#   - Skips test files (*_test.go).
#   - Silently exits if no Go files changed or no companion exists.
#   - Does NOT auto-commit the updated companions (leave to the developer).

set -e

REPO_ROOT=$(git rev-parse --show-toplevel)
TOOLS_DIR="$REPO_ROOT/tools"
GEN_SCRIPT="$TOOLS_DIR/go.meta.gen.py"

if [ ! -f "$GEN_SCRIPT" ]; then
    exit 0
fi

# Find Python venv (prefer project venv, fall back to system python3)
if [ -f "$REPO_ROOT/p_venv/bin/python" ]; then
    PYTHON="$REPO_ROOT/p_venv/bin/python"
elif [ -f "$REPO_ROOT/../MCPs/base/p_venv/bin/python" ]; then
    PYTHON="$REPO_ROOT/../MCPs/base/p_venv/bin/python"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON=python3
else
    exit 0
fi

# Get list of Go source files changed in the last commit (exclude test files)
CHANGED_GO_FILES=$(git diff-tree --no-commit-id -r --name-only HEAD 2>/dev/null \
    | grep '\.go$' \
    | grep -v '_test\.go$' \
    || true)

if [ -z "$CHANGED_GO_FILES" ]; then
    exit 0
fi

# Run --merge on each changed Go file that already has a companion YAML
for GO_FILE in $CHANGED_GO_FILES; do
    ABS_GO="$REPO_ROOT/$GO_FILE"
    COMPANION="${ABS_GO%.go}.yaml"
    if [ ! -f "$COMPANION" ]; then
        continue
    fi
    "$PYTHON" "$GEN_SCRIPT" --file "$ABS_GO" --merge --quiet 2>/dev/null || true
done

exit 0
