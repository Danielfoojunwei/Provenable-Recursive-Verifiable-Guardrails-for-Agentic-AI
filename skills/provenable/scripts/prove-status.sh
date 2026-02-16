#!/usr/bin/env bash
# Quick protection status check — outputs JSON
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINS_DIR="$(dirname "$SCRIPT_DIR")/bins"

# Ensure bins are on PATH
export PATH="$BINS_DIR:$PATH"

if ! command -v proven-aer >/dev/null 2>&1; then
    echo '{"error":"proven-aer not found. Run: bash scripts/setup.sh"}'
    exit 1
fi

# Check if AER is initialized
if ! proven-aer status >/dev/null 2>&1; then
    echo '{"error":"AER not initialized. Run: proven-aer init"}'
    exit 1
fi

# Run the prove query
exec proven-aer prove --json "$@"
