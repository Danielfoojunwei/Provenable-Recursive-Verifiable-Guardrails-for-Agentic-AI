#!/usr/bin/env bash
# Quick alert viewer — shows recent alerts with optional severity filter
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINS_DIR="$(dirname "$SCRIPT_DIR")/bins"

# Ensure bins are on PATH
export PATH="$BINS_DIR:$PATH"

if ! command -v proven-aer >/dev/null 2>&1; then
    echo "ERROR: proven-aer not found. Run: bash scripts/setup.sh"
    exit 1
fi

SEVERITY="${1:-MEDIUM}"
LIMIT="${2:-20}"

exec proven-aer prove --severity "$SEVERITY" --limit "$LIMIT"
