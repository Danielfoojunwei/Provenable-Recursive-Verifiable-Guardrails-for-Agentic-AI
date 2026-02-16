#!/usr/bin/env bash
# Evidence bundle export and verification
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINS_DIR="$(dirname "$SCRIPT_DIR")/bins"

# Ensure bins are on PATH
export PATH="$BINS_DIR:$PATH"

if ! command -v proven-aer >/dev/null 2>&1; then
    echo "ERROR: proven-aer not found. Run: bash scripts/setup.sh"
    exit 1
fi

ACTION="${1:-export}"
shift || true

case "$ACTION" in
    export)
        echo "Exporting evidence bundle..."
        proven-aer bundle export "$@"
        echo ""
        echo "Verifying exported bundle..."
        BUNDLE=$(ls -t ~/.proven/.aer/bundles/*.aegx.zip 2>/dev/null | head -1)
        if [ -n "$BUNDLE" ]; then
            proven-aer verify "$BUNDLE"
            echo ""
            echo "Bundle: $BUNDLE"
        fi
        ;;
    verify)
        if [ -z "${1:-}" ]; then
            echo "Usage: prove-export.sh verify <BUNDLE_PATH>"
            exit 1
        fi
        exec proven-aer verify "$1"
        ;;
    summarize)
        if [ -z "${1:-}" ]; then
            echo "Usage: prove-export.sh summarize <BUNDLE_DIR>"
            exit 1
        fi
        exec aegx summarize "$1"
        ;;
    *)
        echo "Usage: prove-export.sh <export|verify|summarize> [args...]"
        echo ""
        echo "  export [--agent ID]    Export evidence bundle"
        echo "  verify <PATH>          Verify a bundle"
        echo "  summarize <DIR>        Summarize a bundle"
        exit 1
        ;;
esac
