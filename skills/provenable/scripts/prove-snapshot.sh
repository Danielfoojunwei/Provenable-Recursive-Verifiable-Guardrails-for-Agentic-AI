#!/usr/bin/env bash
# Snapshot helper — create, list, or rollback
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINS_DIR="$(dirname "$SCRIPT_DIR")/bins"

# Ensure bins are on PATH
export PATH="$BINS_DIR:$PATH"

if ! command -v proven-aer >/dev/null 2>&1; then
    echo "ERROR: proven-aer not found. Run: bash scripts/setup.sh"
    exit 1
fi

ACTION="${1:-list}"
shift || true

case "$ACTION" in
    create)
        NAME="${1:-"snapshot-$(date +%Y%m%d-%H%M%S)"}"
        SCOPE="${2:-full}"
        exec proven-aer snapshot create "$NAME" --scope "$SCOPE"
        ;;
    list)
        exec proven-aer snapshot list
        ;;
    rollback)
        if [ -z "${1:-}" ]; then
            echo "Usage: prove-snapshot.sh rollback <SNAPSHOT_ID>"
            echo ""
            echo "Available snapshots:"
            proven-aer snapshot list
            exit 1
        fi
        exec proven-aer rollback "$1"
        ;;
    *)
        echo "Usage: prove-snapshot.sh <create|list|rollback> [args...]"
        echo ""
        echo "  create [name] [scope]    Create a snapshot (scope: full|control-plane|memory)"
        echo "  list                     List all snapshots"
        echo "  rollback <ID>            Rollback to a snapshot"
        exit 1
        ;;
esac
