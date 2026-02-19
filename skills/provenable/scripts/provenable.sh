#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINS_DIR="$(dirname "$SCRIPT_DIR")/bins"

# Ensure bins are on PATH
export PATH="$BINS_DIR:$PATH"

usage() {
    echo "Usage: provenable.sh <subcommand> [args...]"
    echo ""
    echo "Subcommands:"
    echo "  alerts  [SEVERITY] [LIMIT]           Show recent alerts (default: MEDIUM, 20)"
    echo "  export  [export|verify|summarize] ... Evidence bundle export and verification"
    echo "  snapshot <create|list|rollback> ...   Snapshot management"
    echo "  status  [args...]                     Quick protection status check (JSON)"
    echo ""
    echo "Examples:"
    echo "  provenable.sh alerts CRITICAL 10"
    echo "  provenable.sh export export --agent my-agent"
    echo "  provenable.sh export verify /path/to/bundle"
    echo "  provenable.sh export summarize /path/to/bundle-dir"
    echo "  provenable.sh snapshot create pre-deploy full"
    echo "  provenable.sh snapshot list"
    echo "  provenable.sh snapshot rollback <SNAPSHOT_ID>"
    echo "  provenable.sh status"
    exit 1
}

# --- alerts ---
cmd_alerts() {
    if ! command -v proven-aer >/dev/null 2>&1; then
        echo "ERROR: proven-aer not found. Run: bash scripts/setup.sh"
        exit 1
    fi

    SEVERITY="${1:-MEDIUM}"
    LIMIT="${2:-20}"

    exec proven-aer prove --severity "$SEVERITY" --limit "$LIMIT"
}

# --- export ---
cmd_export() {
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
                echo "Usage: provenable.sh export verify <BUNDLE_PATH>"
                exit 1
            fi
            exec proven-aer verify "$1"
            ;;
        summarize)
            if [ -z "${1:-}" ]; then
                echo "Usage: provenable.sh export summarize <BUNDLE_DIR>"
                exit 1
            fi
            exec aegx summarize "$1"
            ;;
        *)
            echo "Usage: provenable.sh export <export|verify|summarize> [args...]"
            echo ""
            echo "  export [--agent ID]    Export evidence bundle"
            echo "  verify <PATH>          Verify a bundle"
            echo "  summarize <DIR>        Summarize a bundle"
            exit 1
            ;;
    esac
}

# --- snapshot ---
cmd_snapshot() {
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
                echo "Usage: provenable.sh snapshot rollback <SNAPSHOT_ID>"
                echo ""
                echo "Available snapshots:"
                proven-aer snapshot list
                exit 1
            fi
            exec proven-aer rollback "$1"
            ;;
        *)
            echo "Usage: provenable.sh snapshot <create|list|rollback> [args...]"
            echo ""
            echo "  create [name] [scope]    Create a snapshot (scope: full|control-plane|memory)"
            echo "  list                     List all snapshots"
            echo "  rollback <ID>            Rollback to a snapshot"
            exit 1
            ;;
    esac
}

# --- status ---
cmd_status() {
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
}

# --- main dispatch ---
if [ $# -lt 1 ]; then
    usage
fi

SUBCOMMAND="$1"
shift

case "$SUBCOMMAND" in
    alerts)   cmd_alerts "$@" ;;
    export)   cmd_export "$@" ;;
    snapshot) cmd_snapshot "$@" ;;
    status)   cmd_status "$@" ;;
    help|-h|--help) usage ;;
    *)
        echo "Unknown subcommand: $SUBCOMMAND"
        echo ""
        usage
        ;;
esac
