#!/usr/bin/env bash
# quickstart.sh — End-to-end AEGX CLI demo
# Prerequisite: build aegx first (cargo build --workspace --release)
set -euo pipefail

AEGX="${AEGX_BIN:-./target/release/aegx}"

echo "=== AEGX Quickstart Demo ==="
echo ""

# Step 1: Initialize
echo "--- Step 1: Initialize AEGX ---"
$AEGX init
echo ""

# Step 2: Check status
echo "--- Step 2: Check system status ---"
$AEGX status
echo ""

# Step 3: Create a snapshot
echo "--- Step 3: Create a snapshot ---"
$AEGX snapshot create "quickstart-demo" --scope full
echo ""

# Step 4: List snapshots
echo "--- Step 4: List snapshots ---"
$AEGX snapshot list
echo ""

# Step 5: Query protection status (human-readable)
echo "--- Step 5: Query protection status ---"
$AEGX prove
echo ""

# Step 6: Query protection status (JSON)
echo "--- Step 6: Query protection status (JSON) ---"
$AEGX prove --json
echo ""

# Step 7: Export evidence bundle
echo "--- Step 7: Export evidence bundle ---"
BUNDLE_PATH=$($AEGX bundle export 2>&1 | grep -oP 'Bundle exported: \K.*' || echo "")
if [ -n "$BUNDLE_PATH" ] && [ -f "$BUNDLE_PATH" ]; then
    echo "Bundle exported to: $BUNDLE_PATH"

    # Step 8: Verify the bundle
    echo ""
    echo "--- Step 8: Verify the bundle ---"
    $AEGX verify "$BUNDLE_PATH"

    # Step 9: Generate report
    echo ""
    echo "--- Step 9: Generate report ---"
    $AEGX report "$BUNDLE_PATH"
else
    echo "Bundle export path not captured (this is OK for a fresh install)"
fi

echo ""
echo "=== Quickstart complete ==="
