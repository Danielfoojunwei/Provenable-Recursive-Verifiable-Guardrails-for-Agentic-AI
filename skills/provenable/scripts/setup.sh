#!/usr/bin/env bash
# Provenable.ai — One-command setup for OpenClaw skill
# Builds both CLIs and symlinks them into the skill's bins/ directory.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_DIR="$(dirname "$SCRIPT_DIR")"
BINS_DIR="$SKILL_DIR/bins"

# Locate the repository root (two levels up from skills/provenable/scripts/)
REPO_ROOT="$(cd "$SKILL_DIR/../.." && pwd)"

echo "=== Provenable.ai Setup ==="
echo ""
echo "  Skill dir:  $SKILL_DIR"
echo "  Repo root:  $REPO_ROOT"
echo ""

# ── Step 1: Check prerequisites ──────────────────────────────────────────

if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: Rust toolchain (cargo) is required but not found."
    echo "Install from: https://rustup.rs"
    exit 1
fi

echo "[1/5] Prerequisites OK (cargo found)"

# ── Step 2: Build aegx CLI ───────────────────────────────────────────────

echo "[2/5] Building aegx CLI..."
cargo build --release --locked --manifest-path "$REPO_ROOT/Cargo.toml" 2>&1 | tail -3

AEGX_BIN="$REPO_ROOT/target/release/aegx"
if [ ! -f "$AEGX_BIN" ]; then
    echo "ERROR: aegx binary not found at $AEGX_BIN"
    exit 1
fi

echo "  Built: $AEGX_BIN"

# ── Step 3: Build proven-aer CLI ─────────────────────────────────────────

echo "[3/5] Building proven-aer CLI..."
cargo build --release --locked --manifest-path "$REPO_ROOT/packages/aer/Cargo.toml" 2>&1 | tail -3

AER_BIN="$REPO_ROOT/packages/aer/target/release/proven-aer"
if [ ! -f "$AER_BIN" ]; then
    # Some Cargo workspace configs place output in the root target
    AER_BIN="$REPO_ROOT/target/release/proven-aer"
fi

if [ ! -f "$AER_BIN" ]; then
    echo "ERROR: proven-aer binary not found"
    exit 1
fi

echo "  Built: $AER_BIN"

# ── Step 4: Symlink into bins/ ───────────────────────────────────────────

echo "[4/5] Creating symlinks in $BINS_DIR..."
mkdir -p "$BINS_DIR"

ln -sf "$AEGX_BIN" "$BINS_DIR/aegx"
ln -sf "$AER_BIN" "$BINS_DIR/proven-aer"

echo "  aegx      -> $AEGX_BIN"
echo "  proven-aer -> $AER_BIN"

# ── Step 5: Initialize AER ──────────────────────────────────────────────

echo "[5/5] Initializing AER..."

# Add bins to PATH for this script
export PATH="$BINS_DIR:$PATH"

if proven-aer status >/dev/null 2>&1; then
    echo "  AER already initialized."
else
    proven-aer init
    echo "  AER initialized."
fi

# ── Done ─────────────────────────────────────────────────────────────────

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Both CLIs are now in: $BINS_DIR"
echo "OpenClaw will automatically add bins/ to PATH when this skill is active."
echo ""
echo "Quick test:"
echo "  aegx --help"
echo "  proven-aer status"
echo "  proven-aer prove"
echo ""
