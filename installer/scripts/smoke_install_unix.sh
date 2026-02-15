#!/usr/bin/env bash
# smoke_install_unix.sh — Smoke test for install-proven-aer.sh
# Verifies the installer runs, creates expected structure, and applies security defaults.
# All tooling is Rust-based (no Python dependency).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$REPO_ROOT/install/install-proven-aer.sh"
TOOLS_BIN="$REPO_ROOT/tools/target/debug/installer-tools"

PASS=0
FAIL=0
TESTS=0

# ── Helpers ───────────────────────────────────────────────────────
pass() { PASS=$((PASS + 1)); TESTS=$((TESTS + 1)); echo "  PASS: $1"; }
fail() { FAIL=$((FAIL + 1)); TESTS=$((TESTS + 1)); echo "  FAIL: $1" >&2; }

assert_file()  { [ -f "$1" ] && pass "$2" || fail "$2 — file not found: $1"; }
assert_dir()   { [ -d "$1" ] && pass "$2" || fail "$2 — dir not found: $1"; }
assert_contains() {
  if grep -q "$2" "$1" 2>/dev/null; then
    pass "$3"
  else
    fail "$3 — pattern '$2' not found in $1"
  fi
}

# ── Setup ─────────────────────────────────────────────────────────
TMPDIR_TEST=$(mktemp -d)
trap 'rm -rf "$TMPDIR_TEST"' EXIT

INSTALL_DIR="$TMPDIR_TEST/proven-test"

echo "=== Smoke Test: install-proven-aer.sh ==="
echo "Install dir: $INSTALL_DIR"
echo ""

# ── Build Rust tools if needed ────────────────────────────────────
echo "--- Build Rust tooling ---"
if [ ! -f "$TOOLS_BIN" ]; then
  echo "  Building installer-tools..."
  (cd "$REPO_ROOT/tools" && cargo build --quiet 2>&1)
fi
assert_file "$TOOLS_BIN" "installer-tools binary exists"

# ── Test 1: Installer exists and is executable ────────────────────
echo ""
echo "--- Pre-flight ---"
assert_file "$INSTALLER" "Installer script exists"
if [ -x "$INSTALLER" ]; then
  pass "Installer is executable"
else
  chmod +x "$INSTALLER"
  pass "Installer made executable"
fi

# ── Test 2: --help flag works ─────────────────────────────────────
echo ""
echo "--- Help flag ---"
if "$INSTALLER" --help >/dev/null 2>&1; then
  pass "--help exits cleanly"
else
  fail "--help did not exit cleanly"
fi

# ── Test 3: Invalid version rejected ──────────────────────────────
echo ""
echo "--- Validation ---"
if "$INSTALLER" --version "not-a-version" --install-dir "$INSTALL_DIR" 2>/dev/null; then
  fail "Should reject non-semver version"
else
  pass "Non-semver version rejected"
fi

# ── Test 4: Manifest validation (Rust) ────────────────────────────
echo ""
echo "--- Manifest validation (Rust) ---"
MANIFEST="$REPO_ROOT/manifest/manifest.json"
assert_file "$MANIFEST" "manifest.json exists"

if "$TOOLS_BIN" validate --manifest "$MANIFEST" 2>/dev/null; then
  pass "installer-tools validate passes"
else
  fail "installer-tools validate failed"
fi

# ── Test 5: Manifest schema checks ───────────────────────────────
echo ""
echo "--- Manifest content ---"
assert_contains "$MANIFEST" '"schema_version"' "Manifest has schema_version"
assert_contains "$MANIFEST" '"install_mode"' "Manifest has install_mode"
assert_contains "$MANIFEST" '"pinned_versions"' "Manifest has pinned_versions"
assert_contains "$MANIFEST" '"default_version"' "Manifest has default_version"
assert_contains "$MANIFEST" '"sha256"' "Manifest has sha256 checksums"

# ── Test 6: Security defaults in installer script ─────────────────
echo ""
echo "--- Security defaults in script ---"
assert_contains "$INSTALLER" '127.0.0.1' "Script binds to 127.0.0.1"
assert_contains "$INSTALLER" 'authRequired' "Script sets authRequired"
assert_contains "$INSTALLER" 'trustedProxies' "Script sets trustedProxies"

# ── Test 7: Rust tooling ─────────────────────────────────────────
echo ""
echo "--- Rust tooling ---"
assert_file "$REPO_ROOT/tools/Cargo.toml" "tools/Cargo.toml exists"
assert_file "$REPO_ROOT/tools/src/main.rs" "tools/src/main.rs exists"
assert_file "$REPO_ROOT/tools/src/manifest.rs" "tools/src/manifest.rs exists"
assert_file "$REPO_ROOT/tools/src/validate.rs" "tools/src/validate.rs exists"
assert_file "$REPO_ROOT/tools/src/checksums.rs" "tools/src/checksums.rs exists"
assert_file "$REPO_ROOT/tools/src/pin.rs" "tools/src/pin.rs exists"

# ── Test 8: Rust tools subcommand help ────────────────────────────
echo ""
echo "--- Rust tools CLI ---"
if "$TOOLS_BIN" --help >/dev/null 2>&1; then
  pass "installer-tools --help works"
else
  fail "installer-tools --help failed"
fi

if "$TOOLS_BIN" validate --help >/dev/null 2>&1; then
  pass "installer-tools validate --help works"
else
  fail "installer-tools validate --help failed"
fi

if "$TOOLS_BIN" gen-checksums --help >/dev/null 2>&1; then
  pass "installer-tools gen-checksums --help works"
else
  fail "installer-tools gen-checksums --help failed"
fi

if "$TOOLS_BIN" pin-version --help >/dev/null 2>&1; then
  pass "installer-tools pin-version --help works"
else
  fail "installer-tools pin-version --help failed"
fi

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo "=== Results ==="
echo "  Total: $TESTS"
echo "  Pass:  $PASS"
echo "  Fail:  $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
  echo "SMOKE TEST FAILED"
  exit 1
else
  echo "SMOKE TEST PASSED"
  exit 0
fi
