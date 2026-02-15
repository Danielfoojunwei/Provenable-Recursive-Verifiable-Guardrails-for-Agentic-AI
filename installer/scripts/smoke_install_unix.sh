#!/usr/bin/env bash
# smoke_install_unix.sh — Smoke test for install-openclaw-aer.sh
# Verifies the installer runs, creates expected structure, and applies security defaults.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$REPO_ROOT/install/install-openclaw-aer.sh"

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

INSTALL_DIR="$TMPDIR_TEST/openclaw-test"

echo "=== Smoke Test: install-openclaw-aer.sh ==="
echo "Install dir: $INSTALL_DIR"
echo ""

# ── Test 1: Installer exists and is executable ────────────────────
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

# ── Test 4: Manifest validation ───────────────────────────────────
echo ""
echo "--- Manifest validation ---"
MANIFEST="$REPO_ROOT/manifest/manifest.json"
assert_file "$MANIFEST" "manifest.json exists"

# Validate manifest with Python script
VALIDATE_SCRIPT="$REPO_ROOT/scripts/validate_manifest.py"
if python3 "$VALIDATE_SCRIPT" 2>/dev/null; then
  pass "validate_manifest.py passes"
else
  fail "validate_manifest.py failed"
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

# ── Test 7: Python tooling ────────────────────────────────────────
echo ""
echo "--- Python tooling ---"
assert_file "$REPO_ROOT/scripts/validate_manifest.py" "validate_manifest.py exists"
assert_file "$REPO_ROOT/scripts/gen_checksums.py" "gen_checksums.py exists"
assert_file "$REPO_ROOT/scripts/pin_openclaw.py" "pin_openclaw.py exists"

# Check Python scripts are valid syntax
for script in validate_manifest.py gen_checksums.py pin_openclaw.py; do
  if python3 -c "import py_compile; py_compile.compile('$REPO_ROOT/scripts/$script', doraise=True)" 2>/dev/null; then
    pass "$script has valid Python syntax"
  else
    fail "$script has syntax errors"
  fi
done

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
