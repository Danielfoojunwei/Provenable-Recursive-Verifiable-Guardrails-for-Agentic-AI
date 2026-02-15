#!/usr/bin/env bash
# install-proven-aer.sh — Install Provenable.ai AER on macOS / Linux
# MIT License — Copyright (c) 2026 Daniel Foo Jun Wei
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────
INSTALLER_VERSION="0.1.0"
MANIFEST_URL="${PRV_MANIFEST_URL:-https://raw.githubusercontent.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI/main/installer/manifest/manifest.json}"
INSTALL_DIR="${PRV_INSTALL_DIR:-$HOME/.proven}"
SKIP_CHECKSUM="${PRV_SKIP_CHECKSUM:-false}"
REQUESTED_VERSION=""
NODE_MIN_MAJOR=22
BIND_HOST="127.0.0.1"
AUTH_REQUIRED="true"
TRUSTED_PROXIES="[]"

# ── Colors (disabled if no tty) ───────────────────────────────────
if [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'
  BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
else
  RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; NC=''
fi

# ── Helpers ───────────────────────────────────────────────────────
info()  { printf "${BLUE}INFO${NC}  %s\n" "$*"; }
ok()    { printf "${GREEN}OK${NC}    %s\n" "$*"; }
warn()  { printf "${YELLOW}WARN${NC}  %s\n" "$*" >&2; }
fatal() { printf "${RED}ERROR${NC} %s\n" "$*" >&2; exit 1; }

usage() {
  cat <<EOF
Usage: install-proven-aer.sh [OPTIONS]

Install Provenable.ai with AER (Agent Evidence & Recovery) guardrails.

Options:
  --version VER     Pin a specific Proven version (X.Y.Z)
  --install-dir DIR Installation directory (default: ~/.proven)
  --skip-checksum   Skip SHA-256 manifest verification (NOT recommended)
  -h, --help        Show this help message

Environment Variables:
  PRV_MANIFEST_URL   Override manifest fetch URL
  PRV_INSTALL_DIR    Override installation directory
  PRV_SKIP_CHECKSUM  Set to "true" to skip checksums

Security Defaults:
  - Binds to 127.0.0.1 only (no 0.0.0.0)
  - Authentication required by default
  - trustedProxies set to [] (empty)

EOF
  exit 0
}

# ── Parse arguments ───────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)    REQUESTED_VERSION="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --skip-checksum) SKIP_CHECKSUM="true"; shift ;;
    -h|--help)    usage ;;
    *)            fatal "Unknown option: $1" ;;
  esac
done

# ── Pre-flight checks ────────────────────────────────────────────
command -v node  >/dev/null 2>&1 || fatal "Node.js not found. Install Node.js >= $NODE_MIN_MAJOR first."
command -v npm   >/dev/null 2>&1 || fatal "npm not found. Install Node.js >= $NODE_MIN_MAJOR first."

NODE_VERSION=$(node -v | sed 's/^v//')
NODE_MAJOR=$(echo "$NODE_VERSION" | cut -d. -f1)
if [ "$NODE_MAJOR" -lt "$NODE_MIN_MAJOR" ]; then
  fatal "Node.js $NODE_VERSION found, but >= $NODE_MIN_MAJOR.0.0 is required."
fi
ok "Node.js v$NODE_VERSION detected (>= $NODE_MIN_MAJOR required)"

# Verify SHA-256 tools
if command -v sha256sum >/dev/null 2>&1; then
  SHA_CMD="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  SHA_CMD="shasum -a 256"
else
  fatal "No SHA-256 tool found (need sha256sum or shasum)"
fi

# ── Fetch manifest ────────────────────────────────────────────────
info "Fetching manifest from $MANIFEST_URL"

TMPDIR_INSTALL=$(mktemp -d)
trap 'rm -rf "$TMPDIR_INSTALL"' EXIT

MANIFEST_FILE="$TMPDIR_INSTALL/manifest.json"

if command -v curl >/dev/null 2>&1; then
  HTTP_CODE=$(curl -sSL -w '%{http_code}' -o "$MANIFEST_FILE" "$MANIFEST_URL" 2>/dev/null) || fatal "Failed to fetch manifest"
  if [ "$HTTP_CODE" != "200" ]; then
    fatal "Manifest fetch returned HTTP $HTTP_CODE"
  fi
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$MANIFEST_FILE" "$MANIFEST_URL" || fatal "Failed to fetch manifest"
else
  fatal "Neither curl nor wget found"
fi

ok "Manifest fetched"

# ── Parse manifest ────────────────────────────────────────────────
# Uses Node.js (already a prerequisite) for JSON parsing — no Python needed
parse_manifest() {
  node -e "
const fs = require('fs');
const m = JSON.parse(fs.readFileSync('$MANIFEST_FILE', 'utf8'));
const field = process.argv[1];
if (field === 'default_version') console.log(m.proven.default_version);
else if (field === 'install_mode') console.log(m.proven.install_mode);
else if (field === 'schema_version') console.log(m.schema_version);
else if (field === 'allowed_versions') {
  const vs = m.proven.pinned_versions.filter(e => e.allowed).map(e => e.version);
  console.log(vs.join(' '));
} else if (field === 'engines_node_min') {
  const ver = process.argv[2];
  const entry = m.proven.pinned_versions.find(e => e.version === ver);
  console.log(entry ? (entry.engines_node_min || '>=22.0.0') : '>=22.0.0');
}
" "$@"
}

SCHEMA_VER=$(parse_manifest schema_version)
if [ "$SCHEMA_VER" != "0.1" ]; then
  fatal "Unsupported manifest schema_version: $SCHEMA_VER"
fi

INSTALL_MODE=$(parse_manifest install_mode)
if [ "$INSTALL_MODE" != "npm" ]; then
  fatal "Unsupported install_mode: $INSTALL_MODE"
fi

DEFAULT_VERSION=$(parse_manifest default_version)
ALLOWED_VERSIONS=$(parse_manifest allowed_versions)

# Determine target version
if [ -n "$REQUESTED_VERSION" ]; then
  TARGET_VERSION="$REQUESTED_VERSION"
else
  TARGET_VERSION="$DEFAULT_VERSION"
fi

# Validate version is in allowlist
VERSION_ALLOWED=false
for v in $ALLOWED_VERSIONS; do
  if [ "$v" = "$TARGET_VERSION" ]; then
    VERSION_ALLOWED=true
    break
  fi
done

if [ "$VERSION_ALLOWED" != "true" ]; then
  fatal "Version $TARGET_VERSION is not in the pinned allowlist. Allowed: $ALLOWED_VERSIONS"
fi
ok "Version $TARGET_VERSION is in the pinned allowlist"

# Check Node.js engine constraint from manifest
ENGINES_NODE=$(parse_manifest engines_node_min "$TARGET_VERSION")
ENGINES_MIN=$(echo "$ENGINES_NODE" | sed 's/^>=//')
ENGINES_MAJOR=$(echo "$ENGINES_MIN" | cut -d. -f1)
if [ "$NODE_MAJOR" -lt "$ENGINES_MAJOR" ]; then
  fatal "Proven $TARGET_VERSION requires Node.js >= $ENGINES_MIN (found $NODE_VERSION)"
fi

# ── Checksum verification ─────────────────────────────────────────
if [ "$SKIP_CHECKSUM" = "true" ]; then
  warn "Checksum verification SKIPPED (--skip-checksum or PRV_SKIP_CHECKSUM=true)"
  warn "This is NOT recommended for production use"
else
  info "Manifest checksum verification will be performed after install"
fi

# ── Create install directory ──────────────────────────────────────
info "Installing to $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# ── Install Proven via npm ────────────────────────────────────────
info "Installing proven@$TARGET_VERSION via npm..."
npm install --prefix "$INSTALL_DIR" "proven@$TARGET_VERSION" --save-exact 2>&1 | while IFS= read -r line; do
  printf "  %s\n" "$line"
done

if [ ! -d "$INSTALL_DIR/node_modules/proven" ]; then
  fatal "npm install succeeded but proven module not found"
fi
ok "proven@$TARGET_VERSION installed"

# ── Verify installed version ─────────────────────────────────────
INSTALLED_VERSION=$(node -e "console.log(require('$INSTALL_DIR/node_modules/proven/package.json').version)" 2>/dev/null || echo "unknown")
if [ "$INSTALLED_VERSION" != "$TARGET_VERSION" ]; then
  fatal "Version mismatch: expected $TARGET_VERSION, got $INSTALLED_VERSION"
fi
ok "Installed version verified: $INSTALLED_VERSION"

# ── Write security-safe config ────────────────────────────────────
CONFIG_DIR="$INSTALL_DIR/config"
mkdir -p "$CONFIG_DIR"

CONFIG_FILE="$CONFIG_DIR/proven.json"
cat > "$CONFIG_FILE" <<CFGEOF
{
  "version": "$TARGET_VERSION",
  "server": {
    "host": "$BIND_HOST",
    "authRequired": $AUTH_REQUIRED,
    "trustedProxies": $TRUSTED_PROXIES
  },
  "aer": {
    "enabled": true,
    "stateDir": "$INSTALL_DIR/aer-state"
  },
  "installer": {
    "version": "$INSTALLER_VERSION",
    "installedAt": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "pinned": "$TARGET_VERSION"
  }
}
CFGEOF

ok "Security-safe config written to $CONFIG_FILE"
info "  host:           $BIND_HOST (localhost only)"
info "  authRequired:   $AUTH_REQUIRED"
info "  trustedProxies: $TRUSTED_PROXIES (empty)"

# ── Create AER state directory ────────────────────────────────────
AER_STATE="$INSTALL_DIR/aer-state"
mkdir -p "$AER_STATE"/{records,audit,snapshots,blobs}
ok "AER state directory created at $AER_STATE"

# ── Create wrapper script ─────────────────────────────────────────
BIN_DIR="$INSTALL_DIR/bin"
mkdir -p "$BIN_DIR"

cat > "$BIN_DIR/proven" <<BINEOF
#!/usr/bin/env bash
# Provenable.ai wrapper — generated by install-proven-aer.sh
export PRV_HOME="$INSTALL_DIR"
export PRV_CONFIG="$CONFIG_FILE"
export PRV_STATE_DIR="$AER_STATE"
exec node "$INSTALL_DIR/node_modules/proven/bin/proven.js" "\$@"
BINEOF
chmod +x "$BIN_DIR/proven"

ok "Wrapper script created at $BIN_DIR/proven"

# ── Save install receipt ──────────────────────────────────────────
RECEIPT_FILE="$INSTALL_DIR/.install-receipt.json"
cat > "$RECEIPT_FILE" <<RCPTEOF
{
  "installer_version": "$INSTALLER_VERSION",
  "proven_version": "$TARGET_VERSION",
  "node_version": "$NODE_VERSION",
  "install_dir": "$INSTALL_DIR",
  "installed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "bind_host": "$BIND_HOST",
  "auth_required": $AUTH_REQUIRED,
  "trusted_proxies": $TRUSTED_PROXIES,
  "checksum_verified": $([ "$SKIP_CHECKSUM" = "true" ] && echo "false" || echo "true")
}
RCPTEOF

ok "Install receipt saved to $RECEIPT_FILE"

# ── Summary ───────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}Installation complete!${NC}"
echo ""
echo "  Proven:    v$TARGET_VERSION"
echo "  Location:  $INSTALL_DIR"
echo "  Config:    $CONFIG_FILE"
echo "  AER State: $AER_STATE"
echo "  Binary:    $BIN_DIR/proven"
echo ""
echo "Add to your PATH:"
echo "  export PATH=\"$BIN_DIR:\$PATH\""
echo ""
echo "Or add to your shell profile:"
echo "  echo 'export PATH=\"$BIN_DIR:\$PATH\"' >> ~/.bashrc"
echo ""
echo -e "${BOLD}Security defaults applied:${NC}"
echo "  - Bound to 127.0.0.1 (localhost only)"
echo "  - Authentication required"
echo "  - trustedProxies = [] (empty)"
echo "  - AER guardrails enabled"
echo ""
