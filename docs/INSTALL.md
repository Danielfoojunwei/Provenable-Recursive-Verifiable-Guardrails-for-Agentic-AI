# AEGX v0.1 Installation Guide

This guide covers every step needed to install the AEGX evidence bundle tool on your machine. It assumes no prior Rust experience.

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Clone the Repository](#2-clone-the-repository)
3. [Build from Source](#3-build-from-source)
4. [Verify the Installation](#4-verify-the-installation)
5. [Optional: Install Globally](#5-optional-install-globally)
6. [Platform-Specific Notes](#6-platform-specific-notes)
7. [Automated / Agent Installation](#7-automated--agent-installation)
8. [Uninstall](#8-uninstall)

---

## 1. Prerequisites

You need two things installed:

### Rust toolchain (rustup)

**Linux / macOS:**

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

**Windows (PowerShell):**

```powershell
winget install Rustlang.Rustup
# OR download from https://rustup.rs and run the installer
```

After installing, verify:

```bash
rustc --version
# Expected: rustc 1.XX.0 or later

cargo --version
# Expected: cargo 1.XX.0 or later
```

### Git

Install Git from your package manager or https://git-scm.com/downloads.

```bash
git --version
# Expected: git version 2.X.X or later
```

---

## 2. Clone the Repository

```bash
git clone https://github.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI.git
cd Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI
```

---

## 3. Build from Source

Build the `aegx` binary:

```bash
cargo build --release --locked
```

What this does:
- Downloads all dependencies from crates.io (first time only)
- Compiles the library and CLI
- Places the binary at `target/release/aegx`

The `--locked` flag ensures reproducible builds using the committed `Cargo.lock`.

Expected output (last lines):

```
   Compiling aegx v0.1.0 (...)
    Finished `release` profile [optimized] target(s) in XXs
```

---

## 4. Verify the Installation

Run the built-in test suite:

```bash
cargo test --locked
```

Expected: all tests pass (23 tests across 9 test binaries).

Then try the CLI:

```bash
./target/release/aegx --help
```

Expected output:

```
AEGX v0.1 evidence bundle tool

Usage: aegx <COMMAND>

Commands:
  init        Initialize a new AEGX bundle
  add-blob    Add a blob file to the bundle
  add-record  Add a typed record to the bundle
  export      Export bundle directory to zip
  import      Import zip to bundle directory
  verify      Verify bundle integrity
  summarize   Summarize bundle contents
  help        Print this message or the help of the given subcommand(s)
```

Run verification against the included test vectors:

```bash
./target/release/aegx verify tests/test_vectors/v0.1_minimal_bundle
# Expected: Verification: PASS
```

---

## 5. Optional: Install Globally

To make `aegx` available anywhere on your system:

```bash
cargo install --path . --locked
```

This copies the binary to `~/.cargo/bin/aegx`. Verify:

```bash
aegx --help
```

---

## 6. Platform-Specific Notes

### Linux

No special steps. All dependencies are downloaded from crates.io. Build tools (`gcc`, `make`) may be needed on minimal installs:

```bash
# Debian/Ubuntu
sudo apt-get install build-essential

# Fedora/RHEL
sudo dnf install gcc make
```

### macOS

Xcode Command Line Tools are required:

```bash
xcode-select --install
```

### Windows

The MSVC build tools are needed. Install via:
- Visual Studio Build Tools (select "C++ build tools" workload), OR
- `winget install Microsoft.VisualStudio.2022.BuildTools`

Use PowerShell or CMD. All commands in this guide work the same way, except use `.\target\release\aegx.exe` instead of `./target/release/aegx`.

---

## 7. Automated / Agent Installation

If you are an AI agent or writing a script that needs to install and use AEGX, here is the minimal sequence:

```bash
#!/bin/bash
set -euo pipefail

# Step 1: Ensure Rust is available
if ! command -v cargo &> /dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
  source "$HOME/.cargo/env"
fi

# Step 2: Clone
git clone https://github.com/Danielfoojunwei/Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI.git
cd Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI

# Step 3: Build
cargo build --release --locked

# Step 4: Verify
cargo test --locked

# Step 5: Make available
export PATH="$PWD/target/release:$PATH"

# Step 6: Confirm
aegx --help
aegx verify tests/test_vectors/v0.1_minimal_bundle
```

### Exit codes to check

| Code | Meaning |
|------|---------|
| 0 | Success / verification passed |
| 2 | Verification failure (tamper detected) |
| 3 | Schema validation failure |
| 4 | I/O error (file not found, permission denied) |

### Environment requirements

- Disk: ~500 MB for build artifacts
- Network: needed once for initial `cargo build` (downloads crates)
- RAM: ~1 GB during compilation
- No runtime network access needed (all operations are local)

---

## 8. Uninstall

Remove the binary:

```bash
cargo uninstall aegx
# OR just delete the repository directory
rm -rf Provenable-Recursive-Verifiable-Guardrails-for-Agentic-AI
```

---

## Next Steps

- [Quickstart Tutorial](QUICKSTART.md) - create your first bundle in 5 minutes
- [CLI Reference](CLI_REFERENCE.md) - full command documentation
- [Agent Integration Guide](AGENT_INTEGRATION.md) - integrate AEGX into your agent pipeline
