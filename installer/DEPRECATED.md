# DEPRECATED

This `installer/` directory contains scripts from a previous architecture and
is **no longer the recommended installation method**.

The scripts in this directory install a Node.js npm package (`proven`), which
is a separate product from the Rust workspace in this repository.

## Current Installation

To install AEGX, build from source using the Rust workspace:

```bash
cargo build --workspace --release
./target/release/aegx init
```

See [docs/INSTALL.md](../docs/INSTALL.md) for complete instructions.
