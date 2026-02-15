#!/usr/bin/env python3
"""Compute SHA-256 checksums for installer artifacts and update manifest."""

import hashlib
import json
import os
import sys

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
MANIFEST_PATH = os.path.join(REPO_ROOT, "manifest", "manifest.json")
CHECKSUMS_PATH = os.path.join(REPO_ROOT, "checksums.txt")

ARTIFACTS = {
    "install-openclaw-aer.sh": os.path.join(REPO_ROOT, "install", "install-openclaw-aer.sh"),
    "install-openclaw-aer.ps1": os.path.join(REPO_ROOT, "install", "install-openclaw-aer.ps1"),
}


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    # Compute hashes
    hashes: dict[str, str] = {}
    for name, path in ARTIFACTS.items():
        if not os.path.isfile(path):
            print(f"ERROR: Artifact not found: {path}", file=sys.stderr)
            sys.exit(1)
        hashes[name] = sha256_file(path)
        print(f"  {hashes[name]}  {name}")

    # Also hash manifest.json itself (for checksums.txt)
    manifest_hash = sha256_file(MANIFEST_PATH)

    # Update manifest artifact hashes
    with open(MANIFEST_PATH, "r") as f:
        manifest = json.load(f)

    for name, digest in hashes.items():
        manifest["installer"]["artifacts"][name]["sha256"] = digest

    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    # Re-hash manifest after update (it now contains the correct artifact hashes)
    manifest_hash = sha256_file(MANIFEST_PATH)

    # Write checksums.txt
    lines = []
    for name, digest in sorted(hashes.items()):
        lines.append(f"{digest}  {name}")
    lines.append(f"{manifest_hash}  manifest.json")

    with open(CHECKSUMS_PATH, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"\nChecksums written to {CHECKSUMS_PATH}")
    print(f"Manifest updated at {MANIFEST_PATH}")


if __name__ == "__main__":
    main()
