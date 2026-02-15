#!/usr/bin/env python3
"""Validate manifest/manifest.json schema, checksums, and consistency."""

import json
import os
import re
import sys

MANIFEST_PATH = os.path.join(os.path.dirname(__file__), "..", "manifest", "manifest.json")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def fatal(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def validate() -> None:
    if not os.path.isfile(MANIFEST_PATH):
        fatal(f"Manifest not found: {MANIFEST_PATH}")

    with open(MANIFEST_PATH, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            fatal(f"Invalid JSON: {e}")

    # --- schema_version ---
    if data.get("schema_version") != "0.1":
        fatal(f"Unsupported schema_version: {data.get('schema_version')}")

    # --- installer section ---
    installer = data.get("installer")
    if not isinstance(installer, dict):
        fatal("Missing or invalid 'installer' section")

    version = installer.get("version", "")
    if not SEMVER_RE.match(version):
        fatal(f"Invalid installer version: {version}")

    artifacts = installer.get("artifacts")
    if not isinstance(artifacts, dict):
        fatal("Missing 'installer.artifacts'")

    for name in ("install-openclaw-aer.sh", "install-openclaw-aer.ps1"):
        entry = artifacts.get(name)
        if not isinstance(entry, dict) or "sha256" not in entry:
            fatal(f"Missing artifact entry for {name}")
        sha = entry["sha256"]
        if not SHA256_RE.match(sha):
            fatal(f"Invalid sha256 for {name}: {sha}")

    # --- openclaw section ---
    oc = data.get("openclaw")
    if not isinstance(oc, dict):
        fatal("Missing or invalid 'openclaw' section")

    if oc.get("install_mode") != "npm":
        fatal(f"Unsupported install_mode: {oc.get('install_mode')}")

    pinned = oc.get("pinned_versions")
    if not isinstance(pinned, list) or len(pinned) == 0:
        fatal("pinned_versions must be a non-empty list")

    allowed_versions = set()
    for entry in pinned:
        v = entry.get("version", "")
        if not SEMVER_RE.match(v):
            fatal(f"Invalid pinned version: {v}")
        if not isinstance(entry.get("allowed"), bool):
            fatal(f"Missing 'allowed' flag for version {v}")
        eng = entry.get("engines_node_min", "")
        if not eng.startswith(">="):
            fatal(f"Invalid engines_node_min for {v}: {eng}")
        if entry["allowed"]:
            allowed_versions.add(v)

    default = oc.get("default_version", "")
    if not SEMVER_RE.match(default):
        fatal(f"Invalid default_version: {default}")
    if default not in allowed_versions:
        fatal(f"default_version '{default}' is not in allowed pinned_versions")

    print(f"OK: Manifest valid — installer v{version}, "
          f"default OpenClaw v{default}, "
          f"{len(allowed_versions)} allowed version(s)")


if __name__ == "__main__":
    validate()
