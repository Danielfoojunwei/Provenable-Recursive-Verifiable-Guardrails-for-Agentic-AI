#!/usr/bin/env python3
"""Pin a new OpenClaw version in the manifest after verifying it exists on npm."""

import argparse
import json
import os
import re
import subprocess
import sys

REPO_ROOT = os.path.join(os.path.dirname(__file__), "..")
MANIFEST_PATH = os.path.join(REPO_ROOT, "manifest", "manifest.json")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")


def fatal(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def npm_view_version(version: str) -> str:
    """Verify version exists on npm and return the exact version string."""
    try:
        result = subprocess.run(
            ["npm", "view", f"openclaw@{version}", "version"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            fatal(f"npm view failed for openclaw@{version}: {result.stderr.strip()}")
        return result.stdout.strip()
    except FileNotFoundError:
        fatal("npm not found — install Node.js first")
    except subprocess.TimeoutExpired:
        fatal("npm view timed out")


def npm_view_engines(version: str) -> str:
    """Get the engines.node requirement from npm."""
    try:
        result = subprocess.run(
            ["npm", "view", f"openclaw@{version}", "engines", "--json"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            # Some packages don't declare engines — use a safe default
            return ">=22.0.0"
        engines = json.loads(result.stdout)
        return engines.get("node", ">=22.0.0")
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return ">=22.0.0"


def main() -> None:
    parser = argparse.ArgumentParser(description="Pin a new OpenClaw version")
    parser.add_argument("--version", required=True, help="OpenClaw version to pin (X.Y.Z)")
    parser.add_argument("--set-default", action="store_true", help="Also set as default version")
    parser.add_argument("--skip-npm-check", action="store_true", help="Skip npm verification (for testing)")
    args = parser.parse_args()

    if not SEMVER_RE.match(args.version):
        fatal(f"Invalid version format: {args.version}")

    # Verify on npm
    if not args.skip_npm_check:
        actual = npm_view_version(args.version)
        if actual != args.version:
            fatal(f"npm returned version '{actual}', expected '{args.version}'")
        engines_node = npm_view_engines(args.version)
    else:
        engines_node = ">=22.0.0"

    # Load manifest
    with open(MANIFEST_PATH, "r") as f:
        manifest = json.load(f)

    pinned = manifest["openclaw"]["pinned_versions"]
    existing = [e for e in pinned if e["version"] == args.version]

    if existing:
        print(f"Version {args.version} already pinned — updating.")
        existing[0]["allowed"] = True
        existing[0]["engines_node_min"] = engines_node
    else:
        pinned.append({
            "version": args.version,
            "engines_node_min": engines_node,
            "notes": f"Pinned via pin_openclaw.py",
            "allowed": True,
        })
        print(f"Added version {args.version} to pinned_versions.")

    if args.set_default:
        manifest["openclaw"]["default_version"] = args.version
        print(f"Set default_version to {args.version}.")

    # Write manifest
    with open(MANIFEST_PATH, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    # Run validate_manifest
    validate_script = os.path.join(os.path.dirname(__file__), "validate_manifest.py")
    result = subprocess.run([sys.executable, validate_script])
    if result.returncode != 0:
        fatal("Manifest validation failed after update")

    # Run gen_checksums
    checksums_script = os.path.join(os.path.dirname(__file__), "gen_checksums.py")
    result = subprocess.run([sys.executable, checksums_script])
    if result.returncode != 0:
        fatal("Checksum generation failed")

    print(f"\nDone. Version {args.version} pinned successfully.")


if __name__ == "__main__":
    main()
