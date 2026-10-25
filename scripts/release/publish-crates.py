#!/usr/bin/env python3
"""Package real workspace crates, or publish only versions crates.io lacks.

Dry-run is the default. Credentials are provided to Cargo through its normal
environment/credential provider; this script never reads or prints them.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

CORE = "sourceorrery-core"
# Explicit allowlist for the optional first-publication bootstrap path.
# Current packages, including these two, have trusted publishers configured;
# ordinary 0.3.0 releases leave bootstrap_providers off and use OIDC for all.
# Review this inventory before using the exceptional bootstrap option.
PROVIDERS = ("sourceorrery-provider-azure", "sourceorrery-os")
GROUPS = {"core": (CORE,), "providers": PROVIDERS, "bootstrap": (CORE, *PROVIDERS)}
SEMVER = re.compile(r"\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?")
USER_AGENT = "sourceorrery-release (https://github.com/Netizine/sourceorrery)"


def selected_packages(metadata: dict, version: str, group: str) -> list[str]:
    members = set(metadata["workspace_members"])
    packages = {
        p["name"]: p
        for p in metadata["packages"]
        if p["id"] in members and p.get("publish") != []
    }
    names = sorted(packages) if group == "workspace" else list(GROUPS[group])
    if not names:
        raise ValueError("the workspace contains no publishable crates")
    for name in names:
        if name not in packages:
            raise ValueError(f"{name} is not a publishable workspace member")
        package = packages[name]
        if package["version"] != version:
            raise ValueError(f"{name} is {package['version']}, expected {version}; stamp first")
        if package.get("publish") is not None and "crates-io" not in package["publish"]:
            raise ValueError(f"{name} does not permit publication to crates.io")
    return names


def version_exists(name: str, version: str) -> bool:
    """Only a real 404 means missing. Fail closed on API/network failures."""
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{name}/{version}",
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            record = json.load(response)["version"]
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return False
        raise RuntimeError(f"crates.io lookup failed for {name} {version}: HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError) as error:
        raise RuntimeError(f"crates.io lookup failed for {name} {version}: {error}") from error
    if record.get("num") != version or record.get("crate") != name:
        raise RuntimeError(f"crates.io returned an unexpected version record for {name} {version}")
    if record.get("yanked"):
        raise RuntimeError(f"{name} {version} is yanked; choose a new version, never republish it")
    return True


def cargo_publish_command(names: list[str], publish: bool) -> list[str]:
    command = ["cargo", "publish", "--registry", "crates-io", "--locked", "--allow-dirty"]
    for name in names:
        command.extend(("--package", name))
    if not publish:
        command.append("--dry-run")
    return command


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", help="the already-stamped release version")
    parser.add_argument("--group", choices=("workspace", *GROUPS), default="workspace")
    parser.add_argument("--publish", action="store_true", help="upload missing versions (default: dry run)")
    parser.add_argument("--workspace-root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    if not SEMVER.fullmatch(args.version):
        parser.error("version must be semver without a v prefix")
    root = args.workspace_root.resolve()
    try:
        metadata = json.loads(subprocess.check_output(
            ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"],
            cwd=root, text=True,
        ))
        names = selected_packages(metadata, args.version, args.group)
        if args.publish:
            missing = []
            # Inspect every selected version before uploading any of them.
            for name in names:
                if version_exists(name, args.version):
                    print(f"{name} {args.version} is already on crates.io; skipped", flush=True)
                else:
                    missing.append(name)
            names = missing
        if not names:
            print("All selected crate versions are already published.")
            return 0
        command = cargo_publish_command(names, args.publish)
        print("Running: " + " ".join(command), flush=True)
        # Cargo orders all selected packages by their publish dependencies and
        # provides its workspace overlay while verifying unpublished siblings.
        return subprocess.call(command, cwd=root)
    except (ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"publish-crates: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
