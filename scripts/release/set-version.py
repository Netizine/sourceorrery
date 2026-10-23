#!/usr/bin/env python3
"""Stamp one version into every package manifest in the repository.

    python scripts/release/set-version.py 0.2.0 --keep-node-links  # repository bump
    python scripts/release/set-version.py 0.2.0                    # release build
    python scripts/release/set-version.py 0.2.0 --check             # verify only

Requires Python 3.11 or later. The release workflow runs this before building,
so the version typed into
the workflow_dispatch form is the single source of truth. Touches:

  Cargo.toml                      [workspace.package] version and the
                                  internal workspace.dependencies versions
  Cargo.lock                      the workspace crates' entries (so that
                                  `--locked` still passes)
  bindings/python/Cargo.toml,     the extension crate and its dependency on
  bindings/python/Cargo.lock      the client crate
  bindings/python/python/sourceorrery/__init__.py   __version__
  bindings/node/Cargo.toml, Cargo.lock, package.json, package-lock.json,
  bindings/node/npm/<platform>/package.json
                                  In the repository package.json depends on
                                  the platform packages as `file:npm/<platform>`
                                  links so that `npm ci` resolves without the
                                  registry; stamping turns those into the
                                  version, which is what the published
                                  package must depend on. --keep-node-links
                                  preserves the repository links for local
                                  development; --check accepts either form.
  bindings/java/pom.xml           the project version
  bindings/dotnet/Directory.Build.props             <Version>

Go and PHP take their versions from git tags (bindings/go/v<version> and
v<version>), so nothing is stamped for them.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXTENSION_MANIFESTS = ("bindings/python/Cargo.toml", "bindings/node/Cargo.toml")
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def local_crates() -> tuple[dict, set[str], dict[str, str]]:
    """Read the workspace inventory so a new provider cannot be omitted silently."""
    workspace = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
    members = set()
    for pattern in workspace["members"]:
        manifests = sorted(ROOT.glob(f"{pattern}/Cargo.toml"))
        if not manifests:
            raise SystemExit(f"set-version: no Cargo.toml for workspace member {pattern}")
        for manifest in manifests:
            package = tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]
            if package.get("version") != {"workspace": True}:
                raise SystemExit(f"set-version: {manifest} must inherit the workspace version")
            members.add(package["name"])
    extensions = {
        path: tomllib.loads((ROOT / path).read_text(encoding="utf-8"))["package"]["name"]
        for path in EXTENSION_MANIFESTS
    }
    return workspace, members, extensions


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter, allow_abbrev=False)
    parser.add_argument("version", help="version to stamp into all release packages")
    parser.add_argument("--check", action="store_true", help="report mismatches without writing files")
    parser.add_argument("--keep-node-links", action="store_true", help="preserve Node file:npm dependencies for repository bumps")
    args = parser.parse_args(argv[1:])
    version = args.version
    check = args.check
    if not SEMVER.match(version):
        print(f"set-version: '{version}' is not a semantic version (expected e.g. 0.2.0)", file=sys.stderr)
        return 2

    workspace, workspace_crates, extensions = local_crates()
    crate_names = workspace_crates | set(extensions.values())
    changes: list[tuple[Path, str, str]] = []

    def edit(path: Path, transform) -> None:
        text = path.read_text(encoding="utf-8")
        updated = transform(text)
        if updated != text:
            changes.append((path, text, updated))

    def sub_once(pattern: str, replacement: str, text: str, path: Path, count: int = 1) -> str:
        updated, n = re.subn(pattern, replacement, text, count=count, flags=re.MULTILINE)
        if n == 0:
            raise SystemExit(f"set-version: pattern not found in {path}: {pattern}")
        return updated

    # Workspace Cargo.toml.
    def cargo_toml(text: str) -> str:
        text = sub_once(r'^(version = )"[^"]+"', rf'\1"{version}"', text, ROOT / "Cargo.toml")
        for crate, dependency in workspace.get("dependencies", {}).items():
            if not isinstance(dependency, dict) or "path" not in dependency or "version" not in dependency:
                continue
            if dependency.get("package", crate) not in workspace_crates:
                continue
            text = sub_once(
                rf'^({re.escape(crate)}\s*=\s*\{{[^\n]*?\bversion\s*=\s*)"[^"]+"',
                rf'\1"{version}"',
                text,
                ROOT / "Cargo.toml",
            )
        return text

    edit(ROOT / "Cargo.toml", cargo_toml)

    # Cargo.lock files: our crates' entries only.
    def cargo_lock(path: Path, required: set[str]):
        def transform(text: str) -> str:
            blocks = re.split(r"(?=^\[\[package\]\])", text, flags=re.MULTILINE)
            found = set()
            for index, block in enumerate(blocks):
                packages = tomllib.loads(block).get("package", [])
                if not packages:
                    continue
                package = packages[0]
                # A registry crate with the same name is not our local package.
                if package["name"] in crate_names and "source" not in package:
                    found.add(package["name"])
                    blocks[index] = sub_once(r'^(version = )"[^"]+"', rf'\1"{version}"', block, path)
            if missing := required - found:
                raise SystemExit(f"set-version: {path} is missing local crates: {', '.join(sorted(missing))}")
            return "".join(blocks)

        return transform

    edit(ROOT / "Cargo.lock", cargo_lock(ROOT / "Cargo.lock", workspace_crates))
    for manifest, name in extensions.items():
        lock = ROOT / Path(manifest).with_name("Cargo.lock")
        edit(lock, cargo_lock(lock, {name}))

    # Extension crates.
    def extension_cargo(path: Path):
        def transform(text: str) -> str:
            text = sub_once(r'^(version = )"[^"]+"', rf'\1"{version}"', text, path)
            text = sub_once(
                r'^(sourceorrery = \{ path = "\.\./\.\./crates/sourceorrery", version = )"[^"]+"',
                rf'\1"{version}"',
                text,
                path,
            )
            return text

        return transform

    for crate in EXTENSION_MANIFESTS:
        edit(ROOT / crate, extension_cargo(ROOT / crate))

    edit(
        ROOT / "bindings/python/python/sourceorrery/__init__.py",
        lambda text: sub_once(r'^(__version__ = )"[^"]+"', rf'\1"{version}"', text, ROOT / "bindings/python/python/sourceorrery/__init__.py"),
    )

    # Node package manifests. The main package's optionalDependencies are
    # `file:npm/<platform>` links in the repository and the version in a
    # release; a check accepts the links as carrying the version.
    def package_json(text: str) -> str:
        data = json.loads(text)
        data["version"] = version
        for name, spec in data.get("optionalDependencies", {}).items():
            if name.startswith("@sourceorreryai/sdk-") and not ((check or args.keep_node_links) and spec.startswith("file:")):
                data["optionalDependencies"][name] = version
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    edit(ROOT / "bindings/node/package.json", package_json)

    def platform_package_json(text: str) -> str:
        data = json.loads(text)
        data["version"] = version
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    for manifest in sorted((ROOT / "bindings/node/npm").glob("*/package.json")):
        edit(manifest, platform_package_json)

    def package_lock(text: str) -> str:
        data = json.loads(text)
        data["version"] = version
        for location, entry in data.get("packages", {}).items():
            if location == "" or location.startswith("npm/"):
                entry["version"] = version
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    edit(ROOT / "bindings/node/package-lock.json", package_lock)

    # Java and .NET.
    edit(
        ROOT / "bindings/java/pom.xml",
        lambda text: sub_once(
            r"(<artifactId>sourceorrery</artifactId>\n(?:.*\n)*?  <version>)[^<]+(</version>)",
            rf"\g<1>{version}\g<2>",
            text,
            ROOT / "bindings/java/pom.xml",
        ),
    )
    edit(
        ROOT / "bindings/dotnet/Directory.Build.props",
        lambda text: sub_once(r"(<Version>)[^<]+(</Version>)", rf"\g<1>{version}\g<2>", text, ROOT / "bindings/dotnet/Directory.Build.props"),
    )

    if check:
        if changes:
            for path, _, _ in changes:
                print(f"set-version: {path.relative_to(ROOT)} does not carry version {version}")
            return 1
        print(f"set-version: every manifest carries {version}")
        return 0

    for path, _, updated in changes:
        path.write_text(updated, encoding="utf-8", newline="\n")
        print(f"set-version: updated {path.relative_to(ROOT)}")
    if not changes:
        print(f"set-version: every manifest already carries {version}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
