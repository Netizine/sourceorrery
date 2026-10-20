#!/usr/bin/env python3
"""Stamp one version into every package manifest in the repository.

    python scripts/release/set-version.py 0.2.0          # write
    python scripts/release/set-version.py 0.2.0 --check  # verify only

The release workflow runs this before building, so the version typed into
the workflow_dispatch form is the single source of truth. Touches:

  Cargo.toml                      [workspace.package] version and the
                                  internal workspace.dependencies versions
  Cargo.lock                      the workspace crates' entries (so that
                                  `--locked` still passes)
  bindings/python/Cargo.toml,     the extension crate and its dependency on
  bindings/python/Cargo.lock      the client crate
  bindings/python/python/sourceorrery/__init__.py   __version__
  bindings/node/Cargo.toml, Cargo.lock, package.json, package-lock.json
  bindings/java/pom.xml           the project version
  bindings/dotnet/Directory.Build.props             <Version>

Go and PHP take their versions from git tags (bindings/go/v<version> and
v<version>), so nothing is stamped for them.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_CRATES = [
    "sourceorrery",
    "sourceorrery-core",
    "sourceorrery-crypto",
    "sourceorrery-storage",
    "sourceorrery-cli",
    "sourceorrery-ffi",
    "sourceorrery-conformance",
    "sourceorrery-python",
    "sourceorrery-node",
]
SEMVER = re.compile(r"^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$")


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] in {"-h", "--help"}:
        print(__doc__)
        return 2
    version = argv[1]
    check = "--check" in argv[2:]
    if not SEMVER.match(version):
        print(f"set-version: '{version}' is not a semantic version (expected e.g. 0.2.0)", file=sys.stderr)
        return 2

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
        for crate in ("sourceorrery-core", "sourceorrery-crypto", "sourceorrery-storage", "sourceorrery"):
            text = sub_once(
                rf'^({re.escape(crate)} = \{{ path = "crates/{re.escape(crate)}", version = )"[^"]+"',
                rf'\1"{version}"',
                text,
                ROOT / "Cargo.toml",
            )
        return text

    edit(ROOT / "Cargo.toml", cargo_toml)

    # Cargo.lock files: our crates' entries only.
    def cargo_lock(path: Path):
        def transform(text: str) -> str:
            for crate in WORKSPACE_CRATES:
                text = re.sub(
                    rf'(\[\[package\]\]\nname = "{re.escape(crate)}"\nversion = )"[^"]+"',
                    rf'\1"{version}"',
                    text,
                )
            return text

        return transform

    for lock in ("Cargo.lock", "bindings/python/Cargo.lock", "bindings/node/Cargo.lock"):
        edit(ROOT / lock, cargo_lock(ROOT / lock))

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

    for crate in ("bindings/python/Cargo.toml", "bindings/node/Cargo.toml"):
        edit(ROOT / crate, extension_cargo(ROOT / crate))

    edit(
        ROOT / "bindings/python/python/sourceorrery/__init__.py",
        lambda text: sub_once(r'^(__version__ = )"[^"]+"', rf'\1"{version}"', text, ROOT / "bindings/python/python/sourceorrery/__init__.py"),
    )

    # Node package manifests.
    def package_json(text: str) -> str:
        data = json.loads(text)
        data["version"] = version
        for name in data.get("optionalDependencies", {}):
            if name.startswith("@sourceorrery/sdk-"):
                data["optionalDependencies"][name] = version
        return json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    edit(ROOT / "bindings/node/package.json", package_json)

    def package_lock(text: str) -> str:
        data = json.loads(text)
        data["version"] = version
        root = data.get("packages", {}).get("")
        if root is not None:
            root["version"] = version
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
