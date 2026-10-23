#!/usr/bin/env python3
"""Describe each npm platform package: what it is for and what to install.

    python scripts/release/npm-platform-packages.py

`napi create-npm-dirs` writes every bindings/node/npm/<platform>/ manifest
with the main package's description and a one-line README. On npm those
pages are what a person lands on when a platform package turns up in a
lock file or an audit, so this replaces both with text that says which
platform the addon is for, that @sourceorreryai/sdk installs it, and that
vaults are managed with the sourceorrery CLI. The release workflow runs it
right after `napi create-npm-dirs`; run it after regenerating the
directories by hand too.

Every manifest is checked against the directory it sits in before anything
is written: the package must be named after the directory, ship the addon
file napi names after it, and run on one os and cpu this script knows. One
manifest that says otherwise stops the run with nothing rewritten.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import NoReturn

ROOT = Path(__file__).resolve().parents[2]
NPM_DIR = ROOT / "bindings" / "node" / "npm"
MAIN = "@sourceorreryai/sdk"
# `napi.binaryName` in bindings/node/package.json: a platform package ships
# <binaryName>.<platform>.node and nothing else.
ADDON = "sourceorrery"

# (os, cpu) as npm writes them -> the platform a person would name.
PLATFORMS = {
    ("win32", "x64"): "Windows x64",
    ("win32", "arm64"): "Windows on Arm (arm64)",
    ("darwin", "x64"): "macOS on Intel (x64)",
    ("darwin", "arm64"): "macOS on Apple silicon (arm64)",
    ("linux", "x64"): "Linux x64",
    ("linux", "arm64"): "Linux arm64",
}


def fail(message: str) -> NoReturn:
    sys.exit(f"npm-platform-packages: {message}")


def load_manifest(path: Path) -> dict:
    """The manifest at `path`, refused unless it describes the package its directory is for."""
    platform = path.parent.name
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:
        fail(f"{path}: {err}")
    if not isinstance(manifest, dict):
        fail(f"{path}: not a JSON object")
    expected = {"name": f"{MAIN}-{platform}", "main": f"{ADDON}.{platform}.node"}
    for field, value in expected.items():
        if manifest.get(field) != value:
            fail(f"{path}: {field} is {manifest.get(field)!r}, expected {value!r}")
    for field in ("os", "cpu"):
        values = manifest.get(field)
        if not (isinstance(values, list) and len(values) == 1 and isinstance(values[0], str)):
            fail(f"{path}: {field} must name exactly one value")
    libc = manifest.get("libc", [])
    if not (isinstance(libc, list) and all(isinstance(value, str) for value in libc)):
        fail(f"{path}: libc must be a list of strings")
    return manifest


def platform_label(manifest: dict) -> str:
    key = (manifest["os"][0], manifest["cpu"][0])
    if key not in PLATFORMS:
        fail(f"no label for {manifest['name']} ({key[0]}, {key[1]})")
    label = PLATFORMS[key]
    if "glibc" in manifest.get("libc", []):
        label += " (glibc)"
    elif "musl" in manifest.get("libc", []):
        label += " (musl)"
    return label


def readme(manifest: dict, label: str, table: str) -> str:
    name = manifest["name"]
    addon = manifest["main"]
    return f"""# {name}

The {label} native addon of [`{MAIN}`](https://www.npmjs.com/package/{MAIN}),
the read-only JavaScript and TypeScript SDK for
[SourceOrrery](https://sourceorrery.ai) vaults. Secrets belong to the
runtime, not the repository.

**Do not install this package directly.** Install the SDK:

```bash
npm install {MAIN}
```

`{MAIN}` lists one platform package per operating system and CPU as an
optional dependency, and npm installs only the one that matches the
machine, so nothing is compiled on install. This package holds a single
file, `{addon}`, compiled from the SourceOrrery Rust core by the release
workflow and published with provenance.

| Platform package | For |
|------------------|-----|
{table}

## The CLI

The SDK only reads secrets. Vaults are created, and secrets stored, with
the `sourceorrery` command-line tool, which npm does not install: get it
from the [GitHub release](https://github.com/Netizine/sourceorrery/releases/latest)
or with `cargo install --locked sourceorrery-cli`
([Getting started](https://sourceorrery.ai/getting-started/)). It does not
have to be installed where your application runs.

Documentation: <https://sourceorrery.ai/sdks/javascript/>. Source:
<https://github.com/Netizine/sourceorrery/tree/main/bindings/node>.
Licence: MIT or Apache-2.0, at your option.
"""


def main(npm_dir: Path = NPM_DIR) -> None:
    manifests = []
    for path in sorted(npm_dir.glob("*/package.json")):
        manifest = load_manifest(path)
        manifests.append((path, manifest, platform_label(manifest)))
    if not manifests:
        fail(f"no platform packages under {npm_dir}")

    table = "\n".join(f"| `{m['name']}` | {label} |" for _, m, label in manifests)
    for path, manifest, label in manifests:
        manifest["description"] = (
            f"SourceOrrery native addon for {label}, installed automatically by {MAIN}; "
            f"install {MAIN}, not this package"
        )
        # The paths written come from the directory listing above; nothing
        # read from a manifest ever names a file.
        with path.open("w", encoding="utf-8", newline="\n") as out:
            json.dump(manifest, out, indent=2, ensure_ascii=False)
            out.write("\n")
        with (path.parent / "README.md").open("w", encoding="utf-8", newline="\n") as out:
            out.write(readme(manifest, label, table))
        print(f"npm-platform-packages: {manifest['name']} ({label})")


if __name__ == "__main__":
    main()
