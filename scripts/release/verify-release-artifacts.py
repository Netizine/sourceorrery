#!/usr/bin/env python3
"""Verify release files before a retry uploads them anywhere.

    python3 scripts/release/verify-release-artifacts.py --repo OWNER/NAME \\
        --sha COMMIT --sums SHA256SUMS [--dir DIR --pattern GLOB [--pattern GLOB]...]

`ReleasePackages.yaml` publishes files it downloads from an existing GitHub
Release, which can be changed after it was published. Before any upload,
this checks that they are the files the release run built:

1. `SHA256SUMS` itself carries a build provenance attestation signed by
   `.github/workflows/release.yml` of this repository, on a GitHub-hosted
   runner, for exactly the source commit `--sha` (the one the release gate
   validated). Only then is it trusted as the release's inventory: a
   checksum file downloaded from the same mutable release proves nothing by
   itself.
2. The files in `--dir` are exactly the inventory's files that match the
   `--pattern`s: none missing, none unexpected, none twice.
3. Each file's SHA-256 is the inventory's, and each carries its own
   attestation from the same workflow and commit.

Without `--dir`, only step 1 runs: for a job that uses the digests in
`SHA256SUMS` (the Homebrew formula, the Scoop and WinGet manifests) and not
the files.

A release built before attestations has no provenance to check: it is
refused, never waved through; publish it from a new version, or have its
files reviewed separately. Any failure of the verification service refuses.
Nothing is uploaded or attested here, so a dry run runs exactly this.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable

WORKFLOW = ".github/workflows/release.yml"

Runner = Callable[[list[str]], tuple[int, str]]


class Refused(Exception):
    """A file may not be published; the message says why."""


def run(command: list[str]) -> tuple[int, str]:
    """Run `command`: its exit status and its combined output."""
    program = shutil.which(command[0])
    if program is None:
        return 127, f"{command[0]} is not installed"
    done = subprocess.run(
        [program, *command[1:]], capture_output=True, text=True, check=False
    )
    return done.returncode, (done.stdout + done.stderr).strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_sums(text: str) -> dict[str, str]:
    """`sha256sum` output: file name to digest; a name listed twice refuses."""
    sums: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition("  ")
        name = name.lstrip("*")
        if len(digest) != 64 or not name or "/" in name:
            raise Refused(f"SHA256SUMS has a line that is not `<sha256>  <file>`: {line!r}")
        if name in sums:
            raise Refused(f"SHA256SUMS lists {name} twice")
        sums[name] = digest.lower()
    return sums


def attested(path: Path, repo: str, sha: str, runner: Runner) -> None:
    """Refuse unless `path` carries provenance from the release workflow for `sha`."""
    status, out = runner(
        [
            "gh",
            "attestation",
            "verify",
            str(path),
            "--repo",
            repo,
            "--signer-workflow",
            f"{repo}/{WORKFLOW}",
            "--source-digest",
            sha,
            "--deny-self-hosted-runners",
        ]
    )
    if status != 0:
        detail = out.splitlines()[-1] if out else f"exit status {status}"
        raise Refused(
            f"{path.name} has no build provenance from {WORKFLOW} for {sha} ({detail})"
        )


def verify(
    repo: str,
    sha: str,
    sums_path: Path,
    folder: Path | None,
    patterns: list[str],
    runner: Runner = run,
) -> list[str]:
    """What was verified; raises Refused on the first problem."""
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise Refused(f"'{sha}' is not a full commit SHA")
    if not sums_path.is_file():
        raise Refused(f"{sums_path} was not downloaded")
    try:
        attested(sums_path, repo, sha, runner)
    except Refused as refusal:
        raise Refused(
            f"{refusal}: a release without provenance (one built before attestations, or "
            "SHA256SUMS replaced) is not published from its files; cut a new version, or "
            "have these files reviewed separately"
        ) from refusal
    sums = parse_sums(sums_path.read_text(encoding="utf-8"))
    verified = [f"SHA256SUMS: provenance from {WORKFLOW} for {sha}"]
    if folder is None:
        return verified
    expected = sorted(
        name for name in sums if any(fnmatch.fnmatchcase(name, p) for p in patterns)
    )
    if not expected:
        raise Refused(f"SHA256SUMS lists no file matching {', '.join(patterns)}")
    present = sorted(
        entry.name for entry in folder.iterdir() if entry.is_file() and entry != sums_path
    ) if folder.is_dir() else []
    missing = sorted(set(expected) - set(present))
    unexpected = sorted(set(present) - set(expected))
    if missing or unexpected:
        raise Refused(
            "the downloaded files are not the release's: "
            + "; ".join(
                part
                for part in (
                    f"missing {', '.join(missing)}" if missing else "",
                    f"unexpected {', '.join(unexpected)}" if unexpected else "",
                )
                if part
            )
        )
    for name in expected:
        path = folder / name
        actual = sha256(path)
        if actual != sums[name]:
            raise Refused(f"{name} is not the file the release built: its SHA-256 is {actual}")
        attested(path, repo, sha, runner)
        verified.append(f"{name}: {actual}, provenance verified")
    return verified


def main(argv: list[str] | None = None, runner: Runner = run) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--sums", required=True, type=Path)
    parser.add_argument("--dir", type=Path)
    parser.add_argument("--pattern", action="append", default=[])
    args = parser.parse_args(argv)
    if (args.dir is None) != (not args.pattern):
        parser.error("--dir and --pattern go together")
    try:
        verified = verify(args.repo, args.sha.lower(), args.sums, args.dir, args.pattern, runner)
    except Refused as refusal:
        print(f"::error title=release artifacts::{refusal}")
        return 1
    for line in verified:
        print(f"verified: {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
