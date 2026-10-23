#!/usr/bin/env python3
"""Correct Moto 5.2.4's version creation timestamps in disposable test servers.

Run with the local Moto environment's Python before starting moto_server, or
pass --container <GitHub service container ID> to patch and restart that service.
Do this before creating any fixtures: restarting a Moto server loses its state.

Moto's GetSecretValue already returns version["createdate"], but its
ListSecretVersionIds returns the current wall clock instead. This changes only
that one field; production AWS code and lifecycle assertions remain unchanged.
Remove this helper when Moto ships the correction and the pinned image advances.
Upstream: https://github.com/getmoto/moto/blob/5.2.4/moto/secretsmanager/models.py#L940-L960
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.metadata
import io
import json
import re
import subprocess
import sys
import tokenize
from pathlib import Path

MOTO_VERSION = "5.2.4"
MOTO_IMAGE = f"motoserver/moto:{MOTO_VERSION}"
# Fingerprints cover every meaningful token of the original/patched method.
# The original source fixture is in fixtures/moto_5_2_4_version_listing.py.
# Tokens avoid ast.dump differences between the host and container Python.
ORIGINAL_METHOD = "7c58591e50b29a5fe5c94fad4ea2ea3dcc016fbaae9628f744ae62a9ba4c69bf"
PATCHED_METHOD = "83558ccb186c47d36adefdb6331f01df42abec141006e86a38252c5b6a22d35f"
ORIGINAL_FIELD = '"CreatedDate": int(time.time()),'
PATCHED_FIELD = '"CreatedDate": version["createdate"],'


def method_fingerprint(source: str) -> str:
    ignored = {
        tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT,
        tokenize.DEDENT, tokenize.ENDMARKER,
    }
    tokens = [
        (tokenize.tok_name[token.type], token.string)
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type not in ignored
    ]
    return hashlib.sha256(json.dumps(tokens, separators=(",", ":")).encode()).hexdigest()


def patch_source(source: str, version: str) -> tuple[str, bool]:
    """Fail closed unless the installed method is exactly the known version."""
    if version != MOTO_VERSION:
        raise ValueError(f"expected Moto {MOTO_VERSION}, found {version}; review the workaround")
    classes = [
        node for node in ast.parse(source).body
        if isinstance(node, ast.ClassDef) and node.name == "SecretsManagerBackend"
    ]
    if len(classes) != 1:
        raise ValueError("expected one SecretsManagerBackend class; source left unchanged")
    methods = [
        node for node in classes[0].body
        if isinstance(node, ast.FunctionDef) and node.name == "list_secret_version_ids"
    ]
    if len(methods) != 1:
        raise ValueError("expected one list_secret_version_ids method; source left unchanged")
    method = methods[0]
    if method.decorator_list:
        raise ValueError("Moto listing method has unexpected decorators; source left unchanged")
    segment = ast.get_source_segment(source, method)
    if segment is None:
        raise ValueError("could not locate the listing method; source left unchanged")
    fingerprint = method_fingerprint(segment)
    if fingerprint == PATCHED_METHOD:
        return source, False
    if fingerprint != ORIGINAL_METHOD or segment.count(ORIGINAL_FIELD) != 1:
        raise ValueError("Moto listing method differs from 5.2.4; source left unchanged")
    lines = source.splitlines(keepends=True)
    start = sum(map(len, lines[:method.lineno - 1]))
    end = sum(map(len, lines[:method.end_lineno]))
    patched = source[:start] + source[start:end].replace(ORIGINAL_FIELD, PATCHED_FIELD) + source[end:]
    ast.parse(patched)
    return patched, True


def patch_installed() -> None:
    distribution = importlib.metadata.distribution("moto")
    path = Path(distribution.locate_file("moto/secretsmanager/models.py"))
    source = path.read_bytes().decode("utf-8")
    patched, changed = patch_source(source, distribution.version)
    if changed:
        path.write_bytes(patched.encode("utf-8"))
    state = "corrected" if changed else "already correct"
    print(f"Moto {MOTO_VERSION} ListSecretVersionIds creation timestamps: {state}")


def patch_container(container: str) -> None:
    if not re.fullmatch(r"[0-9a-fA-F]{12,64}", container):
        raise ValueError("--container must be a Docker container ID")
    state = subprocess.check_output(
        ["docker", "inspect", "--format", "{{.State.Running}} {{.Config.Image}}", container],
        text=True,
    ).strip()
    if state != f"true {MOTO_IMAGE}":
        raise ValueError(f"expected a running disposable {MOTO_IMAGE} service; source left unchanged")
    # Passing this self-contained script through stdin avoids shell expansion
    # and does not require a mounted checkout or modify the Docker image.
    subprocess.run(
        ["docker", "exec", "-i", container, "python", "-"],
        input=Path(__file__).read_text(encoding="utf-8"), text=True, check=True,
    )
    # Restart only after the patch succeeds, so the server imports the new code.
    subprocess.run(["docker", "restart", container], check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--container", help="patch and restart this disposable Moto service container")
    args = parser.parse_args()
    try:
        if args.container:
            patch_container(args.container)
        else:
            patch_installed()
    except (ValueError, OSError, SyntaxError, importlib.metadata.PackageNotFoundError,
            subprocess.CalledProcessError) as error:
        print(f"moto-version-timestamps: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
