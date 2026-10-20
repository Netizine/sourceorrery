"""Conformance runner for the Python SDK (tests/conformance/sdk/README.md).

    python run.py <op> [key=value ...]
"""

from __future__ import annotations

import os
import sys

from sourceorrery import Project, SecretReader, SourceOrreryError


def properties_lines(props):
    lines = [
        ("version", props.version),
        ("enabled", "true" if props.enabled else "false"),
        ("content_type", props.content_type or ""),
        ("reference", props.reference),
    ]
    lines += [(f"tag.{key}", value) for key, value in props.tags.items()]
    return lines


def secret_lines(secret):
    return [("value", secret.value.expose_text())] + properties_lines(secret.properties)


def run(op: str, kv: dict[str, str]) -> list[tuple[str, str]]:
    vault = kv.get("vault") or os.environ.get("SOURCEORRERY_TEST_VAULT", "development")
    options = dict(
        home=kv.get("home"),
        passphrase=kv.get("passphrase"),
        passphrase_file=kv.get("passphrase_file"),
        environment=kv.get("environment") != "false",
    )
    if op == "load":
        with Project.load(kv["manifest"], **options) as project:
            lines = [
                ("project.name", project.name),
                ("project.count", str(len(project))),
                ("project.names", ",".join(sorted(s.name for s in project))),
            ]
            lines += [(f"secret.{s.env}", s.value.expose_text()) for s in project]
            return lines
    with SecretReader(vault, **options) as reader:
        if op == "open":
            descriptor = reader.descriptor()
            return [("descriptor.name", descriptor["name"]), ("descriptor.protectors", ",".join(descriptor["protectors"]))]
        if op == "get":
            with reader.get(kv["name"], kv.get("version")) as secret:
                return secret_lines(secret)
        if op == "get-newest-explicit":
            newest = reader.properties(kv["name"]).version
            with reader.get(kv["name"], newest) as secret:
                return secret_lines(secret)
        if op == "properties":
            return properties_lines(reader.properties(kv["name"], kv.get("version")))
        if op == "resolve":
            with reader.resolve(kv["reference"]) as secret:
                return secret_lines(secret)
    raise SystemExit(f"unknown scenario op {op!r}")


def main(argv: list[str]) -> int:
    if not argv:
        print("usage: run.py <op> [key=value ...]", file=sys.stderr)
        return 2
    op, kv = argv[0], dict(arg.split("=", 1) for arg in argv[1:])
    try:
        lines = run(op, kv)
    except SourceOrreryError as err:
        lines = [
            ("outcome", "error"),
            ("code", err.code),
            ("message", err.message),
            ("hint", err.hint),
            ("transient", "true" if err.transient else "false"),
            ("type", type(err).__name__),
        ]
    else:
        lines.insert(0, ("outcome", "ok"))
    for key, value in lines:
        print(f"{key}\t{value}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
