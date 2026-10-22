#!/usr/bin/env python3
"""Check the C ABI header against the one of the previous release (ADR 0007).

Parses the declarations of two ``sourceorrery.h`` files (functions,
structs, enum members and ``#define`` constants) and fails when something
that existed in the baseline changed or disappeared while
``SO_ABI_VERSION`` stayed the same. Additions are compatible. When the
version was bumped, the differences are listed and allowed.

    python3 scripts/ci/abi-check.py --baseline old.h --current new.h

``scripts/ci/abi_check_test.py`` tests the parser and the verdict.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ABI_MACRO = "SO_ABI_VERSION"


@dataclass
class Declarations:
    """Everything in a header that a caller can depend on."""

    functions: dict[str, str] = field(default_factory=dict)
    """function name -> normalised prototype"""
    structs: dict[str, str] = field(default_factory=dict)
    """struct name -> normalised body (fields in order)"""
    enums: dict[str, str] = field(default_factory=dict)
    """``enum.member`` -> value"""
    defines: dict[str, str] = field(default_factory=dict)
    """macro name -> value"""

    @property
    def abi_version(self) -> str | None:
        return self.defines.get(ABI_MACRO)


def strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", text)


def declarations_only(text: str) -> str:
    """The header without comments, preprocessor lines and the
    ``extern "C"`` block, so that only C declarations remain."""
    body = strip_comments(text)
    body = re.sub(r"^[ \t]*#.*$", " ", body, flags=re.M)
    return re.sub(r'extern\s+"C"\s*\{', " ", body)


def normalise(text: str) -> str:
    """One spelling for a declaration: single spaces, none around
    punctuation, a run of `*` glued to what follows (`uint8_t *name`,
    `so_reader **out`)."""
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\s*([(),;{}])\s*", r"\1", text)
    text = re.sub(r"\s*(\*+)\s*", r" \1", text)
    text = text.replace("( *", "(*").replace(", *", ",*")
    return re.sub(r"\s+", " ", text).strip()


def parse(text: str) -> Declarations:
    """The declarations of one header."""
    out = Declarations()
    for name, value in re.findall(r"^[ \t]*#define[ \t]+([A-Za-z_]\w*)[ \t]+(\S+)", text, re.M):
        out.defines[name] = value
    body = declarations_only(text)
    # Only one copy of a declaration counts: cbindgen emits the C and the
    # C++ spelling of an enum under #ifdef, so parse each `enum X {...}`
    # once by name.
    # cbindgen may give an enum a C++ underlying type (`enum x : int32_t {`).
    for name, members in re.findall(
        r"\benum\s+([A-Za-z_]\w*)\s*(?::\s*[A-Za-z_]\w*)?\s*\{([^}]*)\}", body
    ):
        value = -1
        for member in members.split(","):
            member = member.strip()
            if not member:
                continue
            if "=" in member:
                ident, raw = (part.strip() for part in member.split("=", 1))
                value = int(raw, 0)
            else:
                ident, value = member, value + 1
            out.enums[f"{name}.{ident}"] = str(value)
    for name, fields in re.findall(r"\bstruct\s+([A-Za-z_]\w*)\s*\{([^}]*)\}", body):
        out.structs[name] = normalise(fields)
    # A prototype is a statement with a parameter list that is not a
    # typedef, an enum or a struct body. Enum and struct bodies were read
    # above; what is left of the extern "C" block is a stray brace.
    without_bodies = re.sub(
        r"\b(enum|struct)\s+[A-Za-z_]\w*\s*(?::\s*[A-Za-z_]\w*)?\s*\{[^}]*\}", r"\1 _", body
    )
    statements = re.split(r";", without_bodies.replace("{", " ").replace("}", " "))
    for statement in statements:
        statement = normalise(statement)
        if not statement or statement.startswith("typedef") or "(" not in statement:
            continue
        match = re.search(r"\b([A-Za-z_]\w*)\s*\(", statement)
        if match:
            out.functions[match.group(1)] = statement
    return out


def compare(baseline: Declarations, current: Declarations) -> list[str]:
    """Incompatible differences: what a caller of the baseline would miss."""
    problems = []
    for kind, old, new in (
        ("function", baseline.functions, current.functions),
        ("struct", baseline.structs, current.structs),
        ("enum member", baseline.enums, current.enums),
        ("constant", baseline.defines, current.defines),
    ):
        for name, before in old.items():
            if kind == "constant" and name == ABI_MACRO:
                continue
            after = new.get(name)
            if after is None:
                problems.append(f"{kind} {name} was removed")
            elif after != before:
                problems.append(f"{kind} {name} changed:\n    was: {before}\n    now: {after}")
    return problems


def additions(baseline: Declarations, current: Declarations) -> list[str]:
    added = []
    for kind, old, new in (
        ("function", baseline.functions, current.functions),
        ("struct", baseline.structs, current.structs),
        ("enum member", baseline.enums, current.enums),
        ("constant", baseline.defines, current.defines),
    ):
        added += [f"{kind} {name}" for name in new if name not in old]
    return added


def verdict(baseline: Declarations, current: Declarations, baseline_name: str) -> tuple[bool, str]:
    """``(ok, report)`` for the two headers."""
    problems = compare(baseline, current)
    added = additions(baseline, current)
    lines = [
        f"baseline {baseline_name}: {ABI_MACRO} {baseline.abi_version}, "
        f"{len(baseline.functions)} functions; current: {ABI_MACRO} {current.abi_version}, "
        f"{len(current.functions)} functions"
    ]
    if added:
        lines.append("added (compatible): " + ", ".join(added))
    if baseline.abi_version is None or current.abi_version is None:
        lines.append(f"error: {ABI_MACRO} is missing from a header")
        return False, "\n".join(lines)
    if not problems:
        if baseline.abi_version != current.abi_version:
            lines.append(
                f"note: {ABI_MACRO} moved from {baseline.abi_version} to {current.abi_version} "
                "with no incompatible change in the declarations"
            )
        else:
            lines.append("no incompatible change")
        return True, "\n".join(lines)
    lines.append("incompatible changes:")
    lines += [f"  {problem}" for problem in problems]
    if baseline.abi_version != current.abi_version:
        lines.append(
            f"allowed: {ABI_MACRO} was bumped from {baseline.abi_version} to {current.abi_version} "
            "(ADR 0007); the bindings will refuse the old library"
        )
        return True, "\n".join(lines)
    lines.append(
        f"error: these need {ABI_MACRO} bumped from {baseline.abi_version} in the same change "
        "(ADR 0007), or the declarations restored"
    )
    return False, "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--baseline", required=True, type=Path, help="the previous release's header")
    parser.add_argument("--current", required=True, type=Path, help="the header to check")
    parser.add_argument("--baseline-name", default="previous release", help="label for the report")
    args = parser.parse_args(argv)
    ok, report = verdict(
        parse(args.baseline.read_text()), parse(args.current.read_text()), args.baseline_name
    )
    print(report)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
