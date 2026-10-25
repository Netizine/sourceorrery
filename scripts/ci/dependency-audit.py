#!/usr/bin/env python3
"""Audit every independently resolved dependency graph in the repository.

    python3 scripts/ci/dependency-audit.py [--strict]

Each graph in INVENTORY is checked by its scanner: cargo-audit for a
Cargo.lock, `npm audit` for a package-lock.json, and the OSV.dev query API
for the pinned Python requirements and the direct Maven and NuGet references
(their transitive graphs need Maven and the .NET SDK to resolve; Dependabot
follows those). A manifest that declares no third-party dependency (go.mod,
composer.json, the C++ build, the npm platform packages) is checked to stay
that way. Every lock file and package manifest under version control must be
covered, so a new graph cannot go unaudited.

Exit status 1 when a graph has a known vulnerability, when a scanner or the
OSV API fails, when a tracked manifest is not covered, or, with --strict (a
release), when a maintenance warning is not in REVIEWED. Without --strict an
unreviewed maintenance warning is printed as a GitHub warning annotation.
Nothing is installed or written; cargo-audit and npm must be on PATH.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
import tomllib
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parents[2]
OSV_BATCH = "https://api.osv.dev/v1/querybatch"


@dataclass(frozen=True)
class Graph:
    """One dependency graph: where it is and how it is checked."""

    path: str
    kind: str  # cargo | npm | pypi | pyproject | maven | nuget | none


INVENTORY: tuple[Graph, ...] = (
    Graph("Cargo.lock", "cargo"),
    Graph("bindings/python/Cargo.lock", "cargo"),
    Graph("bindings/node/Cargo.lock", "cargo"),
    Graph("site/package-lock.json", "npm"),
    Graph("bindings/node/package-lock.json", "npm"),
    Graph("scripts/coverage/package-lock.json", "npm"),
    Graph("scripts/ci/lstk/package-lock.json", "npm"),
    Graph("bindings/python/ci-requirements.txt", "pypi"),
    Graph("scripts/coverage/requirements.txt", "pypi"),
    Graph("bindings/python/pyproject.toml", "pyproject"),
    Graph("bindings/java/pom.xml", "maven"),
    Graph("bindings/dotnet/SourceOrrery/SourceOrrery.csproj", "nuget"),
    Graph("bindings/dotnet/SourceOrrery.Tests/SourceOrrery.Tests.csproj", "nuget"),
    Graph("bindings/dotnet/conformance/Conformance.csproj", "nuget"),
    Graph("bindings/dotnet/examples/GetSecret/GetSecret.csproj", "nuget"),
    Graph("SourceOrrery.Analysis.Source.csproj", "nuget"),
    Graph("SourceOrrery.Analysis.Tests.csproj", "nuget"),
    Graph("bindings/go/go.mod", "none"),
    Graph("composer.json", "none"),
    Graph("bindings/cpp/CMakeLists.txt", "none"),
)


@dataclass(frozen=True)
class Reviewed:
    """A maintenance warning someone has looked at (docs/supply-chain.md)."""

    package: str
    owner: str
    upstream: str
    target: str
    revisit: str


# Maintenance notices, not vulnerabilities: each has an owner by role, the
# upstream issue, the upgrade that removes it and what makes us look again.
_DBUS = Reviewed(
    package="zbus 5 parts, through secret-service 5.2 (Linux credential store)",
    owner="maintainer of sourceorrery-storage's keystore",
    upstream="https://github.com/z-galaxy/zbus/issues/2043",
    target="secret-service and zbus-secret-service-keyring-store on zbus 6",
    revisit="a secret-service release on zbus 6 (Dependabot cargo update)",
)
REVIEWED: dict[str, Reviewed] = {
    "RUSTSEC-2026-0370": _DBUS,  # zvariant
    "RUSTSEC-2026-0371": _DBUS,  # zbus_names
    "RUSTSEC-2026-0372": _DBUS,  # zvariant_derive
}


@dataclass
class Result:
    """What one graph's check found."""

    graph: Graph
    vulnerabilities: list[str] = field(default_factory=list)
    maintenance: list[str] = field(default_factory=list)
    error: str | None = None
    note: str = ""


Runner = Callable[[list[str], Path], tuple[int, str]]
Poster = Callable[[str, bytes], bytes]


def run(command: list[str], cwd: Path) -> tuple[int, str]:
    """Run `command` in `cwd`: its exit status and standard output; 127 and
    nothing when the program is not installed (then the check fails)."""
    program = shutil.which(command[0])
    if program is None:
        return 127, ""
    done = subprocess.run(
        [program, *command[1:]], cwd=cwd, capture_output=True, text=True, check=False
    )
    return done.returncode, done.stdout


def post(url: str, body: bytes) -> bytes:
    """POST JSON to `url` and return the answer's body."""
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"}, method="POST"
    )
    with urllib.request.urlopen(request, timeout=60) as answer:  # noqa: S310 - fixed https URL
        return answer.read()


# --- coverage of the tracked files ------------------------------------------

LOCK_OR_MANIFEST = re.compile(
    r"(^|/)(Cargo\.lock|Cargo\.toml|package-lock\.json|package\.json|"
    r"requirements[^/]*\.txt|pyproject\.toml|go\.mod|composer\.json|pom\.xml|"
    r"[^/]+\.csproj|CMakeLists\.txt)$"
)
NPM_DEPENDENCY_KEYS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def workspace_members(root: Path) -> set[str]:
    """The root workspace's members, whose graph the root Cargo.lock holds."""
    data = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    return set(data.get("workspace", {}).get("members", []))


def uncovered(tracked: list[str], root: Path) -> list[str]:
    """Tracked lock files and manifests no graph covers."""
    listed = {graph.path for graph in INVENTORY}
    members = workspace_members(root) if (root / "Cargo.toml").is_file() else set()
    missing = []
    for path in tracked:
        if not LOCK_OR_MANIFEST.search(path) or path in listed:
            continue
        name = path.rsplit("/", 1)[-1]
        folder = path.rsplit("/", 1)[0] if "/" in path else ""
        if name == "Cargo.toml" and (
            folder == ""
            or folder in members
            or f"{folder}/Cargo.lock" in listed
        ):
            continue  # the root workspace or a workspace whose own lock is audited
        if name == "package.json":
            if f"{folder}/package-lock.json".lstrip("/") in listed:
                continue
            manifest = json.loads((root / path).read_text(encoding="utf-8"))
            if not any(manifest.get(key) for key in NPM_DEPENDENCY_KEYS):
                continue  # declares nothing to resolve (an npm platform package)
        missing.append(path)
    return missing


# --- parsers ----------------------------------------------------------------

PIN = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*==\s*([^\s;\\]+)")


def requirements(path: Path, seen: set[Path] | None = None) -> list[tuple[str, str]]:
    """The exact pins of a requirements file, following `-r` includes."""
    seen = seen if seen is not None else set()
    path = path.resolve()
    if path in seen:
        return []
    seen.add(path)
    pins: list[tuple[str, str]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line.startswith("-r "):
            pins += requirements((path.parent / line[3:].strip()).resolve(), seen)
            continue
        match = PIN.match(line)
        if match:
            pins.append((match.group(1).lower(), match.group(2)))
    return pins


def pom_coordinates(path: Path) -> list[tuple[str, str]]:
    """`group:artifact` and version of every dependency and plugin a pom names."""
    tree = ET.parse(path)  # noqa: S314 - a file under version control
    ns = {"m": "http://maven.apache.org/POM/4.0.0"}
    props = {
        child.tag.split("}", 1)[-1]: (child.text or "").strip()
        for child in tree.getroot().findall("m:properties/*", ns)
    }
    found = []
    for node in tree.getroot().iter():
        tag = node.tag.split("}", 1)[-1]
        if tag not in ("dependency", "plugin"):
            continue
        group = node.findtext("m:groupId", default="org.apache.maven.plugins", namespaces=ns)
        artifact = node.findtext("m:artifactId", default="", namespaces=ns)
        version = node.findtext("m:version", default="", namespaces=ns).strip()
        version = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m.group(1), m.group(0)), version)
        if artifact and version and "${" not in version:
            found.append((f"{group.strip()}:{artifact.strip()}", version))
    return found


def nuget_references(path: Path) -> list[tuple[str, str]]:
    """The `PackageReference`s of a project file, with their versions."""
    tree = ET.parse(path)  # noqa: S314 - a file under version control
    found = []
    for node in tree.getroot().iter():
        if node.tag.split("}", 1)[-1] == "PackageReference":
            name = node.get("Include")
            version = node.get("Version")
            if name and version:
                found.append((name, version))
    return found


# --- checks -----------------------------------------------------------------


def check_cargo(graph: Graph, root: Path, runner: Runner) -> Result:
    result = Result(graph)
    status, out = runner(["cargo", "audit", "--file", graph.path, "--json"], root)
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        result.error = f"cargo audit exited {status} without a JSON report"
        return result
    for item in report.get("vulnerabilities", {}).get("list", []):
        advisory = item.get("advisory", {})
        package = item.get("package", {})
        result.vulnerabilities.append(
            f"{advisory.get('id')} {package.get('name')} {package.get('version')}"
        )
    for kind, items in (report.get("warnings") or {}).items():
        for item in items:
            advisory = item.get("advisory") or {}
            package = item.get("package", {})
            result.maintenance.append(
                f"{advisory.get('id', kind)} {package.get('name')} {package.get('version')} ({kind})"
            )
    if status != 0 and not result.vulnerabilities:
        result.error = f"cargo audit exited {status}"
    return result


def check_npm(graph: Graph, root: Path, runner: Runner) -> Result:
    result = Result(graph)
    folder = root / graph.path.rsplit("/", 1)[0]
    status, out = runner(["npm", "audit", "--package-lock-only", "--ignore-scripts", "--json"], folder)
    try:
        report = json.loads(out)
    except json.JSONDecodeError:
        result.error = f"npm audit exited {status} without a JSON report"
        return result
    if "error" in report:
        error = report["error"]
        result.error = f"npm audit failed: {error.get('code')} {error.get('summary', '')}".strip()
        return result
    for name, item in sorted(report.get("vulnerabilities", {}).items()):
        result.vulnerabilities.append(f"{name} ({item.get('severity')})")
    total = report.get("metadata", {}).get("vulnerabilities", {}).get("total")
    if total is None:
        result.error = "npm audit gave no vulnerability count"
    elif total and not result.vulnerabilities:
        result.vulnerabilities.append(f"{total} vulnerabilities")
    return result


def osv_query(ecosystem: str, packages: list[tuple[str, str]], poster: Poster) -> list[str]:
    """OSV ids of known vulnerabilities in `packages` (name, version)."""
    if not packages:
        return []
    body = json.dumps(
        {
            "queries": [
                {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
                for name, version in packages
            ]
        }
    ).encode()
    answer = json.loads(poster(OSV_BATCH, body))
    results = answer.get("results")
    if not isinstance(results, list) or len(results) != len(packages):
        raise ValueError("the OSV answer does not match the query")
    found = []
    for (name, version), result in zip(packages, results):
        for vuln in result.get("vulns") or []:
            found.append(f"{vuln.get('id')} {name} {version}")
    return found


def check_osv(graph: Graph, root: Path, poster: Poster) -> Result:
    result = Result(graph)
    path = root / graph.path
    ecosystem, packages = {
        "pypi": lambda: ("PyPI", requirements(path)),
        "maven": lambda: ("Maven", pom_coordinates(path)),
        "nuget": lambda: ("NuGet", nuget_references(path)),
    }[graph.kind]()
    if graph.kind != "pypi":
        result.note = "direct references only"
    try:
        result.vulnerabilities = osv_query(ecosystem, packages, poster)
    except (OSError, ValueError, urllib.error.URLError) as err:
        result.error = f"the OSV query failed: {err}"
    if not result.error:
        result.note = f"{len(packages)} package(s){', ' + result.note if result.note else ''}"
    return result


def check_pyproject(graph: Graph, root: Path) -> Result:
    """Runtime dependencies none; build requirements pinned in a CI requirements file."""
    result = Result(graph)
    data = tomllib.loads((root / graph.path).read_text(encoding="utf-8"))
    runtime = data.get("project", {}).get("dependencies") or []
    if runtime:
        result.error = f"runtime dependencies are not audited: {', '.join(runtime)}"
        return result
    pinned = {
        name
        for g in INVENTORY
        if g.kind == "pypi" and (root / g.path).is_file()
        for name, _ in requirements(root / g.path)
    }
    for requirement in data.get("build-system", {}).get("requires", []):
        name = re.split(r"[<>=!~\[; ]", requirement, maxsplit=1)[0].lower()
        if name not in pinned:
            result.error = f"build requirement {name} is not pinned in a CI requirements file"
    result.note = "no runtime dependencies; build tools pinned for CI"
    return result


def check_none(graph: Graph, root: Path) -> Result:
    """A manifest that must keep declaring no third-party dependency."""
    result = Result(graph, note="no third-party dependencies")
    text = (root / graph.path).read_text(encoding="utf-8")
    if graph.path.endswith("go.mod"):
        if re.search(r"^\s*require\b", text, re.MULTILINE):
            result.error = "go.mod requires modules: give it a scanner"
    elif graph.path.endswith("composer.json"):
        for section in ("require", "require-dev"):
            for name in json.loads(text).get(section, {}):
                if name != "php" and not name.startswith("ext-"):
                    result.error = f"composer.json requires {name}: give it a scanner"
    elif re.search(r"\b(FetchContent|ExternalProject|find_package)\s*\(", text):
        result.error = "the CMake build fetches or finds packages: give it a scanner"
    return result


def audit(
    root: Path = ROOT,
    tracked: list[str] | None = None,
    runner: Runner = run,
    poster: Poster = post,
) -> tuple[list[Result], list[str]]:
    """Check every graph: the results, and the tracked files nothing covers."""
    if tracked is None:
        _, out = runner(["git", "ls-files"], root)
        tracked = out.splitlines()
    results = []
    for graph in INVENTORY:
        try:
            results.append(check(graph, root, runner, poster))
        except Exception as err:  # noqa: BLE001 - a check that breaks fails its graph
            results.append(Result(graph, error=f"the check failed: {err}"))
    return results, uncovered(tracked, root)


def check(graph: Graph, root: Path, runner: Runner, poster: Poster) -> Result:
    """Check one graph with its scanner."""
    if not (root / graph.path).is_file():
        return Result(graph, error="listed in the inventory but not found")
    if graph.kind == "cargo":
        return check_cargo(graph, root, runner)
    if graph.kind == "npm":
        return check_npm(graph, root, runner)
    if graph.kind in ("pypi", "maven", "nuget"):
        return check_osv(graph, root, poster)
    if graph.kind == "pyproject":
        return check_pyproject(graph, root)
    return check_none(graph, root)


def verdict(results: list[Result], missing: list[str], strict: bool) -> tuple[bool, list[str]]:
    """Whether the audit passes, and the lines that say why."""
    ok = True
    lines = []
    for result in results:
        unreviewed = [m for m in result.maintenance if m.split(" ", 1)[0] not in REVIEWED]
        if result.error:
            ok = False
            lines.append(f"ERROR       {result.graph.path}: {result.error}")
        elif result.vulnerabilities:
            ok = False
            lines.append(f"VULNERABLE  {result.graph.path}: {'; '.join(result.vulnerabilities)}")
        else:
            lines.append(f"ok          {result.graph.path}{f' ({result.note})' if result.note else ''}")
        for warning in result.maintenance:
            reviewed = REVIEWED.get(warning.split(" ", 1)[0])
            if reviewed:
                lines.append(f"  reviewed maintenance warning {warning}: revisit on {reviewed.revisit}")
        if unreviewed:
            if strict:
                ok = False
            lines.append(
                f"{'::error' if strict else '::warning'} title=unreviewed maintenance warning::"
                f"{result.graph.path}: {'; '.join(unreviewed)} (add it to REVIEWED with its owner, "
                "upstream and target, or upgrade)"
            )
    for path in missing:
        ok = False
        lines.append(f"UNCOVERED   {path}: a lock file or manifest no audit covers; add it to INVENTORY")
    return ok, lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--strict", action="store_true", help="fail on unreviewed maintenance warnings")
    args = parser.parse_args(argv)
    results, missing = audit()
    ok, lines = verdict(results, missing, args.strict)
    print("\n".join(lines))
    print("dependency audit:", "passed" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
