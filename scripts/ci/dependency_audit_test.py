"""Tests for dependency-audit.py: python3 -m unittest scripts/ci/dependency_audit_test.py

The scanners and the OSV API are replaced by fakes, so a vulnerable graph,
a failed scanner and an uncovered manifest are each shown to fail the
audit; nothing here reaches the network.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("dependency_audit", HERE / "dependency-audit.py")
da = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["dependency_audit"] = da  # dataclasses look the module up by name
spec.loader.exec_module(da)

CLEAN_CARGO = json.dumps({"vulnerabilities": {"found": False, "list": []}, "warnings": {}})
CLEAN_NPM = json.dumps({"vulnerabilities": {}, "metadata": {"vulnerabilities": {"total": 0}}})


def cargo_warning(advisory: str, name: str) -> dict:
    return {"advisory": {"id": advisory}, "package": {"name": name, "version": "1.0.0"}}


class Repo:
    """A tree with every file the inventory names, and fakes for the tools."""

    def __init__(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        for graph in da.INVENTORY:
            path = self.root / graph.path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(self.content(graph), encoding="utf-8")
        (self.root / "Cargo.toml").write_text(
            '[workspace]\nmembers = ["crates/a"]\n', encoding="utf-8"
        )
        self.cargo = {graph.path: (0, CLEAN_CARGO) for graph in da.INVENTORY if graph.kind == "cargo"}
        self.npm = {
            graph.path.rsplit("/", 1)[0]: (0, CLEAN_NPM)
            for graph in da.INVENTORY
            if graph.kind == "npm"
        }
        self.osv: dict[str, list[list[str]]] = {}
        self.osv_fails = False

    @staticmethod
    def content(graph) -> str:
        if graph.kind == "pypi":
            return "pytest==9.1.1 \\\n    --hash=sha256:00\nmaturin==1.15.0\n"
        if graph.kind == "pyproject":
            return '[build-system]\nrequires = ["maturin>=1.0,<2.0"]\n[project]\nname = "x"\n'
        if graph.kind == "maven":
            return (
                '<project xmlns="http://maven.apache.org/POM/4.0.0"><properties>'
                "<junit.version>6.1.3</junit.version></properties><dependencies><dependency>"
                "<groupId>org.junit.jupiter</groupId><artifactId>junit-jupiter</artifactId>"
                "<version>${junit.version}</version></dependency></dependencies></project>"
            )
        if graph.kind == "nuget":
            return '<Project><ItemGroup><PackageReference Include="xunit" Version="2.9.3" /></ItemGroup></Project>'
        if graph.path.endswith("go.mod"):
            return "module example.com/x\n\ngo 1.24\n"
        if graph.path.endswith("composer.json"):
            return json.dumps({"require": {"php": ">=8.2", "ext-ffi": "*"}})
        if graph.path.endswith("CMakeLists.txt"):
            return "cmake_minimum_required(VERSION 3.20)\nproject(x)\n"
        return "{}"

    def tracked(self) -> list[str]:
        return [g.path for g in da.INVENTORY] + ["Cargo.toml", "crates/a/Cargo.toml"]

    def runner(self, command: list[str], cwd: Path) -> tuple[int, str]:
        if command[:2] == ["cargo", "audit"]:
            return self.cargo[command[3]]
        if command[0] == "npm":
            return self.npm[cwd.relative_to(self.root).as_posix()]
        raise AssertionError(command)

    def poster(self, url: str, body: bytes) -> bytes:
        if self.osv_fails:
            raise OSError("connection refused")
        queries = json.loads(body)["queries"]
        results = []
        for query in queries:
            name = query["package"]["name"]
            vulns = self.osv.get(name, [[]])[0]
            results.append({"vulns": [{"id": v} for v in vulns]} if vulns else {})
        return json.dumps({"results": results}).encode()

    def run(self, strict: bool = False, tracked: list[str] | None = None) -> tuple[bool, str]:
        results, missing = da.audit(
            self.root, self.tracked() if tracked is None else tracked, self.runner, self.poster
        )
        ok, lines = da.verdict(results, missing, strict)
        return ok, "\n".join(lines)


class AuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Repo()
        self.addCleanup(self.repo.dir.cleanup)

    def test_a_clean_repository_passes(self) -> None:
        ok, text = self.repo.run()
        self.assertTrue(ok, text)
        self.assertNotIn("ERROR", text)

    def test_a_vulnerable_lock_file_fails(self) -> None:
        self.repo.cargo["bindings/node/Cargo.lock"] = (
            1,
            json.dumps(
                {
                    "vulnerabilities": {
                        "found": True,
                        "list": [
                            {
                                "advisory": {"id": "RUSTSEC-2099-0001"},
                                "package": {"name": "bad", "version": "0.1.0"},
                            }
                        ],
                    },
                    "warnings": {},
                }
            ),
        )
        ok, text = self.repo.run()
        self.assertFalse(ok)
        self.assertIn("VULNERABLE  bindings/node/Cargo.lock: RUSTSEC-2099-0001 bad 0.1.0", text)

    def test_a_scanner_that_fails_cannot_pass_for_a_clean_one(self) -> None:
        self.repo.cargo["Cargo.lock"] = (101, "error: could not fetch the advisory database")
        self.repo.npm["site"] = (127, "")
        ok, text = self.repo.run()
        self.assertFalse(ok)
        self.assertIn("ERROR       Cargo.lock: cargo audit exited 101 without a JSON report", text)
        self.assertIn("ERROR       site/package-lock.json: npm audit exited 127", text)

    def test_npm_vulnerabilities_and_npm_errors_fail(self) -> None:
        self.repo.npm["scripts/ci/lstk"] = (
            1,
            json.dumps(
                {
                    "vulnerabilities": {"tar": {"severity": "high"}},
                    "metadata": {"vulnerabilities": {"total": 1}},
                }
            ),
        )
        self.repo.npm["bindings/node"] = (1, json.dumps({"error": {"code": "ENOLOCK", "summary": "no lock"}}))
        ok, text = self.repo.run()
        self.assertFalse(ok)
        self.assertIn("VULNERABLE  scripts/ci/lstk/package-lock.json: tar (high)", text)
        self.assertIn("ERROR       bindings/node/package-lock.json: npm audit failed: ENOLOCK", text)

    def test_osv_findings_and_osv_failures_fail(self) -> None:
        self.repo.osv["xunit"] = [["GHSA-xxxx"]]
        ok, text = self.repo.run()
        self.assertFalse(ok)
        self.assertIn("GHSA-xxxx xunit 2.9.3", text)
        self.repo.osv.clear()
        self.repo.osv_fails = True
        ok, text = self.repo.run()
        self.assertFalse(ok)
        self.assertIn("the OSV query failed", text)

    def test_maintenance_warnings_are_reviewed_or_flagged(self) -> None:
        reviewed = sorted(da.REVIEWED)[0]
        self.repo.cargo["Cargo.lock"] = (
            0,
            json.dumps(
                {
                    "vulnerabilities": {"list": []},
                    "warnings": {
                        "unmaintained": [
                            cargo_warning(reviewed, "zvariant"),
                            cargo_warning("RUSTSEC-2099-0002", "abandoned"),
                        ]
                    },
                }
            ),
        )
        ok, text = self.repo.run()
        self.assertTrue(ok, "a maintenance warning is not a vulnerability")
        self.assertIn(f"reviewed maintenance warning {reviewed}", text)
        self.assertIn("::warning title=unreviewed maintenance warning::Cargo.lock", text)
        ok, text = self.repo.run(strict=True)
        self.assertFalse(ok, "a release does not pass an unreviewed warning")
        self.assertIn("::error title=unreviewed maintenance warning::", text)

    def test_every_tracked_lock_file_and_manifest_is_covered(self) -> None:
        extra = self.repo.tracked() + ["tools/new/package-lock.json", "other/Cargo.toml"]
        ok, text = self.repo.run(tracked=extra)
        self.assertFalse(ok)
        self.assertIn("UNCOVERED   tools/new/package-lock.json", text)
        self.assertIn("UNCOVERED   other/Cargo.toml", text)

    def test_an_npm_package_without_dependencies_needs_no_lock_file(self) -> None:
        platform = self.repo.root / "bindings/node/npm/linux-x64-gnu/package.json"
        platform.parent.mkdir(parents=True)
        platform.write_text(json.dumps({"name": "x", "os": ["linux"]}), encoding="utf-8")
        ok, text = self.repo.run(tracked=self.repo.tracked() + ["bindings/node/npm/linux-x64-gnu/package.json"])
        self.assertTrue(ok, text)
        platform.write_text(json.dumps({"name": "x", "dependencies": {"y": "1"}}), encoding="utf-8")
        ok, text = self.repo.run(tracked=self.repo.tracked() + ["bindings/node/npm/linux-x64-gnu/package.json"])
        self.assertFalse(ok)

    def test_a_graph_that_gains_dependencies_needs_a_scanner(self) -> None:
        (self.repo.root / "bindings/go/go.mod").write_text(
            "module example.com/x\n\nrequire golang.org/x/sys v0.1.0\n", encoding="utf-8"
        )
        (self.repo.root / "composer.json").write_text(
            json.dumps({"require": {"php": ">=8.2", "vendor/lib": "^1"}}), encoding="utf-8"
        )
        (self.repo.root / "bindings/python/pyproject.toml").write_text(
            '[build-system]\nrequires = ["setuptools"]\n[project]\nname = "x"\ndependencies = ["requests"]\n',
            encoding="utf-8",
        )
        ok, text = self.repo.run()
        self.assertFalse(ok)
        self.assertIn("go.mod requires modules", text)
        self.assertIn("composer.json requires vendor/lib", text)
        self.assertIn("runtime dependencies are not audited: requests", text)

    def test_a_listed_graph_that_disappears_fails(self) -> None:
        (self.repo.root / "scripts/coverage/requirements.txt").unlink()
        ok, text = self.repo.run()
        self.assertFalse(ok)
        self.assertIn("scripts/coverage/requirements.txt: listed in the inventory but not found", text)


class ParserTest(unittest.TestCase):
    def test_requirements_follow_includes_and_ignore_hashes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a").mkdir()
            (root / "a/base.txt").write_text(
                "maturin==1.15.0 \\\n    --hash=sha256:aa\n# comment\nPyTest[extra]==9.1.1 ; python_version>'3'\n",
                encoding="utf-8",
            )
            (root / "b.txt").write_text("-r a/base.txt\ncoverage==7.17.0\n-r b.txt\n", encoding="utf-8")
            self.assertEqual(
                da.requirements(root / "b.txt"),
                [("maturin", "1.15.0"), ("pytest", "9.1.1"), ("coverage", "7.17.0")],
            )

    def test_the_repositorys_own_manifests_parse(self) -> None:
        root = HERE.parents[1]
        self.assertIn(("org.junit.jupiter:junit-jupiter", "6.1.3"), da.pom_coordinates(root / "bindings/java/pom.xml"))
        refs = dict(da.nuget_references(root / "bindings/dotnet/SourceOrrery.Tests/SourceOrrery.Tests.csproj"))
        self.assertIn("xunit", refs)
        self.assertEqual(da.uncovered(da.run(["git", "ls-files"], root)[1].splitlines(), root), [])


if __name__ == "__main__":
    unittest.main()
