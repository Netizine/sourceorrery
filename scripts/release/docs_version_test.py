"""Tests for docs-version.py:
python3 -m unittest scripts/release/docs_version_test.py

Each test builds a small repository with every listed page, stamps or
checks it, and looks at what the pages then say.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("docs_version", HERE / "docs-version.py")
dv = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["docs_version"] = dv
spec.loader.exec_module(dv)

CHANGELOG = """# Changelog

## [Unreleased]

## [0.2.0] - 2026-10-23

## [0.1.4] - 2026-10-22
"""
PAGE = """# A page

Install 0.2.0: `cargo install --locked sourceorrery-cli --version 0.2.0`, or
download https://github.com/Netizine/sourceorrery/releases/download/v0.2.0/sourceorrery-0.2.0-x86_64.tgz
or sourceorreryai-sdk-0.2.0.tgz or SourceOrrery.0.2.0.nupkg. It replaces 0.1.4.
Needs Rust 1.91.1 and cargo-llvm-cov 0.9.1; 1.0.2.0, 0.2.0.1 and 0.2.10 are other numbers.
"""
# 0.2.0 or 0.1.4 on their own, not inside 1.0.2.0 or 0.2.0.1
OLD = r"(?<!\d)(?<!\d\.)(0\.2\.0|0\.1\.4)(?!\d|\.\d)"


class Repository:
    """A temporary checkout with every page docs-version.py stamps."""

    def __init__(self, version: str = "0.3.0", changelog: str = CHANGELOG) -> None:
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        self.write("Cargo.toml", f'[workspace]\nmembers = []\n\n[workspace.package]\nversion = "{version}"\n')
        self.write("CHANGELOG.md", changelog)
        for path in dv.STAMPED:
            text = PAGE
            if path in dv.NOTED:
                start, end = dv.MARKERS[Path(path).suffix]
                text = PAGE + f"\n{start}\n{end}\n\nAfter the note, 0.2.0 again.\n"
            self.write(path, text)

    def write(self, path: str, text: str) -> None:
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text, encoding="utf-8", newline="\n")

    def read(self, path: str) -> str:
        return (self.root / path).read_text(encoding="utf-8")

    def main(self, *args: str) -> tuple[int, str]:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = dv.main(list(args), self.root)
        return code, out.getvalue()


class StampTest(unittest.TestCase):
    def repository(self, *args, **kwargs) -> Repository:
        repository = Repository(*args, **kwargs)
        self.addCleanup(repository.dir.cleanup)
        return repository

    def test_every_sourceorrery_version_becomes_the_workspace_version(self) -> None:
        repo = self.repository()
        self.assertEqual(repo.main()[0], 0)
        page = repo.read("bindings/python/README.md")
        self.assertNotRegex(page, OLD)
        self.assertIn("--version 0.3.0`", page)
        self.assertIn("releases/download/v0.3.0/sourceorrery-0.3.0-x86_64.tgz", page)
        self.assertIn("sourceorreryai-sdk-0.3.0.tgz or SourceOrrery.0.3.0.nupkg. It replaces 0.3.0.", page)
        # other numbers are left alone
        self.assertIn("Rust 1.91.1 and cargo-llvm-cov 0.9.1; 1.0.2.0, 0.2.0.1 and 0.2.10 are other numbers.", page)

    def test_an_unreleased_version_is_labelled_on_every_noted_page(self) -> None:
        repo = self.repository()
        repo.main()
        readme = repo.read("README.md")
        self.assertIn("> [!IMPORTANT]\n> **SourceOrrery 0.3.0 is not released yet.**", readme)
        # the note names the current release, which stamping leaves alone
        self.assertIn("[0.2.0](https://github.com/Netizine/sourceorrery/releases/tag/v0.2.0)", readme)
        self.assertIn("[`v0.2.0` tag](https://github.com/Netizine/sourceorrery/tree/v0.2.0)", readme)
        self.assertIn("[Upgrading](docs/upgrading.md)", readme)
        self.assertIn("After the note, 0.3.0 again.", readme)
        self.assertIn("[Upgrading](../upgrading.md)", repo.read("docs/sdks/python.md"))
        self.assertIn("[Upgrading](upgrading.md)", repo.read("docs/building.md"))
        site = repo.read("site/src/content/docs/getting-started.mdx")
        self.assertIn('<Aside type="caution" title="SourceOrrery 0.3.0 is not released yet">', site)
        self.assertIn("[Upgrading](/guides/upgrading/)", site)
        self.assertNotIn("not released", repo.read("bindings/java/README.md"))

    def test_a_released_version_carries_no_note(self) -> None:
        repo = self.repository(changelog=CHANGELOG.replace("## [Unreleased]", "## [Unreleased]\n\n## [0.3.0] - 2026-11-02"))
        repo.main()
        readme = repo.read("README.md")
        start, end = dv.MARKERS[".md"]
        self.assertIn(f"{start}\n{end}", readme)
        self.assertNotIn("not released", readme)
        self.assertNotRegex(readme, OLD)

    def test_releasing_clears_the_note_that_was_there(self) -> None:
        repo = self.repository()
        repo.main()
        repo.write("CHANGELOG.md", CHANGELOG.replace("## [Unreleased]", "## [Unreleased]\n\n## [0.3.0] - 2026-11-02"))
        self.assertEqual(repo.main("--check")[0], 1, "the note is stale once the version is released")
        repo.main()
        self.assertNotIn("not released", repo.read("site/src/content/docs/index.mdx"))
        self.assertEqual(repo.main("--check")[0], 0)

    def test_check_names_each_stale_page_and_changes_nothing(self) -> None:
        repo = self.repository()
        before = repo.read("docs/sdks/go.md")
        code, out = repo.main("--check")
        self.assertEqual(code, 1)
        self.assertIn("docs/sdks/go.md does not match version 0.3.0 (line 3, 4, 5", out)
        self.assertEqual(repo.read("docs/sdks/go.md"), before)
        repo.main()
        code, out = repo.main("--check")
        self.assertEqual(code, 0, out)
        self.assertIn("pages name 0.3.0 (not released yet; the pages say so)", out)
        self.assertIn("already names", repo.main()[1])

    def test_a_release_run_needs_the_released_version(self) -> None:
        repo = self.repository()
        repo.main()
        code, out = repo.main("--check", "--expect", "0.3.0")
        self.assertEqual(code, 1)
        self.assertIn("names 0.3.0 (not released in CHANGELOG.md), not the release 0.3.0", out)
        repo.write("CHANGELOG.md", CHANGELOG.replace("## [Unreleased]", "## [Unreleased]\n\n## [0.3.0] - 2026-11-02"))
        repo.main()
        self.assertEqual(repo.main("--check", "--expect", "0.3.0")[0], 0)
        self.assertEqual(repo.main("--check", "--expect", "0.3.1")[0], 1)

    def test_the_markers_are_required_where_listed_and_refused_elsewhere(self) -> None:
        repo = self.repository()
        repo.write("docs/sdks/c.md", PAGE)
        code, out = repo.main()
        self.assertEqual(code, 1)
        self.assertIn("docs/sdks/c.md: needs exactly one", out)
        repo = self.repository()
        start, end = dv.MARKERS[".md"]
        repo.write("docs/coverage.md", f"{PAGE}{start}\n{end}\n")
        self.assertIn("carries a release note but is not in NOTED", repo.main()[1])
        repo = self.repository()
        repo.write("README.md", f"{PAGE}{start}\n")
        self.assertIn("is not closed", repo.main()[1])

    def test_a_missing_page_or_an_older_workspace_version_refuses(self) -> None:
        repo = self.repository()
        (repo.root / "bindings/go/README.md").unlink()
        self.assertIn("bindings/go/README.md is listed", repo.main("--check")[1])
        repo = self.repository(version="0.1.9")
        before = repo.read("README.md")
        code, out = repo.main()
        self.assertEqual(code, 1)
        self.assertIn("older than the latest release 0.2.0", out)
        self.assertEqual(repo.read("README.md"), before, "nothing was written")

    def test_the_repository_matches_its_version(self) -> None:
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            code = dv.main(["--check"])
        self.assertEqual(code, 0, out.getvalue())


if __name__ == "__main__":
    unittest.main()
