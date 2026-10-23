"""Tests for package-managers.py: python3 -m unittest scripts/release/package_managers_test.py"""

from __future__ import annotations

import importlib.util
import json
import os
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("package_managers", HERE / "package-managers.py")
pm = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(pm)

VERSION = "0.1.4"
TARGETS = list(pm.BREW_TARGETS) + list(pm.WINDOWS_TARGETS)


def fixture_sums() -> dict[str, str]:
    sums = {}
    for i, target in enumerate(TARGETS):
        sums[pm.cli_archive(VERSION, target)] = f"{i:064x}"
    # Files a real SHA256SUMS also carries and the renderer must ignore.
    sums[f"sourceorrery-ffi-{VERSION}-x86_64-unknown-linux-gnu.tar.gz"] = "ab" * 32
    sums[f"sourceorrery-{VERSION}.jar"] = "cd" * 32
    return sums


class ParseSha256Sums(unittest.TestCase):
    def test_parses_sha256sum_output(self) -> None:
        text = "AB" * 32 + "  a.tar.gz\n" + "cd" * 32 + " *b.zip\n\n"
        self.assertEqual(pm.parse_sha256sums(text), {"a.tar.gz": "ab" * 32, "b.zip": "cd" * 32})

    def test_rejects_malformed_and_duplicate_lines(self) -> None:
        with self.assertRaises(pm.RenderError):
            pm.parse_sha256sums("nothex  a.tar.gz\n")
        with self.assertRaises(pm.RenderError):
            pm.parse_sha256sums("ab" * 32 + "  a\n" + "cd" * 32 + "  a\n")


class Rendering(unittest.TestCase):
    def setUp(self) -> None:
        self.sums = fixture_sums()
        self.files = pm.render_all(VERSION, self.sums, "2026-10-22")

    def test_every_output_is_rendered(self) -> None:
        self.assertEqual(
            sorted(self.files),
            [
                "homebrew/Formula/sourceorrery.rb",
                "scoop/bucket/sourceorrery.json",
                f"winget/manifests/n/Netizine/SourceOrrery/{VERSION}/Netizine.SourceOrrery.installer.yaml",
                f"winget/manifests/n/Netizine/SourceOrrery/{VERSION}/Netizine.SourceOrrery.locale.en-US.yaml",
                f"winget/manifests/n/Netizine/SourceOrrery/{VERSION}/Netizine.SourceOrrery.yaml",
            ],
        )

    def test_formula_names_every_unix_archive_with_its_hash(self) -> None:
        formula = self.files["homebrew/Formula/sourceorrery.rb"]
        self.assertIn(f'version "{VERSION}"', formula)
        for target in pm.BREW_TARGETS:
            file = pm.cli_archive(VERSION, target)
            self.assertIn(pm.release_url(VERSION, file), formula)
            self.assertIn(f'sha256 "{self.sums[file]}"', formula)
        for target in pm.WINDOWS_TARGETS:
            self.assertNotIn(target, formula)
        self.assertIn('generate_completions_from_executable(bin/"sourceorrery", "completions")', formula)

    def test_scoop_manifest_has_both_architectures_and_autoupdate(self) -> None:
        manifest = json.loads(self.files["scoop/bucket/sourceorrery.json"])
        self.assertEqual(manifest["version"], VERSION)
        self.assertEqual(manifest["bin"], "sourceorrery.exe")
        for target, (arch, _) in pm.WINDOWS_TARGETS.items():
            file = pm.cli_archive(VERSION, target)
            self.assertEqual(manifest["architecture"][arch]["url"], pm.release_url(VERSION, file))
            self.assertEqual(manifest["architecture"][arch]["hash"], self.sums[file])
            self.assertIn("$version", manifest["autoupdate"]["architecture"][arch]["url"])
        self.assertEqual(manifest["autoupdate"]["hash"]["url"], "$baseurl/SHA256SUMS")

    def test_winget_installer_manifest_uses_uppercase_hashes_and_portable_zip(self) -> None:
        installer = self.files[
            f"winget/manifests/n/Netizine/SourceOrrery/{VERSION}/Netizine.SourceOrrery.installer.yaml"
        ]
        self.assertIn("InstallerType: zip", installer)
        self.assertIn("NestedInstallerType: portable", installer)
        self.assertIn("PortableCommandAlias: sourceorrery", installer)
        self.assertIn("ReleaseDate: 2026-10-22", installer)
        for target, (_, arch) in pm.WINDOWS_TARGETS.items():
            file = pm.cli_archive(VERSION, target)
            self.assertIn(f"Architecture: {arch}", installer)
            self.assertIn(f"InstallerSha256: {self.sums[file].upper()}", installer)
        for name in self.files:
            if name.startswith("winget/"):
                self.assertIn(f"PackageVersion: {VERSION}", self.files[name])
                self.assertIn(f"ManifestVersion: {pm.WINGET_MANIFEST_VERSION}", self.files[name])

    def test_missing_archive_is_an_error(self) -> None:
        sums = dict(self.sums)
        del sums[pm.cli_archive(VERSION, "aarch64-pc-windows-msvc")]
        with self.assertRaises(pm.RenderError) as ctx:
            pm.render_all(VERSION, sums, "2026-10-22")
        self.assertIn("aarch64-pc-windows-msvc", str(ctx.exception))

    def test_version_and_date_are_validated(self) -> None:
        with self.assertRaises(pm.RenderError):
            pm.render_all("v0.1.4", self.sums, "2026-10-22")
        with self.assertRaises(pm.RenderError):
            pm.render_all(VERSION, self.sums, "22/10/2026")


class WorkingDirectory(unittest.TestCase):
    def test_files_are_read_and_written_only_under_the_working_directory(self) -> None:
        cwd = Path(os.path.realpath(os.getcwd()))
        self.assertEqual(pm.under_working_directory(Path("dist"), "--out"), cwd / "dist")
        self.assertEqual(pm.under_working_directory(Path("."), "--out"), cwd)
        with self.assertRaises(ValueError):
            pm.under_working_directory(cwd.parent / "SHA256SUMS", "--sha256sums")
        with self.assertRaises(ValueError):
            pm.under_working_directory(Path("..") / "dist", "--out")
        argv = ["--version", VERSION, "--release-date", "2026-01-01", "--out", "dist"]
        self.assertEqual(pm.main(argv + ["--sha256sums", str(cwd.parent / "SHA256SUMS")]), 1)


if __name__ == "__main__":
    unittest.main()
