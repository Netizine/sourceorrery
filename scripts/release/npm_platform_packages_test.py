"""Tests for npm-platform-packages.py: python3 -m unittest scripts/release/npm_platform_packages_test.py"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("npm_platform_packages", HERE / "npm-platform-packages.py")
npp = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(npp)


def manifest(platform: str, os_name: str, cpu: str, **extra) -> dict:
    """What `napi create-npm-dirs` writes for one platform package."""
    written = {
        "name": f"{npp.MAIN}-{platform}",
        "version": "0.1.4",
        "cpu": [cpu],
        "main": f"{npp.ADDON}.{platform}.node",
        "files": [f"{npp.ADDON}.{platform}.node"],
        "description": "copied from the main package",
        "os": [os_name],
    }
    written.update(extra)
    return written


def write_platform(npm_dir: Path, platform: str, written: dict) -> Path:
    path = npm_dir / platform / "package.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(written, indent=2) + "\n", encoding="utf-8")
    (path.parent / "README.md").write_text(f"`{written['name']}` is the {platform} binary for `{npp.MAIN}`\n", encoding="utf-8")
    return path


def files(npm_dir: Path) -> dict[Path, str]:
    return {p: p.read_text(encoding="utf-8") for p in sorted(npm_dir.rglob("*")) if p.is_file()}


def run(npm_dir: Path) -> None:
    with contextlib.redirect_stdout(io.StringIO()):
        npp.main(npm_dir)


class LoadManifest(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.npm = Path(tmp.name)

    def test_accepts_the_package_its_directory_is_for(self) -> None:
        path = write_platform(self.npm, "linux-x64-gnu", manifest("linux-x64-gnu", "linux", "x64", libc=["glibc"]))
        loaded = npp.load_manifest(path)
        self.assertEqual("Linux x64 (glibc)", npp.platform_label(loaded))

    def test_refuses_a_package_named_for_another_directory(self) -> None:
        path = write_platform(self.npm, "linux-x64-gnu", manifest("win32-x64-msvc", "win32", "x64"))
        with self.assertRaises(SystemExit) as stop:
            npp.load_manifest(path)
        self.assertIn("name is '@sourceorreryai/sdk-win32-x64-msvc'", str(stop.exception))

    def test_refuses_an_addon_file_napi_would_not_name(self) -> None:
        path = write_platform(self.npm, "darwin-arm64", manifest("darwin-arm64", "darwin", "arm64", main="../../index.js"))
        with self.assertRaises(SystemExit) as stop:
            npp.load_manifest(path)
        self.assertIn("main is '../../index.js'", str(stop.exception))

    def test_refuses_more_than_one_os_or_cpu(self) -> None:
        two_cpus = manifest("darwin-x64", "darwin", "x64")
        two_cpus["cpu"] = ["x64", "arm64"]
        path = write_platform(self.npm, "darwin-x64", two_cpus)
        with self.assertRaises(SystemExit) as stop:
            npp.load_manifest(path)
        self.assertIn("cpu must name exactly one value", str(stop.exception))

    def test_refuses_a_platform_without_a_label(self) -> None:
        path = write_platform(self.npm, "freebsd-x64", manifest("freebsd-x64", "freebsd", "x64"))
        with self.assertRaises(SystemExit) as stop:
            npp.platform_label(npp.load_manifest(path))
        self.assertIn("no label", str(stop.exception))

    def test_refuses_what_is_not_a_manifest(self) -> None:
        path = self.npm / "win32-x64-msvc" / "package.json"
        path.parent.mkdir()
        path.write_text("[]\n", encoding="utf-8")
        with self.assertRaises(SystemExit):
            npp.load_manifest(path)
        path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(SystemExit):
            npp.load_manifest(path)


class Main(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.npm = Path(tmp.name)

    def test_describes_every_package_and_is_idempotent(self) -> None:
        write_platform(self.npm, "win32-x64-msvc", manifest("win32-x64-msvc", "win32", "x64"))
        write_platform(self.npm, "linux-arm64-gnu", manifest("linux-arm64-gnu", "linux", "arm64", libc=["glibc"]))
        run(self.npm)
        first = files(self.npm)

        win = json.loads(first[self.npm / "win32-x64-msvc" / "package.json"])
        self.assertEqual(
            "SourceOrrery native addon for Windows x64, installed automatically by @sourceorreryai/sdk; "
            "install @sourceorreryai/sdk, not this package",
            win["description"],
        )
        self.assertEqual("0.1.4", win["version"])
        self.assertEqual(["sourceorrery.win32-x64-msvc.node"], win["files"])
        readme = first[self.npm / "win32-x64-msvc" / "README.md"]
        self.assertTrue(readme.startswith("# @sourceorreryai/sdk-win32-x64-msvc\n"))
        self.assertIn("The Windows x64 native addon", readme)
        self.assertIn("file, `sourceorrery.win32-x64-msvc.node`,", readme)
        self.assertIn("| `@sourceorreryai/sdk-linux-arm64-gnu` | Linux arm64 (glibc) |", readme)
        self.assertIn("| `@sourceorreryai/sdk-win32-x64-msvc` | Windows x64 |", readme)

        run(self.npm)
        self.assertEqual(first, files(self.npm))

    def test_one_wrong_manifest_stops_the_run_before_anything_is_written(self) -> None:
        write_platform(self.npm, "win32-x64-msvc", manifest("win32-x64-msvc", "win32", "x64"))
        write_platform(self.npm, "linux-x64-gnu", manifest("win32-arm64-msvc", "win32", "arm64"))
        before = files(self.npm)
        with self.assertRaises(SystemExit):
            run(self.npm)
        self.assertEqual(before, files(self.npm))

    def test_no_platform_packages_is_an_error(self) -> None:
        with self.assertRaises(SystemExit) as stop:
            run(self.npm)
        self.assertIn("no platform packages", str(stop.exception))


if __name__ == "__main__":
    unittest.main()
