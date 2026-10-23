"""Release stamping regressions: python3 -m unittest scripts/release/set_version_test.py."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import re
import shutil
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("set_version", Path(__file__).with_name("set-version.py"))
stamping = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(stamping)

VERSION = "9.8.7"
LOCKS = ("Cargo.lock", "bindings/python/Cargo.lock", "bindings/node/Cargo.lock")
PROVIDERS = {"sourceorrery-provider", "sourceorrery-provider-vault", "sourceorrery-provider-aws"}


class VersionStamping(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        workspace = tomllib.loads((REPO / "Cargo.toml").read_text(encoding="utf-8"))["workspace"]
        paths = {
            "Cargo.toml", *LOCKS, *stamping.EXTENSION_MANIFESTS,
            "bindings/python/python/sourceorrery/__init__.py",
            "bindings/node/package.json", "bindings/node/package-lock.json",
            "bindings/java/pom.xml", "bindings/dotnet/Directory.Build.props",
        }
        for member in workspace["members"]:
            paths.update(path.relative_to(REPO).as_posix() for path in REPO.glob(f"{member}/Cargo.toml"))
        paths.update(path.relative_to(REPO).as_posix() for path in (REPO / "bindings/node/npm").glob("*/package.json"))
        for relative in paths:
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / relative, target)
        self.root_patch = patch.object(stamping, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def run_stamp(self, *arguments: str) -> int:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return stamping.main(["set-version.py", VERSION, *arguments])

    def snapshot(self) -> dict[str, bytes]:
        return {path.relative_to(self.root).as_posix(): path.read_bytes() for path in self.root.rglob("*") if path.is_file()}

    def packages(self, relative: str) -> list[dict]:
        return tomllib.loads((self.root / relative).read_text(encoding="utf-8"))["package"]

    def test_repository_bump_updates_providers_in_every_lock_and_preserves_node_links(self) -> None:
        main_before = json.loads((self.root / "bindings/node/package.json").read_text(encoding="utf-8"))
        lock_before = json.loads((self.root / "bindings/node/package-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(0, self.run_stamp("--keep-node-links"))
        for lock in LOCKS:
            local = {package["name"]: package["version"] for package in self.packages(lock) if "source" not in package}
            self.assertTrue(PROVIDERS <= local.keys())
            self.assertTrue(all(local[provider] == VERSION for provider in PROVIDERS))
        main = json.loads((self.root / "bindings/node/package.json").read_text(encoding="utf-8"))
        lock = json.loads((self.root / "bindings/node/package-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(VERSION, main["version"])
        self.assertEqual(main_before["optionalDependencies"], main["optionalDependencies"])
        self.assertEqual(lock_before["packages"][""]["optionalDependencies"], lock["packages"][""]["optionalDependencies"])
        self.assertEqual(main["optionalDependencies"], lock["packages"][""]["optionalDependencies"])
        self.assertEqual(main_before["devDependencies"], main["devDependencies"])
        for location, package in lock["packages"].items():
            if location == "" or location.startswith("npm/"):
                self.assertEqual(VERSION, package["version"])
        for manifest in (self.root / "bindings/node/npm").glob("*/package.json"):
            self.assertEqual(VERSION, json.loads(manifest.read_text(encoding="utf-8"))["version"])
        snapshot = self.snapshot()
        self.assertEqual(0, self.run_stamp("--check"))
        self.assertEqual(snapshot, self.snapshot())
        self.assertEqual(0, self.run_stamp("--keep-node-links"))
        self.assertEqual(snapshot, self.snapshot())

    def test_release_stamp_keeps_registry_versions_for_packaging(self) -> None:
        self.assertEqual(0, self.run_stamp())
        main = json.loads((self.root / "bindings/node/package.json").read_text(encoding="utf-8"))
        for name, value in main["optionalDependencies"].items():
            if name.startswith("@sourceorreryai/sdk-"):
                self.assertEqual(VERSION, value)
        self.assertEqual(0, self.run_stamp("--check"))

    def test_check_detects_a_stale_provider_lock_without_writing(self) -> None:
        self.run_stamp("--keep-node-links")
        lock = self.root / "bindings/python/Cargo.lock"
        text, count = re.subn(
            r'(name = "sourceorrery-provider-aws"\nversion = )"[^"]+"',
            r'\1"0.0.1"', lock.read_text(encoding="utf-8"), count=1,
        )
        self.assertEqual(1, count)
        lock.write_text(text, encoding="utf-8")
        before = self.snapshot()
        self.assertEqual(1, self.run_stamp("--check"))
        self.assertEqual(before, self.snapshot())

    def test_new_workspace_provider_is_discovered_without_a_script_allowlist(self) -> None:
        name = "sourceorrery-provider-new"
        manifest = self.root / "crates" / name / "Cargo.toml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text(f'[package]\nname = "{name}"\nversion.workspace = true\n', encoding="utf-8")
        cargo = self.root / "Cargo.toml"
        text = cargo.read_text(encoding="utf-8")
        text = text.replace("members = [\n", f'members = [\n    "crates/{name}",\n', 1)
        text = text.replace("[workspace.dependencies]\n", f'[workspace.dependencies]\n{name} = {{ version = "0.0.1", path = "crates/{name}" }}\n', 1)
        cargo.write_text(text, encoding="utf-8")
        with (self.root / "Cargo.lock").open("a", encoding="utf-8") as output:
            output.write(f'\n[[package]]\nname = "{name}"\nversion = "0.0.1"\n')
        self.assertEqual(0, self.run_stamp("--keep-node-links"))
        packages = {package["name"]: package["version"] for package in self.packages("Cargo.lock") if "source" not in package}
        self.assertEqual(VERSION, packages[name])
        workspace = tomllib.loads(cargo.read_text(encoding="utf-8"))["workspace"]
        self.assertEqual(VERSION, workspace["dependencies"][name]["version"])

    def test_registry_packages_are_unchanged_even_when_a_name_matches(self) -> None:
        with (self.root / "Cargo.lock").open("a", encoding="utf-8") as output:
            output.write('\n[[package]]\nname = "sourceorrery-provider"\nversion = "0.0.1"\nsource = "registry+https://github.com/rust-lang/crates.io-index"\n')
        registry_before = {lock: [package for package in self.packages(lock) if "source" in package] for lock in LOCKS}
        node_before = json.loads((self.root / "bindings/node/package-lock.json").read_text(encoding="utf-8"))["packages"]
        self.assertEqual(0, self.run_stamp("--keep-node-links"))
        for lock in LOCKS:
            self.assertEqual(registry_before[lock], [package for package in self.packages(lock) if "source" in package])
        node_after = json.loads((self.root / "bindings/node/package-lock.json").read_text(encoding="utf-8"))["packages"]
        for location, package in node_before.items():
            if location.startswith("node_modules/"):
                self.assertEqual(package, node_after[location])

    def test_missing_workspace_lock_entry_aborts_before_any_write(self) -> None:
        lock = self.root / "Cargo.lock"
        blocks = re.split(r"(?=^\[\[package\]\])", lock.read_text(encoding="utf-8"), flags=re.MULTILINE)
        blocks = [block for block in blocks if 'name = "sourceorrery-provider-vault"\n' not in block]
        lock.write_text("".join(blocks), encoding="utf-8")
        before = self.snapshot()
        with self.assertRaisesRegex(SystemExit, "missing local crates: sourceorrery-provider-vault"):
            self.run_stamp("--keep-node-links")
        self.assertEqual(before, self.snapshot())

    def test_mistyped_option_is_rejected_before_any_write(self) -> None:
        before = self.snapshot()
        with self.assertRaises(SystemExit) as stopped:
            self.run_stamp("--keep-node-link")
        self.assertEqual(2, stopped.exception.code)
        self.assertEqual(before, self.snapshot())


if __name__ == "__main__":
    unittest.main()
