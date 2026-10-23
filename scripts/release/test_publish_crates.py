"""Check publishing decisions without accessing a registry or invoking Cargo."""

import contextlib
import importlib.util
import io
import json
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("publish_crates", Path(__file__).with_name("publish-crates.py"))
publish = importlib.util.module_from_spec(spec)
spec.loader.exec_module(publish)


class PublishCratesTests(unittest.TestCase):
    def metadata(self, extra=None):
        names = [publish.CORE, *publish.PROVIDERS, "sourceorrery"]
        packages = [{"id": name, "name": name, "version": "0.2.0", "publish": None} for name in names]
        packages.append({"id": "tests", "name": "tests", "version": "0.2.0", "publish": []})
        if extra:
            packages.append(extra)
        return {"workspace_members": [p["id"] for p in packages], "packages": packages}

    def test_workspace_includes_every_publishable_member(self):
        extra = {"id": "future", "name": "future", "version": "0.2.0", "publish": None}
        self.assertEqual(len(publish.selected_packages(self.metadata(extra), "0.2.0", "workspace")), 6)
        self.assertNotIn("tests", publish.selected_packages(self.metadata(), "0.2.0", "workspace"))

    def test_bootstrap_has_core_and_all_three_real_providers(self):
        self.assertEqual(publish.selected_packages(self.metadata(), "0.2.0", "bootstrap"),
                         [publish.CORE, *publish.PROVIDERS])

    def test_wrong_version_or_missing_provider_fails(self):
        with self.assertRaises(ValueError):
            publish.selected_packages(self.metadata(), "0.1.5", "workspace")
        metadata = self.metadata()
        metadata["packages"] = metadata["packages"][:1]
        with self.assertRaises(ValueError):
            publish.selected_packages(metadata, "0.2.0", "providers")

    def test_only_404_means_unpublished(self):
        for code in (401, 403, 429, 500, 503):
            with self.subTest(code=code), patch.object(publish.urllib.request, "urlopen", side_effect=
                    urllib.error.HTTPError("https://crates.io", code, "error", {}, None)):
                with self.assertRaises(RuntimeError):
                    publish.version_exists(publish.CORE, "0.2.0")
        with patch.object(publish.urllib.request, "urlopen", side_effect=
                urllib.error.HTTPError("https://crates.io", 404, "missing", {}, None)):
            self.assertFalse(publish.version_exists(publish.CORE, "0.2.0"))

    def test_existing_and_yanked_versions(self):
        for yanked in (False, True):
            payload = {"version": {"crate": publish.CORE, "num": "0.2.0", "yanked": yanked}}
            with patch.object(publish.urllib.request, "urlopen", return_value=io.BytesIO(json.dumps(payload).encode())):
                if yanked:
                    with self.assertRaises(RuntimeError):
                        publish.version_exists(publish.CORE, "0.2.0")
                else:
                    self.assertTrue(publish.version_exists(publish.CORE, "0.2.0"))

    def test_default_command_cannot_upload(self):
        command = publish.cargo_publish_command(list(publish.PROVIDERS), False)
        self.assertIn("--dry-run", command)
        self.assertNotIn("--dry-run", publish.cargo_publish_command(list(publish.PROVIDERS), True))
        self.assertEqual(command.count("--package"), 3)
        self.assertIn("--locked", command)

    def test_partial_publish_resumes_only_missing_versions(self):
        argv = ["publish-crates.py", "0.2.0", "--group", "providers", "--publish"]
        with patch.object(publish.sys, "argv", argv), \
                patch.object(publish.subprocess, "check_output", return_value=json.dumps(self.metadata())), \
                patch.object(publish, "version_exists", side_effect=[True, False, False]), \
                patch.object(publish.subprocess, "call", return_value=0) as upload, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(publish.main(), 0)
            command = upload.call_args.args[0]
            self.assertNotIn(publish.PROVIDERS[0], command)
            self.assertIn(publish.PROVIDERS[1], command)
            self.assertIn(publish.PROVIDERS[2], command)

    def test_registry_failure_prevents_all_uploads(self):
        argv = ["publish-crates.py", "0.2.0", "--group", "providers", "--publish"]
        with patch.object(publish.sys, "argv", argv), \
                patch.object(publish.subprocess, "check_output", return_value=json.dumps(self.metadata())), \
                patch.object(publish, "version_exists", side_effect=[False, RuntimeError("HTTP 503")]), \
                patch.object(publish.subprocess, "call") as upload, \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(publish.main(), 1)
            upload.assert_not_called()

    def test_fully_published_group_never_runs_cargo_publish(self):
        argv = ["publish-crates.py", "0.2.0", "--group", "providers", "--publish"]
        with patch.object(publish.sys, "argv", argv), \
                patch.object(publish.subprocess, "check_output", return_value=json.dumps(self.metadata())), \
                patch.object(publish, "version_exists", return_value=True), \
                patch.object(publish.subprocess, "call") as upload, \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(publish.main(), 0)
            upload.assert_not_called()


if __name__ == "__main__":
    unittest.main()
