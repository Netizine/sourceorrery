"""The emulator correction fails closed and preserves stored version dates."""

import importlib.util
import json
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("moto_version_timestamps", HERE / "moto-version-timestamps.py")
fix = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fix)
ORIGINAL = (HERE / "fixtures/moto_5_2_4_version_listing.py").read_text(encoding="utf-8")


class MotoVersionTimestampsTests(unittest.TestCase):
    def test_only_the_listing_creation_date_changes(self):
        corrected, changed = fix.patch_source(ORIGINAL, "5.2.4")
        self.assertTrue(changed)
        self.assertEqual(corrected, ORIGINAL.replace(
            '"CreatedDate": int(time.time()),', '"CreatedDate": version["createdate"],', 1,
        ))
        self.assertIn('"LastAccessedDate": int(time.time()),', corrected)
        self.assertEqual(corrected.count('return {"CreatedDate": int(time.time())}'), 2)

    def test_a_second_application_is_unchanged(self):
        corrected, _ = fix.patch_source(ORIGINAL, "5.2.4")
        self.assertEqual(fix.patch_source(corrected, "5.2.4"), (corrected, False))

    def test_pinned_docker_package_version_uses_the_same_source_guard(self):
        corrected, changed = fix.patch_source(ORIGINAL, "5.2.4.dev0")
        self.assertTrue(changed)
        self.assertEqual(corrected, fix.patch_source(ORIGINAL, "5.2.4")[0])
        self.assertEqual(fix.patch_source(corrected, "5.2.4.dev0"), (corrected, False))
        modified = ORIGINAL.replace('"NextToken": ""', '"NextToken": "changed"')
        with self.assertRaises(ValueError):
            fix.patch_source(modified, "5.2.4.dev0")

    def test_other_versions_and_changed_method_bodies_are_rejected(self):
        for version in ("5.2.3", "5.2.5", "5.2.4.dev1", "5.2.5.dev0"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                fix.patch_source(ORIGINAL, version)
        for source in (
            ORIGINAL.replace('"NextToken": ""', '"NextToken": "changed"'),
            ORIGINAL.replace('"CreatedDate": int(time.time()),', '"CreatedDate": 123,'),
            ORIGINAL.replace("def list_secret_version_ids", "def renamed_method"),
            ORIGINAL.replace("    def list_secret_version_ids", "    @changed\n    def list_secret_version_ids"),
            ORIGINAL + "\nclass SecretsManagerBackend:\n    pass\n",
        ):
            with self.subTest(source=source[-60:]), self.assertRaises(ValueError):
                fix.patch_source(source, "5.2.4")

    def test_original_creation_dates_survive_a_later_wall_clock(self):
        corrected, _ = fix.patch_source(ORIGINAL, "5.2.4")
        namespace = {}
        exec(corrected, namespace)
        backend = namespace["SecretsManagerBackend"]()
        backend.secrets = {"example": types.SimpleNamespace(
            secret_id="example", name="example", versions={
                "first": {"createdate": 100, "version_stages": ["AWSPREVIOUS"]},
                "second": {"createdate": 200, "version_stages": ["AWSCURRENT"]},
            },
        )}
        for clock in (300, 400):
            with self.subTest(clock=clock), patch("time.time", return_value=clock):
                versions = json.loads(backend.list_secret_version_ids("example"))["Versions"]
                self.assertEqual([v["CreatedDate"] for v in versions], [100, 200])
                self.assertEqual([v["LastAccessedDate"] for v in versions], [clock, clock])
                self.assertEqual([v["VersionId"] for v in versions], ["first", "second"])

    def test_installed_source_is_not_written_when_validation_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "models.py"
            modified = ORIGINAL.replace('"NextToken": ""', '"NextToken": "changed"')
            source.write_text(modified, encoding="utf-8")
            distribution = types.SimpleNamespace(version="5.2.4", locate_file=lambda _: source)
            with patch.object(fix.importlib.metadata, "distribution", return_value=distribution):
                with self.assertRaises(ValueError):
                    fix.patch_installed()
            self.assertEqual(source.read_text(encoding="utf-8"), modified)

    def test_container_requires_the_pinned_running_service(self):
        with patch.object(fix.subprocess, "check_output") as inspect, \
                patch.object(fix.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                fix.patch_container("--untrusted-option")
            inspect.assert_not_called()
            for state in ("false motoserver/moto:5.2.4", "true another/image:5.2.4"):
                inspect.return_value = state
                with self.subTest(state=state), self.assertRaises(ValueError):
                    fix.patch_container("a" * 64)
            run.assert_not_called()

    def test_container_restart_follows_a_successful_patch(self):
        container = "a" * 64
        with patch.object(fix.subprocess, "check_output", return_value="true motoserver/moto:5.2.4"), \
                patch.object(fix.subprocess, "run") as run:
            fix.patch_container(container)
            self.assertEqual(run.call_args_list[0].args[0], ["docker", "exec", "-i", container, "python", "-"])
            self.assertIn("def patch_installed()", run.call_args_list[0].kwargs["input"])
            self.assertEqual(run.call_args_list[1].args[0], ["docker", "restart", container])

    def test_a_failed_container_patch_does_not_restart_the_service(self):
        with patch.object(fix.subprocess, "check_output", return_value="true motoserver/moto:5.2.4"), \
                patch.object(fix.subprocess, "run", side_effect=subprocess.CalledProcessError(1, "docker")) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                fix.patch_container("a" * 64)
            self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
