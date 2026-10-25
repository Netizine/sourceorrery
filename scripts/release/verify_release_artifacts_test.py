"""Tests for verify-release-artifacts.py:
python3 -m unittest scripts/release/verify_release_artifacts_test.py

`gh attestation verify` is a fake that knows which files the release
workflow attested, for which commit; each test changes one thing from a
release that verifies, and the check must refuse it.
"""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("verify_release_artifacts", HERE / "verify-release-artifacts.py")
vra = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["verify_release_artifacts"] = vra
spec.loader.exec_module(vra)

REPO = "Netizine/sourceorrery"
SHA = "956c05a6eb287db1f655f8440664c5150ba92570"
FILES = {
    "sourceorreryai-sdk-0.3.0.tgz": b"main package",
    "sourceorreryai-sdk-linux-x64-gnu-0.3.0.tgz": b"linux package",
    "SourceOrrery.0.3.0.nupkg": b"nuget package",
}


class Release:
    """Files on disk, their SHA256SUMS, and what the fake `gh` attests."""

    def __init__(self) -> None:
        self.dir = tempfile.TemporaryDirectory()
        root = Path(self.dir.name)
        self.dist = root / "dist"
        self.dist.mkdir()
        self.checks = root / "checksums"
        self.checks.mkdir()
        for name, body in FILES.items():
            (self.dist / name).write_bytes(body)
        self.sums = self.checks / "SHA256SUMS"
        self.write_sums()
        # digest -> commit it was attested for, by the release workflow
        self.attested = {self.digest(p): SHA for p in [*self.dist.iterdir(), self.sums]}
        self.service_down = False
        self.calls: list[list[str]] = []

    def write_sums(self, extra: str = "") -> None:
        lines = [
            f"{hashlib.sha256(body).hexdigest()}  {name}" for name, body in sorted(FILES.items())
        ]
        self.sums.write_text("\n".join(lines) + "\n" + extra, encoding="utf-8")

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def runner(self, command: list[str]) -> tuple[int, str]:
        self.calls.append(command)
        assert command[:3] == ["gh", "attestation", "verify"], command
        if self.service_down:
            return 1, "Error: HTTP 503: Service Unavailable"
        path = Path(command[3])
        args = dict(zip(command[4::2], command[5::2]))
        assert args["--signer-workflow"] == f"{REPO}/.github/workflows/release.yml"
        assert "--deny-self-hosted-runners" in command
        commit = self.attested.get(self.digest(path))
        if commit is None:
            return 1, "Error: HTTP 404: Not Found (no attestations for this digest)"
        if commit != args["--source-digest"]:
            return 1, f"Error: the source digest is {commit}"
        return 0, f"Loaded 1 attestation for {path.name}"

    def verify(self, patterns: list[str], sha: str = SHA) -> list[str]:
        return vra.verify(REPO, sha, self.sums, self.dist, patterns, self.runner)


class VerifyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.release = Release()
        self.addCleanup(self.release.dir.cleanup)

    def refused(self, patterns: list[str], says: str, sha: str = SHA) -> None:
        with self.assertRaises(vra.Refused) as caught:
            self.release.verify(patterns, sha)
        self.assertIn(says, str(caught.exception))

    def test_the_files_the_release_built_verify(self) -> None:
        verified = self.release.verify(["*.tgz", "*.nupkg"])
        self.assertEqual(len(verified), 4)
        self.assertEqual(len(self.release.calls), 4, "SHA256SUMS and each file")

    def test_a_pattern_takes_only_its_files(self) -> None:
        for name in list(FILES):
            if not name.endswith(".nupkg"):
                (self.release.dist / name).unlink()
        verified = self.release.verify(["*.nupkg"])
        self.assertEqual(len(verified), 2)

    def test_changed_bytes_are_refused(self) -> None:
        (self.release.dist / "SourceOrrery.0.3.0.nupkg").write_bytes(b"tampered")
        self.refused(["*.tgz", "*.nupkg"], "is not the file the release built")

    def test_changed_bytes_with_matching_sums_are_refused(self) -> None:
        # Both the file and SHA256SUMS replaced on the release: the new
        # SHA256SUMS carries no provenance.
        FILES_ALT = dict(FILES)
        FILES_ALT["SourceOrrery.0.3.0.nupkg"] = b"tampered"
        (self.release.dist / "SourceOrrery.0.3.0.nupkg").write_bytes(b"tampered")
        lines = [f"{hashlib.sha256(b).hexdigest()}  {n}" for n, b in sorted(FILES_ALT.items())]
        self.release.sums.write_text("\n".join(lines) + "\n", encoding="utf-8")
        self.refused(["*.tgz", "*.nupkg"], "a release without provenance")

    def test_a_file_without_its_own_attestation_is_refused(self) -> None:
        path = self.release.dist / "sourceorreryai-sdk-0.3.0.tgz"
        del self.release.attested[self.release.digest(path)]
        self.refused(["*.tgz", "*.nupkg"], "sourceorreryai-sdk-0.3.0.tgz has no build provenance")

    def test_provenance_for_another_commit_is_refused(self) -> None:
        self.refused(["*.tgz", "*.nupkg"], "has no build provenance", sha="f" * 40)
        for digest in self.release.attested:
            self.release.attested[digest] = "e" * 40
        self.refused(["*.tgz", "*.nupkg"], "the source digest is")

    def test_missing_unexpected_and_listed_twice_are_refused(self) -> None:
        (self.release.dist / "sourceorreryai-sdk-linux-x64-gnu-0.3.0.tgz").unlink()
        self.refused(["*.tgz"], "missing sourceorreryai-sdk-linux-x64-gnu-0.3.0.tgz")
        release = Release()
        self.addCleanup(release.dir.cleanup)
        (release.dist / "extra.tgz").write_bytes(b"x")
        with self.assertRaises(vra.Refused) as caught:
            release.verify(["*.tgz", "*.nupkg"])
        self.assertIn("unexpected extra.tgz", str(caught.exception))
        release = Release()
        self.addCleanup(release.dir.cleanup)
        name, body = next(iter(FILES.items()))
        release.write_sums(f"{hashlib.sha256(body).hexdigest()}  {name}\n")
        release.attested[release.digest(release.sums)] = SHA
        with self.assertRaises(vra.Refused) as caught:
            release.verify(["*"])
        self.assertIn("lists sourceorreryai-sdk-0.3.0.tgz twice", str(caught.exception))

    def test_a_pattern_the_release_never_had_is_refused(self) -> None:
        self.refused(["*.whl"], "lists no file matching *.whl")

    def test_the_verification_service_failing_refuses(self) -> None:
        self.release.service_down = True
        self.refused(["*.tgz"], "503")

    def test_a_legacy_release_without_provenance_is_refused_with_its_way_out(self) -> None:
        self.release.attested.clear()
        self.refused(["*.tgz"], "cut a new version, or have these files reviewed separately")

    def test_the_checksums_alone_can_be_verified(self) -> None:
        verified = vra.verify(REPO, SHA, self.release.sums, None, [], self.release.runner)
        self.assertEqual(len(verified), 1)
        self.release.sums.write_text("0" * 64 + "  other" + chr(10), encoding="utf-8")
        with self.assertRaises(vra.Refused):
            vra.verify(REPO, SHA, self.release.sums, None, [], self.release.runner)

    def test_main_exits_non_zero_on_refusal(self) -> None:
        args = ["--repo", REPO, "--sha", SHA, "--sums", str(self.release.sums), "--dir", str(self.release.dist)]
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(vra.main([*args, "--pattern", "*.tgz", "--pattern", "*.nupkg"], self.release.runner), 0)
        self.assertIn("provenance verified", out.getvalue())
        (self.release.dist / "SourceOrrery.0.3.0.nupkg").write_bytes(b"tampered")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(vra.main([*args, "--pattern", "*.nupkg"], self.release.runner), 1)
        self.assertIn("::error title=release artifacts::", out.getvalue())


if __name__ == "__main__":
    unittest.main()
