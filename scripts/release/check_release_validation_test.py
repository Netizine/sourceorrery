"""Tests for check-release-validation.py:
python3 -m unittest scripts/release/check_release_validation_test.py

The GitHub API is a fake: each test changes one answer from a commit that
passes, and the gate must refuse it.
"""

from __future__ import annotations

import contextlib
import copy
import importlib.util
import io
import os
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("check_release_validation", HERE / "check-release-validation.py")
crv = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["check_release_validation"] = crv
spec.loader.exec_module(crv)

REPO = "Netizine/sourceorrery"
SHA = "18138d3" + "0" * 33


def passing() -> dict:
    """The API's answers for a commit that may be released."""
    return {
        f"/repos/{REPO}/compare/{SHA}...main": {"status": "ahead"},
        f"/repos/{REPO}/actions/runs?head_sha={SHA}&status=completed&per_page=100": {
            "workflow_runs": [
                {
                    "id": 7,
                    "path": ".github/workflows/ci.yml",
                    "head_sha": SHA,
                    "head_branch": "main",
                    "event": "push",
                    "conclusion": "success",
                    "run_attempt": 1,
                    "head_repository": {"full_name": REPO},
                }
            ]
        },
        f"/repos/{REPO}/actions/runs/7/jobs?per_page=100&filter=latest": {
            "total_count": 3,
            "jobs": [
                {"name": "Changes", "conclusion": "success"},
                {"name": "clippy", "conclusion": "success"},
                {"name": "CI", "conclusion": "success"},
            ],
        },
        f"/repos/{REPO}/commits/{SHA}/check-runs?check_name=CI&per_page=100": {
            "check_runs": [{"name": "CI", "conclusion": "success", "app": {"slug": "github-actions"}}]
        },
    }


def getter(answers: dict):
    def get(path: str):
        answer = answers.get(path)
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            raise urllib.error.HTTPError(path, 404, "Not Found", None, None)
        return answer

    return get


def runs(answers: dict) -> list:
    return answers[f"/repos/{REPO}/actions/runs?head_sha={SHA}&status=completed&per_page=100"]["workflow_runs"]


def jobs(answers: dict, run: int = 7) -> dict:
    return answers[f"/repos/{REPO}/actions/runs/{run}/jobs?per_page=100&filter=latest"]


class GateTest(unittest.TestCase):
    def refused(self, answers: dict, says: str, sha: str = SHA) -> None:
        with self.assertRaises(crv.Refused) as caught:
            crv.check(getter(answers), REPO, sha)
        self.assertIn(says, str(caught.exception))

    def test_a_fully_validated_commit_on_main_passes(self) -> None:
        evidence = crv.check(getter(passing()), REPO, SHA)
        self.assertEqual(len(evidence), 3)
        self.assertIn("3 jobs, all success", evidence[1])

    def test_a_commit_not_on_main_is_refused(self) -> None:
        for status in ("diverged", "behind"):
            answers = passing()
            answers[f"/repos/{REPO}/compare/{SHA}...main"] = {"status": status}
            self.refused(answers, "is not on main")

    def test_only_a_full_sha_is_accepted(self) -> None:
        self.refused(passing(), "is not a full commit SHA", sha="18138d3")

    def test_a_run_that_is_not_mains_ci_does_not_count(self) -> None:
        changes = [
            ("head_branch", "feature"),
            ("event", "pull_request"),
            ("path", ".github/workflows/ci-copy.yml"),
            ("conclusion", "failure"),
            ("head_sha", "f" * 40),
            ("head_repository", {"full_name": "someone/fork"}),
        ]
        for key, value in changes:
            answers = passing()
            runs(answers)[0][key] = value
            self.refused(answers, "no successful run", sha=SHA)

    def test_a_docs_only_or_cancelled_run_is_refused(self) -> None:
        for conclusion in ("skipped", "cancelled", "failure", None):
            answers = passing()
            jobs(answers)["jobs"][1]["conclusion"] = conclusion
            self.refused(answers, f"clippy ({conclusion})")

    def test_jobs_that_cannot_all_be_read_are_refused(self) -> None:
        answers = passing()
        jobs(answers)["total_count"] = 150
        self.refused(answers, "could not all be read")

    def test_a_later_complete_attempt_is_accepted(self) -> None:
        answers = passing()
        second = copy.deepcopy(runs(answers)[0])
        second.update({"id": 8, "run_attempt": 2})
        runs(answers).append(second)
        jobs(answers)["jobs"][1]["conclusion"] = "cancelled"
        answers[f"/repos/{REPO}/actions/runs/8/jobs?per_page=100&filter=latest"] = copy.deepcopy(passing()[
            f"/repos/{REPO}/actions/runs/7/jobs?per_page=100&filter=latest"
        ])
        evidence = crv.check(getter(answers), REPO, SHA)
        self.assertIn("CI run 8", evidence[1])

    def test_a_ci_check_from_another_app_does_not_count(self) -> None:
        answers = passing()
        answers[f"/repos/{REPO}/commits/{SHA}/check-runs?check_name=CI&per_page=100"] = {
            "check_runs": [{"name": "CI", "conclusion": "success", "app": {"slug": "lookalike"}}]
        }
        self.refused(answers, "reported by GitHub Actions")

    def test_an_api_failure_refuses(self) -> None:
        for path in list(passing()):
            answers = passing()
            answers[path] = urllib.error.URLError("connection reset")
            self.refused(answers, "the GitHub API could not be read")
        answers = passing()
        answers[f"/repos/{REPO}/compare/{SHA}...main"] = ValueError("not JSON")
        self.refused(answers, "could not be read")

    def test_main_fails_a_real_run_and_warns_in_a_dry_run(self) -> None:
        answers = passing()
        jobs(answers)["jobs"][1]["conclusion"] = "skipped"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = crv.main(["--repo", REPO, "--sha", SHA], getter=getter(answers))
        self.assertEqual(status, 1)
        self.assertIn("::error title=release validation::", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            status = crv.main(["--repo", REPO, "--sha", SHA, "--warn-only"], getter=getter(answers))
        self.assertEqual(status, 0)
        self.assertIn("::warning title=release validation::", out.getvalue())
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(crv.main(["--repo", REPO, "--sha", SHA], getter=getter(passing())), 0)

    def test_a_dry_run_that_builds_the_commit_still_needs_it_on_main(self) -> None:
        dry_run = ["--repo", REPO, "--sha", SHA, "--warn-only", "--require-main"]
        for answer in ({"status": "diverged"}, urllib.error.URLError("connection reset")):
            answers = passing()
            answers[f"/repos/{REPO}/compare/{SHA}...main"] = answer
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(crv.main(dry_run, getter=getter(answers)), 1)
            self.assertIn("::error title=release validation::", out.getvalue())
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(crv.main(dry_run[:3] + ["18138d3"] + dry_run[4:], getter=getter(passing())), 1)
        self.assertIn("is not a full commit SHA", out.getvalue())
        # On main, an incomplete CI run is still only reported.
        answers = passing()
        jobs(answers)["jobs"][1]["conclusion"] = "skipped"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(crv.main(dry_run, getter=getter(answers)), 0)
        self.assertIn("::warning title=release validation::", out.getvalue())

    def test_no_token_fails_unless_the_run_only_reports(self) -> None:
        cases = [([], 1), (["--warn-only"], 0), (["--warn-only", "--require-main"], 1)]
        for extra, status in cases:
            out = io.StringIO()
            with mock.patch.dict(os.environ, {}, clear=True), contextlib.redirect_stdout(out):
                self.assertEqual(crv.main(["--repo", REPO, "--sha", SHA, *extra]), status, extra)
            self.assertIn("GH_TOKEN is not set", out.getvalue())


if __name__ == "__main__":
    unittest.main()
