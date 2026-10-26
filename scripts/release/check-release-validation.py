#!/usr/bin/env python3
"""Refuse a release whose source commit was not validated in full.

    python3 scripts/release/check-release-validation.py --repo OWNER/NAME \\
        --sha COMMIT [--warn-only [--require-main]]

A commit may be released only when all of these hold, each read from the
GitHub API with the workflow's token:

1. it is on `main` (`main` is it or descends from it);
2. a completed run of `.github/workflows/ci.yml` in this repository, for
   exactly this commit, on `main`, triggered by a push or a dispatch,
   concluded `success`;
3. every job of that run concluded `success`: none skipped, so a docs-only
   run (which skips the build jobs) is refused, as is a cancelled one;
4. the commit's `CI` check, the one the branch rule requires, was reported
   by the GitHub Actions app and concluded `success`, so a check of the
   same name from another app does not count.

A docs-only commit gets a full run by dispatching CI on `main` (the change
classifier treats a dispatch as code). Any API error, or an answer that
cannot be read, refuses: an unknown is never a pass. With --warn-only (a dry
run) the verdict is printed as warning annotations and the exit status is 0,
so a dry run exercises the same gate without needing a releasable commit.
With --require-main as well, rule 1 still refuses, as does a SHA or an
answer that cannot decide it: a dry run that builds the selected commit in
jobs able to publish (ReleasePackages.yaml) runs only code already on main.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Callable

API = "https://api.github.com"
CI_WORKFLOW = ".github/workflows/ci.yml"
REQUIRED_CHECK = "CI"
ACTIONS_APP = "github-actions"
TRIGGERS = ("push", "workflow_dispatch")

Getter = Callable[[str], Any]


class Refused(Exception):
    """The commit may not be released; the message says why."""


class NotOnMain(Refused):
    """Rule 1 failed, or could not be decided: the commit is not known to be on main."""


def github_get(token: str) -> Getter:
    """A GET against the GitHub REST API with `token`; the parsed JSON."""

    def get(path: str) -> Any:
        request = urllib.request.Request(
            f"{API}{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {token}",
                "X-GitHub-Api-Version": "2022-11-28",
            },
        )
        with urllib.request.urlopen(request, timeout=60) as answer:  # noqa: S310 - fixed https URL
            return json.load(answer)

    return get


def fetch(get: Getter, path: str) -> Any:
    """`get(path)`, with every failure turned into a refusal."""
    try:
        return get(path)
    except (OSError, ValueError, urllib.error.URLError) as err:
        raise Refused(f"the GitHub API could not be read ({path}): {err}") from err


def check(get: Getter, repo: str, sha: str) -> list[str]:
    """What shows `sha` was validated; raises Refused when it was not."""
    if len(sha) != 40 or any(c not in "0123456789abcdef" for c in sha):
        raise NotOnMain(f"'{sha}' is not a full commit SHA")
    evidence = []

    try:
        compare = fetch(get, f"/repos/{repo}/compare/{sha}...main")
    except Refused as refusal:
        raise NotOnMain(str(refusal)) from refusal
    if compare.get("status") not in ("identical", "ahead"):
        raise NotOnMain(f"{sha} is not on main (main is {compare.get('status', 'unknown')} of it)")
    evidence.append(f"{sha} is on main ({compare['status']})")

    runs = fetch(get, f"/repos/{repo}/actions/runs?head_sha={sha}&status=completed&per_page=100")
    candidates = [
        run
        for run in runs.get("workflow_runs", [])
        if run.get("path") == CI_WORKFLOW
        and run.get("head_sha") == sha
        and run.get("head_branch") == "main"
        and run.get("event") in TRIGGERS
        and (run.get("head_repository") or {}).get("full_name") == repo
        and run.get("conclusion") == "success"
    ]
    if not candidates:
        raise Refused(
            f"no successful run of {CI_WORKFLOW} on main for {sha}; push it to main or dispatch CI there"
        )
    reasons = []
    for run in sorted(candidates, key=lambda r: r.get("run_attempt", 0), reverse=True):
        jobs = fetch(get, f"/repos/{repo}/actions/runs/{run['id']}/jobs?per_page=100&filter=latest")
        listed = jobs.get("jobs", [])
        if not listed or jobs.get("total_count", len(listed)) != len(listed):
            reasons.append(f"run {run['id']}: its jobs could not all be read")
            continue
        incomplete = [
            f"{job.get('name')} ({job.get('conclusion')})"
            for job in listed
            if job.get("conclusion") != "success"
        ]
        if incomplete:
            reasons.append(f"run {run['id']}: not every job ran and passed: {', '.join(incomplete)}")
            continue
        evidence.append(f"CI run {run['id']} ({run['event']}): {len(listed)} jobs, all success")
        break
    else:
        raise Refused(
            "no complete CI run: "
            + "; ".join(reasons)
            + " (a docs-only run skips the build jobs: dispatch CI on main for a full run)"
        )

    checks = fetch(get, f"/repos/{repo}/commits/{sha}/check-runs?check_name={REQUIRED_CHECK}&per_page=100")
    trusted = [
        run
        for run in checks.get("check_runs", [])
        if run.get("name") == REQUIRED_CHECK
        and (run.get("app") or {}).get("slug") == ACTIONS_APP
        and run.get("conclusion") == "success"
    ]
    if not trusted:
        raise Refused(f"the {REQUIRED_CHECK} check of {sha} did not pass as reported by GitHub Actions")
    evidence.append(f"{REQUIRED_CHECK} check passed, reported by {ACTIONS_APP}")
    return evidence


def main(argv: list[str] | None = None, getter: Getter | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repo", required=True)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--warn-only", action="store_true", help="report, do not fail (dry runs)")
    parser.add_argument(
        "--require-main",
        action="store_true",
        help="with --warn-only, still fail a commit not known to be on main",
    )
    args = parser.parse_args(argv)
    if getter is None:
        token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
        if not token:
            print("::error title=release validation::GH_TOKEN is not set")
            return 0 if args.warn_only and not args.require_main else 1
        getter = github_get(token)
    try:
        evidence = check(getter, args.repo, args.sha.lower())
    except Refused as refusal:
        fatal = not args.warn_only or (args.require_main and isinstance(refusal, NotOnMain))
        level = "error" if fatal else "warning"
        print(f"::{level} title=release validation::{refusal}")
        return 1 if fatal else 0
    for line in evidence:
        print(f"validated: {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
