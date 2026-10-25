#!/usr/bin/env python3
"""Cross-language SDK conformance harness.

Runs every scenario in scenarios.json through one SDK's runner and compares
what the runner observed with the scenario's expectations, so each language
is held to the same contract (tests/conformance/sdk/README.md).

    python tests/conformance/sdk/harness.py --runner python
    python tests/conformance/sdk/harness.py --runner cpp --command build/conformance_cpp
    python tests/conformance/sdk/harness.py --list

The fixture vault must exist and its variables must be in the environment
(`eval "$(bash scripts/ci/fixture-vault.sh)"`). Exit status is 0 only when
every scenario passes.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
SCENARIOS = HERE / "scenarios.json"

EXE = ".exe" if os.name == "nt" else ""

# Default runner commands, relative to the repository root. CI builds the
# compiled ones first and passes --command with the built binary.
RUNNERS = {
    "rust": [f"target/release/examples/conformance{EXE}"],
    "python": [sys.executable, "bindings/python/conformance/run.py"],
    "node": ["node", "bindings/node/conformance/run.mjs"],
    "java": ["java", "--enable-native-access=ALL-UNNAMED", "-cp", "bindings/java/target/classes", "bindings/java/conformance/Run.java"],
    "dotnet": ["dotnet", "bindings/dotnet/conformance/bin/Release/net10.0/Conformance.dll"],
    "go": [f"bindings/go/conformance-go{EXE}"],
    "c": [f"build/conformance_c{EXE}"],
    "cpp": [f"build/conformance_cpp{EXE}"],
    "php": ["php", "bindings/php/conformance/run.php"],
}

ENV_VARIABLES = {
    "vault": "SOURCEORRERY_TEST_VAULT",
    "home": "SOURCEORRERY_HOME",
    "recovery_key": "SOURCEORRERY_RECOVERY_KEY",
    "manifest": "SOURCEORRERY_TEST_MANIFEST",
    "old_version": "SOURCEORRERY_TEST_OLD_VERSION",
}

# What the scenarios marked `"requires": "remote"` need besides the fixture:
# the manifest fixture-vault.sh writes when it is given a provider's
# connection flags, and the secrets it then keeps at that provider. Set by
# the provider CI jobs, which run those scenarios with --remote; absent
# otherwise, and the scenarios are skipped.
REMOTE_VARIABLES = {
    "remote_manifest": "SOURCEORRERY_TEST_REMOTE_MANIFEST",
}


class Failure(Exception):
    """One expectation that did not hold."""


def variables(remote: bool = False) -> dict[str, str]:
    values = {}
    missing = []
    required = dict(ENV_VARIABLES, **REMOTE_VARIABLES) if remote else ENV_VARIABLES
    for name, env in required.items():
        value = os.environ.get(env, "")
        if not value:
            missing.append(env)
        values[name] = value
    if missing:
        how = "with a provider's connection flags" if remote else "first"
        sys.exit(f"harness: {', '.join(missing)} not set; run scripts/ci/fixture-vault.sh {how}")
    return values


def substitute(text, values: dict[str, str]):
    if isinstance(text, str):
        for name, value in values.items():
            text = text.replace("${" + name + "}", value)
        return text
    if isinstance(text, list):
        return [substitute(item, values) for item in text]
    if isinstance(text, dict):
        return {key: substitute(item, values) for key, item in text.items()}
    return text


def scenario_environment(scenario: dict, values: dict[str, str], base: dict[str, str] | None = None) -> dict[str, str]:
    """The runner's environment: the fixture's, with the scenario's `env`
    set and its `unset` removed, so a scenario can vary where a key comes
    from without a runner knowing about it."""
    environment = dict(os.environ if base is None else base)
    for name in scenario.get("unset", []):
        environment.pop(name, None)
    environment.update(substitute(scenario.get("env", {}), values))
    return environment


def select(scenarios: list[dict], only: list[str], allowed: set) -> tuple[list[dict], list[dict]]:
    """The scenarios to run, and those skipped because what they require
    was not asked for (`--only` leaves the rest out without counting them)."""
    wanted = [s for s in scenarios if not only or s["id"] in only]
    return [s for s in wanted if s.get("requires") in allowed], [s for s in wanted if s.get("requires") not in allowed]


def run_scenario(command: list[str], scenario: dict, values: dict[str, str]) -> tuple[dict[str, str], str]:
    args = [f"{key}={value}" for key, value in substitute(scenario["args"], values).items()]
    completed = subprocess.run(
        [*command, scenario["op"], *args],
        cwd=ROOT,
        env=scenario_environment(scenario, values),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    observed: dict[str, str] = {}
    for line in completed.stdout.splitlines():
        if "\t" not in line:
            continue
        key, value = line.split("\t", 1)
        observed[key.strip()] = value
    if completed.returncode != 0 and "outcome" not in observed:
        raise Failure(f"runner exited with {completed.returncode}: {completed.stderr.strip()[-800:]}")
    derive_from_json(observed)
    return observed, completed.stderr


def properties_fields(props: dict) -> dict[str, str]:
    fields = {
        "version": props.get("version", ""),
        "enabled": "true" if props.get("enabled") else "false",
        "content_type": props.get("content_type", "") or "",
        "reference": f"sourceorrery://{props.get('vault')}/{props.get('name')}/{props.get('version')}",
    }
    for key, value in (props.get("tags") or {}).items():
        fields[f"tag.{key}"] = value
    return fields


def derive_from_json(observed: dict[str, str]) -> None:
    """Runners over the raw C ABI hand the core's JSON over verbatim."""
    if "properties_json" in observed and "version" not in observed:
        observed.update(properties_fields(json.loads(observed["properties_json"])))
    if "descriptor_json" in observed and "descriptor.name" not in observed:
        descriptor = json.loads(observed["descriptor_json"])
        observed["descriptor.name"] = descriptor.get("name", "")
        observed["descriptor.protectors"] = ",".join(descriptor.get("protectors", []))
    if "project_info_json" in observed and "project.name" not in observed:
        info = json.loads(observed["project_info_json"])
        observed["project.name"] = info.get("name", "")
        observed["project.count"] = str(info.get("count", 0))
    if "project.names" not in observed and any(k.startswith("entry.") for k in observed):
        names = []
        index = 0
        while f"entry.{index}.json" in observed:
            entry = json.loads(observed[f"entry.{index}.json"])
            names.append(entry["name"])
            observed[f"secret.{entry['env']}"] = observed.get(f"entry.{index}.value", "")
            index += 1
        observed["project.names"] = ",".join(sorted(names))
        observed.setdefault("project.count", str(len(names)))


def check(expect: dict, observed: dict[str, str], values: dict[str, str]) -> None:
    values = dict(values, version=observed.get("version", ""))
    expect = substitute(expect, values)

    def need(key: str) -> str:
        if key not in observed:
            raise Failure(f"runner reported no `{key}` (reported: {', '.join(sorted(observed)) or 'nothing'})")
        return observed[key]

    def equal(key: str, wanted) -> None:
        got = need(key)
        if isinstance(wanted, bool):
            wanted = "true" if wanted else "false"
            got = got.lower()
        elif isinstance(wanted, int):
            wanted = str(wanted)
        if got != wanted:
            raise Failure(f"{key}: expected {wanted!r}, got {got!r}")

    equal("outcome", expect["outcome"])
    if expect["outcome"] == "error":
        equal("code", expect["code"])
    for key in ("value", "content_type", "message", "descriptor.name", "project.name", "project.count", "reference"):
        if key in expect:
            equal(key, expect[key])
    if "version" in expect:
        wanted = expect["version"]
        got = need("version")
        if isinstance(wanted, dict):
            if got == wanted["not"]:
                raise Failure(f"version: expected anything but {wanted['not']!r}")
        else:
            equal("version", wanted)
    if "enabled" in expect:
        equal("enabled", expect["enabled"])
    if "transient" in expect:
        equal("transient", expect["transient"])
    for key, wanted in expect.get("tags", {}).items():
        equal(f"tag.{key}", wanted)
    for key in ("hint", "message"):
        for needle in expect.get(f"{key}_contains", []):
            if needle not in need(key):
                raise Failure(f"{key} does not contain {needle!r}: {observed[key]!r}")
        for needle in expect.get(f"{key}_excludes", []):
            if needle in observed.get(key, ""):
                raise Failure(f"{key} must not contain {needle!r}: {observed[key]!r}")
        if f"{key}_starts_with" in expect and not need(key).startswith(expect[f"{key}_starts_with"]):
            raise Failure(f"{key} does not start with {expect[f'{key}_starts_with']!r}: {observed[key]!r}")
    for needle in expect.get("descriptor.protectors_contains", []):
        if needle not in need("descriptor.protectors").split(","):
            raise Failure(f"descriptor.protectors lacks {needle!r}: {observed['descriptor.protectors']!r}")
    for env, wanted in expect.get("project.secrets", {}).items():
        equal(f"secret.{env}", wanted)
    if "project.absent" in expect:
        names = set(filter(None, need("project.names").split(",")))
        for name in expect["project.absent"]:
            if name in names:
                raise Failure(f"project should not contain {name!r}: {sorted(names)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runner", choices=sorted(RUNNERS), help="which SDK to drive")
    parser.add_argument("--command", help="runner command line, overriding the default for --runner")
    parser.add_argument("--only", action="append", default=[], help="run only this scenario id (repeatable)")
    parser.add_argument("--list", action="store_true", help="list scenarios and exit")
    parser.add_argument("--verbose", "-v", action="store_true", help="print every observation")
    parser.add_argument(
        "--remote",
        action="store_true",
        help="also run the scenarios that read secrets kept at a provider (a fixture made with connection flags, SOURCEORRERY_TEST_REMOTE_MANIFEST)",
    )
    parser.add_argument(
        "--remote-per-version",
        action="store_true",
        help="with --remote: the remote provider keeps properties per version, so run the scenarios that need that too",
    )
    options = parser.parse_args()

    scenarios = json.loads(SCENARIOS.read_text(encoding="utf-8"))["scenarios"]
    if options.list:
        for scenario in scenarios:
            print(f"{scenario['id']:32} {scenario['op']:20} {scenario['about']}")
        return 0
    if not options.runner and not options.command:
        parser.error("--runner or --command is required")

    command = shlex.split(options.command, posix=os.name != "nt") if options.command else list(RUNNERS[options.runner])
    # A relative runner path is relative to the repository; Windows would
    # otherwise resolve it against the harness's own working directory.
    if (ROOT / command[0]).exists():
        command[0] = str(ROOT / command[0])
    elif len(command) == 1 and not Path(command[0]).exists():
        sys.exit(f"harness: runner {command[0]} does not exist; build it first (see tests/conformance/sdk/README.md)")
    values = variables(options.remote)
    label = options.runner or command[0]

    failures = 0
    allowed = {None}
    if options.remote:
        allowed.add("remote")
        if options.remote_per_version:
            allowed.add("remote-per-version")
    selected, skipped = select(scenarios, options.only, allowed)
    for scenario in skipped:
        flag = "--remote --remote-per-version" if scenario["requires"] == "remote-per-version" else "--remote"
        print(f"SKIP  {scenario['id']}: requires {scenario['requires']} ({flag})")
    for scenario in selected:
        try:
            observed, stderr = run_scenario(command, scenario, values)
            check(scenario["expect"], observed, values)
            print(f"PASS  {scenario['id']}")
            if options.verbose:
                for key in sorted(observed):
                    print(f"        {key} = {observed[key]}")
        except Failure as failure:
            failures += 1
            print(f"FAIL  {scenario['id']}: {failure}")
        except (OSError, json.JSONDecodeError) as err:
            failures += 1
            print(f"FAIL  {scenario['id']}: cannot run the runner: {err}")
    total = len(selected)
    print(f"\n{label}: {total - failures}/{total} scenarios passed, {len(skipped)} skipped")
    unrun = live_required_but_skipped(skipped)
    if unrun:
        print(f"{label}: SOURCEORRERY_LIVE_REQUIRED=true, but {len(unrun)} scenarios at a provider were not run")
        return 1
    return 1 if failures else 0


def live_required_but_skipped(skipped: list[dict], environment: dict[str, str] | None = None) -> list[dict]:
    """Where the live suites must run (SOURCEORRERY_LIVE_REQUIRED=true, as
    for tests/conformance/src/live.rs: a provider job, a release rehearsal),
    a scenario at a provider that was skipped is a failure, never coverage.
    `remote-per-version` alone stays a skip: that the provider keeps
    properties per secret is the job's statement, not a missing service."""
    environment = os.environ if environment is None else environment
    if environment.get("SOURCEORRERY_LIVE_REQUIRED") != "true":
        return []
    return [s for s in skipped if s.get("requires") == "remote"]


if __name__ == "__main__":
    sys.exit(main())
