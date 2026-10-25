"""Tests for harness.py:
python3 -m unittest tests/conformance/sdk/harness_test.py

The harness decides what counts as conformance: which scenarios run, in
what environment, and when a skipped one is a failure. These check those
decisions without a runner.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("harness", HERE / "harness.py")
harness = importlib.util.module_from_spec(spec)
assert spec.loader is not None
sys.modules["harness"] = harness
spec.loader.exec_module(harness)

VALUES = {"vault": "ci", "home": "/h", "recovery_key": "QX7F-2MVA", "manifest": "/m", "old_version": "v1"}


class HarnessTest(unittest.TestCase):
    def test_a_scenario_sets_and_removes_variables_for_its_runner_only(self) -> None:
        base = {"SOURCEORRERY_RECOVERY_KEY": "KEY", "SOURCEORRERY_HOME": "/h", "PATH": "/bin"}
        scenario = {
            "unset": ["SOURCEORRERY_RECOVERY_KEY", "NOT_SET_ANYWAY"],
            "env": {"SOURCEORRERY_RECOVERY_KEY_FILE": "${home}/no-such.key"},
        }
        environment = harness.scenario_environment(scenario, VALUES, base)
        self.assertNotIn("SOURCEORRERY_RECOVERY_KEY", environment)
        self.assertEqual(environment["SOURCEORRERY_RECOVERY_KEY_FILE"], "/h/no-such.key")
        self.assertEqual(environment["PATH"], "/bin")
        self.assertEqual(base["SOURCEORRERY_RECOVERY_KEY"], "KEY", "the fixture's environment is not changed")
        self.assertEqual(harness.scenario_environment({}, VALUES, base), base)

    def test_scenarios_that_need_a_provider_are_skipped_without_it_and_counted(self) -> None:
        scenarios = [{"id": "local"}, {"id": "remote", "requires": "remote"}, {"id": "per", "requires": "remote-per-version"}]
        selected, skipped = harness.select(scenarios, [], {None})
        self.assertEqual([s["id"] for s in selected], ["local"])
        self.assertEqual([s["id"] for s in skipped], ["remote", "per"])
        selected, skipped = harness.select(scenarios, [], {None, "remote"})
        self.assertEqual([s["id"] for s in skipped], ["per"])
        selected, skipped = harness.select(scenarios, ["remote"], {None})
        self.assertEqual((selected, [s["id"] for s in skipped]), ([], ["remote"]))

    def test_a_skipped_provider_scenario_fails_where_live_runs_are_required(self) -> None:
        skipped = [{"id": "remote", "requires": "remote"}, {"id": "per", "requires": "remote-per-version"}]
        required = {"SOURCEORRERY_LIVE_REQUIRED": "true"}
        self.assertEqual([s["id"] for s in harness.live_required_but_skipped(skipped, required)], ["remote"])
        self.assertEqual(harness.live_required_but_skipped(skipped[1:], required), [], "per-version is the provider's capability")
        self.assertEqual(harness.live_required_but_skipped(skipped, {}), [])
        self.assertEqual(harness.live_required_but_skipped(skipped, {"SOURCEORRERY_LIVE_REQUIRED": "false"}), [])

    def test_expectations_on_messages_and_hints(self) -> None:
        expect = {
            "outcome": "error",
            "code": "io",
            "hint_contains": ["SOURCEORRERY_RECOVERY_KEY_FILE"],
            "message_contains": ["no-such.key"],
            "hint_excludes": ["${recovery_key}"],
        }
        observed = {"outcome": "error", "code": "io", "message": "cannot read /h/no-such.key", "hint": "SOURCEORRERY_RECOVERY_KEY_FILE was needed"}
        harness.check(expect, observed, VALUES)
        with self.assertRaises(harness.Failure):
            harness.check(expect, dict(observed, hint="SOURCEORRERY_RECOVERY_KEY_FILE and QX7F-2MVA"), VALUES)
        with self.assertRaises(harness.Failure):
            harness.check(expect, dict(observed, code="locked"), VALUES)

    def test_every_scenario_is_well_formed(self) -> None:
        import json

        scenarios = json.loads((HERE / "scenarios.json").read_text(encoding="utf-8"))["scenarios"]
        ids = [s["id"] for s in scenarios]
        self.assertEqual(len(ids), len(set(ids)), "scenario ids are unique")
        for scenario in scenarios:
            for key in ("id", "about", "op", "args", "expect"):
                self.assertIn(key, scenario, scenario["id"])
            self.assertIn(scenario.get("requires"), (None, "remote", "remote-per-version"), scenario["id"])
            self.assertIsInstance(scenario.get("env", {}), dict, scenario["id"])
            self.assertIsInstance(scenario.get("unset", []), list, scenario["id"])
            unknown = set(scenario) - {"id", "about", "op", "args", "expect", "requires", "env", "unset"}
            self.assertEqual(unknown, set(), scenario["id"])


if __name__ == "__main__":
    unittest.main()
