import argparse
import unittest
from unittest.mock import patch

from sentinel_blue.selftest import (
    MAX_FUZZ_ITERATIONS,
    MAX_LOAD_EVENTS,
    MAX_SCENARIOS,
    run,
    self_test,
)
from sentinel_blue.store import Store


class SelfTestTests(unittest.TestCase):
    def test_packaged_certification(self):
        with patch.object(
            Store,
            "approve_baseline",
            side_effect=AssertionError("certification bypassed controller baseline approval"),
        ):
            report = self_test(scenarios=20, fuzz_iterations=150, load_events=30)
        self.assertTrue(report["passed"], report)
        self.assertEqual(len(report["checks"]), 15)
        names = {item["name"] for item in report["checks"]}
        self.assertIn("authentication-freshness-boundary", names)
        self.assertIn(
            "controller-alternate-source-fairness-and-error-hygiene", names
        )
        details = {item["name"]: item["detail"] for item in report["checks"]}
        self.assertEqual(details["end-to-end-range"]["baseline_capture_actions"], 20)
        self.assertEqual(details["end-to-end-range"]["baseline_capture_receipts"], 40)
        self.assertEqual(details["bounded-telemetry-load"]["baseline_capture_actions"], 16)
        self.assertEqual(details["bounded-telemetry-load"]["baseline_capture_receipts"], 16)
        recovery = details["authenticated-controller-recovery-and-rollback-floor"]
        self.assertTrue(recovery["manifest_verified"])
        self.assertEqual(recovery["anchor_binding"], "latest")
        self.assertEqual(recovery["rollback_copy_action"], "block")

    def test_full_cli_uses_every_certification_ceiling(self):
        args = argparse.Namespace(
            full=True,
            scenarios=1,
            fuzz_iterations=1,
            load_events=1,
            json=True,
        )
        report = {"passed": True, "checks": [], "duration_seconds": 0.0}
        with patch("sentinel_blue.selftest.self_test", return_value=report) as certify:
            with patch("builtins.print"):
                run(args)
        certify.assert_called_once_with(
            MAX_SCENARIOS,
            MAX_FUZZ_ITERATIONS,
            MAX_LOAD_EVENTS,
        )
        self.assertEqual(
            (MAX_SCENARIOS, MAX_FUZZ_ITERATIONS, MAX_LOAD_EVENTS),
            (5_000, 50_000, 50_000),
        )


if __name__ == "__main__":
    unittest.main()
