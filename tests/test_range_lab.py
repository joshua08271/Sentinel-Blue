import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.actions import ActionExecutor
from sentinel_blue.range_lab import campaign
from sentinel_blue.store import Store


class RangeLabTests(unittest.TestCase):
    def test_end_to_end_campaign(self):
        with patch.object(
            Store,
            "approve_baseline",
            side_effect=AssertionError("campaign bypassed controller baseline approval"),
        ):
            report = campaign(40)
        self.assertEqual(report["scenarios"], 40)
        self.assertGreaterEqual(report["precision"], 0.95)
        self.assertGreaterEqual(report["recall"], 0.95)
        self.assertEqual(report["actions_queued"], report["actions_completed"])
        self.assertEqual(report["baseline_capture_actions"], 40)
        self.assertEqual(report["baseline_capture_receipts"], 80)
        self.assertEqual(
            report["baseline_capture_mode"],
            "non-dry-run disposable files",
        )
        self.assertEqual(report["agent_state_isolation"], "per-agent")

    def test_campaign_uses_one_private_state_tree_per_agent(self):
        state_roots = []

        def tracked_executor(state_dir, *args, **kwargs):
            state_roots.append(Path(state_dir))
            return ActionExecutor(state_dir, *args, **kwargs)

        with patch(
            "sentinel_blue.range_lab.ActionExecutor",
            side_effect=tracked_executor,
        ):
            report = campaign(24)

        self.assertEqual(report["scenarios"], 24)
        self.assertEqual(len(state_roots), 24)
        self.assertEqual(len(set(state_roots)), 24)
        self.assertEqual(
            {path.name for path in state_roots},
            {f"range-agent-{index}" for index in range(24)},
        )

    def test_campaign_beyond_clock_skew_boundary(self):
        report = campaign(350)
        self.assertEqual(report["scenarios"], 350)
        self.assertEqual(report["false_negative"], 0)
        self.assertEqual(report["baseline_capture_actions"], 350)
        self.assertEqual(report["baseline_capture_receipts"], 700)


if __name__ == "__main__":
    unittest.main()
