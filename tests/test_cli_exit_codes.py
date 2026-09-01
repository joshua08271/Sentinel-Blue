import argparse
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from sentinel_blue import diagnostics, policy_lab, range_lab, restoration_lab, selftest
from sentinel_blue.__main__ import main


class CLIExitCodeTests(unittest.TestCase):
    def _json_cases(self, passed):
        return (
            (
                selftest.run,
                "sentinel_blue.selftest.self_test",
                argparse.Namespace(
                    full=False,
                    scenarios=1,
                    fuzz_iterations=1,
                    load_events=1,
                    json=True,
                ),
                {"passed": passed},
            ),
            (
                policy_lab.run,
                "sentinel_blue.policy_lab.competition_policy_campaign",
                argparse.Namespace(runs=1, json=True),
                {"passed": passed},
            ),
            (
                restoration_lab.run,
                "sentinel_blue.restoration_lab.restoration_policy_campaign",
                argparse.Namespace(runs=1, json=True),
                {"passed": passed},
            ),
            (
                range_lab.run,
                "sentinel_blue.range_lab.campaign",
                argparse.Namespace(runs=1, json=True),
                {
                    "false_negative": 0 if passed else 1,
                    "false_positive": 0,
                    "actions_queued": 1,
                    "actions_completed": 1,
                    "protocol_fuzz": {"passed": True},
                },
            ),
            (
                diagnostics.run,
                "sentinel_blue.diagnostics.doctor",
                argparse.Namespace(
                    command="doctor",
                    state_dir="unused",
                    database=None,
                    json=True,
                ),
                {"ready": passed},
            ),
        )

    def test_json_certification_commands_return_failure_status(self):
        for runner, target, args, report in self._json_cases(False):
            with self.subTest(target=target):
                output = io.StringIO()
                with patch(target, return_value=report), contextlib.redirect_stdout(output):
                    exit_code = runner(args)
                self.assertEqual(exit_code, 1)
                self.assertEqual(json.loads(output.getvalue()), report)

    def test_json_certification_commands_return_success_status(self):
        for runner, target, args, report in self._json_cases(True):
            with self.subTest(target=target):
                output = io.StringIO()
                with patch(target, return_value=report), contextlib.redirect_stdout(output):
                    exit_code = runner(args)
                self.assertEqual(exit_code, 0)
                self.assertEqual(json.loads(output.getvalue()), report)

    def test_main_propagates_a_failed_certification_status(self):
        args = argparse.Namespace(command="self-test")
        with (
            patch("sentinel_blue.__main__.parser") as make_parser,
            patch("sentinel_blue.selftest.run", return_value=1),
        ):
            make_parser.return_value.parse_args.return_value = args
            with self.assertRaisesRegex(SystemExit, "1"):
                main()


if __name__ == "__main__":
    unittest.main()
