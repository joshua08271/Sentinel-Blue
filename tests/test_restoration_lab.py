import unittest

from sentinel_blue.__main__ import parser
from sentinel_blue.restoration_lab import CASES, restoration_policy_campaign


class RestorationLabTests(unittest.TestCase):
    def test_public_cli_exposes_bounded_restoration_campaign(self):
        args = parser().parse_args(["restoration-lab", "--runs", "25", "--json"])
        self.assertEqual(args.command, "restoration-lab")
        self.assertEqual(args.runs, 25)
        self.assertTrue(args.json)

    def test_every_policy_case_is_covered_and_passes(self):
        report = restoration_policy_campaign(len(CASES), seed=7)
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["scenarios"], len(CASES))
        self.assertTrue(all(report["case_coverage"][name] >= 1 for name in CASES))


if __name__ == "__main__":
    unittest.main()
