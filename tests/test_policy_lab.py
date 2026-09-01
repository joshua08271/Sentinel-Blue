import unittest

from sentinel_blue.__main__ import parser
from sentinel_blue.policy_lab import CASES, competition_policy_campaign


class PolicyLabTests(unittest.TestCase):
    def test_every_competition_policy_case_is_covered_and_passes(self):
        report = competition_policy_campaign(len(CASES), seed=18)
        self.assertTrue(report["passed"], report)
        self.assertTrue(all(report["case_coverage"][name] for name in CASES))
        self.assertFalse(report["real_hosts_modified"])
        self.assertFalse(report["real_competition_attacks"])

    def test_public_cli_exposes_bounded_policy_campaign(self):
        args = parser().parse_args(["policy-lab", "--runs", "50", "--json"])
        self.assertEqual(args.command, "policy-lab")
        self.assertEqual(args.runs, 50)
        self.assertTrue(args.json)


if __name__ == "__main__":
    unittest.main()
