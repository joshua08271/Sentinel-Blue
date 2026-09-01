import unittest

from sentinel_blue.correlation import correlate


class CorrelationTests(unittest.TestCase):
    def test_groups_open_alerts_by_agent_and_window(self):
        alerts = [
            {"alert_id": "1", "agent_id": "a", "status": "open", "severity": "high", "kind": "account", "created_at": 100},
            {"alert_id": "2", "agent_id": "a", "status": "open", "severity": "critical", "kind": "route", "created_at": 110},
            {"alert_id": "3", "agent_id": "a", "status": "decided", "severity": "critical", "kind": "old", "created_at": 115},
        ]
        result = correlate(alerts)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["alert_count"], 2)
        self.assertEqual(result[0]["severity"], "critical")


if __name__ == "__main__":
    unittest.main()
