import unittest

from sentinel_blue.analyzers import analyze_all, analyze_security_events, analyze_services
from sentinel_blue.risk import RiskModel


class AnalyzerTests(unittest.TestCase):
    def test_post_baseline_account_creation_and_failure_burst_are_flagged(self):
        baseline = {"observed_at": 100.0, "accounts": []}
        events = [
            {
                "event_id": "created",
                "category": "account_created",
                "account": "redadmin",
                "actor": "root",
                "remote_address": "local",
                "occurred_at": 101.0,
            }
        ]
        events.extend(
            {
                "event_id": f"failed-{index}",
                "category": "auth_failure",
                "account": "root",
                "actor": "sshd",
                "remote_address": "192.0.2.50",
                "occurred_at": 102.0 + index,
            }
            for index in range(5)
        )
        alerts = analyze_security_events(
            {"accounts": [], "security_events": events}, baseline, set(), RiskModel()
        )
        self.assertEqual(
            {alert.kind for alert in alerts},
            {"security_event_account_created", "authentication_failure_burst"},
        )

    def test_protected_account_change_is_never_suppressed(self):
        events = [
            {
                "event_id": "protected-change",
                "category": "privilege_change",
                "account": "service-monitor-example",
                "actor": "unexpected-admin",
                "remote_address": "local",
                "occurred_at": 101.0,
            },
            {
                "event_id": "audit-change",
                "category": "audit_policy_changed",
                "account": "unknown",
                "actor": "unexpected-admin",
                "remote_address": "local",
                "occurred_at": 102.0,
            },
        ]
        alerts = analyze_security_events(
            {"accounts": [], "security_events": events},
            {"observed_at": 100.0, "accounts": []},
            {"service-monitor-example"},
            RiskModel(),
        )
        self.assertEqual(
            {alert.kind for alert in alerts},
            {"security_event_privilege_change", "security_event_audit_policy_changed"},
        )
    def test_service_restart_loop_is_flagged(self):
        baseline = {
            "services": [
                {
                    "name": "scored-web.service",
                    "state": "running",
                    "start_mode": "enabled",
                    "restart_count": 1,
                    "result": "success",
                }
            ]
        }
        telemetry = {
            "services": [
                {
                    "name": "scored-web.service",
                    "state": "running",
                    "start_mode": "enabled",
                    "restart_count": 5,
                    "result": "exit-code",
                }
            ]
        }
        alerts = analyze_services(telemetry, baseline, RiskModel())
        self.assertEqual(alerts[0].kind, "service_restart_loop")
        self.assertEqual(alerts[0].recommended_action, "snapshot")
    def setUp(self):
        self.baseline = {
            "accounts": [
                {"name": "service-monitor-example", "enabled": True, "privileged": False, "groups": []},
                {"name": "analyst", "enabled": True, "privileged": False, "groups": ["users"]},
            ],
            "services": [{"name": "web", "state": "running", "start_mode": "enabled"}],
            "persistence": [],
            "firewall": {"enabled": True, "provider": "nft", "rules_sha256": "a" * 64},
            "processes": [{"path": "/sbin/init"}],
        }

    def kinds(self, current, protected=None):
        return {
            item.kind
            for item in analyze_all(current, self.baseline, protected or set(), RiskModel())
        }

    def test_protected_identity_loss(self):
        current = {**self.baseline, "accounts": [self.baseline["accounts"][1]]}
        self.assertIn("protected_identity_unavailable", self.kinds(current, {"service-monitor-example"}))

    def test_privilege_membership_change(self):
        accounts = [
            self.baseline["accounts"][0],
            {**self.baseline["accounts"][1], "privileged": True, "groups": ["users", "sudo"]},
        ]
        self.assertIn("privilege_membership_changed", self.kinds({**self.baseline, "accounts": accounts}))

    def test_service_startup_disabled(self):
        current = {**self.baseline, "services": [{"name": "web", "state": "running", "start_mode": "disabled"}]}
        self.assertIn("service_startup_disabled", self.kinds(current))

    def test_persistence_and_firewall_changes(self):
        current = {
            **self.baseline,
            "persistence": [{"kind": "cron", "name": "/etc/cron.d/x", "owner": "root", "enabled": True, "sha256": "b" * 64}],
            "firewall": {"enabled": False, "provider": "nft", "rules_sha256": "c" * 64},
        }
        kinds = self.kinds(current)
        self.assertIn("new_persistence_item", kinds)
        self.assertIn("host_firewall_disabled", kinds)

    def test_privileged_temporary_process(self):
        current = {
            **self.baseline,
            "processes": self.baseline["processes"] + [
                {"name": "x", "path": "/tmp/x", "username": "root", "process_id": 9, "privileged": True}
            ],
        }
        self.assertIn("privileged_temporary_process", self.kinds(current))


if __name__ == "__main__":
    unittest.main()
