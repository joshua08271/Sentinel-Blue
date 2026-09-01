import unittest

from sentinel_blue.detection import detect
from sentinel_blue.risk import RiskModel


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.baseline = {
            "accounts": [{"name": "root", "privileged": True, "enabled": True}],
            "sessions": [],
            "services": [{"name": "web", "state": "running"}],
        }

    def test_protected_privileged_session_is_not_high_priority(self):
        telemetry = {
            **self.baseline,
            "sessions": [
                {
                    "username": "protected-admin-example",
                    "source": "198.51.100.4",
                    "privileged": True,
                    "interactive": True,
                    "process_id": 42,
                }
            ],
            "collector_errors": [],
        }
        alerts = detect(telemetry, self.baseline, {"protected-admin-example"}, RiskModel())
        self.assertFalse([item for item in alerts if item.severity in {"high", "critical"}])

    def test_unknown_uid_zero_account_alerts(self):
        telemetry = {
            **self.baseline,
            "accounts": self.baseline["accounts"]
            + [{"name": "backup", "account_id": "0", "privileged": True, "enabled": True}],
            "collector_errors": [],
        }
        alerts = detect(telemetry, self.baseline, set(), RiskModel())
        self.assertIn("unverified_privileged_account", {item.kind for item in alerts})

    def test_privileged_session_requires_multiple_indicators_before_restriction(self):
        session = {
            "username": "root",
            "source": "198.51.100.4",
            "session_id": "pts/detection-test",
            "process_id": 4242,
            "privileged": True,
            "interactive": True,
            "process_identity": {
                "schema": "sentinel-process-v1",
                "platform": "linux",
                "process_id": 4242,
                "boot_id": "detection-test-boot-0001",
                "start_time": "123456",
                "executable_path": "/usr/sbin/sshd",
                "executable_file_id": "dev:1:ino:2",
                "user_id": "uid:0:0",
                "kernel_session_id": "4242",
            },
        }
        alerts = detect({**self.baseline, "sessions": [session]}, self.baseline, set(), RiskModel())
        alert = next(item for item in alerts if item.kind == "unverified_privileged_session")
        self.assertEqual(alert.recommended_action, "snapshot")
        self.assertFalse(alert.evidence["restriction_supported"])

        telemetry = {
            **self.baseline,
            "sessions": [session],
            "security_events": [
                {
                    "event_id": "auth-1",
                    "category": "auth_success",
                    "account": "root",
                    "remote_address": "198.51.100.4",
                    "occurred_at": 1,
                }
            ],
        }
        alerts = detect(telemetry, self.baseline, set(), RiskModel())
        alert = next(item for item in alerts if item.kind == "unverified_privileged_session")
        self.assertEqual(alert.recommended_action, "quarantine_session")
        self.assertTrue(alert.evidence["restriction_supported"])

    def test_stopped_baseline_service_alerts(self):
        telemetry = {**self.baseline, "services": [{"name": "web", "state": "stopped"}], "collector_errors": []}
        alerts = detect(telemetry, self.baseline, set(), RiskModel())
        self.assertIn("baseline_service_stopped", {item.kind for item in alerts})

    def test_integrity_route_and_probe_failures_alert(self):
        baseline = {
            **self.baseline,
            "integrity": [{"path": "/etc/passwd", "sha256": "a" * 64}],
            "routes": [{"destination": "default", "gateway": "198.51.100.1", "interface": "eth0"}],
        }
        telemetry = {
            **baseline,
            "integrity": [{"path": "/etc/passwd", "sha256": "b" * 64}],
            "routes": [{"destination": "default", "gateway": "198.51.100.254", "interface": "eth0"}],
            "probes": [{"name": "web", "target": "http://198.51.100.10", "healthy": False}],
            "collector_errors": [],
        }
        kinds = {item.kind for item in detect(telemetry, baseline, set(), RiskModel())}
        self.assertTrue(
            {"critical_file_changed", "default_route_changed", "service_probe_failed"}.issubset(kinds)
        )

    def test_security_descriptor_only_drift_is_a_critical_file_change(self):
        baseline = {
            **self.baseline,
            "integrity": [
                {
                    "path": "C:/Windows/System32/drivers/etc/hosts",
                    "sha256": "a" * 64,
                    "security_descriptor_sha256": "b" * 64,
                }
            ],
        }
        telemetry = {
            **baseline,
            "integrity": [
                {
                    **baseline["integrity"][0],
                    "security_descriptor_sha256": "c" * 64,
                }
            ],
            "collector_errors": [],
        }
        alert = next(
            item
            for item in detect(telemetry, baseline, set(), RiskModel())
            if item.kind == "critical_file_changed"
        )
        self.assertEqual(alert.evidence["change_types"], ["security_metadata"])
        self.assertTrue(alert.evidence["security_metadata_changed"])
        self.assertFalse(alert.evidence["security_baseline_upgrade"])

    def test_legacy_security_descriptor_promotion_is_explicit(self):
        baseline = {
            **self.baseline,
            "integrity": [{"path": "C:/protected", "sha256": "a" * 64}],
        }
        telemetry = {
            **baseline,
            "integrity": [
                {
                    "path": "C:/protected",
                    "sha256": "a" * 64,
                    "security_descriptor_sha256": "b" * 64,
                }
            ],
        }
        alert = next(
            item
            for item in detect(telemetry, baseline, set(), RiskModel())
            if item.kind == "critical_file_changed"
        )
        self.assertTrue(alert.evidence["security_baseline_upgrade"])
        self.assertEqual(alert.evidence["change_types"], ["security_metadata"])


if __name__ == "__main__":
    unittest.main()
