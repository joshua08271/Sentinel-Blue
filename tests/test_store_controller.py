import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import MagicMock, patch

from sentinel_blue.controller import (
    ControllerApp,
    assess_baseline_readiness,
    relay_probe_loop,
)
from sentinel_blue.protocol import ProbeResult
from sentinel_blue.store import Store


def _capture_result(action) -> dict:
    now = time.time()
    files = list(action.parameters["files"])
    return {
        "action_id": action.action_id,
        "action_type": "capture_restore_point",
        "success": True,
        "message": "captured exact restore points",
        "started_at": now,
        "completed_at": now,
        "dry_run": False,
        "captured": [item["path"] for item in files],
        "rejected": [],
        "capture_receipts": [
            {
                "path": item["path"],
                "source_sha256": item["sha256"],
                "backup_sha256": item["sha256"],
                "backup_matches_source": True,
                "byte_size": item.get("size", 0),
                "security_metadata_sha256": "c" * 64,
                "security_descriptor_sha256": item.get(
                    "security_descriptor_sha256", ""
                ),
                "restore_point_id": str(uuid.uuid4()),
                "stored": True,
            }
            for item in files
        ],
    }


def _dispatch_baseline_capture(app: ControllerApp, agent_id: str):
    approval = app.approve_baseline(agent_id)
    if not approval or approval.get("approved") is True:
        raise AssertionError("integrity baseline did not enter pending promotion")
    actions = [
        item
        for item in app.pending_actions_for_agent(agent_id)
        if item.action_id == approval["restore_point_action_id"]
    ]
    if len(actions) != 1 or actions[0].action_type != "capture_restore_point":
        raise AssertionError("exact restore-point capture was not dispatched")
    return approval, actions[0]


def _complete_baseline_capture(
    app: ControllerApp, store: Store, agent_id: str, action
) -> None:
    if app.complete_action(_capture_result(action), agent_id) != "new":
        raise AssertionError("receipt-bound baseline promotion did not complete")
    if store.baseline_status(agent_id) != "approved":
        raise AssertionError("baseline remained unapproved after exact capture receipts")


def _promote_integrity_baseline(app: ControllerApp, store: Store, agent_id: str):
    approval, action = _dispatch_baseline_capture(app, agent_id)
    _complete_baseline_capture(app, store, agent_id, action)
    return approval, action


class ControllerTests(unittest.TestCase):
    def test_relay_probes_receive_the_complete_event_scope(self):
        app = MagicMock()
        app.authorized_networks = ["203.0.113.0/24"]
        app.authorized_hosts = ["203.0.113.7"]
        app.excluded_hosts = ["203.0.113.99"]
        app.event_profile.profile_id = "profile"
        app.event_profile.fingerprint = "a" * 64
        stop = MagicMock()
        stop.is_set.side_effect = [False, True]
        healthy = ProbeResult("web", "203.0.113.7", True)
        with patch("sentinel_blue.probes.run_probes", return_value=[healthy]) as runner:
            relay_probe_loop(app, [{"name": "web"}], 5.0, stop)
        runner.assert_called_once_with(
            [{"name": "web"}],
            ["203.0.113.0/24"],
            authorized_hosts=["203.0.113.7"],
            excluded_hosts=["203.0.113.99"],
        )
        app.ingest.assert_called_once()

    def test_windows_baseline_requires_complete_security_descriptor_coverage(self):
        incomplete = {
            "platform": "Windows Server 2022",
            "collector_errors": [],
            "probes": [],
            "services": [],
            "interfaces": [],
            "integrity": [
                {
                    "path": "C:/Windows/System32/drivers/etc/hosts",
                    "sha256": "a" * 64,
                }
            ],
        }
        readiness = assess_baseline_readiness(incomplete)
        self.assertFalse(readiness["ready"])
        self.assertTrue(
            any("security descriptor" in item for item in readiness["blockers"])
        )

    def test_baseline_readiness_surfaces_unhealthy_collection_and_probes(self):
        readiness = assess_baseline_readiness(
            {
                "collector_errors": ["self-health: runtime package digest mismatch"],
                "probes": [{"name": "service-monitor-example", "healthy": False}],
                "integrity": [],
                "services": [],
                "interfaces": [],
            }
        )
        self.assertFalse(readiness["ready"])
        self.assertLess(readiness["score"], 50)
        self.assertEqual(len(readiness["blockers"]), 2)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "test.db")
        self.app = ControllerApp(
            self.store, "a" * 32, operator_token="o" * 32
        )

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def test_ingest_alert_decision_and_action(self):
        baseline = {
            "agent_id": "agent-1",
            "hostname": "host-1",
            "platform": "Linux",
            "observed_at": time.time(),
            "accounts": [{"name": "root", "privileged": True, "enabled": True}],
            "sessions": [],
            "services": [{"name": "web", "state": "running"}],
            "interfaces": [],
            "collector_errors": [],
        }
        self.app.ingest(baseline)
        self.assertEqual(self.store.baseline_status("agent-1"), "pending")
        self.assertTrue(self.store.approve_baseline("agent-1"))
        incident = {**baseline, "services": [{"name": "web", "state": "stopped"}]}
        alert_ids = self.app.ingest(incident)
        self.assertTrue(alert_ids)
        result = self.app.decision(alert_ids[0], "approve")
        self.assertEqual(result["status"], "queued")
        actions = self.store.pending_actions("agent-1")
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0].action_type, "restart_service")
        self.assertEqual(self.store.baseline_status("agent-1"), "approved")

    def test_dashboard_never_calls_pending_baseline_restoration_armed(self):
        app = ControllerApp(
            self.store,
            "a" * 32,
            auto_restore=True,
            allow_unprobed_restoration=True,
            operator_token="o" * 32,
        )
        telemetry = {
            "agent_id": "pending-agent",
            "hostname": "pending-host",
            "platform": "Linux",
            "observed_at": time.time(),
            "accounts": [],
            "sessions": [],
            "services": [],
            "interfaces": [],
            "integrity": [],
            "collector_errors": [],
        }
        app.ingest(telemetry)
        pending = app.dashboard()["controller"]
        self.assertTrue(pending["automatic_restoration"])
        self.assertFalse(pending["automatic_restoration_ready"])
        self.assertEqual(pending["restoration_blocked_agents"], ["pending-agent"])

        app.approve_baseline("pending-agent")
        approved = app.dashboard()["controller"]
        self.assertTrue(approved["automatic_restoration_ready"])
        self.assertEqual(approved["restoration_blocked_agents"], [])

    def test_pending_baseline_approval_uses_latest_healthy_sample(self):
        first = {
            "agent_id": "recovering-agent",
            "hostname": "recovering-host",
            "platform": "Linux",
            "observed_at": time.time(),
            "boot_id": "stable-boot",
            "sequence": 1,
            "accounts": [],
            "sessions": [],
            "services": [{"name": "web", "state": "running"}],
            "interfaces": [{"name": "eth0", "addresses": ["192.0.2.10/24"]}],
            "integrity": [],
            "probes": [{"name": "web", "target": "local", "healthy": False}],
            "collector_errors": ["transient first-poll failure"],
        }
        self.app.ingest(first)
        with self.assertRaisesRegex(PermissionError, "healthy collection"):
            self.app.approve_baseline("recovering-agent")

        second = {
            **first,
            "observed_at": time.time(),
            "sequence": 2,
            "probes": [{"name": "web", "target": "local", "healthy": True}],
            "collector_errors": [],
        }
        self.app.ingest(second)
        approval = self.app.approve_baseline("recovering-agent")

        self.assertTrue(approval["approved"])
        promoted = self.store.get_baseline("recovering-agent")
        latest = self.store.latest_telemetry_for_agent("recovering-agent")
        self.assertEqual(promoted, latest)
        self.assertEqual(promoted["sequence"], 2)
        self.assertEqual(promoted["collector_errors"], [])
        self.assertTrue(promoted["probes"][0]["healthy"])

    def test_dashboard_exposes_bounded_connection_pressure_to_the_operator(self):
        self.app.connection_pressure_provider = lambda: {"source_quota_rejected": 9}
        self.assertEqual(
            self.app.dashboard()["controller"]["connection_pressure"],
            {"source_quota_rejected": 9},
        )

    def test_dashboard_waits_for_successful_restore_point_capture(self):
        app = ControllerApp(
            self.store,
            "a" * 32,
            auto_restore=True,
            allow_unprobed_restoration=True,
            operator_token="o" * 32,
        )
        telemetry = {
            "agent_id": "capture-agent",
            "hostname": "capture-host",
            "platform": "Linux",
            "observed_at": time.time(),
            "accounts": [],
            "sessions": [],
            "services": [],
            "interfaces": [],
            "integrity": [
                {
                    "path": "/etc/capture-test.conf",
                    "sha256": "a" * 64,
                    "size": 1,
                    "modified_at": 1,
                }
            ],
            "collector_errors": [],
        }
        app.ingest(telemetry)
        approval = app.approve_baseline("capture-agent")
        self.assertIsNotNone(approval)
        pending = app.dashboard()["controller"]
        self.assertFalse(pending["automatic_restoration_ready"])
        self.assertEqual(
            pending["restoration_blockers"]["capture-agent"],
            "baseline_promotion_pending",
        )
        delivered = app.pending_actions_for_agent("capture-agent")
        self.assertEqual(
            [item.action_id for item in delivered],
            [approval["restore_point_action_id"]],
        )
        _complete_baseline_capture(
            app,
            self.store,
            "capture-agent",
            delivered[0],
        )
        ready = app.dashboard()["controller"]
        self.assertTrue(ready["automatic_restoration_ready"])
        self.assertEqual(ready["restoration_blockers"], {})

    def test_windows_approval_binds_security_descriptor_to_restore_point_capture(self):
        telemetry = {
            "agent_id": "windows-capture-agent",
            "hostname": "windows-host",
            "platform": "Windows Server 2022",
            "observed_at": time.time(),
            "accounts": [],
            "sessions": [],
            "services": [],
            "interfaces": [],
            "integrity": [
                {
                    "path": "C:/Windows/System32/drivers/etc/hosts",
                    "sha256": "a" * 64,
                    "size": 1,
                    "modified_at": 1,
                    "security_descriptor_sha256": "b" * 64,
                }
            ],
            "collector_errors": [],
        }
        self.app.ingest(telemetry)
        approval, action = _dispatch_baseline_capture(
            self.app, "windows-capture-agent"
        )
        self.assertEqual(action.action_id, approval["restore_point_action_id"])
        self.assertEqual(
            action.parameters["files"][0]["security_descriptor_sha256"],
            "b" * 64,
        )
        _complete_baseline_capture(
            self.app,
            self.store,
            "windows-capture-agent",
            action,
        )
        self.assertEqual(
            self.store.get_baseline("windows-capture-agent")["integrity"][0][
                "security_descriptor_sha256"
            ],
            "b" * 64,
        )

    def test_legacy_windows_descriptor_upgrade_cannot_auto_restore(self):
        app = ControllerApp(
            self.store,
            "a" * 32,
            auto_restore=True,
            allow_unprobed_restoration=True,
            restore_confirmations=1,
            operator_token="o" * 32,
        )
        baseline = {
            "agent_id": "legacy-windows",
            "hostname": "legacy-host",
            "platform": "Windows Server 2022",
            "observed_at": time.time(),
            "accounts": [],
            "sessions": [],
            "services": [],
            "interfaces": [],
            "integrity": [
                {
                    "path": "C:/protected.conf",
                    "sha256": "a" * 64,
                    "size": 1,
                    "modified_at": 1,
                }
            ],
            "collector_errors": [],
        }
        app.ingest(baseline)
        with self.assertRaisesRegex(PermissionError, "healthy collection"):
            app.approve_baseline("legacy-windows")
        self.assertEqual(self.store.baseline_status("legacy-windows"), "pending")
        current = {
            **baseline,
            "observed_at": time.time() + 1,
            "integrity": [
                {
                    **baseline["integrity"][0],
                    "security_descriptor_sha256": "b" * 64,
                }
            ],
        }
        alert_ids = app.ingest(current)
        alert_id = next(
            item
            for item in alert_ids
            if self.store.get_alert(item)["kind"] == "critical_file_changed"
        )
        alert = next(
            row for row in self.store.dashboard()["alerts"] if row["alert_id"] == alert_id
        )
        self.assertTrue(alert["evidence"]["security_baseline_upgrade"])
        self.assertEqual(alert["recommended_action"], "snapshot")
        self.assertIn("pending approval", alert["recommendation"])
        self.assertEqual(
            app.dashboard()["controller"]["restoration_blockers"]["legacy-windows"],
            "baseline_not_approved",
        )
        self.assertNotIn(
            "restore_integrity",
            [item.action_type for item in self.store.pending_actions("legacy-windows")],
        )

    def test_action_result_type_must_match_queue(self):
        action_id = self.store.queue_action("agent-1", "snapshot", {})
        self.assertEqual(
            [item.action_id for item in self.store.pending_actions("agent-1")],
            [action_id],
        )
        self.assertEqual(
            self.app.complete_action(
                {
                    "action_id": action_id,
                    "action_type": "observe",
                    "success": True,
                    "message": "wrong type",
                    "started_at": time.time(),
                    "completed_at": time.time(),
                },
                "agent-1",
            ),
            "conflict",
        )
        self.assertEqual(self.store.get_action(action_id)["status"], "dispatched")

    def test_approved_baseline_captures_restore_points_and_auto_restores_drift(self):
        app = ControllerApp(
            self.store,
            "a" * 32,
            auto_restore=True,
            restoration_probes=[
                {
                    "name": "ssh-scorer",
                    "kind": "tcp",
                    "target": "127.0.0.1",
                    "port": 22,
                    "restore_paths": ["/etc/ssh/**"],
                }
            ],
            operator_token="o" * 32,
        )
        baseline = {
            "agent_id": "guarded-agent",
            "hostname": "guarded-host",
            "platform": "Linux",
            "observed_at": time.time(),
            "accounts": [],
            "sessions": [],
            "services": [],
            "interfaces": [],
            "integrity": [
                {"path": "/etc/ssh/sshd_config", "sha256": "a" * 64, "size": 10, "modified_at": 1}
            ],
            "collector_errors": [],
        }
        app.ingest(baseline)
        approval, capture = _promote_integrity_baseline(
            app, self.store, "guarded-agent"
        )
        self.assertFalse(approval["approved"])
        self.assertEqual(capture.action_type, "capture_restore_point")
        drift = {
            **baseline,
            "observed_at": time.time() + 1,
            "integrity": [
                {"path": "/etc/ssh/sshd_config", "sha256": "b" * 64, "size": 11, "modified_at": 2}
            ],
        }
        alert_ids = app.ingest(drift)
        actions = self.store.pending_actions("guarded-agent")
        self.assertTrue(alert_ids)
        self.assertNotIn("restore_integrity", [item.action_type for item in actions])
        repeated = {
            **drift,
            "observed_at": time.time() + 2,
        }
        app.ingest(repeated)
        actions = self.store.pending_actions("guarded-agent")
        self.assertEqual(actions[-1].action_type, "restore_integrity")
        self.assertEqual(actions[-1].parameters["probes"][0]["name"], "ssh-scorer")

        app.ingest({**repeated, "observed_at": time.time() + 3})
        restore_actions = [
            item
            for item in self.store.dashboard()["actions"]
            if item["action_type"] == "restore_integrity"
        ]
        self.assertEqual(len(restore_actions), 1)

    def test_one_use_change_grant_pauses_automatic_restoration(self):
        app = ControllerApp(
            self.store,
            "a" * 32,
            auto_restore=True,
            restore_confirmations=1,
            allow_unprobed_restoration=True,
            operator_token="o" * 32,
        )
        baseline = {
            "agent_id": "grant-agent",
            "hostname": "grant-host",
            "platform": "Linux",
            "observed_at": time.time(),
            "accounts": [], "sessions": [], "services": [], "interfaces": [],
            "integrity": [{"path": "/etc/test.conf", "sha256": "a" * 64, "size": 1, "modified_at": 1}],
            "collector_errors": [],
        }
        app.ingest(baseline)
        _promote_integrity_baseline(app, self.store, "grant-agent")
        app.authorize_change({"agent_id": "grant-agent", "path": "/etc/test.conf", "ttl_seconds": 60})
        drift = {
            **baseline,
            "observed_at": time.time() + 1,
            "integrity": [{"path": "/etc/test.conf", "sha256": "b" * 64, "size": 1, "modified_at": 2}],
        }
        alert_id = app.ingest(drift)[0]
        alert = next(item for item in self.store.dashboard()["alerts"] if item["alert_id"] == alert_id)
        self.assertEqual(alert["recommended_action"], "snapshot")
        self.assertIn("change_grant_id", alert["evidence"])
        actions = [item.action_type for item in self.store.pending_actions("grant-agent")]
        self.assertNotIn("restore_integrity", actions)

        # The claimed grant remains attached to repeated observations of the
        # same exact change; it is not accidentally consumed for one poll only.
        app.ingest({**drift, "observed_at": time.time() + 2})
        actions = [item.action_type for item in self.store.pending_actions("grant-agent")]
        self.assertNotIn("restore_integrity", actions)

    def test_scoped_probe_mapping_holds_unvalidated_automatic_restore(self):
        app = ControllerApp(
            self.store,
            "a" * 32,
            auto_restore=True,
            restoration_probes=[
                {
                    "name": "web",
                    "kind": "http",
                    "target": "http://127.0.0.1/",
                    "restore_paths": ["/etc/nginx/**"],
                }
            ],
            restore_confirmations=1,
            operator_token="o" * 32,
        )
        baseline = {
            "agent_id": "mapped-agent",
            "hostname": "mapped-host",
            "platform": "Linux",
            "observed_at": time.time(),
            "accounts": [], "sessions": [], "services": [], "interfaces": [],
            "integrity": [{"path": "/etc/ssh/sshd_config", "sha256": "a" * 64, "size": 1, "modified_at": 1}],
            "collector_errors": [],
        }
        app.ingest(baseline)
        _promote_integrity_baseline(app, self.store, "mapped-agent")
        drift = {
            **baseline,
            "observed_at": time.time() + 1,
            "integrity": [{"path": "/etc/ssh/sshd_config", "sha256": "b" * 64, "size": 1, "modified_at": 2}],
        }
        alert_id = app.ingest(drift)[0]
        alert = next(item for item in self.store.dashboard()["alerts"] if item["alert_id"] == alert_id)
        self.assertEqual(alert["evidence"]["automation_hold"], "no_applicable_service_probe")
        self.assertIsNone(self.store.action_for_alert(alert_id, "restore_integrity"))

    def test_windows_and_linux_restore_path_patterns_are_normalized(self):
        app = ControllerApp(
            self.store,
            "a" * 32,
            restoration_probes=[
                {"name": "iis", "restore_paths": ["C:/Windows/System32/inetsrv/**"]},
                {"name": "web", "restore_paths": ["/etc/nginx/**"]},
            ],
            operator_token="o" * 32,
        )
        self.assertEqual(
            [item["name"] for item in app.restoration_probes_for_path(r"c:\Windows\System32\inetsrv\config\applicationHost.config")],
            ["iis"],
        )
        self.assertEqual(
            [item["name"] for item in app.restoration_probes_for_path("/etc/nginx/nginx.conf")],
            ["web"],
        )


if __name__ == "__main__":
    unittest.main()
