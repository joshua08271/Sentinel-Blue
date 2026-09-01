import tempfile
import threading
import time
import unittest
import uuid
from dataclasses import asdict
from pathlib import Path

from sentinel_blue import __version__
from sentinel_blue.agent import execute_queued_action
from sentinel_blue.controller import ControllerApp
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.protocol import AlertCandidate
from sentinel_blue.state import ActionJournal
from sentinel_blue.store import Store
from sentinel_blue.validation import (
    canonical_action_envelope_sha256,
    validate_action_request,
)
from tests.test_event_profile import live_profile


class CompetitionGovernanceTests(unittest.TestCase):
    def setUp(self):
        payload = live_profile("ncae-standard")
        payload["autonomy_mode"] = "approval-based"
        payload["services"][0]["host"] = "agent-example"
        payload["services"][0]["approval_actions"].append("rollback_service")
        self.profile = EventProfile.from_dict(payload)
        self.store = Store(":memory:")
        self.app = ControllerApp(
            self.store,
            "g" * 32,
            authorized_networks=list(self.profile.authorized_networks),
            event_profile=self.profile,
            operator_token="o" * 32,
        )

    def tearDown(self):
        self.store.close()

    def test_profile_identity_enrollment_and_action_are_exactly_bound(self):
        self.assertIn(
            "scoring-service-example", self.store.protected_accounts("agent-example")
        )
        with self.assertRaises(PermissionError):
            self.app.enroll(
                {
                    "agent_id": "agent-example",
                    "hostname": "fixture",
                    "platform": "Linux",
                    "profile_id": "wrong",
                    "profile_fingerprint": "0" * 64,
                }
            )
        enrolled = self.app.enroll(
            {
                "agent_id": "agent-example",
                "hostname": "fixture",
                "platform": "Linux",
                "profile_id": self.profile.profile_id,
                "profile_fingerprint": self.profile.fingerprint,
            }
        )
        self.assertEqual(enrolled["agent_id"], "agent-example")

        issued = self.app.issue_action_authorization(
            {
                "agent_id": "agent-example",
                "action_type": "restart_service",
                "subject": "manual-repair-example",
            }
        )
        action_id = self.app._queue_action(
            "agent-example",
            "restart_service",
            {"service": "web-example"},
            authorization_code=issued["authorization_code"],
            authorization_subject="manual-repair-example",
        )
        action = self.store.get_action(str(action_id))
        self.assertEqual(action["profile_id"], self.profile.profile_id)
        self.assertEqual(action["profile_fingerprint"], self.profile.fingerprint)
        self.assertGreater(action["expires_at"], time.time())
        with self.assertRaises(PermissionError):
            self.app._queue_action(
                "agent-example",
                "restart_service",
                {"service": "web-example"},
                authorization_code=issued["authorization_code"],
                authorization_subject="manual-repair-example",
            )

    def test_emergency_stop_holds_new_changes_but_keeps_rollback(self):
        self.app.emergency_stop()
        with self.assertRaises(PermissionError):
            self.app._queue_action(
                "agent-example", "restart_service", {"service": "web-example"}
            )
        issued = self.app.issue_action_authorization(
            {
                "agent_id": "agent-example",
                "action_type": "rollback_service",
                "subject": "rollback-example",
            }
        )
        action_id = self.app._queue_action(
            "agent-example",
            "rollback_service",
            {"service": "web-example", "desired_state": "running"},
            authorization_code=issued["authorization_code"],
            authorization_subject="rollback-example",
        )
        self.assertIsNotNone(action_id)
        automatic, manual = self.app.dispatch_policy()
        self.assertNotIn("restart_service", automatic | manual)
        self.assertIn("rollback_service", manual)

    def test_governance_transition_waits_for_inflight_action_egress(self):
        started = threading.Event()
        finished = threading.Event()

        def stop_controller():
            started.set()
            self.app.emergency_stop()
            finished.set()

        with self.app._action_egress_lock:
            worker = threading.Thread(target=stop_controller)
            worker.start()
            self.assertTrue(started.wait(1.0))
            self.assertFalse(finished.wait(0.05))
            self.assertFalse(self.app.emergency_stopped)
        worker.join(timeout=1.0)
        self.assertFalse(worker.is_alive())
        self.assertTrue(finished.is_set())
        self.assertTrue(self.app.emergency_stopped)

    def test_agent_refuses_expired_or_wrong_profile_action_before_executor(self):
        class RefusingExecutor:
            calls = 0

            def execute(self, *_args, **_kwargs):
                self.calls += 1
                return {"success": True}

        health = {"action_safe": True, "critical_errors": []}
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(Path(directory))
            executor = RefusingExecutor()
            base = {
                "agent_id": "agent-example",
                "action_type": "restart_service",
                "parameters": {"service": "web-example"},
                "status": "dispatched",
                "created_at": time.time() - 120,
                "automated": False,
                "risk": "high",
                "profile_id": self.profile.profile_id,
                "profile_fingerprint": self.profile.fingerprint,
                "autonomy_mode": self.profile.autonomy_mode,
            }
            expired = execute_queued_action(
                journal,
                executor,
                {**base, "action_id": "expired", "expires_at": time.time() - 1},
                {},
                health,
                self.profile,
            )
            wrong = execute_queued_action(
                journal,
                executor,
                {
                    **base,
                    "action_id": "wrong-profile",
                    "expires_at": time.time() + 60,
                    "profile_fingerprint": "0" * 64,
                },
                {},
                health,
                self.profile,
            )
            self.assertFalse(expired["success"])
            self.assertFalse(wrong["success"])
            self.assertEqual(executor.calls, 0)

    def test_recovery_promotion_delay_fails_without_deciding_alert(self):
        payload = live_profile("ncae-standard")
        payload["autonomy_mode"] = "guarded-autonomous"
        payload["capabilities"]["guarded_autonomy"] = True
        payload["allowed_automatic_actions"] = ["capture_restore_point"]
        payload["services"][0]["host"] = "agent-promotion"
        payload["services"][0]["allowed_automatic_actions"] = [
            "capture_restore_point"
        ]
        profile = EventProfile.from_dict(payload)
        store = Store(":memory:")
        app = ControllerApp(
            store,
            "g" * 32,
            authorized_networks=list(profile.authorized_networks),
            event_profile=profile,
            operator_token="o" * 32,
        )
        telemetry = {
            "agent_id": "agent-promotion",
            "hostname": "promotion-fixture",
            "platform": "Linux",
            "observed_at": time.time(),
            "accounts": [],
            "sessions": [],
            "services": [{"name": "web-example", "state": "running"}],
            "interfaces": [{"name": "eth0", "addresses": ["192.0.2.10/24"]}],
            "routes": [],
            "neighbors": [],
            "listeners": [],
            "integrity": [
                {
                    "path": "/etc/nginx/nginx.conf",
                    "sha256": "a" * 64,
                    "size": 1,
                    "modified_at": 1,
                }
            ],
            "probes": [{"name": "web-example", "target": "local", "healthy": True}],
            "collector_errors": [],
            "agent_version": __version__,
            "profile_id": profile.profile_id,
            "profile_fingerprint": profile.fingerprint,
        }
        try:
            app.ingest(telemetry)
            approval = app.approve_baseline("agent-promotion")
            self.assertFalse(approval["approved"])
            actions = store.pending_actions(
                "agent-promotion",
                allowed_automated_action_types={"capture_restore_point"},
                allowed_manual_action_types=set(),
            )
            self.assertEqual(
                [item.action_id for item in actions],
                [approval["restore_point_action_id"]],
            )
            action = actions[0]
            envelope = validate_action_request(
                asdict(action),
                expected_agent_id="agent-promotion",
                expected_profile_id=profile.profile_id,
                expected_profile_fingerprint=profile.fingerprint,
                expected_autonomy_mode=profile.autonomy_mode,
                require_binding=True,
            )
            now = time.time()
            files = list(action.parameters["files"])
            result = {
                "action_id": action.action_id,
                "action_type": "capture_restore_point",
                "success": True,
                "message": "captured exact restore point",
                "started_at": now,
                "completed_at": now,
                "dry_run": False,
                "action_envelope_sha256": canonical_action_envelope_sha256(
                    envelope
                ),
                "captured": [item["path"] for item in files],
                "rejected": [],
                "capture_receipts": [
                    {
                        "path": item["path"],
                        "source_sha256": item["sha256"],
                        "backup_sha256": item["sha256"],
                        "backup_matches_source": True,
                        "byte_size": item["size"],
                        "security_metadata_sha256": "c" * 64,
                        "security_descriptor_sha256": "",
                        "restore_point_id": str(uuid.uuid4()),
                        "stored": True,
                    }
                    for item in files
                ],
            }
            self.assertEqual(
                app.complete_action(result, "agent-promotion"),
                "new",
            )
            self.assertEqual(store.baseline_status("agent-promotion"), "approved")

            alert_id = store.add_alert(
                "agent-promotion",
                AlertCandidate(
                    kind="critical_file_changed",
                    title="fixture",
                    summary="fixture",
                    severity="high",
                    confidence=1.0,
                    evidence={
                        "current": {
                            "path": "/etc/nginx/nginx.conf",
                            "sha256": "b" * 64,
                            "size": 1,
                            "modified_at": 2,
                        }
                    },
                    recommendation="fixture",
                    recommended_action="restore_integrity",
                ),
            )
            with self.assertRaisesRegex(PermissionError, "delay"):
                app.decision(alert_id, "accept_change")
            self.assertEqual(store.get_alert(alert_id)["status"], "open")
        finally:
            store.close()


if __name__ == "__main__":
    unittest.main()
