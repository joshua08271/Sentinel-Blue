import tempfile
import time
import unittest
import uuid
from pathlib import Path

from sentinel_blue.controller import ControllerApp
from sentinel_blue.protocol import AlertCandidate
from sentinel_blue.store import Store


def telemetry(agent_id: str, files: list[dict], *, sequence: int = 1) -> dict:
    return {
        "agent_id": agent_id,
        "hostname": f"{agent_id}-host",
        "platform": "Linux",
        "observed_at": time.time(),
        "boot_id": "promotion-test-boot",
        "sequence": sequence,
        "accounts": [],
        "sessions": [],
        "services": [],
        "interfaces": [],
        "integrity": files,
        "probes": [],
        "collector_errors": [],
    }


def capture_result(action, *, success: bool = True, files: list[dict] | None = None) -> dict:
    now = time.time()
    result = {
        "action_id": action.action_id,
        "action_type": "capture_restore_point",
        "success": success,
        "message": "capture fixture",
        "started_at": now,
        "completed_at": now,
        "dry_run": False,
    }
    if success:
        requested = list(files if files is not None else action.parameters["files"])
        result.update(
            {
                "captured": [item["path"] for item in requested],
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
                    for item in requested
                ],
            }
        )
    return result


class BaselinePromotionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "promotion.db"
        self.store = Store(self.path)
        self.app = ControllerApp(
            self.store,
            "e" * 32,
            auto_restore=True,
            allow_unprobed_restoration=True,
            operator_token="o" * 32,
        )

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    @staticmethod
    def _files(first: str = "a", second: str = "b") -> list[dict]:
        return [
            {
                "path": "/etc/sentinel/first.conf",
                "sha256": first * 64,
                "size": 11,
                "modified_at": 1,
            },
            {
                "path": "/etc/sentinel/second.conf",
                "sha256": second * 64,
                "size": 17,
                "modified_at": 1,
            },
        ]

    def _begin(self, agent_id: str = "promotion-agent"):
        sample = telemetry(agent_id, self._files())
        self.app.ingest(sample)
        # Promotion freezes the controller's strict normalized observation,
        # not the caller-owned pre-validation dictionary.
        sample = self.store.latest_telemetry_for_agent(agent_id)
        self.assertIsNotNone(sample)
        approval = self.app.approve_baseline(agent_id)
        self.assertFalse(approval["approved"])
        self.assertTrue(approval["promotion_pending"])
        action = self.store.pending_actions(agent_id)[0]
        return sample, approval, action

    def test_multifile_candidate_promotes_only_after_exact_receipts(self):
        sample, approval, action = self._begin()
        self.assertEqual(self.store.baseline_status("promotion-agent"), "pending")
        self.assertEqual(action.parameters["files"], [
            {"path": item["path"], "sha256": item["sha256"], "size": item["size"]}
            for item in self._files()
        ])
        dashboard = self.app.dashboard()["controller"]
        self.assertEqual(
            dashboard["restoration_blockers"]["promotion-agent"],
            "baseline_promotion_pending",
        )

        result = capture_result(action)
        self.assertEqual(
            self.app.complete_action(result, "promotion-agent"), "new"
        )
        self.assertEqual(self.store.baseline_status("promotion-agent"), "approved")
        self.assertEqual(self.store.get_baseline("promotion-agent"), sample)
        promotion = self.store.latest_baseline_promotion("promotion-agent")
        self.assertEqual(promotion["promotion_id"], approval["promotion_id"])
        self.assertEqual(promotion["status"], "completed")
        self.assertTrue(self.app.dashboard()["controller"]["automatic_restoration_ready"])
        self.assertEqual(
            self.app.complete_action(dict(result), "promotion-agent"), "exact_retry"
        )

    def test_failed_capture_blocks_candidate_and_retry_is_idempotent(self):
        _, first, action = self._begin("retry-agent")
        self.assertEqual(
            self.app.complete_action(
                capture_result(action, success=False), "retry-agent"
            ),
            "new",
        )
        self.assertEqual(self.store.baseline_status("retry-agent"), "pending")
        blocked = self.store.latest_baseline_promotion("retry-agent")
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["failure_reason"], "capture_failed")

        retry = self.app.approve_baseline("retry-agent")
        same_retry = self.app.approve_baseline("retry-agent")
        self.assertNotEqual(retry["promotion_id"], first["promotion_id"])
        self.assertEqual(same_retry["promotion_id"], retry["promotion_id"])
        self.assertEqual(
            same_retry["restore_point_action_id"], retry["restore_point_action_id"]
        )

    def test_changed_observation_blocks_late_capture(self):
        _, _, action = self._begin("race-agent")
        newer = telemetry("race-agent", self._files("d", "b"), sequence=2)
        self.app.ingest(newer)
        self.assertEqual(
            self.app.complete_action(capture_result(action), "race-agent"), "new"
        )
        promotion = self.store.latest_baseline_promotion("race-agent")
        self.assertEqual(promotion["status"], "blocked")
        self.assertEqual(
            promotion["failure_reason"], "promotion_telemetry_observation_stale"
        )
        self.assertEqual(self.store.baseline_status("race-agent"), "pending")

    def test_rotation_and_operator_abort_never_promote(self):
        _, _, action = self._begin("rotation-agent")
        self.store.rotate_agent_credential("rotation-agent")
        promotion = self.store.latest_baseline_promotion("rotation-agent")
        self.assertEqual(promotion["status"], "blocked")
        self.assertEqual(promotion["failure_reason"], "credential_rotation")
        self.assertEqual(self.store.baseline_status("rotation-agent"), "invalidated")

        sample = telemetry("abort-agent", self._files())
        self.app.ingest(sample)
        approval = self.app.approve_baseline("abort-agent")
        aborted = self.app.abort_baseline_promotion("abort-agent")
        self.assertEqual(aborted["promotion_id"], approval["promotion_id"])
        self.assertEqual(aborted["status"], "aborted")
        self.assertEqual(self.app.abort_baseline_promotion("abort-agent"), aborted)
        self.assertEqual(self.store.baseline_status("abort-agent"), "pending")
        self.assertEqual(self.store.get_action(approval["restore_point_action_id"])["status"], "failed")

    def test_pending_promotion_survives_restart_and_completes(self):
        _, approval, action = self._begin("restart-agent")
        # A persistent controller deliberately refuses to restart with a
        # legacy enabled agent that has no independent credential.
        self.store.ensure_agent_secret("restart-agent")
        self.store.close()
        self.store = Store(self.path)
        self.app = ControllerApp(
            self.store,
            "e" * 32,
            auto_restore=True,
            allow_unprobed_restoration=True,
            operator_token="o" * 32,
        )
        # The action was already dispatched before the crash.  It must not be
        # reissued, but the agent's durable result outbox may still complete
        # that exact immutable envelope after controller restart.
        self.assertEqual(self.store.pending_actions("restart-agent"), [])
        self.assertEqual(action.action_id, approval["restore_point_action_id"])
        self.assertEqual(
            self.app.complete_action(capture_result(action), "restart-agent"), "new"
        )
        self.assertEqual(self.store.baseline_status("restart-agent"), "approved")

    def test_accept_change_keeps_prior_baseline_and_alert_open_until_capture(self):
        original, _, initial_action = self._begin("change-agent")
        self.assertEqual(
            self.app.complete_action(capture_result(initial_action), "change-agent"),
            "new",
        )
        changed_files = self._files("d", "b")
        current = telemetry("change-agent", changed_files, sequence=2)
        alert_ids = self.app.ingest(current)
        alert_id = next(
            alert_id
            for alert_id in alert_ids
            if self.store.get_alert(alert_id)["kind"] == "critical_file_changed"
        )
        pending = self.app.decision(alert_id, "accept_change")
        self.assertEqual(pending["status"], "promotion_pending")
        self.assertEqual(self.store.get_alert(alert_id)["status"], "open")
        self.assertEqual(self.store.get_baseline("change-agent"), original)
        action = self.store.pending_actions("change-agent")[0]
        self.assertEqual(len(action.parameters["files"]), 2)

        self.assertEqual(
            self.app.complete_action(capture_result(action), "change-agent"), "new"
        )
        self.assertEqual(self.store.get_alert(alert_id)["decision"], "accept_change")
        promoted = self.store.get_baseline("change-agent")
        self.assertEqual(
            [item["sha256"] for item in promoted["integrity"]],
            ["b" * 64, "d" * 64],
        )

    def test_capture_receipt_digest_or_size_mismatch_blocks_promotion(self):
        _, _, action = self._begin("receipt-agent")
        forged = capture_result(action)
        forged["capture_receipts"][0]["byte_size"] += 1
        self.assertEqual(
            self.app.complete_action(forged, "receipt-agent"), "new"
        )
        promotion = self.store.latest_baseline_promotion("receipt-agent")
        self.assertEqual(promotion["status"], "blocked")
        self.assertEqual(
            promotion["failure_reason"], "capture_receipt_size_mismatch"
        )
        self.assertEqual(self.store.baseline_status("receipt-agent"), "pending")


if __name__ == "__main__":
    unittest.main()
