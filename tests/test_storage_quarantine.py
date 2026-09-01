import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.protocol import AlertCandidate
from sentinel_blue.store import (
    ActionQuotaExceeded,
    Store,
    _require_success_result_contract,
)


def candidate() -> AlertCandidate:
    return AlertCandidate(
        "test",
        "Test",
        "summary",
        "high",
        0.9,
        {"safe": True},
        "review",
        "snapshot",
    )


class StorageQuarantineTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "controller.db")
        self.store.register_agent("agent-a", "host-a", "Linux")

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def corrupt(self, sql: str, values: tuple = ()) -> None:
        with self.store._lock:
            self.store._connection.execute(sql, values)
            self.store._connection.commit()

    def test_alert_quarantine_atomically_invalidates_linked_action(self):
        alert_id = self.store.add_alert("agent-a", candidate())
        action_id = self.store.queue_action(
            "agent-a", "snapshot", {}, alert_id
        )
        self.corrupt(
            "UPDATE alerts SET evidence_json='not-json' WHERE alert_id=?",
            (alert_id,),
        )

        self.assertIsNone(self.store.get_alert(alert_id))
        row = self.store._connection.execute(
            "SELECT status, decision FROM alerts WHERE alert_id=?", (alert_id,)
        ).fetchone()
        self.assertEqual(tuple(row), ("decided", "json_quarantined"))
        self.assertEqual(self.store.get_action(action_id)["status"], "failed")
        self.assertEqual(self.store.pending_actions("agent-a"), [])

    def test_incident_and_outcome_hold_survive_caller_rollback(self):
        action_id = self.store.queue_action("agent-a", "snapshot", {})
        self.corrupt(
            "UPDATE actions SET status='completed', result_source='operator', "
            "attempts=1, dispatched_at=created_at+1, result_json='not-json' "
            "WHERE action_id=?",
            (action_id,),
        )

        with self.assertRaises(RuntimeError):
            self.store.reconcile_action_outcome(action_id, "executed")

        self.assertFalse(self.store.stored_json_readiness()["ready"])
        self.assertEqual(
            self.store._connection.execute(
                "SELECT status FROM actions WHERE action_id=?", (action_id,)
            ).fetchone()[0],
            "outcome_unknown",
        )

    def test_repeated_detection_is_one_bounded_case(self):
        action_id = self.store.queue_action("agent-a", "snapshot", {})
        self.corrupt(
            "UPDATE actions SET parameters_json='not-json' WHERE action_id=?",
            (action_id,),
        )
        self.store.get_action(action_id)
        self.store.get_action(action_id)
        cases = self.store.list_storage_quarantines()
        self.assertEqual(len(cases), 1)
        self.assertGreaterEqual(cases[0]["detection_count"], 2)

    def test_forensic_only_audit_damage_does_not_block_mutation(self):
        audit_id = self.store.audit("test", "operation", "subject", {})
        self.corrupt(
            "UPDATE audit_log SET detail_json='not-json' WHERE audit_id=?",
            (audit_id,),
        )
        self.store.dashboard()
        readiness = self.store.stored_json_readiness()
        self.assertTrue(readiness["ready"])
        self.assertEqual(readiness["forensic_rows"], 1)
        self.assertIsInstance(
            self.store.queue_action("agent-a", "snapshot", {}), str
        )

    def test_delete_resolution_uses_digest_cas_and_never_reactivates_action(self):
        alert_id = self.store.add_alert("agent-a", candidate())
        linked = self.store.queue_action("agent-a", "snapshot", {}, alert_id)
        waiting = self.store.queue_action("agent-a", "snapshot", {})
        self.corrupt(
            "UPDATE alerts SET evidence_json='not-json' WHERE alert_id=?",
            (alert_id,),
        )
        self.store.get_alert(alert_id)
        case = self.store.list_storage_quarantines()[0]
        with self.assertRaises(RuntimeError):
            self.store.resolve_storage_quarantine(
                case["quarantine_id"],
                decision="resolve",
                expected_revision=case["revision"],
                expected_raw_sha256=case["raw_sha256"],
                operator_id="operator-one",
                note="unchanged source",
            )
        resolved = self.store.resolve_storage_quarantine(
            case["quarantine_id"],
            decision="delete",
            expected_revision=case["revision"],
            expected_raw_sha256=case["raw_sha256"],
            operator_id="operator-one",
            note="discard corrupt alert evidence",
        )
        self.assertEqual(resolved["state"], "resolved")
        self.assertTrue(self.store.stored_json_readiness()["ready"])
        self.assertEqual(self.store.get_action(linked)["status"], "failed")
        self.assertEqual(
            [item.action_id for item in self.store.pending_actions("agent-a")],
            [waiting],
        )

    def test_open_case_capacity_sets_sticky_overflow_without_growth(self):
        with patch("sentinel_blue.store.MAX_OPEN_STORAGE_QUARANTINES", 2):
            for index in range(3):
                self.store._quarantine_json(
                    "alerts", f"missing-{index}", "evidence_json", "not-json", "bad"
                )
        readiness = self.store.stored_json_readiness()
        self.assertEqual(readiness["quarantined_rows"], 2)
        self.assertTrue(readiness["overflowed"])
        self.assertEqual(readiness["overflow_count"], 1)
        with self.assertRaises(ActionQuotaExceeded):
            self.store.queue_action("agent-a", "snapshot", {})


class QuarantineResultContractTests(unittest.TestCase):
    def setUp(self):
        self.identity = {
            "schema": "sentinel-process-v1",
            "platform": "linux",
            "process_id": 4242,
            "boot_id": "boot-one",
            "start_time": "123456",
            "executable_path": "/usr/bin/fixture",
            "executable_file_id": "dev:1:ino:2",
            "user_id": "uid:1000:1000",
            "kernel_session_id": "99",
        }
        self.session = {
            "username": "operator",
            "source": "10.0.0.8",
            "session_id": "pts/1",
            "process_id": 4242,
            "privileged": True,
            "interactive": True,
            "process_identity": dict(self.identity),
        }
        self.observation = {
            "boot_id": "boot-one",
            "sequence": 7,
            "payload_sha256": "a" * 64,
        }

    def result(self) -> dict:
        return {
            "success": True,
            "dry_run": False,
            "record": {
                **self.session,
                "process_identity": dict(self.identity),
                "target_observation": dict(self.observation),
                "status": "active",
                "boot_id": "boot-one",
            },
        }

    def test_quarantine_success_binds_session_and_source_observation(self):
        parameters = {
            "session": dict(self.session),
            "observation": dict(self.observation),
        }
        _require_success_result_contract(
            "quarantine_session", parameters, self.result()
        )
        for field in (
            "username",
            "source",
            "session_id",
            "privileged",
            "interactive",
        ):
            with self.subTest(field=field):
                altered = self.result()
                altered["record"][field] = (
                    not altered["record"][field]
                    if type(altered["record"][field]) is bool
                    else str(altered["record"][field]) + "-changed"
                )
                with self.assertRaises(ValueError):
                    _require_success_result_contract(
                        "quarantine_session", parameters, altered
                    )
        altered = self.result()
        altered["record"]["target_observation"]["sequence"] += 1
        with self.assertRaises(ValueError):
            _require_success_result_contract(
                "quarantine_session", parameters, altered
            )


if __name__ == "__main__":
    unittest.main()
