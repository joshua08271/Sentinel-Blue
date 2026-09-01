import io
import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sentinel_blue.agent import AgentClient
from sentinel_blue.auth import response_signature, signature
from sentinel_blue.controller import ControllerApp, ControllerServer, make_handler
from sentinel_blue.json_codec import (
    StrictJsonError,
    canonical_json_dumps,
    strict_json_loads,
    validate_json_value,
)
from sentinel_blue.protocol import AlertCandidate
from sentinel_blue.store import Store
from sentinel_blue.validation import ValidationError, validate_action_result


class StrictJsonCodecTests(unittest.TestCase):
    def test_rejects_duplicate_keys_nonfinite_and_non_utf8_encodings(self):
        invalid = (
            b'{"same":1,"same":2}',
            b'{"nested":{"value":NaN}}',
            b"\xef\xbb\xbf{}",
            "{}".encode("utf-16"),
            b'{"bad":"\xed\xa0\x80"}',
            b'{"bad":"\\ud800"}',
        )
        for payload in invalid:
            with self.subTest(payload=payload[:32]):
                with self.assertRaises(StrictJsonError):
                    strict_json_loads(payload, max_bytes=1024)

    def test_rejects_depth_node_and_container_exhaustion(self):
        nested = ("[" * 33 + "0" + "]" * 33).encode()
        with self.assertRaisesRegex(StrictJsonError, "depth"):
            strict_json_loads(nested, max_bytes=1024)
        with self.assertRaisesRegex(StrictJsonError, "node"):
            validate_json_value([1, 2], max_nodes=2)
        with self.assertRaisesRegex(StrictJsonError, "item"):
            validate_json_value([1, 2], max_container_items=1)

    def test_serializer_never_coerces_or_emits_nonfinite_values(self):
        for value in ({"bad": float("nan")}, {"bad": object()}):
            with self.assertRaises(StrictJsonError):
                canonical_json_dumps(value)


class ActionResultValidationTests(unittest.TestCase):
    def _result(self, **changes):
        result = {
            "action_id": "action-1",
            "action_type": "snapshot",
            "success": False,
            "message": "result",
            "started_at": 10.0,
            "completed_at": 11.0,
        }
        result.update(changes)
        return result

    def test_nested_result_state_is_finite_and_bounded(self):
        with self.assertRaisesRegex(ValidationError, "finite"):
            validate_action_result(
                self._result(record={"outer": {"value": float("nan")}})
            )
        deep = {}
        cursor = deep
        for _ in range(14):
            cursor["next"] = {}
            cursor = cursor["next"]
        with self.assertRaisesRegex(ValidationError, "nesting"):
            validate_action_result(self._result(pre_state=deep))

    def test_rejects_impossible_success_and_reversed_times(self):
        for changes in (
            {"success": True, "rolled_back": True},
            {"success": True, "interrupted": True},
            {"started_at": 12.0, "completed_at": 11.0},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValidationError):
                    validate_action_result(self._result(**changes))


class ActionCompletionIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "results.db")
        self.store.register_agent("agent-a", "host-a", "Linux")
        self.store.ensure_agent_secret("agent-a")
        self.app = ControllerApp(self.store, "e" * 32, operator_token="o" * 32)

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    @staticmethod
    def _result(action_id, *, success, message="result", **extra):
        now = time.time()
        return {
            "action_id": action_id,
            "action_type": extra.pop("action_type", "snapshot"),
            "success": success,
            "message": message,
            "started_at": now,
            "completed_at": now,
            **extra,
        }

    def test_success_and_failure_retries_are_exact_and_conflicts_have_no_side_effects(self):
        successful = self.store.queue_action("agent-a", "snapshot", {})
        self.assertEqual(
            [item.action_id for item in self.store.pending_actions("agent-a")],
            [successful],
        )
        success = self._result(successful, success=True)
        self.assertEqual(self.app.complete_action(success, "agent-a"), "new")
        self.assertEqual(self.app.complete_action(dict(reversed(list(success.items()))), "agent-a"), "exact_retry")
        self.assertEqual(
            self.app.complete_action({**success, "message": "changed"}, "agent-a"),
            "conflict",
        )

        failed = self.store.queue_action("agent-a", "snapshot", {})
        self.assertEqual(
            [item.action_id for item in self.store.pending_actions("agent-a")],
            [failed],
        )
        failure = self._result(failed, success=False, message="failed")
        self.assertEqual(self.app.complete_action(failure, "agent-a"), "new")
        first = [
            item
            for item in self.store.dashboard()["alerts"]
            if item["kind"] == "automation_action_failed"
        ][0]
        self.assertEqual(self.app.complete_action(failure, "agent-a"), "exact_retry")
        self.assertEqual(
            self.app.complete_action({**failure, "message": "conflict"}, "agent-a"),
            "conflict",
        )
        repeated = next(
            item
            for item in self.store.dashboard()["alerts"]
            if item["alert_id"] == first["alert_id"]
        )
        self.assertEqual(repeated["occurrence_count"], 1)

    def test_dispatched_result_is_accepted_during_report_grace(self):
        created = time.time()
        expires = created + 1.0
        action_id = self.store.queue_action(
            "agent-a", "snapshot", {}, expires_at=expires
        )
        self.assertEqual(
            [item.action_id for item in self.store.pending_actions("agent-a")],
            [action_id],
        )
        result = {
            "action_id": action_id,
            "action_type": "snapshot",
            "success": True,
            "message": "executed before authorization expiry",
            "started_at": created + 0.5,
            "completed_at": expires + 0.25,
        }
        with patch("sentinel_blue.store.time.time", return_value=expires + 5.0):
            self.assertEqual(
                self.app.complete_action(result, "agent-a"), "new"
            )
        self.assertEqual(self.store.get_action(action_id)["status"], "completed")

    def test_expired_result_cannot_resolve_linked_alert(self):
        alert_id = self.store.add_alert(
            "agent-a",
            AlertCandidate(
                "critical_file_changed",
                "Changed",
                "changed",
                "high",
                0.99,
                {"path": "/tmp/a"},
                "review",
                "restore_integrity",
            ),
        )
        action_id = self.store.queue_action(
            "agent-a",
            "restore_integrity",
            {"path": "/tmp/a", "baseline_sha256": "a" * 64},
            alert_id,
            expires_at=time.time() - 1,
        )
        result = self._result(
            action_id,
            success=True,
            action_type="restore_integrity",
            pre_state={"transaction_id": "transaction-1"},
        )
        self.assertEqual(self.app.complete_action(result, "agent-a"), "conflict")
        self.assertEqual(self.store.get_alert(alert_id)["status"], "open")

    def test_governance_transition_holds_delivered_outcome_until_late_result(self):
        alert_id = self.store.add_alert(
            "agent-a",
            AlertCandidate(
                "fixture",
                "Fixture",
                "fixture",
                "high",
                0.99,
                {"fixture": True},
                "review",
                "snapshot",
            ),
        )
        action_id = self.store.queue_action(
            "agent-a", "snapshot", {}, alert_id
        )
        self.assertEqual(
            [item.action_id for item in self.store.pending_actions("agent-a")],
            [action_id],
        )

        self.app.emergency_stop()
        self.assertEqual(
            self.store.get_action(action_id)["status"], "outcome_unknown"
        )
        self.assertEqual(
            self.store.queue_action("agent-a", "snapshot", {}, alert_id),
            action_id,
        )

        late = self._result(action_id, success=True)
        self.assertEqual(self.app.complete_action(late, "agent-a"), "new")
        self.assertEqual(self.store.get_action(action_id)["status"], "completed")

    def test_operator_reconciliation_is_idempotent_and_controls_deduplication(self):
        alert_id = self.store.add_alert(
            "agent-a",
            AlertCandidate(
                "fixture-reconcile",
                "Fixture",
                "fixture",
                "high",
                0.99,
                {"fixture": True},
                "review",
                "snapshot",
            ),
        )
        action_id = self.store.queue_action(
            "agent-a", "snapshot", {}, alert_id
        )
        self.store.pending_actions("agent-a")
        self.app.emergency_stop()

        reconciled = self.store.reconcile_action_outcome(action_id, "executed")
        self.assertEqual(reconciled["status"], "reconciled")
        self.assertEqual(
            self.store.reconcile_action_outcome(action_id, "executed")[
                "completion"
            ],
            "exact_retry",
        )
        self.assertEqual(
            self.store.queue_action("agent-a", "snapshot", {}, alert_id),
            action_id,
        )
        self.assertEqual(
            self.app.complete_action(
                self._result(action_id, success=True), "agent-a"
            ),
            "conflict",
        )

        second_alert = self.store.add_alert(
            "agent-a",
            AlertCandidate(
                "fixture-not-executed",
                "Fixture",
                "fixture",
                "high",
                0.99,
                {"fixture": True},
                "review",
                "snapshot",
            ),
        )
        second = self.store.queue_action(
            "agent-a", "snapshot", {}, second_alert
        )
        self.assertIsNotNone(self.store.decide_alert(second_alert, "approve"))
        self.store.pending_actions("agent-a")
        self.app.resume_changes()
        self.assertEqual(
            self.store.get_action(second)["status"], "outcome_unknown"
        )
        not_executed = self.store.reconcile_action_outcome(
            second, "not_executed"
        )
        self.assertEqual(not_executed["status"], "failed")
        self.assertTrue(not_executed["alert_reopened"])
        self.assertEqual(self.store.get_alert(second_alert)["status"], "open")
        replacement = self.store.queue_action(
            "agent-a", "snapshot", {}, second_alert
        )
        self.assertNotEqual(replacement, second)

    def test_exhausted_delivery_becomes_reconcilable_without_consuming_quota(self):
        base = time.time()
        action_id = self.store.queue_action(
            "agent-a", "snapshot", {}, expires_at=base + 10_000
        )
        for attempt in range(5):
            with patch(
                "sentinel_blue.store.time.time",
                return_value=base + attempt * 91.0,
            ):
                self.assertEqual(
                    [
                        item.action_id
                        for item in self.store.pending_actions("agent-a")
                    ],
                    [action_id],
                )
        with patch(
            "sentinel_blue.store.time.time",
            return_value=base + 5 * 91.0,
        ):
            self.assertEqual(self.store.pending_actions("agent-a"), [])
        self.assertEqual(
            self.store.get_action(action_id)["status"], "outcome_unknown"
        )
        with self.store._lock:
            outstanding = self.store._connection.execute(
                "SELECT COUNT(*) FROM actions WHERE agent_id='agent-a' "
                "AND status IN ('queued','dispatched')"
            ).fetchone()[0]
        self.assertEqual(outstanding, 0)

    def test_alertless_unknown_effect_blocks_identical_requeue_until_reconciled(self):
        action_id = self.store.queue_action(
            "agent-a", "snapshot", {"scope": "same"}
        )
        self.store.pending_actions("agent-a")
        self.app.emergency_stop()
        self.assertEqual(
            self.store.queue_action(
                "agent-a", "snapshot", {"scope": "same"}
            ),
            action_id,
        )
        self.store.reconcile_action_outcome(action_id, "not_executed")
        replacement = self.store.queue_action(
            "agent-a", "snapshot", {"scope": "same"}
        )
        self.assertNotEqual(replacement, action_id)

    def test_reenrolled_agent_can_flush_exact_pre_rotation_result_without_effects(self):
        binding = {
            "credential_epoch": 0,
            "profile_id": "profile-a",
            "profile_fingerprint": "a" * 64,
            "agent_version": "1.9.7",
        }
        with self.store._lock:
            self.store._connection.execute(
                "UPDATE agents SET latest_telemetry='{}', profile_id=?, "
                "profile_fingerprint=?, agent_version=? WHERE agent_id='agent-a'",
                (
                    binding["profile_id"],
                    binding["profile_fingerprint"],
                    binding["agent_version"],
                ),
            )
            self.store._connection.commit()
        action_id = self.store.queue_action(
            "agent-a",
            "snapshot",
            {},
            profile_id=binding["profile_id"],
            profile_fingerprint=binding["profile_fingerprint"],
            autonomy_mode="approval-based",
            binding=binding,
        )
        self.assertEqual(
            [
                item.action_id
                for item in self.store.pending_actions(
                    "agent-a", binding=binding
                )
            ],
            [action_id],
        )
        envelope_sha256 = self.store.get_action(action_id)["envelope_sha256"]
        self.assertTrue(self.store.set_agent_enabled("agent-a", False))
        self.assertEqual(
            self.store.get_action(action_id)["status"], "outcome_unknown"
        )
        with self.store._lock:
            self.store._connection.execute(
                "UPDATE agents SET enabled=1, latest_telemetry='{}', "
                "profile_id=?, profile_fingerprint=?, agent_version=? "
                "WHERE agent_id='agent-a'",
                (
                    binding["profile_id"],
                    binding["profile_fingerprint"],
                    binding["agent_version"],
                ),
            )
            self.store._connection.commit()
        late = self._result(
            action_id,
            success=True,
            action_envelope_sha256=envelope_sha256,
        )
        self.assertEqual(self.app.complete_action(late, "agent-a"), "new")
        self.assertEqual(self.store.get_action(action_id)["status"], "completed")


class StoredJsonIsolationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "corrupt.db")
        self.store.register_agent("agent-a", "host-a", "Linux")

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    def test_corrupt_active_rows_are_isolated_without_breaking_consumers(self):
        action_id = self.store.queue_action("agent-a", "snapshot", {})
        alert_id = self.store.add_alert(
            "agent-a",
            AlertCandidate(
                "test", "Test", "summary", "high", 0.9, {"safe": True}, "review", "snapshot"
            ),
        )
        self.store.record_feedback(
            alert_id, "test", "approve", 1, {"integrity_change": 0.5}
        )
        with self.store._lock:
            self.store._connection.execute(
                "UPDATE actions SET parameters_json=? WHERE action_id=?",
                ('{"same":1,"same":2}', action_id),
            )
            self.store._connection.execute(
                "UPDATE alerts SET evidence_json=? WHERE alert_id=?",
                ('{"value":NaN}', alert_id),
            )
            self.store._connection.execute(
                "UPDATE agents SET latest_telemetry=? WHERE agent_id='agent-a'",
                ('{"agent_id":"agent-a","nested":{"value":Infinity}}',),
            )
            self.store._connection.execute(
                "UPDATE learning_feedback SET features_json='not-json'"
            )
            self.store._connection.commit()

        self.assertEqual(self.store.pending_actions("agent-a"), [])
        self.assertEqual(self.store.feedback_samples(), [])
        latest = self.store.latest_telemetry_for_agent("agent-a")
        dashboard = self.store.dashboard()
        action = next(item for item in dashboard["actions"] if item["action_id"] == action_id)
        alert = next(item for item in dashboard["alerts"] if item["alert_id"] == alert_id)
        self.assertEqual(action["status"], "failed")
        self.assertTrue(action["parameters"]["unavailable"])
        # Corrupt current agent telemetry revokes the whole agent authority
        # epoch before the dashboard later decodes this alert's evidence.
        self.assertEqual(alert["status"], "invalidated")
        self.assertTrue(alert["evidence"]["unavailable"])
        self.assertFalse(dashboard["stored_json"]["ready"])
        self.assertGreaterEqual(dashboard["stored_json"]["quarantined_rows"], 4)
        self.assertTrue(latest["unavailable"])
        self.assertTrue(latest["collector_errors"])


class StrictHttpJsonTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "http.db")
        self.app = ControllerApp(self.store, "b" * 32, operator_token="o" * 32)
        self.server = ControllerServer(("127.0.0.1", 0), make_handler(self.app))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.store.close()
        self.directory.cleanup()

    def test_signed_duplicate_key_ingress_gets_signed_rejection_and_no_state_change(self):
        agent_id = "duplicate-agent"
        path = "/api/v1/agent/enroll"
        body = b'{"agent_id":"duplicate-agent","agent_id":"other","hostname":"h","platform":"p"}'
        timestamp = str(time.time())
        request_signature = signature("b" * 32, timestamp, "POST", path, body)
        request = Request(
            self.url + path,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-SB-Agent": agent_id,
                "X-SB-Timestamp": timestamp,
                "X-SB-Signature": request_signature,
            },
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(request)
        self.assertEqual(raised.exception.code, 400)
        self.assertTrue(raised.exception.headers.get("X-SB-Response-Signature"))
        self.assertFalse(self.store.agent_exists(agent_id))

    def test_agent_rejects_signed_duplicate_key_response(self):
        class Response:
            status = 200

            def __init__(self, headers, body):
                self.headers = headers
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _limit):
                return self.body

        token = "c" * 64
        agent_id = "strict-agent"
        path = f"/api/v1/agent/actions?agent_id={agent_id}"
        body = b'{"actions":[],"actions":[{}]}'
        now = time.time()
        timestamp = str(now)
        request_signature = signature(token, timestamp, "GET", path, b"")
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
            "X-SB-Response-Version": "2",
            "X-SB-Response-Timestamp": timestamp,
            "X-SB-Response-Signature": response_signature(
                token, timestamp, 200, path, request_signature, body
            ),
        }
        client = AgentClient(self.url, "b" * 32, agent_id, agent_token=token)
        with patch("sentinel_blue.agent.time.time", return_value=now):
            with patch.object(client.opener, "open", return_value=Response(headers, body)):
                with self.assertRaisesRegex(ValueError, "duplicate"):
                    client.actions()

    def test_conflicting_action_result_is_a_signed_http_409(self):
        client = AgentClient(self.url, "b" * 32, "result-agent")
        client.enroll("result-host", "Linux")
        action_id = self.store.queue_action("result-agent", "snapshot", {})
        self.assertEqual(client.actions()[0]["action_id"], action_id)
        now = time.time()
        result = {
            "action_type": "snapshot",
            "success": True,
            "message": "complete",
            "started_at": now,
            "completed_at": now,
        }
        accepted = client.result(action_id, result)
        self.assertEqual(accepted["completion"], "new")
        with self.assertRaises(HTTPError) as raised:
            client.result(action_id, {**result, "message": "conflict"})
        self.assertEqual(raised.exception.code, 409)
        self.assertTrue(raised.exception.sentinel_blue_verified)
        self.assertIn("conflicts", raised.exception.sentinel_blue_error)


if __name__ == "__main__":
    unittest.main()
