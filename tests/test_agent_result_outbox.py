import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from sentinel_blue.agent import (
    MAX_ACTION_RESULTS_PER_CYCLE,
    ActionResultOutbox,
    _run_with_windows_state_guard,
    deliver_pending_action_results,
    enroll_and_persist_identity,
    execute_queued_action,
    load_agent_credentials,
    process_controller_actions,
)
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.state import ActionJournal, read_private_json, write_private_json
from sentinel_blue.validation import validate_action_result


def action_result(message="complete"):
    return {
        "action_type": "snapshot",
        "success": True,
        "message": message,
        "started_at": 10.0,
        "completed_at": 11.0,
    }


def verified_http_error(status, message):
    error = HTTPError("https://controller.invalid", status, message, {}, None)
    error.sentinel_blue_verified = True
    error.sentinel_blue_error = message
    return error


class ResultClient:
    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = []

    def result(self, action_id, result):
        self.calls.append((action_id, result))
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class EnrollmentClient:
    def __init__(self, events, candidate="n" * 64):
        self.events = events
        self.candidate = candidate
        self.token = "t" * 64
        self.agent_token = None

    def request_enrollment(self, hostname, platform_name):
        self.events.append(("request", hostname, platform_name))
        return self.candidate

    def activate_enrollment(self, candidate):
        self.events.append(("activate", candidate))
        self.agent_token = candidate
        self.token = ""


class ActionResultOutboxTests(unittest.TestCase):
    def test_completed_journal_result_retries_without_action_redelivery(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            journal.remember("action-1", action_result(), now=12.0)
            outbox = ActionResultOutbox(journal)

            failed = ResultClient(URLError("offline"))
            self.assertEqual(
                deliver_pending_action_results(failed, outbox, now=20.0), 0
            )
            self.assertEqual([item[0] for item in failed.calls], ["action-1"])
            self.assertEqual(outbox.pending(now=24.9), [])

            restarted = ActionResultOutbox(ActionJournal(directory))
            accepted = ResultClient(
                {"completed": True, "completion": "exact_retry"}
            )
            self.assertEqual(
                deliver_pending_action_results(accepted, restarted, now=25.0), 1
            )
            final = ActionResultOutbox(ActionJournal(directory))
            self.assertEqual(final.pending(now=10_000.0), [])
            self.assertEqual(
                final.delivery_record("action-1")["completion"], "exact_retry"
            )

    def test_legacy_completion_without_delivery_metadata_is_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            journal.remember("legacy-action", action_result(), now=12.0)
            restarted = ActionResultOutbox(ActionJournal(directory))
            self.assertEqual(
                [item[0] for item in restarted.pending(now=20.0)],
                ["legacy-action"],
            )
            self.assertTrue(restarted.has_unacknowledged())

    def test_signed_conflict_remains_bounded_reconciliation_state(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            journal.remember("conflicted-action", action_result(), now=12.0)
            outbox = ActionResultOutbox(journal)
            client = ResultClient(
                *(verified_http_error(409, "terminal conflict") for _ in range(4))
            )
            current = 20.0
            for expected_attempts in range(1, 5):
                deliver_pending_action_results(client, outbox, now=current)
                delivery = outbox.delivery_record("conflicted-action")
                self.assertEqual(delivery["state"], "reconciliation")
                self.assertEqual(
                    delivery["reconciliation_attempts"], expected_attempts
                )
                current = delivery["next_attempt_at"]
            self.assertEqual(outbox.pending(now=100_000.0), [])
            self.assertTrue(outbox.has_unacknowledged())
            self.assertIsNotNone(journal.record("conflicted-action"))

    def test_signed_non_acknowledgement_body_stays_for_reconciliation(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            journal.remember("action-bad-ack", action_result(), now=12.0)
            outbox = ActionResultOutbox(journal)
            client = ResultClient({"completed": False, "completion": "conflict"})
            self.assertEqual(
                deliver_pending_action_results(client, outbox, now=20.0), 0
            )
            self.assertEqual(
                outbox.delivery_record("action-bad-ack")["state"],
                "reconciliation",
            )

    def test_ack_commit_failure_does_not_false_ack_in_memory(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            journal.remember("action-commit", action_result(), now=12.0)
            outbox = ActionResultOutbox(journal)
            with patch.object(journal, "_commit", side_effect=OSError("disk full")):
                with self.assertRaisesRegex(RuntimeError, "requires review"):
                    outbox.acknowledge("action-commit", "new", now=20.0)
            self.assertNotIn(
                ActionResultOutbox._FIELD, journal._records["action-commit"]
            )
            self.assertFalse(journal.healthy)

            restarted = ActionResultOutbox(ActionJournal(directory))
            self.assertEqual(
                [item[0] for item in restarted.pending(now=20.0)],
                ["action-commit"],
            )

    def test_acknowledged_redelivery_resets_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            result = action_result()
            journal.remember("action-redelivered", result, now=12.0)
            outbox = ActionResultOutbox(journal)
            outbox.acknowledge("action-redelivered", "new", now=20.0)
            self.assertFalse(outbox.has_unacknowledged())

            outbox.enqueue("action-redelivered", result)
            self.assertTrue(outbox.has_unacknowledged())
            self.assertEqual(
                [item[0] for item in outbox.pending(now=20.0)],
                ["action-redelivered"],
            )

    def test_result_batch_is_bounded_without_evicting_pending(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            for index in range(MAX_ACTION_RESULTS_PER_CYCLE + 8):
                journal.remember(
                    f"action-{index:02d}", action_result(str(index)), now=12.0 + index
                )
            outbox = ActionResultOutbox(ActionJournal(directory))
            self.assertEqual(len(outbox.pending(now=100.0, limit=10_000)), 32)
            self.assertEqual(
                len(ActionJournal(directory)._records),
                MAX_ACTION_RESULTS_PER_CYCLE + 8,
            )

    def test_duplicate_key_journal_fails_at_private_state_boundary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "action-journal.json"
            record = {
                "status": "completed",
                "completed_at": 12.0,
                "expires_at": 0.0,
                "retain_until": 20.0,
                "profile_fingerprint": "",
                "result": action_result(),
            }
            encoded = json.dumps(record, separators=(",", ":"))
            path.write_text(
                '{"duplicate":' + encoded + ',"duplicate":' + encoded + "}",
                encoding="utf-8",
            )
            journal = ActionJournal(directory)
            self.assertFalse(journal.healthy)
            outbox = ActionResultOutbox(journal)
            with self.assertRaisesRegex(RuntimeError, "requires review"):
                outbox.pending(now=20.0)

    def test_verified_401_never_triggers_enrollment_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            journal.remember("action-401", action_result(), now=12.0)
            outbox = ActionResultOutbox(journal)
            client = ResultClient(verified_http_error(401, "invalid signature"))
            client.agent_token = "o" * 64
            client.request_enrollment = MagicMock()
            deliver_pending_action_results(client, outbox, now=20.0)
            self.assertEqual(client.agent_token, "o" * 64)
            client.request_enrollment.assert_not_called()
            self.assertEqual(
                outbox.delivery_record("action-401")["state"], "pending"
            )

    def test_unacknowledged_backoff_blocks_new_action_polling(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            journal.remember("action-backoff", action_result(), now=12.0)
            outbox = ActionResultOutbox(journal)
            outbox.defer("action-backoff", "offline", now=20.0)
            client = MagicMock()

            self.assertEqual(
                process_controller_actions(
                    client,
                    outbox,
                    journal,
                    MagicMock(),
                    {"boot_id": "boot-one"},
                    {"action_safe": True, "critical_errors": []},
                    EventProfile.testing(),
                ),
                0,
            )
            client.actions.assert_not_called()

    def test_self_health_refusal_is_a_schema_valid_durable_result(self):
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            result = execute_queued_action(
                journal,
                MagicMock(),
                {
                    "action_id": "health-refusal",
                    "action_type": "snapshot",
                    "parameters": {},
                },
                {},
                {"action_safe": False, "critical_errors": ["unsafe state"]},
            )
            normalized = validate_action_result(
                {**result, "action_id": "health-refusal"}
            )
            self.assertFalse(normalized["success"])
            self.assertEqual(
                ActionJournal(directory).get("health-refusal"), result
            )


class AgentReenrollmentTests(unittest.TestCase):
    @staticmethod
    def write_identity(path, token="o" * 64, fingerprint="a" * 64):
        write_private_json(
            path,
            {
                "agent_id": "agent-one",
                "agent_token": token,
                "profile_id": "profile-one",
                "profile_fingerprint": fingerprint,
            },
        )

    def test_existing_identity_and_ticket_require_explicit_reenroll(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "identity.json"
            ticket = root / "enrollment.json"
            self.write_identity(identity)
            ticket.write_text(json.dumps({"token": "t" * 64}), encoding="utf-8")
            original = identity.read_bytes()

            with self.assertRaisesRegex(ValueError, "without --re-enroll"):
                load_agent_credentials(
                    identity,
                    "agent-one",
                    "profile-one",
                    "a" * 64,
                    token_file=str(ticket),
                )
            self.assertEqual(identity.read_bytes(), original)
            self.assertTrue(ticket.exists())

    def test_explicit_reenroll_uses_ticket_not_stored_token(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "identity.json"
            ticket = root / "enrollment.json"
            self.write_identity(identity)
            ticket.write_text(json.dumps({"token": "t" * 64}), encoding="utf-8")

            bootstrap, agent_token, token_path = load_agent_credentials(
                identity,
                "agent-one",
                "profile-one",
                "a" * 64,
                token_file=str(ticket),
                reenroll=True,
            )
            self.assertEqual(bootstrap, "t" * 64)
            self.assertIsNone(agent_token)
            self.assertEqual(token_path, ticket)
            self.assertEqual(read_private_json(identity)["agent_token"], "o" * 64)

    def test_reenroll_requires_existing_valid_identity_and_ticket(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "identity.json"
            with self.assertRaisesRegex(ValueError, "existing valid identity"):
                load_agent_credentials(
                    identity,
                    "agent-one",
                    "profile-one",
                    "a" * 64,
                    inline_token="t" * 64,
                    reenroll=True,
                )
            self.write_identity(identity, fingerprint="b" * 64)
            with self.assertRaisesRegex(ValueError, "different event profile"):
                load_agent_credentials(
                    identity,
                    "agent-one",
                    "profile-one",
                    "a" * 64,
                    inline_token="t" * 64,
                    reenroll=True,
                )

    def test_identity_requires_exact_profile_id_and_fingerprint(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "identity.json"
            self.write_identity(identity)
            cases = (
                ("other-profile", "a" * 64),
                ("profile-one", "b" * 64),
            )
            for profile_id, fingerprint in cases:
                for reenroll in (False, True):
                    with self.subTest(
                        profile_id=profile_id,
                        fingerprint=fingerprint,
                        reenroll=reenroll,
                    ):
                        with self.assertRaisesRegex(
                            ValueError, "different event profile"
                        ):
                            load_agent_credentials(
                                identity,
                                "agent-one",
                                profile_id,
                                fingerprint,
                                inline_token="t" * 64 if reenroll else None,
                                reenroll=reenroll,
                            )

    def test_identity_missing_release_binding_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "identity.json"
            ticket = root / "enrollment.json"
            ticket.write_text(json.dumps({"token": "t" * 64}), encoding="utf-8")
            for invalid_field, invalid_value in (
                ("profile_id", "missing"),
                ("profile_id", None),
                ("profile_fingerprint", "missing"),
                ("profile_fingerprint", None),
            ):
                payload = {
                    "agent_id": "agent-one",
                    "agent_token": "o" * 64,
                    "profile_id": "profile-one",
                    "profile_fingerprint": "a" * 64,
                }
                if invalid_value == "missing":
                    payload.pop(invalid_field)
                else:
                    payload[invalid_field] = invalid_value
                write_private_json(identity, payload)
                original = identity.read_bytes()
                with self.subTest(
                    invalid_field=invalid_field, invalid_value=invalid_value
                ):
                    with patch(
                        "sentinel_blue.agent._read_bootstrap_ticket"
                    ) as read_ticket:
                        with self.assertRaisesRegex(
                            ValueError, "different event profile"
                        ):
                            load_agent_credentials(
                                identity,
                                "agent-one",
                                "profile-one",
                                "a" * 64,
                                token_file=str(ticket),
                                reenroll=True,
                            )
                    read_ticket.assert_not_called()
                    self.assertEqual(identity.read_bytes(), original)
                    self.assertTrue(ticket.exists())

    def test_bootstrap_ticket_requires_at_least_32_url_safe_characters(self):
        with tempfile.TemporaryDirectory() as directory:
            identity = Path(directory) / "identity.json"
            for ticket in ("x" * 31, "x" * 31 + "!"):
                with self.subTest(ticket=ticket):
                    with self.assertRaisesRegex(ValueError, "bootstrap token is invalid"):
                        load_agent_credentials(
                            identity,
                            "agent-one",
                            "profile-one",
                            "a" * 64,
                            inline_token=ticket,
                        )

    def test_first_enrollment_finishes_before_readiness(self):
        class ReadyReached(Exception):
            pass

        with tempfile.TemporaryDirectory() as directory:
            events = []
            client = MagicMock()
            client.agent_token = None
            client.token = "t" * 64
            profile = MagicMock()
            profile.release = {"sha256": ""}
            profile.authorized_networks = ()
            profile.authorized_hosts = ()
            profile.excluded_hosts = ()
            profile.fingerprint = "a" * 64
            profile.profile_id = "profile-one"
            profile.allows.return_value = True
            profile.assert_inventory_networks = MagicMock()
            lock = MagicMock()
            lock.acquire.return_value = lock
            args = SimpleNamespace(
                log_level="WARNING",
                agent_id="agent-one",
                event_profile="profile.json",
                range_deployment=False,
                expected_package_sha256=None,
                authorized_network=[],
                allow_containment=False,
                allow_restoration=False,
                state_dir=directory,
                log_file=None,
                controller="https://127.0.0.1:8765",
                token="t" * 64,
                token_file=None,
                reenroll=False,
                ca_file=None,
                spool_limit=16,
                probe_config=None,
                quarantine_ttl=300.0,
                change_watch_interval=1.0,
                once=True,
            )

            def enroll(*_args, **_kwargs):
                events.append("enroll")
                client.agent_token = "n" * 64
                client.token = ""
                return client.agent_token

            def notify(message):
                if message.startswith("READY=1"):
                    events.append("ready")
                    raise ReadyReached
                return True

            with (
                patch("sentinel_blue.agent.configure_agent_logging"),
                patch("sentinel_blue.agent.load_event_profile", return_value=profile),
                patch("sentinel_blue.agent.AgentProcessLock", return_value=lock),
                patch("sentinel_blue.agent.AgentClient", return_value=client),
                patch(
                    "sentinel_blue.agent.enroll_and_persist_identity",
                    side_effect=enroll,
                ),
                patch("sentinel_blue.agent.ActionExecutor", return_value=MagicMock()),
                patch("sentinel_blue.agent.ChangeWatcher", return_value=MagicMock()),
                patch("sentinel_blue.agent.systemd_notify", side_effect=notify),
                patch("sentinel_blue.agent.atexit.register"),
            ):
                with self.assertRaises(ReadyReached):
                    _run_with_windows_state_guard(args, None)
            self.assertEqual(events, ["enroll", "ready"])

    def test_reenroll_publishes_then_activates_then_removes_ticket(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "identity.json"
            ticket = root / "enrollment.json"
            self.write_identity(identity)
            ticket.write_text(json.dumps({"token": "t" * 64}), encoding="utf-8")
            events = []
            client = EnrollmentClient(events)

            def write(path, payload):
                events.append(("write", path, payload["agent_token"]))

            def remove(path):
                events.append(("remove", path))

            with patch("sentinel_blue.agent.write_private_json", side_effect=write), patch(
                "sentinel_blue.agent.remove_private_file", side_effect=remove
            ):
                enroll_and_persist_identity(
                    client,
                    identity,
                    agent_id="agent-one",
                    hostname="host-one",
                    platform_name="Linux",
                    profile_id="profile-one",
                    profile_fingerprint="a" * 64,
                    token_path=ticket,
                )
            self.assertEqual(
                [event[0] for event in events],
                ["request", "write", "activate", "remove"],
            )

    def test_identity_write_failure_preserves_identity_ticket_and_activation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "identity.json"
            ticket = root / "enrollment.json"
            self.write_identity(identity)
            ticket.write_text(json.dumps({"token": "t" * 64}), encoding="utf-8")
            original = identity.read_bytes()
            events = []
            client = EnrollmentClient(events)

            with patch(
                "sentinel_blue.agent.write_private_json",
                side_effect=OSError("synthetic publish failure"),
            ):
                with self.assertRaisesRegex(OSError, "publish failure"):
                    enroll_and_persist_identity(
                        client,
                        identity,
                        agent_id="agent-one",
                        hostname="host-one",
                        platform_name="Linux",
                        profile_id="profile-one",
                        profile_fingerprint="a" * 64,
                        token_path=ticket,
                    )
            self.assertEqual(identity.read_bytes(), original)
            self.assertTrue(ticket.exists())
            self.assertIsNone(client.agent_token)
            self.assertEqual(client.token, "t" * 64)
            self.assertEqual([event[0] for event in events], ["request"])

    def test_successful_reenroll_atomically_replaces_identity_and_ticket(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = root / "identity.json"
            ticket = root / "enrollment.json"
            self.write_identity(identity)
            ticket.write_text(json.dumps({"token": "t" * 64}), encoding="utf-8")
            client = EnrollmentClient([])

            enroll_and_persist_identity(
                client,
                identity,
                agent_id="agent-one",
                hostname="host-one",
                platform_name="Linux",
                profile_id="profile-one",
                profile_fingerprint="a" * 64,
                token_path=ticket,
            )
            published = read_private_json(identity)
            self.assertEqual(published["agent_token"], "n" * 64)
            self.assertEqual(client.agent_token, "n" * 64)
            self.assertFalse(ticket.exists())


if __name__ == "__main__":
    unittest.main()
