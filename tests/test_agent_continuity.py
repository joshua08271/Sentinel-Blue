"""Outage collection, bounded retries, and at-most-once result reconciliation."""
import copy
from http.client import IncompleteRead, RemoteDisconnected
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.error import HTTPError, URLError

from sentinel_blue import __version__
from sentinel_blue.agent import (
    AgentClient, ActionResultOutbox, ControllerBackoff, _run_with_windows_state_guard,
    deliver_pending_action_results, process_controller_actions,
)
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.state import ActionJournal, TelemetrySpool


class EndRun(BaseException):
    pass


class AgentContinuityTests(unittest.TestCase):
    def test_all_routes_share_bounded_backoff_and_success_resets_it(self):
        client = AgentClient("https://127.0.0.1:8765", "", "agent-one", agent_token="a" * 64)
        clock = [100.0]
        with patch("sentinel_blue.agent.time.monotonic", side_effect=lambda: clock[0]), patch.object(
            client, "_request_once", side_effect=TimeoutError("owned disconnected controller")
        ) as request:
            for delay in (5, 10, 15, 15):
                with self.assertRaises(TimeoutError):
                    client.actions()
                before = request.call_count
                with self.assertRaises(ControllerBackoff):
                    client.telemetry({})
                with self.assertRaises(ControllerBackoff):
                    client.result("result-one", {})
                self.assertEqual(request.call_count, before)
                self.assertEqual(client._retry_at, clock[0] + delay)
                clock[0] += delay
            request.side_effect = None
            request.return_value = {"actions": []}
            self.assertEqual(client.actions(), [])
            self.assertEqual(client._connection_failures, 0)
            request.side_effect = TimeoutError("offline again")
            with self.assertRaises(TimeoutError):
                client.actions()
            self.assertEqual(client._retry_at, clock[0] + 5)

    def test_only_authenticated_permanent_rejections_skip_backoff(self):
        for code, verified, deferred in ((403, True, False), (403, False, True), (429, True, True), (503, True, True)):
            with self.subTest(code=code, verified=verified):
                client = AgentClient("https://127.0.0.1:8765", "", "agent-one", agent_token="a" * 64)
                error = HTTPError(client.controller, code, "fixture", {}, None)
                error.sentinel_blue_verified = verified
                with patch.object(client, "_request_once", side_effect=error):
                    with self.assertRaises(HTTPError):
                        client.actions()
                self.assertEqual(client._retry_at > 0, deferred)

    def test_poll_disconnects_cannot_claim_or_execute_an_action(self):
        for failure in (TimeoutError(), URLError("offline"), RemoteDisconnected(), IncompleteRead(b"{"), ValueError("bad response signature")):
            with self.subTest(failure=type(failure).__name__):
                client = MagicMock()
                client.actions.side_effect = failure
                outbox = MagicMock()
                outbox.has_unacknowledged.return_value = False
                journal, executor = MagicMock(), MagicMock()
                self.assertEqual(process_controller_actions(
                    client, outbox, journal, executor, {}, {}, EventProfile.testing()
                ), 0)
                journal.begin.assert_not_called()
                executor.execute.assert_not_called()

    def test_mutation_errors_are_not_misclassified_as_network_fetch_failures(self):
        client = MagicMock()
        client.actions.return_value = [{"action_id": "owned-action"}]
        outbox = MagicMock()
        outbox.has_unacknowledged.return_value = False
        with patch("sentinel_blue.agent.refresh_recovery_health"), patch(
            "sentinel_blue.agent.execute_queued_action", side_effect=OSError("journal write failed")
        ):
            with self.assertRaisesRegex(OSError, "journal write failed"):
                process_controller_actions(client, outbox, MagicMock(), MagicMock(), {}, {}, EventProfile.testing())

    def test_collection_and_durable_spooling_continue_at_every_disconnect_boundary(self):
        for boundary in ("offline_start", "before_collection", "during_collection"):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as directory:
                state = {"collections": 0, "clock": 0.0, "offline": boundary == "offline_start"}
                sent, retained = [], []
                client = MagicMock()
                client.agent_token = "a" * 64
                profile = MagicMock()
                profile.assert_inventory_networks = MagicMock()
                profile.release = {"sha256": ""}
                profile.profile_id, profile.fingerprint = "profile-one", "b" * 64
                profile.authorized_networks = profile.authorized_hosts = profile.excluded_hosts = ()
                lock, watcher = MagicMock(), MagicMock()
                lock.acquire.return_value = lock
                args = SimpleNamespace(
                    log_level="WARNING", agent_id="agent-one", event_profile="profile.json",
                    range_deployment=False, expected_package_sha256=None, authorized_network=[],
                    allow_containment=False, allow_restoration=False, state_dir=directory,
                    log_file=None, controller="https://127.0.0.1:8765", token=None, token_file=None,
                    reenroll=False, ca_file=None, spool_limit=16, probe_config=None, quarantine_ttl=300,
                    change_watch_interval=1, once=False, interval=5,
                )

                def collect(*_args, **_kwargs):
                    retained.append([row[1]["sequence"] for row in TelemetrySpool(directory).pending()])
                    state["collections"] += 1
                    if state["collections"] == 2 and boundary == "during_collection":
                        state["offline"] = True
                    if state["collections"] == 4:
                        state["offline"] = False
                    return SimpleNamespace(as_dict=lambda: {
                        "agent_id": "agent-one", "agent_version": __version__, "hostname": "host",
                        "platform": "Linux", "boot_id": "boot-one", "observed_at": float(state["collections"]),
                        "collector_errors": [], "probes": [], "integrity": [],
                    })

                def actions():
                    if state["offline"]:
                        raise TimeoutError("owned controller unavailable")
                    return []

                def upload(sample):
                    if state["offline"]:
                        raise URLError("owned controller unavailable")
                    sent.append(copy.deepcopy(sample))

                def wait(seconds):
                    if state["collections"] == 4:
                        raise EndRun
                    state["clock"] += seconds
                    if state["collections"] == 1 and boundary == "before_collection":
                        state["offline"] = True
                    return False

                client.actions.side_effect, client.telemetry.side_effect = actions, upload
                watcher.wait.side_effect = wait
                with (
                    patch("sentinel_blue.agent.configure_agent_logging"),
                    patch("sentinel_blue.agent.load_event_profile", return_value=profile),
                    patch("sentinel_blue.agent.AgentProcessLock", return_value=lock),
                    patch("sentinel_blue.agent.AgentClient", return_value=client),
                    patch("sentinel_blue.agent.load_agent_credentials", return_value=("", "a" * 64, None)),
                    patch("sentinel_blue.agent.ActionExecutor", return_value=MagicMock()),
                    patch("sentinel_blue.agent.ChangeWatcher", return_value=watcher),
                    patch("sentinel_blue.agent.collect", side_effect=collect),
                    patch("sentinel_blue.agent.assess_agent_health", side_effect=lambda *_: {
                        "healthy": True, "action_safe": True, "errors": [], "critical_errors": [],
                    }),
                    patch("sentinel_blue.agent.refresh_windows_state_health"),
                    patch("sentinel_blue.agent.refresh_recovery_health"),
                    patch("sentinel_blue.agent.systemd_notify"),
                    patch("sentinel_blue.agent.time.monotonic", side_effect=lambda: state["clock"]),
                    patch("sentinel_blue.agent.atexit.register"),
                ):
                    with self.assertRaises(EndRun):
                        _run_with_windows_state_guard(args, None)
                self.assertEqual([row["sequence"] for row in sent], [1, 2, 3, 4])
                self.assertIn(2, retained[2], "second sample must survive the disconnect")
                self.assertIn(3, retained[3], "third sample must survive the disconnect")
                self.assertEqual(TelemetrySpool(directory).pending(), [])

    def test_lost_result_ack_restarts_outbox_without_repeating_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = EventProfile.testing()
            journal = ActionJournal(directory, profile_fingerprint=profile.fingerprint)
            outbox = ActionResultOutbox(journal)
            executor, client = MagicMock(), MagicMock()
            executor.execute.return_value = {"success": True, "message": "owned action completed"}
            action = {"action_id": "owned-once", "action_type": "snapshot", "parameters": {}}
            client.actions.return_value = [action]
            client.result.side_effect = RemoteDisconnected("ack lost after controller commit")
            with patch("sentinel_blue.agent.refresh_recovery_health"):
                self.assertEqual(process_controller_actions(
                    client, outbox, journal, executor, {"agent_id": "agent-one"},
                    {"action_safe": True}, profile,
                ), 1)
            self.assertEqual(executor.execute.call_count, 1)
            reloaded = ActionResultOutbox(ActionJournal(directory, profile_fingerprint=profile.fingerprint))
            self.assertTrue(reloaded.has_unacknowledged())
            client.result.side_effect = None
            client.result.return_value = {"completed": True, "completion": "exact_retry"}
            self.assertEqual(deliver_pending_action_results(client, reloaded, now=2_000_000_000), 1)
            with patch("sentinel_blue.agent.refresh_recovery_health"):
                process_controller_actions(client, reloaded, reloaded.journal, executor,
                                           {"agent_id": "agent-one"}, {"action_safe": True}, profile)
            self.assertEqual(executor.execute.call_count, 1)
