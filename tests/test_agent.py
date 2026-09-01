import logging
import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from sentinel_blue.agent import (
    AgentClient,
    MIN_LOG_BYTES,
    configure_agent_logging,
    execute_queued_action,
    prepare_state_directory,
    refresh_recovery_health,
    refresh_restoration_health,
    refresh_windows_state_health,
    run,
    systemd_notify,
    telemetry_matches_release_binding,
)
from sentinel_blue import __version__
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.state import ActionJournal


class AgentTests(unittest.TestCase):
    def test_enrollment_payload_is_release_bound_and_stable_for_exact_retry(self):
        ticket = "t" * 64
        fingerprint = "a" * 64
        payloads = []

        def capture(_method, _path, payload, enrollment=False):
            self.assertTrue(enrollment)
            payloads.append(payload)
            return {"agent_token": "s" * 64}

        first = AgentClient(
            "https://127.0.0.1:8765",
            ticket,
            "agent-one",
            profile_id="profile-one",
            profile_fingerprint=fingerprint,
        )
        second = AgentClient(
            "https://127.0.0.1:8765",
            ticket,
            "agent-one",
            profile_id="profile-one",
            profile_fingerprint=fingerprint,
        )
        first._request = capture
        second._request = capture
        first.enroll("host-one", "Linux")
        second.enroll("host-one", "Linux")
        self.assertEqual(payloads[0], payloads[1])
        self.assertEqual(payloads[0]["agent_version"], __version__)
        self.assertRegex(payloads[0]["enrollment_nonce"], r"^[0-9a-f]{64}$")
        changed = AgentClient(
            "https://127.0.0.1:8765",
            "u" * 64,
            "agent-one",
            profile_id="profile-one",
            profile_fingerprint=fingerprint,
        )
        self.assertNotEqual(first.enrollment_nonce, changed.enrollment_nonce)

    def test_windows_state_health_refresh_is_validation_only(self):
        report = object()
        guard = MagicMock()
        guard.refresh.return_value = report
        health = {
            "healthy": True,
            "action_safe": True,
            "errors": [],
            "critical_errors": [],
        }
        self.assertIs(refresh_windows_state_health(guard, health), report)
        guard.refresh.assert_called_once_with(harden_safe_descendants=False)
        self.assertTrue(health["healthy"])
        self.assertTrue(health["action_safe"])

    def test_windows_state_health_failure_closes_action_gate(self):
        guard = MagicMock()
        guard.refresh.side_effect = ValueError("guard is closed")
        health = {
            "healthy": True,
            "action_safe": True,
            "errors": [],
            "critical_errors": [],
        }
        refresh_windows_state_health(guard, health)
        refresh_windows_state_health(guard, health)
        self.assertFalse(health["healthy"])
        self.assertFalse(health["action_safe"])
        self.assertEqual(len(health["errors"]), 1)
        self.assertEqual(len(health["critical_errors"]), 1)

    def test_windows_state_guard_precedes_stateful_start_and_lives_through_it(self):
        events: list[str] = []
        guard = MagicMock()
        guard.close.side_effect = lambda: events.append("close")

        def acquire(path, *, initialize):
            self.assertEqual(path, r"C:\ProgramData\SentinelBlue")
            self.assertTrue(initialize)
            events.append("acquire")
            return guard

        def stateful_start(_args, observed_guard):
            events.append("start")
            self.assertIs(observed_guard, guard)
            guard.close.assert_not_called()

        args = SimpleNamespace(state_dir=r"C:\ProgramData\SentinelBlue")
        with (
            patch("sentinel_blue.agent.acquire_windows_state_tree", side_effect=acquire),
            patch(
                "sentinel_blue.agent._run_with_windows_state_guard",
                side_effect=stateful_start,
            ),
            patch("sentinel_blue.agent.atexit.register") as register,
            patch("sentinel_blue.agent.atexit.unregister") as unregister,
        ):
            run(args)
        self.assertEqual(events, ["acquire", "start", "close"])
        register.assert_called_once_with(guard.close)
        unregister.assert_called_once_with(guard.close)
        guard.close.assert_called_once_with()

    def test_windows_state_guard_closes_on_startup_failure(self):
        guard = MagicMock()
        args = SimpleNamespace(state_dir=r"C:\ProgramData\SentinelBlue")
        with (
            patch(
                "sentinel_blue.agent.acquire_windows_state_tree", return_value=guard
            ),
            patch(
                "sentinel_blue.agent._run_with_windows_state_guard",
                side_effect=RuntimeError("startup failed"),
            ),
            patch("sentinel_blue.agent.atexit.register"),
            patch("sentinel_blue.agent.atexit.unregister"),
        ):
            with self.assertRaisesRegex(RuntimeError, "startup failed"):
                run(args)
        guard.close.assert_called_once_with()

    def test_non_windows_guard_path_remains_a_noop(self):
        args = SimpleNamespace(state_dir="/var/lib/sentinel-blue-agent")
        with (
            patch("sentinel_blue.agent.acquire_windows_state_tree", return_value=None),
            patch("sentinel_blue.agent._run_with_windows_state_guard") as stateful,
            patch("sentinel_blue.agent.atexit.register") as register,
        ):
            run(args)
        stateful.assert_called_once_with(args, None)
        register.assert_not_called()

    def test_running_agent_refreshes_restoration_failure_gate_without_restart(self):
        executor = MagicMock()
        executor.refresh_restore_recovery.return_value = {
            "healthy": False,
            "unresolved": ["transaction-example"],
        }
        health = {
            "healthy": True,
            "action_safe": True,
            "errors": [],
            "critical_errors": [],
        }
        refresh_restoration_health(executor, health)
        refresh_restoration_health(executor, health)
        self.assertFalse(health["healthy"])
        self.assertFalse(health["action_safe"])
        self.assertEqual(len(health["errors"]), 1)
        self.assertEqual(len(health["critical_errors"]), 1)

    def test_running_agent_refreshes_every_recovery_gate_in_the_same_cycle(self):
        executor = MagicMock()
        executor.refresh_recovery.return_value = {
            "restoration": {"healthy": True, "unresolved": []},
            "quarantine": {"healthy": False, "unresolved": ["resume failed"]},
            "service": {"healthy": False, "unresolved": ["rollback failed"]},
        }
        health = {
            "healthy": True,
            "action_safe": True,
            "errors": [],
            "critical_errors": [],
        }
        refresh_recovery_health(executor, health, "current-boot")
        refresh_recovery_health(executor, health, "current-boot")
        executor.refresh_recovery.assert_called_with("current-boot")
        self.assertFalse(health["healthy"])
        self.assertFalse(health["action_safe"])
        self.assertEqual(len(health["errors"]), 2)
        self.assertEqual(len(health["critical_errors"]), 2)

    def test_deployed_action_requires_exact_profile_and_local_agent_binding(self):
        profile = EventProfile.testing()
        profile = replace(
            profile,
            release={"version": __version__, "approved": True, "sha256": "a" * 64},
        )
        health = {"action_safe": True, "critical_errors": []}
        telemetry = {"agent_id": "local-agent"}
        executor = MagicMock()
        executor.execute.return_value = {"success": True}
        base = {
            "agent_id": "local-agent",
            "action_type": "observe",
            "parameters": {},
            "status": "dispatched",
            "created_at": time.time(),
            "automated": False,
            "risk": "none",
            "expires_at": time.time() + 60,
            "profile_id": profile.profile_id,
            "profile_fingerprint": profile.fingerprint,
            "autonomy_mode": profile.autonomy_mode,
        }
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            missing_profile = execute_queued_action(
                journal,
                executor,
                {
                    **base,
                    "action_id": "missing-profile",
                    "profile_id": "",
                    "profile_fingerprint": "",
                },
                telemetry,
                health,
                profile,
            )
            wrong_agent = execute_queued_action(
                journal,
                executor,
                {**base, "action_id": "wrong-agent", "agent_id": "other-agent"},
                telemetry,
                health,
                profile,
            )
            valid = execute_queued_action(
                journal,
                executor,
                {**base, "action_id": "valid"},
                telemetry,
                health,
                profile,
            )
        self.assertFalse(missing_profile["success"])
        self.assertFalse(wrong_agent["success"])
        self.assertTrue(valid["success"])
        executor.execute.assert_called_once()

    def test_deployed_action_rejects_type_confusion_and_malformed_parameters_before_claim(self):
        profile = replace(
            EventProfile.testing(),
            release={"version": __version__, "approved": True, "sha256": "a" * 64},
        )
        now = time.time()
        base = {
            "action_id": "strict-action",
            "agent_id": "local-agent",
            "action_type": "restart_service",
            "parameters": {"service": "web.service"},
            "status": "dispatched",
            "created_at": now,
            "automated": False,
            "risk": "high",
            "expires_at": now + 60,
            "profile_id": profile.profile_id,
            "profile_fingerprint": profile.fingerprint,
            "autonomy_mode": profile.autonomy_mode,
        }
        telemetry = {"agent_id": "local-agent"}
        health = {"action_safe": True, "critical_errors": []}
        executor = MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            confused = execute_queued_action(
                journal,
                executor,
                {**base, "automated": 0},
                telemetry,
                health,
                profile,
            )
            malformed = execute_queued_action(
                journal,
                executor,
                {**base, "parameters": {"service": 7}},
                telemetry,
                health,
                profile,
            )
            nonfinite = execute_queued_action(
                journal,
                executor,
                {**base, "expires_at": float("nan")},
                telemetry,
                health,
                profile,
            )
            self.assertIsNone(journal.record("strict-action"))
        self.assertFalse(confused["success"])
        self.assertFalse(malformed["success"])
        self.assertFalse(nonfinite["success"])
        executor.execute.assert_not_called()

    def test_same_action_id_with_altered_valid_envelope_fails_closed(self):
        profile = replace(
            EventProfile.testing(),
            release={"version": __version__, "approved": True, "sha256": "a" * 64},
        )
        now = time.time()
        action = {
            "action_id": "immutable-envelope",
            "agent_id": "local-agent",
            "action_type": "snapshot",
            "parameters": {},
            "status": "dispatched",
            "created_at": now,
            "automated": False,
            "risk": "low",
            "expires_at": now + 60,
            "profile_id": profile.profile_id,
            "profile_fingerprint": profile.fingerprint,
            "autonomy_mode": profile.autonomy_mode,
        }
        telemetry = {"agent_id": "local-agent"}
        health = {"action_safe": True, "critical_errors": []}
        executor = MagicMock()
        executor.execute.return_value = {
            "action_type": "snapshot",
            "success": True,
            "message": "once",
        }
        with tempfile.TemporaryDirectory() as directory:
            journal = ActionJournal(directory)
            first = execute_queued_action(
                journal, executor, action, telemetry, health, profile
            )
            replay = execute_queued_action(
                journal, executor, action, telemetry, health, profile
            )
            with self.assertRaisesRegex(RuntimeError, "different envelope"):
                execute_queued_action(
                    journal,
                    executor,
                    {**action, "parameters": {"marker": "altered"}},
                    telemetry,
                    health,
                    profile,
                )
        self.assertEqual(first, replay)
        executor.execute.assert_called_once()

    def test_spooled_telemetry_must_match_the_exact_release_binding(self):
        profile = EventProfile.testing()
        telemetry = {
            "agent_version": __version__,
            "profile_id": profile.profile_id,
            "profile_fingerprint": profile.fingerprint,
        }
        self.assertTrue(telemetry_matches_release_binding(telemetry, profile))
        for field, value in (
            ("agent_version", "0.0.0"),
            ("profile_id", "other-profile"),
            ("profile_fingerprint", "0" * 64),
        ):
            with self.subTest(field=field):
                changed = dict(telemetry)
                changed[field] = value
                self.assertFalse(telemetry_matches_release_binding(changed, profile))

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_agent_refuses_symbolic_link_state_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual"
            actual.mkdir()
            linked = root / "linked"
            linked.symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                prepare_state_directory(linked)

    def test_agent_log_is_private_and_rotates_with_a_strict_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            state = prepare_state_directory(Path(directory) / "state")
            log_path = state / "agent.log"
            try:
                configure_agent_logging(
                    "INFO", state, str(log_path), max_bytes=MIN_LOG_BYTES, backups=2
                )
                logging.getLogger().handlers[0].setLevel(logging.CRITICAL)
                logger = logging.getLogger("sentinel_blue.rotation_test")
                for _ in range(1_000):
                    logger.error("bounded-log-record-%s", "x" * 240)
                for handler in logging.getLogger().handlers:
                    handler.flush()
                logs = sorted(state.glob("agent.log*"))
                self.assertEqual(len(logs), 3)
                self.assertTrue(all(item.stat().st_size <= MIN_LOG_BYTES for item in logs))
                if os.name == "posix":
                    self.assertTrue(all(item.stat().st_mode & 0o777 == 0o600 for item in logs))
            finally:
                configure_agent_logging("WARNING")

    def test_agent_log_refuses_untrusted_paths_and_type_coercion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = prepare_state_directory(root / "state")
            with self.assertRaisesRegex(ValueError, "absolute path"):
                configure_agent_logging("INFO", state, "agent.log")
            with self.assertRaisesRegex(ValueError, "direct child"):
                configure_agent_logging("INFO", state, str(root / "outside.log"))
            with self.assertRaisesRegex(ValueError, "integers"):
                configure_agent_logging("INFO", state, str(state / "agent.log"), True, 3)
            with self.assertRaisesRegex(ValueError, "integers"):
                configure_agent_logging("INFO", state, str(state / "agent.log"), MIN_LOG_BYTES, "3")

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_agent_log_refuses_a_substituted_symbolic_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state = prepare_state_directory(root / "state")
            outside = root / "outside.log"
            outside.write_text("do not overwrite", encoding="utf-8")
            (state / "agent.log").symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                configure_agent_logging("INFO", state, str(state / "agent.log"))

    def test_systemd_readiness_and_watchdog_notification(self):
        notifier = MagicMock()
        with (
            patch.dict(os.environ, {"NOTIFY_SOCKET": "/run/systemd/notify"}),
            patch("sentinel_blue.agent.socket.socket", return_value=notifier),
        ):
            self.assertTrue(systemd_notify("READY=1\nWATCHDOG=1"))
        notifier.connect.assert_called_once_with("/run/systemd/notify")
        notifier.sendall.assert_called_once_with(b"READY=1\nWATCHDOG=1")
        notifier.close.assert_called_once()

    def test_systemd_notification_is_noop_without_socket(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(systemd_notify("READY=1"))


if __name__ == "__main__":
    unittest.main()
