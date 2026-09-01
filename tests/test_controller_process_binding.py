import tempfile
import time
import unittest
from pathlib import Path

from sentinel_blue.controller import ControllerApp
from sentinel_blue.policy import validate_action_parameters
from sentinel_blue.store import Store
from sentinel_blue.validation import telemetry_observation_sha256


class ControllerProcessBindingTests(unittest.TestCase):
    agent_id = "process-agent"
    boot_id = "process-controller-boot-0001"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "controller.db")
        self.app = ControllerApp(
            self.store, "a" * 32, operator_token="o" * 32
        )
        self.app.ingest(self._telemetry(1, sessions=[], security_events=[]))

    def tearDown(self):
        self.store.close()
        self.directory.cleanup()

    @staticmethod
    def _identity(
        process_id: int = 4242,
        boot_id: str = "process-controller-boot-0001",
        start_time: str = "123456",
    ) -> dict:
        return {
            "schema": "sentinel-process-v1",
            "platform": "linux",
            "process_id": process_id,
            "boot_id": boot_id,
            "start_time": start_time,
            "executable_path": "/usr/sbin/sshd",
            "executable_file_id": "dev:1:ino:2",
            "user_id": "uid:0:0",
            "kernel_session_id": "4242",
        }

    @classmethod
    def _session(
        cls,
        *,
        boot_id: str = "process-controller-boot-0001",
        start_time: str = "123456",
    ) -> dict:
        return {
            "username": "root",
            "source": "198.51.100.4",
            "session_id": "pts/process-controller",
            "process_id": 4242,
            "privileged": True,
            "interactive": True,
            "process_identity": cls._identity(
                boot_id=boot_id, start_time=start_time
            ),
        }

    @classmethod
    def _telemetry(
        cls,
        sequence: int,
        *,
        boot_id: str = "process-controller-boot-0001",
        sessions: list[dict] | None = None,
        security_events: list[dict] | None = None,
    ) -> dict:
        if sessions is None:
            sessions = [cls._session(boot_id=boot_id)]
        if security_events is None:
            security_events = [
                {
                    "event_id": f"auth-{sequence}",
                    "category": "auth_success",
                    "account": "root",
                    "remote_address": "198.51.100.4",
                    "occurred_at": time.time(),
                }
            ]
        return {
            "agent_id": cls.agent_id,
            "hostname": "process-host",
            "platform": "Linux",
            "observed_at": time.time(),
            "boot_id": boot_id,
            "sequence": sequence,
            "accounts": [
                {"name": "root", "privileged": True, "enabled": True}
            ],
            "sessions": sessions,
            "services": [],
            "interfaces": [],
            "security_events": security_events,
            "collector_errors": [],
        }

    def _quarantine_alert(self, telemetry: dict) -> str:
        alert_ids = self.app.ingest(telemetry)
        matches = [
            alert_id
            for alert_id in alert_ids
            if self.store.get_alert(alert_id)["kind"]
            == "unverified_privileged_session"
        ]
        self.assertEqual(len(matches), 1)
        return matches[0]

    def _complete_quarantine(self, telemetry: dict):
        alert_id = self._quarantine_alert(telemetry)
        queued = self.app.decision(alert_id, "approve")
        self.assertEqual(queued["status"], "queued")
        actions = [
            action
            for action in self.store.pending_actions(self.agent_id)
            if action.action_id == queued["action_id"]
        ]
        self.assertEqual(len(actions), 1)
        action = actions[0]
        self.assertEqual(action.action_type, "quarantine_session")
        now = time.time()
        session = action.parameters["session"]
        observation = action.parameters["observation"]
        result = {
            "action_id": action.action_id,
            "action_type": action.action_type,
            "success": True,
            "message": "session process suspended",
            "started_at": now,
            "completed_at": now,
            "dry_run": False,
            "record": {
                **session,
                "target_observation": observation,
                "execution_observation": observation,
                "quarantined_at": now,
                "expires_at": now + 300,
                "boot_id": observation["boot_id"],
                "status": "active",
            },
        }
        self.assertEqual(
            self.app.complete_action(result, self.agent_id), "new"
        )
        return action

    def test_manual_approval_binds_immutable_alert_creation_observation(self):
        creation = self._telemetry(2)
        alert_id = self._quarantine_alert(creation)
        later = self._telemetry(3)
        self.assertIn(alert_id, self.app.ingest(later))

        queued = self.app.decision(alert_id, "approve")
        action = next(
            item
            for item in self.store.pending_actions(self.agent_id)
            if item.action_id == queued["action_id"]
        )

        self.assertEqual(queued["action_id"], action.action_id)
        self.assertEqual(
            set(action.parameters), {"session", "observation"}
        )
        self.assertEqual(action.parameters["session"], self._session())
        self.assertEqual(
            action.parameters["observation"],
            {
                "boot_id": self.boot_id,
                "sequence": 2,
                "payload_sha256": telemetry_observation_sha256(creation),
            },
        )
        self.assertNotEqual(
            action.parameters["observation"]["payload_sha256"],
            telemetry_observation_sha256(later),
        )
        validate_action_parameters(
            action.action_type,
            action.parameters,
            require_process_binding=True,
        )

    def test_signal_actions_cannot_queue_without_complete_binding(self):
        session = self._session()
        incomplete = ({"session": session}, {"observation": {}})
        for action_type in ("quarantine_session", "release_quarantine"):
            for parameters in incomplete:
                with self.subTest(action_type=action_type, parameters=parameters):
                    with self.assertRaises(ValueError):
                        self.app._queue_action(
                            self.agent_id, action_type, parameters
                        )
        self.assertIsNone(
            self.store.latest_action_for_agent(
                self.agent_id, "quarantine_session"
            )
        )
        self.assertIsNone(
            self.store.latest_action_for_agent(
                self.agent_id, "release_quarantine"
            )
        )

    def test_release_uses_a_newer_latest_exact_session_observation(self):
        source = self._telemetry(2)
        quarantine = self._complete_quarantine(source)
        latest = self._telemetry(3)
        self.app.ingest(latest)

        queued = self.app.release_action(quarantine.action_id)
        actions = [
            action
            for action in self.store.pending_actions(self.agent_id)
            if action.action_id == queued["action_id"]
        ]

        self.assertEqual(len(actions), 1)
        release = actions[0]
        self.assertEqual(queued["action_id"], release.action_id)
        self.assertEqual(release.action_type, "release_quarantine")
        self.assertEqual(release.parameters["session"], self._session())
        self.assertEqual(
            release.parameters["observation"],
            {
                "boot_id": self.boot_id,
                "sequence": 3,
                "payload_sha256": telemetry_observation_sha256(latest),
            },
        )
        self.assertNotEqual(
            release.parameters["observation"],
            quarantine.parameters["observation"],
        )

    def test_release_rejects_stale_rebooted_changed_or_ambiguous_session(self):
        quarantine = self._complete_quarantine(self._telemetry(2))
        cases = (
            self._telemetry(3, sessions=[]),
            self._telemetry(
                4, sessions=[self._session(start_time="654321")]
            ),
            self._telemetry(
                5, sessions=[self._session(), self._session()]
            ),
            self._telemetry(
                6,
                boot_id="process-controller-boot-0002",
                sessions=[
                    self._session(boot_id="process-controller-boot-0002")
                ],
            ),
        )
        for latest in cases:
            with self.subTest(
                boot=latest["boot_id"],
                sequence=latest["sequence"],
                sessions=len(latest["sessions"]),
            ):
                self.app.ingest(latest)
                with self.assertRaises(PermissionError):
                    self.app.release_action(quarantine.action_id)
                self.assertIsNone(
                    self.store.latest_action_for_agent(
                        self.agent_id, "release_quarantine"
                    )
                )


if __name__ == "__main__":
    unittest.main()
