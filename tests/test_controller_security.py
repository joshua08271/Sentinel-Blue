import copy
import json
import sqlite3
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from unittest.mock import Mock, patch

from sentinel_blue import __version__
from sentinel_blue.__main__ import parser
from sentinel_blue.adversarial_lab import valid_payload
from sentinel_blue.agent import AgentClient
from sentinel_blue.auth import derive_enrollment_ticket, signature
from sentinel_blue.controller import (
    ControllerApp,
    ControllerDatabaseLock,
    ControllerServer,
    _run_locked,
    _validate_controller_path_separation,
    make_handler,
)
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.store import Store


class ControllerSecurityTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "controller.db")
        self.app = ControllerApp(
            self.store,
            "z" * 32,
            operator_token="o" * 32,
        )
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

    def test_dashboard_requires_operator_token(self):
        with self.assertRaises(HTTPError) as raised:
            urlopen(f"{self.url}/api/v1/dashboard")
        self.assertEqual(raised.exception.code, 401)

    def test_authenticated_agent_response_uses_request_credential_snapshot(self):
        client = AgentClient(self.url, "z" * 32, "response-race-agent")
        old_token = client.enroll("response-race-host", "Linux")
        payload = valid_payload()
        payload["agent_id"] = "response-race-agent"

        def rotate_during_request(*_args, **_kwargs):
            self.store.rotate_agent_credential("response-race-agent")
            return []

        with patch.object(self.app, "ingest", side_effect=rotate_during_request):
            self.assertEqual(client.telemetry(payload), {"alerts": []})
        self.assertNotEqual(
            self.store.agent_secret("response-race-agent"), old_token
        )

    def test_replay_marker_storage_failure_precedes_endpoint_side_effects(self):
        agent_id = "replay-storage-failure-agent"
        client = AgentClient(self.url, "z" * 32, agent_id)
        agent_token = client.enroll("failure-host", "Linux")
        payload = valid_payload()
        payload["agent_id"] = agent_id
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        path = "/api/v1/agent/telemetry"
        timestamp = str(time.time())
        request = Request(
            self.url + path,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-SB-Agent": agent_id,
                "X-SB-Timestamp": timestamp,
                "X-SB-Signature": signature(
                    agent_token, timestamp, "POST", path, body
                ),
            },
        )
        with patch.object(
            self.store,
            "admit_http_request",
            side_effect=sqlite3.OperationalError("disk unavailable"),
        ), patch.object(self.app, "ingest") as ingest:
            with self.assertRaises(HTTPError) as rejected:
                urlopen(request)
        self.assertEqual(rejected.exception.code, 401)
        ingest.assert_not_called()

    def test_controller_database_lock_is_singleton_per_database(self):
        database = Path(self.directory.name) / "singleton.db"
        first = ControllerDatabaseLock(database).acquire()
        try:
            with self.assertRaisesRegex(RuntimeError, "already owns"):
                ControllerDatabaseLock(database).acquire()
        finally:
            first.close()
        second = ControllerDatabaseLock(database).acquire()
        second.close()

    def test_checksum_bound_startup_rejects_non_urlsafe_master_token(self):
        raw_profile = copy.deepcopy(EventProfile.testing().raw)
        raw_profile["release"]["sha256"] = "a" * 64
        raw_profile["official_identities"] = [
            {
                "agent_id": "exact-agent",
                "name": "exact-agent",
                "class": "service",
                "source": "test-inventory",
            }
        ]
        with self.assertRaisesRegex(ValueError, "32-256 URL-safe"):
            ControllerApp(
                self.store,
                "!" * 32,
                event_profile=EventProfile.from_dict(raw_profile),
                operator_token="o" * 32,
            )

    def test_controller_cli_requires_separate_operator_credential(self):
        base = [
            "controller",
            "--token",
            "e" * 32,
            "--event-profile",
            "profile.json",
        ]
        with patch("sys.stderr"):
            with self.assertRaises(SystemExit):
                parser().parse_args(base)
        args = parser().parse_args(
            [
                *base,
                "--operator-token-file",
                "operator.token",
                "--operator-principal-id",
                "blue-lead",
                "--recovery-key-file",
                "recovery.key",
                "--recovery-anchor",
                "recovery.anchor",
            ]
        )
        self.assertEqual(args.operator_token_file, "operator.token")
        self.assertEqual(args.operator_principal_id, "blue-lead")
        self.assertEqual(args.operator_credential_epoch, 2)

    def test_direct_controller_runner_reapplies_strict_transport_gate(self):
        args = SimpleNamespace(
            log_level="INFO",
            token="z" * 32,
            token_file=None,
            event_profile="profile.json",
            range_deployment=True,
            tls_ca_file=None,
            tls_cert=None,
            tls_key=None,
            syslog_bind=None,
        )
        profile = Mock()
        with (
            patch("sentinel_blue.controller.load_event_profile", return_value=profile),
            patch(
                "sentinel_blue.controller.validate_bound_transport",
                side_effect=ValueError("strict transport gate"),
            ) as validate_transport,
        ):
            with self.assertRaisesRegex(ValueError, "strict transport gate"):
                _run_locked(args)
        profile.require_runtime_ready.assert_called_once_with(
            __version__, range_deployment=True
        )
        validate_transport.assert_called_once_with(
            profile,
            role="controller",
            ca_file=None,
            tls_cert=None,
            tls_key=None,
            syslog_bind=None,
        )

    def test_library_controller_refuses_removed_local_bearer_bootstrap(self):
        with self.assertRaisesRegex(ValueError, "bearer bootstrap was removed"):
            ControllerApp(
                self.store,
                "x" * 32,
                operator_token="p" * 32,
                local_operator_bootstrap=True,
            )

    def test_missing_legacy_agent_secret_is_an_explicit_migration_blocker(self):
        self.store.register_agent("legacy-agent", "legacy-host", "Linux")
        with self.assertRaisesRegex(PermissionError, "offline migration"):
            self.app.agent_token("legacy-agent")
        self.assertEqual(
            self.app.dashboard()["controller"]["credential_migration_blockers"],
            ["legacy-agent"],
        )

    def test_empty_key_cannot_authenticate_legacy_agent_or_dispatch_action(self):
        agent_id = "empty-secret-agent"
        self.store.register_agent(agent_id, "legacy-host", "Linux")
        action_id = self.store.queue_action(agent_id, "snapshot", {})
        path = f"/api/v1/agent/actions?agent_id={agent_id}"
        timestamp = str(time.time())
        request = Request(
            self.url + path,
            headers={
                "X-SB-Agent": agent_id,
                "X-SB-Timestamp": timestamp,
                "X-SB-Signature": signature("", timestamp, "GET", path, b""),
            },
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(request)
        self.assertEqual(raised.exception.code, 401)
        self.assertEqual(self.store.get_action(action_id)["status"], "queued")

    def test_controller_internal_relay_row_cannot_authenticate_or_enroll(self):
        relay = valid_payload()
        relay["agent_id"] = "sentinel-relay-probes"
        self.app.ingest(relay)
        path = "/api/v1/agent/actions?agent_id=sentinel-relay-probes"
        timestamp = str(time.time())
        request = Request(
            self.url + path,
            headers={
                "X-SB-Agent": "sentinel-relay-probes",
                "X-SB-Timestamp": timestamp,
                "X-SB-Signature": signature("", timestamp, "GET", path, b""),
            },
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(request)
        self.assertEqual(raised.exception.code, 401)
        with self.assertRaisesRegex(PermissionError, "reserved"):
            self.app.enroll(
                {
                    "agent_id": "sentinel-relay-probes",
                    "hostname": "attacker",
                    "platform": "Linux",
                }
            )

    def test_enabled_empty_secret_blocks_controller_startup(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / "legacy.db")
            store.register_agent("legacy-agent", "legacy-host", "Linux")
            try:
                with self.assertRaisesRegex(ValueError, "offline migration"):
                    ControllerApp(
                        store, "e" * 32, operator_token="o" * 32
                    )
            finally:
                store.close()

    def test_operator_auth_info_is_public_metadata_and_bootstrap_is_gone(self):
        with urlopen(f"{self.url}/api/v1/operator/auth-info") as response:
            payload = json.loads(response.read())
        self.assertEqual(
            payload,
            {
                "version": "1",
                "principal_id": self.app.operator_principal_id,
                "credential_epoch": self.app.operator_credential_epoch,
                "request_not_before": self.app.operator_request_not_before,
            },
        )
        self.assertNotIn(self.app.operator_token, json.dumps(payload))
        with self.assertRaises(HTTPError) as removed:
            urlopen(f"{self.url}/api/v1/operator/bootstrap")
        self.assertEqual(removed.exception.code, 404)

    def test_dashboard_never_embeds_operator_token(self):
        with urlopen(f"{self.url}/") as response:
            html = response.read().decode()
        self.assertNotIn(self.app.operator_token, html)
        self.assertIn("Operator authentication", html)

    def test_enrollment_window_closes_for_new_agents(self):
        self.app.enrollment_deadline = time.time() - 1
        with self.assertRaises(PermissionError):
            self.app.enroll({"agent_id": "new-agent", "hostname": "host", "platform": "Linux"})

    def test_enrollment_window_also_closes_for_existing_agents(self):
        first = self.app.enroll(
            {"agent_id": "existing", "hostname": "host", "platform": "Linux"}
        )
        self.app.enrollment_deadline = time.time() - 1
        retry = self.app.enroll(
            {"agent_id": "existing", "hostname": "host", "platform": "Linux"}
        )
        self.assertEqual(retry["agent_token"], first["agent_token"])

    def test_enrollment_deadline_is_absolute_and_does_not_extend_on_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "restart.db"
            with patch("sentinel_blue.controller.time.time", return_value=1_000.0):
                first_store = Store(database)
                first = ControllerApp(
                    first_store,
                    "e" * 32,
                    enrollment_window=60,
                    operator_token="o" * 32,
                )
            self.assertEqual(first.enrollment_deadline, 1_060.0)
            first_store.close()

            with patch("sentinel_blue.controller.time.time", return_value=1_030.0):
                second_store = Store(database)
                second = ControllerApp(
                    second_store,
                    "e" * 32,
                    enrollment_window=3_600,
                    operator_token="o" * 32,
                )
            self.assertEqual(second.enrollment_deadline, 1_060.0)
            second_store.close()

    def test_pre_1_9_7_database_defaults_enrollment_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "upgrade.db"
            prior_store = Store(database)
            prior_store.close()
            with patch("sentinel_blue.controller.time.time", return_value=2_000.0):
                upgraded_store = Store(database)
                upgraded = ControllerApp(
                    upgraded_store,
                    "e" * 32,
                    enrollment_window=3_600,
                    operator_token="n" * 32,
                    operator_credential_epoch=2,
                )
            try:
                self.assertEqual(upgraded.enrollment_deadline, 0.0)
                with self.assertRaisesRegex(PermissionError, "window is closed"):
                    upgraded.enroll(
                        {
                            "agent_id": "unexpected-agent",
                            "hostname": "host",
                            "platform": "Linux",
                        }
                    )
            finally:
                upgraded_store.close()

    def test_each_new_agent_receives_an_independent_secret(self):
        first = self.app.enroll({"agent_id": "first", "hostname": "one", "platform": "Linux"})
        second = self.app.enroll({"agent_id": "second", "hostname": "two", "platform": "Linux"})
        self.assertNotEqual(first["agent_token"], second["agent_token"])
        self.assertNotEqual(first["agent_token"], self.app.token)

    def test_checksum_bound_range_requires_profile_binding_and_exact_agent_release(self):
        raw_profile = copy.deepcopy(EventProfile.testing().raw)
        raw_profile["profile_id"] = "checksum-bound-range"
        raw_profile["release"] = {
            "version": __version__,
            "sha256": "a" * 64,
            "cloud_processing": False,
            "external_telemetry_export": False,
        }
        raw_profile["official_identities"] = [
            {
                "agent_id": "bound-agent",
                "name": "bound-agent",
                "class": "service",
                "source": "test-inventory",
            }
        ]
        profile = EventProfile.from_dict(raw_profile)
        app = ControllerApp(
            self.store,
            "y" * 32,
            event_profile=profile,
            operator_token="o" * 32,
        )

        with self.assertRaisesRegex(PermissionError, "profile binding"):
            app.enroll(
                {
                    "agent_id": "bound-agent",
                    "hostname": "host",
                    "platform": "Linux",
                }
            )
        enrollment = {
                "agent_id": "bound-agent",
                "hostname": "host",
                "platform": "Linux",
                "agent_version": __version__,
                "profile_id": profile.profile_id,
                "profile_fingerprint": profile.fingerprint,
                "enrollment_nonce": "1" * 64,
            }
        enrolled = app.enroll(
            enrollment,
            authenticated_ticket=derive_enrollment_ticket(
                app.token, profile.fingerprint, "bound-agent"
            ),
        )

        telemetry = valid_payload()
        telemetry.update(
            {
                "agent_id": "bound-agent",
                "agent_version": "0.0.0",
                "profile_id": profile.profile_id,
                "profile_fingerprint": profile.fingerprint,
                "boot_id": "bound-agent-boot",
                "sequence": 1,
                "queued_at": time.time(),
            }
        )
        with self.assertRaisesRegex(PermissionError, "release version"):
            app.ingest(telemetry)
        self.assertEqual(self.store.latest_telemetry(), [])

        telemetry["agent_version"] = __version__
        app.ingest(
            telemetry,
            expected_agent_id="bound-agent",
            expected_agent_secret=enrolled["agent_token"],
        )
        self.assertEqual(self.store.latest_telemetry()[0]["agent_id"], "bound-agent")

    def test_shared_bootstrap_cannot_rotate_an_existing_agent_credential(self):
        first = self.app.enroll(
            {"agent_id": "rotate-agent", "hostname": "host", "platform": "Windows"}
        )
        old_token = first["agent_token"]
        action_id = self.store.queue_action("rotate-agent", "snapshot", {})
        self.store.save_telemetry(
            "rotate-agent",
            {"boot_id": "same-boot", "sequence": 42},
            expected_agent_secret=old_token,
        )

        exact_retry = self.app.enroll(
            {"agent_id": "rotate-agent", "hostname": "host", "platform": "Windows"}
        )
        self.assertEqual(exact_retry["agent_token"], old_token)
        with self.assertRaisesRegex(PermissionError, "already enrolled"):
            self.app.enroll(
                {
                    "agent_id": "rotate-agent",
                    "hostname": "different-host",
                    "platform": "Windows",
                }
            )
        self.assertEqual(self.store.agent_secret("rotate-agent"), old_token)
        self.assertTrue(
            self.store.save_telemetry(
                "rotate-agent",
                {"boot_id": "same-boot", "sequence": 43},
                expected_agent_secret=old_token,
            )
        )
        self.assertEqual(self.store.get_action(action_id)["status"], "queued")

    def test_database_integrity_check_is_cached(self):
        with patch.object(self.store, "integrity_check", return_value="ok") as check:
            self.assertEqual(self.app.database_integrity(), "ok")
            self.assertEqual(self.app.database_integrity(), "ok")
        check.assert_called_once()

    def test_enrollment_metadata_is_bounded(self):
        with self.assertRaisesRegex(ValueError, "hostname"):
            self.app.enroll(
                {"agent_id": "bounded-agent", "hostname": "x" * 257, "platform": "Linux"}
            )

    def test_controller_paths_separate_live_state_authority_and_backups(self):
        root = Path(self.directory.name)
        shared = root / "shared.json"
        args = SimpleNamespace(
            database=root / "controller.db",
            event_profile=shared,
            probe_config=shared,
            token_file=root / "enrollment.token",
            operator_token_file=root / "operator.token",
            recovery_key_file=root / "recovery.key",
            recovery_anchor=root / "recovery.anchor",
            tls_cert=root / "controller.crt",
            tls_key=root / "controller.key",
            tls_ca_file=root / "controller.crt",
            model=None,
            adaptive_model_output=root / "model-output.json",
            backup_directory=root / "backups",
        )
        _validate_controller_path_separation(args)
        args.operator_token_file = args.token_file
        with self.assertRaisesRegex(ValueError, "operator token"):
            _validate_controller_path_separation(args)
        args.operator_token_file = root / "operator.token"
        args.database = root / "backups" / "controller.db"
        with self.assertRaisesRegex(ValueError, "outside the backup directory"):
            _validate_controller_path_separation(args)


if __name__ == "__main__":
    unittest.main()
