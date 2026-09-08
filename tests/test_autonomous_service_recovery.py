import copy
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from dataclasses import asdict
from unittest.mock import MagicMock, patch

from sentinel_blue.actions import ActionExecutor
from sentinel_blue.agent import execute_queued_action
from sentinel_blue.controller import ControllerApp
from sentinel_blue.protocol import ProbeResult
from sentinel_blue.service_recovery import ServiceRecoveryPlanner, recovery_parameters, recovery_contract
from sentinel_blue.state import ActionJournal, write_private_json
from sentinel_blue.store import Store, ActionQuotaExceeded
from test_service_manifest_policy import profile_for, service_manifest, PROBE
from test_store_controller import _promote_integrity_baseline


def fixtures(path="/etc/web.conf"):
    manifest = service_manifest(automatic=["restart_service", "capture_restore_point"],
                                approval=["capture_restore_point"], required_files=[path])
    manifest["required_accounts"] = ["web-user"]
    baseline = {
        "agent_id": "agent-one", "hostname": "host", "platform": "Linux",
        "observed_at": time.time() - 10, "boot_id": "service-test-boot", "sequence": 1,
        "accounts": [{"name": "web-user", "enabled": True, "privileged": False}],
        "sessions": [], "interfaces": [], "collector_errors": [],
        "services": [{"name": "web.service", "state": "running", "start_mode": "enabled"}],
        "integrity": [{"path": path, "sha256": hashlib.sha256(b"trusted").hexdigest(),
                       "size": 7, "modified_at": 1, "security_descriptor_sha256": ""}],
        "probes": [],
    }
    return profile_for([manifest]), baseline


def stopped(baseline, sequence=2):
    value = copy.deepcopy(baseline)
    value["services"][0]["state"] = "stopped"
    value["sequence"] = sequence
    value["observed_at"] = baseline["observed_at"] + sequence
    return value


class AutonomousServiceRecoveryTests(unittest.TestCase):
    def test_two_consecutive_observations_queue_manifest_bound_action(self):
        profile, baseline = fixtures()
        store = Store(":memory:")
        self.addCleanup(store.close)
        app = ControllerApp(store, "t" * 32, operator_token="o" * 32,
                            event_profile=profile, auto_recover_services=True)
        app.ingest(baseline)
        _promote_integrity_baseline(app, store, "agent-one")
        app.ingest(stopped(baseline, 2))
        self.assertEqual(store.pending_actions("agent-one"), [])
        app.ingest(stopped(baseline, 3))
        actions = [asdict(item) for item in store.pending_actions("agent-one")]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["action_type"], "restart_service")
        self.assertEqual(actions[0]["parameters"]["probes"], [PROBE])
        self.assertEqual(actions[0]["parameters"]["recovery_guard"]["sequence"], 3)
        app.ingest(stopped(baseline, 4))
        self.assertEqual(sum(row["action_type"] == "restart_service" for row in store.dashboard()["actions"]), 1)
        action = actions[0]
        now = time.time()
        result = {
            "action_id": action["action_id"], "action_type": "restart_service", "success": True,
            "message": "unit fixture recovery", "started_at": now, "completed_at": now,
            "pre_state": {"service": "web.service", "desired_state": "stopped"},
            "probes": [{"name": "web-health", "target": PROBE["target"], "healthy": True}],
            "stable_health": True, "probe_attempts": 3,
        }
        self.assertEqual(app.complete_action(result, "agent-one"), "new")
        stored_action = store.get_action(action["action_id"])
        self.assertEqual(store.get_alert(stored_action["alert_id"])["decision"], "automatic_service_recovery")
        # A later outage is a new recovery episode, rather than being suppressed
        # forever by the first completed service alert.
        with patch("time.time", return_value=now + 301):
            healthy = copy.deepcopy(baseline)
            healthy.update(sequence=5, observed_at=now + 298)
            app.ingest(healthy)
            for sequence, age in ((6, 2), (7, 1)):
                outage = stopped(baseline, sequence)
                outage["observed_at"] = now + 301 - age
                app.ingest(outage)
            next_actions = store.pending_actions("agent-one")
        self.assertEqual(sum(item.action_type == "restart_service" for item in next_actions), 1)

    def test_healthy_observation_and_controller_restart_clear_confirmation(self):
        profile, baseline = fixtures()
        planner = ServiceRecoveryPlanner(profile)
        self.assertEqual(planner.observe("agent-one", baseline, True, stopped(baseline)), {})
        healthy = copy.deepcopy(baseline)
        healthy.update(sequence=3, observed_at=baseline["observed_at"] + 3)
        self.assertEqual(planner.observe("agent-one", baseline, True, healthy), {})
        self.assertEqual(planner.observe("agent-one", baseline, True, stopped(baseline, 4)), {})
        self.assertIn("web.service", planner.observe("agent-one", baseline, True, stopped(baseline, 5)))
        restarted = ServiceRecoveryPlanner(profile)
        self.assertEqual(restarted.observe("agent-one", baseline, True, stopped(baseline, 6)), {})

    def test_incomplete_changed_disabled_stale_or_rebooted_observations_hold(self):
        profile, baseline = fixtures()
        changes = [
            lambda row: row.update(collector_errors=["service collection failed"]),
            lambda row: row["services"][0].update(state="unknown"),
            lambda row: row["services"][0].update(start_mode="masked"),
            lambda row: row["services"][0].update(restart_count=3),
            lambda row: row["integrity"][0].update(sha256="f" * 64),
            lambda row: row["accounts"][0].update(enabled=False),
            lambda row: row.update(observed_at=time.time() - 100),
            lambda row: row.update(boot_id="unknown"),
            lambda row: row.update(services=[]),
        ]
        for change in changes:
            with self.subTest(change=changes.index(change)):
                planner = ServiceRecoveryPlanner(profile)
                planner.observe("agent-one", baseline, True, stopped(baseline, 2))
                bad = stopped(baseline, 3)
                change(bad)
                self.assertEqual(planner.observe("agent-one", baseline, True, bad), {})
                self.assertEqual(planner.observe("agent-one", baseline, True, stopped(baseline, 4)), {})
        planner = ServiceRecoveryPlanner(profile)
        planner.observe("agent-one", baseline, True, stopped(baseline, 2))
        reboot = stopped(baseline, 3)
        reboot["boot_id"] = "another-boot"
        self.assertEqual(planner.observe("agent-one", baseline, True, reboot), {})

    def test_baseline_approval_and_mode_gate_are_required(self):
        profile, baseline = fixtures()
        planner = ServiceRecoveryPlanner(profile)
        for sequence in (2, 3):
            self.assertEqual(planner.observe("agent-one", baseline, False, stopped(baseline, sequence)), {})
        raw = copy.deepcopy(profile.raw)
        raw["autonomy_mode"] = "approval-based"
        raw["allowed_automatic_actions"] = []
        from sentinel_blue.event_profile import EventProfile
        store = Store(":memory:")
        self.addCleanup(store.close)
        with self.assertRaisesRegex(ValueError, "not authorized"):
            ControllerApp(store, "t" * 32, operator_token="o" * 32,
                          event_profile=EventProfile.from_dict(raw), auto_recover_services=True)

    def test_dependency_health_is_required_and_graph_is_unambiguous(self):
        profile, baseline = fixtures()
        web = copy.deepcopy(profile.services[0])
        web["dependencies"] = ["database.service"]
        database = service_manifest("database.service", expected_transactions=[{
            "name": "db", "kind": "tcp", "target": "192.0.2.10", "port": 5432
        }])
        profile = profile_for([web, database])
        current = stopped(baseline)
        current["services"].append({"name": "database.service", "state": "stopped"})
        with self.assertRaisesRegex(ValueError, "dependency"):
            recovery_parameters(profile, "agent-one", "web.service", baseline, current)
        current["services"][1]["state"] = "running"
        with self.assertRaisesRegex(ValueError, "dependency application"):
            recovery_parameters(profile, "agent-one", "web.service", baseline, current)
        current["probes"] = [{"name": "db", "target": "192.0.2.10", "healthy": True}]
        self.assertEqual(recovery_parameters(profile, "agent-one", "web.service", baseline, current)
                         ["recovery_guard"]["dependencies"], ["database.service"])
        database["dependencies"] = ["web.service"]
        with self.assertRaisesRegex(ValueError, "cycle"):
            recovery_contract(profile_for([web, database]), "agent-one", "web.service")
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            recovery_contract(profile_for([web]), "agent-one", "web.service")

    def test_agent_refuses_automatic_restart_without_manifest_guard(self):
        profile, baseline = fixtures()
        store = Store(":memory:")
        self.addCleanup(store.close)
        identifier = store.queue_action("agent-one", "restart_service", {"service": "web.service"},
                                        automated=True, profile_id=profile.profile_id,
                                        profile_fingerprint=profile.fingerprint,
                                        autonomy_mode=profile.autonomy_mode)
        action = asdict(store.pending_actions("agent-one")[0])
        executor = MagicMock()
        with tempfile.TemporaryDirectory() as directory:
            result = execute_queued_action(ActionJournal(directory), executor, action, stopped(baseline),
                                           {"action_safe": True}, profile)
        self.assertFalse(result["success"])
        self.assertIn("exact manifest contract", result["message"])
        executor.execute.assert_not_called()

    def test_native_file_preflight_blocks_change_after_telemetry(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "unit.conf"
            target.write_bytes(b"trusted")
            profile, baseline = fixtures(str(target))
            current = stopped(baseline)
            parameters = recovery_parameters(profile, "agent-one", "web.service", baseline, current)
            target.write_bytes(b"modified after telemetry")
            executor = ActionExecutor(Path(directory) / "state", allow_containment=True)
            with patch.object(executor, "_service_state", return_value="stopped"), patch.object(
                executor, "_set_service_state"
            ) as change:
                result = executor.execute("restart_service", parameters, current)
            self.assertFalse(result["success"])
            self.assertIn("changed before execution", result["message"])
            change.assert_not_called()

    def test_agent_restart_does_not_reset_native_recovery_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory).resolve() / "unit.conf"
            target.write_bytes(b"trusted")
            profile, baseline = fixtures(str(target))
            state = Path(directory).resolve() / "state"
            executor = ActionExecutor(state, allow_containment=True)
            _data, metadata = executor.restore_points._read_target(target)
            baseline['integrity'][0]['security_descriptor_sha256'] = (
                executor.restore_points._metadata_security_descriptor_sha256(metadata)
            )
            current = stopped(baseline)
            parameters = recovery_parameters(profile, "agent-one", "web.service", baseline, current)
            with patch.object(executor, "_service_state", side_effect=["stopped", "running"]), patch.object(
                executor, "_set_service_state"
            ), patch("sentinel_blue.actions.run_probes", return_value=[ProbeResult("web-health", PROBE["target"], True)]), patch(
                "sentinel_blue.actions.time.sleep"
            ):
                first = executor.execute("restart_service", parameters, current)
            self.assertTrue(first["success"], first)
            restarted = ActionExecutor(state, allow_containment=True)
            with patch.object(restarted, "_service_state", return_value="stopped"), patch.object(
                restarted, "_set_service_state"
            ) as change:
                second = restarted.execute("restart_service", parameters, current)
            self.assertFalse(second["success"])
            self.assertIn("cooldown", second["message"])
            change.assert_not_called()

    def test_store_budget_survives_reopen_and_blocks_unresolved_cross_alert_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "controller.db"
            store = Store(path)
            store.queue_action("agent-one", "restart_service", {"service": "web.service"}, automated=True)
            store.close()
            reopened = Store(path)
            try:
                with self.assertRaisesRegex(ActionQuotaExceeded, "unresolved"):
                    reopened.queue_action("agent-one", "restart_service", {"service": "web.service", "episode": 2}, automated=True)
                other = reopened.queue_action("agent-one", "restart_service", {"service": "other.service"}, automated=True)
                self.assertIsInstance(other, str)
            finally:
                reopened.close()

    def test_durable_hourly_budget_and_cooldown_cover_failed_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "controller.db"
            store = Store(path)
            epoch = time.time()
            for index in range(3):
                now = epoch + index * 301
                with patch("time.time", return_value=now):
                    identifier = store.queue_action("agent-one", "restart_service", {"service": "web.service"}, automated=True)
                    store.pending_actions("agent-one")
                    self.assertEqual(store.complete_action(identifier, {
                        "action_id": identifier, "action_type": "restart_service", "success": False,
                        "message": "failed application validation", "started_at": now, "completed_at": now,
                    }), "new")
                    with self.assertRaisesRegex(ActionQuotaExceeded, "cooldown|hourly"):
                        store.queue_action("agent-one", "restart_service", {"service": "web.service"}, automated=True)
            store.close()
            store = Store(path)
            try:
                with patch("time.time", return_value=epoch + 1000), self.assertRaisesRegex(ActionQuotaExceeded, "hourly"):
                    store.queue_action("agent-one", "restart_service", {"service": "web.service"}, automated=True)
                with patch("time.time", return_value=epoch + 3601):
                    self.assertIsInstance(store.queue_action("agent-one", "restart_service", {"service": "web.service"}, automated=True), str)
            finally:
                store.close()

    def test_visible_budget_matches_admission_at_the_exact_retry_boundary(self):
        store = Store(':memory:')
        self.addCleanup(store.close)
        epoch = time.time()
        for index in range(4):
            now = epoch + index * 301
            with patch('time.time', return_value=now):
                # Explicit operator work also consumes the durable allowance.
                identifier = store.queue_action('agent-one', 'restart_service', {'service': 'web.service'})
                store.pending_actions('agent-one')
                unresolved = store.service_recovery_budget_status('agent-one', 'web.service')
                self.assertEqual(unresolved['reason'], 'service_recovery_prior_outcome_unresolved')
                self.assertIsNone(unresolved['retry_at'])
                store.complete_action(identifier, {
                    'action_id': identifier, 'action_type': 'restart_service', 'success': False,
                    'message': 'failed application validation', 'started_at': now, 'completed_at': now,
                })
                status = store.service_recovery_budget_status('agent-one', 'web.service')
                self.assertEqual(status['attempts_in_window'], index + 1)
                self.assertEqual(status['retry_at'], now + 300 if index < 2 else epoch + (index - 2) * 301 + 3600)
        retry = epoch + 301 + 3600
        with patch('time.time', return_value=retry - .001):
            self.assertFalse(store.service_recovery_budget_status('agent-one', 'web.service')['allowed'])
            with self.assertRaisesRegex(ActionQuotaExceeded, 'hourly'):
                store.queue_action('agent-one', 'restart_service', {'service': 'web.service'}, automated=True)
        with patch('time.time', return_value=retry):
            self.assertTrue(store.service_recovery_budget_status('agent-one', 'web.service')['allowed'])
            self.assertIsInstance(store.queue_action('agent-one', 'restart_service', {'service': 'web.service'}, automated=True), str)

    def test_dashboard_never_reports_ready_during_durable_hold_or_telemetry_silence(self):
        profile, baseline = fixtures()
        store = Store(':memory:')
        self.addCleanup(store.close)
        app = ControllerApp(store, 't' * 32, operator_token='o' * 32,
                            event_profile=profile, auto_recover_services=True)
        app.ingest(baseline)
        _promote_integrity_baseline(app, store, 'agent-one')
        for sequence in (2, 3):
            app.ingest(stopped(baseline, sequence))
        current = {'agent-one': stopped(baseline, 3)}
        row = app.service_recovery_status(current)[0]
        self.assertEqual(row['observation_status'], 'ready')
        self.assertEqual(row['status'], 'service_recovery_prior_outcome_unresolved')
        current['agent-one']['observed_at'] = time.time() - 91
        self.assertEqual(app.service_recovery_status(current)[0]['status'], 'fresh telemetry unavailable')
        app.emergency_stopped = True
        self.assertEqual(app.service_recovery_status(current)[0]['status'], 'emergency stop enabled')

    def test_success_cannot_omit_stable_application_attestation(self):
        from sentinel_blue.store import _require_success_result_contract
        profile, baseline = fixtures()
        parameters = recovery_parameters(profile, "agent-one", "web.service", baseline, stopped(baseline))
        with self.assertRaisesRegex(ValueError, "stable manifest probe"):
            _require_success_result_contract("restart_service", parameters, {
                "success": True,
                "pre_state": {"service": "web.service", "desired_state": "stopped"},
                "probes": [{"name": "web-health", "target": PROBE["target"], "healthy": True}],
            })
