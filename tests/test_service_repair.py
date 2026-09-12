"""Fault-oriented coverage of coordinated autonomous service repair."""

import copy
import hashlib
import json
import tempfile
import time
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.actions import ActionExecutor
from sentinel_blue.agent import execute_queued_action
from sentinel_blue.controller import ControllerApp
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.policy import validate_action_parameters
from sentinel_blue.protocol import ProbeResult
from sentinel_blue.service_recovery import ServiceRecoveryPlanner
from sentinel_blue.service_repair import (diagnose_service, repair_parameters, validate_repair_contract,
                                          normalize_repair_policy, plan_digest)
from sentinel_blue.state import ActionJournal
from sentinel_blue.store import Store, _require_success_result_contract
from test_autonomous_service_recovery import fixtures, stopped
from test_service_manifest_policy import profile_for, service_manifest
from test_store_controller import _promote_integrity_baseline


def repair_fixture(path="/etc/web.conf"):
    profile, baseline = fixtures(path)
    manifest = copy.deepcopy(profile.services[0])
    manifest["allowed_automatic_actions"] += ["repair_service", "restore_integrity"]
    manifest["approval_actions"] += ["repair_service", "rollback_service_repair"]
    manifest["expected_transactions"] = [{"name": "local-web", "kind": "http", "target": "http://127.0.0.1:8765/health"}]
    manifest["repair_policy"] = {"restore_files": [path], "restart_unhealthy": True, "validation_timeout_seconds": 5}
    baseline["probes"] = [{"name": "local-web", "target": "http://127.0.0.1:8765/health", "healthy": True}]
    return profile_for([manifest]), baseline


def damage(baseline, sequence=2):
    value = stopped(baseline, sequence)
    value["integrity"][0]["sha256"] = hashlib.sha256(b"damaged").hexdigest()
    value["probes"][0]["healthy"] = False
    return value


class RepairPlanningTests(unittest.TestCase):
    def test_config_and_service_deadlock_produces_one_coordinated_action(self):
        profile, baseline = repair_fixture()
        store = Store(":memory:")
        self.addCleanup(store.close)
        app = ControllerApp(store, "t" * 32, operator_token="o" * 32, event_profile=profile,
                            auto_recover_services=True, auto_restore=True,
                            restoration_probes=profile.services[0]["expected_transactions"])
        app.ingest(baseline)
        _promote_integrity_baseline(app, store, "agent-one")
        app.ingest(damage(baseline, 2))
        self.assertFalse(any(item.action_type in {"repair_service", "restore_integrity", "restart_service"}
                             for item in store.pending_actions("agent-one")))
        app.ingest(damage(baseline, 3))
        actions = [asdict(item) for item in store.pending_actions("agent-one") if item.action_type == "repair_service"]
        self.assertEqual(len(actions), 1)
        self.assertEqual(actions[0]["parameters"]["repair"]["restore_files"][0]["path"], "/etc/web.conf")
        self.assertFalse(any(item.action_type == "restore_integrity" for item in store.pending_actions("agent-one")))

    def test_changed_fault_resets_confirmation(self):
        profile, baseline = repair_fixture()
        planner = ServiceRecoveryPlanner(profile)
        self.assertFalse(planner.observe("agent-one", baseline, True, damage(baseline, 2)))
        current = damage(baseline, 3)
        current["integrity"][0]["sha256"] = "f" * 64
        self.assertFalse(planner.observe("agent-one", baseline, True, current))
        current.update(sequence=4, observed_at=baseline["observed_at"] + 4)
        self.assertIn("web.service", planner.observe("agent-one", baseline, True, current))

    def test_running_unhealthy_local_service_is_repairable(self):
        profile, baseline = repair_fixture()
        current = damage(baseline)
        current["services"][0]["state"] = "running"
        parameters = repair_parameters(profile, "agent-one", "web.service", baseline, current)
        validate_action_parameters("repair_service", parameters)
        validate_repair_contract(profile, "agent-one", parameters, current)
        findings = diagnose_service(profile, "agent-one", "web.service", baseline, current)["findings"]
        self.assertIn("local_application_unhealthy", [item["code"] for item in findings])

    def test_healthy_local_with_external_failure_does_not_restart(self):
        profile, baseline = repair_fixture()
        raw = copy.deepcopy(profile.raw)
        raw["services"][0]["expected_transactions"].append({"name": "external", "kind": "http", "target": "http://192.0.2.10/health"})
        profile = EventProfile.from_dict(raw)
        current = copy.deepcopy(baseline)
        current["probes"].append({"name": "external", "target": "http://192.0.2.10/health", "healthy": False})
        with self.assertRaisesRegex(ValueError, "failed local"):
            repair_parameters(profile, "agent-one", "web.service", baseline, current)
        findings = diagnose_service(profile, "agent-one", "web.service", baseline, current)["findings"]
        self.assertIn("external_path_or_access_failure", [item["code"] for item in findings])

    def test_dependency_is_diagnosed_before_downstream_service(self):
        profile, baseline = repair_fixture()
        web = copy.deepcopy(profile.services[0])
        web["dependencies"] = ["database.service"]
        db = service_manifest("database.service", required_files=["/etc/db.conf"], automatic=["restart_service"])
        profile = profile_for([web, db])
        current = damage(baseline)
        baseline["services"].append({"name": "database.service", "state": "running"})
        current["services"].append({"name": "database.service", "state": "stopped"})
        diag = diagnose_service(profile, "agent-one", "web.service", baseline, current)
        self.assertEqual(diag["repair_order"], ["database.service", "web.service"])
        planner = ServiceRecoveryPlanner(profile)
        self.assertNotIn("web.service", planner.observe("agent-one", baseline, True, current))

    def test_agent_rejects_file_probe_and_policy_rebinding(self):
        profile, baseline = repair_fixture()
        current = damage(baseline)
        parameters = repair_parameters(profile, "agent-one", "web.service", baseline, current)
        for change in (
            lambda p: p["repair"].update(restart_unhealthy=False),
            lambda p: p["repair"].update(validation_timeout_seconds=120),
            lambda p: p["repair"]["restore_files"][0].update(path="/etc/other.conf"),
            lambda p: p["probes"][0].update(target="http://127.0.0.1:22/"),
            lambda p: p["repair"].update(restore_files=[]),
        ):
            altered = copy.deepcopy(parameters)
            change(altered)
            with self.assertRaises((ValueError, KeyError)):
                validate_repair_contract(profile, "agent-one", altered, current)

    def test_data_shared_files_missing_policy_and_privilege_gates(self):
        profile, baseline = repair_fixture()
        raw = copy.deepcopy(profile.raw)
        for change in (
            lambda r: r["services"][0].pop("repair_policy"),
            lambda r: r["services"][0].update(required_data=["/etc"]),
            lambda r: r["services"].append(service_manifest("another.service")),
        ):
            value = copy.deepcopy(raw)
            change(value)
            with self.assertRaises(ValueError):
                repair_parameters(EventProfile.from_dict(value), "agent-one", "web.service", baseline, damage(baseline))
        raw["capabilities"]["file_restoration"] = False
        self.assertFalse(EventProfile.from_dict(raw).action_allowed("repair_service", automated=True))
        for value in (True, 0, 121, 5.0):
            policy = copy.deepcopy(profile.services[0]["repair_policy"])
            policy["validation_timeout_seconds"] = value
            with self.assertRaises(ValueError):
                normalize_repair_policy(policy, profile.services[0])

    def test_active_change_grant_holds_coordinated_repair(self):
        profile, baseline = repair_fixture()
        store = Store(":memory:")
        self.addCleanup(store.close)
        app = ControllerApp(store, "t" * 32, operator_token="o" * 32, event_profile=profile, auto_recover_services=True)
        app.ingest(baseline)
        _promote_integrity_baseline(app, store, "agent-one")
        store.create_change_grant("agent-one", "/etc/web.conf", 120)
        for sequence in (2, 3, 4):
            app.ingest(damage(baseline, sequence))
        self.assertFalse(any(item.action_type == "repair_service" for item in store.pending_actions("agent-one")))
        self.assertIn("change grant", app.service_recovery_planner.status()[0]["status"])


class RepairExecutionTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.target = self.root / "web.conf"
        self.target.write_bytes(b"trusted")
        self.profile, self.baseline = repair_fixture(str(self.target))
        self.executor = ActionExecutor(self.root / "state", allow_service_recovery=True, allow_restoration=True,
                                       authorized_networks=["127.0.0.0/8"])
        result = self.executor.restore_points.capture(self.baseline["integrity"])
        self.assertTrue(result["success"], result)
        self.target.write_bytes(b"damaged")
        self.current = damage(self.baseline)
        self.parameters = repair_parameters(self.profile, "agent-one", "web.service", self.baseline, self.current)
        self.native_state = "stopped"
        self.transitions = []
        state_patch = patch.object(self.executor, "_service_state", side_effect=lambda _: self.native_state)
        set_patch = patch.object(self.executor, "_set_service_state", side_effect=self.change_state)
        state_patch.start()
        set_patch.start()
        self.addCleanup(state_patch.stop)
        self.addCleanup(set_patch.stop)
        spec = self.parameters["probes"][0]
        self.healthy = [ProbeResult(spec["name"], spec["target"], True)]
        wait_patch = patch.object(self.executor, "_wait_for_service_probes", return_value=(self.healthy, 3, True))
        wait_patch.start()
        self.addCleanup(wait_patch.stop)

    def change_state(self, service, state):
        if state == "running" and not self.transitions:
            self.assertEqual(self.target.read_bytes(), b"trusted", "service start must follow file repair")
        self.transitions.append((service, state))
        self.native_state = state

    def run_repair(self):
        return self.executor.execute("repair_service", self.parameters, self.current)

    def test_file_restore_and_start_commit_together_and_support_exact_undo(self):
        result = self.run_repair()
        self.assertTrue(result["success"], result)
        self.assertEqual(self.target.read_bytes(), b"trusted")
        self.assertEqual(self.native_state, "running")
        _require_success_result_contract("repair_service", self.parameters, result)
        undone = self.executor.execute("rollback_service_repair", result["pre_state"], self.current)
        self.assertTrue(undone["success"], undone)
        self.assertEqual(self.target.read_bytes(), b"damaged")
        self.assertEqual(self.native_state, "stopped")

    def test_failed_application_validation_restores_prior_files_and_state(self):
        self.executor._wait_for_service_probes.return_value = (self.healthy, 4, False)
        result = self.run_repair()
        self.assertFalse(result["success"])
        self.assertTrue(result["rolled_back"], result)
        self.assertEqual(self.target.read_bytes(), b"damaged")
        self.assertEqual(self.native_state, "stopped")
        self.assertTrue(self.executor.refresh_recovery()["service"]["healthy"])

    def test_missing_file_is_recreated_and_undo_removes_only_created_file(self):
        self.target.unlink()
        self.current["integrity"] = []
        self.parameters = repair_parameters(self.profile, "agent-one", "web.service", self.baseline, self.current)
        result = self.run_repair()
        self.assertTrue(result["success"], result)
        self.assertEqual(self.target.read_bytes(), b"trusted")
        result = self.executor.execute("rollback_service_repair", result["pre_state"], self.current)
        self.assertTrue(result["success"], result)
        self.assertFalse(self.target.exists())

    def test_corrupt_backup_and_concurrent_target_changes_prevent_mutation(self):
        blob = self.executor.restore_points.blobs / self.parameters["repair"]["restore_files"][0]["baseline_sha256"]
        blob.write_bytes(b"corrupt backup")
        result = self.run_repair()
        self.assertFalse(result["success"])
        self.assertEqual(self.transitions, [])
        self.assertEqual(self.target.read_bytes(), b"damaged")
        blob.write_bytes(b"trusted")
        self.target.write_bytes(b"new operator edit")
        result = self.run_repair()
        self.assertFalse(result["success"])
        self.assertEqual(self.transitions, [])
        self.assertEqual(self.target.read_bytes(), b"new operator edit")

    def test_rollback_never_overwrites_new_file_state(self):
        result = self.run_repair()
        self.assertTrue(result["success"], result)
        self.target.write_bytes(b"new operator edit")
        undo = self.executor.execute("rollback_service_repair", result["pre_state"], self.current)
        self.assertFalse(undo["success"])
        self.assertEqual(self.target.read_bytes(), b"new operator edit")
        self.assertEqual(self.native_state, "running")

    def test_dry_run_cannot_claim_repair_attestations(self):
        self.executor.allow_restoration = False
        result = self.run_repair()
        self.assertTrue(result["dry_run"])
        self.assertEqual(self.target.read_bytes(), b"damaged")
        self.assertEqual(self.transitions, [])

    def test_success_receipt_cannot_change_plan_files_or_health(self):
        result = self.run_repair()
        self.assertTrue(result["success"], result)
        for mutate in (lambda r: r["record"].update(plan_sha256="f" * 64),
                       lambda r: r["record"].update(files=[]),
                       lambda r: r.update(stable_health=False),
                       lambda r: r.update(probe_attempts=1)):
            altered = copy.deepcopy(result)
            mutate(altered)
            with self.assertRaises(ValueError):
                _require_success_result_contract("repair_service", self.parameters, altered)

    def test_interruption_after_file_commit_can_undo_exact_reserved_children(self):
        class Interrupted(BaseException):
            pass
        self.executor._set_service_state.side_effect = Interrupted()
        with self.assertRaises(Interrupted):
            self.run_repair()
        self.assertEqual(self.target.read_bytes(), b"trusted")
        self.executor._set_service_state.side_effect = self.change_state
        recovery = self.executor.repairs.reconcile()
        self.assertTrue(recovery["healthy"], recovery)
        self.assertEqual(self.target.read_bytes(), b"damaged")
        self.assertEqual(self.native_state, "stopped")

    def test_interrupted_repair_cannot_resume_under_a_different_profile(self):
        class Interrupted(BaseException):
            pass
        self.executor.repair_profile_fingerprint = "a" * 64
        self.executor._set_service_state.side_effect = Interrupted()
        with self.assertRaises(Interrupted):
            self.run_repair()
        self.executor._set_service_state.side_effect = self.change_state
        self.executor.repair_profile_fingerprint = "b" * 64
        recovery = self.executor.repairs.reconcile()
        self.assertFalse(recovery["healthy"])
        self.assertIn("different approved profile", recovery["unresolved"][0]["reason"])
        self.assertEqual(self.target.read_bytes(), b"trusted")
        self.assertEqual(self.transitions, [])

    def test_recovered_local_health_prevents_disruptive_restart(self):
        self.native_state = "running"
        self.current["services"][0]["state"] = "running"
        self.parameters = repair_parameters(self.profile, "agent-one", "web.service", self.baseline, self.current)
        with patch.object(self.executor.repairs, "_probe", return_value=self.healthy):
            result = self.run_repair()
        self.assertFalse(result["success"])
        self.assertIn("recovered", result["message"])
        self.assertEqual(self.transitions, [])
        self.assertEqual(self.target.read_bytes(), b"damaged")

    def test_malformed_child_identity_holds_recovery_without_crashing_or_mutating(self):
        result = self.run_repair()
        self.assertTrue(result["success"], result)
        path = self.executor.repairs._path(result["record"]["transaction_id"])
        original = json.loads(path.read_text())
        self.transitions.clear()
        for identifier in (None, 7, [], {}, True, "not-a-uuid"):
            with self.subTest(identifier=identifier):
                altered = copy.deepcopy(original)
                altered["status"] = "prepared"
                altered["children"][0]["transaction_id"] = identifier
                self.executor.repairs._write(altered)
                recovery = self.executor.repairs.reconcile()
                self.assertFalse(recovery["healthy"])
                self.assertEqual(len(recovery["unresolved"]), 1)
                self.assertEqual(self.target.read_bytes(), b"trusted")
                self.assertEqual(self.native_state, "running")
                self.assertEqual(self.transitions, [])

    def test_live_agent_envelope_validates_and_controller_accepts_repair(self):
        store = Store(":memory:")
        self.addCleanup(store.close)
        app = ControllerApp(store, "t" * 32, operator_token="o" * 32,
                            event_profile=self.profile, auto_recover_services=True)
        app.ingest(self.baseline)
        _promote_integrity_baseline(app, store, "agent-one")
        app.ingest(self.current)
        newest = damage(self.baseline, 3)
        app.ingest(newest)
        action = next(asdict(item) for item in store.pending_actions("agent-one") if item.action_type == "repair_service")
        result = execute_queued_action(ActionJournal(self.root / "journal"), self.executor, action, newest,
                                       {"action_safe": True}, self.profile)
        self.assertTrue(result["success"], result)
        self.assertEqual(app.complete_action({**result, "action_id": action["action_id"]}, "agent-one"), "new")
        self.assertEqual(store.get_action(action["action_id"])["status"], "completed")
        self.assertFalse(store.service_recovery_budget_status("agent-one", "web.service")["allowed"])


if __name__ == "__main__":
    unittest.main()
