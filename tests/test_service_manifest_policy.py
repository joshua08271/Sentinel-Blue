import copy
import time
import unittest

from sentinel_blue.controller import ControllerApp
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.policy import ALLOWED_ACTIONS
from sentinel_blue.store import Store


PROBE = {
    "name": "web-health",
    "kind": "http",
    "target": "http://192.0.2.10/health",
    "expected_status": [200],
}


def service_manifest(
    service_id: str = "web.service",
    *,
    host: str = "agent-one",
    required_files: list[str] | None = None,
    expected_transactions: list[dict] | None = None,
    automatic: list[str] | None = None,
    approval: list[str] | None = None,
) -> dict:
    return {
        "service_id": service_id,
        "host": host,
        "protocol": "http",
        "port": 80,
        "implementation": "fixture",
        "dependencies": [],
        "required_accounts": [],
        "required_files": list(required_files or ["/etc/web.conf"]),
        "required_data": ["/srv/web"],
        "credential_source": "fixture",
        "expected_transactions": list(expected_transactions or [PROBE]),
        "local_checks": ["fixture"],
        "allowed_automatic_actions": list(automatic or []),
        "approval_actions": list(approval or []),
        "backup_method": "fixture",
        "recovery_method": "fixture",
        "rollback_method": "fixture",
    }


def profile_for(
    services: list[dict], *, automatic_actions: list[str] | None = None
) -> EventProfile:
    payload = copy.deepcopy(EventProfile.testing().raw)
    payload["profile_id"] = "service-manifest-policy-test"
    payload["services"] = services
    payload["services_confirmed"] = True
    payload["allowed_automatic_actions"] = list(
        ALLOWED_ACTIONS if automatic_actions is None else automatic_actions
    )
    return EventProfile.from_dict(payload)


class ServiceManifestPolicyTests(unittest.TestCase):
    def make_app(self, profile: EventProfile) -> tuple[ControllerApp, Store]:
        store = Store(":memory:")
        return (
            ControllerApp(
                store,
                "m" * 32,
                event_profile=profile,
                operator_token="o" * 32,
            ),
            store,
        )

    def test_service_action_requires_global_and_mode_specific_manifest_policy(self):
        manifest = service_manifest(
            automatic=["restart_service"],
            approval=["rollback_service"],
        )
        app, store = self.make_app(profile_for([manifest]))
        self.addCleanup(store.close)

        automatic_id = app._queue_action(
            "agent-one",
            "restart_service",
            {"service": "web.service"},
            automated=True,
        )
        self.assertIsNotNone(automatic_id)
        with self.assertRaisesRegex(PermissionError, "service manifest"):
            app._queue_action(
                "agent-one", "restart_service", {"service": "web.service"}
            )
        rollback_id = app._queue_action(
            "agent-one",
            "rollback_service",
            {"service": "web.service", "desired_state": "running"},
        )
        self.assertIsNotNone(rollback_id)

        global_hold, global_store = self.make_app(
            profile_for([manifest], automatic_actions=["validate_service"])
        )
        self.addCleanup(global_store.close)
        self.assertIsNone(
            global_hold._queue_action(
                "agent-one",
                "restart_service",
                {"service": "web.service"},
                automated=True,
            )
        )

    def test_service_id_and_host_mapping_are_exact_and_unique(self):
        manifest = service_manifest(approval=["restart_service"])
        app, store = self.make_app(profile_for([manifest]))
        self.addCleanup(store.close)
        for agent_id, service_id in (
            ("agent-one", "WEB.SERVICE"),
            ("agent-two", "web.service"),
            ("agent-one", "missing.service"),
        ):
            with self.subTest(agent_id=agent_id, service_id=service_id):
                with self.assertRaisesRegex(PermissionError, "service manifest"):
                    app._queue_action(
                        agent_id, "restart_service", {"service": service_id}
                    )

        duplicate = service_manifest(
            "web.service", approval=["restart_service"]
        )
        ambiguous, ambiguous_store = self.make_app(
            profile_for([manifest, duplicate])
        )
        self.addCleanup(ambiguous_store.close)
        with self.assertRaisesRegex(PermissionError, "service manifest"):
            ambiguous._queue_action(
                "agent-one", "restart_service", {"service": "web.service"}
            )

    def test_integrity_paths_are_exact_and_every_service_must_authorize(self):
        web = service_manifest(
            automatic=["capture_restore_point"],
            approval=["restore_integrity", "rollback_integrity"],
        )
        database = service_manifest(
            "database.service",
            required_files=["/etc/database.conf"],
            expected_transactions=[
                {
                    "name": "database-health",
                    "kind": "tcp",
                    "target": "192.0.2.10",
                    "port": 5432,
                }
            ],
        )
        app, store = self.make_app(profile_for([web, database]))
        self.addCleanup(store.close)

        capture = app._queue_action(
            "agent-one",
            "capture_restore_point",
            {"files": [{"path": "/etc/web.conf", "sha256": "a" * 64}]},
            automated=True,
        )
        self.assertIsNotNone(capture)
        self.assertIsNone(
            app._queue_action(
                "agent-one",
                "capture_restore_point",
                {
                    "files": [
                        {"path": "/etc/web.conf", "sha256": "a" * 64},
                        {"path": "/etc/database.conf", "sha256": "b" * 64},
                    ]
                },
                automated=True,
            )
        )
        with self.assertRaisesRegex(PermissionError, "service manifest"):
            app._queue_action(
                "agent-one",
                "restore_integrity",
                {
                    "path": "/etc/not-declared.conf",
                    "baseline_sha256": "a" * 64,
                    "observed_sha256": "b" * 64,
                },
            )

        duplicate_path = service_manifest(
            "duplicate.service",
            required_files=["/etc/web.conf"],
            approval=["restore_integrity"],
        )
        ambiguous, ambiguous_store = self.make_app(
            profile_for([web, duplicate_path])
        )
        self.addCleanup(ambiguous_store.close)
        with self.assertRaisesRegex(PermissionError, "service manifest"):
            ambiguous._queue_action(
                "agent-one",
                "restore_integrity",
                {
                    "path": "/etc/web.conf",
                    "baseline_sha256": "a" * 64,
                    "observed_sha256": "b" * 64,
                },
            )

    def test_probe_contract_mapping_rejects_rebinding_and_ambiguity(self):
        manifest = service_manifest(automatic=["validate_service"])
        app, store = self.make_app(profile_for([manifest]))
        self.addCleanup(store.close)

        action_id = app._queue_action(
            "agent-one",
            "validate_service",
            {"probes": [{**PROBE, "restore_paths": ["/etc/web.conf"]}]},
            automated=True,
        )
        self.assertIsNotNone(action_id)
        rebound = {**PROBE, "target": "http://192.0.2.11/health"}
        self.assertIsNone(
            app._queue_action(
                "agent-one",
                "validate_service",
                {"probes": [rebound]},
                automated=True,
            )
        )
        self.assertIsNone(
            app._queue_action(
                "agent-one",
                "validate_service",
                {"probes": []},
                automated=True,
            )
        )

        duplicate = service_manifest(
            "duplicate.service",
            expected_transactions=[PROBE],
            automatic=["validate_service"],
        )
        ambiguous, ambiguous_store = self.make_app(
            profile_for([manifest, duplicate])
        )
        self.addCleanup(ambiguous_store.close)
        self.assertIsNone(
            ambiguous._queue_action(
                "agent-one",
                "validate_service",
                {"probes": [PROBE]},
                automated=True,
            )
        )

    def test_integrity_rollback_keeps_manifest_path_and_probe_binding(self):
        manifest = service_manifest(
            approval=["restore_integrity", "rollback_integrity"]
        )
        app, store = self.make_app(profile_for([manifest]))
        self.addCleanup(store.close)
        parameters = {
            "path": "/etc/web.conf",
            "baseline_sha256": "a" * 64,
            "observed_sha256": "b" * 64,
            "probes": [{**PROBE, "restore_paths": ["/etc/web.conf"]}],
        }
        original = app._queue_action(
            "agent-one", "restore_integrity", parameters
        )
        self.assertEqual(
            [item.action_id for item in store.pending_actions("agent-one")],
            [original],
        )
        now = time.time()
        self.assertTrue(
            app.complete_action(
                {
                    "action_id": original,
                    "action_type": "restore_integrity",
                    "success": True,
                    "message": "fixture",
                    "started_at": now,
                    "completed_at": now,
                    "pre_state": {"transaction_id": "fixture-transaction"},
                    "transaction_id": "fixture-transaction",
                    "evidence_preserved": True,
                    "config_validation": {
                        "applicable": False,
                        "available": False,
                        "healthy": None,
                        "validator": None,
                        "detail": "fixture",
                    },
                    "probes": [
                        {
                            "name": PROBE["name"],
                            "target": PROBE["target"],
                            "healthy": True,
                            "latency_ms": 0,
                            "detail": "fixture",
                        }
                    ],
                },
                "agent-one",
            )
        )
        rollback = app.rollback_action(str(original))
        queued = store.get_action(str(rollback["action_id"]))
        self.assertEqual(queued["parameters"]["path"], "/etc/web.conf")
        self.assertEqual(queued["parameters"]["probes"], parameters["probes"])


if __name__ == "__main__":
    unittest.main()
