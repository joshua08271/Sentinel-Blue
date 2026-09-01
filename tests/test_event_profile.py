import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from sentinel_blue import __version__
from sentinel_blue.event_profile import CAPABILITIES, EventProfile, load_event_profile
from sentinel_blue.risk import RiskModel


def live_profile(competition="ccdc-strict"):
    capabilities = {name: False for name in CAPABILITIES}
    capabilities.update(
        {
            "in_place_repair": True,
            "structured_rollback": True,
            "configuration_backups": True,
            "network_monitoring": True,
            "external_controller": True,
            "file_restoration": True,
            "session_containment": True,
        }
    )
    return {
        "profile_version": 1,
        "profile_id": f"fixture-{competition}",
        "competition": competition,
        "environment": "live-competition",
        "autonomy_mode": "observe",
        "architecture": {
            "single_live_scored_network": True,
            "blue_staging_non_authoritative": True,
        },
        "scope": {
            "authorized_networks": ["192.0.2.0/24"],
            "authorized_hosts": ["192.0.2.10"],
            "controller_ingress_hosts": ["192.0.2.10"],
            "excluded_hosts": ["192.0.2.254"],
            "approved_deployment_paths": ["/opt/sentinel-blue", "C:\\ProgramData\\SentinelBlue"],
        },
        "deployment": {"approved_routes": ["ssh", "winrm"]},
        "capabilities": capabilities,
        "organizer_exceptions": [],
        "allowed_automatic_actions": [],
        "official_identities": [
            {
                "agent_id": "*",
                "name": "scoring-service-example",
                "class": "scoring",
                "source": "fixture",
            }
        ],
        "services": [
            {
                "service_id": "web-example",
                "host": "agent-web",
                "protocol": "https",
                "port": 443,
                "implementation": "nginx",
                "dependencies": [],
                "required_accounts": ["web-service-example"],
                "required_files": ["/etc/nginx/nginx.conf"],
                "required_data": ["/srv/www"],
                "credential_source": "event-provided secret store",
                "expected_transactions": [
                    {
                        "name": "web-transaction",
                        "kind": "https",
                        "target": "https://192.0.2.10/health",
                        "expected_status": [200],
                    }
                ],
                "local_checks": ["service state"],
                "allowed_automatic_actions": [],
                "approval_actions": ["restart_service", "restore_integrity"],
                "backup_method": "versioned configuration copy",
                "recovery_method": "repair original assigned host in place",
                "rollback_method": "restore captured pre-state",
            }
        ],
        "services_confirmed": True,
        "recovery": {"baseline_promotion_delay_seconds": 60},
        "approval": {"status": "approved", "approved_by": "event-official"},
        "release": {
            "version": __version__,
            "approved": True,
            "sha256": "a" * 64,
            "controller_ca_sha256": "c" * 64,
            "public_url": f"https://example.invalid/sentinel-blue-{__version__}.pyz",
            "frozen": True,
            "submitted_to_officials": True,
            "submission_approved": True,
            "public_and_equal_access": True,
            "cloud_processing": False,
            "external_telemetry_export": False,
            "public_days_before_event": 120,
            "submitted_days_before_event": 45,
        },
    }


class EventProfileTests(unittest.TestCase):
    def _external_range_profile(self):
        payload = copy.deepcopy(EventProfile.testing().raw)
        payload["scope"]["authorized_networks"] = ["10.70.0.0/16"]
        payload["scope"]["authorized_hosts"] = ["10.70.0.4", "10.70.10.4"]
        payload["scope"]["controller_ingress_hosts"] = ["10.70.10.4"]
        payload["scope"]["approved_deployment_paths"] = [
            "/opt/sentinel-blue",
            "C:\\ProgramData\\SentinelBlue",
        ]
        payload["deployment"]["approved_routes"] = ["preinstalled"]
        payload["capabilities"]["external_cloud_processing"] = False
        payload["capabilities"]["external_telemetry_export"] = False
        payload["capabilities"]["external_controller"] = True
        payload["services"] = [copy.deepcopy(live_profile()["services"][0])]
        payload["services"][0]["host"] = "10.70.10.4"
        payload["services"][0]["expected_transactions"][0]["target"] = (
            "http://10.70.10.4:8080/health"
        )
        payload["services"][0]["expected_transactions"][0]["kind"] = "http"
        payload["services_confirmed"] = True
        payload["approval"] = {"status": "range-only", "approved_by": "range-owner"}
        payload["release"] = {
            "version": __version__,
            "sha256": "b" * 64,
            "controller_ca_sha256": "c" * 64,
            "cloud_processing": False,
            "external_telemetry_export": False,
        }
        return payload

    def test_external_range_requires_explicit_range_gate(self):
        profile = EventProfile.from_dict(self._external_range_profile())
        profile.require_runtime_ready(__version__, range_deployment=True)
        with self.assertRaisesRegex(ValueError, "disposable range"):
            profile.require_runtime_ready(__version__)

    def test_profile_loader_rejects_duplicate_authority_fields(self):
        payload = json.dumps(EventProfile.testing().raw, separators=(",", ":"))
        payload = payload.replace(
            '"autonomy_mode":"range-autonomous"',
            '"autonomy_mode":"observe","autonomy_mode":"range-autonomous"',
            1,
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "event-profile.json"
            path.write_text(payload, encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "duplicate JSON object key"):
                load_event_profile(path)

    def test_range_autonomy_still_enforces_the_automatic_action_allowlist(self):
        payload = self._external_range_profile()
        payload["allowed_automatic_actions"] = ["snapshot"]
        profile = EventProfile.from_dict(payload)
        self.assertTrue(profile.action_allowed("snapshot", automated=True))
        self.assertFalse(profile.action_allowed("restore_integrity", automated=True))
        self.assertTrue(profile.action_allowed("restore_integrity", automated=False))

    def test_range_gate_never_accepts_live_profiles(self):
        with self.assertRaisesRegex(ValueError, "range-autonomous"):
            EventProfile.from_dict(live_profile()).require_runtime_ready(
                __version__, range_deployment=True
            )

    def test_range_gate_requires_pinned_local_only_release(self):
        payload = self._external_range_profile()
        payload["release"].pop("sha256")
        with self.assertRaisesRegex(ValueError, "exact SHA-256"):
            EventProfile.from_dict(payload).require_range_ready(__version__)
        payload = self._external_range_profile()
        payload["release"]["external_telemetry_export"] = True
        with self.assertRaisesRegex(ValueError, "telemetry export"):
            EventProfile.from_dict(payload).require_range_ready(__version__)

    def test_live_profile_is_default_deny_and_scope_exact(self):
        profile = EventProfile.from_dict(live_profile())
        self.assertTrue(profile.allows("in_place_repair"))
        self.assertFalse(profile.allows("host_snapshots"))
        profile.assert_target("192.0.2.10")
        with self.assertRaisesRegex(ValueError, "excluded"):
            profile.assert_target("192.0.2.254")
        with self.assertRaisesRegex(ValueError, "host inventory"):
            profile.assert_target("192.0.2.11")
        self.assertEqual(profile.controller_ingress_hosts, ("192.0.2.10",))
        profile.assert_inventory_networks(["192.0.2.0/24"])
        with self.assertRaisesRegex(ValueError, "match"):
            profile.assert_inventory_networks(["192.0.2.0/25"])

    def test_unaddressed_and_unknown_capabilities_do_not_become_enabled(self):
        payload = live_profile()
        payload["capabilities"].pop("account_disabling")
        profile = EventProfile.from_dict(payload)
        self.assertFalse(profile.allows("account_disabling"))
        payload = live_profile()
        payload["capabilities"]["typo_all_powerful_mode"] = True
        with self.assertRaisesRegex(ValueError, "unknown keys"):
            EventProfile.from_dict(payload)

    def test_live_profiles_refuse_migration_failover_and_forks(self):
        for capability in (
            "scored_service_migration",
            "automatic_vm_replacement",
            "network_forks",
        ):
            payload = live_profile()
            payload["capabilities"][capability] = True
            payload["organizer_exceptions"] = [capability]
            with self.subTest(capability=capability):
                with self.assertRaisesRegex(ValueError, "prohibited"):
                    EventProfile.from_dict(payload)

    def test_hivestorm_refuses_snapshots_and_vm_copies_even_as_exceptions(self):
        for capability in ("host_snapshots", "full_vm_duplication"):
            payload = live_profile("hivestorm")
            payload["capabilities"][capability] = True
            payload["organizer_exceptions"] = [capability]
            with self.subTest(capability=capability):
                with self.assertRaises(ValueError):
                    EventProfile.from_dict(payload)

    def test_guarded_autonomy_must_be_explicit_and_action_bounded(self):
        payload = live_profile("ncae-standard")
        payload["autonomy_mode"] = "guarded-autonomous"
        payload["capabilities"]["guarded_autonomy"] = True
        payload["allowed_automatic_actions"] = ["restart_service"]
        profile = EventProfile.from_dict(payload)
        self.assertTrue(
            profile.action_allowed(
                "restart_service", automated=True, autonomy_mode="guarded-autonomous"
            )
        )
        self.assertFalse(
            profile.action_allowed(
                "restore_integrity", automated=True, autonomy_mode="guarded-autonomous"
            )
        )

    def test_observe_and_emergency_stop_fail_closed(self):
        profile = EventProfile.from_dict(live_profile())
        self.assertFalse(profile.action_allowed("restart_service", automated=False))
        self.assertFalse(
            profile.action_allowed(
                "restart_service",
                automated=False,
                autonomy_mode="approval-based",
                emergency_stopped=True,
            )
        )
        self.assertTrue(
            profile.action_allowed(
                "rollback_service",
                automated=False,
                autonomy_mode="approval-based",
                emergency_stopped=True,
            )
        )

    def test_live_readiness_requires_approval_and_exact_release(self):
        profile = EventProfile.from_dict(live_profile())
        profile.require_live_ready(__version__)
        draft = copy.deepcopy(live_profile())
        draft["approval"]["status"] = "draft"
        with self.assertRaisesRegex(ValueError, "approval"):
            EventProfile.from_dict(draft).require_live_ready(__version__)
        with self.assertRaisesRegex(ValueError, "not '1.9.2'"):
            profile.require_live_ready("1.9.2")

    def test_service_manifest_must_contain_transactional_recovery_contract(self):
        payload = live_profile()
        payload["services"][0].pop("rollback_method")
        with self.assertRaisesRegex(ValueError, "rollback_method"):
            EventProfile.from_dict(payload)

    def test_live_release_requires_frozen_public_submitted_digest_contract(self):
        for field in (
            "sha256",
            "controller_ca_sha256",
            "public_url",
            "frozen",
            "submitted_to_officials",
            "submission_approved",
            "public_and_equal_access",
            "cloud_processing",
            "external_telemetry_export",
        ):
            payload = live_profile()
            payload["release"].pop(field)
            with self.subTest(field=field):
                with self.assertRaises(ValueError):
                    EventProfile.from_dict(payload).require_live_ready(__version__)

    def test_controller_ingress_hosts_are_exact_and_inventory_bound(self):
        payload = live_profile()
        payload["scope"]["controller_ingress_hosts"] = ["192.0.2.11"]
        with self.assertRaisesRegex(ValueError, "authorized host inventory"):
            EventProfile.from_dict(payload)
        payload = live_profile()
        payload["scope"]["controller_ingress_hosts"] *= 2
        with self.assertRaisesRegex(ValueError, "duplicates"):
            EventProfile.from_dict(payload)

    def test_controller_ca_file_is_exactly_digest_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            ca_file = Path(directory) / "controller-ca.crt"
            ca_file.write_bytes(b"fixture public trust anchor")
            payload = live_profile()
            payload["release"]["controller_ca_sha256"] = hashlib.sha256(
                ca_file.read_bytes()
            ).hexdigest()
            profile = EventProfile.from_dict(payload)
            self.assertEqual(
                profile.verify_controller_ca_file(ca_file),
                payload["release"]["controller_ca_sha256"],
            )
            ca_file.write_bytes(b"substituted trust anchor")
            with self.assertRaisesRegex(ValueError, "digest"):
                profile.verify_controller_ca_file(ca_file)

    def test_release_file_digest_is_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "sentinel-blue.pyz"
            runtime.write_bytes(b"frozen fixture")
            payload = live_profile()
            payload["release"]["sha256"] = hashlib.sha256(runtime.read_bytes()).hexdigest()
            profile = EventProfile.from_dict(payload)
            self.assertEqual(profile.verify_release_file(runtime), payload["release"]["sha256"])
            runtime.write_bytes(b"tampered fixture")
            with self.assertRaisesRegex(ValueError, "digest"):
                profile.verify_release_file(runtime)

    def test_external_model_requires_an_exact_profile_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / "risk-model.json"
            RiskModel().save(model)
            profile = EventProfile.from_dict(live_profile())
            with self.assertRaisesRegex(ValueError, "model_sha256"):
                profile.verify_model_file(model)
            payload = live_profile()
            payload["release"]["model_sha256"] = hashlib.sha256(model.read_bytes()).hexdigest()
            profile = EventProfile.from_dict(payload)
            self.assertEqual(profile.verify_model_file(model), payload["release"]["model_sha256"])
            self.assertEqual(
                profile.load_model_file(model).fingerprint(),
                RiskModel().fingerprint(),
            )
            model.write_text('{"bias":0,"weights":{}}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest"):
                profile.verify_model_file(model)

    def test_matching_digest_does_not_approve_an_invalid_model(self):
        with tempfile.TemporaryDirectory() as directory:
            model = Path(directory) / "risk-model.json"
            model.write_text('{"bias":-1,"weights":{}}', encoding="utf-8")
            payload = live_profile()
            payload["release"]["model_sha256"] = hashlib.sha256(model.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "feature set"):
                EventProfile.from_dict(payload).load_model_file(model)

    @unittest.skipUnless(hasattr(Path, "symlink_to"), "symbolic links unavailable")
    def test_external_model_refuses_symbolic_links_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            actual = root / "actual.json"
            actual.write_text("{}", encoding="utf-8")
            linked = root / "linked.json"
            linked.symlink_to(actual)
            payload = live_profile()
            payload["release"]["model_sha256"] = hashlib.sha256(actual.read_bytes()).hexdigest()
            profile = EventProfile.from_dict(payload)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                profile.verify_model_file(linked)
            oversized = root / "oversized.json"
            oversized.write_bytes(b"x" * (1024 * 1024 + 1))
            payload["release"]["model_sha256"] = hashlib.sha256(oversized.read_bytes()).hexdigest()
            with self.assertRaisesRegex(ValueError, "size limit"):
                EventProfile.from_dict(payload).verify_model_file(oversized)


if __name__ == "__main__":
    unittest.main()
