import copy
import time
import unittest

from sentinel_blue.adversarial_lab import (
    authentication_boundary_campaign,
    protocol_fuzz,
    valid_payload,
)
from sentinel_blue.validation import (
    ValidationError,
    canonical_action_envelope_sha256,
    validate_action_request,
    validate_action_result,
    validate_telemetry,
)


class ValidationTests(unittest.TestCase):
    @staticmethod
    def bound_action(now: float) -> dict:
        return {
            "action_id": "action-example",
            "agent_id": "agent-example",
            "action_type": "restart_service",
            "parameters": {"service": "web.service"},
            "status": "dispatched",
            "created_at": now,
            "automated": False,
            "risk": "high",
            "expires_at": now + 300,
            "profile_id": "profile-example",
            "profile_fingerprint": "a" * 64,
            "autonomy_mode": "approval-based",
        }

    def validate_bound_action(self, action: dict, now: float) -> dict:
        return validate_action_request(
            action,
            expected_agent_id="agent-example",
            expected_profile_id="profile-example",
            expected_profile_fingerprint="a" * 64,
            expected_autonomy_mode="approval-based",
            require_binding=True,
            now=now,
        )

    def test_valid_payload_is_normalized(self):
        now = time.time()
        result = validate_telemetry(valid_payload(now), "fuzz-agent", now=now)
        self.assertEqual(result["agent_id"], "fuzz-agent")
        self.assertEqual(result["accounts"][0]["groups"], [])

    def test_authenticated_identity_must_match(self):
        with self.assertRaises(ValidationError):
            validate_telemetry(valid_payload(), "different-agent")

    def test_integrity_security_descriptor_digest_is_optional_and_normalized(self):
        payload = valid_payload()
        payload["integrity"][0]["security_descriptor_sha256"] = "A" * 64
        result = validate_telemetry(payload, "fuzz-agent")
        self.assertEqual(
            result["integrity"][0]["security_descriptor_sha256"], "a" * 64
        )

        payload["integrity"][0]["security_descriptor_sha256"] = "invalid"
        with self.assertRaisesRegex(ValidationError, "security_descriptor_sha256"):
            validate_telemetry(payload, "fuzz-agent")

    def test_release_profile_fingerprint_is_optional_but_strict_when_present(self):
        payload = valid_payload()
        payload["profile_id"] = "range-profile"
        payload["profile_fingerprint"] = "A" * 64
        result = validate_telemetry(payload, "fuzz-agent")
        self.assertEqual(result["profile_fingerprint"], "a" * 64)
        payload["profile_fingerprint"] = "not-a-digest"
        with self.assertRaisesRegex(ValidationError, "profile_fingerprint"):
            validate_telemetry(payload, "fuzz-agent")

    def test_oversized_and_bad_nested_values_fail(self):
        payload = valid_payload()
        payload["accounts"] = payload["accounts"] * 4097
        with self.assertRaises(ValidationError):
            validate_telemetry(payload, "fuzz-agent")
        payload = valid_payload()
        payload["listeners"][0]["port"] = 0
        with self.assertRaises(ValidationError):
            validate_telemetry(payload, "fuzz-agent")

    def test_action_result_has_strict_boolean(self):
        payload = {
            "action_id": "a",
            "action_type": "snapshot",
            "success": "true",
            "message": "bad",
            "started_at": time.time(),
            "completed_at": time.time(),
        }
        with self.assertRaises(ValidationError):
            validate_action_result(payload)

    def test_bound_action_rejects_nonfinite_expiry_and_type_confusion(self):
        now = time.time()
        for field, value in (
            ("expires_at", float("nan")),
            ("expires_at", float("inf")),
            ("automated", 0),
            ("created_at", str(now)),
            ("parameters", []),
            ("status", True),
            ("risk", ["high"]),
            ("autonomy_mode", 1),
        ):
            with self.subTest(field=field, value=value):
                action = self.bound_action(now)
                action[field] = value
                with self.assertRaises(ValidationError):
                    self.validate_bound_action(action, now)

    def test_bound_action_rejects_policy_invalid_and_oversized_parameters(self):
        now = time.time()
        malformed = self.bound_action(now)
        malformed["parameters"] = {"service": 7}
        with self.assertRaisesRegex(ValidationError, "parameters are invalid"):
            self.validate_bound_action(malformed, now)

        oversized = self.bound_action(now)
        oversized["parameters"] = {"padding": "x" * 4097}
        with self.assertRaisesRegex(ValidationError, "exceeds 4096"):
            self.validate_bound_action(oversized, now)

    def test_bound_action_accepts_a_valid_controller_selected_autonomy_mode(self):
        now = time.time()
        action = self.bound_action(now)
        action["autonomy_mode"] = "interactive"
        self.assertEqual(
            self.validate_bound_action(action, now)["autonomy_mode"],
            "interactive",
        )

    def test_canonical_action_envelope_digest_is_stable_and_complete(self):
        now = time.time()
        normalized = self.validate_bound_action(self.bound_action(now), now)
        reordered = dict(reversed(list(normalized.items())))
        self.assertEqual(
            canonical_action_envelope_sha256(normalized),
            canonical_action_envelope_sha256(reordered),
        )
        changed = dict(normalized)
        changed["expires_at"] += 1
        self.assertNotEqual(
            canonical_action_envelope_sha256(normalized),
            canonical_action_envelope_sha256(changed),
        )

    def test_action_result_preserves_bounded_failure_evidence(self):
        payload = {
            "action_id": "a",
            "action_type": "restore_integrity",
            "success": False,
            "message": "rolled back",
            "started_at": time.time(),
            "completed_at": time.time(),
            "rolled_back": True,
            "errors": ["self-health: runtime package digest mismatch"],
            "config_validation": {
                "applicable": True,
                "available": True,
                "healthy": False,
                "validator": "sshd",
                "detail": "invalid directive",
            },
        }
        result = validate_action_result(payload)
        self.assertEqual(result["errors"], payload["errors"])
        self.assertEqual(result["config_validation"], payload["config_validation"])

    def test_successful_restore_point_capture_requires_explicit_non_dry_run(self):
        receipt = {
            "path": "/etc/example.conf",
            "source_sha256": "a" * 64,
            "backup_sha256": "a" * 64,
            "backup_matches_source": True,
            "byte_size": 12,
            "security_metadata_sha256": "b" * 64,
            "security_descriptor_sha256": "",
            "restore_point_id": "11111111-1111-4111-8111-111111111111",
            "stored": True,
        }
        payload = {
            "action_id": "capture-one",
            "action_type": "capture_restore_point",
            "success": True,
            "message": "captured",
            "started_at": 1,
            "completed_at": 2,
            "captured": [receipt["path"]],
            "capture_receipts": [receipt],
        }
        with self.assertRaisesRegex(ValidationError, "durable receipts"):
            validate_action_result(payload)
        payload["dry_run"] = False
        self.assertFalse(validate_action_result(payload)["dry_run"])

    def test_fuzz_campaign_rejects_all_invalid_cases(self):
        report = protocol_fuzz(300)
        self.assertTrue(report["passed"])
        self.assertEqual(report["invalid_accepted"], 0)
        self.assertTrue(all(report["case_coverage"].values()), report)

    def test_authentication_boundary_campaign(self):
        report = authentication_boundary_campaign()
        self.assertTrue(report["passed"], report)
        self.assertEqual(report["nonfinite_cases"], report["nonfinite_rejected"])


if __name__ == "__main__":
    unittest.main()
