import hashlib
import hmac
import time
import unittest

from sentinel_blue.auth import (
    PrincipalRateLimiter,
    ReplayGuard,
    derive_agent_token,
    derive_enrollment_ticket,
    response_signature,
    signature,
    unwrap_enrollment_token,
    validate_operator_token,
    verify,
    verify_response,
    wrap_enrollment_token,
)


class AuthTests(unittest.TestCase):
    def test_operator_token_must_use_independent_secret_material(self):
        enrollment = "e" * 32
        independent = "o" * 32
        self.assertEqual(
            validate_operator_token(enrollment, independent), independent
        )
        with self.assertRaisesRegex(ValueError, "not independent"):
            validate_operator_token(enrollment, enrollment)
        legacy = hmac.new(
            enrollment.encode(),
            b"sentinel-blue-operator-v1",
            hashlib.sha256,
        ).hexdigest()
        with self.assertRaisesRegex(ValueError, "not independent"):
            validate_operator_token(enrollment, legacy)

    def test_operator_token_format_fails_closed(self):
        for candidate in ("short", "contains spaces" * 3, "x" * 257):
            with self.subTest(candidate=candidate[:20]):
                with self.assertRaisesRegex(ValueError, "operator token"):
                    validate_operator_token("e" * 32, candidate)

    def test_replay_cache_saturation_fails_closed(self):
        guard = ReplayGuard(lifetime=60, max_entries=128)
        for index in range(128):
            self.assertTrue(guard.accept(f"signature-{index}", now=1.0))
        self.assertFalse(guard.accept("overflow", now=1.0))
        self.assertFalse(guard.accept("signature-0", now=1.0))

    def test_replay_partitions_prevent_one_agent_from_starving_another(self):
        guard = ReplayGuard(lifetime=60, max_entries=128, max_principals=2)
        for index in range(128):
            self.assertTrue(
                guard.accept(f"hostile-{index}", now=1.0, principal="hostile")
            )
        self.assertFalse(
            guard.accept("hostile-overflow", now=1.0, principal="hostile")
        )
        self.assertTrue(guard.accept("healthy", now=1.0, principal="healthy"))
        self.assertFalse(guard.accept("third", now=1.0, principal="third"))
        self.assertTrue(guard.accept("third", now=62.0, principal="third"))

    def test_token_buckets_are_isolated_and_principal_table_is_bounded(self):
        limiter = PrincipalRateLimiter(
            rate_per_second=1.0,
            burst=2,
            max_principals=2,
        )
        self.assertTrue(limiter.consume("hostile", now=10.0)[0])
        self.assertTrue(limiter.consume("hostile", now=10.0)[0])
        allowed, retry = limiter.consume("hostile", now=10.0)
        self.assertFalse(allowed)
        self.assertEqual(retry, 1.0)
        self.assertTrue(limiter.consume("healthy", now=10.0)[0])
        self.assertFalse(limiter.consume("third", now=10.0)[0])
        self.assertTrue(limiter.consume("hostile", now=11.0)[0])

    def test_valid_signature(self):
        now = time.time()
        timestamp = str(now)
        body = b'{"ok":true}'
        supplied = signature("a" * 32, timestamp, "POST", "/telemetry", body)
        self.assertTrue(verify("a" * 32, timestamp, "POST", "/telemetry", body, supplied, now=now))

    def test_tampering_and_replay_fail(self):
        now = time.time()
        timestamp = str(now - 301)
        supplied = signature("a" * 32, timestamp, "GET", "/actions", b"")
        self.assertFalse(verify("a" * 32, timestamp, "GET", "/actions", b"", supplied, now=now))
        current = str(now)
        supplied = signature("a" * 32, current, "GET", "/actions", b"")
        self.assertFalse(verify("a" * 32, current, "GET", "/other", b"", supplied, now=now))

    def test_nonfinite_request_timestamps_fail_closed(self):
        token = "a" * 32
        now = time.time()
        for timestamp in ("nan", "NaN", "inf", "-inf"):
            with self.subTest(timestamp=timestamp):
                supplied = signature(token, timestamp, "GET", "/actions", b"")
                self.assertFalse(
                    verify(token, timestamp, "GET", "/actions", b"", supplied, now=now)
                )

    def test_nonfinite_response_timestamps_fail_closed(self):
        token = "r" * 32
        now = time.time()
        path = "/api/v1/agent/result"
        request_signature = "a" * 64
        body = b'{"completed":false}'
        for timestamp in ("nan", "NaN", "inf", "-inf"):
            with self.subTest(timestamp=timestamp):
                supplied = response_signature(
                    token, timestamp, 200, path, request_signature, body
                )
                self.assertFalse(
                    verify_response(
                        token,
                        timestamp,
                        200,
                        path,
                        request_signature,
                        body,
                        supplied,
                        now=now,
                    )
                )

    def test_agent_tokens_are_distinct(self):
        self.assertNotEqual(
            derive_agent_token("a" * 32, "agent-one"),
            derive_agent_token("a" * 32, "agent-two"),
        )

    def test_enrollment_tickets_bind_profile_and_agent_with_a_distinct_domain(self):
        master = "m" * 32
        profile = "a" * 64
        first = derive_enrollment_ticket(master, profile, "agent-one")
        self.assertEqual(first, derive_enrollment_ticket(master, profile, "agent-one"))
        self.assertNotEqual(first, derive_enrollment_ticket(master, profile, "agent-two"))
        self.assertNotEqual(
            first, derive_enrollment_ticket(master, "b" * 64, "agent-one")
        )
        self.assertNotEqual(first, derive_agent_token(master, "agent-one"))
        self.assertNotEqual(first, master)

    def test_enrollment_ticket_inputs_fail_closed(self):
        for master, profile, agent_id in (
            ("short", "a" * 64, "agent-one"),
            ("m" * 32, "not-a-digest", "agent-one"),
            ("m" * 32, "a" * 64, "agent one"),
        ):
            with self.subTest(agent_id=agent_id, profile=profile[:12]):
                with self.assertRaises(ValueError):
                    derive_enrollment_ticket(master, profile, agent_id)

    def test_replay_guard_rejects_duplicate_signature(self):
        guard = ReplayGuard(lifetime=10)
        self.assertTrue(guard.accept("signed-request", now=100))
        self.assertFalse(guard.accept("signed-request", now=101))
        self.assertTrue(guard.accept("signed-request", now=111))

    def test_response_signature_binds_status_and_exact_request(self):
        now = time.time()
        timestamp = str(now)
        token = "r" * 32
        body = b'{"completed":false}'
        first_request = signature(token, timestamp, "POST", "/api/v1/agent/result", b"{}")
        other_request = signature(token, timestamp, "GET", "/api/v1/agent/result", b"")
        supplied = response_signature(
            token,
            timestamp,
            400,
            "/api/v1/agent/result",
            first_request,
            body,
        )
        self.assertTrue(
            verify_response(
                token,
                timestamp,
                400,
                "/api/v1/agent/result",
                first_request,
                body,
                supplied,
                now=now,
            )
        )
        self.assertFalse(
            verify_response(
                token,
                timestamp,
                200,
                "/api/v1/agent/result",
                first_request,
                body,
                supplied,
                now=now,
            )
        )
        self.assertFalse(
            verify_response(
                token,
                timestamp,
                400,
                "/api/v1/agent/result",
                other_request,
                body,
                supplied,
                now=now,
            )
        )

    def test_agent_enrollment_token_is_request_bound_and_not_plaintext(self):
        master = "m" * 32
        request = signature(master, "1800000000", "POST", "/api/v1/agent/enroll", b"{}")
        token = "agent_secret-" + "x" * 52
        wrapped = wrap_enrollment_token(master, request, token)
        self.assertNotIn(token, wrapped)
        self.assertEqual(unwrap_enrollment_token(master, request, wrapped), token)
        other_request = signature(
            master, "1800000001", "POST", "/api/v1/agent/enroll", b"{}"
        )
        with self.assertRaisesRegex(ValueError, "wrapped agent token"):
            unwrap_enrollment_token(master, other_request, wrapped)


if __name__ == "__main__":
    unittest.main()
