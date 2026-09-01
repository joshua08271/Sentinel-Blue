from __future__ import annotations

from dataclasses import FrozenInstanceError
from email.message import Message
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import unittest

from sentinel_blue.operator_auth import (
    OPERATOR_AUTH_DOMAIN,
    OPERATOR_AUTH_VERSION,
    OPERATOR_HEADER_EPOCH,
    OPERATOR_HEADER_PRINCIPAL,
    OPERATOR_HEADER_REQUEST_ID,
    OPERATOR_HEADER_SIGNATURE,
    OPERATOR_HEADER_TIMESTAMP,
    OPERATOR_HEADER_VERSION,
    OperatorAuthenticationError,
    OperatorHeaderError,
    authenticate_operator_request,
    operator_canonical_bytes,
    operator_key_fingerprint,
    operator_signature,
    parse_operator_headers,
    verify_operator_request,
)


TOKEN = "0123456789abcdef0123456789abcdef"
PRINCIPAL = "blue-lead"
EPOCH = 7
TIMESTAMP = 1_787_932_800
REQUEST_ID = "00112233445566778899aabbccddeeff"
METHOD = "POST"
TARGET = "/api/v1/governance/mode?source=ui"
BODY = b'{"mode":"approval-based"}'
EXPECTED_FINGERPRINT = (
    "600dfc5c462bc5a967a41dbfe560cefa080d15de8f96998735ecb7053159f456"
)
EXPECTED_SIGNATURE = (
    "534d3ca9fe83249bf27b6fea4674d9a4d1fd7928ccfc37d4b95bbd928b0a1132"
)


def signed_headers(**changes: object) -> dict[str, str]:
    fields: dict[str, object] = {
        "principal": PRINCIPAL,
        "epoch": EPOCH,
        "timestamp": TIMESTAMP,
        "request_id": REQUEST_ID,
        "method": METHOD,
        "target": TARGET,
        "body": BODY,
    }
    fields.update(changes)
    supplied = operator_signature(
        TOKEN,
        str(fields["principal"]),
        fields["epoch"],
        fields["timestamp"],
        str(fields["request_id"]),
        str(fields["method"]),
        str(fields["target"]),
        fields["body"],
    )
    return {
        OPERATOR_HEADER_VERSION: OPERATOR_AUTH_VERSION,
        OPERATOR_HEADER_PRINCIPAL: str(fields["principal"]),
        OPERATOR_HEADER_EPOCH: str(fields["epoch"]),
        OPERATOR_HEADER_TIMESTAMP: str(fields["timestamp"]),
        OPERATOR_HEADER_REQUEST_ID: str(fields["request_id"]),
        OPERATOR_HEADER_SIGNATURE: supplied,
    }


class OperatorAuthPrimitiveTests(unittest.TestCase):
    def test_fixed_version_one_vector(self):
        self.assertEqual(OPERATOR_AUTH_DOMAIN, b"sentinel-blue-operator-request-v1")
        self.assertEqual(operator_key_fingerprint(TOKEN), EXPECTED_FINGERPRINT)
        self.assertEqual(
            operator_signature(
                TOKEN,
                PRINCIPAL,
                EPOCH,
                TIMESTAMP,
                REQUEST_ID,
                METHOD,
                TARGET,
                BODY,
            ),
            EXPECTED_SIGNATURE,
        )
        canonical = operator_canonical_bytes(
            PRINCIPAL, EPOCH, TIMESTAMP, REQUEST_ID, METHOD, TARGET, BODY
        )
        self.assertEqual(
            canonical.split(b"\x00"),
            [
                b"sentinel-blue-operator-request-v1",
                b"blue-lead",
                b"7",
                b"1787932800",
                b"00112233445566778899aabbccddeeff",
                b"POST",
                b"/api/v1/governance/mode?source=ui",
                hashlib.sha256(BODY).hexdigest().encode("ascii"),
            ],
        )

    def test_every_request_binding_field_is_authenticated(self):
        supplied = EXPECTED_SIGNATURE
        valid = {
            "principal_id": PRINCIPAL,
            "credential_epoch": EPOCH,
            "request_timestamp": TIMESTAMP,
            "request_id": REQUEST_ID,
            "method": METHOD,
            "target": TARGET,
            "body": BODY,
        }
        self.assertTrue(
            verify_operator_request(
                TOKEN,
                **valid,
                supplied_signature=supplied,
                expected_principal=PRINCIPAL,
                expected_credential_epoch=EPOCH,
                now=TIMESTAMP,
            )
        )
        changes = {
            "principal_id": "blue-backup",
            "credential_epoch": EPOCH + 1,
            "request_timestamp": TIMESTAMP + 1,
            "request_id": "10112233445566778899aabbccddeeff",
            "method": "PUT",
            "target": TARGET + "2",
            "body": BODY + b" ",
        }
        for field, replacement in changes.items():
            with self.subTest(field=field):
                altered = dict(valid)
                altered[field] = replacement
                self.assertFalse(
                    verify_operator_request(
                        TOKEN,
                        **altered,
                        supplied_signature=supplied,
                        now=TIMESTAMP,
                    )
                )

    def test_freshness_and_authority_binding_fail_closed(self):
        arguments = (
            TOKEN,
            PRINCIPAL,
            EPOCH,
            TIMESTAMP,
            REQUEST_ID,
            METHOD,
            TARGET,
            BODY,
            EXPECTED_SIGNATURE,
        )
        self.assertFalse(verify_operator_request(*arguments, now=TIMESTAMP + 301))
        self.assertFalse(verify_operator_request(*arguments, now=float("nan")))
        self.assertFalse(verify_operator_request(*arguments, now=True))
        self.assertFalse(
            verify_operator_request(*arguments, max_clock_skew=True, now=TIMESTAMP)
        )
        self.assertFalse(
            verify_operator_request(
                *arguments, expected_principal="blue-backup", now=TIMESTAMP
            )
        )
        self.assertFalse(
            verify_operator_request(
                *arguments, expected_credential_epoch=EPOCH + 1, now=TIMESTAMP
            )
        )

    def test_noncanonical_inputs_are_refused_before_signing(self):
        cases = (
            {"principal_id": "blue lead"},
            {"credential_epoch": "07"},
            {"credential_epoch": 0},
            {"request_timestamp": "1.0"},
            {"request_id": REQUEST_ID.upper()},
            {"request_id": "a" * 31},
            {"method": "post"},
            {"target": "https://controller/api/v1/dashboard"},
            {"target": "//controller/api/v1/dashboard"},
            {"target": "/api/v1/dashboard#fragment"},
            {"target": "/api/v1\\dashboard"},
            {"target": "/api/v1/%zz"},
            {"body": "not-bytes"},
        )
        defaults: dict[str, object] = {
            "principal_id": PRINCIPAL,
            "credential_epoch": EPOCH,
            "request_timestamp": TIMESTAMP,
            "request_id": REQUEST_ID,
            "method": METHOD,
            "target": TARGET,
            "body": BODY,
        }
        for change in cases:
            with self.subTest(change=change):
                parameters = {**defaults, **change}
                with self.assertRaises(ValueError):
                    operator_signature(TOKEN, **parameters)

    def test_strict_header_parser_rejects_bearer_missing_and_duplicates(self):
        headers = signed_headers()
        parsed = parse_operator_headers(headers)
        self.assertEqual(parsed.principal_id, PRINCIPAL)
        self.assertEqual(parsed.credential_epoch, EPOCH)

        legacy = dict(headers)
        legacy["X-SB-Operator"] = TOKEN
        with self.assertRaisesRegex(OperatorHeaderError, "bearer"):
            parse_operator_headers(legacy)

        missing = dict(headers)
        del missing[OPERATOR_HEADER_REQUEST_ID]
        with self.assertRaisesRegex(OperatorHeaderError, "exactly one"):
            parse_operator_headers(missing)

        duplicated = Message()
        for name, value in headers.items():
            duplicated.add_header(name, value)
        duplicated.add_header(OPERATOR_HEADER_TIMESTAMP, str(TIMESTAMP))
        with self.assertRaisesRegex(OperatorHeaderError, "exactly one"):
            parse_operator_headers(duplicated)

        noncanonical = dict(headers)
        noncanonical[OPERATOR_HEADER_EPOCH] = "07"
        with self.assertRaises(OperatorHeaderError):
            parse_operator_headers(noncanonical)

    def test_authenticated_context_is_immutable_and_has_hashed_marker(self):
        context = authenticate_operator_request(
            TOKEN,
            signed_headers(),
            METHOD,
            TARGET,
            BODY,
            expected_principal=PRINCIPAL,
            expected_credential_epoch=EPOCH,
            now=TIMESTAMP,
        )
        self.assertEqual(context.principal_id, PRINCIPAL)
        self.assertEqual(
            context.marker_sha256,
            hashlib.sha256(EXPECTED_SIGNATURE.encode("ascii")).hexdigest(),
        )
        with self.assertRaises(FrozenInstanceError):
            context.request_id = "f" * 32

        wrong = signed_headers()
        wrong[OPERATOR_HEADER_SIGNATURE] = "f" * 64
        with self.assertRaisesRegex(
            OperatorAuthenticationError, "invalid operator authentication"
        ):
            authenticate_operator_request(
                TOKEN,
                wrong,
                METHOD,
                TARGET,
                BODY,
                expected_principal=PRINCIPAL,
                expected_credential_epoch=EPOCH,
                now=TIMESTAMP,
            )


class OperatorAuthBrowserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (
            Path(__file__).parents[1]
            / "src"
            / "sentinel_blue"
            / "web"
            / "index.html"
        ).read_text(encoding="utf-8")

    def test_ui_never_persists_or_transmits_a_bearer(self):
        self.assertNotIn("sessionStorage", self.html)
        self.assertNotIn("sentinelOperatorToken", self.html)
        self.assertNotIn("/api/v1/operator/bootstrap", self.html)
        self.assertNotIn("operator_token", self.html)
        self.assertNotIn("headers.set('X-SB-Operator',", self.html)
        self.assertNotIn("extractKey", self.html)
        self.assertIn("false,['sign']", self.html)
        self.assertIn("secret=''", self.html)

    def test_ui_uses_strict_request_signing_inputs(self):
        self.assertIn("/api/v1/operator/auth-info", self.html)
        self.assertIn("globalThis.crypto.getRandomValues", self.html)
        self.assertIn("globalThis.crypto.subtle.sign('HMAC'", self.html)
        self.assertIn("OPERATOR_AUTH_DOMAIN", self.html)
        self.assertIn("url.pathname+url.search", self.html)
        self.assertIn("operatorEncoder.encode(body)", self.html)
        self.assertIn("redirect:'error'", self.html)
        for name in (
            OPERATOR_HEADER_VERSION,
            OPERATOR_HEADER_PRINCIPAL,
            OPERATOR_HEADER_EPOCH,
            OPERATOR_HEADER_TIMESTAMP,
            OPERATOR_HEADER_REQUEST_ID,
            OPERATOR_HEADER_SIGNATURE,
        ):
            self.assertIn(name, self.html)

    def test_actual_embedded_javascript_matches_fixed_python_vector(self):
        node = shutil.which("node")
        if node is None:
            self.skipTest("Node.js is unavailable for the browser signing vector")
        start = self.html.index("// BEGIN OPERATOR AUTH V1")
        end = self.html.index("// END OPERATOR AUTH V1")
        implementation = self.html[start:end]
        vector = {
            "token": TOKEN,
            "principal": PRINCIPAL,
            "epoch": EPOCH,
            "timestamp": str(TIMESTAMP),
            "request_id": REQUEST_ID,
            "method": METHOD,
            "target": TARGET,
            "body": BODY.decode("ascii"),
        }
        script = f"""
{implementation}
const vector={json.dumps(vector, separators=(',', ':'))};
(async()=>{{
  const key=await importOperatorKey(vector.token);
  const metadata={{principal_id:vector.principal,credential_epoch:vector.epoch}};
  const signature=await operatorRequestSignature(
    key,metadata,vector.timestamp,vector.request_id,vector.method,
    vector.target,operatorEncoder.encode(vector.body));
  process.stdout.write(signature);
}})().catch(error=>{{console.error(error);process.exit(1)}});
"""
        completed = subprocess.run(
            [node, "-e", script],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(completed.stdout, EXPECTED_SIGNATURE)


if __name__ == "__main__":
    unittest.main()
