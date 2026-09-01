import io
import json
import os
import secrets
import socket
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from sentinel_blue import __version__
from sentinel_blue.agent import (
    MAX_CONTROLLER_RESPONSE_BYTES,
    MAX_VERIFIED_ERROR_LENGTH,
    AgentClient,
)
from sentinel_blue.auth import response_signature, signature, unwrap_enrollment_token
from sentinel_blue.controller import ControllerApp, ControllerServer, make_handler
from sentinel_blue.operator_auth import (
    OPERATOR_AUTH_VERSION,
    OPERATOR_HEADER_EPOCH,
    OPERATOR_HEADER_PRINCIPAL,
    OPERATOR_HEADER_REQUEST_ID,
    OPERATOR_HEADER_SIGNATURE,
    OPERATOR_HEADER_TIMESTAMP,
    OPERATOR_HEADER_VERSION,
    operator_signature,
)
from sentinel_blue.store import Store


class HttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = Store(Path(self.directory.name) / "http.db")
        self.app = ControllerApp(
            self.store, "b" * 32, operator_token="o" * 32
        )
        self.operator_token = self.app.operator_token
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

    def _raw_request_status(self, request: bytes, timeout: float = 1.0) -> int:
        connection = socket.create_connection(
            ("127.0.0.1", self.server.server_port), timeout=timeout
        )
        connection.settimeout(timeout)
        try:
            connection.sendall(request)
            response = b""
            while b"\r\n" not in response:
                chunk = connection.recv(4096)
                if not chunk:
                    break
                response += chunk
        finally:
            connection.close()
        return int(response.split(b" ", 2)[1])

    def _operator_headers(
        self,
        method: str,
        path: str,
        body: bytes = b"",
        *,
        request_id: str | None = None,
        timestamp: int | None = None,
    ) -> dict[str, str]:
        timestamp = int(time.time()) if timestamp is None else timestamp
        request_id = request_id or secrets.token_hex(16)
        return {
            OPERATOR_HEADER_VERSION: OPERATOR_AUTH_VERSION,
            OPERATOR_HEADER_PRINCIPAL: self.app.operator_principal_id,
            OPERATOR_HEADER_EPOCH: str(self.app.operator_credential_epoch),
            OPERATOR_HEADER_TIMESTAMP: str(timestamp),
            OPERATOR_HEADER_REQUEST_ID: request_id,
            OPERATOR_HEADER_SIGNATURE: operator_signature(
                self.operator_token,
                self.app.operator_principal_id,
                self.app.operator_credential_epoch,
                timestamp,
                request_id,
                method,
                path,
                body,
            ),
        }

    def test_health_is_constant_and_readiness_refreshes_integrity_async(self):
        with patch.object(
            self.store,
            "integrity_check",
            side_effect=AssertionError("liveness must not touch SQLite"),
        ) as integrity:
            with urlopen(f"{self.url}/api/v1/health") as response:
                payload = json.loads(response.read())
            self.assertEqual(payload, {"status": "ok", "version": __version__})
        integrity.assert_not_called()

        with patch.object(self.store, "integrity_check", return_value="ok") as integrity:
            with self.assertRaises(HTTPError) as initial:
                urlopen(f"{self.url}/api/v1/readiness")
            self.assertEqual(initial.exception.code, 503)
            deadline = time.monotonic() + 1.0
            while self.app._integrity_refreshing and time.monotonic() < deadline:
                time.sleep(0.01)
            with urlopen(f"{self.url}/api/v1/readiness") as response:
                ready = json.loads(response.read())
        self.assertTrue(ready["ready"])
        self.assertEqual(ready["database"], "ok")
        integrity.assert_called_once()

    def test_readiness_returns_503_for_unhealthy_cached_integrity(self):
        with patch.object(self.store, "integrity_check", return_value="corrupt"):
            with self.assertRaises(HTTPError):
                urlopen(f"{self.url}/api/v1/readiness")
            deadline = time.monotonic() + 1.0
            while self.app._integrity_refreshing and time.monotonic() < deadline:
                time.sleep(0.01)
            with self.assertRaises(HTTPError) as unhealthy:
                urlopen(f"{self.url}/api/v1/readiness")
        self.assertEqual(unhealthy.exception.code, 503)
        payload = json.loads(unhealthy.exception.read())
        self.assertFalse(payload["ready"])
        self.assertEqual(payload["database"], "corrupt")

    def test_post_framing_rejects_ambiguous_or_encoded_bodies_pre_auth(self):
        base = b"POST /api/v1/agent/enroll HTTP/1.0\r\nHost: localhost\r\n"
        cases = (
            b"Content-Type: application/json\r\n\r\n",
            b"Content-Type: application/json\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",
            b"Content-Type: application/json\r\nContent-Length: 00\r\n\r\n",
            b"Content-Type: application/json\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"Content-Type: application/json\r\nContent-Length: 0\r\nContent-Encoding: gzip\r\n\r\n",
            b"Content-Type: text/plain\r\nContent-Length: 0\r\n\r\n",
            b"Content-Type: application/json\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
        )
        for headers in cases:
            with self.subTest(headers=headers):
                self.assertEqual(self._raw_request_status(base + headers), 400)

    def test_agent_authentication_rejects_duplicate_signing_headers(self):
        path = "/api/v1/agent/enroll"
        for index, duplicate_name in enumerate(
            ("X-SB-Agent", "X-SB-Timestamp", "X-SB-Signature")
        ):
            agent_id = f"duplicate-header-agent-{index}"
            body = json.dumps(
                {
                    "agent_id": agent_id,
                    "hostname": "duplicate-header-host",
                    "platform": "test",
                },
                separators=(",", ":"),
            ).encode()
            timestamp = str(time.time())
            request_signature = signature(
                "b" * 32,
                timestamp,
                "POST",
                path,
                body,
            )
            signing_headers = [
                ("X-SB-Agent", agent_id),
                ("X-SB-Timestamp", timestamp),
                ("X-SB-Signature", request_signature),
            ]
            duplicated = next(
                value for name, value in signing_headers if name == duplicate_name
            )
            request = (
                f"POST {path} HTTP/1.0\r\n"
                "Host: localhost\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {len(body)}\r\n"
                + "".join(f"{name}: {value}\r\n" for name, value in signing_headers)
                + f"{duplicate_name}: {duplicated}\r\n\r\n"
            ).encode("ascii") + body
            with self.subTest(header=duplicate_name):
                self.assertEqual(self._raw_request_status(request), 401)
                self.assertFalse(self.store.agent_exists(agent_id))

    def test_route_caps_are_enforced_before_authentication_or_body_read(self):
        cases = (
            ("/api/v1/agent/enroll", 16 * 1024 + 1),
            ("/api/v1/agent/telemetry", 2_000_001),
            ("/api/v1/agent/result", 600_001),
            ("/api/v1/protected-accounts/import", 1_500_001),
            ("/api/v1/change-grants", 16 * 1024 + 1),
            ("/api/v1/governance/emergency-stop", 1025),
        )
        for path, length in cases:
            request = (
                f"POST {path} HTTP/1.0\r\n"
                "Host: localhost\r\n"
                "Content-Type: application/json\r\n"
                f"Content-Length: {length}\r\n\r\n"
            ).encode("ascii")
            with self.subTest(path=path):
                self.assertEqual(self._raw_request_status(request), 400)

    def test_unknown_post_returns_404_without_waiting_for_declared_body(self):
        request = (
            b"POST /api/v1/not-a-route HTTP/1.0\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 2000000\r\n\r\n"
        )
        started = time.monotonic()
        self.assertEqual(self._raw_request_status(request, timeout=0.5), 404)
        self.assertLess(time.monotonic() - started, 0.5)

    def test_signed_agent_telemetry_and_dashboard(self):
        client = AgentClient(self.url, "b" * 32, "integration-agent")
        telemetry = {
            "agent_id": "integration-agent",
            "hostname": "integration-host",
            "platform": "Linux test",
            "observed_at": time.time(),
            "accounts": [{"name": "root", "account_id": "0", "privileged": True, "enabled": True}],
            "sessions": [],
            "services": [{"name": "web", "state": "running"}],
            "interfaces": [],
            "collector_errors": [],
        }
        client.enroll("integration-host", "Linux test")
        self.assertEqual(client.token, "")
        client.telemetry(telemetry)
        request = Request(
            f"{self.url}/api/v1/dashboard",
            headers=self._operator_headers("GET", "/api/v1/dashboard"),
        )
        with urlopen(request) as response:
            dashboard = json.loads(response.read())
        self.assertEqual(dashboard["agents"][0]["hostname"], "integration-host")
        self.assertEqual(client.actions(), [])

    def test_operator_requests_are_single_use_and_legacy_bearers_are_refused(self):
        path = "/api/v1/dashboard"
        headers = self._operator_headers(
            "GET", path, request_id="1" * 32
        )
        with urlopen(Request(self.url + path, headers=headers)) as response:
            self.assertEqual(response.status, 200)
        with self.assertRaises(HTTPError) as replayed:
            urlopen(Request(self.url + path, headers=headers))
        self.assertEqual(replayed.exception.code, 409)
        with self.assertRaises(HTTPError) as legacy:
            urlopen(
                Request(
                    self.url + path,
                    headers={"X-SB-Operator": self.operator_token},
                )
            )
        self.assertEqual(legacy.exception.code, 401)

    def test_operator_replay_storage_failure_precedes_endpoint_effects(self):
        path = "/api/v1/governance/mode"
        body = b'{"mode":"observe"}'
        request = Request(
            self.url + path,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                **self._operator_headers("POST", path, body),
            },
        )
        with patch.object(
            self.store,
            "admit_operator_request",
            side_effect=sqlite3.OperationalError("disk unavailable"),
        ), patch.object(self.app, "set_autonomy_mode") as mutate:
            with self.assertRaises(HTTPError) as rejected:
                urlopen(request)
        self.assertEqual(rejected.exception.code, 503)
        mutate.assert_not_called()

    def test_enrollment_wire_response_wraps_the_agent_credential(self):
        agent_id = "wire-enrollment-agent"
        body = json.dumps(
            {"agent_id": agent_id, "hostname": "wire-host", "platform": "test"},
            separators=(",", ":"),
        ).encode()
        timestamp = str(time.time())
        request_signature = signature(
            "b" * 32, timestamp, "POST", "/api/v1/agent/enroll", body
        )
        request = Request(
            f"{self.url}/api/v1/agent/enroll",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-SB-Agent": agent_id,
                "X-SB-Timestamp": timestamp,
                "X-SB-Signature": request_signature,
            },
        )
        with urlopen(request) as response:
            payload = json.loads(response.read())
        self.assertNotIn("agent_token", payload)
        token = unwrap_enrollment_token(
            "b" * 32, request_signature, payload["agent_token_wrapped"]
        )
        self.assertEqual(token, self.store.agent_secret(agent_id))

    def test_exact_enrollment_replay_is_rejected_but_fresh_retry_is_idempotent(self):
        agent_id = "restart-replay-agent"
        path = "/api/v1/agent/enroll"
        body = json.dumps(
            {"agent_id": agent_id, "hostname": "replay-host", "platform": "test"},
            separators=(",", ":"),
        ).encode()
        def enrollment_request(timestamp: str, request_signature: str) -> Request:
            return Request(
                self.url + path,
                data=body,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "X-SB-Agent": agent_id,
                    "X-SB-Timestamp": timestamp,
                    "X-SB-Signature": request_signature,
                },
            )

        timestamp = str(time.time())
        request_signature = signature("b" * 32, timestamp, "POST", path, body)
        with urlopen(enrollment_request(timestamp, request_signature)) as response:
            self.assertEqual(response.status, 201)
        original_secret = self.store.agent_secret(agent_id)
        action_id = self.store.queue_action(agent_id, "snapshot", {})

        database = Path(self.directory.name) / "http.db"
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.store.close()
        self.store = Store(database)
        self.app = ControllerApp(
            self.store, "b" * 32, operator_token="o" * 32
        )
        self.server = ControllerServer(("127.0.0.1", 0), make_handler(self.app))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

        with self.assertRaises(HTTPError) as replayed:
            urlopen(enrollment_request(timestamp, request_signature))
        self.assertEqual(replayed.exception.code, 401)

        retry_timestamp = str(time.time())
        retry_signature = signature(
            "b" * 32, retry_timestamp, "POST", path, body
        )
        with urlopen(
            enrollment_request(retry_timestamp, retry_signature)
        ) as response:
            self.assertEqual(response.status, 201)
            self.assertTrue(response.headers.get("X-SB-Response-Signature"))
        self.assertEqual(self.store.agent_secret(agent_id), original_secret)
        self.assertEqual(self.store.get_action(action_id)["status"], "queued")

    def test_exact_steady_state_request_is_rejected_after_restart(self):
        agent_id = "steady-replay-agent"
        client = AgentClient(self.url, "b" * 32, agent_id)
        agent_token = client.enroll("steady-host", "Linux")
        path = f"/api/v1/agent/actions?agent_id={agent_id}"
        timestamp = str(time.time())
        request_signature = signature(agent_token, timestamp, "GET", path, b"")

        def action_request(request_time: str, request_hmac: str) -> Request:
            return Request(
                self.url + path,
                headers={
                    "X-SB-Agent": agent_id,
                    "X-SB-Timestamp": request_time,
                    "X-SB-Signature": request_hmac,
                },
            )

        with urlopen(action_request(timestamp, request_signature)) as response:
            self.assertEqual(response.status, 200)

        database = Path(self.directory.name) / "http.db"
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.store.close()
        self.store = Store(database)
        self.app = ControllerApp(
            self.store, "b" * 32, operator_token="o" * 32
        )
        self.server = ControllerServer(("127.0.0.1", 0), make_handler(self.app))
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.url = f"http://127.0.0.1:{self.server.server_port}"

        with self.assertRaises(HTTPError) as replayed:
            urlopen(action_request(timestamp, request_signature))
        self.assertEqual(replayed.exception.code, 401)

        fresh_timestamp = str(time.time())
        fresh_signature = signature(
            agent_token, fresh_timestamp, "GET", path, b""
        )
        with urlopen(
            action_request(fresh_timestamp, fresh_signature)
        ) as response:
            self.assertEqual(response.status, 200)

    def test_nonfinite_signed_enrollment_timestamp_is_rejected_without_state_change(self):
        agent_id = "nonfinite-enrollment-agent"
        body = json.dumps(
            {"agent_id": agent_id, "hostname": "wire-host", "platform": "test"},
            separators=(",", ":"),
        ).encode()
        timestamp = "nan"
        request_signature = signature(
            "b" * 32, timestamp, "POST", "/api/v1/agent/enroll", body
        )
        request = Request(
            f"{self.url}/api/v1/agent/enroll",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-SB-Agent": agent_id,
                "X-SB-Timestamp": timestamp,
                "X-SB-Signature": request_signature,
            },
        )
        with self.assertRaises(HTTPError) as raised:
            urlopen(request)
        self.assertEqual(raised.exception.code, 401)
        self.assertFalse(self.store.agent_exists(agent_id))

    def test_agent_rejects_unsigned_controller_response(self):
        class UnsignedResponse:
            headers: dict[str, str] = {}
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, *_args):
                return b'{"actions":[]}'

        client = AgentClient(self.url, "b" * 32, "integration-agent", agent_token="c" * 64)
        with patch.object(client.opener, "open", return_value=UnsignedResponse()):
            with self.assertRaisesRegex(ValueError, "response signature"):
                client.actions()

    def test_agent_rejects_signed_error_relabelled_as_success(self):
        class RelabelledResponse:
            status = 200

            def __init__(self, headers, body):
                self.headers = headers
                self.body = body

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, *_args):
                return self.body

        token = "c" * 64
        path = "/api/v1/agent/actions?agent_id=integration-agent"
        body = b'{"error":"rejected"}'
        now = 1_800_000_000.0
        timestamp = str(now)
        request_signature = signature(token, timestamp, "GET", path, b"")
        headers = {
            "Content-Length": str(len(body)),
            "X-SB-Response-Version": "2",
            "X-SB-Response-Timestamp": timestamp,
            "X-SB-Response-Signature": response_signature(
                token, timestamp, 400, path, request_signature, body
            ),
        }
        client = AgentClient(self.url, "b" * 32, "integration-agent", agent_token=token)
        with patch("sentinel_blue.agent.time.time", return_value=now):
            with patch.object(
                client.opener,
                "open",
                return_value=RelabelledResponse(headers, body),
            ):
                with self.assertRaisesRegex(ValueError, "response signature"):
                    client.actions()

    def test_agent_rejects_oversized_controller_response_before_json_decode(self):
        class OversizedResponse:
            status = 200
            headers: dict[str, str] = {}

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, limit):
                return b"x" * limit

        client = AgentClient(self.url, "b" * 32, "integration-agent", agent_token="c" * 64)
        with patch.object(client.opener, "open", return_value=OversizedResponse()):
            with self.assertRaisesRegex(ValueError, "exceeds the size limit"):
                client.actions()
        self.assertEqual(MAX_CONTROLLER_RESPONSE_BYTES, 2_000_000)

    def test_agent_rejects_unsigned_error_response(self):
        client = AgentClient(self.url, "b" * 32, "integration-agent", agent_token="c" * 64)
        error = HTTPError(
            f"{self.url}/api/v1/agent/actions",
            400,
            "bad",
            {},
            io.BytesIO(b'{"error":"fake"}'),
        )
        with patch.object(client.opener, "open", side_effect=error):
            with self.assertRaisesRegex(ValueError, "response signature"):
                client.actions()
        self.assertFalse(hasattr(error, "sentinel_blue_error"))

    def test_agent_exposes_only_bounded_authenticated_error_detail(self):
        client = AgentClient(self.url, "b" * 32, "integration-agent", agent_token="c" * 64)
        path = "/api/v1/agent/actions?agent_id=integration-agent"
        body = json.dumps({"error": "bad\u0000\r\n\t\u2028" + ("x" * 400)}).encode()
        now = 1_800_000_001.0
        timestamp = str(now)
        request_signature = signature("c" * 64, timestamp, "GET", path, b"")
        headers = {
            "Content-Length": str(len(body)),
            "X-SB-Response-Version": "2",
            "X-SB-Response-Timestamp": timestamp,
            "X-SB-Response-Signature": response_signature(
                "c" * 64, timestamp, 400, path, request_signature, body
            ),
        }
        error = HTTPError(f"{self.url}{path}", 400, "bad", headers, io.BytesIO(body))
        with patch("sentinel_blue.agent.time.time", return_value=now):
            with patch.object(client.opener, "open", side_effect=error):
                with self.assertRaises(HTTPError) as raised:
                    client.actions()
        self.assertTrue(raised.exception.sentinel_blue_verified)
        self.assertEqual(len(raised.exception.sentinel_blue_error), MAX_VERIFIED_ERROR_LENGTH)
        for control in ("\x00", "\r", "\n", "\t", "\u2028"):
            self.assertNotIn(control, raised.exception.sentinel_blue_error)

    def test_agent_result_keeps_queue_action_id_authoritative(self):
        client = AgentClient(self.url, "b" * 32, "integration-agent", agent_token="c" * 64)
        with patch.object(client, "_request", return_value={}) as request:
            client.result("queue-issued", {"action_id": "untrusted", "success": True})
        request.assert_called_once_with(
            "POST",
            "/api/v1/agent/result",
            {"action_id": "queue-issued", "success": True},
        )

    def test_authenticated_validation_error_is_signed(self):
        client = AgentClient(self.url, "b" * 32, "integration-agent")
        client.enroll("integration-host", "Linux test")
        with self.assertRaises(HTTPError) as raised:
            client.telemetry({"agent_id": "integration-agent"})
        self.assertEqual(raised.exception.code, 400)
        self.assertTrue(getattr(raised.exception, "sentinel_blue_verified", False))
        self.assertEqual(
            raised.exception.sentinel_blue_error,
            "observed_at must be numeric",
        )

    def test_agent_refuses_redirectable_or_credentialed_controller_urls(self):
        for url in (
            "http://user:password@127.0.0.1:8765",
            "http://127.0.0.1:8765/controller",
            "http://127.0.0.1:8765?next=elsewhere",
            "http://bad'host:8765",
            "http://bad;host:8765",
            "http://127.0.0.1:99999",
        ):
            with self.assertRaises(ValueError):
                AgentClient(url, "b" * 32, "integration-agent")

    def test_agent_ignores_environment_proxy_for_controller_secrets(self):
        with patch.dict(
            os.environ,
            {"HTTP_PROXY": "http://127.0.0.1:1", "http_proxy": "http://127.0.0.1:1", "NO_PROXY": ""},
        ):
            client = AgentClient(self.url, "b" * 32, "proxy-test-agent")
            token = client.enroll("proxy-test-host", "Linux")
        self.assertTrue(token)


if __name__ == "__main__":
    unittest.main()
