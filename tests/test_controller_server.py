import socket
import socketserver
import ssl
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch
from http.client import HTTPConnection

from sentinel_blue.controller import ControllerServer, LOG, make_handler


class HealthHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def do_GET(self):  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class FakeConnection:
    def __init__(self, handshake_error=None):
        self.timeouts = []
        self.closed = False
        self.handshakes = 0
        self.handshake_error = handshake_error
        self.shutdowns = 0

    def settimeout(self, value):
        self.timeouts.append(value)

    def close(self):
        self.closed = True

    def shutdown(self, _how):
        self.shutdowns += 1

    def do_handshake(self):
        self.handshakes += 1
        if self.handshake_error is not None:
            raise self.handshake_error


class FakeTlsContext:
    def __init__(self):
        self.calls = []

    def wrap_socket(self, connection, **kwargs):
        self.calls.append((connection, kwargs))
        return connection


class ControllerServerTests(unittest.TestCase):
    def _server(self, **kwargs):
        return ControllerServer(("127.0.0.1", 0), HealthHandler, **kwargs)

    def test_source_quota_cannot_consume_global_capacity(self):
        server = self._server(max_workers=2, max_workers_per_client=1)
        try:
            first = ("192.0.2.10", 1000)
            second = ("192.0.2.11", 1001)
            third = ("192.0.2.12", 1002)
            self.assertTrue(server._acquire_worker(first))
            self.assertFalse(server._acquire_worker(first))
            self.assertTrue(server._acquire_worker(second))
            self.assertFalse(server._acquire_worker(third))
            self.assertEqual(
                server.active_connections(), {"192.0.2.10": 1, "192.0.2.11": 1}
            )
            pressure = server.connection_pressure_snapshot()
            self.assertEqual(pressure["source_quota_rejected"], 1)
            self.assertEqual(pressure["global_capacity_rejected"], 1)
            server._release_worker(first)
            self.assertTrue(server._acquire_worker(third))
            server._release_worker(second)
            server._release_worker(third)
            self.assertEqual(server.active_connections(), {})
        finally:
            server.server_close()

    def test_thread_start_failure_releases_global_and_source_permits(self):
        server = self._server(max_workers=1, max_workers_per_client=1)
        address = ("192.0.2.10", 1000)
        try:
            with patch.object(
                socketserver.ThreadingMixIn,
                "process_request",
                side_effect=RuntimeError("thread start failed"),
            ):
                with self.assertRaisesRegex(RuntimeError, "thread start failed"):
                    server.process_request(Mock(), address)
            self.assertEqual(server.active_connections(), {})
            self.assertTrue(server._acquire_worker(address))
            server._release_worker(address)
        finally:
            server.server_close()

    def test_release_without_a_client_lease_cannot_inflate_global_capacity(self):
        server = self._server(max_workers=2, max_workers_per_client=1)
        first = ("192.0.2.10", 1000)
        second = ("192.0.2.11", 1001)
        third = ("192.0.2.12", 1002)
        try:
            self.assertTrue(server._acquire_worker(first))
            with patch.object(LOG, "error") as error_log:
                server._release_worker(second)
            error_log.assert_called_once()
            self.assertTrue(server._acquire_worker(second))
            self.assertFalse(server._acquire_worker(third))
            server._release_worker(first)
            server._release_worker(second)
        finally:
            server.server_close()

    def test_tls_handshake_is_deferred_until_worker_processing(self):
        server = self._server(tls_handshake_timeout=2.5)
        connection = FakeConnection()
        context = FakeTlsContext()
        server.enable_tls(context)
        try:
            with patch.object(
                ThreadingHTTPServer,
                "get_request",
                return_value=(connection, ("192.0.2.10", 1000)),
            ):
                returned, address = server.get_request()
            self.assertIs(returned, connection)
            self.assertEqual(address, ("192.0.2.10", 1000))
            self.assertEqual(connection.timeouts, [2.5])
            self.assertEqual(
                context.calls,
                [
                    (
                        connection,
                        {"server_side": True, "do_handshake_on_connect": False},
                    )
                ],
            )
        finally:
            server.server_close()

    def test_exact_source_gate_rejects_before_tls_or_worker_admission(self):
        profile = Mock(
            requires_strict_transport=True,
            controller_ingress_hosts=("192.0.2.10",),
        )
        server = self._server(event_profile=profile)
        connection = FakeConnection()
        context = FakeTlsContext()
        server.enable_tls(context)
        try:
            with patch.object(
                ThreadingHTTPServer,
                "get_request",
                return_value=(connection, ("192.0.2.11", 1000)),
            ):
                with self.assertRaises(ConnectionAbortedError):
                    server.get_request()
            self.assertTrue(connection.closed)
            self.assertEqual(context.calls, [])
            self.assertEqual(server.active_connections(), {})
            self.assertEqual(
                server.connection_pressure_snapshot()["source_scope_rejected"], 1
            )
        finally:
            server.server_close()

    def test_source_gate_normalizes_v4_mapped_and_allows_loopback_admin(self):
        profile = Mock(
            requires_strict_transport=True,
            controller_ingress_hosts=("192.0.2.10",),
        )
        server = self._server(event_profile=profile)
        try:
            for source in ("::ffff:192.0.2.10", "::ffff:127.0.0.1"):
                connection = FakeConnection()
                with patch.object(
                    ThreadingHTTPServer,
                    "get_request",
                    return_value=(connection, (source, 1000)),
                ):
                    returned, address = server.get_request()
                self.assertIs(returned, connection)
                self.assertEqual(server._client_key(address), source.removeprefix("::ffff:"))
                self.assertFalse(connection.closed)
        finally:
            server.server_close()

    def test_tls_worker_completes_handshake_then_switches_timeout_and_releases(self):
        server = self._server(max_workers=1, max_workers_per_client=1, request_timeout=4.0)
        server.enable_tls(FakeTlsContext())
        address = ("192.0.2.10", 1000)
        connection = FakeConnection()
        try:
            self.assertTrue(server._acquire_worker(address))
            with (
                patch.object(server, "finish_request") as finish,
                patch.object(server, "shutdown_request") as shutdown,
            ):
                server.process_request_thread(connection, address)
            self.assertEqual(connection.handshakes, 1)
            self.assertEqual(connection.timeouts, [4.0])
            finish.assert_called_once_with(connection, address)
            shutdown.assert_called_once_with(connection)
            self.assertEqual(server.active_connections(), {})
            self.assertTrue(server._acquire_worker(address))
            server._release_worker(address)
        finally:
            server.server_close()

    def test_tls_handshake_failure_is_counted_and_releases_capacity(self):
        server = self._server(max_workers=1, max_workers_per_client=1)
        server.enable_tls(FakeTlsContext())
        address = ("192.0.2.10", 1000)
        connection = FakeConnection(ssl.SSLError("incomplete handshake"))
        try:
            self.assertTrue(server._acquire_worker(address))
            with patch.object(server, "shutdown_request") as shutdown:
                server.process_request_thread(connection, address)
            shutdown.assert_called_once_with(connection)
            self.assertEqual(server.active_connections(), {})
            self.assertEqual(server.connection_pressure_snapshot()["SSLError"], 1)
            self.assertTrue(server._acquire_worker(address))
            server._release_worker(address)
        finally:
            server.server_close()

    def test_fast_request_cancels_absolute_deadline_without_late_shutdown(self):
        server = self._server(
            max_workers=1,
            max_workers_per_client=1,
            request_timeout=0.1,
        )
        address = ("192.0.2.10", 1000)
        connection = FakeConnection()
        try:
            self.assertTrue(server._acquire_worker(address))
            with (
                patch.object(server, "finish_request") as finish,
                patch.object(server, "shutdown_request") as shutdown,
            ):
                server.process_request_thread(connection, address)
            time.sleep(0.15)
            finish.assert_called_once_with(connection, address)
            shutdown.assert_called_once_with(connection)
            self.assertEqual(connection.shutdowns, 0)
            self.assertNotIn(
                "request_deadline", server.connection_pressure_snapshot()
            )
            self.assertEqual(server.active_connections(), {})
        finally:
            server.server_close()

    def test_deadline_callback_finishes_before_socket_close_and_permit_release(self):
        server = self._server(
            max_workers=1,
            max_workers_per_client=1,
            request_timeout=0.1,
        )
        address = ("192.0.2.10", 1000)
        connection = FakeConnection()
        shutdown_entered = threading.Event()
        release_shutdown = threading.Event()

        def blocking_shutdown(_how):
            shutdown_entered.set()
            release_shutdown.wait(1.0)

        connection.shutdown = blocking_shutdown
        try:
            self.assertTrue(server._acquire_worker(address))
            with (
                patch.object(server, "finish_request", side_effect=lambda *_: time.sleep(0.12)),
                patch.object(server, "shutdown_request") as shutdown_request,
            ):
                worker = threading.Thread(
                    target=server.process_request_thread,
                    args=(connection, address),
                )
                worker.start()
                self.assertTrue(shutdown_entered.wait(0.5))
                time.sleep(0.05)
                shutdown_request.assert_not_called()
                self.assertEqual(server.active_connections().get("192.0.2.10"), 1)
                release_shutdown.set()
                worker.join(timeout=1.0)
                self.assertFalse(worker.is_alive())
                shutdown_request.assert_called_once_with(connection)
            self.assertEqual(server.active_connections(), {})
            self.assertEqual(
                server.connection_pressure_snapshot().get("request_deadline"), 1
            )
        finally:
            release_shutdown.set()
            server.server_close()

    def test_deadline_thread_start_failure_still_closes_and_releases(self):
        server = self._server(max_workers=1, max_workers_per_client=1)
        address = ("192.0.2.10", 1000)
        connection = FakeConnection()
        try:
            self.assertTrue(server._acquire_worker(address))
            with (
                patch("sentinel_blue.controller.threading.Timer") as timer_type,
                patch.object(server, "handle_error") as handle_error,
                patch.object(server, "shutdown_request") as shutdown_request,
            ):
                timer_type.return_value.start.side_effect = RuntimeError(
                    "thread unavailable"
                )
                server.process_request_thread(connection, address)
            handle_error.assert_called_once_with(connection, address)
            shutdown_request.assert_called_once_with(connection)
            timer_type.return_value.cancel.assert_not_called()
            self.assertEqual(server.active_connections(), {})
        finally:
            server.server_close()

    def test_expected_connection_errors_emit_no_traceback_log(self):
        server = self._server()
        try:
            with patch.object(LOG, "error") as error_log:
                try:
                    raise ConnectionResetError("peer reset")
                except ConnectionResetError:
                    server.handle_error(Mock(), ("192.0.2.10", 1000))
            error_log.assert_not_called()
        finally:
            server.server_close()

    def test_unexpected_failures_are_rate_limited(self):
        server = self._server()
        try:
            with patch("sentinel_blue.controller.time.monotonic", side_effect=[100.0, 101.0]):
                with patch.object(LOG, "error") as error_log:
                    for _ in range(2):
                        try:
                            raise RuntimeError("internal failure")
                        except RuntimeError:
                            server.handle_error(Mock(), ("192.0.2.10", 1000))
            error_log.assert_called_once()
            self.assertEqual(sum(server._suppressed_error_logs.values()), 1)
        finally:
            server.server_close()

    def test_unexpected_failures_with_different_keys_are_not_cross_suppressed(self):
        server = self._server()
        try:
            with patch("sentinel_blue.controller.time.monotonic", return_value=100.0):
                with patch.object(LOG, "error") as error_log:
                    for error, address in (
                        (RuntimeError("first"), ("192.0.2.10", 1)),
                        (RuntimeError("second source"), ("192.0.2.11", 1)),
                        (ValueError("different type"), ("192.0.2.10", 1)),
                    ):
                        try:
                            raise error
                        except Exception:
                            server.handle_error(Mock(), address)
            self.assertEqual(error_log.call_count, 3)
        finally:
            server.server_close()

    def test_production_handler_counts_request_line_and_post_timeouts_without_logs(self):
        server = self._server()
        handler_type = make_handler(Mock())
        handler = object.__new__(handler_type)
        handler.server = server
        handler.path = "/api/v1/agent/telemetry"
        try:
            with (patch.object(LOG, "info") as info, patch.object(LOG, "error") as error):
                handler.log_error("Request timed out: %r", TimeoutError("slow request"))
                with patch.object(handler, "_read_body", side_effect=TimeoutError("slow body")):
                    handler.do_POST()
            pressure = server.connection_pressure_snapshot()
            self.assertEqual(pressure["request_timeout"], 1)
            self.assertEqual(pressure["TimeoutError"], 1)
            info.assert_not_called()
            error.assert_not_called()
        finally:
            server.server_close()

    def test_production_handler_uses_one_request_per_deadline_and_bounds_protocol_logs(self):
        server = self._server()
        handler_type = make_handler(Mock())
        handler = object.__new__(handler_type)
        handler.server = server
        try:
            self.assertEqual(handler_type.protocol_version, "HTTP/1.0")
            with (patch.object(LOG, "info") as info, patch.object(LOG, "error") as error):
                for _ in range(20):
                    handler.log_error("code %d, message %s", 400, "bad request")
            self.assertEqual(
                server.connection_pressure_snapshot()["http_protocol_error"], 20
            )
            info.assert_not_called()
            error.assert_not_called()
        finally:
            server.server_close()

    def test_production_handler_sanitizes_and_bounds_access_log_text(self):
        server = self._server()
        handler_type = make_handler(Mock())
        handler = object.__new__(handler_type)
        handler.server = server
        handler.client_address = ("192.0.2.10", 1000)
        try:
            with patch.object(LOG, "debug") as debug:
                handler.log_message('"%s"', "bad\r\nline\x1b" + "x" * 4096)
            rendered = debug.call_args.args[2]
            self.assertNotIn("\r", rendered)
            self.assertNotIn("\n", rendered)
            self.assertNotIn("\x1b", rendered)
            self.assertIn("\\x0d\\x0aline\\x1b", rendered)
            self.assertLessEqual(len(rendered), 2048)
        finally:
            server.server_close()

    def test_unexpected_post_failures_use_rate_limited_server_logging(self):
        server = self._server()
        handler_type = make_handler(Mock())
        handler = object.__new__(handler_type)
        handler.server = server
        handler.connection = Mock()
        handler.client_address = ("192.0.2.10", 1000)
        try:
            with (
                patch.object(handler, "_read_body", side_effect=RuntimeError("failure")),
                patch.object(handler, "_json"),
                patch("sentinel_blue.controller.time.monotonic", return_value=100.0),
                patch.object(LOG, "error") as error_log,
            ):
                handler.do_POST()
                handler.do_POST()
            error_log.assert_called_once()
            self.assertEqual(sum(server._suppressed_error_logs.values()), 1)
        finally:
            server.server_close()

    def test_absolute_request_deadline_stops_byte_drip_and_recovers_capacity(self):
        server = self._server(
            max_workers=3,
            max_workers_per_client=1,
            request_timeout=0.15,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        dripper = socket.socket()
        dripper.settimeout(1.0)
        dripper.bind(("127.0.0.2", 0))
        dripper.connect(("127.0.0.1", server.server_port))
        stop = threading.Event()

        def drip() -> None:
            while not stop.is_set():
                try:
                    dripper.sendall(b"G")
                except OSError:
                    return
                time.sleep(0.03)

        drip_thread = threading.Thread(target=drip, daemon=True)
        try:
            with patch.object(LOG, "error") as error_log:
                drip_thread.start()
                deadline = time.monotonic() + 1.5
                while (
                    server.connection_pressure_snapshot().get("request_deadline", 0) < 1
                    and time.monotonic() < deadline
                ):
                    time.sleep(0.01)
                self.assertEqual(
                    server.connection_pressure_snapshot().get("request_deadline"), 1
                )
                deadline = time.monotonic() + 1.0
                while server.active_connections() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertEqual(server.active_connections(), {})

                connection = HTTPConnection(
                    "127.0.0.1",
                    server.server_port,
                    timeout=1.0,
                    source_address=("127.0.0.1", 0),
                )
                try:
                    connection.request("GET", "/health")
                    response = connection.getresponse()
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b"ok")
                finally:
                    connection.close()
            error_log.assert_not_called()
            self.assertNotIn(
                "http_protocol_error", server.connection_pressure_snapshot()
            )
        finally:
            stop.set()
            dripper.close()
            drip_thread.join(timeout=1)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_source_saturation_preserves_other_source_health(self):
        server = self._server(
            max_workers=8,
            max_workers_per_client=2,
            request_timeout=2.0,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        held = []
        try:
            for _ in range(6):
                connection = socket.socket()
                connection.settimeout(1.0)
                connection.bind(("127.0.0.2", 0))
                connection.connect(("127.0.0.1", server.server_port))
                connection.sendall(b"G")
                held.append(connection)
            deadline = time.monotonic() + 1.0
            while (
                server.active_connections().get("127.0.0.2", 0) < 2
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            self.assertEqual(server.active_connections().get("127.0.0.2", 0), 2)
            connection = HTTPConnection(
                "127.0.0.1",
                server.server_port,
                timeout=1.0,
                source_address=("127.0.0.1", 0),
            )
            try:
                connection.request("GET", "/health")
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.read(), b"ok")
            finally:
                connection.close()
        finally:
            for connection in held:
                connection.close()
            deadline = time.monotonic() + 3.0
            while server.active_connections() and time.monotonic() < deadline:
                time.sleep(0.01)
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
        self.assertEqual(server.active_connections(), {})


if __name__ == "__main__":
    unittest.main()
