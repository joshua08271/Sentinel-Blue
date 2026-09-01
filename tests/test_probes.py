import socketserver
import struct
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

from sentinel_blue.probes import run_probe, run_probes
from sentinel_blue.protocol import ProbeResult


class QuietHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"sentinel healthy")

    def log_message(self, *_args):
        pass


class RedirectHandler(BaseHTTPRequestHandler):
    followed = 0

    def do_GET(self):  # noqa: N802
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/must-not-follow")
            self.end_headers()
            return
        type(self).followed += 1
        self.send_response(200)
        self.end_headers()

    def log_message(self, *_args):
        pass


class ProbeTests(unittest.TestCase):
    def test_probe_batch_is_bounded_parallel_and_ordered(self):
        specs = [{"name": f"probe-{index}"} for index in range(20)]

        def fixture(spec, _networks, **_scope):
            time.sleep(0.02)
            return ProbeResult(spec["name"], "fixture", True)

        started = time.perf_counter()
        with patch("sentinel_blue.probes.run_probe", side_effect=fixture) as runner:
            results = run_probes(
                specs,
                ["203.0.113.0/24"],
                authorized_hosts=["203.0.113.7"],
                excluded_hosts=["203.0.113.99"],
            )
        duration = time.perf_counter() - started
        self.assertEqual([item.name for item in results], [item["name"] for item in specs])
        self.assertLess(duration, 0.25)
        self.assertTrue(
            all(
                item.kwargs
                == {
                    "authorized_hosts": ["203.0.113.7"],
                    "excluded_hosts": ["203.0.113.99"],
                }
                for item in runner.call_args_list
            )
        )

    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), QuietHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_http_probe(self):
        result = run_probe(
            {
                "name": "local-test",
                "kind": "http",
                "target": f"http://127.0.0.1:{self.server.server_port}/health",
                "expected_status": [200],
            },
            [],
        )
        self.assertTrue(result.healthy)

    def test_http_expected_body(self):
        result = run_probe(
            {
                "name": "local-body",
                "kind": "http",
                "target": f"http://127.0.0.1:{self.server.server_port}/health",
                "expected_status": [200],
                "expected_body": "sentinel healthy",
            },
            [],
        )
        self.assertTrue(result.healthy)

    def test_banner_and_dns_application_probes(self):
        class BannerHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(b"220 test smtp ready\r\n")
                self.request.recv(1024)
                self.request.sendall(b"250 hel")
                time.sleep(0.01)
                self.request.sendall(b"lo sentinel-blue\r\n")

        class DnsHandler(socketserver.BaseRequestHandler):
            def handle(self):
                request, sock = self.request
                transaction = request[:2]
                response = (
                    transaction
                    + struct.pack("!HHHHH", 0x8180, 1, 1, 0, 0)
                    + request[12:]
                    + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
                )
                sock.sendto(response, self.client_address)

        banner = socketserver.ThreadingTCPServer(("127.0.0.1", 0), BannerHandler)
        dns = socketserver.ThreadingUDPServer(("127.0.0.1", 0), DnsHandler)
        threads = [
            threading.Thread(target=banner.serve_forever, daemon=True),
            threading.Thread(target=dns.serve_forever, daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            smtp_result = run_probe(
                {
                    "name": "smtp",
                    "kind": "smtp",
                    "target": "127.0.0.1",
                    "port": banner.server_address[1],
                    "expected": "250 hello",
                },
                [],
            )
            dns_result = run_probe(
                {
                    "name": "dns",
                    "kind": "dns",
                    "target": "127.0.0.1",
                    "port": dns.server_address[1],
                    "query": "example.test",
                },
                [],
            )
            self.assertTrue(smtp_result.healthy, smtp_result.detail)
            self.assertTrue(dns_result.healthy, dns_result.detail)
        finally:
            banner.shutdown()
            dns.shutdown()
            banner.server_close()
            dns.server_close()
            for thread in threads:
                thread.join(timeout=2)

    def test_bounded_application_transaction_probe(self):
        class TransactionHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(b"+OK example service ready\r\n")
                if self.request.recv(1024) == b"USER example\r\n":
                    self.request.sendall(b"+OK user accepted\r\n")
                if self.request.recv(1024) == b"QUIT\r\n":
                    self.request.sendall(b"+OK goodbye\r\n")

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), TransactionHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = run_probe(
                {
                    "name": "transaction",
                    "kind": "transaction",
                    "target": "127.0.0.1",
                    "port": server.server_address[1],
                    "initial_expected": "+OK example service",
                    "steps": [
                        {"send": "USER example\r\n", "expect": "+OK user accepted"},
                        {"send": "QUIT\r\n", "expect": "+OK goodbye"},
                    ],
                },
                [],
            )
            self.assertTrue(result.healthy, result.detail)
            self.assertNotIn("USER example", result.detail)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_transaction_probe_tolerates_fragmented_expected_text(self):
        class FragmentedTransactionHandler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.sendall(b"+OK frag")
                time.sleep(0.01)
                self.request.sendall(b"mented service ready\r\n")
                if self.request.recv(1024) == b"NOOP\r\n":
                    self.request.sendall(b"+OK res")
                    time.sleep(0.01)
                    self.request.sendall(b"ponse complete\r\n")

        server = socketserver.ThreadingTCPServer(
            ("127.0.0.1", 0), FragmentedTransactionHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = run_probe(
                {
                    "name": "fragmented-transaction",
                    "kind": "transaction",
                    "target": "127.0.0.1",
                    "port": server.server_address[1],
                    "initial_expected": "+OK fragmented service",
                    "steps": [{"send": "NOOP\r\n", "expect": "+OK response complete"}],
                },
                [],
            )
            self.assertTrue(result.healthy, result.detail)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_transaction_probe_rejects_unbounded_scripts_before_connecting(self):
        with patch("sentinel_blue.probes.socket.create_connection") as create:
            result = run_probe(
                {
                    "name": "oversized-transaction",
                    "kind": "transaction",
                    "target": "127.0.0.1",
                    "port": 110,
                    "steps": [{"send": "NOOP\r\n", "expect": "+OK"}] * 9,
                },
                [],
            )
        self.assertFalse(result.healthy)
        self.assertIn("1 to 8", result.detail)
        create.assert_not_called()

    def test_probe_rejects_coerced_ports_timeouts_and_tls_flags(self):
        invalid_specs = (
            {"name": "string-port", "kind": "tcp", "target": "127.0.0.1", "port": "80"},
            {"name": "boolean-port", "kind": "tcp", "target": "127.0.0.1", "port": True},
            {"name": "string-timeout", "kind": "tcp", "target": "127.0.0.1", "port": 80, "timeout": "3"},
            {
                "name": "string-tls",
                "kind": "transaction",
                "target": "127.0.0.1",
                "port": 110,
                "tls": "false",
                "steps": [{"send": "NOOP\r\n", "expect": "+OK"}],
            },
            {
                "name": "string-status",
                "kind": "http",
                "target": "http://127.0.0.1/",
                "expected_status": ["200"],
            },
            {"name": "coerced-target", "kind": "tcp", "target": 127001, "port": 80},
            {
                "name": "coerced-banner",
                "kind": "banner",
                "target": "127.0.0.1",
                "port": 25,
                "expected": True,
            },
        )
        with patch("sentinel_blue.probes.socket.create_connection") as create:
            results = [run_probe(spec, []) for spec in invalid_specs]
        self.assertTrue(all(not result.healthy for result in results))
        create.assert_not_called()


    def test_out_of_scope_probe_is_rejected(self):
        result = run_probe(
            {"name": "outside", "kind": "tcp", "target": "192.0.2.1", "port": 22},
            ["198.51.100.0/24"],
        )
        self.assertFalse(result.healthy)
        self.assertIn("outside", result.detail)

    def test_malformed_probe_returns_evidence_instead_of_crashing_agent(self):
        result = run_probe({"name": "missing-target", "kind": "http"}, [])
        self.assertFalse(result.healthy)
        self.assertIn("target", result.detail)

    def test_http_probe_does_not_follow_redirects(self):
        redirect = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=redirect.serve_forever, daemon=True)
        thread.start()
        RedirectHandler.followed = 0
        try:
            result = run_probe(
                {
                    "name": "redirect",
                    "kind": "http",
                    "target": f"http://127.0.0.1:{redirect.server_port}/redirect",
                    "expected_status": [302],
                },
                [],
            )
            self.assertTrue(result.healthy, result.detail)
            self.assertEqual(RedirectHandler.followed, 0)
        finally:
            redirect.shutdown()
            redirect.server_close()
            thread.join(timeout=2)

    def test_tcp_probe_connects_to_the_already_validated_address(self):
        answers = [
            (2, 1, 6, "", ("203.0.113.7", 0)),
        ]
        connection = MagicMock()
        connection.__enter__.return_value = connection
        with (
            patch("sentinel_blue.probes.socket.getaddrinfo", return_value=answers),
            patch("sentinel_blue.probes.socket.create_connection", return_value=connection) as create,
        ):
            result = run_probe(
                {"name": "pinned", "kind": "tcp", "target": "service.test", "port": 443},
                ["203.0.113.0/24"],
            )
        self.assertTrue(result.healthy, result.detail)
        create.assert_called_once_with(("203.0.113.7", 443), timeout=3.0)

    def test_scope_validation_rejects_a_mixed_dns_answer_set(self):
        answers = [
            (2, 1, 6, "", ("203.0.113.7", 0)),
            (2, 1, 6, "", ("192.0.2.9", 0)),
        ]
        with (
            patch("sentinel_blue.probes.socket.getaddrinfo", return_value=answers),
            patch("sentinel_blue.probes.socket.create_connection") as create,
        ):
            result = run_probe(
                {"name": "mixed", "kind": "tcp", "target": "service.test", "port": 443},
                ["203.0.113.0/24"],
            )
        self.assertFalse(result.healthy)
        self.assertIn("outside", result.detail)
        create.assert_not_called()

    def test_scope_validation_rejects_an_unlisted_in_network_dns_answer(self):
        answers = [
            (2, 1, 6, "", ("203.0.113.7", 0)),
            (2, 1, 6, "", ("203.0.113.8", 0)),
        ]
        with (
            patch("sentinel_blue.probes.socket.getaddrinfo", return_value=answers),
            patch("sentinel_blue.probes.socket.create_connection") as create,
        ):
            result = run_probe(
                {"name": "inventory", "kind": "tcp", "target": "service.test", "port": 443},
                ["203.0.113.0/24"],
                authorized_hosts=["203.0.113.7"],
                excluded_hosts=[],
            )
        self.assertFalse(result.healthy)
        self.assertIn("authorized host inventory", result.detail)
        create.assert_not_called()

    def test_scope_validation_rejects_an_explicitly_excluded_address(self):
        with patch("sentinel_blue.probes.socket.create_connection") as create:
            result = run_probe(
                {"name": "excluded", "kind": "tcp", "target": "203.0.113.99", "port": 443},
                ["203.0.113.0/24"],
                authorized_hosts=[],
                excluded_hosts=["203.0.113.99"],
            )
        self.assertFalse(result.healthy)
        self.assertIn("explicitly excluded", result.detail)
        create.assert_not_called()

    def test_bound_scope_does_not_apply_the_legacy_loopback_exception(self):
        with patch("sentinel_blue.probes.socket.create_connection") as create:
            result = run_probe(
                {"name": "loopback", "kind": "tcp", "target": "127.0.0.1", "port": 443},
                ["203.0.113.0/24"],
                authorized_hosts=[],
                excluded_hosts=[],
            )
        self.assertFalse(result.healthy)
        self.assertIn("outside", result.detail)
        create.assert_not_called()


if __name__ == "__main__":
    unittest.main()
