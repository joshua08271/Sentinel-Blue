"""Inert loopback-only HTTP fixture for the disposable native range.

The service is deliberately self-contained so systemd can run it with a
dynamic identity and a private temporary directory.  It has no write paths,
accepts no configurable address, and serves only a fixed health marker.
"""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Sequence


HEALTH_MARKER = "sentinel-blue-native-healthy-v1"


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/health":
            self.send_error(404)
            return
        body = (HEALTH_MARKER + "\n").encode("ascii")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=us-ascii")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


def create_server(port: int) -> ThreadingHTTPServer:
    """Create a server pinned to IPv4 loopback; port zero is test-only."""

    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("port must be an integer from 0 to 65,535")
    server = ThreadingHTTPServer(("127.0.0.1", port), _HealthHandler)
    server.daemon_threads = True
    return server


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Sentinel Blue inert loopback fixture")
    parser.add_argument("--port", required=True, type=int)
    args = parser.parse_args(argv)
    if not 1 <= args.port <= 65535:
        parser.error("--port must be from 1 to 65,535")
    with create_server(args.port) as server:
        server.serve_forever(poll_interval=0.2)
    return 0


if __name__ == "__main__":  # pragma: no cover - exercised by the native runner
    raise SystemExit(main())


__all__ = ["HEALTH_MARKER", "create_server", "main"]
