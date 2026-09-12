"""Stress agent request deadlines against disposable loopback peers.

Each peer expires after a bounded number of bytes and is closed in finally.
No remote addresses, accounts, services, or machine configuration are changed.
"""
from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import threading
import time

from sentinel_blue import __version__
from sentinel_blue.agent import AgentClient, ControllerBackoff
from sentinel_blue.auth import response_signature


def rehearse(*, repeats: int = 5, budget: float = .25) -> dict:
    token = secrets.token_urlsafe(48)
    stop = threading.Event()
    mode = "healthy"
    body = b'{"actions": [], "padding": "owned bounded response fixture"}'

    class Peer(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            selected = mode
            status = 503 if selected == "error_body" else 200
            stamp = str(time.time())
            response_body = b'{"error":"owned temporary outage"}' if status == 503 else body
            signed = response_signature(token, stamp, status, self.path,
                                        self.headers.get("X-SB-Signature", ""), response_body)
            header = (f"HTTP/1.0 {status} Fixture\r\nContent-Type: application/json\r\n"
                      f"Content-Length: {len(response_body)}\r\nX-SB-Response-Version: 2\r\n"
                      f"X-SB-Response-Timestamp: {stamp}\r\nX-SB-Response-Signature: {signed}\r\n\r\n").encode()
            try:
                if selected == "headers":
                    self.drip(header)
                    self.wfile.write(response_body)
                else:
                    self.wfile.write(header)
                    self.wfile.flush()
                    if selected in {"body", "error_body"}:
                        self.drip(response_body)
                    else:
                        self.wfile.write(response_body)
            except OSError:
                pass

        def drip(self, data):
            for value in data:
                if stop.is_set():
                    return
                self.wfile.write(bytes([value]))
                self.wfile.flush()
                if stop.wait(budget / 5):
                    return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Peer)
    # Join every owned handler as well as the listener at cleanup.
    server.daemon_threads = False
    server.block_on_close = True
    listener = threading.Thread(target=server.serve_forever, daemon=True)
    listener.start()
    rows = []
    started = time.monotonic()
    try:
        for selected in ("headers", "body", "error_body"):
            mode = selected
            for attempt in range(repeats):
                client = AgentClient(f"http://127.0.0.1:{server.server_port}", "", "deadline-fixture",
                                     timeout=budget, agent_token=token)
                before = time.monotonic()
                try:
                    client.actions()
                    outcome = "unexpected_success"
                except Exception as exc:
                    outcome = type(exc).__name__
                elapsed = time.monotonic() - before
                try:
                    client.actions()
                    deferred = False
                except ControllerBackoff:
                    deferred = True
                worker = getattr(getattr(client, "_transport", None), "_worker", None)
                if worker is not None:
                    worker.join(timeout=1)
                drained = worker is None or not worker.is_alive()
                rows.append({"case": selected, "attempt": attempt + 1,
                             "elapsed_seconds": round(elapsed, 4), "outcome": outcome,
                             "backoff_applied": deferred, "network_worker_drained": drained,
                             "passed": outcome == "TimeoutError" and elapsed < budget + .5 and deferred and drained})
        mode = "healthy"
        client = AgentClient(f"http://127.0.0.1:{server.server_port}", "", "deadline-fixture",
                             timeout=2, agent_token=token)
        healthy = client.actions() == []
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        listener.join(timeout=3)
    return {"version": __version__, "scope": "owned loopback TCP peers", "samples": rows,
            "request_budget_seconds": budget, "healthy_signed_request_passed": healthy,
            "cleanup_verified": not listener.is_alive(), "seconds": round(time.monotonic() - started, 3),
            "passed": bool(rows) and all(row["passed"] for row in rows) and healthy and not listener.is_alive()}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=5)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 100:
        parser.error("repeats must be 1..100")
    report = rehearse(repeats=args.repeats)
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["passed"] else 1)
