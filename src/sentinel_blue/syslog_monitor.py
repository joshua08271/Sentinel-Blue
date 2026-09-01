"""Optional agentless UDP syslog receiver for assigned appliances."""

from __future__ import annotations

import ipaddress
import re
import socketserver
import threading
import time

from .protocol import AlertCandidate


HIGH_RISK = re.compile(
    r"\b(useradd|adduser|usermod|net\s+user|sudoers|authorized_keys|configuration changed|commit complete)\b",
    re.IGNORECASE,
)
AUTH_FAILURE = re.compile(
    r"\b(failed password|authentication failure|login failed|invalid user)\b", re.IGNORECASE
)


def classify(message: str) -> tuple[str, str]:
    if HIGH_RISK.search(message):
        return "high", "Agentless device reported an identity or configuration change"
    if AUTH_FAILURE.search(message):
        return "medium", "Agentless device reported an authentication failure"
    return "info", "Agentless device event"


class RateLimiter:
    def __init__(self, per_minute: int = 120):
        self.limit = max(10, per_minute)
        self._events: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def allow(self, source: str) -> bool:
        now = time.monotonic()
        with self._lock:
            events = [value for value in self._events.get(source, []) if now - value < 60]
            if len(events) >= self.limit:
                self._events[source] = events
                return False
            events.append(now)
            self._events[source] = events
            return True


def _source_allowed(source: str, networks: list[str]) -> bool:
    address = ipaddress.ip_address(source)
    return address.is_loopback or any(
        address in ipaddress.ip_network(value, strict=False) for value in networks
    )


def make_handler(app, limiter: RateLimiter | None = None):
    rate_limiter = limiter or RateLimiter()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            data = self.request[0]
            source = str(self.client_address[0])
            if not _source_allowed(source, app.authorized_networks) or not rate_limiter.allow(source):
                return
            message = data[:8192].decode("utf-8", errors="replace").strip()
            if not message:
                return
            severity, title = classify(message)
            app.store.add_external_event(source, message, severity)
            if severity == "high":
                app.store.add_alert(
                    f"agentless:{source}",
                    AlertCandidate(
                        kind="agentless_configuration_event",
                        title=title,
                        summary=message[:500],
                        severity="high",
                        confidence=0.72,
                        evidence={"source": source, "message": message},
                        recommendation=(
                            "Verify the event against the approved change record and inspect the "
                            "device through its authorized management interface."
                        ),
                        recommended_action="observe",
                    ),
                )

    return Handler


class SyslogMonitor:
    def __init__(self, app, bind: str, port: int):
        profile = getattr(app, "event_profile", None)
        if profile is not None and getattr(profile, "requires_strict_transport", False):
            raise ValueError(
                "checksum-bound controllers refuse unauthenticated UDP syslog"
            )
        self.server = socketserver.ThreadingUDPServer((bind, port), make_handler(app))
        self.server.daemon_threads = True
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True, name="sentinel-syslog"
        )

    @property
    def address(self) -> tuple[str, int]:
        return self.server.server_address

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
