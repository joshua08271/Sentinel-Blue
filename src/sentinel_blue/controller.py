"""Sentinel Blue controller HTTP API and dashboard server."""

from __future__ import annotations

import argparse
from fnmatch import fnmatchcase
import hashlib
import hmac
import ipaddress
import json
import logging
import mimetypes
import os
import re
import socket
import sqlite3
import ssl
import stat
import sys
import threading
import time
from collections import Counter
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.resources import files
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .auth import (
    ENROLLMENT_TOKEN,
    MAX_CLOCK_SKEW_SECONDS,
    PrincipalRateLimiter,
    derive_enrollment_ticket,
    response_signature,
    validate_operator_token,
    verify,
    wrap_enrollment_token,
)
from .correlation import correlate
from .config_validation import validate_bound_transport
from .detection import detect
from .event_profile import (
    AUTONOMY_MODES,
    EMERGENCY_ALLOWED_ACTIONS,
    EventProfile,
    load_event_profile,
)
from .json_codec import canonical_json_bytes, strict_json_loads
from .operator_auth import (
    OPERATOR_AUTH_VERSION,
    OPERATOR_MAX_CLOCK_SKEW_SECONDS,
    OperatorAuthenticationError,
    OperatorRequestContext,
    authenticate_operator_request,
    operator_key_fingerprint,
)
from .policy import (
    ALLOWED_ACTIONS,
    action_risk,
    should_automate_evidence,
    validate_action_parameters,
)
from .protocol import (
    MAX_AGENT_EGRESS_BYTES,
    MAX_DETECTION_CANDIDATES_PER_KIND,
    MAX_DETECTION_CANDIDATES_PER_TELEMETRY,
    AlertCandidate,
)
from .risk import RiskModel, features_for_kind
from .store import (
    ActionQuotaExceeded,
    Store,
    baseline_capture_files,
    capture_receipt_error,
)
from .state import read_private_json, read_private_text
from .topology import build_topology
from .validation import (
    MODEL_FEATURE_SCHEMA_SHA256,
    validate_action_result,
    validate_agent_id,
    validate_telemetry,
)


LOG = logging.getLogger("sentinel_blue.controller")

CONTROLLER_MAX_WORKERS = 128
CONTROLLER_MAX_WORKERS_PER_CLIENT = 16
TLS_HANDSHAKE_TIMEOUT_SECONDS = 3.0
REQUEST_TIMEOUT_SECONDS = 15.0
ERROR_LOG_INTERVAL_SECONDS = 10.0
PRESSURE_LOG_INTERVAL_SECONDS = 60.0
PRESSURE_LOG_THRESHOLD = 8
INTERNAL_AGENT_IDS = frozenset({"sentinel-relay-probes"})
EXPECTED_CONNECTION_ERRORS = (ConnectionError, TimeoutError, ssl.SSLError)
CONTROL_CHARACTER_TRANSLATION = {
    value: f"\\x{value:02x}" for value in (*range(32), 127)
}
MAX_ACCESS_LOG_MESSAGE = 2048
REPLAY_MARKERS_PER_PRINCIPAL = 1024
OPERATOR_REPLAY_MARKERS = 2048
INGEST_RATE_PER_SECOND = 1.0
INGEST_BURST = 8
EGRESS_LIMIT_ERROR = {"error": "controller response exceeds the egress limit"}
CONTROLLER_MAX_REQUEST_BYTES = 2_000_000
CONTROLLER_REQUEST_LIMITS = {
    "/api/v1/agent/enroll": 16 * 1024,
    "/api/v1/agent/telemetry": CONTROLLER_MAX_REQUEST_BYTES,
    "/api/v1/agent/result": 600_000,
    "/api/v1/protected-accounts/import": 1_500_000,
}
CONTROLLER_JSON_REQUEST_BYTES = 16 * 1024
CONTROLLER_BODYLESS_REQUEST_BYTES = 1024
CANONICAL_CONTENT_LENGTH = re.compile(r"(?:0|[1-9][0-9]*)\Z")
JSON_CONTENT_TYPES = frozenset(
    {"application/json", "application/json; charset=utf-8"}
)
STATIC_JSON_POST_ROUTES = frozenset(
    {
        "/api/v1/change-grants",
        "/api/v1/authorizations",
        "/api/v1/governance/mode",
    }
)
STATIC_BODYLESS_POST_ROUTES = frozenset(
    {
        "/api/v1/governance/emergency-stop",
        "/api/v1/governance/resume",
    }
)
PROCESS_SIGNAL_ACTIONS = frozenset(
    {"quarantine_session", "release_quarantine"}
)
PROCESS_SESSION_FIELDS = (
    "username",
    "source",
    "session_id",
    "process_id",
    "privileged",
    "interactive",
    "process_identity",
)
PROCESS_OBSERVATION_FIELDS = frozenset(
    {"boot_id", "sequence", "payload_sha256"}
)


def _dynamic_post_route_limit(path: str) -> int | None:
    """Return an exact cap for a recognized dynamic operator route."""
    parts = path.split("/")
    if any(not part for part in parts[1:]):
        return None
    if (
        len(parts) == 6
        and parts[1:4] == ["api", "v1", "alerts"]
        and parts[5] == "decision"
    ):
        return CONTROLLER_JSON_REQUEST_BYTES
    if (
        len(parts) == 6
        and parts[1:4] == ["api", "v1", "actions"]
        and parts[5] in {"release", "reconcile", "rollback"}
    ):
        return CONTROLLER_JSON_REQUEST_BYTES
    if len(parts) == 6 and parts[1:4] == ["api", "v1", "agents"]:
        if parts[5] in {"revoke", "enable"}:
            return CONTROLLER_BODYLESS_REQUEST_BYTES
    if (
        len(parts) == 7
        and parts[1:4] == ["api", "v1", "agents"]
        and parts[5:] == ["baseline", "approve"]
    ):
        return CONTROLLER_BODYLESS_REQUEST_BYTES
    if (
        len(parts) == 8
        and parts[1:4] == ["api", "v1", "agents"]
        and parts[5:] == ["baseline", "promotion", "abort"]
    ):
        return CONTROLLER_BODYLESS_REQUEST_BYTES
    return None


def controller_post_route_limit(path: str) -> int | None:
    """Return a strict pre-authentication request cap or reject the route."""
    if path in CONTROLLER_REQUEST_LIMITS:
        return CONTROLLER_REQUEST_LIMITS[path]
    if path in STATIC_JSON_POST_ROUTES:
        return CONTROLLER_JSON_REQUEST_BYTES
    if path in STATIC_BODYLESS_POST_ROUTES:
        return CONTROLLER_BODYLESS_REQUEST_BYTES
    return _dynamic_post_route_limit(path)


def _telemetry_observation(telemetry: dict[str, Any]) -> dict[str, Any]:
    """Bind an action to the exact normalized telemetry document."""
    return {
        "boot_id": telemetry.get("boot_id"),
        "sequence": telemetry.get("sequence"),
        "payload_sha256": hashlib.sha256(
            canonical_json_bytes(telemetry)
        ).hexdigest(),
    }


def _bound_process_action_parameters(
    action_type: str,
    session: Any,
    observation: Any,
) -> dict[str, Any]:
    """Return only the immutable process target and source observation."""
    if action_type not in PROCESS_SIGNAL_ACTIONS:
        raise ValueError("process binding is only valid for session signal actions")
    if not isinstance(session, dict) or set(session) != set(PROCESS_SESSION_FIELDS):
        raise ValueError("session action requires an exact structured session")
    if not isinstance(observation, dict) or set(observation) != set(
        PROCESS_OBSERVATION_FIELDS
    ):
        raise ValueError("session action requires an exact telemetry observation")
    exact_session = {
        field: (
            dict(session[field])
            if field == "process_identity" and isinstance(session.get(field), dict)
            else session.get(field)
        )
        for field in PROCESS_SESSION_FIELDS
    }
    parameters = {
        "session": exact_session,
        "observation": dict(observation),
    }
    validate_action_parameters(
        action_type, parameters, require_process_binding=True
    )
    return parameters


class ControllerDatabaseLock:
    """One non-blocking, process-wide controller lease per database.

    SQLite serializes individual writes, but it cannot establish that exactly
    one controller owns release binding, governance, maintenance, and action
    dispatch.  The lock is deliberately acquired before ``Store`` opens the
    database and is retained for the complete controller lifetime.
    """

    def __init__(self, database: str | os.PathLike[str]):
        if os.fspath(database) == ":memory:":
            raise ValueError("the controller requires a persistent database")
        database_path = Path(database)
        parent = database_path.parent or Path(".")
        if not parent.exists() or not parent.is_dir() or parent.is_symlink():
            raise ValueError("controller database directory is unavailable or unsafe")
        self.path = parent / f".{database_path.name}.sentinel-blue.lock"
        self._fd: int | None = None
        self._windows_overlapped: Any | None = None

    def acquire(self) -> "ControllerDatabaseLock":
        if self._fd is not None:
            return self
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, flags, 0o600)
        except OSError as exc:
            raise RuntimeError("controller database lock is unavailable") from exc
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise RuntimeError("controller database lock is not a private regular file")
            if hasattr(os, "getuid") and metadata.st_uid != os.getuid():
                raise RuntimeError("controller database lock has an unexpected owner")
            if os.name != "nt":
                os.fchmod(fd, 0o600)
                import fcntl

                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise RuntimeError(
                        "another controller already owns this database"
                    ) from exc
            else:  # pragma: no cover - exercised by native Windows acceptance
                import ctypes
                import msvcrt
                from ctypes import wintypes

                class Overlapped(ctypes.Structure):
                    _fields_ = [
                        ("Internal", ctypes.c_size_t),
                        ("InternalHigh", ctypes.c_size_t),
                        ("Offset", wintypes.DWORD),
                        ("OffsetHigh", wintypes.DWORD),
                        ("hEvent", wintypes.HANDLE),
                    ]

                overlapped = Overlapped()
                handle = msvcrt.get_osfhandle(fd)
                lock_file_ex = ctypes.windll.kernel32.LockFileEx
                lock_file_ex.argtypes = [
                    wintypes.HANDLE,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    wintypes.DWORD,
                    ctypes.POINTER(Overlapped),
                ]
                lock_file_ex.restype = wintypes.BOOL
                if not lock_file_ex(handle, 0x00000002 | 0x00000001, 0, 1, 0, ctypes.byref(overlapped)):
                    raise RuntimeError("another controller already owns this database")
                self._windows_overlapped = overlapped
            self._fd = fd
            return self
        except Exception:
            os.close(fd)
            raise

    def close(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        if os.name == "nt" and self._windows_overlapped is not None:  # pragma: no cover
            import ctypes
            import msvcrt

            ctypes.windll.kernel32.UnlockFileEx(
                msvcrt.get_osfhandle(fd),
                0,
                1,
                0,
                ctypes.byref(self._windows_overlapped),
            )
            self._windows_overlapped = None
        os.close(fd)

    def __enter__(self) -> "ControllerDatabaseLock":
        return self.acquire()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def _paths_alias(left: str | os.PathLike[str], right: str | os.PathLike[str]) -> bool:
    first, second = Path(left), Path(right)
    try:
        if first.resolve() == second.resolve():
            return True
        if first.exists() and second.exists():
            return os.path.samefile(first, second)
    except OSError:
        return False
    return False


def _path_is_within(
    child: str | os.PathLike[str], parent: str | os.PathLike[str]
) -> bool:
    try:
        resolved_child = Path(child).resolve()
        resolved_parent = Path(parent).resolve()
        return resolved_child == resolved_parent or resolved_parent in resolved_child.parents
    except OSError:
        return False


def _validate_controller_path_separation(args: argparse.Namespace) -> None:
    """Keep live authority, state, and generated outputs in distinct paths."""
    roles = (
        ("frozen runtime", sys.argv[0]),
        ("controller database", getattr(args, "database", None)),
        ("event profile", getattr(args, "event_profile", None)),
        ("enrollment token", getattr(args, "token_file", None)),
        ("operator token", getattr(args, "operator_token_file", None)),
        ("recovery key", getattr(args, "recovery_key_file", None)),
        ("recovery anchor", getattr(args, "recovery_anchor", None)),
        ("TLS certificate", getattr(args, "tls_cert", None)),
        ("TLS private key", getattr(args, "tls_key", None)),
        ("TLS CA", getattr(args, "tls_ca_file", None)),
        ("frozen model", getattr(args, "model", None)),
        ("probe configuration", getattr(args, "probe_config", None)),
        ("adaptive model output", getattr(args, "adaptive_model_output", None)),
        ("backup directory", getattr(args, "backup_directory", None)),
    )
    configured = [(label, value) for label, value in roles if value]
    permitted_aliases = {
        frozenset(("event profile", "probe configuration")),
        frozenset(("TLS certificate", "TLS CA")),
    }
    for index, (left_label, left_value) in enumerate(configured):
        for right_label, right_value in configured[index + 1 :]:
            if frozenset((left_label, right_label)) in permitted_aliases:
                continue
            if _paths_alias(left_value, right_value):
                raise ValueError(
                    f"{left_label} must differ from the {right_label}"
                )
    backup_directory = getattr(args, "backup_directory", None)
    if backup_directory:
        for label, value in configured:
            if label == "backup directory":
                continue
            if _path_is_within(value, backup_directory):
                raise ValueError(
                    f"{label} must be stored outside the backup directory"
                )


SEVERITY_PRIORITY = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SERVICE_MANIFEST_ACTIONS = frozenset(
    {
        "validate_service",
        "capture_restore_point",
        "restore_integrity",
        "rollback_integrity",
        "restart_service",
        "rollback_service",
    }
)
SERVICE_ID_ACTIONS = frozenset({"restart_service", "rollback_service"})
PATH_ACTIONS = frozenset(
    {"capture_restore_point", "restore_integrity", "rollback_integrity"}
)


def _manifest_path(value: object) -> str | None:
    """Return a separator-normalized exact path key, without resolving it."""
    if not isinstance(value, str) or not value:
        return None
    if not (PurePosixPath(value).is_absolute() or PureWindowsPath(value).is_absolute()):
        return None
    normalized = value.replace("\\", "/")
    if PureWindowsPath(value).is_absolute():
        return normalized.casefold()
    return normalized


def _probe_contract(value: object) -> dict[str, Any] | None:
    """Keep every executable probe field and omit only controller path metadata."""
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        return None
    return {key: item for key, item in value.items() if key != "restore_paths"}


def assess_baseline_readiness(telemetry: dict[str, Any] | None) -> dict[str, Any]:
    """Summarize first-sample quality without silently approving or changing it."""
    if not telemetry:
        return {
            "ready": False,
            "score": 0,
            "blockers": ["no telemetry has been received"],
            "warnings": [],
        }
    blockers: list[str] = []
    warnings: list[str] = []
    score = 100
    errors = list(telemetry.get("collector_errors", []))
    if errors:
        blockers.append(f"{len(errors)} collector or agent self-health error(s)")
        score -= min(50, 15 + len(errors) * 5)
    probes = list(telemetry.get("probes", []))
    unhealthy = [probe for probe in probes if not probe.get("healthy", False)]
    if unhealthy:
        blockers.append(f"{len(unhealthy)} service/scoring probe(s) are unhealthy")
        score -= min(50, 20 + len(unhealthy) * 5)
    elif not probes:
        warnings.append("no service/scoring probes are configured")
        score -= 10
    if not telemetry.get("integrity"):
        warnings.append("no protected-file hashes are configured")
        score -= 10
    if str(telemetry.get("platform", "")).casefold().startswith("windows"):
        integrity = list(telemetry.get("integrity", []))
        incomplete_security = [
            item for item in integrity if not item.get("security_descriptor_sha256")
        ]
        if not integrity:
            blockers.append("Windows protected-file security metadata is unavailable")
            score -= 25
        elif incomplete_security:
            blockers.append(
                f"{len(incomplete_security)} Windows protected-file security descriptor(s) are unavailable"
            )
            score -= min(40, 10 + len(incomplete_security) * 5)
    if not telemetry.get("services"):
        warnings.append("no service state was collected")
        score -= 10
    if not telemetry.get("interfaces"):
        warnings.append("no network interfaces were collected")
        score -= 10
    return {
        "ready": not blockers,
        "score": max(0, score),
        "blockers": blockers,
        "warnings": warnings,
    }


def prioritize_detection_candidates(
    candidates: list[AlertCandidate],
) -> tuple[list[AlertCandidate], dict[str, Any]]:
    """Select a deterministic severity-first, per-kind-bounded evidence set."""
    indexed = list(enumerate(candidates))
    indexed.sort(
        key=lambda item: (
            SEVERITY_PRIORITY.get(str(item[1].severity).casefold(), 4),
            -float(item[1].confidence),
            str(item[1].kind),
            item[0],
        )
    )
    selected: list[AlertCandidate] = []
    selected_by_kind: Counter[str] = Counter()
    suppressed_by_kind: Counter[str] = Counter()
    suppressed_by_severity: Counter[str] = Counter()
    for _index, candidate in indexed:
        kind = str(candidate.kind)
        severity = str(candidate.severity).casefold()
        if (
            len(selected) >= MAX_DETECTION_CANDIDATES_PER_TELEMETRY
            or selected_by_kind[kind] >= MAX_DETECTION_CANDIDATES_PER_KIND
        ):
            suppressed_by_kind[kind] += 1
            suppressed_by_severity[severity] += 1
            continue
        selected.append(candidate)
        selected_by_kind[kind] += 1
    summary = {
        "observed_candidates": len(candidates),
        "selected_candidates": len(selected),
        "suppressed_candidates": len(candidates) - len(selected),
        "max_candidates_per_telemetry": MAX_DETECTION_CANDIDATES_PER_TELEMETRY,
        "max_candidates_per_kind": MAX_DETECTION_CANDIDATES_PER_KIND,
        "suppressed_by_kind": dict(sorted(suppressed_by_kind.items())),
        "suppressed_by_severity": dict(sorted(suppressed_by_severity.items())),
    }
    return selected, summary


class ControllerServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128

    def __init__(
        self,
        *args: Any,
        max_workers: int = CONTROLLER_MAX_WORKERS,
        max_workers_per_client: int = CONTROLLER_MAX_WORKERS_PER_CLIENT,
        tls_handshake_timeout: float = TLS_HANDSHAKE_TIMEOUT_SECONDS,
        request_timeout: float = REQUEST_TIMEOUT_SECONDS,
        event_profile: EventProfile | None = None,
        **kwargs: Any,
    ):
        if type(max_workers) is not int or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")
        if (
            type(max_workers_per_client) is not int
            or max_workers_per_client < 1
            or max_workers_per_client > max_workers
        ):
            raise ValueError("max_workers_per_client must be between one and max_workers")
        if not 0.1 <= float(tls_handshake_timeout) <= 60.0:
            raise ValueError("tls_handshake_timeout is outside its accepted range")
        if not 0.1 <= float(request_timeout) <= 300.0:
            raise ValueError("request_timeout is outside its accepted range")
        super().__init__(*args, **kwargs)
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        self._max_workers_per_client = max_workers_per_client
        self._tls_handshake_timeout = float(tls_handshake_timeout)
        self._request_timeout = float(request_timeout)
        self._tls_context: ssl.SSLContext | None = None
        self._controller_ingress_hosts: frozenset[str] | None = None
        if event_profile is not None and event_profile.requires_strict_transport:
            ingress = frozenset(
                self._normalize_source_address(value)
                for value in event_profile.controller_ingress_hosts
            )
            if not ingress:
                raise ValueError(
                    "checksum-bound controllers require exact controller ingress hosts"
                )
            self._controller_ingress_hosts = ingress
        self._client_lock = threading.Lock()
        self._active_by_client: dict[str, int] = {}
        self._error_lock = threading.Lock()
        self._last_error_log: dict[tuple[str, str], float] = {}
        self._suppressed_error_logs: dict[tuple[str, str], int] = {}
        self._expected_connection_failures: dict[str, int] = {}
        self._last_pressure_log: dict[str, float] = {}
        self._deadline_lock = threading.Lock()
        self._deadline_requests: set[int] = set()

    def enable_tls(self, context: ssl.SSLContext) -> None:
        """Defer TLS handshakes to bounded workers instead of blocking accept()."""
        self._tls_context = context

    @staticmethod
    def _normalize_source_address(value: Any) -> str:
        address = ipaddress.ip_address(str(value))
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        return address.compressed

    @classmethod
    def _client_key(cls, client_address: Any) -> str:
        try:
            return cls._normalize_source_address(client_address[0])
        except (IndexError, TypeError, ValueError):
            return "unknown"

    def _source_allowed(self, client_address: Any) -> bool:
        if self._controller_ingress_hosts is None:
            return True
        source = self._client_key(client_address)
        if source == "unknown":
            return False
        address = ipaddress.ip_address(source)
        return address.is_loopback or source in self._controller_ingress_hosts

    def _acquire_worker(self, client_address: Any) -> bool:
        if not self._worker_slots.acquire(blocking=False):
            self._record_expected_connection_failure("global_capacity_rejected")
            return False
        client = self._client_key(client_address)
        with self._client_lock:
            active = self._active_by_client.get(client, 0)
            if active >= self._max_workers_per_client:
                self._worker_slots.release()
                self._record_expected_connection_failure("source_quota_rejected")
                return False
            self._active_by_client[client] = active + 1
        return True

    def _release_worker(self, client_address: Any) -> None:
        client = self._client_key(client_address)
        with self._client_lock:
            active = self._active_by_client.get(client, 0)
            if active < 1:
                LOG.error("controller worker permit release had no matching client lease")
                return
            if active == 1:
                self._active_by_client.pop(client, None)
            else:
                self._active_by_client[client] = active - 1
        self._worker_slots.release()

    def active_connections(self) -> dict[str, int]:
        """Return a bounded diagnostic snapshot without exposing socket details."""
        with self._client_lock:
            return dict(self._active_by_client)

    def _record_expected_connection_failure(self, kind: str) -> None:
        normalized = kind if kind in {
            "ConnectionError",
            "ConnectionResetError",
            "BrokenPipeError",
            "TimeoutError",
            "SSLError",
            "request_timeout",
            "request_deadline",
            "http_protocol_error",
            "source_quota_rejected",
            "global_capacity_rejected",
            "source_scope_rejected",
        } else "other"
        should_log = False
        with self._error_lock:
            total = min(
                2**63 - 1,
                self._expected_connection_failures.get(normalized, 0) + 1,
            )
            self._expected_connection_failures[normalized] = total
            now = time.monotonic()
            last = self._last_pressure_log.get(normalized, float("-inf"))
            if total >= PRESSURE_LOG_THRESHOLD and (
                total == PRESSURE_LOG_THRESHOLD
                or now - last >= PRESSURE_LOG_INTERVAL_SECONDS
            ):
                self._last_pressure_log[normalized] = now
                should_log = True
        if should_log:
            LOG.warning(
                "controller connection pressure observed: kind=%s total=%s",
                normalized,
                total,
            )

    def connection_pressure_snapshot(self) -> dict[str, int]:
        with self._error_lock:
            return dict(self._expected_connection_failures)

    def _set_request_deadline_expired(
        self, request: socket.socket, expired: bool
    ) -> None:
        request_key = id(request)
        with self._deadline_lock:
            if expired:
                self._deadline_requests.add(request_key)
            else:
                self._deadline_requests.discard(request_key)

    def request_deadline_expired(self, request: socket.socket) -> bool:
        """Return whether the absolute deadline ended this exact request."""
        with self._deadline_lock:
            return id(request) in self._deadline_requests

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        try:
            if not self._source_allowed(address):
                self._record_expected_connection_failure("source_scope_rejected")
                raise ConnectionAbortedError(
                    "controller source is outside the exact ingress inventory"
                )
            connection.settimeout(
                self._tls_handshake_timeout if self._tls_context else self._request_timeout
            )
            if self._tls_context is not None:
                connection = self._tls_context.wrap_socket(
                    connection,
                    server_side=True,
                    do_handshake_on_connect=False,
                )
            return connection, address
        except Exception:
            connection.close()
            raise

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._acquire_worker(client_address):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release_worker(client_address)
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        deadline_expired = threading.Event()
        deadline_timer: threading.Timer | None = None

        def expire_request() -> None:
            deadline_expired.set()
            self._set_request_deadline_expired(request, True)
            self._record_expected_connection_failure("request_deadline")
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        try:
            if self._tls_context is not None:
                request.do_handshake()
                request.settimeout(self._request_timeout)
            timer = threading.Timer(self._request_timeout, expire_request)
            timer.daemon = True
            timer.start()
            deadline_timer = timer
            try:
                self.finish_request(request, client_address)
            except EXPECTED_CONNECTION_ERRORS as exc:
                if not deadline_expired.is_set():
                    self._record_expected_connection_failure(type(exc).__name__)
            except OSError:
                if not deadline_expired.is_set():
                    self.handle_error(request, client_address)
            except Exception:
                self.handle_error(request, client_address)
        except EXPECTED_CONNECTION_ERRORS as exc:
            self._record_expected_connection_failure(type(exc).__name__)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            if deadline_timer is not None:
                deadline_timer.cancel()
                deadline_timer.join()
            self._set_request_deadline_expired(request, False)
            try:
                self.shutdown_request(request)
            finally:
                self._release_worker(client_address)

    def handle_error(self, request: socket.socket, client_address: Any) -> None:
        """Suppress routine disconnect tracebacks and rate-limit unexpected failures."""
        error_info = sys.exc_info()
        error = error_info[1]
        if isinstance(error, EXPECTED_CONNECTION_ERRORS):
            self._record_expected_connection_failure(type(error).__name__)
            return
        now = time.monotonic()
        key = (type(error).__name__, self._client_key(client_address))
        with self._error_lock:
            if key not in self._last_error_log and len(self._last_error_log) >= 256:
                key = ("other", "other")
            last = self._last_error_log.get(key, float("-inf"))
            if now - last < ERROR_LOG_INTERVAL_SECONDS:
                self._suppressed_error_logs[key] = (
                    self._suppressed_error_logs.get(key, 0) + 1
                )
                return
            suppressed = self._suppressed_error_logs.pop(key, 0)
            self._last_error_log[key] = now
        LOG.error(
            "unhandled controller request failure (%s); %s similar failures suppressed",
            type(error).__name__,
            suppressed,
            exc_info=error_info,
        )


def maintenance_loop(
    app: "ControllerApp",
    stale_after: float,
    retention_days: int,
    backup_directory: str | None,
    backup_interval: float,
    backup_keep: int,
    interval: float,
    stop: threading.Event,
) -> None:
    last_backup = 0.0
    last_prune = 0.0
    while not stop.is_set():
        try:
            app.resume_pending_telemetry()
            app.store.mark_stale_dispatched_actions()
            app.monitor_stale_agents(max(15.0, stale_after))
            now = time.time()
            if now - last_prune >= 3600:
                app.store.prune(retention_days)
                last_prune = now
            if backup_directory and now - last_backup >= max(60.0, backup_interval):
                app.create_recovery_backup(backup_directory)
                from .recovery_ops import prune_recovery_backups

                if app.recovery_key is None or app.recovery_anchor is None:
                    raise RuntimeError(
                        "authenticated controller recovery is unavailable"
                    )
                prune_recovery_backups(
                    backup_directory,
                    app.recovery_anchor,
                    app.recovery_key,
                    keep=backup_keep,
                )
                last_backup = now
        except Exception:
            LOG.exception("controller maintenance cycle failed")
        stop.wait(max(5.0, interval))


def relay_probe_loop(
    app: "ControllerApp",
    probe_specs: list[dict[str, Any]],
    interval: float,
    stop: threading.Event,
) -> None:
    from dataclasses import asdict

    from .probes import run_probes

    while not stop.is_set():
        try:
            results = run_probes(
                probe_specs,
                app.authorized_networks,
                authorized_hosts=app.authorized_hosts,
                excluded_hosts=app.excluded_hosts,
            )
            app.ingest(
                {
                    "agent_id": "sentinel-relay-probes",
                    "hostname": f"{socket.gethostname()}-relay-probes",
                    "platform": "Sentinel Blue relay",
                    "observed_at": time.time(),
                    "accounts": [],
                    "sessions": [],
                    "services": [],
                    "interfaces": [],
                    "routes": [],
                    "neighbors": [],
                    "listeners": [],
                    "integrity": [],
                    "probes": [asdict(item) for item in results],
                    "collector_errors": [],
                    "agent_version": __version__,
                    "profile_id": app.event_profile.profile_id,
                    "profile_fingerprint": app.event_profile.fingerprint,
                }
            )
        except Exception:
            LOG.exception("relay probe cycle failed")
        stop.wait(max(5.0, interval))


class ControllerApp:
    def __init__(
        self,
        store: Store,
        token: str,
        model: RiskModel | None = None,
        authorized_networks: list[str] | None = None,
        enrollment_window: float = 3600.0,
        max_agents: int = 512,
        local_operator_bootstrap: bool = False,
        health_stale_after: float = 90.0,
        auto_restore: bool = False,
        restoration_probes: list[dict[str, Any]] | None = None,
        restore_confirmations: int = 2,
        allow_unprobed_restoration: bool = False,
        event_profile: EventProfile | None = None,
        *,
        operator_token: str,
        operator_principal_id: str = "operator",
        operator_credential_epoch: int = 1,
        recovery_key: bytes | None = None,
        recovery_anchor: str | os.PathLike[str] | None = None,
        require_authenticated_recovery: bool = False,
        force_safe_governance: bool = False,
        campaign_id: str | None = None,
    ):
        if len(token) < 16:
            raise ValueError("the enrollment token must be at least 16 characters")
        self.store = store
        self.token = token
        self.operator_token = validate_operator_token(token, operator_token)
        if local_operator_bootstrap:
            raise ValueError(
                "local operator bearer bootstrap was removed; use signed requests"
            )
        self.operator_key_fingerprint = operator_key_fingerprint(
            self.operator_token
        )
        if (recovery_key is None) != (recovery_anchor is None):
            raise ValueError(
                "recovery key and protected anchor must be configured together"
            )
        if require_authenticated_recovery and recovery_key is None:
            raise ValueError("authenticated controller recovery is required")
        self.recovery_key = recovery_key
        self.recovery_anchor = (
            None if recovery_anchor is None else str(recovery_anchor)
        )
        self.require_authenticated_recovery = bool(
            require_authenticated_recovery
        )
        self.max_agents = max(1, max_agents)
        self.event_profile = event_profile or EventProfile.testing()
        self._strict_release_binding = self._release_binding_required()
        if self._strict_release_binding and not ENROLLMENT_TOKEN.fullmatch(token):
            raise ValueError(
                "checksum-bound enrollment tokens must be 32-256 URL-safe characters"
            )
        candidate_agent_ids = {
            str(service.get("host", ""))
            for service in self.event_profile.services
            if service.get("host")
        }
        candidate_agent_ids.update(
            str(identity.get("agent_id", ""))
            for identity in self.event_profile.identities
            if identity.get("agent_id") not in {None, "", "*"}
        )
        self.enrollable_agent_ids = frozenset(
            validate_agent_id(value) for value in candidate_agent_ids
        )
        if self._strict_release_binding and not self.enrollable_agent_ids:
            raise ValueError(
                "checksum-bound profiles require an exact enrollable agent inventory"
            )
        if len(self.enrollable_agent_ids) > self.max_agents:
            raise ValueError("the exact agent inventory exceeds --max-agents")
        operator_info = self.store.initialize_operator_auth(
            principal_id=operator_principal_id,
            key_fingerprint=self.operator_key_fingerprint,
            credential_epoch=operator_credential_epoch,
            max_clock_skew=OPERATOR_MAX_CLOCK_SKEW_SECONDS,
            now=time.time(),
        )
        self.operator_principal_id = str(operator_info["principal_id"])
        self.operator_credential_epoch = int(
            operator_info["credential_epoch"]
        )
        self.operator_request_not_before = int(
            operator_info["request_not_before"]
        )
        self.store.initialize_http_request_replay(
            MAX_CLOCK_SKEW_SECONDS,
            now=time.time(),
        )
        self.campaign_id = self.store.initialize_campaign_id(campaign_id)
        release_sha256 = str(self.event_profile.release.get("sha256", "")).casefold()
        self.store.activate_release_binding(
            profile_id=self.event_profile.profile_id,
            profile_fingerprint=self.event_profile.fingerprint,
            agent_version=__version__,
            release_sha256=release_sha256,
            strict=self._strict_release_binding,
        )
        credential_blockers = self.credential_migration_blockers()
        if credential_blockers:
            preview = ", ".join(credential_blockers[:8])
            suffix = "..." if len(credential_blockers) > 8 else ""
            raise ValueError(
                "enabled agents without independent credentials require offline "
                f"migration before startup: {preview}{suffix}"
            )
        self.ingest_limiter = PrincipalRateLimiter(
            rate_per_second=INGEST_RATE_PER_SECOND,
            burst=INGEST_BURST,
            max_principals=self.max_agents,
        )
        self.model = model or RiskModel()
        self.model_fingerprint = self.model.fingerprint()
        self.authorized_networks = authorized_networks or []
        self.started_at = time.time()
        self.enrollment_deadline = self.store.initialize_enrollment_deadline(
            enrollment_window, self.started_at
        )
        self.health_stale_after = max(15.0, health_stale_after)
        self.auto_restore = auto_restore
        self.restoration_probes = restoration_probes or []
        self.restore_confirmations = max(1, min(int(restore_confirmations), 5))
        self.allow_unprobed_restoration = bool(allow_unprobed_restoration)
        self.authorized_hosts = list(self.event_profile.authorized_hosts)
        self.excluded_hosts = list(self.event_profile.excluded_hosts)
        # An in-memory database is an explicit ephemeral test fixture and cannot
        # provide restart persistence. Persistent checksum-bound controllers
        # always start stopped when governance is missing, corrupt, or rebound.
        mode_ceiling = {
            "observe": ("observe",),
            "interactive": ("observe", "interactive"),
            "approval-based": ("observe", "interactive", "approval-based"),
            "guarded-autonomous": (
                "observe", "interactive", "approval-based", "guarded-autonomous"
            ),
            "range-autonomous": tuple(AUTONOMY_MODES),
        }
        allowed_governance_modes = set(
            mode_ceiling.get(self.event_profile.autonomy_mode, ("observe",))
        )
        if not self.event_profile.allows("guarded_autonomy"):
            allowed_governance_modes.discard("guarded-autonomous")
        if self.event_profile.environment != "range-autonomous":
            allowed_governance_modes.discard("range-autonomous")
        self._allowed_governance_modes = frozenset(allowed_governance_modes)
        governance = self.store.load_governance(
            profile_fingerprint=self.event_profile.fingerprint,
            default_mode=self.event_profile.autonomy_mode,
            strict=self._strict_release_binding and self.store.path != ":memory:",
            allowed_modes=self._allowed_governance_modes,
            force_safe=bool(force_safe_governance),
        )
        self.autonomy_mode = str(governance["autonomy_mode"])
        self.emergency_stopped = bool(governance["emergency_stopped"])
        self._governance_revision = int(governance["revision"])
        self._governance_persistence_uncertain = False
        self.connection_pressure_provider: Any = lambda: {}
        if self.auto_restore and not self.event_profile.action_allowed(
            "restore_integrity",
            automated=True,
            autonomy_mode=self.event_profile.autonomy_mode,
        ):
            raise ValueError("automatic restoration is not authorized by the event profile")
        if self.allow_unprobed_restoration and self.event_profile.environment == "live-competition":
            raise ValueError("live competition profiles cannot authorize unprobed restoration")
        self._integrity_lock = threading.Lock()
        self._decision_lock = threading.Lock()
        # The outer barrier spans both leasing and the actual HTTP write. Any
        # authority transition that returns to an operator has therefore
        # waited until all earlier action responses have left the controller.
        self._action_egress_lock = threading.RLock()
        self._governance_lock = threading.RLock()
        self._integrity_value = "pending"
        self._integrity_checked_at = 0.0
        self._integrity_refreshing = False
        for spec in self.restoration_probes:
            if not isinstance(spec, dict):
                raise ValueError("each restoration probe must be an object")
            patterns = spec.get("restore_paths")
            if patterns is not None and (
                not isinstance(patterns, list)
                or not patterns
                or len(patterns) > 64
                or any(not isinstance(item, str) or not item or len(item) > 1024 for item in patterns)
            ):
                raise ValueError("probe restore_paths must be a non-empty bounded array")
        for identity in self.event_profile.protected_accounts():
            self.store.protect_account(
                identity["agent_id"],
                identity["name"],
                identity["class"],
                identity["source"],
            )

    def _release_binding_required(self) -> bool:
        digest = str(self.event_profile.release.get("sha256", "")).casefold()
        return self.event_profile.environment == "live-competition" or (
            len(digest) == 64
            and all(character in "0123456789abcdef" for character in digest)
        )

    def credential_migration_blockers(self) -> list[str]:
        return [
            agent_id
            for agent_id in self.store.enabled_agents_missing_credentials()
            if agent_id not in INTERNAL_AGENT_IDS
        ]

    def _require_agent_binding(
        self,
        payload: dict[str, Any],
        *,
        include_version: bool = False,
    ) -> None:
        if not self._release_binding_required():
            return
        if (
            payload.get("profile_id") != self.event_profile.profile_id
            or payload.get("profile_fingerprint") != self.event_profile.fingerprint
        ):
            raise PermissionError(
                "agent event-profile binding does not match the controller"
            )
        if include_version and payload.get("agent_version") != __version__:
            raise PermissionError("agent release version does not match the controller")

    def governance_status(self) -> dict[str, Any]:
        with self._governance_lock:
            return {
                "profile_id": self.event_profile.profile_id,
                "profile_fingerprint": self.event_profile.fingerprint,
                "competition": self.event_profile.competition,
                "environment": self.event_profile.environment,
                "autonomy_mode": self.autonomy_mode,
                "emergency_stopped": self.emergency_stopped,
                "governance_revision": self._governance_revision,
                "services_confirmed": self.event_profile.services_confirmed,
                "single_live_scored_network": True,
                "blue_staging_non_authoritative": True,
            }

    def dispatch_policy(self) -> tuple[set[str], set[str]]:
        with self._governance_lock:
            automatic = {
                action
                for action in ALLOWED_ACTIONS
                if self.event_profile.action_allowed(
                    action,
                    automated=True,
                    autonomy_mode=self.autonomy_mode,
                    emergency_stopped=self.emergency_stopped,
                )
            }
            manual = {
                action
                for action in ALLOWED_ACTIONS
                if self.event_profile.action_allowed(
                    action,
                    automated=False,
                    autonomy_mode=self.autonomy_mode,
                    emergency_stopped=self.emergency_stopped,
                )
            }
            return automatic, manual

    def pending_actions_for_agent(self, agent_id: str) -> list[Any]:
        """Compute policy and lease actions under one stop/dispatch barrier."""
        with self._governance_lock:
            automatic, manual = self.dispatch_policy()
            binding = (
                self.store.agent_binding(
                    agent_id,
                    require_fresh=True,
                    freshness_seconds=self.health_stale_after,
                )
                if self._strict_release_binding
                else None
            )
            if self._strict_release_binding and binding is None:
                return []
            return self.store.pending_actions(
                agent_id,
                allowed_automated_action_types=automatic,
                allowed_manual_action_types=manual,
                max_serialized_bytes=MAX_AGENT_EGRESS_BYTES,
                binding=binding,
            )

    def _persist_governance(self, mode: str, emergency_stopped: bool) -> None:
        try:
            state = self.store.update_governance(
                profile_fingerprint=self.event_profile.fingerprint,
                mode=mode,
                emergency_stopped=emergency_stopped,
                expected_revision=self._governance_revision,
            )
        except Exception:
            # Never retain permissive in-memory authority after persistence is
            # uncertain. The independent safe write handles partial failures;
            # the runtime dirty marker covers complete storage failure/crash.
            self.autonomy_mode = "observe"
            self.emergency_stopped = True
            self._governance_persistence_uncertain = True
            try:
                self.store.force_safe_governance(
                    self.event_profile.fingerprint
                )
                self._governance_persistence_uncertain = False
            except Exception:
                LOG.exception("durable fail-safe governance write also failed")
            raise
        self.autonomy_mode = str(state["autonomy_mode"])
        self.emergency_stopped = bool(state["emergency_stopped"])
        self._governance_revision = int(state["revision"])

    def set_autonomy_mode(self, mode: str) -> dict[str, Any]:
        normalized = str(mode).casefold()
        if normalized not in AUTONOMY_MODES:
            raise ValueError("unsupported autonomy mode")
        if normalized not in self._allowed_governance_modes:
            raise PermissionError(
                "autonomy mode exceeds the signed event-profile authority"
            )
        with self._action_egress_lock, self._governance_lock:
            self._persist_governance(normalized, self.emergency_stopped)
            return self.governance_status()

    def emergency_stop(self) -> dict[str, Any]:
        with self._action_egress_lock, self._governance_lock:
            # Stop in memory before touching persistence; failure remains stopped.
            self.emergency_stopped = True
            self._persist_governance(self.autonomy_mode, True)
            return self.governance_status()

    def resume_changes(self) -> dict[str, Any]:
        with self._action_egress_lock, self._governance_lock:
            self._persist_governance(self.autonomy_mode, False)
            return self.governance_status()

    def issue_action_authorization(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = validate_agent_id(str(payload.get("agent_id", "")))
        action_type = str(payload.get("action_type", ""))
        subject = str(payload.get("subject", ""))
        if not subject or len(subject) > 512:
            raise ValueError("authorization requires a bounded exact subject")
        if action_risk(action_type) != "high":
            raise ValueError("one-use authorization is reserved for high-risk actions")
        if not self.event_profile.action_allowed(
            action_type,
            automated=False,
            autonomy_mode=self.autonomy_mode,
            emergency_stopped=self.emergency_stopped,
        ):
            raise PermissionError("the event profile does not authorize this action")
        binding = (
            self.store.agent_binding(
                agent_id,
                require_fresh=True,
                freshness_seconds=self.health_stale_after,
            )
            if self._strict_release_binding and self.store.path != ":memory:"
            else None
        )
        if self._strict_release_binding and self.store.path != ":memory:" and binding is None:
            raise PermissionError("agent release binding is not current and fresh")
        return self.store.issue_privileged_authorization(
            agent_id,
            action_type,
            subject,
            float(payload.get("ttl_seconds", 120.0)),
            binding=binding,
        )

    def _service_manifest_policy(
        self,
        agent_id: str,
        action_type: str,
        parameters: dict[str, Any],
        *,
        automated: bool,
    ) -> tuple[bool, dict[str, Any]]:
        """Bind a service-affecting action to one or more exact manifest entries.

        Unconfirmed manifests exist only in the explicit in-process testing
        profile. Both real runtime readiness gates require confirmed manifests,
        so deployed controllers always take this default-deny branch.
        """
        if (
            action_type not in SERVICE_MANIFEST_ACTIONS
            or not self.event_profile.services_confirmed
        ):
            return True, {}

        manifests = [
            (index, service)
            for index, service in enumerate(self.event_profile.services)
            if service.get("host") == agent_id
        ]
        if not manifests:
            return False, {"policy_reason": "service_manifest_host_no_match"}

        relevant: dict[int, dict[str, Any]] = {}

        def select_one(label: str, matches: list[tuple[int, dict[str, Any]]]) -> bool:
            if len(matches) != 1:
                detail["policy_reason"] = (
                    "service_manifest_ambiguous"
                    if len(matches) > 1
                    else "service_manifest_no_match"
                )
                detail["selector"] = label
                return False
            index, service = matches[0]
            relevant[index] = service
            return True

        detail: dict[str, Any] = {}
        if action_type in SERVICE_ID_ACTIONS:
            service_id = parameters.get("service")
            matches = [
                item
                for item in manifests
                if isinstance(service_id, str)
                and item[1].get("service_id") == service_id
            ]
            if not select_one("service", matches):
                return False, detail
        elif action_type in PATH_ACTIONS:
            if action_type == "capture_restore_point":
                files = parameters.get("files")
                paths = (
                    [item.get("path") for item in files if isinstance(item, dict)]
                    if isinstance(files, list)
                    else []
                )
            else:
                paths = [parameters.get("path")]
            if not paths:
                return False, {
                    "policy_reason": "service_manifest_no_match",
                    "selector": "path",
                }
            for path in paths:
                normalized = _manifest_path(path)
                matches: list[tuple[int, dict[str, Any]]] = []
                if normalized is not None:
                    for item in manifests:
                        declared = {
                            candidate
                            for candidate in (
                                _manifest_path(value)
                                for value in (
                                    list(item[1].get("required_files", []))
                                    + list(item[1].get("required_data", []))
                                )
                            )
                            if candidate is not None
                        }
                        if normalized in declared:
                            matches.append(item)
                if not select_one("path", matches):
                    return False, detail
        else:
            probes = parameters.get("probes")
            if not isinstance(probes, list) or not probes:
                return False, {
                    "policy_reason": "service_manifest_no_match",
                    "selector": "probe",
                }
            for probe in probes:
                contract = _probe_contract(probe)
                matches = [
                    item
                    for item in manifests
                    if contract is not None
                    and any(
                        _probe_contract(expected) == contract
                        for expected in item[1].get("expected_transactions", [])
                    )
                ]
                if not select_one("probe", matches):
                    return False, detail

        # Service and integrity mutations may carry probes for transactional
        # validation. Those probes must be exact declared transactions of the
        # already selected service(s); they cannot expand the action's scope.
        if action_type != "validate_service" and "probes" in parameters:
            probes = parameters.get("probes")
            if not isinstance(probes, list):
                return False, {
                    "policy_reason": "service_manifest_no_match",
                    "selector": "probe",
                }
            for probe in probes:
                contract = _probe_contract(probe)
                matches = [
                    (index, service)
                    for index, service in relevant.items()
                    if contract is not None
                    and any(
                        _probe_contract(expected) == contract
                        for expected in service.get("expected_transactions", [])
                    )
                ]
                if not select_one("probe", matches):
                    return False, detail

        policy_field = (
            "allowed_automatic_actions" if automated else "approval_actions"
        )
        denied = sorted(
            str(service.get("service_id", ""))
            for service in relevant.values()
            if action_type not in service.get(policy_field, [])
        )
        if denied:
            return False, {
                "policy_reason": "service_manifest_action_not_authorized",
                "service_ids": denied,
                "service_policy": policy_field,
            }
        return True, {
            "service_ids": sorted(
                str(service.get("service_id", ""))
                for service in relevant.values()
            ),
            "service_policy": policy_field,
        }

    def _queue_action(
        self,
        agent_id: str,
        action_type: str,
        parameters: dict[str, Any],
        alert_id: str | None = None,
        *,
        automated: bool = False,
        authorization_code: str = "",
        authorization_subject: str | None = None,
    ) -> str | None:
        with self._governance_lock:
            return self._queue_action_locked(
                agent_id,
                action_type,
                parameters,
                alert_id,
                automated=automated,
                authorization_code=authorization_code,
                authorization_subject=authorization_subject,
            )

    def _queue_action_locked(
        self,
        agent_id: str,
        action_type: str,
        parameters: dict[str, Any],
        alert_id: str | None = None,
        *,
        automated: bool = False,
        authorization_code: str = "",
        authorization_subject: str | None = None,
    ) -> str | None:
        if action_type in PROCESS_SIGNAL_ACTIONS:
            validate_action_parameters(
                action_type, parameters, require_process_binding=True
            )
        binding = (
            self.store.agent_binding(
                agent_id,
                require_fresh=True,
                freshness_seconds=self.health_stale_after,
            )
            if self._strict_release_binding and self.store.path != ":memory:"
            else None
        )
        if (
            self._strict_release_binding
            and self.store.path != ":memory:"
            and binding is None
        ):
            if automated:
                return None
            raise PermissionError("agent release binding is not current and fresh")
        allowed = self.event_profile.action_allowed(
            action_type,
            automated=automated,
            autonomy_mode=self.autonomy_mode,
            emergency_stopped=self.emergency_stopped,
        )
        if not allowed:
            self.store.audit(
                "policy",
                "hold_action",
                str(alert_id or agent_id),
                {"action_type": action_type, "automated": automated, **self.governance_status()},
            )
            if automated:
                return None
            raise PermissionError("the current event profile, mode, or emergency stop forbids this action")
        manifest_allowed, manifest_detail = self._service_manifest_policy(
            agent_id,
            action_type,
            parameters,
            automated=automated,
        )
        if not manifest_allowed:
            self.store.audit(
                "policy",
                "hold_action",
                str(alert_id or agent_id),
                {
                    "action_type": action_type,
                    "automated": automated,
                    **manifest_detail,
                    **self.governance_status(),
                },
            )
            if automated:
                return None
            raise PermissionError(
                "the relevant confirmed service manifest does not authorize this action"
            )
        subject = authorization_subject or str(alert_id or action_type)
        requires_one_use_authorization = (
            not automated
            and action_risk(action_type) == "high"
            and self.event_profile.environment == "live-competition"
        )
        try:
            if requires_one_use_authorization:
                return self.store.queue_action_with_authorization(
                    authorization_code=authorization_code,
                    authorization_subject=subject,
                    agent_id=agent_id,
                    action_type=action_type,
                    parameters=parameters,
                    alert_id=alert_id,
                    automated=automated,
                    expires_at=time.time() + 300.0,
                    profile_id=self.event_profile.profile_id,
                    profile_fingerprint=self.event_profile.fingerprint,
                    autonomy_mode=self.autonomy_mode,
                    binding=binding,
                )
            return self.store.queue_action(
                agent_id,
                action_type,
                parameters,
                alert_id,
                automated=automated,
                expires_at=time.time() + 300.0,
                profile_id=self.event_profile.profile_id,
                profile_fingerprint=self.event_profile.fingerprint,
                autonomy_mode=self.autonomy_mode,
                binding=binding,
            )
        except ActionQuotaExceeded as exc:
            self.store.audit(
                "policy",
                "hold_action",
                str(alert_id or agent_id),
                {
                    "action_type": action_type,
                    "automated": automated,
                    "policy_reason": str(exc),
                    **self.governance_status(),
                },
            )
            if automated:
                return None
            raise PermissionError(
                "the per-agent outstanding-action queue is full"
            ) from exc

    def database_integrity(self, maximum_age: float = 60.0) -> str:
        now = time.monotonic()
        with self._integrity_lock:
            if (
                (
                    self._integrity_checked_at <= 0.0
                    or now - self._integrity_checked_at >= max(1.0, maximum_age)
                )
                and not self._integrity_refreshing
            ):
                self._integrity_value = self.store.integrity_check()
                self._integrity_checked_at = now
            return self._integrity_value

    def _refresh_database_integrity(self) -> None:
        try:
            value = self.store.integrity_check()
            if not isinstance(value, str) or not value:
                value = "error"
        except Exception:
            LOG.exception("asynchronous controller readiness check failed")
            value = "error"
        with self._integrity_lock:
            self._integrity_value = value
            self._integrity_checked_at = time.monotonic()
            self._integrity_refreshing = False

    def readiness(self, maximum_age: float = 60.0) -> dict[str, Any]:
        """Return a non-blocking, fail-closed database readiness snapshot."""
        now = time.monotonic()
        maximum = max(1.0, float(maximum_age))
        start_refresh = False
        with self._integrity_lock:
            checked_at = self._integrity_checked_at
            stale = checked_at <= 0.0 or now - checked_at >= maximum
            if stale and not self._integrity_refreshing:
                self._integrity_refreshing = True
                start_refresh = True
            value = self._integrity_value
            refreshing = self._integrity_refreshing
        if start_refresh:
            worker = threading.Thread(
                target=self._refresh_database_integrity,
                daemon=True,
                name="sentinel-readiness-integrity",
            )
            try:
                worker.start()
            except RuntimeError:
                with self._integrity_lock:
                    self._integrity_value = "error"
                    self._integrity_checked_at = time.monotonic()
                    self._integrity_refreshing = False
                value = "error"
                refreshing = False
        age = None if checked_at <= 0.0 else max(0.0, now - checked_at)
        recovery_ready = bool(
            not self.require_authenticated_recovery
            or (self.recovery_key is not None and self.recovery_anchor is not None)
        )
        ready = value == "ok" and not stale and recovery_ready
        return {
            "status": "ready" if ready else "not_ready",
            "version": __version__,
            "database": value,
            "cache_fresh": not stale,
            "refreshing": refreshing,
            "checked_age_seconds": None if age is None else round(age, 3),
            "authenticated_recovery": recovery_ready,
            "ready": ready,
        }

    def create_recovery_backup(self, directory: str | Path) -> dict[str, Any]:
        if self.recovery_key is None or self.recovery_anchor is None:
            raise RuntimeError("authenticated controller recovery is unavailable")
        from .recovery_ops import create_controller_backup

        return create_controller_backup(
            self.store,
            directory,
            self.recovery_anchor,
            self.recovery_key,
        )

    def restoration_probes_for_path(self, path: str) -> list[dict[str, Any]]:
        """Select only scorer/service probes explicitly associated with a path.

        Existing configurations with no restore_paths metadata retain their old
        all-probes behavior. Once any probe is scoped, unscoped probes are not
        used to authorize an automatic write.
        """
        scoped = [spec for spec in self.restoration_probes if "restore_paths" in spec]
        if not scoped:
            return [dict(spec) for spec in self.restoration_probes]
        normalized = path.replace("\\", "/")
        folded = normalized.casefold()
        selected: list[dict[str, Any]] = []
        for spec in scoped:
            patterns = spec.get("restore_paths", [])
            if any(
                fnmatchcase(folded, str(pattern).replace("\\", "/").casefold())
                for pattern in patterns
            ):
                selected.append(dict(spec))
        return selected

    def service_recovery_probes(
        self, agent_id: str, service_id: str
    ) -> list[dict[str, Any]]:
        """Return exact manifest transactions for one service recovery.

        A service manager's ``running`` state is not enough to prove that the
        application transaction recovered. Confirmed manifests define the
        probes a manually approved restart must pass. An absent or ambiguous
        mapping returns no probes so the existing manifest policy can reject
        the restart instead of guessing.
        """

        if not self.event_profile.services_confirmed:
            return []
        matches = [
            service
            for service in self.event_profile.services
            if service.get("host") == agent_id
            and service.get("service_id") == service_id
        ]
        if len(matches) != 1:
            return []
        return [
            dict(probe)
            for probe in matches[0].get("expected_transactions", [])
            if isinstance(probe, dict)
        ]

    def dashboard(self) -> dict[str, Any]:
        payload = self.store.dashboard(self.health_stale_after)
        agent_by_id = {
            str(item.get("agent_id", "")): item for item in payload["agents"]
        }
        expected_agents = {
            str(service.get("host", ""))
            for service in self.event_profile.services
            if service.get("host")
        }
        if not expected_agents:
            expected_agents = set(agent_by_id)
        restoration_blockers: dict[str, str] = {}
        for agent_id in sorted(expected_agents):
            agent = agent_by_id.get(agent_id)
            if agent is None:
                restoration_blockers[agent_id] = "agent_missing"
                continue
            if not agent.get("enabled", False):
                restoration_blockers[agent_id] = "agent_revoked"
                continue
            if self.store.latest_baseline_promotion(agent_id, pending_only=True):
                restoration_blockers[agent_id] = "baseline_promotion_pending"
                continue
            if agent.get("baseline_status") != "approved":
                restoration_blockers[agent_id] = "baseline_not_approved"
                continue
            binding = (
                self.store.agent_binding(
                    agent_id,
                    require_fresh=True,
                    freshness_seconds=self.health_stale_after,
                )
                if self._strict_release_binding and self.store.path != ":memory:"
                else None
            )
            if self._strict_release_binding and self.store.path != ":memory:" and binding is None:
                restoration_blockers[agent_id] = "agent_binding_not_current"
                continue
            baseline = self.store.get_baseline(agent_id, binding=binding) or {}
            if not baseline:
                restoration_blockers[agent_id] = "baseline_binding_not_current"
                continue
            if str(baseline.get("platform", "")).casefold().startswith("windows") and any(
                not item.get("security_descriptor_sha256")
                for item in baseline.get("integrity", [])
            ):
                restoration_blockers[agent_id] = "baseline_security_metadata_unapproved"
                continue
            if baseline.get("integrity"):
                try:
                    expected_files = baseline_capture_files(baseline)
                except (TypeError, ValueError, OverflowError):
                    restoration_blockers[agent_id] = "baseline_capture_scope_invalid"
                    continue
                capture = self.store.matching_capture_for_agent(
                    agent_id, expected_files, binding=binding
                )
                if capture is None:
                    restoration_blockers[agent_id] = "restore_point_missing"
                elif binding is not None and (
                    int(capture.get("credential_epoch", -1)),
                    str(capture.get("profile_id", "")),
                    str(capture.get("profile_fingerprint", "")),
                    str(capture.get("agent_version", "")),
                ) != self.store._binding_values(binding):
                    restoration_blockers[agent_id] = "restore_point_binding_mismatch"
                elif (capture.get("parameters") or {}).get("files") != expected_files:
                    restoration_blockers[agent_id] = "restore_point_scope_mismatch"
                elif capture_receipt_error(
                    expected_files, capture.get("result") or {}
                ) is not None:
                    restoration_blockers[agent_id] = "restore_point_capture_incomplete"
        restoration_blocked_agents = sorted(restoration_blockers)
        restoration_ready = bool(
            self.auto_restore and expected_agents and not restoration_blocked_agents
        )
        telemetry_by_agent = {
            str(item.get("agent_id", "")): item for item in self.store.latest_telemetry()
        }
        stored_json = self.store.stored_json_readiness()
        payload["stored_json"] = stored_json
        if not stored_json["ready"]:
            restoration_blockers["controller"] = "stored_json_quarantine"
            restoration_blocked_agents = sorted(restoration_blockers)
            restoration_ready = False
        for agent in payload["agents"]:
            agent["baseline_readiness"] = assess_baseline_readiness(
                telemetry_by_agent.get(str(agent["agent_id"]))
            )
        payload["topology"] = build_topology(
            list(telemetry_by_agent.values()), self.authorized_networks
        )
        payload["incidents"] = correlate(payload["alerts"])
        recovery_identity = (
            self.store.recovery_identity()
            if self.recovery_key is not None
            else None
        )
        payload["controller"] = {
            "version": __version__,
            "uptime_seconds": round(time.time() - self.started_at, 1),
            "database_integrity": self.database_integrity(),
            "enrollment_open": time.time() < self.enrollment_deadline,
            "authorized_networks": list(self.authorized_networks),
            "automatic_restoration": self.auto_restore,
            "automatic_restoration_ready": restoration_ready,
            "restoration_blocked_agents": restoration_blocked_agents,
            "restoration_blockers": restoration_blockers,
            "restore_confirmations": self.restore_confirmations,
            "allow_unprobed_restoration": self.allow_unprobed_restoration,
            "connection_pressure": self.connection_pressure_provider(),
            "credential_migration_blockers": self.credential_migration_blockers(),
            "stored_json_ready": stored_json["ready"],
            "authenticated_recovery": recovery_identity is not None,
            "recovery_generation": (
                None
                if recovery_identity is None
                else recovery_identity["recovery_generation"]
            ),
            "backup_sequence": (
                None
                if recovery_identity is None
                else recovery_identity["backup_sequence"]
            ),
            "governance": self.governance_status(),
        }
        payload["metrics"] = {
            "online_agents": sum(agent.get("health") == "online" for agent in payload["agents"]),
            "stale_agents": sum(agent.get("health") == "stale" for agent in payload["agents"]),
            "critical_alerts": sum(
                alert.get("status") == "open" and alert.get("severity") == "critical"
                for alert in payload["alerts"]
            ),
            "failed_actions": sum(action.get("status") == "failed" for action in payload["actions"]),
        }
        return payload

    def enroll(
        self,
        payload: dict[str, Any],
        *,
        authenticated_ticket: str | None = None,
    ) -> dict[str, str]:
        agent_id = validate_agent_id(payload["agent_id"])
        if agent_id in INTERNAL_AGENT_IDS:
            raise PermissionError("the requested agent identity is reserved by the controller")
        self._require_agent_binding(payload)
        agent_version = payload.get("agent_version", "")
        if self.store.path == ":memory:" and not agent_version:
            agent_version = __version__
        if self._strict_release_binding and agent_version != __version__:
            raise PermissionError("agent release version does not match the controller")
        hostname = payload.get("hostname", agent_id)
        platform_name = payload.get("platform", "unknown")
        if not isinstance(hostname, str) or not hostname or len(hostname) > 256:
            raise ValueError("enrollment hostname must be a bounded string")
        if not isinstance(platform_name, str) or not platform_name or len(platform_name) > 256:
            raise ValueError("enrollment platform must be a bounded string")
        if self._strict_release_binding:
            if agent_id not in self.enrollable_agent_ids:
                raise PermissionError("agent identity is outside the approved inventory")
            expected_ticket = derive_enrollment_ticket(
                self.token, self.event_profile.fingerprint, agent_id
            )
            supplied_ticket = authenticated_ticket
            if supplied_ticket is None and self.store.path == ":memory:":
                supplied_ticket = expected_ticket
            if not supplied_ticket or not hmac.compare_digest(
                supplied_ticket, expected_ticket
            ):
                raise PermissionError("a host-specific enrollment ticket is required")
            nonce = payload.get("enrollment_nonce")
            if self.store.path == ":memory:" and nonce is None:
                nonce = hashlib.sha256(
                    f"ephemeral-test:{agent_id}".encode()
                ).hexdigest()
            if (
                not isinstance(nonce, str)
                or len(nonce) != 64
                or any(character not in "0123456789abcdef" for character in nonce.casefold())
            ):
                raise ValueError("enrollment_nonce must be a 64-character hex value")
            request_sha256 = hashlib.sha256(
                canonical_json_bytes(payload)
            ).hexdigest()
            agent_token, _created = self.store.enroll_agent_once(
                agent_id=agent_id,
                hostname=hostname,
                platform=platform_name,
                agent_version=__version__,
                profile_id=self.event_profile.profile_id,
                profile_fingerprint=self.event_profile.fingerprint,
                ticket=supplied_ticket,
                request_sha256=request_sha256,
                deadline=self.enrollment_deadline,
                max_agents=self.max_agents,
            )
        else:
            # Even compatibility-mode enrollment uses the same single
            # transaction for deadline, quota, identity creation, credential
            # issuance, and exact retry.  The HTTP request is authenticated by
            # the shared bootstrap token, while this derived host key prevents
            # one host's consumed marker colliding with another's.
            internal_ticket = hmac.new(
                self.token.encode("utf-8"),
                (
                    "sentinel-blue-compat-enrollment-ticket-v1\x00"
                    f"{self.event_profile.fingerprint}\x00{agent_id}"
                ).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
            request_sha256 = hashlib.sha256(
                canonical_json_bytes(payload)
            ).hexdigest()
            agent_token, _created = self.store.enroll_agent_once(
                agent_id=agent_id,
                hostname=hostname,
                platform=platform_name,
                agent_version=str(agent_version),
                profile_id="",
                profile_fingerprint="",
                ticket=internal_ticket,
                request_sha256=request_sha256,
                deadline=self.enrollment_deadline,
                max_agents=self.max_agents,
            )
        return {"agent_id": agent_id, "agent_token": agent_token}

    def agent_token(self, agent_id: str) -> str:
        # A missing pre-1.0 credential must be repaired by controlled
        # re-enrollment.  Never recreate agent authority from bootstrap
        # enrollment material.
        if agent_id in INTERNAL_AGENT_IDS:
            raise PermissionError("controller-internal identities cannot authenticate over HTTP")
        secret = self.store.agent_secret(agent_id) or ""
        if not ENROLLMENT_TOKEN.fullmatch(secret):
            raise PermissionError(
                "agent credential is unavailable or invalid; offline migration is required"
            )
        return secret

    def ingest(
        self,
        payload: dict[str, Any],
        expected_agent_id: str | None = None,
        expected_agent_secret: str | None = None,
    ) -> list[str]:
        strict_external = (
            self._strict_release_binding
            and self.store.path != ":memory:"
            and str(payload.get("agent_id", "")) not in INTERNAL_AGENT_IDS
        )
        if strict_external:
            missing = {
                name
                for name in ("boot_id", "sequence", "queued_at")
                if name not in payload
            }
            if missing:
                raise ValueError(
                    "bound telemetry is missing: " + ", ".join(sorted(missing))
                )
            if payload.get("boot_id") in {"", "unknown"}:
                raise ValueError("bound telemetry requires an exact boot identifier")
        payload = validate_telemetry(payload, expected_agent_id)
        self._require_agent_binding(payload, include_version=True)
        agent_id = str(payload["agent_id"])
        processing_key: tuple[str, int, str, str, int, str] | None = None
        source_observation = _telemetry_observation(payload)
        observation_id = str(source_observation["payload_sha256"])
        if strict_external:
            if not expected_agent_secret:
                raise PermissionError("authenticated agent credential is required")
            with self._action_egress_lock:
                commit = self.store.commit_bound_telemetry(
                    agent_id,
                    payload,
                    expected_agent_secret=expected_agent_secret,
                    freshness_seconds=self.health_stale_after,
                    release_sha256=str(
                        self.event_profile.release.get("sha256", "")
                    ).casefold(),
                    model_fingerprint=self.model_fingerprint,
                    campaign_id=self.campaign_id,
                    feature_schema_sha256=MODEL_FEATURE_SCHEMA_SHA256,
                )
            if commit == "historical":
                # A signed 400 makes the agent move this payload into its
                # bounded rejected spool rather than deleting it as accepted.
                raise ValueError(
                    "historical telemetry is non-authoritative and was quarantined"
                )
            if commit == "processing_backlog":
                raise RuntimeError(
                    "prior telemetry derivatives are not durably complete"
                )
            if commit == "exact_retry":
                return []
            binding = self.store.agent_binding(
                agent_id,
                require_fresh=commit == "current",
                freshness_seconds=self.health_stale_after,
                validate_current_telemetry=True,
            )
            if binding is None:
                raise PermissionError("telemetry did not establish a current release binding")
            processing_key = (
                agent_id,
                int(binding["credential_epoch"]),
                str(payload["profile_fingerprint"]),
                str(payload["boot_id"]),
                int(payload["sequence"]),
                observation_id,
            )
        else:
            self.store.register_agent(
                agent_id,
                str(payload.get("hostname", agent_id)),
                str(payload.get("platform", "unknown")),
                touch_last_seen=False,
            )
            if not self.store.save_telemetry(
                agent_id, payload, expected_agent_secret=expected_agent_secret
            ):
                return []
            binding = None
        if not strict_external or commit == "current":
            self.store.resolve_heartbeat_alerts(agent_id, binding=binding)
        baseline = self.store.get_baseline(agent_id, binding=binding)
        baseline_status = self.store.baseline_status(agent_id, binding=binding)
        protected = self.store.protected_accounts(agent_id)
        candidates, candidate_summary = prioritize_detection_candidates(
            detect(payload, baseline, protected, self.model)
        )
        if candidate_summary["suppressed_candidates"]:
            self.store.audit(
                "controller",
                "ingest_candidate_overflow",
                agent_id,
                candidate_summary,
            )
        if baseline and baseline_status != "approved":
            for candidate in candidates:
                if candidate.kind in {
                    "baseline_service_stopped",
                    "critical_file_changed",
                    "default_route_changed",
                    "new_network_listener",
                }:
                    candidate.recommended_action = "snapshot"
                    candidate.recommendation += (
                        " This baseline is still pending approval, so configuration-changing "
                        "recovery is disabled."
                    )
        if baseline is None:
            self.store.create_baseline(agent_id, payload, binding)
        alert_ids: list[str] = []
        alert_quota_by_kind: Counter[str] = Counter()
        alert_quota_by_severity: Counter[str] = Counter()
        for candidate in candidates:
            if candidate.recommended_action == "quarantine_session":
                try:
                    bound_parameters = _bound_process_action_parameters(
                        "quarantine_session",
                        candidate.evidence.get("session"),
                        source_observation,
                    )
                except (TypeError, ValueError):
                    candidate.recommended_action = "snapshot"
                    candidate.evidence["restriction_supported"] = False
                    candidate.evidence[
                        "automation_hold"
                    ] = "incomplete_process_action_binding"
                    candidate.recommendation += (
                        " Session containment is held because an exact immutable "
                        "process and telemetry observation binding is unavailable."
                    )
                else:
                    candidate.evidence["session"] = bound_parameters["session"]
                    candidate.evidence["observation"] = bound_parameters[
                        "observation"
                    ]
            restoration_eligible = False
            if (
                candidate.kind == "critical_file_changed"
                and baseline
                and baseline_status == "approved"
            ):
                path = str(candidate.evidence.get("path", ""))
                if candidate.evidence.get("security_baseline_upgrade"):
                    candidate.recommended_action = "snapshot"
                    candidate.recommendation += (
                        " Security metadata was not present in the approved legacy baseline; "
                        "automatic restoration is held until an operator explicitly promotes it."
                    )
                    candidate.evidence[
                        "automation_hold"
                    ] = "baseline_security_metadata_unapproved"
                else:
                    grant = self.store.consume_change_grant(
                        agent_id,
                        path,
                        candidate.evidence.get("change_observation_sha256"),
                        binding=binding,
                    )
                    if grant:
                        candidate.recommended_action = "snapshot"
                        candidate.recommendation += (
                            " A signed one-use change grant is active for this exact path and "
                            "security state, so automatic restoration is paused until the team "
                            "accepts or rejects the change."
                        )
                        candidate.evidence["change_grant_id"] = grant["grant_id"]
                    elif self.auto_restore:
                        selected_probes = self.restoration_probes_for_path(path)
                        candidate.evidence["probes"] = selected_probes
                        if selected_probes or self.allow_unprobed_restoration:
                            restoration_eligible = True
                            candidate.recommendation += (
                                f" Automatic restoration requires {self.restore_confirmations} "
                                "matching observation(s) before it is dispatched."
                            )
                        else:
                            candidate.evidence["automation_hold"] = "no_applicable_service_probe"
                            candidate.recommendation += (
                                " Automatic restoration is held because no service/scoring probe "
                                "is mapped to this path."
                            )
            alert_id = self.store.add_alert(
                agent_id,
                candidate,
                binding=binding,
                release_sha256=str(
                    self.event_profile.release.get("sha256", "")
                ).casefold(),
                model_fingerprint=self.model_fingerprint,
                campaign_id=self.campaign_id,
                observation_id=observation_id,
            )
            if alert_id is None:
                alert_quota_by_kind[str(candidate.kind)] += 1
                alert_quota_by_severity[str(candidate.severity).casefold()] += 1
                continue
            alert_ids.append(alert_id)
            current_alert = self.store.get_alert(alert_id)
            if current_alert is None or current_alert["status"] != "open":
                # A recently decided duplicate is intentionally suppressed;
                # it is not new authority for automation.
                continue
            if (
                restoration_eligible
                and self.store.alert_occurrence_count(alert_id) >= self.restore_confirmations
                and self.store.action_for_alert(alert_id, "restore_integrity") is None
            ):
                self._queue_action(
                    agent_id,
                    "restore_integrity",
                    dict(candidate.evidence),
                    alert_id,
                    automated=True,
                )
            elif should_automate_evidence(candidate.recommended_action, candidate.severity):
                self._queue_action(
                    agent_id,
                    candidate.recommended_action,
                    dict(candidate.evidence),
                    alert_id,
                    automated=True,
                )
        suppressed_alerts = sum(alert_quota_by_kind.values())
        if suppressed_alerts:
            self.store.audit(
                "controller",
                "ingest_alert_overflow",
                agent_id,
                {
                    "suppressed_alerts": suppressed_alerts,
                    "suppressed_by_kind": dict(sorted(alert_quota_by_kind.items())),
                    "suppressed_by_severity": dict(
                        sorted(alert_quota_by_severity.items())
                    ),
                    "reason": "per_agent_open_alert_quota",
                },
            )
        if processing_key is not None and not self.store.mark_telemetry_processed(
            *processing_key
        ):
            raise RuntimeError("telemetry derivative checkpoint changed concurrently")
        return alert_ids

    def resume_pending_telemetry(self, limit: int = 32) -> int:
        """Finish crash-interrupted detection/baseline/alert derivation."""
        resumed = 0
        for item in self.store.pending_telemetry_processing(limit=limit):
            try:
                agent_id = str(item["agent_id"])
                secret = self.store.agent_secret(agent_id)
                if not secret or not self.store.agent_enabled(agent_id):
                    continue
                self.ingest(
                    dict(item["telemetry"]),
                    expected_agent_id=agent_id,
                    expected_agent_secret=secret,
                )
                resumed += 1
            except Exception as exc:
                self.store.record_telemetry_processing_failure(
                    item, f"{type(exc).__name__}: {exc}"
                )
                LOG.warning(
                    "held failed telemetry derivative checkpoint for %s: %s",
                    item.get("agent_id", "unknown"),
                    type(exc).__name__,
                )
        return resumed

    def decision(
        self,
        alert_id: str,
        decision: str,
        authorization_code: str = "",
        *,
        reviewer_principal_id: str = "operator",
    ) -> dict[str, Any] | None:
        with self._decision_lock:
            return self._decision(
                alert_id,
                decision,
                authorization_code,
                reviewer_principal_id=reviewer_principal_id,
            )

    def _decision(
        self,
        alert_id: str,
        decision: str,
        authorization_code: str = "",
        *,
        reviewer_principal_id: str = "operator",
    ) -> dict[str, Any] | None:
        allowed = {
            "approve",
            "observe",
            "reject",
            "mark_protected",
            "accept_change",
        }
        if decision not in allowed:
            raise ValueError(f"unsupported decision: {decision}")
        row = self.store.get_alert(alert_id)
        if row is None or row["status"] != "open":
            return None
        requires_fresh_authority = decision not in {"observe", "reject"}
        binding = (
            self.store.agent_binding(
                str(row["agent_id"]),
                require_fresh=requires_fresh_authority,
                freshness_seconds=self.health_stale_after,
            )
            if self._strict_release_binding and self.store.path != ":memory:"
            else None
        )
        if self._strict_release_binding and self.store.path != ":memory:":
            if binding is None or (
                int(row["credential_epoch"]),
                str(row["profile_id"]),
                str(row["profile_fingerprint"]),
                str(row["agent_version"]),
            ) != self.store._binding_values(binding):
                raise PermissionError(
                    "alert authority does not match the current agent release binding"
                )
        learning_lineage = self.store.alert_learning_lineage(alert_id)
        if (
            decision in {"approve", "mark_protected", "reject"}
            and self._strict_release_binding
            and self.store.path != ":memory:"
            and learning_lineage is None
        ):
            raise PermissionError(
                "the alert has no immutable displayed learning occurrence"
            )
        evidence = strict_json_loads(
            str(row["evidence_json"]), max_bytes=CONTROLLER_MAX_REQUEST_BYTES
        )
        if not isinstance(evidence, dict):
            raise ValueError("stored alert evidence is not an object")
        account = evidence.get("account", {}).get("name") or evidence.get("session", {}).get("username")
        result: dict[str, Any]
        if decision == "mark_protected" and account:
            self.store.protect_account(row["agent_id"], account, "competition-protected")
            result = {"status": "protected", "account": account}
        elif decision == "accept_change":
            if row["kind"] != "critical_file_changed":
                raise ValueError("accept_change is only valid for monitored file changes")
            current = evidence.get("current")
            if not isinstance(current, dict) or not current.get("sha256"):
                raise ValueError("a missing protected file cannot be accepted as a new restore point")
            age = time.time() - float(row["created_at"])
            if age < self.event_profile.recovery_promotion_delay_seconds:
                raise PermissionError(
                    "the recovery baseline promotion delay has not elapsed"
                )
            latest = next(
                (
                    item
                    for item in self.store.latest_telemetry()
                    if str(item.get("agent_id", "")) == str(row["agent_id"])
                ),
                None,
            )
            readiness = assess_baseline_readiness(latest)
            if not readiness["ready"]:
                raise PermissionError("healthy local and external validation is required before promotion")
            if not self.event_profile.action_allowed(
                "capture_restore_point",
                automated=True,
                autonomy_mode=self.autonomy_mode,
                emergency_stopped=self.emergency_stopped,
            ):
                raise PermissionError("the current governance mode forbids baseline promotion")
            baseline = self.store.get_baseline(
                str(row["agent_id"]), binding=binding
            )
            if not baseline or self.store.baseline_status(
                str(row["agent_id"]), binding=binding
            ) != "approved":
                raise ValueError("approved baseline is unavailable")
            candidate = dict(baseline)
            candidate["integrity"] = [
                item
                for item in baseline.get("integrity", [])
                if isinstance(item, dict)
                and str(item.get("path", "")) != str(current.get("path", ""))
            ] + [dict(current)]
            files_to_capture = baseline_capture_files(candidate)
            manifest_allowed, _ = self._service_manifest_policy(
                str(row["agent_id"]),
                "capture_restore_point",
                {"files": files_to_capture},
                automated=True,
            )
            if not manifest_allowed:
                raise PermissionError(
                    "the confirmed service manifest does not authorize the full baseline capture"
                )
            with self._governance_lock:
                if not self.event_profile.action_allowed(
                    "capture_restore_point",
                    automated=True,
                    autonomy_mode=self.autonomy_mode,
                    emergency_stopped=self.emergency_stopped,
                ):
                    raise PermissionError(
                        "the current governance mode forbids baseline promotion"
                    )
                promotion = self.store.begin_baseline_promotion(
                    str(row["agent_id"]),
                    candidate,
                    latest,
                    source="accepted_change",
                    alert_id=alert_id,
                    binding=binding,
                    expires_at=time.time() + 300.0,
                    profile_id=self.event_profile.profile_id,
                    profile_fingerprint=self.event_profile.fingerprint,
                    autonomy_mode=self.autonomy_mode,
                )
            result = {
                "status": "promotion_pending",
                "promotion_id": promotion["promotion_id"],
                "action_id": promotion["action_id"],
            }
        elif decision == "approve":
            action_type = str(row["recommended_action"])
            parameters = (
                _bound_process_action_parameters(
                    action_type,
                    evidence.get("session"),
                    evidence.get("observation"),
                )
                if action_type in PROCESS_SIGNAL_ACTIONS
                else dict(evidence)
            )
            if action_type == "restart_service" and "probes" not in parameters:
                parameters["probes"] = self.service_recovery_probes(
                    str(row["agent_id"]), str(parameters.get("service", ""))
                )
            action_id = self._queue_action(
                row["agent_id"], action_type, parameters, alert_id,
                authorization_code=authorization_code,
            )
            result = {"status": "queued", "action_id": action_id}
        else:
            result = {"status": "recorded", "decision": decision}
        if decision == "accept_change":
            # The alert remains open authority until the exact aggregate
            # restore-point result promotes the candidate transactionally.
            return result
        if decision in {"approve", "mark_protected", "reject"}:
            if learning_lineage is not None:
                decided = self.store.decide_alert_with_learning_label(
                    alert_id,
                    decision,
                    1 if decision == "approve" else 0,
                    occurrence_id=str(
                        learning_lineage["creation_occurrence_id"]
                    ),
                    reviewer_principal_id=reviewer_principal_id,
                    label_source="operator-decision",
                    binding=binding,
                )
            else:
                # Only ephemeral compatibility fixtures can lack occurrence
                # lineage.  Deployable learning always uses the branch above.
                decided = self.store.decide_alert_with_feedback(
                    alert_id,
                    decision,
                    str(row["kind"]),
                    1 if decision == "approve" else 0,
                    features_for_kind(str(row["kind"])),
                    binding=binding,
                    reviewer_principal_id=reviewer_principal_id,
                )
        else:
            decided = self.store.decide_alert(
                alert_id, decision, binding=binding
            )
        if decided is None:
            raise RuntimeError("alert decision changed concurrently")
        return result

    def approve_baseline(self, agent_id: str) -> dict[str, Any] | None:
        agent_id = validate_agent_id(agent_id)
        if self.event_profile.environment == "live-competition" and not self.event_profile.services_confirmed:
            raise PermissionError("live baseline approval requires confirmed service manifests")
        binding = (
            self.store.agent_binding(
                agent_id,
                require_fresh=True,
                freshness_seconds=self.health_stale_after,
            )
            if self._strict_release_binding and self.store.path != ":memory:"
            else None
        )
        if self._strict_release_binding and self.store.path != ":memory:" and binding is None:
            raise PermissionError("agent release binding is not current and fresh")
        if self.store.baseline_status(agent_id, binding=binding) != "pending":
            return None
        latest = self.store.latest_telemetry_for_agent(agent_id)
        readiness = assess_baseline_readiness(latest)
        if not latest or not readiness["ready"]:
            raise PermissionError(
                "baseline approval requires healthy collection and service validation"
            )
        files_to_capture = baseline_capture_files(latest)
        with self._governance_lock:
            if not self.event_profile.action_allowed(
                "capture_restore_point",
                automated=True,
                autonomy_mode=self.autonomy_mode,
                emergency_stopped=self.emergency_stopped,
            ):
                raise PermissionError(
                    "the current governance mode forbids baseline promotion"
                )
            if files_to_capture:
                manifest_allowed, _ = self._service_manifest_policy(
                    agent_id,
                    "capture_restore_point",
                    {"files": files_to_capture},
                    automated=True,
                )
                if not manifest_allowed:
                    raise PermissionError(
                        "the confirmed service manifest does not authorize the full baseline capture"
                    )
            promotion = self.store.begin_baseline_promotion(
                agent_id,
                latest,
                latest,
                source="initial",
                binding=binding,
                expires_at=time.time() + 300.0,
                profile_id=self.event_profile.profile_id,
                profile_fingerprint=self.event_profile.fingerprint,
                autonomy_mode=self.autonomy_mode,
            )
        completed = promotion["status"] == "completed"
        return {
            "approved": completed,
            "promotion_pending": not completed,
            "promotion_id": promotion["promotion_id"],
            "restore_point_action_id": promotion["action_id"],
        }

    def abort_baseline_promotion(self, agent_id: str) -> dict[str, Any] | None:
        return self.store.abort_baseline_promotion(validate_agent_id(agent_id))

    def authorize_change(self, payload: dict[str, Any]) -> dict[str, Any]:
        agent_id = validate_agent_id(str(payload.get("agent_id", "")))
        path = str(payload.get("path", ""))
        ttl = float(payload.get("ttl_seconds", 300.0))
        absolute = PurePosixPath(path).is_absolute() or PureWindowsPath(path).is_absolute()
        if not path or not absolute or len(path) > 1024 or "\x00" in path:
            raise ValueError("change grant requires an exact absolute path")
        binding = (
            self.store.agent_binding(
                agent_id,
                require_fresh=True,
                freshness_seconds=self.health_stale_after,
            )
            if self._strict_release_binding and self.store.path != ":memory:"
            else None
        )
        if self._strict_release_binding and self.store.path != ":memory:" and binding is None:
            raise PermissionError("agent release binding is not current and fresh")
        grant_id = self.store.create_change_grant(
            agent_id, path, ttl, binding=binding
        )
        return {"grant_id": grant_id, "agent_id": agent_id, "path": path, "ttl_seconds": max(30.0, min(ttl, 900.0))}

    def import_protected_accounts(self, payload: dict[str, Any]) -> int:
        accounts = payload.get("accounts")
        if not isinstance(accounts, list):
            raise ValueError("accounts must be an array")
        if len(accounts) > 2048:
            raise ValueError("protected account manifest exceeds 2,048 entries")
        imported = 0
        for item in accounts:
            if not isinstance(item, dict) or not str(item.get("name", "")).strip():
                raise ValueError("each protected account requires a name")
            agent_id = str(item.get("agent_id", "*"))
            if agent_id != "*":
                agent_id = validate_agent_id(agent_id)
            name = str(item["name"]).strip()
            if len(name) > 128 or any(ord(character) < 32 for character in name):
                raise ValueError("protected account name is invalid")
            role = str(item.get("role", "competition-protected"))
            if len(role) > 128:
                raise ValueError("protected account role is too long")
            self.store.protect_account(
                agent_id,
                name,
                role,
                str(item.get("source", "manifest")),
            )
            imported += 1
        return imported

    def complete_action(
        self,
        payload: dict[str, Any],
        expected_agent_id: str | None = None,
    ) -> str | None:
        payload = validate_action_result(
            payload, require_envelope_sha256=self._strict_release_binding
        )
        action_id = str(payload["action_id"])
        return self.store.complete_action(action_id, payload, expected_agent_id)

    def reconcile_action_outcome(
        self,
        action_id: str,
        resolution: str,
    ) -> dict[str, Any] | None:
        return self.store.reconcile_action_outcome(action_id, resolution)

    def monitor_stale_agents(self, threshold_seconds: float) -> list[str]:
        alert_ids: list[str] = []
        for agent in self.store.stale_agents(threshold_seconds):
            binding = (
                self.store.agent_binding(str(agent["agent_id"]), require_fresh=False)
                if self._strict_release_binding and self.store.path != ":memory:"
                else None
            )
            if (
                self._strict_release_binding
                and self.store.path != ":memory:"
                and binding is None
            ):
                continue
            alert_id = self.store.add_alert(
                str(agent["agent_id"]),
                AlertCandidate(
                    kind="agent_heartbeat_missing",
                    title="Host agent stopped reporting",
                    summary=(
                        f"{agent['hostname']} has not reported for "
                        f"{int(time.time() - float(agent['last_seen']))} seconds."
                    ),
                    severity="high",
                    confidence=0.98,
                    evidence={"agent": agent, "threshold_seconds": threshold_seconds},
                    recommendation=(
                        "Check host reachability and the Sentinel Blue service. Treat telemetry "
                        "from this system as unknown until reporting resumes."
                    ),
                    recommended_action="observe",
                ),
                binding=binding,
                release_sha256=str(
                    self.event_profile.release.get("sha256", "")
                ).casefold(),
                model_fingerprint=self.model_fingerprint,
                campaign_id=self.campaign_id,
            )
            if alert_id is not None:
                alert_ids.append(alert_id)
        return alert_ids

    def release_action(
        self, action_id: str, authorization_code: str = ""
    ) -> dict[str, Any] | None:
        # Governance first, then Store, is the same lock order as ordinary
        # dispatch.  Holding both through validation and queueing prevents a
        # credential/profile rotation from rebinding historical recovery data.
        with self._governance_lock, self.store._lock:
            action = self.store.get_action(action_id)
            if not action or action["action_type"] != "quarantine_session":
                return None
            result = action.get("result")
            if (
                action.get("status") != "completed"
                or action.get("result_source") != "agent"
                or not isinstance(result, dict)
                or result.get("success") is not True
                or result.get("dry_run") is True
                or result.get("rolled_back") is True
                or result.get("interrupted") is True
                or not isinstance(result.get("record"), dict)
            ):
                return None
            agent_id = str(action["agent_id"])
            record = result["record"]
            original_parameters = action.get("parameters")
            if not isinstance(original_parameters, dict):
                raise PermissionError(
                    "completed quarantine lacks immutable process authority"
                )
            original = _bound_process_action_parameters(
                "quarantine_session",
                original_parameters.get("session"),
                original_parameters.get("observation"),
            )
            record_session = {
                field: (
                    dict(record[field])
                    if field == "process_identity"
                    and isinstance(record.get(field), dict)
                    else record.get(field)
                )
                for field in PROCESS_SESSION_FIELDS
            }
            if (
                record.get("status") != "active"
                or record_session != original["session"]
                or record.get("target_observation") != original["observation"]
                or record.get("boot_id") != original["observation"]["boot_id"]
            ):
                raise PermissionError(
                    "completed quarantine does not attest the exact approved target"
                )
            execution_observation = record.get("execution_observation")
            execution = _bound_process_action_parameters(
                "release_quarantine", record_session, execution_observation
            )["observation"]
            if (
                execution["boot_id"] != original["observation"]["boot_id"]
                or execution["sequence"] < original["observation"]["sequence"]
                or (
                    execution["sequence"] == original["observation"]["sequence"]
                    and execution["payload_sha256"]
                    != original["observation"]["payload_sha256"]
                )
            ):
                raise PermissionError(
                    "completed quarantine execution provenance is inconsistent"
                )
            binding = (
                self.store.agent_binding(
                    agent_id,
                    require_fresh=True,
                    freshness_seconds=self.health_stale_after,
                    validate_current_telemetry=True,
                )
                if self._strict_release_binding and self.store.path != ":memory:"
                else None
            )
            if self._strict_release_binding and self.store.path != ":memory:":
                if binding is None or (
                    int(action["credential_epoch"]),
                    str(action["profile_id"]),
                    str(action["profile_fingerprint"]),
                    str(action["agent_version"]),
                ) != self.store._binding_values(binding):
                    return None
            latest = self.store.latest_telemetry_for_agent(agent_id)
            if latest is None:
                raise PermissionError(
                    "fresh telemetry is required before releasing quarantine"
                )
            try:
                latest = validate_telemetry(latest, expected_agent_id=agent_id)
            except ValueError as exc:
                raise PermissionError(
                    "latest telemetry cannot authorize a process signal"
                ) from exc
            latest_observation = _telemetry_observation(latest)
            if (
                latest_observation["boot_id"] != execution["boot_id"]
                or latest_observation["sequence"] <= execution["sequence"]
                or latest_observation["payload_sha256"]
                == execution["payload_sha256"]
            ):
                raise PermissionError(
                    "a newer same-boot telemetry observation is required before release"
                )
            matches = [
                session
                for session in latest.get("sessions", [])
                if all(
                    session.get(field) == record_session.get(field)
                    for field in PROCESS_SESSION_FIELDS
                )
            ]
            if len(matches) != 1:
                raise PermissionError(
                    "the quarantined session is absent or ambiguous in fresh telemetry"
                )
            release_parameters = _bound_process_action_parameters(
                "release_quarantine", matches[0], latest_observation
            )
            release_id = self._queue_action_locked(
                agent_id,
                "release_quarantine",
                release_parameters,
                None,
                authorization_code=authorization_code,
                authorization_subject=action_id,
            )
        return {"status": "queued", "action_id": release_id}

    def rollback_action(
        self, action_id: str, authorization_code: str = ""
    ) -> dict[str, Any] | None:
        with self._governance_lock, self.store._lock:
            action = self.store.get_action(action_id)
            if not action or action["action_type"] not in {
                "restart_service", "restore_integrity"
            }:
                return None
            result = action.get("result")
            pre_state = result.get("pre_state") if isinstance(result, dict) else None
            if (
                action.get("status") != "completed"
                or action.get("result_source") != "agent"
                or not isinstance(result, dict)
                or result.get("success") is not True
                or result.get("dry_run") is True
                or result.get("rolled_back") is True
                or result.get("interrupted") is True
                or not isinstance(pre_state, dict)
            ):
                return None
            agent_id = str(action["agent_id"])
            binding = (
                self.store.agent_binding(
                    agent_id,
                    require_fresh=True,
                    freshness_seconds=self.health_stale_after,
                )
                if self._strict_release_binding and self.store.path != ":memory:"
                else None
            )
            if self._strict_release_binding and self.store.path != ":memory:":
                if binding is None or (
                    int(action["credential_epoch"]),
                    str(action["profile_id"]),
                    str(action["profile_fingerprint"]),
                    str(action["agent_version"]),
                ) != self.store._binding_values(binding):
                    return None
            rollback_type = (
                "rollback_service"
                if action["action_type"] == "restart_service"
                else "rollback_integrity"
            )
            rollback_parameters = dict(pre_state)
            if rollback_type == "rollback_integrity":
                original_parameters = action.get("parameters")
                if isinstance(original_parameters, dict):
                    for name in ("path", "probes"):
                        if name in original_parameters:
                            rollback_parameters[name] = original_parameters[name]
            rollback_id = self._queue_action_locked(
                agent_id,
                rollback_type,
                rollback_parameters,
                None,
                authorization_code=authorization_code,
                authorization_subject=action_id,
            )
        return {"status": "queued", "action_id": rollback_id}


def make_handler(app: ControllerApp) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = f"SentinelBlue/{__version__}"
        protocol_version = "HTTP/1.0"

        def log_message(self, format_string: str, *args: object) -> None:
            message = (format_string % args).translate(CONTROL_CHARACTER_TRANSLATION)
            LOG.debug(
                "%s - %s",
                self.address_string(),
                message[:MAX_ACCESS_LOG_MESSAGE],
            )

        def _deadline_expired(self) -> bool:
            server = getattr(self, "server", None)
            connection = getattr(self, "connection", None)
            return (
                isinstance(server, ControllerServer)
                and connection is not None
                and server.request_deadline_expired(connection)
            )

        def log_error(self, format_string: str, *args: object) -> None:
            if self._deadline_expired():
                return
            if format_string.startswith("Request timed out") and isinstance(
                self.server, ControllerServer
            ):
                self.server._record_expected_connection_failure("request_timeout")
                return
            if isinstance(self.server, ControllerServer):
                self.server._record_expected_connection_failure("http_protocol_error")
                return
            super().log_error(format_string, *args)

        def _validated_post_length(self, maximum: int) -> int:
            if self.headers.get_all("Transfer-Encoding"):
                raise ValueError("Transfer-Encoding is not supported")
            if self.headers.get_all("Content-Encoding"):
                raise ValueError("Content-Encoding is not supported")
            lengths = self.headers.get_all("Content-Length") or []
            if len(lengths) != 1:
                raise ValueError("exactly one Content-Length header is required")
            raw_length = lengths[0]
            if (
                not isinstance(raw_length, str)
                or len(raw_length) > 10
                or not CANONICAL_CONTENT_LENGTH.fullmatch(raw_length)
            ):
                raise ValueError("Content-Length must be a canonical decimal integer")
            try:
                length = int(raw_length)
            except (TypeError, ValueError) as exc:
                raise ValueError("invalid Content-Length") from exc
            if length > maximum:
                raise ValueError("request body too large")
            self._require_json_content_type()
            return length

        def _read_body(self, maximum: int) -> bytes:
            length = self._validated_post_length(maximum)
            chunks: list[bytes] = []
            remaining = length
            while remaining:
                chunk = self.rfile.read(remaining)
                if not chunk:
                    raise ValueError("request body ended before Content-Length bytes arrived")
                chunks.append(chunk)
                remaining -= len(chunk)
            return b"".join(chunks)

        def _require_json_content_type(self) -> None:
            values = self.headers.get_all("Content-Type") or []
            if len(values) != 1:
                raise ValueError("exactly one Content-Type header is required")
            value = values[0].strip().casefold()
            if value not in JSON_CONTENT_TYPES:
                raise ValueError("Content-Type must be application/json using UTF-8")

        @staticmethod
        def _decode_json_body(body: bytes) -> dict[str, Any]:
            payload = strict_json_loads(
                body or b"{}", max_bytes=CONTROLLER_MAX_REQUEST_BYTES
            )
            if not isinstance(payload, dict):
                raise ValueError("JSON request body must be an object")
            return payload

        def _json(self, status: int, payload: Any, response_token: str | None = None) -> None:
            try:
                body = canonical_json_bytes(payload)
            except ValueError as exc:
                if "exceed" in str(exc).casefold():
                    status = HTTPStatus.SERVICE_UNAVAILABLE
                    body = canonical_json_bytes(EGRESS_LIMIT_ERROR)
                else:
                    LOG.error("controller refused to serialize a non-JSON response")
                    status = HTTPStatus.INTERNAL_SERVER_ERROR
                    body = canonical_json_bytes({"error": "internal serialization error"})
            if len(body) > MAX_AGENT_EGRESS_BYTES:
                status = HTTPStatus.SERVICE_UNAVAILABLE
                body = canonical_json_bytes(EGRESS_LIMIT_ERROR)
            if (
                response_token is None
                and urlparse(self.path).path.startswith("/api/v1/agent/")
            ):
                response_token = getattr(self, "_agent_response_token", None)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            if response_token:
                timestamp = str(time.time())
                request_signature = getattr(self, "_agent_request_signature", "")
                self.send_header("X-SB-Response-Timestamp", timestamp)
                self.send_header("X-SB-Response-Version", "2")
                self.send_header(
                    "X-SB-Response-Signature",
                    response_signature(
                        response_token,
                        timestamp,
                        int(status),
                        self.path,
                        request_signature,
                        body,
                    ),
                )
            self.end_headers()
            self.wfile.write(body)

        def _single_agent_header(self, name: str, maximum: int) -> str | None:
            values = self.headers.get_all(name) or []
            if len(values) != 1 or not isinstance(values[0], str):
                return None
            value = values[0]
            if (
                not value
                or len(value) > maximum
                or value != value.strip()
                or any(
                    ord(character) < 0x21 or ord(character) == 0x7F
                    for character in value
                )
            ):
                return None
            return value

        def _authenticated(self, body: bytes, enrollment: bool = False) -> bool:
            self._agent_request_signature = ""
            timestamp = self._single_agent_header("X-SB-Timestamp", 64)
            supplied = self._single_agent_header("X-SB-Signature", 64)
            raw_agent_id = self._single_agent_header("X-SB-Agent", 128)
            if timestamp is None or supplied is None or raw_agent_id is None:
                return False
            try:
                agent_id = validate_agent_id(raw_agent_id)
            except ValueError:
                return False
            if agent_id in INTERNAL_AGENT_IDS:
                return False
            if (
                enrollment
                and app._strict_release_binding
                and agent_id not in app.enrollable_agent_ids
            ):
                return False
            try:
                auth_snapshot = app.store.agent_http_auth_snapshot(agent_id)
            except (OSError, sqlite3.Error, ValueError):
                LOG.error("agent authentication snapshot failed closed")
                return False
            if enrollment:
                token = (
                    derive_enrollment_ticket(
                        app.token, app.event_profile.fingerprint, agent_id
                    )
                    if app._strict_release_binding
                    else app.token
                )
                expected_credential_epoch = (
                    -1
                    if auth_snapshot is None
                    else int(auth_snapshot["credential_epoch"])
                )
            else:
                if auth_snapshot is None or auth_snapshot["enabled"] is not True:
                    return False
                token = str(auth_snapshot["agent_secret"])
                if not ENROLLMENT_TOKEN.fullmatch(token):
                    return False
                expected_credential_epoch = int(
                    auth_snapshot["credential_epoch"]
                )
            auth_now = time.time()
            valid = verify(
                token,
                timestamp,
                self.command,
                self.path,
                body,
                supplied,
                now=auth_now,
            )
            if not valid:
                return False
            try:
                admission = app.store.admit_http_request(
                    agent_id,
                    supplied,
                    timestamp,
                    auth_kind="enrollment" if enrollment else "agent",
                    expected_credential_epoch=expected_credential_epoch,
                    expected_agent_secret=None if enrollment else token,
                    max_entries=REPLAY_MARKERS_PER_PRINCIPAL,
                    max_principals=app.max_agents + 1,
                    max_clock_skew=MAX_CLOCK_SKEW_SECONDS,
                    now=auth_now,
                )
            except (OSError, sqlite3.Error, ValueError):
                LOG.error("persistent request replay admission failed closed")
                return False
            accepted = admission == "accepted"
            if accepted:
                self._agent_response_token = token
                self._agent_request_signature = supplied
            return accepted

        def _operator_authenticated(self, body: bytes = b"") -> bool:
            """Verify and durably admit one signed operator request."""
            self._operator_context = None
            self._operator_auth_status = HTTPStatus.UNAUTHORIZED
            auth_now = time.time()
            try:
                context = authenticate_operator_request(
                    app.operator_token,
                    self.headers,
                    self.command,
                    self.path,
                    body,
                    expected_principal=app.operator_principal_id,
                    expected_credential_epoch=app.operator_credential_epoch,
                    max_clock_skew=OPERATOR_MAX_CLOCK_SKEW_SECONDS,
                    now=auth_now,
                )
            except OperatorAuthenticationError:
                return False
            try:
                admission = app.store.admit_operator_request(
                    principal_id=context.principal_id,
                    credential_epoch=context.credential_epoch,
                    request_id=context.request_id,
                    marker_sha256=context.marker_sha256,
                    request_timestamp=context.request_timestamp,
                    expected_key_fingerprint=app.operator_key_fingerprint,
                    method=self.command,
                    target=self.path,
                    max_entries=OPERATOR_REPLAY_MARKERS,
                    max_clock_skew=OPERATOR_MAX_CLOCK_SKEW_SECONDS,
                    now=auth_now,
                )
            except (OSError, sqlite3.Error, UnicodeError, ValueError):
                LOG.error("persistent operator replay admission failed closed")
                self._operator_auth_status = HTTPStatus.SERVICE_UNAVAILABLE
                return False
            if admission != "accepted":
                if admission in {"duplicate", "request_id_conflict"}:
                    self._operator_auth_status = HTTPStatus.CONFLICT
                elif admission == "capacity":
                    self._operator_auth_status = HTTPStatus.SERVICE_UNAVAILABLE
                return False
            self._operator_context = context
            return True

        def _operator_denied(self) -> None:
            status = getattr(
                self, "_operator_auth_status", HTTPStatus.UNAUTHORIZED
            )
            if status == HTTPStatus.CONFLICT:
                error = "operator request was already admitted"
            elif status == HTTPStatus.SERVICE_UNAVAILABLE:
                error = "operator authentication is temporarily unavailable"
            else:
                error = "operator authentication required"
            self._json(status, {"error": error})

        def _operator_principal(self) -> str:
            context = getattr(self, "_operator_context", None)
            if not isinstance(context, OperatorRequestContext):
                raise PermissionError("operator authentication required")
            return context.principal_id

        def do_GET(self) -> None:  # noqa: N802
            self._agent_response_token = None
            self._agent_request_signature = ""
            parsed = urlparse(self.path)
            if parsed.path == "/api/v1/health":
                self._json(
                    HTTPStatus.OK,
                    {"status": "ok", "version": __version__},
                )
                return
            if parsed.path == "/api/v1/readiness":
                readiness = app.readiness()
                self._json(
                    HTTPStatus.OK
                    if readiness["ready"]
                    else HTTPStatus.SERVICE_UNAVAILABLE,
                    readiness,
                )
                return
            if parsed.path == "/api/v1/operator/auth-info":
                self._json(
                    HTTPStatus.OK,
                    {
                        "version": OPERATOR_AUTH_VERSION,
                        "principal_id": app.operator_principal_id,
                        "credential_epoch": app.operator_credential_epoch,
                        "request_not_before": app.operator_request_not_before,
                    },
                )
                return
            if parsed.path == "/api/v1/dashboard":
                if not self._operator_authenticated():
                    self._operator_denied()
                    return
                self._json(HTTPStatus.OK, app.dashboard())
                return
            if parsed.path == "/api/v1/agent/actions":
                if not self._authenticated(b""):
                    self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid signature"})
                    return
                agent_id = parse_qs(parsed.query).get("agent_id", [""])[0]
                if agent_id != self.headers.get("X-SB-Agent"):
                    self._json(HTTPStatus.FORBIDDEN, {"error": "agent identity mismatch"})
                    return
                # Keep governance transitions outside the lease-to-egress
                # interval. Once emergency_stop returns, no response that was
                # still buffered inside the controller can newly deliver a
                # pre-stop action.
                with app._action_egress_lock, app._governance_lock:
                    actions = [
                        asdict(item)
                        for item in app.pending_actions_for_agent(agent_id)
                    ]
                    self._json(
                        HTTPStatus.OK,
                        {"actions": actions},
                        self._agent_response_token,
                    )
                return
            if parsed.path in {"/", "/index.html"}:
                resource = files("sentinel_blue").joinpath("web/index.html")
                body = resource.read_text(encoding="utf-8").encode()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", mimetypes.guess_type("index.html")[0] or "text/html")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("X-Frame-Options", "DENY")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'",
                )
                self.end_headers()
                self.wfile.write(body)
                return
            self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            self._agent_response_token = None
            self._agent_request_signature = ""
            try:
                parsed = urlparse(self.path)
                maximum = controller_post_route_limit(parsed.path)
                if maximum is None:
                    # HTTP/1.0 closes the connection, so an unknown request body
                    # cannot be reused as a smuggled follow-on request.
                    self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
                    return
                body = self._read_body(maximum)
                if parsed.path in CONTROLLER_REQUEST_LIMITS and parsed.path.startswith(
                    "/api/v1/agent/"
                ):
                    enrollment = parsed.path == "/api/v1/agent/enroll"
                    if not self._authenticated(body, enrollment=enrollment):
                        self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid signature"})
                        return
                    if not enrollment and parsed.path == "/api/v1/agent/telemetry":
                        ingest_allowed, retry_after = app.ingest_limiter.consume(
                            self.headers.get("X-SB-Agent", "")
                        )
                        if not ingest_allowed:
                            self._json(
                                HTTPStatus.TOO_MANY_REQUESTS,
                                {
                                    "error": "telemetry ingest rate limit exceeded",
                                    "retry_after_seconds": max(
                                        1, min(60, int(retry_after + 0.999))
                                    ),
                                },
                            )
                            return
                    payload = self._decode_json_body(body)
                    if enrollment:
                        if str(payload.get("agent_id", "")) != self.headers.get("X-SB-Agent"):
                            self._json(HTTPStatus.FORBIDDEN, {"error": "agent identity mismatch"})
                            return
                        enrollment_result = app.enroll(
                            payload,
                            authenticated_ticket=self._agent_response_token,
                        )
                        agent_token = enrollment_result.pop("agent_token")
                        enrollment_result["agent_token_wrapped"] = wrap_enrollment_token(
                            self._agent_response_token,
                            self.headers.get("X-SB-Signature", ""),
                            agent_token,
                        )
                        self._json(
                            HTTPStatus.CREATED,
                            enrollment_result,
                            self._agent_response_token,
                        )
                        return
                    if parsed.path == "/api/v1/agent/telemetry":
                        alerts = app.ingest(
                            payload,
                            self.headers.get("X-SB-Agent", ""),
                            self._agent_response_token,
                        )
                        self._json(
                            HTTPStatus.ACCEPTED,
                            {"alerts": alerts},
                            self._agent_response_token,
                        )
                        return
                    if parsed.path == "/api/v1/agent/result":
                        completion = app.complete_action(
                            payload, self.headers.get("X-SB-Agent", "")
                        )
                        completion_payload = {
                            "completed": completion in {"new", "exact_retry"},
                            "completion": completion or "not_found",
                        }
                        if completion == "conflict":
                            completion_payload["error"] = (
                                "action result conflicts with this delivered action record"
                            )
                        elif completion is None:
                            completion_payload["error"] = "action not found"
                        self._json(
                            (
                                HTTPStatus.NOT_FOUND
                                if completion is None
                                else HTTPStatus.CONFLICT
                                if completion == "conflict"
                                else HTTPStatus.OK
                            ),
                            completion_payload,
                            self._agent_response_token,
                        )
                        return
                if parsed.path.startswith("/api/v1/alerts/") and parsed.path.endswith("/decision"):
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    alert_id = parsed.path.split("/")[4]
                    payload = self._decode_json_body(body)
                    result = app.decision(
                        alert_id,
                        str(payload.get("decision", "")),
                        str(payload.get("authorization_code", "")),
                        reviewer_principal_id=self._operator_principal(),
                    )
                    self._json(HTTPStatus.OK if result else HTTPStatus.NOT_FOUND, result or {"error": "alert not open"})
                    return
                if parsed.path == "/api/v1/protected-accounts/import":
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    payload = self._decode_json_body(body)
                    self._json(HTTPStatus.OK, {"imported": app.import_protected_accounts(payload)})
                    return
                if parsed.path == "/api/v1/change-grants":
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    payload = self._decode_json_body(body)
                    self._json(HTTPStatus.CREATED, app.authorize_change(payload))
                    return
                if parsed.path == "/api/v1/authorizations":
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    payload = self._decode_json_body(body)
                    self._json(HTTPStatus.CREATED, app.issue_action_authorization(payload))
                    return
                if parsed.path == "/api/v1/governance/mode":
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    payload = self._decode_json_body(body)
                    self._json(HTTPStatus.OK, app.set_autonomy_mode(str(payload.get("mode", ""))))
                    return
                if parsed.path == "/api/v1/governance/emergency-stop":
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    self._json(HTTPStatus.OK, app.emergency_stop())
                    return
                if parsed.path == "/api/v1/governance/resume":
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    self._json(HTTPStatus.OK, app.resume_changes())
                    return
                if parsed.path.startswith("/api/v1/agents/") and parsed.path.endswith("/baseline/approve"):
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    agent_id = parsed.path.split("/")[4]
                    result = app.approve_baseline(agent_id)
                    self._json(HTTPStatus.OK if result else HTTPStatus.NOT_FOUND, result or {"approved": False})
                    return
                if parsed.path.startswith("/api/v1/agents/") and parsed.path.endswith("/baseline/promotion/abort"):
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    agent_id = parsed.path.split("/")[4]
                    result = app.abort_baseline_promotion(agent_id)
                    self._json(
                        HTTPStatus.OK if result else HTTPStatus.NOT_FOUND,
                        result or {"error": "baseline promotion not found"},
                    )
                    return
                if parsed.path.startswith("/api/v1/actions/") and parsed.path.endswith("/release"):
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    action_id = parsed.path.split("/")[4]
                    payload = self._decode_json_body(body)
                    result = app.release_action(
                        action_id, str(payload.get("authorization_code", ""))
                    )
                    self._json(HTTPStatus.OK if result else HTTPStatus.NOT_FOUND, result or {"error": "quarantine action not found"})
                    return
                if parsed.path.startswith("/api/v1/actions/") and parsed.path.endswith("/reconcile"):
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    action_id = parsed.path.split("/")[4]
                    payload = self._decode_json_body(body)
                    if set(payload) != {"resolution"}:
                        raise ValueError(
                            "action reconciliation requires only resolution"
                        )
                    try:
                        result = app.reconcile_action_outcome(
                            action_id,
                            payload["resolution"],
                        )
                    except RuntimeError as exc:
                        self._json(HTTPStatus.CONFLICT, {"error": str(exc)})
                        return
                    self._json(
                        HTTPStatus.OK if result else HTTPStatus.NOT_FOUND,
                        result or {"error": "action not found"},
                    )
                    return
                if parsed.path.startswith("/api/v1/actions/") and parsed.path.endswith("/rollback"):
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    action_id = parsed.path.split("/")[4]
                    payload = self._decode_json_body(body)
                    result = app.rollback_action(
                        action_id, str(payload.get("authorization_code", ""))
                    )
                    self._json(HTTPStatus.OK if result else HTTPStatus.NOT_FOUND, result or {"error": "reversible service action not found"})
                    return
                if parsed.path.startswith("/api/v1/agents/") and parsed.path.endswith("/revoke"):
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    agent_id = parsed.path.split("/")[4]
                    with app._action_egress_lock:
                        changed = app.store.set_agent_enabled(
                            validate_agent_id(agent_id), False
                        )
                    self._json(HTTPStatus.OK if changed else HTTPStatus.NOT_FOUND, {"revoked": changed})
                    return
                if parsed.path.startswith("/api/v1/agents/") and parsed.path.endswith("/enable"):
                    if not self._operator_authenticated(body):
                        self._operator_denied()
                        return
                    agent_id = parsed.path.split("/")[4]
                    with app._action_egress_lock:
                        changed = app.store.set_agent_enabled(
                            validate_agent_id(agent_id), True
                        )
                    self._json(
                        HTTPStatus.OK if changed else HTTPStatus.NOT_FOUND,
                        {"reenrollment_pending": changed, "enabled": False},
                    )
                    return
                self._json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            except EXPECTED_CONNECTION_ERRORS as exc:
                if isinstance(self.server, ControllerServer):
                    if not self._deadline_expired():
                        self.server._record_expected_connection_failure(type(exc).__name__)
                return
            except PermissionError as exc:
                self._json(HTTPStatus.FORBIDDEN, {"error": str(exc)})
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            except Exception:
                if isinstance(self.server, ControllerServer):
                    self.server.handle_error(self.connection, self.client_address)
                else:
                    LOG.exception("unhandled request failure")
                self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": "internal error"})

    return Handler


def run(args: argparse.Namespace) -> None:
    # Acquire before Store can migrate or mutate release/governance state.  A
    # second process fails here even when it intends to bind a different port.
    with ControllerDatabaseLock(args.database):
        _run_locked(args)


def _run_locked(args: argparse.Namespace) -> None:
    logging.basicConfig(level=getattr(logging, args.log_level.upper()))
    _validate_controller_path_separation(args)
    token = args.token or read_private_text(args.token_file, 64 * 1024).strip()
    try:
        token_payload = json.loads(token)
        token = str(token_payload.get("token", ""))
    except json.JSONDecodeError:
        pass
    event_profile = load_event_profile(args.event_profile)
    event_profile.require_runtime_ready(
        __version__, range_deployment=bool(getattr(args, "range_deployment", False))
    )
    validate_bound_transport(
        event_profile,
        role="controller",
        ca_file=getattr(args, "tls_ca_file", None),
        tls_cert=getattr(args, "tls_cert", None),
        tls_key=getattr(args, "tls_key", None),
        syslog_bind=getattr(args, "syslog_bind", None),
    )
    event_profile.verify_release_file(sys.argv[0])
    event_profile.assert_inventory_networks(
        args.authorized_network or list(event_profile.authorized_networks)
    )
    authorized_networks = list(event_profile.authorized_networks)
    from .recovery import load_recovery_key
    from .recovery_ops import controller_recovery_status

    recovery_key = load_recovery_key(args.recovery_key_file)
    recovery_status = controller_recovery_status(
        args.database, args.recovery_anchor, recovery_key
    )
    if not recovery_status["ready"]:
        raise RuntimeError(
            "controller recovery preflight blocked startup: "
            + str(recovery_status["reason"])
        )
    operator_token = args.operator_token or read_private_text(
        args.operator_token_file, 64 * 1024
    ).strip()
    if args.operator_token_file:
        operator_path = Path(args.operator_token_file)
        reserved_inputs = [Path(args.database)]
        if args.token_file:
            reserved_inputs.append(Path(args.token_file))
        if any(operator_path.resolve() == path.resolve() for path in reserved_inputs):
            raise ValueError(
                "operator token input must differ from the database and enrollment token"
            )
    if args.adaptive_model_output:
        output = Path(args.adaptive_model_output)
        outputs = (output, output.with_suffix(output.suffix + ".report.json"))
        reserved = [
            ("controller database", args.database),
            ("event profile", args.event_profile),
            ("frozen runtime", sys.argv[0]),
        ]
        for name in (
            "model", "token_file", "operator_token_file", "probe_config",
            "tls_cert", "tls_key", "tls_ca_file", "recovery_key_file",
            "recovery_anchor", "backup_directory",
        ):
            value = getattr(args, name, None)
            if value:
                reserved.append((name.replace("_", " "), value))
        for generated in outputs:
            for label, source in reserved:
                if _paths_alias(generated, source):
                    raise ValueError(
                        f"adaptive output must differ from the {label}"
                    )
    store = Store(args.database)
    controller_session_id, prior_unclean_shutdown = store.begin_controller_session()
    if args.model:
        # Digest authentication and JSON parsing share one immutable snapshot.
        model = event_profile.load_model_file(args.model)
    else:
        bundled = json.loads(
            files("sentinel_blue").joinpath("models/risk-v1.0.json").read_text(encoding="utf-8")
        )
        model = RiskModel.from_dict(bundled)
    probe_specs: list[dict[str, Any]] = []
    if args.probe_config:
        probe_payload = read_private_json(args.probe_config, 1024 * 1024)
        probe_specs = probe_payload.get("probes", []) if isinstance(probe_payload, dict) else []
        if not isinstance(probe_specs, list):
            raise ValueError("probe config must contain a probes array")
    app = ControllerApp(
        store,
        token,
        model,
        authorized_networks,
        enrollment_window=args.enrollment_window,
        max_agents=args.max_agents,
        health_stale_after=args.stale_after,
        auto_restore=args.auto_restore,
        restoration_probes=probe_specs,
        restore_confirmations=args.restore_confirmations,
        allow_unprobed_restoration=args.allow_unprobed_restoration,
        event_profile=event_profile,
        operator_token=operator_token,
        operator_principal_id=args.operator_principal_id,
        operator_credential_epoch=args.operator_credential_epoch,
        recovery_key=recovery_key,
        recovery_anchor=args.recovery_anchor,
        require_authenticated_recovery=True,
        force_safe_governance=prior_unclean_shutdown,
        campaign_id=getattr(args, "campaign_id", None),
    )
    server = ControllerServer(
        (args.bind, args.port),
        make_handler(app),
        event_profile=event_profile,
    )
    app.connection_pressure_provider = server.connection_pressure_snapshot
    if bool(args.tls_cert) != bool(args.tls_key):
        raise ValueError("--tls-cert and --tls-key must be supplied together")
    if args.tls_cert and args.tls_key:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(args.tls_cert, args.tls_key)
        server.enable_tls(context)
    probe_stop = threading.Event()
    probe_thread = None
    maintenance_thread = threading.Thread(
        target=maintenance_loop,
        args=(
            app,
            args.stale_after,
            args.retention_days,
            args.backup_directory,
            args.backup_interval,
            args.backup_keep,
            args.maintenance_interval,
            probe_stop,
        ),
        daemon=True,
        name="sentinel-maintenance",
    )
    maintenance_thread.start()
    syslog_monitor = None
    if probe_specs:
        probe_thread = threading.Thread(
            target=relay_probe_loop,
            args=(app, probe_specs, args.probe_interval, probe_stop),
            daemon=True,
            name="sentinel-relay-probes",
        )
        probe_thread.start()
    if args.syslog_bind:
        from .syslog_monitor import SyslogMonitor

        syslog_monitor = SyslogMonitor(app, args.syslog_bind, args.syslog_port)
        syslog_monitor.start()
    scheme = "https" if args.tls_cert else "http"
    LOG.warning("controller listening on %s://%s:%s", scheme, args.bind, args.port)
    clean_shutdown = False
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        clean_shutdown = True
    else:
        clean_shutdown = True
    finally:
        probe_stop.set()
        if probe_thread:
            probe_thread.join(timeout=3)
        maintenance_thread.join(timeout=3)
        if syslog_monitor:
            syslog_monitor.stop()
        server.server_close()
        if args.adaptive_model_output:
            try:
                from .learning import train_candidate

                provenance_filter = {
                    "campaign_id": app.campaign_id,
                    "profile_id": event_profile.profile_id,
                    "profile_fingerprint": event_profile.fingerprint,
                    "release_sha256": str(
                        event_profile.release.get("sha256", "")
                    ).casefold(),
                    "agent_version": __version__,
                    "model_fingerprint": model.fingerprint(),
                }
                report = train_candidate(
                    store,
                    model,
                    args.adaptive_model_output,
                    provenance_filter=provenance_filter,
                    require_structured_lineage=app._strict_release_binding,
                )
                LOG.warning("adaptive model evaluation: %s", json.dumps(report, sort_keys=True))
            except Exception:
                LOG.exception("adaptive model training failed; current model retained")
        if clean_shutdown and not app._governance_persistence_uncertain and not maintenance_thread.is_alive() and not (
            probe_thread and probe_thread.is_alive()
        ):
            if not store.end_controller_session(controller_session_id):
                LOG.error("controller clean-session marker could not be cleared")
        store.close()
