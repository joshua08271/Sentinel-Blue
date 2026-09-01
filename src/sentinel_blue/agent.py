"""Outbound-only Sentinel Blue host agent."""

from __future__ import annotations

import argparse
import atexit
import hashlib
import hmac
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import re
import socket
import ssl
import stat
import sys
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urljoin
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from . import __version__
from .actions import ActionExecutor
from .auth import ReplayGuard, signature, unwrap_enrollment_token, verify_response
from .change_watch import ChangeWatcher
from .collectors import collect, integrity_watch_paths, machine_identity
from .event_profile import EventProfile, load_event_profile
from .health import assess_agent_health
from .json_codec import canonical_json_bytes, strict_json_loads
from .net_safety import validate_http_origin
from .state import (
    MAX_STATE_BYTES,
    AgentProcessLock,
    ActionJournal,
    SequenceCounter,
    TelemetrySpool,
    read_private_json,
    read_private_text,
    remove_private_file,
    write_private_json,
)
from .validation import (
    ValidationError,
    canonical_action_envelope_sha256,
    validate_action_request,
    validate_action_result,
)
from .win_state import WindowsStateTreeGuard, acquire_windows_state_tree


LOG = logging.getLogger("sentinel_blue.agent")
MAX_CONTROLLER_RESPONSE_BYTES = 2_000_000
MAX_AGENT_REQUEST_BYTES = 1_000_000
AGENT_REQUEST_LIMITS = {
    "/api/v1/agent/enroll": 64 * 1024,
    "/api/v1/agent/telemetry": MAX_AGENT_REQUEST_BYTES,
    "/api/v1/agent/result": 512 * 1024,
}
AGENT_RESPONSE_LIMITS = {
    "/api/v1/agent/enroll": 64 * 1024,
    "/api/v1/agent/telemetry": MAX_AGENT_REQUEST_BYTES,
    "/api/v1/agent/result": 64 * 1024,
    "/api/v1/agent/actions": MAX_AGENT_REQUEST_BYTES,
}
MAX_VERIFIED_ERROR_LENGTH = 256
MIN_LOG_BYTES = 64 * 1024
MAX_LOG_BYTES = 100 * 1024 * 1024
MAX_LOG_BACKUPS = 10
MAX_ACTION_RESULTS_PER_CYCLE = 32
MAX_ACTION_RESULT_RECONCILIATION_ATTEMPTS = 4
MAX_ACTION_RESULT_ATTEMPT_COUNTER = 2**31 - 1
ACTION_RESULT_INITIAL_BACKOFF_SECONDS = 5.0
ACTION_RESULT_MAX_BACKOFF_SECONDS = 3600.0
MAX_ACTION_RESULT_DELIVERY_DETAIL = 256


def telemetry_matches_release_binding(
    telemetry: dict[str, Any], event_profile: EventProfile
) -> bool:
    """Return whether queued telemetry belongs to this exact runtime/profile."""
    return (
        telemetry.get("agent_version") == __version__
        and telemetry.get("profile_id") == event_profile.profile_id
        and telemetry.get("profile_fingerprint") == event_profile.fingerprint
    )


def refresh_restoration_health(
    executor: ActionExecutor, health: dict[str, Any]
) -> dict[str, Any]:
    """Refresh the fail-closed restoration gate inside the running process."""
    recovery = executor.refresh_restore_recovery()
    if recovery.get("healthy") is not True:
        error = "self-health: one or more interrupted restorations require review"
        critical = "self-health: unresolved interrupted restoration"
        if error not in health["errors"]:
            health["errors"].append(error)
        if critical not in health["critical_errors"]:
            health["critical_errors"].append(critical)
        health["healthy"] = False
        health["action_safe"] = False
    return recovery


def refresh_windows_state_health(
    guard: WindowsStateTreeGuard | None, health: dict[str, Any]
) -> Any | None:
    """Revalidate the pinned Windows state tree and fail action health closed."""
    if guard is None:
        return None
    try:
        return guard.refresh(harden_safe_descendants=False)
    except Exception as exc:
        # Do not attempt ACL repair from the recurring health path.  A widened,
        # substituted, over-budget, or already-closed tree requires operator
        # review before any remote action can be trusted again.
        error = "self-health: Windows state tree trust validation failed"
        critical = "self-health: Windows state tree requires review"
        if error not in health["errors"]:
            health["errors"].append(error)
        if critical not in health["critical_errors"]:
            health["critical_errors"].append(critical)
        health["healthy"] = False
        health["action_safe"] = False
        LOG.error("Windows state tree trust validation failed: %s", exc)
        return None


def refresh_recovery_health(
    executor: ActionExecutor,
    health: dict[str, Any],
    current_boot_id: str = "unknown",
) -> dict[str, dict[str, Any]]:
    """Refresh and apply every durable action recovery gate in this cycle."""
    reports = executor.refresh_recovery(current_boot_id)
    messages = {
        "restoration": (
            "self-health: one or more interrupted restorations require review",
            "self-health: unresolved interrupted restoration",
        ),
        "quarantine": (
            "self-health: one or more interrupted quarantines require review",
            "self-health: unresolved interrupted quarantine",
        ),
        "service": (
            "self-health: one or more interrupted service changes require review",
            "self-health: unresolved interrupted service change",
        ),
    }
    for component, (error, critical) in messages.items():
        if reports.get(component, {}).get("healthy") is True:
            continue
        if error not in health["errors"]:
            health["errors"].append(error)
        if critical not in health["critical_errors"]:
            health["critical_errors"].append(critical)
        health["healthy"] = False
        health["action_safe"] = False
    return reports


def profile_requires_action_binding(event_profile: EventProfile) -> bool:
    """Return whether actions must bind to this exact deployed agent/profile."""
    digest = str(event_profile.release.get("sha256", "")).casefold()
    return event_profile.environment == "live-competition" or (
        len(digest) == 64
        and all(character in "0123456789abcdef" for character in digest)
    )


class PrivateRotatingFileHandler(RotatingFileHandler):
    """Open the active log without following a substituted final symlink."""

    def _open(self):
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        flags |= getattr(os, "O_BINARY", 0) | getattr(os, "O_NOINHERIT", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.baseFilename, flags, 0o600)
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise OSError("agent log target is not a regular file")
            os.set_inheritable(descriptor, False)
            if os.name == "posix":
                os.fchmod(descriptor, 0o600)
            return open(
                descriptor,
                mode=self.mode,
                encoding=self.encoding,
                errors=self.errors,
                closefd=True,
            )
        except Exception:
            os.close(descriptor)
            raise


def configure_agent_logging(
    level_name: str,
    state_dir: Path | None = None,
    log_file: str | None = None,
    max_bytes: int = 5 * 1024 * 1024,
    backups: int = 3,
) -> None:
    level = getattr(logging, level_name.upper(), None)
    if not isinstance(level, int):
        raise ValueError(f"unsupported log level: {level_name}")
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        if state_dir is None:
            raise ValueError("a prepared state directory is required for file logging")
        target = Path(log_file)
        if not target.is_absolute():
            raise ValueError("--log-file must be an absolute path")
        state_root = state_dir.resolve(strict=True)
        resolved_parent = target.parent.resolve(strict=True)
        if resolved_parent != state_root or target.name in {"", ".", ".."}:
            raise ValueError("--log-file must be a direct child of the agent state directory")
        if target.is_symlink():
            raise ValueError("--log-file cannot be a symbolic link")
        if type(max_bytes) is not int or type(backups) is not int:
            raise ValueError("log rotation limits must be integers")
        bounded_bytes = max(MIN_LOG_BYTES, min(max_bytes, MAX_LOG_BYTES))
        bounded_backups = max(1, min(backups, MAX_LOG_BACKUPS))
        handlers.append(
            PrivateRotatingFileHandler(
                target,
                maxBytes=bounded_bytes,
                backupCount=bounded_backups,
                encoding="utf-8",
                delay=True,
            )
        )
    logging.basicConfig(
        level=level,
        handlers=handlers,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        force=True,
    )


def systemd_notify(message: str) -> bool:
    """Send a best-effort readiness/watchdog datagram without a systemd dependency."""
    address = os.environ.get("NOTIFY_SOCKET", "")
    if os.name != "posix" or not address or len(message) > 4096:
        return False
    if address.startswith("@"):
        address = "\0" + address[1:]
    notifier = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        notifier.settimeout(1.0)
        notifier.connect(address)
        notifier.sendall(message.encode("utf-8"))
        return True
    except OSError:
        return False
    finally:
        notifier.close()


class NoRedirectHandler(HTTPRedirectHandler):
    """Never forward agent credentials or signed headers through redirects."""

    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


class AgentClient:
    def __init__(
        self,
        controller: str,
        token: str,
        agent_id: str,
        timeout: float = 12.0,
        agent_token: str | None = None,
        ca_file: str | None = None,
        profile_id: str = "",
        profile_fingerprint: str = "",
        enrollment_nonce: str | None = None,
    ):
        validate_http_origin(controller)
        if token and not re.fullmatch(r"[A-Za-z0-9_-]{32,256}", token):
            raise ValueError(
                "the enrollment token must be 32-256 URL-safe characters"
            )
        if not token and not agent_token:
            raise ValueError("an enrollment token or existing agent token is required")
        self.controller = validate_http_origin(controller) + "/"
        self.token = token
        self.agent_token = agent_token
        self.agent_id = agent_id
        self.timeout = timeout
        self.ssl_context = ssl.create_default_context(cafile=ca_file) if ca_file else None
        handlers: list[Any] = [ProxyHandler({}), NoRedirectHandler()]
        if self.ssl_context is not None:
            handlers.append(HTTPSHandler(context=self.ssl_context))
        self.opener = build_opener(*handlers)
        self.response_guard = ReplayGuard()
        self.profile_id = profile_id
        self.profile_fingerprint = profile_fingerprint
        if enrollment_nonce is not None:
            if not isinstance(enrollment_nonce, str) or not re.fullmatch(
                r"[0-9a-f]{64}", enrollment_nonce
            ):
                raise ValueError("enrollment nonce is not a SHA-256 digest")
            self.enrollment_nonce = enrollment_nonce
        elif token:
            self.enrollment_nonce = hmac.new(
                token.encode("utf-8"),
                (
                    "sentinel-blue-enrollment-nonce-v1\x00"
                    + profile_fingerprint
                    + "\x00"
                    + agent_id
                ).encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()
        else:
            self.enrollment_nonce = ""

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        enrollment: bool = False,
    ) -> Any:
        route = path.partition("?")[0]
        request_limit = AGENT_REQUEST_LIMITS.get(route, MAX_AGENT_REQUEST_BYTES)
        body = (
            canonical_json_bytes(payload, max_bytes=request_limit)
            if payload is not None
            else b""
        )
        timestamp = str(time.time())
        request_token = self.token if enrollment else self.agent_token
        if not request_token:
            raise ValueError("agent is not enrolled")
        request_signature = signature(request_token, timestamp, method, path, body)
        headers = {
            "X-SB-Agent": self.agent_id,
            "X-SB-Timestamp": timestamp,
            "X-SB-Signature": request_signature,
            "Content-Type": "application/json",
        }
        request = Request(urljoin(self.controller, path.lstrip("/")), data=body if method != "GET" else None, headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=self.timeout)
        except HTTPError as exc:
            response_limit = AGENT_RESPONSE_LIMITS.get(route, MAX_CONTROLLER_RESPONSE_BYTES)
            response_body = self._read_response_body(exc, response_limit)
            self._verify_response(
                request_token,
                path,
                int(exc.code),
                request_signature,
                response_body,
                exc.headers,
            )
            exc.sentinel_blue_verified = True
            exc.sentinel_blue_error = self._verified_error_reason(
                response_body,
                exc.headers,
            )
            raise
        with response:
            status_value = getattr(response, "status", None)
            status = int(response.getcode() if status_value is None else status_value)
            response_limit = AGENT_RESPONSE_LIMITS.get(route, MAX_CONTROLLER_RESPONSE_BYTES)
            response_body = self._read_response_body(response, response_limit)
            self._verify_response(
                request_token,
                path,
                status,
                request_signature,
                response_body,
                response.headers,
            )
            self._require_json_response_headers(response.headers)
            decoded = strict_json_loads(response_body, max_bytes=response_limit)
            if enrollment:
                if not isinstance(decoded, dict) or "agent_token" in decoded:
                    raise ValueError("controller returned an unsafe enrollment response")
                decoded["agent_token"] = unwrap_enrollment_token(
                    request_token,
                    request_signature,
                    decoded.get("agent_token_wrapped", ""),
                )
                decoded.pop("agent_token_wrapped", None)
            return decoded

    @staticmethod
    def _read_response_body(response: Any, maximum: int = MAX_CONTROLLER_RESPONSE_BYTES) -> bytes:
        maximum = min(MAX_CONTROLLER_RESPONSE_BYTES, max(1, int(maximum)))
        raw_length = response.headers.get("Content-Length") if response.headers else None
        declared = None
        if raw_length not in {None, ""}:
            try:
                declared = int(raw_length)
            except (TypeError, ValueError) as exc:
                raise ValueError("controller response has an invalid Content-Length") from exc
            if declared < 0 or declared > maximum:
                raise ValueError("controller response exceeds the size limit")
        body = response.read(maximum + 1) or b""
        if len(body) > maximum:
            raise ValueError("controller response exceeds the size limit")
        if declared is not None and declared != len(body):
            raise ValueError("controller response length does not match Content-Length")
        return body

    @staticmethod
    def _json_content_type(headers: Any) -> bool:
        raw = headers.get("Content-Type", "") if headers else ""
        if not isinstance(raw, str):
            return False
        parts = [part.strip().casefold() for part in raw.split(";")]
        return bool(
            parts
            and parts[0] == "application/json"
            and all(part == "charset=utf-8" for part in parts[1:] if part)
        )

    @classmethod
    def _require_json_response_headers(cls, headers: Any) -> None:
        raw_length = headers.get("Content-Length") if headers else None
        if raw_length in {None, ""}:
            raise ValueError("controller response is missing Content-Length")
        get_all = getattr(headers, "get_all", None)
        if callable(get_all) and len(get_all("Content-Length") or []) != 1:
            raise ValueError("controller response has ambiguous Content-Length")
        if not cls._json_content_type(headers):
            raise ValueError("controller response is not application/json")

    @classmethod
    def _verified_error_reason(cls, response_body: bytes, headers: Any = None) -> str:
        """Return only a bounded diagnostic from an authenticated error body."""
        content_type = headers.get("Content-Type", "") if headers else ""
        if content_type and not cls._json_content_type(headers):
            return "authenticated controller rejection"
        try:
            decoded = strict_json_loads(
                response_body,
                max_bytes=min(len(response_body) or 1, MAX_CONTROLLER_RESPONSE_BYTES),
            )
        except ValueError:
            return "authenticated controller rejection"
        value = decoded.get("error") if isinstance(decoded, dict) else None
        if not isinstance(value, str):
            return "authenticated controller rejection"
        clean = "".join(character if character.isprintable() else "\ufffd" for character in value).strip()
        return (clean or "authenticated controller rejection")[:MAX_VERIFIED_ERROR_LENGTH]

    def _verify_response(
        self,
        request_token: str,
        path: str,
        status: int,
        request_signature: str,
        response_body: bytes,
        headers: Any,
    ) -> None:
        response_timestamp = headers.get("X-SB-Response-Timestamp", "")
        response_signature = headers.get("X-SB-Response-Signature", "")
        if headers.get("X-SB-Response-Version", "") != "2" or not verify_response(
            request_token,
            response_timestamp,
            status,
            path,
            request_signature,
            response_body,
            response_signature,
        ) or not self.response_guard.accept(response_signature):
            raise ValueError("controller response signature is invalid or replayed")

    def request_enrollment(self, hostname: str, platform_name: str) -> str:
        """Request and verify a candidate credential without activating it."""
        response = self._request(
            "POST",
            "/api/v1/agent/enroll",
            {
                "agent_id": self.agent_id,
                "hostname": hostname,
                "platform": platform_name,
                "agent_version": __version__,
                "profile_id": self.profile_id,
                "profile_fingerprint": self.profile_fingerprint,
                "enrollment_nonce": self.enrollment_nonce,
            },
            enrollment=True,
        )
        candidate = response.get("agent_token") if isinstance(response, dict) else None
        if not isinstance(candidate, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{32,256}", candidate
        ):
            raise ValueError("controller returned an invalid agent credential")
        return candidate

    def activate_enrollment(self, agent_token: str) -> None:
        if not isinstance(agent_token, str) or not re.fullmatch(
            r"[A-Za-z0-9_-]{32,256}", agent_token
        ):
            raise ValueError("agent credential is invalid")
        self.agent_token = agent_token
        self.token = ""

    def enroll(self, hostname: str, platform_name: str) -> str:
        candidate = self.request_enrollment(hostname, platform_name)
        self.activate_enrollment(candidate)
        return candidate

    def telemetry(self, payload: dict[str, Any]) -> Any:
        return self._request("POST", "/api/v1/agent/telemetry", payload)

    def actions(self) -> list[dict[str, Any]]:
        path = "/api/v1/agent/actions?" + urlencode({"agent_id": self.agent_id})
        return list(self._request("GET", path).get("actions", []))

    def result(self, action_id: str, result: dict[str, Any]) -> Any:
        # The queue-issued identifier is authoritative even if an executor result is
        # malformed or compromised and tries to supply another action_id.
        return self._request("POST", "/api/v1/agent/result", {**result, "action_id": action_id})


class ActionResultOutbox:
    """Durable delivery metadata layered onto completed action tombstones.

    ``ActionJournal.remember`` commits the result before this layer can attempt
    HTTP delivery.  A completed record without delivery metadata is therefore a
    pending outbox item, including after a crash in that exact gap.  Metadata is
    committed through the journal's existing Windows-safe atomic writer.
    """

    _FIELD = "result_delivery"
    _STATES = frozenset({"pending", "reconciliation", "acknowledged"})
    _COMPLETIONS = frozenset({"", "new", "exact_retry"})
    _DELIVERY_FIELDS = frozenset(
        {
            "state",
            "attempts",
            "reconciliation_attempts",
            "next_attempt_at",
            "updated_at",
            "last_status",
            "detail",
            "completion",
        }
    )

    def __init__(self, journal: ActionJournal):
        self.journal = journal
        self._validate_persisted_document()

    @staticmethod
    def _finite_timestamp(value: Any) -> bool:
        return (
            type(value) in {int, float}
            and value == value
            and abs(value) != float("inf")
            and 0 <= value <= 2**63 - 1
        )

    @staticmethod
    def _clean_detail(value: Any) -> str:
        text = value if isinstance(value, str) else str(value)
        return "".join(
            character if character.isprintable() else "\ufffd" for character in text
        ).strip()[:MAX_ACTION_RESULT_DELIVERY_DETAIL]

    def _fail_closed(self, exc: Exception) -> None:
        self.journal.healthy = False
        self.journal.error = f"action result outbox requires review: {exc}"

    def _validate_persisted_document(self) -> None:
        if not self.journal.healthy:
            return
        path = self.journal.path
        if not path.exists() and not path.is_symlink():
            return
        try:
            raw = read_private_text(path, MAX_STATE_BYTES)
            decoded = strict_json_loads(raw, max_bytes=MAX_STATE_BYTES)
            if not isinstance(decoded, dict) or decoded != self.journal._records:
                raise ValueError("action journal strict decode changed persisted state")
            for record in decoded.values():
                if isinstance(record, dict) and self._FIELD in record:
                    self._validate_delivery(record[self._FIELD])
        except (OSError, TypeError, ValueError, UnicodeDecodeError) as exc:
            self._fail_closed(exc)

    def _validate_delivery(self, value: Any) -> dict[str, Any]:
        if not isinstance(value, dict) or set(value) != self._DELIVERY_FIELDS:
            raise ValueError("action result delivery metadata has an invalid schema")
        if value.get("state") not in self._STATES:
            raise ValueError("action result delivery state is invalid")
        for field in ("attempts", "reconciliation_attempts"):
            counter = value.get(field)
            if type(counter) is not int or not 0 <= counter <= MAX_ACTION_RESULT_ATTEMPT_COUNTER:
                raise ValueError(f"action result delivery {field} is invalid")
        for field in ("next_attempt_at", "updated_at"):
            if not self._finite_timestamp(value.get(field)):
                raise ValueError(f"action result delivery {field} is invalid")
        status = value.get("last_status")
        if type(status) is not int or not 0 <= status <= 599:
            raise ValueError("action result delivery HTTP status is invalid")
        detail = value.get("detail")
        if not isinstance(detail, str) or len(detail) > MAX_ACTION_RESULT_DELIVERY_DETAIL:
            raise ValueError("action result delivery detail is invalid")
        if value.get("completion") not in self._COMPLETIONS:
            raise ValueError("action result delivery completion is invalid")
        return dict(value)

    def _delivery(self, record: dict[str, Any]) -> dict[str, Any]:
        value = record.get(self._FIELD)
        if value is None:
            return {
                "state": "pending",
                "attempts": 0,
                "reconciliation_attempts": 0,
                "next_attempt_at": 0.0,
                "updated_at": 0.0,
                "last_status": 0,
                "detail": "",
                "completion": "",
            }
        return self._validate_delivery(value)

    def _store_delivery(
        self, action_id: str, record: dict[str, Any], delivery: dict[str, Any]
    ) -> None:
        validated = self._validate_delivery(delivery)
        missing = object()
        previous = record.get(self._FIELD, missing)
        record[self._FIELD] = validated
        try:
            self.journal._commit()
        except Exception as exc:
            if previous is missing:
                record.pop(self._FIELD, None)
            else:
                record[self._FIELD] = previous
            self._fail_closed(exc)
            raise RuntimeError(self.journal.error) from exc

    @staticmethod
    def _normalized_result(action_id: str, result: dict[str, Any]) -> dict[str, Any]:
        normalized = validate_action_result({**result, "action_id": action_id})
        normalized.pop("action_id", None)
        canonical_json_bytes(
            {**normalized, "action_id": action_id},
            max_bytes=AGENT_REQUEST_LIMITS["/api/v1/agent/result"],
        )
        return normalized

    def enqueue(self, action_id: str, result: dict[str, Any]) -> None:
        """Ensure a result has a durable journal tombstone before any POST."""
        self.journal._require_healthy()
        normalized = self._normalized_result(action_id, result)
        record = self.journal.record(action_id)
        if record is None:
            self.journal.remember(action_id, normalized)
            return
        if record.get("status", "completed") == "in_progress":
            self.journal.remember(
                action_id,
                normalized,
                record.get("envelope_sha256"),
                expires_at=float(record.get("expires_at", 0.0)),
                profile_fingerprint=str(record.get("profile_fingerprint", "")),
            )
            return
        stored = record.get("result")
        if not isinstance(stored, dict):
            raise RuntimeError("completed action journal record has no result")
        stored_bytes = canonical_json_bytes(
            {**stored, "action_id": action_id},
            max_bytes=AGENT_REQUEST_LIMITS["/api/v1/agent/result"],
        )
        normalized_bytes = canonical_json_bytes(
            {**normalized, "action_id": action_id},
            max_bytes=AGENT_REQUEST_LIMITS["/api/v1/agent/result"],
        )
        if not hmac.compare_digest(stored_bytes, normalized_bytes):
            raise RuntimeError("action result changed after durable completion")
        delivery = self._delivery(record)
        if delivery["state"] != "pending" or delivery["next_attempt_at"] > 0:
            current = time.time()
            self._store_delivery(
                action_id,
                self.journal._records[action_id],
                {
                    "state": "pending",
                    "attempts": delivery["attempts"],
                    "reconciliation_attempts": 0,
                    "next_attempt_at": 0.0,
                    "updated_at": current,
                    "last_status": 0,
                    "detail": "controller redelivered the completed action",
                    "completion": "",
                },
            )

    def pending(
        self, *, now: float | None = None, limit: int = MAX_ACTION_RESULTS_PER_CYCLE
    ) -> list[tuple[str, dict[str, Any]]]:
        self.journal._require_healthy()
        current = time.time() if now is None else now
        if not self._finite_timestamp(current):
            raise ValueError("action result outbox time is invalid")
        bounded_limit = max(1, min(int(limit), MAX_ACTION_RESULTS_PER_CYCLE))
        candidates: list[tuple[float, str, dict[str, Any]]] = []
        try:
            for action_id, record in self.journal._records.items():
                if record.get("status", "completed") != "completed":
                    continue
                result = record.get("result")
                if not isinstance(result, dict):
                    raise ValueError("completed action journal record has no result")
                delivery = self._delivery(record)
                if delivery["state"] == "acknowledged":
                    continue
                if (
                    delivery["state"] == "reconciliation"
                    and delivery["reconciliation_attempts"]
                    >= MAX_ACTION_RESULT_RECONCILIATION_ATTEMPTS
                ):
                    continue
                if float(delivery["next_attempt_at"]) > float(current):
                    continue
                normalized = self._normalized_result(action_id, result)
                completed_at = record.get("completed_at", 0.0)
                order = float(completed_at) if self._finite_timestamp(completed_at) else 0.0
                candidates.append((order, action_id, normalized))
        except (TypeError, ValueError) as exc:
            self._fail_closed(exc)
            raise RuntimeError(self.journal.error) from exc
        candidates.sort(key=lambda item: (item[0], item[1]))
        return [(action_id, result) for _, action_id, result in candidates[:bounded_limit]]

    def defer(
        self,
        action_id: str,
        detail: str,
        *,
        status: int = 0,
        reconciliation: bool = False,
        now: float | None = None,
    ) -> None:
        self.journal._require_healthy()
        current = time.time() if now is None else now
        if not self._finite_timestamp(current):
            raise ValueError("action result outbox time is invalid")
        record = self.journal._records.get(action_id)
        if not isinstance(record, dict) or record.get("status", "completed") != "completed":
            raise RuntimeError("cannot defer a missing action result")
        delivery = self._delivery(record)
        attempts = min(delivery["attempts"] + 1, MAX_ACTION_RESULT_ATTEMPT_COUNTER)
        reconciliation_attempts = delivery["reconciliation_attempts"]
        state = delivery["state"]
        if reconciliation or state == "reconciliation":
            state = "reconciliation"
            reconciliation_attempts = min(
                reconciliation_attempts + 1, MAX_ACTION_RESULT_ATTEMPT_COUNTER
            )
        exponent = min(max(0, attempts - 1), 10)
        delay = min(
            ACTION_RESULT_MAX_BACKOFF_SECONDS,
            ACTION_RESULT_INITIAL_BACKOFF_SECONDS * (2**exponent),
        )
        updated = {
            "state": state,
            "attempts": attempts,
            "reconciliation_attempts": reconciliation_attempts,
            "next_attempt_at": float(current) + delay,
            "updated_at": float(current),
            "last_status": status if type(status) is int and 0 <= status <= 599 else 0,
            "detail": self._clean_detail(detail),
            "completion": "",
        }
        self._store_delivery(action_id, record, updated)

    def acknowledge(
        self, action_id: str, completion: str, *, now: float | None = None
    ) -> None:
        self.journal._require_healthy()
        if completion not in {"new", "exact_retry"}:
            raise ValueError("controller completion is not an acknowledgement")
        current = time.time() if now is None else now
        if not self._finite_timestamp(current):
            raise ValueError("action result outbox time is invalid")
        record = self.journal._records.get(action_id)
        if not isinstance(record, dict) or record.get("status", "completed") != "completed":
            raise RuntimeError("cannot acknowledge a missing action result")
        delivery = self._delivery(record)
        updated = {
            "state": "acknowledged",
            "attempts": delivery["attempts"],
            "reconciliation_attempts": delivery["reconciliation_attempts"],
            "next_attempt_at": 0.0,
            "updated_at": float(current),
            "last_status": 200,
            "detail": "",
            "completion": completion,
        }
        self._store_delivery(action_id, record, updated)

    def delivery_record(self, action_id: str) -> dict[str, Any] | None:
        self.journal._require_healthy()
        record = self.journal._records.get(action_id)
        if not isinstance(record, dict) or record.get("status", "completed") != "completed":
            return None
        return self._delivery(record)

    def has_unacknowledged(self) -> bool:
        self.journal._require_healthy()
        for record in self.journal._records.values():
            if record.get("status", "completed") != "completed":
                continue
            if self._delivery(record)["state"] != "acknowledged":
                return True
        return False


def deliver_pending_action_results(
    client: AgentClient,
    outbox: ActionResultOutbox,
    *,
    now: float | None = None,
    limit: int = MAX_ACTION_RESULTS_PER_CYCLE,
) -> int:
    """Attempt a bounded independent result-delivery batch."""
    acknowledged = 0
    for action_id, result in outbox.pending(now=now, limit=limit):
        try:
            response = client.result(action_id, result)
        except HTTPError as exc:
            verified = bool(getattr(exc, "sentinel_blue_verified", False))
            status = int(exc.code) if type(exc.code) is int else 0
            permanent = verified and status in {400, 403, 404, 409}
            outbox.defer(
                action_id,
                getattr(exc, "sentinel_blue_error", "controller rejected action result"),
                status=status,
                reconciliation=permanent,
                now=now,
            )
            if not permanent:
                break
            continue
        except (URLError, TimeoutError, OSError, RuntimeError, ValueError, KeyError, ssl.SSLError) as exc:
            outbox.defer(action_id, str(exc), now=now)
            # One transport/authentication failure predicts the same outcome for
            # the remainder of this controller batch; avoid multiplying timeouts.
            break
        if (
            isinstance(response, dict)
            and response.get("completed") is True
            and response.get("completion") in {"new", "exact_retry"}
        ):
            outbox.acknowledge(action_id, str(response["completion"]), now=now)
            acknowledged += 1
            continue
        outbox.defer(
            action_id,
            "signed controller response was not a completion acknowledgement",
            reconciliation=True,
            now=now,
        )
    return acknowledged


def default_agent_id() -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_OID, machine_identity()))


def _read_bootstrap_ticket(path: Path) -> str:
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 64 * 1024:
        raise ValueError("bootstrap token file is unavailable, unsafe, or oversized")
    raw = read_private_text(path, 64 * 1024).strip()
    if raw.startswith("{"):
        payload = strict_json_loads(raw, max_bytes=64 * 1024)
        if not isinstance(payload, dict) or set(payload) != {"token"}:
            raise ValueError("bootstrap token document must contain only token")
        ticket = payload.get("token")
    else:
        ticket = raw
    if not isinstance(ticket, str) or not re.fullmatch(
        r"[A-Za-z0-9_-]{32,256}", ticket
    ):
        raise ValueError("bootstrap token is invalid")
    return ticket


def load_agent_credentials(
    identity_path: Path,
    agent_id: str,
    profile_id: str,
    profile_fingerprint: str,
    *,
    inline_token: str | None = None,
    token_file: str | None = None,
    reenroll: bool = False,
) -> tuple[str, str | None, Path | None]:
    """Select exactly one explicit startup credential path."""
    if type(reenroll) is not bool:
        raise ValueError("re-enrollment mode must be explicit")
    if inline_token is not None and not isinstance(inline_token, str):
        raise ValueError("bootstrap token must be a string")
    identity_present = identity_path.exists() or identity_path.is_symlink()
    agent_token: str | None = None
    if identity_present:
        try:
            raw_identity = read_private_text(identity_path, 64 * 1024)
            identity = strict_json_loads(raw_identity, max_bytes=64 * 1024)
            if not isinstance(identity, dict):
                raise ValueError("identity state is not an object")
            if identity.get("agent_id") != agent_id:
                raise ValueError("identity state belongs to a different agent")
            if identity.get("profile_id") != profile_id:
                raise ValueError("identity state belongs to a different event profile")
            if identity.get("profile_fingerprint") != profile_fingerprint:
                raise ValueError("identity state belongs to a different event profile")
            candidate = identity.get("agent_token")
            if not isinstance(candidate, str) or not re.fullmatch(
                r"[A-Za-z0-9_-]{32,256}", candidate
            ):
                raise ValueError("identity state has an invalid agent token")
            agent_token = candidate
        except (OSError, TypeError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"agent identity state requires review: {exc}") from exc

    token_path = Path(token_file) if token_file else None
    staged_ticket = bool(
        inline_token
        or (
            token_path is not None
            and (token_path.exists() or token_path.is_symlink())
        )
    )
    if reenroll:
        if not identity_present or agent_token is None:
            raise ValueError("--re-enroll requires an existing valid identity")
        if not staged_ticket:
            raise ValueError("--re-enroll requires a freshly provisioned ticket")
    elif agent_token is not None:
        if staged_ticket:
            raise ValueError(
                "refusing to replace an existing identity without --re-enroll"
            )
        return "", agent_token, token_path

    if inline_token and token_path is not None:
        raise ValueError("bootstrap token sources are mutually exclusive")
    if token_path is not None:
        bootstrap_token = _read_bootstrap_ticket(token_path)
    else:
        bootstrap_token = inline_token or ""
        if bootstrap_token and not re.fullmatch(
            r"[A-Za-z0-9_-]{32,256}", bootstrap_token
        ):
            raise ValueError("bootstrap token is invalid")
    if not bootstrap_token:
        raise ValueError("agent enrollment requires a bootstrap ticket")
    return bootstrap_token, None, token_path


def enroll_and_persist_identity(
    client: AgentClient,
    identity_path: Path,
    *,
    agent_id: str,
    hostname: str,
    platform_name: str,
    profile_id: str,
    profile_fingerprint: str,
    token_path: Path | None = None,
) -> str:
    """Publish a verified candidate credential before activating it in memory."""
    enrollment_ticket = client.token
    candidate = client.request_enrollment(hostname, platform_name)
    write_private_json(
        identity_path,
        {
            "agent_id": agent_id,
            "agent_token": candidate,
            "profile_id": profile_id,
            "profile_fingerprint": profile_fingerprint,
        },
    )
    client.activate_enrollment(candidate)
    if token_path is not None:
        try:
            remove_private_file(token_path)
        except Exception:
            # Identity publication succeeded, but do not proceed while reusable
            # bootstrap material could not be removed.  An explicit exact retry
            # can recover using the still-present ticket.
            client.agent_token = None
            client.token = enrollment_ticket
            raise
    return candidate


def prepare_state_directory(path: str | Path) -> Path:
    state = Path(path)
    if state.is_symlink():
        raise ValueError("agent state directory must not be a symbolic link")
    state.mkdir(parents=True, exist_ok=True)
    if state.is_symlink() or not state.is_dir():
        raise ValueError("agent state path is not a safe directory")
    if os.name == "posix":
        state.chmod(0o700)
        if state.stat().st_uid != os.geteuid():
            raise ValueError("agent state directory is owned by another identity")
    return state


def _normalize_local_action_result(
    action_id: str,
    action_type: str,
    result: dict[str, Any],
    *,
    started_at: float,
    envelope_sha256: str,
) -> dict[str, Any]:
    if not isinstance(result, dict):
        raise ValueError("action executor result must be an object")
    candidate = dict(result)
    candidate.setdefault("action_type", action_type)
    candidate.setdefault("message", "action completed")
    candidate.setdefault("started_at", started_at)
    candidate.setdefault("completed_at", time.time())
    candidate["action_envelope_sha256"] = envelope_sha256
    normalized = validate_action_result({**candidate, "action_id": action_id})
    if normalized["action_type"] != action_type:
        raise ValueError("action executor changed the action type")
    normalized.pop("action_id", None)
    canonical_json_bytes(
        {**normalized, "action_id": action_id},
        max_bytes=AGENT_REQUEST_LIMITS["/api/v1/agent/result"],
    )
    return normalized


def execute_queued_action(
    journal: ActionJournal,
    executor: ActionExecutor,
    action: dict[str, Any],
    telemetry: dict[str, Any],
    health: dict[str, Any],
    event_profile: EventProfile | None = None,
) -> dict[str, Any]:
    """Execute at most once, including across a crash between action and result."""
    profile = event_profile or EventProfile.testing()
    binding_required = profile_requires_action_binding(profile)
    local_agent_id = telemetry.get("agent_id", "")
    if not isinstance(local_agent_id, str):
        local_agent_id = ""
    try:
        envelope = validate_action_request(
            action,
            expected_agent_id=local_agent_id,
            expected_profile_id=profile.profile_id,
            expected_profile_fingerprint=profile.fingerprint,
            expected_autonomy_mode=profile.autonomy_mode,
            require_binding=binding_required,
        )
    except ValidationError as exc:
        action_type = action.get("action_type")
        if not isinstance(action_type, str) or not action_type or len(action_type) > 128:
            action_type = "unknown"
        completed = time.time()
        return {
            "action_type": action_type,
            "success": False,
            "message": f"action envelope rejected: {exc}",
            "started_at": completed,
            "completed_at": completed,
        }
    action_id = envelope["action_id"]
    action_type = envelope["action_type"]
    expires_at = envelope["expires_at"]
    envelope_sha256 = canonical_action_envelope_sha256(envelope)
    # Check an existing tombstone before evaluating current policy so an action
    # identifier can never be silently rebound to a different valid envelope.
    record = journal.record(action_id, envelope_sha256)
    if record and record.get("status", "completed") == "completed":
        result = record.get("result")
        if isinstance(result, dict):
            replay = dict(result)
            replay["action_envelope_sha256"] = envelope_sha256
            return replay
        raise RuntimeError("completed action journal record has no result")
    if record and record.get("status") == "in_progress":
        interrupted_at = time.time()
        result = _normalize_local_action_result(
            action_id,
            action_type,
            {
                "success": False,
                "message": (
                    "prior action execution was interrupted; refusing automatic replay and "
                    "requiring state review"
                ),
                "interrupted": True,
            },
            started_at=float(record.get("started_at", interrupted_at)),
            envelope_sha256=envelope_sha256,
        )
        journal.remember(
            action_id,
            result,
            envelope_sha256,
            expires_at=expires_at,
            profile_fingerprint=envelope["profile_fingerprint"],
        )
        return result
    if not profile.action_allowed(
        action_type,
        automated=envelope["automated"],
        autonomy_mode=envelope["autonomy_mode"],
    ):
        refused_at = time.time()
        return _normalize_local_action_result(
            action_id,
            action_type,
            {
                "success": False,
                "message": "agent event profile refused the action",
            },
            started_at=refused_at,
            envelope_sha256=envelope_sha256,
        )
    if not journal.begin(
        action_id,
        action_type,
        envelope_sha256,
        expires_at=expires_at,
        profile_fingerprint=envelope["profile_fingerprint"],
    ):
        raise RuntimeError("action journal claim changed unexpectedly")
    execution_started = time.time()
    if health["action_safe"]:
        result = executor.execute(action_type, envelope["parameters"], telemetry)
    else:
        result = {
            "success": False,
            "message": "agent self-health gate refused the action",
            "errors": health["critical_errors"],
        }
    result = _normalize_local_action_result(
        action_id,
        action_type,
        result,
        started_at=execution_started,
        envelope_sha256=envelope_sha256,
    )
    journal.remember(
        action_id,
        result,
        envelope_sha256,
        expires_at=expires_at,
        profile_fingerprint=envelope["profile_fingerprint"],
    )
    return result


def process_controller_actions(
    client: AgentClient,
    result_outbox: ActionResultOutbox,
    journal: ActionJournal,
    executor: ActionExecutor,
    telemetry: dict[str, Any],
    health: dict[str, Any],
    event_profile: EventProfile,
) -> int:
    """Lease new work only when every older result is acknowledged."""
    if result_outbox.has_unacknowledged():
        LOG.warning(
            "holding new controller actions until durable results are acknowledged"
        )
        return 0
    processed = 0
    for action in client.actions():
        if not isinstance(action, dict):
            raise ValueError("controller action must be an object")
        action_id = action.get("action_id")
        if not isinstance(action_id, str):
            raise ValueError("controller action_id must be a string")
        refresh_recovery_health(
            executor, health, str(telemetry.get("boot_id", "unknown"))
        )
        result = execute_queued_action(
            journal, executor, action, telemetry, health, event_profile
        )
        result_outbox.enqueue(action_id, result)
        refresh_recovery_health(
            executor, health, str(telemetry.get("boot_id", "unknown"))
        )
        deliver_pending_action_results(client, result_outbox)
        processed += 1
        if result_outbox.has_unacknowledged():
            break
    return processed


def _run_with_windows_state_guard(
    args: argparse.Namespace, windows_state_guard: WindowsStateTreeGuard | None
) -> None:
    configure_agent_logging(args.log_level)
    agent_id = args.agent_id or default_agent_id()
    event_profile = load_event_profile(args.event_profile)
    event_profile.require_runtime_ready(
        range_deployment=bool(getattr(args, "range_deployment", False))
    )
    event_profile.verify_release_file(sys.argv[0])
    profile_digest = str(event_profile.release["sha256"]).casefold()
    if args.expected_package_sha256 and args.expected_package_sha256.casefold() != profile_digest:
        raise ValueError("--expected-package-sha256 does not match the event profile")
    args.expected_package_sha256 = profile_digest
    event_profile.assert_inventory_networks(
        args.authorized_network or list(event_profile.authorized_networks)
    )
    authorized_networks = list(event_profile.authorized_networks)
    authorized_hosts = list(event_profile.authorized_hosts)
    excluded_hosts = list(event_profile.excluded_hosts)
    if args.allow_containment and not event_profile.allows("session_containment"):
        raise ValueError("session containment is not authorized by the event profile")
    if args.allow_restoration and not event_profile.allows("file_restoration"):
        raise ValueError("file restoration is not authorized by the event profile")
    state_dir = prepare_state_directory(args.state_dir)
    log_file = getattr(args, "log_file", None)
    if log_file:
        configure_agent_logging(
            args.log_level,
            state_dir,
            log_file,
            getattr(args, "log_max_bytes", 5 * 1024 * 1024),
            getattr(args, "log_backups", 3),
        )
    process_lock = AgentProcessLock(state_dir).acquire()
    atexit.register(process_lock.close)
    identity_path = state_dir / "identity.json"
    reenroll = bool(getattr(args, "reenroll", False))
    bootstrap_token, agent_token, token_path = load_agent_credentials(
        identity_path,
        agent_id,
        event_profile.profile_id,
        event_profile.fingerprint,
        inline_token=getattr(args, "token", None),
        token_file=getattr(args, "token_file", None),
        reenroll=reenroll,
    )
    client = AgentClient(
        args.controller,
        bootstrap_token,
        agent_id,
        agent_token=agent_token,
        ca_file=args.ca_file,
        profile_id=event_profile.profile_id,
        profile_fingerprint=event_profile.fingerprint,
    )
    bootstrap_token = ""
    if hasattr(args, "token"):
        args.token = None
    if not client.agent_token:
        enroll_and_persist_identity(
            client,
            identity_path,
            agent_id=agent_id,
            hostname=socket.gethostname() or agent_id,
            platform_name=(
                f"{platform.system()} {platform.release()}".strip() or sys.platform
            ),
            profile_id=event_profile.profile_id,
            profile_fingerprint=event_profile.fingerprint,
            token_path=token_path,
        )
        LOG.warning(
            "agent %s completed %s",
            agent_id,
            "explicit ticket-gated re-enrollment" if reenroll else "first enrollment",
        )
    spool = TelemetrySpool(state_dir, max_items=args.spool_limit)
    journal = ActionJournal(
        state_dir, profile_fingerprint=event_profile.fingerprint
    )
    result_outbox = ActionResultOutbox(journal)
    sequence = SequenceCounter(state_dir)
    probe_specs: list[dict[str, Any]] = []
    integrity_paths: list[str] = []
    if args.probe_config:
        probe_path = Path(args.probe_config)
        if probe_path.is_symlink() or not probe_path.is_file() or probe_path.stat().st_size > 1024 * 1024:
            raise ValueError("probe config is unavailable, unsafe, or oversized")
        probe_data = read_private_json(probe_path, 1024 * 1024)
        if not isinstance(probe_data, dict):
            raise ValueError("probe config must be an object")
        if "probes" in probe_data and not isinstance(probe_data.get("probes"), list):
            raise ValueError("probe config probes must be an array")
        if "protected_paths" in probe_data and not isinstance(probe_data.get("protected_paths"), list):
            raise ValueError("probe config protected_paths must be an array")
        probe_specs = list(probe_data.get("probes", []))
        integrity_paths = [str(path) for path in probe_data.get("protected_paths", [])]
        if len(integrity_paths) > 256 or any(len(path) > 1024 for path in integrity_paths):
            raise ValueError("protected_paths exceeds safe bounds")
    executor = ActionExecutor(
        state_dir,
        args.allow_containment,
        authorized_networks,
        quarantine_ttl=args.quarantine_ttl,
        allow_restoration=args.allow_restoration,
        default_probes=probe_specs,
        authorized_hosts=authorized_hosts,
        excluded_hosts=excluded_hosts,
    )
    watcher = ChangeWatcher(
        integrity_watch_paths(integrity_paths),
        poll_interval=args.change_watch_interval,
    )
    if not args.once:
        watcher.start()
    LOG.warning(
        "agent %s starting; containment=%s restoration=%s",
        agent_id,
        args.allow_containment,
        args.allow_restoration,
    )
    systemd_notify("READY=1\nSTATUS=Sentinel Blue agent collecting defensive telemetry")
    while True:
        try:
            health = assess_agent_health(
                state_dir,
                args.expected_package_sha256,
            )
            refresh_windows_state_health(windows_state_guard, health)
            if client.agent_token:
                deliver_pending_action_results(client, result_outbox)
            collection_started = time.monotonic()
            telemetry = collect(
                agent_id,
                probe_specs,
                authorized_networks,
                integrity_paths,
                authorized_hosts=authorized_hosts,
                excluded_hosts=excluded_hosts,
            ).as_dict()
            telemetry["profile_id"] = event_profile.profile_id
            telemetry["profile_fingerprint"] = event_profile.fingerprint
            LOG.info(
                "telemetry collection completed in %.3f seconds",
                time.monotonic() - collection_started,
            )
            for component, healthy, error in (
                ("action journal", journal.healthy, journal.error),
                ("sequence state", sequence.healthy, sequence.error),
            ):
                if not healthy:
                    health["errors"].append(f"self-health: {component}: {error}")
                    health["critical_errors"].append(f"self-health: {component} requires review")
                    health["healthy"] = False
                    health["action_safe"] = False
            refresh_recovery_health(
                executor, health, str(telemetry.get("boot_id", "unknown"))
            )
            telemetry["collector_errors"].extend(health["errors"])
            telemetry["sequence"] = sequence.next()
            # The controller's observation digest includes the durable queue
            # timestamp.  Keep the exact submitted document in memory so an
            # action can be bound to this cycle byte-for-byte after ingest.
            telemetry["queued_at"] = time.time()
            spool.enqueue(telemetry)
            for queued_path, queued in spool.pending(limit=32):
                if not telemetry_matches_release_binding(queued, event_profile):
                    rejected = spool.reject(queued_path, "release-binding-mismatch")
                    LOG.warning(
                        "quarantined telemetry from an incompatible release binding as %s",
                        rejected.name,
                    )
                    continue
                try:
                    client.telemetry(queued)
                    spool.acknowledge(queued_path)
                except HTTPError as exc:
                    if exc.code in {400, 403} and getattr(
                        exc, "sentinel_blue_verified", False
                    ):
                        rejected = spool.reject(queued_path, f"controller-{exc.code}")
                        LOG.error(
                            "controller permanently rejected spooled telemetry (%s); preserved as %s",
                            getattr(exc, "sentinel_blue_error", "authenticated rejection"),
                            rejected.name,
                        )
                        continue
                    raise
            process_controller_actions(
                client,
                result_outbox,
                journal,
                executor,
                telemetry,
                health,
                event_profile,
            )
        except (
            HTTPError,
            URLError,
            TimeoutError,
            OSError,
            RuntimeError,
            ValueError,
            KeyError,
            ssl.SSLError,
        ) as exc:
            LOG.error("agent cycle failed: %s", exc)
        systemd_notify("WATCHDOG=1\nSTATUS=Sentinel Blue agent cycle complete")
        if args.once:
            watcher.stop()
            process_lock.close()
            return
        if watcher.wait(max(5.0, args.interval)):
            changed = watcher.changed_paths()
            LOG.warning("protected-file change triggered an early collection: %s", changed[:16])


def run(args: argparse.Namespace) -> None:
    """Run the agent while retaining the native Windows state-tree pins."""
    windows_state_guard = acquire_windows_state_tree(args.state_dir, initialize=True)
    if windows_state_guard is None:
        # The native guard is intentionally a no-op off Windows.
        _run_with_windows_state_guard(args, None)
        return

    cleanup = windows_state_guard.close
    atexit.register(cleanup)
    try:
        _run_with_windows_state_guard(args, windows_state_guard)
    finally:
        original = sys.exc_info()[1]
        atexit.unregister(cleanup)
        try:
            # --once returns through this path, so its native handles are closed
            # deterministically rather than waiting for interpreter shutdown.
            cleanup()
        except Exception as cleanup_error:
            # A partial CloseHandle failure is explicitly retryable by the guard.
            # Preserve the startup/runtime exception when one already exists and
            # retain an exit callback for one final cleanup attempt.
            atexit.register(cleanup)
            if original is None:
                raise
            original.add_note(
                f"Windows state guard cleanup also failed: {cleanup_error}"
            )
