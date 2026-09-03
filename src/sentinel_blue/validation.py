"""Strict wire validation and bounded normalization for untrusted agent input."""

from __future__ import annotations

import hashlib
import json
import math
import re
import time
from dataclasses import dataclass
from typing import Any

from .protocol import AlertCandidate
from .risk import FEATURES
from .policy import action_risk, validate_action_parameters
from .process_identity import validate_process_identity
from .json_codec import canonical_json_bytes


AGENT_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
ACTION_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
SHA256 = re.compile(r"^[a-fA-F0-9]{64}$")
CANONICAL_UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
MAX_TELEMETRY_AGE = 7 * 24 * 60 * 60
MAX_FUTURE_SKEW = 10 * 60
MAX_ACTION_AGE = 7 * 24 * 60 * 60
MAX_ACTION_LIFETIME = 24 * 60 * 60
MAX_ACTION_PARAMETER_BYTES = 512 * 1024
MAX_ACTION_PARAMETER_DEPTH = 12
MAX_ACTION_PARAMETER_ITEMS = 8192
ACTION_STATUSES = frozenset({"dispatched"})
ACTION_RISKS = frozenset({"none", "low", "medium", "high"})
ACTION_AUTONOMY_MODES = frozenset(
    {"observe", "interactive", "approval-based", "guarded-autonomous", "range-autonomous"}
)
ACTION_REQUEST_FIELDS = frozenset(
    {
        "action_id",
        "agent_id",
        "action_type",
        "parameters",
        "status",
        "created_at",
        "automated",
        "risk",
        "expires_at",
        "profile_id",
        "profile_fingerprint",
        "autonomy_mode",
    }
)

MODEL_FEATURE_BINDING_FIELD = "_sentinel_blue_model_features"
MODEL_FEATURE_SCHEMA = 1
MODEL_FEATURE_SCHEMA_SHA256 = hashlib.sha256(
    canonical_json_bytes(
        {"schema": MODEL_FEATURE_SCHEMA, "feature_names": list(FEATURES)}
    )
).hexdigest()
ACTION_RESULT_FIELDS = frozenset(
    {
        "action_id",
        "action_type",
        "success",
        "message",
        "started_at",
        "completed_at",
        "dry_run",
        "rolled_back",
        "interrupted",
        "record",
        "pre_state",
        "errors",
        "config_validation",
        "probes",
        "probe_attempts",
        "retention_warnings",
        "captured",
        "capture_receipts",
        "rejected",
        "transaction_id",
        "evidence_preserved",
        "action_envelope_sha256",
        "review_required",
    }
)


class ValidationError(ValueError):
    """Raised when an authenticated peer sends an unsafe or malformed payload."""


@dataclass(frozen=True, slots=True, init=False)
class ExactModelFeatures:
    """An immutable, canonical snapshot of the values actually scored.

    Feature names and numeric types are validated before the tuple is created;
    callers can obtain a fresh dictionary but cannot mutate the bound snapshot.
    The digest commits to both this release's ordered feature schema and the
    exact sparse mapping, including explicitly supplied zero values.
    """

    items: tuple[tuple[str, float], ...]
    sha256: str

    def __init__(self, value: Any, *, require_nonempty: bool = True) -> None:
        if not isinstance(value, dict) or len(value) > len(FEATURES):
            raise ValidationError("model features must be a bounded object")
        normalized: dict[str, float] = {}
        for name, raw in value.items():
            if not isinstance(name, str) or name not in FEATURES:
                raise ValidationError("model features contain an unknown feature")
            if type(raw) not in {int, float}:
                raise ValidationError(
                    "model feature values must be numeric without type coercion"
                )
            try:
                numeric = float(raw)
            except (OverflowError, ValueError):
                raise ValidationError("model feature values must be finite") from None
            if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
                raise ValidationError(
                    "model feature values must be finite and between zero and one"
                )
            normalized[name] = numeric
        if require_nonempty and not normalized:
            raise ValidationError("model features must not be empty")
        ordered = tuple((name, normalized[name]) for name in FEATURES if name in normalized)
        payload = {
            "schema": MODEL_FEATURE_SCHEMA,
            "feature_schema_sha256": MODEL_FEATURE_SCHEMA_SHA256,
            "values": dict(ordered),
        }
        object.__setattr__(self, "items", ordered)
        object.__setattr__(
            self,
            "sha256",
            hashlib.sha256(canonical_json_bytes(payload)).hexdigest(),
        )

    def as_dict(self) -> dict[str, float]:
        return dict(self.items)

    def as_binding(self) -> dict[str, Any]:
        return {
            "schema": MODEL_FEATURE_SCHEMA,
            "feature_schema_sha256": MODEL_FEATURE_SCHEMA_SHA256,
            "values": self.as_dict(),
            "sha256": self.sha256,
        }


class ModelBoundAlertCandidate(AlertCandidate):
    """A legacy-compatible alert whose scored features cannot be replaced.

    The base alert stays compatible with existing controller/store code.  The
    exact model input is held in a private immutable object and is also copied
    into a reserved evidence binding so older persistence paths retain it.
    """

    __slots__ = ("_exact_model_features",)

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "_exact_model_features" and hasattr(self, name):
            raise AttributeError("model feature binding is immutable")
        super().__setattr__(name, value)

    def __init__(
        self,
        kind: str,
        title: str,
        summary: str,
        severity: str,
        confidence: float,
        evidence: dict[str, Any],
        recommendation: str,
        recommended_action: str,
        *,
        model_features: Any,
    ) -> None:
        exact = ExactModelFeatures(model_features)
        if not isinstance(evidence, dict):
            raise ValidationError("alert evidence must be an object")
        if MODEL_FEATURE_BINDING_FIELD in evidence:
            raise ValidationError("alert evidence uses the reserved model-feature field")
        bound_evidence = dict(evidence)
        bound_evidence[MODEL_FEATURE_BINDING_FIELD] = exact.as_binding()
        super().__init__(
            kind=kind,
            title=title,
            summary=summary,
            severity=severity,
            confidence=confidence,
            evidence=bound_evidence,
            recommendation=recommendation,
            recommended_action=recommended_action,
        )
        self._exact_model_features = exact

    @property
    def model_features(self) -> dict[str, float]:
        return self._exact_model_features.as_dict()

    @property
    def model_features_sha256(self) -> str:
        return self._exact_model_features.sha256


def _text(value: Any, label: str, limit: int = 512, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{label} must be a string")
    if not empty and not value:
        raise ValidationError(f"{label} must not be empty")
    if len(value) > limit:
        raise ValidationError(f"{label} exceeds {limit} characters")
    if any(ord(character) < 32 and character not in "\t\r\n" for character in value):
        raise ValidationError(f"{label} contains control characters")
    return value


def _boolean(value: Any, label: str) -> bool:
    if type(value) is not bool:
        raise ValidationError(f"{label} must be a boolean")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValidationError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _number(value: Any, label: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationError(f"{label} must be numeric")
    try:
        result = float(value)
    except (OverflowError, ValueError):
        raise ValidationError(f"{label} is outside its accepted range") from None
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise ValidationError(f"{label} is outside its accepted range")
    return result


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValidationError(f"{label} must be an object with string keys")
    return value


def _rows(value: Any, label: str, maximum: int) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        raise ValidationError(f"{label} must be an array")
    if len(value) > maximum:
        raise ValidationError(f"{label} contains more than {maximum} entries")
    return [_object(item, f"{label}[{index}]") for index, item in enumerate(value)]


def validate_agent_id(value: Any) -> str:
    result = _text(value, "agent_id", 128)
    if not AGENT_ID.fullmatch(result):
        raise ValidationError("agent_id contains unsupported characters")
    return result


def _bounded_action_parameter(
    value: Any,
    label: str,
    *,
    depth: int,
    budget: list[int],
) -> Any:
    """Validate a JSON value without converting attacker-controlled types."""
    if depth > MAX_ACTION_PARAMETER_DEPTH:
        raise ValidationError(
            f"{label} exceeds the action parameter nesting limit"
        )
    budget[0] += 1
    if budget[0] > MAX_ACTION_PARAMETER_ITEMS:
        raise ValidationError("action parameters exceed the item budget")
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not -(2**63) <= value <= 2**63 - 1:
            raise ValidationError(f"{label} integer is outside the signed 64-bit range")
        return value
    if type(value) is float:
        if not math.isfinite(value) or abs(value) > 2**63 - 1:
            raise ValidationError(f"{label} number must be finite and bounded")
        return value
    if isinstance(value, str):
        if len(value) > 4096 or "\x00" in value:
            raise ValidationError(f"{label} string is invalid or exceeds 4096 characters")
        return value
    if isinstance(value, list):
        if len(value) > 512:
            raise ValidationError(f"{label} array exceeds 512 entries")
        return [
            _bounded_action_parameter(
                item,
                f"{label}[{index}]",
                depth=depth + 1,
                budget=budget,
            )
            for index, item in enumerate(value)
        ]
    if isinstance(value, dict):
        if len(value) > 512 or not all(isinstance(key, str) for key in value):
            raise ValidationError(
                f"{label} must have at most 512 bounded string keys"
            )
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not key or len(key) > 256 or "\x00" in key:
                raise ValidationError(f"{label} contains an invalid key")
            result[key] = _bounded_action_parameter(
                item,
                f"{label}.{key}",
                depth=depth + 1,
                budget=budget,
            )
        return result
    raise ValidationError(f"{label} contains a non-JSON value")


def _action_number(value: Any, label: str) -> int | float:
    """Accept a JSON number while preserving whether it was an int or float."""
    if type(value) not in {int, float}:
        raise ValidationError(f"{label} must be a number without type coercion")
    try:
        finite = math.isfinite(value)
    except (OverflowError, ValueError):
        finite = False
    if not finite:
        raise ValidationError(f"{label} must be finite")
    if not -(2**63) <= value <= 2**63 - 1:
        raise ValidationError(f"{label} is outside the signed 64-bit range")
    return value


def validate_action_request(
    value: Any,
    *,
    expected_agent_id: str,
    expected_profile_id: str,
    expected_profile_fingerprint: str,
    expected_autonomy_mode: str,
    require_binding: bool,
    now: float | None = None,
) -> dict[str, Any]:
    """Validate the complete controller-issued action envelope before claiming it.

    Bound deployments require every wire field.  The only compatibility path is
    the explicit, unbound disposable-test profile, whose old in-process fixtures
    may omit controller-populated fields.
    """
    payload = _object(value, "action request")
    unknown = set(payload) - set(ACTION_REQUEST_FIELDS)
    if unknown:
        raise ValidationError(
            "action request contains unknown fields: " + ", ".join(sorted(unknown))
        )
    required = {"action_id", "action_type", "parameters"}
    if require_binding:
        required = set(ACTION_REQUEST_FIELDS)
    missing = required - set(payload)
    if missing:
        raise ValidationError(
            "action request is missing fields: " + ", ".join(sorted(missing))
        )

    current = time.time() if now is None else now
    if not math.isfinite(current):
        raise ValidationError("action validation clock must be finite")
    action_id = _text(payload.get("action_id"), "action_id", 128)
    if not ACTION_ID.fullmatch(action_id):
        raise ValidationError("action_id contains unsupported characters")
    action_type = _text(payload.get("action_type"), "action_type", 128)
    try:
        expected_risk = action_risk(action_type)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    parameters = _bounded_action_parameter(
        payload.get("parameters"), "parameters", depth=0, budget=[0]
    )
    if not isinstance(parameters, dict):
        raise ValidationError("action parameters must be an object")
    try:
        encoded_parameters = json.dumps(
            parameters,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"action parameters are not canonical JSON: {exc}") from exc
    if len(encoded_parameters) > MAX_ACTION_PARAMETER_BYTES:
        raise ValidationError("action parameters exceed the 524288-byte budget")
    if require_binding:
        try:
            validate_action_parameters(
                action_type, parameters, require_process_binding=True
            )
        except ValueError as exc:
            raise ValidationError(f"action parameters are invalid: {exc}") from exc

    status = payload.get("status", "dispatched")
    if not isinstance(status, str) or status not in ACTION_STATUSES:
        raise ValidationError("action status must be dispatched")
    automated = payload.get("automated", False)
    if type(automated) is not bool:
        raise ValidationError("action automated must be a boolean")
    risk = payload.get("risk", expected_risk)
    if not isinstance(risk, str) or risk not in ACTION_RISKS or risk != expected_risk:
        raise ValidationError("action risk does not match the action type")
    autonomy_mode = payload.get("autonomy_mode", expected_autonomy_mode)
    if (
        not isinstance(autonomy_mode, str)
        or (
            autonomy_mode not in ACTION_AUTONOMY_MODES
            and not (not require_binding and autonomy_mode == "")
        )
    ):
        raise ValidationError("action autonomy mode is unsupported")

    created_at = _action_number(payload.get("created_at", 0), "action created_at")
    expires_at = _action_number(payload.get("expires_at", 0), "action expires_at")
    if require_binding:
        if not current - MAX_ACTION_AGE <= created_at <= current + MAX_FUTURE_SKEW:
            raise ValidationError("action created_at is outside the accepted time window")
        if expires_at <= current:
            raise ValidationError("action authorization expired before execution")
        if expires_at > current + MAX_ACTION_LIFETIME:
            raise ValidationError("action expires_at exceeds the maximum authorization lifetime")
        if expires_at <= created_at or expires_at - created_at > MAX_ACTION_LIFETIME:
            raise ValidationError("action authorization timestamps are inconsistent")
    elif expires_at and expires_at <= current:
        raise ValidationError("action authorization expired before execution")

    agent_id = payload.get("agent_id", expected_agent_id if require_binding else "")
    if agent_id:
        agent_id = validate_agent_id(agent_id)
    elif not isinstance(agent_id, str):
        raise ValidationError("action agent_id must be a string")
    profile_id = payload.get("profile_id", expected_profile_id if require_binding else "")
    profile_fingerprint = payload.get(
        "profile_fingerprint",
        expected_profile_fingerprint if require_binding else "",
    )
    if not isinstance(profile_id, str) or len(profile_id) > 128:
        raise ValidationError("action profile_id must be a bounded string")
    if not isinstance(profile_fingerprint, str) or len(profile_fingerprint) > 64:
        raise ValidationError("action profile_fingerprint must be a bounded string")
    if profile_fingerprint and not SHA256.fullmatch(profile_fingerprint):
        raise ValidationError("action profile_fingerprint is not a SHA-256 digest")
    if require_binding:
        if agent_id != expected_agent_id:
            raise ValidationError("action agent binding does not match this agent")
        if (
            profile_id != expected_profile_id
            or profile_fingerprint != expected_profile_fingerprint
        ):
            raise ValidationError(
                "action event-profile binding does not match this agent"
            )
    else:
        if agent_id not in {"", expected_agent_id}:
            raise ValidationError("action agent binding does not match this agent")
        if profile_id not in {"", expected_profile_id} or profile_fingerprint not in {
            "",
            expected_profile_fingerprint,
        }:
            raise ValidationError(
                "action event-profile binding does not match this agent"
            )

    return {
        "action_id": action_id,
        "agent_id": agent_id,
        "action_type": action_type,
        "parameters": parameters,
        "status": status,
        "created_at": created_at,
        "automated": automated,
        "risk": risk,
        "expires_at": expires_at,
        "profile_id": profile_id,
        "profile_fingerprint": profile_fingerprint,
        "autonomy_mode": autonomy_mode,
    }


def canonical_action_envelope_sha256(action: dict[str, Any]) -> str:
    """Return a stable digest of an already validated action envelope."""
    try:
        encoded = json.dumps(
            action,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"action envelope is not canonical JSON: {exc}") from exc
    return hashlib.sha256(encoded).hexdigest()


def _string_array(value: Any, label: str, maximum: int = 64) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValidationError(f"{label} must be an array of at most {maximum} strings")
    return [_text(item, f"{label}[{index}]", 256) for index, item in enumerate(value)]


def _account(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"accounts[{index}]"
    return {
        "name": _text(row.get("name"), f"{label}.name", 128),
        "account_id": _text(str(row.get("account_id", "")), f"{label}.account_id", 256, empty=True),
        "privileged": _boolean(row.get("privileged", False), f"{label}.privileged"),
        "enabled": _boolean(row.get("enabled", True), f"{label}.enabled"),
        "source": _text(row.get("source", "local"), f"{label}.source", 128),
        "groups": _string_array(row.get("groups", []), f"{label}.groups"),
    }


def _session(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"sessions[{index}]"
    process_id = row.get("process_id")
    identity = row.get("process_identity")
    if identity is not None:
        try:
            identity = validate_process_identity(identity)
        except ValueError as exc:
            raise ValidationError(f"{label}.process_identity is invalid: {exc}") from exc
        if process_id is None or identity["process_id"] != process_id:
            raise ValidationError(
                f"{label}.process_identity does not match process_id"
            )
    return {
        "username": _text(row.get("username"), f"{label}.username", 128),
        "source": _text(row.get("source", "unknown"), f"{label}.source", 256),
        "session_id": _text(str(row.get("session_id", "")), f"{label}.session_id", 256, empty=True),
        "process_id": None if process_id is None else _integer(process_id, f"{label}.process_id", 1, 2**31 - 1),
        "privileged": _boolean(row.get("privileged", False), f"{label}.privileged"),
        "interactive": _boolean(row.get("interactive", True), f"{label}.interactive"),
        "process_identity": identity,
    }


def _service(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"services[{index}]"
    exit_code = row.get("exit_code")
    return {
        "name": _text(row.get("name"), f"{label}.name", 256),
        "state": _text(row.get("state", "unknown"), f"{label}.state", 64),
        "start_mode": _text(row.get("start_mode", "unknown"), f"{label}.start_mode", 64),
        "substate": _text(row.get("substate", "unknown"), f"{label}.substate", 64),
        "result": _text(row.get("result", "unknown"), f"{label}.result", 128),
        "restart_count": _integer(
            row.get("restart_count", 0), f"{label}.restart_count", 0, 2**31 - 1
        ),
        "exit_code": (
            None
            if exit_code is None
            else _integer(exit_code, f"{label}.exit_code", 0, 2**31 - 1)
        ),
    }


def _interface(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"interfaces[{index}]"
    return {
        "name": _text(row.get("name"), f"{label}.name", 128),
        "addresses": _string_array(row.get("addresses", []), f"{label}.addresses", 64),
    }


def _route(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"routes[{index}]"
    metric = row.get("metric")
    return {
        "destination": _text(row.get("destination"), f"{label}.destination", 128),
        "gateway": _text(row.get("gateway", ""), f"{label}.gateway", 128, empty=True),
        "interface": _text(row.get("interface", ""), f"{label}.interface", 128, empty=True),
        "metric": None if metric is None else _integer(metric, f"{label}.metric", 0, 2**31 - 1),
    }


def _neighbor(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"neighbors[{index}]"
    return {
        "address": _text(row.get("address"), f"{label}.address", 128),
        "hardware_address": _text(row.get("hardware_address", ""), f"{label}.hardware_address", 128, empty=True),
        "interface": _text(row.get("interface", ""), f"{label}.interface", 128, empty=True),
        "state": _text(row.get("state", "unknown"), f"{label}.state", 64),
    }


def _listener(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"listeners[{index}]"
    return {
        "protocol": _text(row.get("protocol", "tcp"), f"{label}.protocol", 16),
        "address": _text(row.get("address", ""), f"{label}.address", 128, empty=True),
        "port": _integer(row.get("port"), f"{label}.port", 1, 65535),
        "process": _text(row.get("process", ""), f"{label}.process", 512, empty=True),
    }


def _integrity(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"integrity[{index}]"
    digest = _text(row.get("sha256"), f"{label}.sha256", 64)
    if not SHA256.fullmatch(digest):
        raise ValidationError(f"{label}.sha256 is not a SHA-256 digest")
    security_digest = _text(
        row.get("security_descriptor_sha256", ""),
        f"{label}.security_descriptor_sha256",
        64,
        empty=True,
    )
    if security_digest and not SHA256.fullmatch(security_digest):
        raise ValidationError(
            f"{label}.security_descriptor_sha256 is not a SHA-256 digest"
        )
    return {
        "path": _text(row.get("path"), f"{label}.path", 1024),
        "sha256": digest.casefold(),
        "size": _integer(row.get("size", 0), f"{label}.size", 0, 2**63 - 1),
        "modified_at": _number(row.get("modified_at", 0), f"{label}.modified_at", 0, 2**63 - 1),
        "readable": _boolean(row.get("readable", True), f"{label}.readable"),
        "security_descriptor_sha256": security_digest.casefold(),
    }


def _probe(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"probes[{index}]"
    latency = row.get("latency_ms")
    return {
        "name": _text(row.get("name"), f"{label}.name", 256),
        "target": _text(row.get("target"), f"{label}.target", 2048),
        "healthy": _boolean(row.get("healthy"), f"{label}.healthy"),
        "latency_ms": None if latency is None else _number(latency, f"{label}.latency_ms", 0, 3_600_000),
        "detail": _text(row.get("detail", ""), f"{label}.detail", 2048, empty=True),
    }


def _process(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"processes[{index}]"
    return {
        "name": _text(row.get("name", "unknown"), f"{label}.name", 256),
        "path": _text(row.get("path", ""), f"{label}.path", 1024, empty=True),
        "username": _text(row.get("username", "unknown"), f"{label}.username", 128),
        "process_id": _integer(row.get("process_id"), f"{label}.process_id", 1, 2**31 - 1),
        "parent_id": _integer(row.get("parent_id", 0), f"{label}.parent_id", 0, 2**31 - 1),
        "privileged": _boolean(row.get("privileged", False), f"{label}.privileged"),
    }


def _persistence(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"persistence[{index}]"
    digest = _text(row.get("sha256", ""), f"{label}.sha256", 64, empty=True)
    if digest and not SHA256.fullmatch(digest):
        raise ValidationError(f"{label}.sha256 is not a SHA-256 digest")
    return {
        "kind": _text(row.get("kind"), f"{label}.kind", 64),
        "name": _text(row.get("name"), f"{label}.name", 512),
        "owner": _text(row.get("owner", "unknown"), f"{label}.owner", 128),
        "enabled": _boolean(row.get("enabled", True), f"{label}.enabled"),
        "sha256": digest.casefold(),
    }


def _security_event(row: dict[str, Any], index: int) -> dict[str, Any]:
    label = f"security_events[{index}]"
    return {
        "event_id": _text(row.get("event_id"), f"{label}.event_id", 256),
        "category": _text(row.get("category"), f"{label}.category", 64),
        "outcome": _text(row.get("outcome", "observed"), f"{label}.outcome", 64),
        "account": _text(row.get("account", "unknown"), f"{label}.account", 128),
        "actor": _text(row.get("actor", "unknown"), f"{label}.actor", 128),
        "remote_address": _text(
            row.get("remote_address", "unknown"), f"{label}.remote_address", 256
        ),
        "occurred_at": _number(
            row.get("occurred_at", 0), f"{label}.occurred_at", 0, 2**63 - 1
        ),
        "detail": _text(row.get("detail", ""), f"{label}.detail", 1024, empty=True),
    }


def _firewall(value: Any) -> dict[str, Any]:
    row = _object(value, "firewall")
    digest = _text(row.get("rules_sha256", ""), "firewall.rules_sha256", 64, empty=True)
    if digest and not SHA256.fullmatch(digest):
        raise ValidationError("firewall.rules_sha256 is not a SHA-256 digest")
    return {
        "enabled": _boolean(row.get("enabled", False), "firewall.enabled"),
        "provider": _text(row.get("provider", "unknown"), "firewall.provider", 128),
        "rules_sha256": digest.casefold(),
        "detail": _text(row.get("detail", ""), "firewall.detail", 512, empty=True),
    }


def validate_telemetry(
    value: Any,
    expected_agent_id: str | None = None,
    *,
    now: float | None = None,
) -> dict[str, Any]:
    payload = _object(value, "telemetry")
    agent_id = validate_agent_id(payload.get("agent_id"))
    if expected_agent_id is not None and agent_id != expected_agent_id:
        raise ValidationError("telemetry agent_id does not match the authenticated agent")
    current = time.time() if now is None else now
    observed_at = _number(payload.get("observed_at"), "observed_at", 0, current + MAX_FUTURE_SKEW)
    if observed_at < current - MAX_TELEMETRY_AGE:
        raise ValidationError("telemetry is older than the seven-day replay limit")

    result: dict[str, Any] = {
        "agent_id": agent_id,
        "hostname": _text(payload.get("hostname"), "hostname", 256),
        "platform": _text(payload.get("platform"), "platform", 256),
        "observed_at": observed_at,
        "agent_version": _text(payload.get("agent_version", "unknown"), "agent_version", 64),
        "profile_id": _text(payload.get("profile_id", ""), "profile_id", 128, empty=True),
        "profile_fingerprint": _text(
            payload.get("profile_fingerprint", ""),
            "profile_fingerprint",
            64,
            empty=True,
        ).casefold(),
        "boot_id": _text(payload.get("boot_id", "unknown"), "boot_id", 256),
        "sequence": _integer(payload.get("sequence", 0), "sequence", 0, 2**63 - 1),
    }
    if result["profile_fingerprint"] and not SHA256.fullmatch(
        result["profile_fingerprint"]
    ):
        raise ValidationError("profile_fingerprint is not a SHA-256 digest")
    specifications = (
        ("accounts", 4096, _account),
        ("sessions", 1024, _session),
        ("services", 4096, _service),
        ("interfaces", 512, _interface),
        ("routes", 4096, _route),
        ("neighbors", 4096, _neighbor),
        ("listeners", 4096, _listener),
        ("integrity", 2048, _integrity),
        ("probes", 1024, _probe),
        ("processes", 4096, _process),
        ("persistence", 4096, _persistence),
        ("security_events", 1024, _security_event),
    )
    for name, maximum, normalizer in specifications:
        result[name] = [
            normalizer(row, index)
            for index, row in enumerate(_rows(payload.get(name, []), name, maximum))
        ]
    result["firewall"] = _firewall(payload.get("firewall", {}))
    result["collector_errors"] = _string_array(payload.get("collector_errors", []), "collector_errors", 256)
    queued_at = payload.get("queued_at")
    if queued_at is not None:
        result["queued_at"] = _number(queued_at, "queued_at", 0, current + MAX_FUTURE_SKEW)
    return result


def telemetry_observation_sha256(value: Any) -> str:
    """Digest the exact normalized telemetry document used by the controller."""
    normalized = validate_telemetry(value)
    return hashlib.sha256(canonical_json_bytes(normalized)).hexdigest()


def validate_action_result(
    value: Any, *, require_envelope_sha256: bool = False
) -> dict[str, Any]:
    payload = _object(value, "action result")
    unknown = set(payload) - set(ACTION_RESULT_FIELDS)
    if unknown:
        raise ValidationError(
            "action result contains unknown fields: " + ", ".join(sorted(unknown))
        )
    required = {
        "action_id",
        "action_type",
        "success",
        "message",
        "started_at",
        "completed_at",
    }
    missing = required - set(payload)
    if missing:
        raise ValidationError(
            "action result is missing fields: " + ", ".join(sorted(missing))
        )
    action_id = _text(payload.get("action_id"), "action_id", 128)
    if not ACTION_ID.fullmatch(action_id):
        raise ValidationError("action_id contains unsupported characters")
    result: dict[str, Any] = {
        "action_id": action_id,
        "action_type": _text(payload.get("action_type"), "action_type", 128),
        "success": _boolean(payload.get("success"), "success"),
        "message": _text(payload.get("message", ""), "message", 4096, empty=True),
        # Preserve the exact JSON numeric type.  Terminal retry equivalence is
        # byte-canonical and must not silently collapse ``1`` into ``1.0``.
        "started_at": _action_number(payload["started_at"], "started_at"),
        "completed_at": _action_number(payload["completed_at"], "completed_at"),
    }
    if not 0 <= result["started_at"] <= 2**63 - 1:
        raise ValidationError("started_at is outside its accepted range")
    if not 0 <= result["completed_at"] <= 2**63 - 1:
        raise ValidationError("completed_at is outside its accepted range")
    raw_envelope_sha256 = payload.get("action_envelope_sha256")
    if raw_envelope_sha256 is not None:
        envelope_sha256 = _text(
            raw_envelope_sha256, "action_envelope_sha256", 64
        ).casefold()
        if not SHA256.fullmatch(envelope_sha256):
            raise ValidationError(
                "action_envelope_sha256 is not a SHA-256 digest"
            )
        result["action_envelope_sha256"] = envelope_sha256
    elif require_envelope_sha256:
        raise ValidationError(
            "action_envelope_sha256 is required for a bound action result"
        )
    for flag in ("dry_run", "rolled_back", "interrupted", "review_required"):
        if flag in payload:
            result[flag] = _boolean(payload[flag], flag)
    if result["completed_at"] < result["started_at"]:
        raise ValidationError("completed_at must not precede started_at")
    if result["success"] and (
        result.get("rolled_back", False)
        or result.get("interrupted", False)
        or result.get("review_required", False)
    ):
        raise ValidationError(
            "a successful action result cannot be rolled back or interrupted"
        )
    nested_budget = [0]
    for name in ("record", "pre_state"):
        if name in payload:
            normalized = _bounded_action_parameter(
                payload[name], name, depth=0, budget=nested_budget
            )
            if not isinstance(normalized, dict):
                raise ValidationError(f"{name} must be an object")
            result[name] = normalized
    if "errors" in payload:
        result["errors"] = _string_array(payload["errors"], "errors", 32)
    if "retention_warnings" in payload:
        result["retention_warnings"] = _string_array(
            payload["retention_warnings"], "retention_warnings", 32
        )
    if "captured" in payload:
        captured = payload["captured"]
        if not isinstance(captured, list) or len(captured) > 512:
            raise ValidationError("captured must be an array of at most 512 paths")
        result["captured"] = [
            _text(item, f"captured[{index}]", 1024)
            for index, item in enumerate(captured)
        ]
    if "capture_receipts" in payload:
        receipts: list[dict[str, Any]] = []
        paths: set[str] = set()
        identifiers: set[str] = set()
        exact_fields = {
            "path",
            "source_sha256",
            "backup_sha256",
            "backup_matches_source",
            "byte_size",
            "security_metadata_sha256",
            "security_descriptor_sha256",
            "restore_point_id",
            "stored",
        }
        for index, row in enumerate(
            _rows(payload["capture_receipts"], "capture_receipts", 256)
        ):
            if set(row) != exact_fields:
                raise ValidationError(
                    f"capture_receipts[{index}] has an incomplete or unknown field set"
                )
            path = _text(row.get("path"), f"capture_receipts[{index}].path", 1024)
            source = _text(
                row.get("source_sha256"),
                f"capture_receipts[{index}].source_sha256",
                64,
            ).casefold()
            backup = _text(
                row.get("backup_sha256"),
                f"capture_receipts[{index}].backup_sha256",
                64,
            ).casefold()
            metadata = _text(
                row.get("security_metadata_sha256"),
                f"capture_receipts[{index}].security_metadata_sha256",
                64,
            ).casefold()
            descriptor = _text(
                row.get("security_descriptor_sha256", ""),
                f"capture_receipts[{index}].security_descriptor_sha256",
                64,
                empty=True,
            ).casefold()
            identifier = _text(
                row.get("restore_point_id"),
                f"capture_receipts[{index}].restore_point_id",
                36,
            )
            if any(not SHA256.fullmatch(item) for item in (source, backup, metadata)):
                raise ValidationError(
                    f"capture_receipts[{index}] contains an invalid SHA-256 digest"
                )
            if descriptor and not SHA256.fullmatch(descriptor):
                raise ValidationError(
                    f"capture_receipts[{index}] security descriptor digest is invalid"
                )
            if source != backup:
                raise ValidationError(
                    f"capture_receipts[{index}] backup does not match its source"
                )
            if not CANONICAL_UUID.fullmatch(identifier):
                raise ValidationError(
                    f"capture_receipts[{index}] restore-point identity is invalid"
                )
            if path in paths or identifier in identifiers:
                raise ValidationError("capture receipts contain duplicate paths or identities")
            paths.add(path)
            identifiers.add(identifier)
            receipt = {
                "path": path,
                "source_sha256": source,
                "backup_sha256": backup,
                "backup_matches_source": _boolean(
                    row.get("backup_matches_source"),
                    f"capture_receipts[{index}].backup_matches_source",
                ),
                "byte_size": _integer(
                    row.get("byte_size"),
                    f"capture_receipts[{index}].byte_size",
                    0,
                    2**63 - 1,
                ),
                "security_metadata_sha256": metadata,
                "security_descriptor_sha256": descriptor,
                "restore_point_id": identifier,
                "stored": _boolean(
                    row.get("stored"), f"capture_receipts[{index}].stored"
                ),
            }
            if (
                receipt["backup_matches_source"] is not True
                or receipt["stored"] is not True
            ):
                raise ValidationError(
                    f"capture_receipts[{index}] does not attest durable exact storage"
                )
            receipts.append(receipt)
        result["capture_receipts"] = receipts
    if "rejected" in payload:
        rejected: list[dict[str, str]] = []
        for index, row in enumerate(_rows(payload["rejected"], "rejected", 512)):
            unknown_nested = set(row) - {"path", "reason"}
            if unknown_nested:
                raise ValidationError(
                    f"rejected[{index}] contains unknown fields: "
                    + ", ".join(sorted(unknown_nested))
                )
            rejected.append({
                "path": _text(
                    row.get("path", ""),
                    f"rejected[{index}].path",
                    1024,
                    empty=True,
                ),
                "reason": _text(
                    row.get("reason", ""),
                    f"rejected[{index}].reason",
                    1024,
                    empty=True,
                ),
            })
        result["rejected"] = rejected
    if result["action_type"] == "capture_restore_point" and result["success"]:
        receipts = result.get("capture_receipts")
        captured = result.get("captured")
        if (
            result.get("dry_run") is not False
            or not isinstance(receipts, list)
            or not receipts
            or captured != [item["path"] for item in receipts]
            or result.get("rejected", [])
        ):
            raise ValidationError(
                "successful restore-point capture lacks exact durable receipts"
            )
    if "transaction_id" in payload:
        result["transaction_id"] = _text(
            payload["transaction_id"], "transaction_id", 128
        )
    if "evidence_preserved" in payload:
        result["evidence_preserved"] = _boolean(
            payload["evidence_preserved"], "evidence_preserved"
        )
    if "config_validation" in payload:
        raw_validation = _object(payload["config_validation"], "config_validation")
        unknown_nested = set(raw_validation) - {
            "applicable", "available", "healthy", "validator", "detail"
        }
        if unknown_nested:
            raise ValidationError(
                "config_validation contains unknown fields: "
                + ", ".join(sorted(unknown_nested))
            )
        healthy = raw_validation.get("healthy")
        validator = raw_validation.get("validator")
        result["config_validation"] = {
            "applicable": _boolean(
                raw_validation.get("applicable"), "config_validation.applicable"
            ),
            "available": _boolean(
                raw_validation.get("available"), "config_validation.available"
            ),
            "healthy": (
                None
                if healthy is None
                else _boolean(healthy, "config_validation.healthy")
            ),
            "validator": (
                None
                if validator is None
                else _text(validator, "config_validation.validator", 128)
            ),
            "detail": _text(
                raw_validation.get("detail", ""),
                "config_validation.detail",
                500,
                empty=True,
            ),
        }
    if "probes" in payload:
        normalized_probes: list[dict[str, Any]] = []
        for index, row in enumerate(_rows(payload["probes"], "probes", 256)):
            unknown_nested = set(row) - {
                "name", "target", "healthy", "latency_ms", "detail"
            }
            if unknown_nested:
                raise ValidationError(
                    f"probes[{index}] contains unknown fields: "
                    + ", ".join(sorted(unknown_nested))
                )
            normalized_probes.append(_probe(row, index))
        result["probes"] = normalized_probes
    if "probe_attempts" in payload:
        if result["action_type"] != "restart_service":
            raise ValidationError(
                "probe_attempts is valid only for restart_service results"
            )
        result["probe_attempts"] = _integer(
            payload["probe_attempts"], "probe_attempts", 0, 64
        )
    try:
        encoded = json.dumps(
            result,
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError(f"action result is not canonical JSON: {exc}") from exc
    if len(encoded) > MAX_ACTION_PARAMETER_BYTES:
        raise ValidationError("action result exceeds the 524288-byte budget")
    return result
