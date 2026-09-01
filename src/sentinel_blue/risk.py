"""Small, auditable offline model used to rank defensive alerts."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import stat
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Iterable


MAX_MODEL_BYTES = 1024 * 1024
MAX_ABSOLUTE_BIAS = 30.0
MAX_ABSOLUTE_WEIGHT = 20.0
SHA256 = re.compile(r"^[0-9a-f]{64}$")
LINEAGE_FIELDS = frozenset(
    {
        "schema",
        "kind",
        "trusted_base_fingerprint",
        "training_data_fingerprint",
        "maximum_weight_delta_from_bundled",
        "regression_metrics",
    }
)
REGRESSION_METRICS = frozenset({"accuracy", "brier", "log_loss", "roc_auc"})


FEATURES = (
    "unknown_privileged_account",
    "new_privileged_account",
    "interactive_privileged_session",
    "external_source",
    "protected_identity",
    "critical_service_stopped",
    "integrity_change",
    "default_route_change",
    "probe_failure",
    "new_listener",
    "collector_failure",
    "protected_identity_loss",
    "privilege_membership_change",
    "service_configuration_change",
    "persistence_change",
    "privileged_persistence",
    "firewall_disabled",
    "firewall_rule_change",
    "suspicious_process_path",
    "agent_heartbeat_missing",
)


KIND_FEATURES: dict[str, dict[str, float]] = {
    "unverified_privileged_account": {
        "unknown_privileged_account": 1.0,
        "new_privileged_account": 1.0,
    },
    "unverified_privileged_session": {
        "interactive_privileged_session": 1.0,
        "external_source": 1.0,
    },
    "baseline_service_stopped": {"critical_service_stopped": 1.0},
    "critical_file_changed": {"integrity_change": 1.0},
    "default_route_changed": {"default_route_change": 1.0},
    "service_probe_failed": {"probe_failure": 1.0},
    "new_network_listener": {"new_listener": 1.0},
    "telemetry_degraded": {"collector_failure": 1.0},
    "protected_identity_unavailable": {"protected_identity_loss": 1.0},
    "privilege_membership_changed": {"privilege_membership_change": 1.0},
    "service_startup_disabled": {"service_configuration_change": 1.0},
    "persistence_changed": {"persistence_change": 1.0},
    "new_persistence_item": {"persistence_change": 1.0},
    "host_firewall_disabled": {"firewall_disabled": 1.0},
    "host_firewall_rules_changed": {"firewall_rule_change": 1.0},
    "privileged_temporary_process": {"suspicious_process_path": 1.0},
    "agent_heartbeat_missing": {"agent_heartbeat_missing": 1.0},
}


def features_for_kind(kind: str) -> dict[str, float]:
    return {name: float(value) for name, value in KIND_FEATURES.get(kind, {}).items()}


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError(f"risk model JSON contains duplicate field {name!r}")
        result[name] = value
    return result


def _invalid_json_constant(value: str) -> None:
    raise ValueError(f"risk model JSON contains non-finite constant {value}")


def _read_model_bytes(path: str | Path) -> bytes:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError("risk model is unavailable or is a symbolic link")
    descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode):
            raise ValueError("risk model is not a regular file")
        if details.st_size > MAX_MODEL_BYTES:
            raise ValueError("risk model exceeds its size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(MAX_MODEL_BYTES + 1)
        if len(raw) > MAX_MODEL_BYTES:
            raise ValueError("risk model exceeds its size limit")
        return raw
    finally:
        os.close(descriptor)


def _strict_json(raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("risk model is not valid UTF-8") from exc
    try:
        return json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_invalid_json_constant,
        )
    except json.JSONDecodeError as exc:
        raise ValueError("risk model is not valid JSON") from exc


@dataclass
class RiskModel:
    weights: dict[str, float] = field(
        default_factory=lambda: {
            "unknown_privileged_account": 1.4,
            "new_privileged_account": 1.2,
            "interactive_privileged_session": 1.0,
            "external_source": 0.8,
            "protected_identity": -3.0,
            "critical_service_stopped": 1.7,
            "integrity_change": 1.9,
            "default_route_change": 1.8,
            "probe_failure": 1.8,
            "new_listener": 0.7,
            "collector_failure": 0.3,
            "protected_identity_loss": 2.4,
            "privilege_membership_change": 2.2,
            "service_configuration_change": 1.5,
            "persistence_change": 1.3,
            "privileged_persistence": 1.0,
            "firewall_disabled": 2.3,
            "firewall_rule_change": 1.5,
            "suspicious_process_path": 1.8,
            "agent_heartbeat_missing": 1.5,
        }
    )
    bias: float = -1.1

    def predict(self, features: dict[str, float]) -> float:
        score = self.bias + sum(self.weights.get(name, 0.0) * value for name, value in features.items())
        score = max(-30.0, min(30.0, score))
        return 1.0 / (1.0 + math.exp(-score))

    def train(
        self,
        samples: Iterable[tuple[dict[str, float], int]],
        epochs: int = 200,
        learning_rate: float = 0.08,
        l2: float = 0.002,
    ) -> None:
        materialized = list(samples)
        if not materialized:
            return
        for _ in range(epochs):
            for features, label in materialized:
                prediction = self.predict(features)
                error = prediction - float(label)
                self.bias -= learning_rate * error
                for name in FEATURES:
                    current = self.weights.get(name, 0.0)
                    gradient = error * features.get(name, 0.0) + l2 * current
                    self.weights[name] = current - learning_rate * gradient

    def save(
        self,
        path: str | Path,
        *,
        lineage: dict[str, Any] | None = None,
    ) -> None:
        from .state import write_private_json

        validated = type(self).from_dict({"bias": self.bias, "weights": self.weights})
        payload: dict[str, Any] = {
            "bias": validated.bias,
            "weights": validated.weights,
        }
        if lineage is not None:
            if not isinstance(lineage, dict):
                raise ValueError("risk model lineage must be an object")
            payload["lineage"] = lineage
            type(self)._validate_lineage(lineage)
        write_private_json(path, payload)

    def fingerprint(self) -> str:
        """Return a stable semantic digest for model lineage checks."""
        validated = type(self).from_dict({"bias": self.bias, "weights": self.weights})
        encoded = json.dumps(
            {"bias": validated.bias, "weights": validated.weights},
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @classmethod
    def bundled(cls) -> "RiskModel":
        """Load the immutable model shipped inside this exact runtime."""
        raw = files("sentinel_blue").joinpath("models/risk-v1.0.json").read_bytes()
        if len(raw) > MAX_MODEL_BYTES:
            raise ValueError("bundled risk model exceeds its size limit")
        return cls.from_dict(_strict_json(raw))

    @classmethod
    def load(
        cls,
        path: str | Path,
        *,
        expected_sha256: str | None = None,
    ) -> "RiskModel":
        """Read, optionally authenticate, and parse one immutable byte snapshot."""
        raw = _read_model_bytes(path)
        if expected_sha256 is not None:
            if not isinstance(expected_sha256, str) or not SHA256.fullmatch(expected_sha256):
                raise ValueError("expected risk model digest must be a lowercase SHA-256")
            observed = hashlib.sha256(raw).hexdigest()
            if not hmac.compare_digest(observed, expected_sha256):
                raise ValueError("risk model digest does not match the approved profile")
        return cls.from_dict(_strict_json(raw))

    @classmethod
    def load_verified(cls, path: str | Path, expected_sha256: str) -> "RiskModel":
        """Load an approved model without a verify/reopen race."""
        return cls.load(path, expected_sha256=expected_sha256)

    @staticmethod
    def _bounded_number(value: object, label: str, maximum: float) -> float:
        if type(value) not in {int, float}:
            raise ValueError(f"risk model {label} must be numeric without type coercion")
        try:
            numeric = float(value)
        except OverflowError as exc:
            raise ValueError(f"risk model {label} is outside the safe range") from exc
        if not math.isfinite(numeric) or abs(numeric) > maximum:
            raise ValueError(f"risk model {label} is outside the safe range")
        return numeric

    @classmethod
    def _validate_lineage(cls, lineage: object) -> None:
        if not isinstance(lineage, dict) or set(lineage) != LINEAGE_FIELDS:
            raise ValueError("risk model lineage does not match schema 1")
        if type(lineage.get("schema")) is not int or lineage["schema"] != 1:
            raise ValueError("risk model lineage does not match schema 1")
        if lineage.get("kind") != "sentinel-blue-adaptive-confidence-model":
            raise ValueError("risk model lineage kind is invalid")
        for name in ("trusted_base_fingerprint", "training_data_fingerprint"):
            if not isinstance(lineage.get(name), str) or not SHA256.fullmatch(lineage[name]):
                raise ValueError(f"risk model lineage {name} must be a lowercase SHA-256")
        delta = cls._bounded_number(
            lineage.get("maximum_weight_delta_from_bundled"),
            "lineage weight delta",
            1.0,
        )
        if delta <= 0.0:
            raise ValueError("risk model lineage weight delta must be positive")
        metrics = lineage.get("regression_metrics")
        if not isinstance(metrics, dict) or set(metrics) != REGRESSION_METRICS:
            raise ValueError("risk model lineage regression metrics are incomplete")
        for name, value in metrics.items():
            maximum = 1.0 if name in {"accuracy", "brier", "roc_auc"} else 100.0
            numeric = cls._bounded_number(value, f"lineage metric {name}", maximum)
            if numeric < 0.0:
                raise ValueError(f"risk model lineage metric {name} cannot be negative")

    @classmethod
    def from_dict(cls, data: object) -> "RiskModel":
        if not isinstance(data, dict) or not isinstance(data.get("weights"), dict):
            raise ValueError("risk model must contain a weights object")
        if not set(data).issubset({"bias", "weights", "lineage"}):
            raise ValueError("risk model contains unsupported top-level fields")
        if "lineage" in data:
            cls._validate_lineage(data["lineage"])
        raw_weights = data["weights"]
        if set(raw_weights) != set(FEATURES):
            raise ValueError("risk model feature set does not match this release")
        bias = cls._bounded_number(data.get("bias"), "bias", MAX_ABSOLUTE_BIAS)
        weights = {
            str(name): cls._bounded_number(value, f"weight {name}", MAX_ABSOLUTE_WEIGHT)
            for name, value in raw_weights.items()
        }
        return cls(weights=weights, bias=bias)
