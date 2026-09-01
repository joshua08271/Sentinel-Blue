"""Thread-safe SQLite persistence used by the controller."""

from __future__ import annotations

import hmac
import hashlib
import math
import os
import secrets
import sqlite3
import threading
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .json_codec import canonical_json_dumps, strict_json_loads
from .protocol import (
    MAX_AGENT_EGRESS_BYTES,
    MAX_PENDING_ACTIONS_PER_RESPONSE,
    ActionRequest,
    AlertCandidate,
)
from .risk import FEATURES
from .process_identity import validate_process_identity


MAX_LEARNING_FEEDBACK = 10_000
MAX_OPEN_ALERTS_PER_AGENT = 128
OPEN_ALERT_LIMITS_BY_SEVERITY = {
    "critical": 64,
    "high": 40,
    "medium": 16,
    "low": 8,
}
MAX_OUTSTANDING_ACTIONS_PER_AGENT = 64
MAX_AUTOMATED_OUTSTANDING_ACTIONS_PER_AGENT = 32
MAX_STORED_JSON_BYTES = 1_000_000
MAX_ACTION_RESULT_REPORT_GRACE_SECONDS = 7 * 24 * 60 * 60
STORAGE_QUARANTINE_SCHEMA = 2
MAX_OPEN_STORAGE_QUARANTINES = 512
MAX_RESOLVED_STORAGE_QUARANTINES = 2_048
FORENSIC_ONLY_QUARANTINE_TABLES = frozenset({"audit_log"})
INVALID_JSON_PLACEHOLDER = {
    "unavailable": True,
    "reason": "stored JSON failed strict validation",
}
ACTION_CREDENTIAL_ROTATED_RESULT = canonical_json_dumps(
    {
        "success": False,
        "message": "action invalidated by agent credential rotation",
    }
)
ACTION_AUTHORIZATION_EXPIRED_RESULT = canonical_json_dumps(
    {
        "success": False,
        "message": "action authorization expired before delivery",
    }
)
ACTION_DELIVERY_EXHAUSTED_RESULT = canonical_json_dumps(
    {"success": False, "message": "action delivery attempts exhausted"}
)
ACTION_OUTCOME_UNKNOWN_RESULT = canonical_json_dumps(
    {
        "success": False,
        "outcome_unknown": True,
        "message": (
            "the delivered action was not acknowledged before its delivery "
            "window closed; operator reconciliation is required"
        ),
    }
)
ACTION_DELIVERY_OVERSIZED_RESULT = canonical_json_dumps(
    {
        "success": False,
        "message": "action exceeds the controller delivery size limit",
    }
)
ACTION_BINDING_INVALIDATED_RESULT = canonical_json_dumps(
    {
        "success": False,
        "message": "action invalidated by agent release or credential binding change",
    }
)
ACTION_GOVERNANCE_CHANGED_RESULT = canonical_json_dumps(
    {
        "success": False,
        "message": "action invalidated by a governance transition",
    }
)
ACTION_STORAGE_QUARANTINED_RESULT = canonical_json_dumps(
    {
        "success": False,
        "message": "action authority invalidated by quarantined controller storage",
    }
)
MAX_BOOT_EPOCHS_PER_AGENT = 64
HTTP_REQUEST_REPLAY_STATE_KEY = "http_request_replay_state"
HTTP_REQUEST_REPLAY_SCHEMA = 1
HTTP_REQUEST_AUTH_KINDS = frozenset({"agent", "enrollment"})
HTTP_REQUEST_AGENT_ID_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:@-"
)
OPERATOR_AUTH_STATE_KEY = "operator_auth_state"
OPERATOR_AUTH_STATE_SCHEMA = 1
GOVERNANCE_MODES = frozenset(
    {
        "observe",
        "interactive",
        "approval-based",
        "guarded-autonomous",
        "range-autonomous",
    }
)
GOVERNANCE_FIELDS = frozenset(
    {
        "schema",
        "profile_fingerprint",
        "autonomy_mode",
        "emergency_stopped",
        "revision",
    }
)


class ActionQuotaExceeded(OverflowError):
    """The bounded per-agent outstanding-action queue is full."""


class _ImmediateTransaction:
    """Acquire SQLite's write lock before security clocks are sampled."""

    def __init__(self, connection: sqlite3.Connection):
        self.connection = connection

    def __enter__(self) -> None:
        self.connection.execute("BEGIN IMMEDIATE")

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if exc_type is not None and self.connection.in_transaction:
            self.connection.rollback()
        return False


def _learning_features(value: object) -> dict[str, float]:
    if not isinstance(value, dict) or len(value) > len(FEATURES):
        raise ValueError("learning features must be a bounded object")
    normalized: dict[str, float] = {}
    for name, feature in value.items():
        if name not in FEATURES:
            raise ValueError("learning feedback contains an unknown model feature")
        if isinstance(feature, bool) or not isinstance(feature, (int, float)):
            raise ValueError("learning feature values must be numeric without type coercion")
        numeric = float(feature)
        if not math.isfinite(numeric) or not 0.0 <= numeric <= 1.0:
            raise ValueError("learning feature values must be finite and between zero and one")
        normalized[str(name)] = numeric
    return normalized


def hmac_compare_json(left: str, right: str) -> bool:
    """Constant-time equality avoids leaking partial authenticated payload state."""
    return hmac.compare_digest(left.encode(), right.encode())


def _stored_value_evidence(raw: object) -> tuple[str, bytes]:
    """Return a typed, deterministic representation without retaining raw data."""
    if isinstance(raw, sqlite3.Row):
        raw = dict(raw)
    if isinstance(raw, str):
        return "text", raw.encode("utf-8", "surrogatepass")
    if isinstance(raw, (bytes, bytearray, memoryview)):
        return "blob", bytes(raw)
    if raw is None:
        return "null", b""
    if type(raw) is int:
        return "integer", str(raw).encode("ascii")
    if type(raw) is float:
        return "real", repr(raw).encode("ascii")
    if isinstance(raw, dict):
        fields: list[dict[str, object]] = []
        for name in sorted(raw, key=lambda item: str(item)):
            storage_class, encoded = _stored_value_evidence(raw[name])
            fields.append(
                {
                    "name": str(name),
                    "storage_class": storage_class,
                    "sha256": hashlib.sha256(encoded).hexdigest(),
                    "size": len(encoded),
                }
            )
        return "row", canonical_json_dumps(fields).encode("utf-8")
    # This is evidence about an already-invalid SQLite/Python type.  Its type
    # tag prevents a textual value with the same representation from colliding.
    return type(raw).__name__[:32], repr(raw).encode("utf-8", "backslashreplace")


def _quarantine_locator_sha256(
    table_name: str, row_key: str, column_name: str
) -> str:
    return hashlib.sha256(
        canonical_json_dumps(
            {
                "table_name": str(table_name),
                "row_key": str(row_key),
                "column_name": str(column_name),
            }
        ).encode("utf-8")
    ).hexdigest()


def _require_success_result_contract(
    action_type: str,
    parameters: dict[str, Any],
    result: dict[str, Any],
) -> None:
    """Reject generic success claims that cannot prove the queued operation."""
    if result.get("success") is not True or result.get("dry_run") is True:
        return

    expected_probes = parameters.get("probes", [])
    if expected_probes:
        observed_probes = result.get("probes")
        if not isinstance(observed_probes, list) or len(observed_probes) != len(
            expected_probes
        ):
            raise ValueError("successful action omitted exact probe attestations")
        expected_contract = [
            (str(item.get("name", "")), str(item.get("target", "")))
            for item in expected_probes
            if isinstance(item, dict)
        ]
        observed_contract = [
            (str(item.get("name", "")), str(item.get("target", "")))
            for item in observed_probes
            if isinstance(item, dict) and item.get("healthy") is True
        ]
        if observed_contract != expected_contract:
            raise ValueError("successful action probe attestations do not match")

    if action_type == "restore_integrity":
        transaction_id = result.get("transaction_id")
        pre_state = result.get("pre_state")
        validation = result.get("config_validation")
        if (
            not isinstance(transaction_id, str)
            or not transaction_id
            or not isinstance(pre_state, dict)
            or pre_state.get("transaction_id") != transaction_id
            or type(result.get("evidence_preserved")) is not bool
            or not isinstance(validation, dict)
        ):
            raise ValueError("restoration success lacks transaction attestation")
        if validation.get("applicable") is True and (
            validation.get("available") is not True
            or validation.get("healthy") is not True
        ):
            raise ValueError("restoration success lacks healthy configuration validation")
    elif action_type == "quarantine_session":
        record = result.get("record")
        session = parameters.get("session", parameters)
        expected_process = session.get("process_id") if isinstance(session, dict) else None
        expected_observation = parameters.get("observation")
        try:
            record_identity = validate_process_identity(
                record.get("process_identity") if isinstance(record, dict) else None
            )
            expected_identity = validate_process_identity(
                session.get("process_identity") if isinstance(session, dict) else None
            )
        except ValueError as exc:
            raise ValueError(
                "quarantine success lacks a valid exact process identity"
            ) from exc
        if (
            not isinstance(record, dict)
            or type(record.get("process_id")) is not int
            or record.get("process_id") != expected_process
            or record_identity != expected_identity
            or record.get("status") != "active"
            or record.get("boot_id") != record_identity["boot_id"]
            or any(
                record.get(field) != session.get(field)
                for field in (
                    "username",
                    "source",
                    "session_id",
                    "privileged",
                    "interactive",
                )
            )
            or not isinstance(expected_observation, dict)
            or record.get("target_observation") != expected_observation
        ):
            raise ValueError("quarantine success lacks exact process attestation")
    elif action_type in {"restart_service", "rollback_service"}:
        pre_state = result.get("pre_state")
        if (
            not isinstance(pre_state, dict)
            or pre_state.get("service") != parameters.get("service")
            or pre_state.get("desired_state") not in {"running", "stopped"}
        ):
            raise ValueError("service action success lacks prior-state attestation")
    elif action_type == "validate_service":
        probes = result.get("probes")
        if not isinstance(probes, list) or not probes or any(
            not isinstance(item, dict) or item.get("healthy") is not True
            for item in probes
        ):
            raise ValueError("service validation success lacks healthy probe attestations")


def baseline_capture_files(baseline: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the exact, bounded restore-point contract for one baseline.

    Baseline promotion is an aggregate operation.  Omitting an integrity row
    would silently approve a candidate whose restore evidence covers only a
    subset, so this helper deliberately rejects malformed, duplicate, or
    over-sized inventories instead of filtering them.
    """

    integrity = baseline.get("integrity", [])
    if not isinstance(integrity, list) or len(integrity) > 256:
        raise ValueError("baseline promotion requires at most 256 integrity files")
    files: list[dict[str, Any]] = []
    paths: set[str] = set()
    for index, item in enumerate(integrity):
        if not isinstance(item, dict):
            raise ValueError(f"baseline integrity[{index}] must be an object")
        path = item.get("path")
        digest = item.get("sha256")
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 1024
            or "\x00" in path
            or path in paths
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise ValueError("baseline integrity path or digest is invalid")
        paths.add(path)
        row: dict[str, Any] = {"path": path, "sha256": digest}
        size = item.get("size")
        if size is not None:
            if type(size) is not int or not 0 <= size <= 2**63 - 1:
                raise ValueError("baseline integrity size is invalid")
            row["size"] = size
        security = item.get("security_descriptor_sha256", "")
        if security:
            if (
                not isinstance(security, str)
                or len(security) != 64
                or any(character not in "0123456789abcdef" for character in security)
            ):
                raise ValueError("baseline security descriptor digest is invalid")
            row["security_descriptor_sha256"] = security
        files.append(row)
    return files


def capture_receipt_error(
    files: list[dict[str, Any]], result: dict[str, Any]
) -> str | None:
    """Explain why a signed capture result cannot authorize promotion."""

    if result.get("success") is not True:
        return "capture_failed"
    # Promotion is an authority-bearing transition.  Absence of a dry-run
    # attestation is not proof that the executor performed a real capture.
    if result.get("dry_run") is not False:
        return "capture_non_dry_run_unattested"
    if result.get("rejected", []):
        return "capture_rejected_files"
    expected_paths = [str(item["path"]) for item in files]
    if len(expected_paths) != len(set(expected_paths)):
        return "candidate_paths_not_unique"
    if result.get("captured") != expected_paths:
        return "captured_paths_mismatch"
    receipts = result.get("capture_receipts")
    if not isinstance(receipts, list) or len(receipts) != len(files):
        return "capture_receipts_incomplete"
    receipt_paths: list[str] = []
    restore_point_ids: set[str] = set()
    for expected, receipt in zip(files, receipts, strict=True):
        if not isinstance(receipt, dict):
            return "capture_receipt_invalid"
        path = receipt.get("path")
        source = receipt.get("source_sha256")
        backup = receipt.get("backup_sha256")
        restore_point_id = receipt.get("restore_point_id")
        security_metadata = receipt.get("security_metadata_sha256")
        if path != expected["path"] or not isinstance(path, str):
            return "capture_receipt_path_mismatch"
        receipt_paths.append(path)
        if source != expected["sha256"] or backup != expected["sha256"]:
            return "capture_receipt_digest_mismatch"
        if (
            receipt.get("backup_matches_source") is not True
            or receipt.get("stored") is not True
        ):
            return "capture_receipt_storage_unverified"
        if (
            not isinstance(security_metadata, str)
            or len(security_metadata) != 64
            or any(
                character not in "0123456789abcdef"
                for character in security_metadata
            )
        ):
            return "capture_receipt_security_metadata_missing"
        if "size" in expected and receipt.get("byte_size") != expected["size"]:
            return "capture_receipt_size_mismatch"
        expected_descriptor = expected.get("security_descriptor_sha256")
        if expected_descriptor and receipt.get(
            "security_descriptor_sha256"
        ) != expected_descriptor:
            return "capture_receipt_security_descriptor_mismatch"
        try:
            parsed_restore_point_id = str(uuid.UUID(str(restore_point_id)))
        except (ValueError, TypeError, AttributeError):
            return "capture_receipt_identity_invalid"
        if parsed_restore_point_id != restore_point_id:
            return "capture_receipt_identity_invalid"
        if restore_point_id in restore_point_ids:
            return "capture_receipt_identity_reused"
        restore_point_ids.add(restore_point_id)
    if receipt_paths != expected_paths or len(receipt_paths) != len(set(receipt_paths)):
        return "capture_receipt_paths_incomplete"
    return None


SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS agents (
    agent_id TEXT PRIMARY KEY,
    hostname TEXT NOT NULL,
    platform TEXT NOT NULL,
    registered_at REAL NOT NULL,
    last_seen REAL NOT NULL,
    latest_telemetry TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_sequence INTEGER NOT NULL DEFAULT -1,
    boot_id TEXT NOT NULL DEFAULT '',
    agent_secret TEXT NOT NULL DEFAULT '',
    credential_epoch INTEGER NOT NULL DEFAULT 0,
    profile_id TEXT NOT NULL DEFAULT '',
    profile_fingerprint TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    last_observed_at REAL NOT NULL DEFAULT 0,
    latest_payload_sha256 TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS baselines (
    agent_id TEXT PRIMARY KEY,
    baseline_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    approved_at REAL,
    credential_epoch INTEGER NOT NULL DEFAULT -1,
    profile_id TEXT NOT NULL DEFAULT '',
    profile_fingerprint TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS baseline_promotions (
    promotion_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    source TEXT NOT NULL,
    alert_id TEXT,
    candidate_json TEXT NOT NULL,
    candidate_sha256 TEXT NOT NULL,
    prior_baseline_sha256 TEXT NOT NULL DEFAULT '',
    telemetry_sha256 TEXT NOT NULL,
    telemetry_observed_at REAL NOT NULL,
    telemetry_boot_id TEXT NOT NULL DEFAULT '',
    telemetry_sequence INTEGER NOT NULL DEFAULT -1,
    credential_epoch INTEGER NOT NULL DEFAULT -1,
    profile_id TEXT NOT NULL DEFAULT '',
    profile_fingerprint TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    action_id TEXT,
    status TEXT NOT NULL,
    failure_reason TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    completed_at REAL,
    FOREIGN KEY(action_id) REFERENCES actions(action_id)
);
CREATE TABLE IF NOT EXISTS protected_accounts (
    agent_id TEXT NOT NULL,
    account_name TEXT NOT NULL,
    role TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at REAL NOT NULL,
    PRIMARY KEY(agent_id, account_name)
);
CREATE TABLE IF NOT EXISTS alerts (
    alert_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL,
    evidence_json TEXT NOT NULL,
    recommendation TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    fingerprint TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    decision TEXT,
    created_at REAL NOT NULL,
    decided_at REAL,
    occurrence_count INTEGER NOT NULL DEFAULT 1,
    last_observed_at REAL,
    credential_epoch INTEGER NOT NULL DEFAULT -1,
    profile_id TEXT NOT NULL DEFAULT '',
    profile_fingerprint TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    release_sha256 TEXT NOT NULL DEFAULT '',
    model_fingerprint TEXT NOT NULL DEFAULT '',
    campaign_id TEXT NOT NULL DEFAULT '',
    last_observation_id TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS actions (
    action_id TEXT PRIMARY KEY,
    alert_id TEXT,
    agent_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    parameters_json TEXT NOT NULL,
    status TEXT NOT NULL,
    result_json TEXT,
    created_at REAL NOT NULL,
    completed_at REAL,
    dispatched_at REAL,
    attempts INTEGER NOT NULL DEFAULT 0,
    automated INTEGER NOT NULL DEFAULT 0,
    risk TEXT NOT NULL DEFAULT 'high',
    expires_at REAL NOT NULL DEFAULT 0,
    profile_id TEXT NOT NULL DEFAULT '',
    profile_fingerprint TEXT NOT NULL DEFAULT '',
    autonomy_mode TEXT NOT NULL DEFAULT '',
    credential_epoch INTEGER NOT NULL DEFAULT -1,
    agent_version TEXT NOT NULL DEFAULT '',
    envelope_sha256 TEXT NOT NULL DEFAULT '',
    result_source TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS learning_feedback (
    feedback_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    label INTEGER NOT NULL,
    features_json TEXT NOT NULL,
    decision TEXT NOT NULL,
    created_at REAL NOT NULL,
    agent_id TEXT NOT NULL DEFAULT '',
    credential_epoch INTEGER NOT NULL DEFAULT -1,
    profile_id TEXT NOT NULL DEFAULT '',
    profile_fingerprint TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    campaign_id TEXT NOT NULL DEFAULT '',
    release_sha256 TEXT NOT NULL DEFAULT '',
    model_fingerprint TEXT NOT NULL DEFAULT '',
    reviewer TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    provenance_status TEXT NOT NULL DEFAULT 'quarantined',
    provenance_reason TEXT NOT NULL DEFAULT 'legacy-unbound'
);
CREATE TABLE IF NOT EXISTS external_events (
    event_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    message TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS change_grants (
    grant_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    used_at REAL,
    observed_sha256 TEXT,
    credential_epoch INTEGER NOT NULL DEFAULT -1,
    profile_id TEXT NOT NULL DEFAULT '',
    profile_fingerprint TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    revoked_at REAL,
    revocation_reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS privileged_authorizations (
    authorization_id TEXT PRIMARY KEY,
    code_hash TEXT NOT NULL UNIQUE,
    agent_id TEXT NOT NULL,
    action_type TEXT NOT NULL,
    subject TEXT NOT NULL,
    created_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    used_at REAL,
    credential_epoch INTEGER NOT NULL DEFAULT -1,
    profile_id TEXT NOT NULL DEFAULT '',
    profile_fingerprint TEXT NOT NULL DEFAULT '',
    agent_version TEXT NOT NULL DEFAULT '',
    revoked_at REAL,
    revocation_reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id TEXT PRIMARY KEY,
    actor TEXT NOT NULL,
    operation TEXT NOT NULL,
    subject TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS controller_state (
    state_key TEXT PRIMARY KEY,
    state_value TEXT NOT NULL,
    updated_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS telemetry_boots (
    agent_id TEXT NOT NULL,
    credential_epoch INTEGER NOT NULL,
    profile_fingerprint TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    max_sequence INTEGER NOT NULL,
    max_observed_at REAL NOT NULL,
    last_payload_sha256 TEXT NOT NULL,
    state TEXT NOT NULL,
    first_seen_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    PRIMARY KEY(agent_id, credential_epoch, profile_fingerprint, boot_id)
);
CREATE TABLE IF NOT EXISTS telemetry_processing (
    agent_id TEXT NOT NULL,
    credential_epoch INTEGER NOT NULL,
    profile_fingerprint TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    payload_sha256 TEXT NOT NULL,
    telemetry_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at REAL NOT NULL DEFAULT 0,
    PRIMARY KEY(agent_id, credential_epoch, profile_fingerprint,
                boot_id, sequence, payload_sha256)
);
CREATE TABLE IF NOT EXISTS telemetry_observations (
    observation_id TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    telemetry_sha256 TEXT NOT NULL,
    telemetry_json TEXT NOT NULL,
    observed_at REAL NOT NULL,
    queued_at REAL NOT NULL,
    accepted_at REAL NOT NULL,
    boot_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    credential_epoch INTEGER NOT NULL,
    profile_id TEXT NOT NULL,
    profile_fingerprint TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    release_sha256 TEXT NOT NULL,
    model_fingerprint TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    feature_schema_sha256 TEXT NOT NULL,
    admission_status TEXT NOT NULL DEFAULT 'eligible'
      CHECK(admission_status IN ('eligible','quarantined')),
    CHECK(length(observation_id)=64),
    CHECK(length(telemetry_sha256)=64),
    CHECK(telemetry_sha256=observation_id),
    UNIQUE(agent_id, credential_epoch, profile_fingerprint, boot_id, sequence),
    UNIQUE(agent_id, telemetry_sha256)
);
CREATE TABLE IF NOT EXISTS alert_occurrences (
    occurrence_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    observation_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    incident_group_id TEXT NOT NULL,
    occurrence_index INTEGER NOT NULL,
    candidate_json TEXT NOT NULL,
    candidate_sha256 TEXT NOT NULL,
    features_json TEXT NOT NULL,
    features_sha256 TEXT NOT NULL,
    feature_schema_sha256 TEXT NOT NULL,
    kind TEXT NOT NULL,
    observed_at REAL NOT NULL,
    credential_epoch INTEGER NOT NULL,
    profile_id TEXT NOT NULL,
    profile_fingerprint TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    release_sha256 TEXT NOT NULL,
    model_fingerprint TEXT NOT NULL,
    admission_status TEXT NOT NULL DEFAULT 'eligible'
      CHECK(admission_status IN ('eligible','quarantined')),
    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE RESTRICT,
    FOREIGN KEY(observation_id) REFERENCES telemetry_observations(observation_id)
      ON DELETE RESTRICT,
    UNIQUE(alert_id, observation_id),
    UNIQUE(alert_id, occurrence_index),
    CHECK(length(candidate_sha256)=64),
    CHECK(length(features_sha256)=64),
    CHECK(length(feature_schema_sha256)=64)
);
CREATE TABLE IF NOT EXISTS alert_lineage (
    alert_id TEXT PRIMARY KEY,
    creation_occurrence_id TEXT NOT NULL UNIQUE,
    last_occurrence_id TEXT NOT NULL,
    updated_at REAL NOT NULL,
    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE RESTRICT,
    FOREIGN KEY(creation_occurrence_id) REFERENCES alert_occurrences(occurrence_id)
      ON DELETE RESTRICT,
    FOREIGN KEY(last_occurrence_id) REFERENCES alert_occurrences(occurrence_id)
      ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS learning_labels (
    label_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    decision TEXT NOT NULL,
    label INTEGER NOT NULL CHECK(label IN (0,1)),
    reviewer_principal_id TEXT NOT NULL,
    label_source TEXT NOT NULL,
    created_at REAL NOT NULL,
    provenance_status TEXT NOT NULL DEFAULT 'eligible'
      CHECK(provenance_status IN ('eligible','quarantined')),
    FOREIGN KEY(alert_id) REFERENCES alerts(alert_id) ON DELETE RESTRICT,
    FOREIGN KEY(occurrence_id) REFERENCES alert_occurrences(occurrence_id)
      ON DELETE RESTRICT
);
CREATE TABLE IF NOT EXISTS enrollment_tickets (
    ticket_hash TEXT PRIMARY KEY,
    agent_id TEXT NOT NULL,
    profile_fingerprint TEXT NOT NULL,
    agent_version TEXT NOT NULL,
    expires_at REAL NOT NULL,
    consumed_at REAL,
    request_sha256 TEXT NOT NULL DEFAULT '',
    credential_epoch INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS agent_reenrollment (
    agent_id TEXT PRIMARY KEY,
    authorized_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    credential_epoch INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS json_quarantine (
    quarantine_id TEXT PRIMARY KEY,
    table_name TEXT NOT NULL,
    row_key TEXT NOT NULL,
    column_name TEXT NOT NULL,
    raw_sha256 TEXT NOT NULL,
    reason TEXT NOT NULL,
    detected_at REAL NOT NULL,
    locator_sha256 TEXT NOT NULL DEFAULT '',
    raw_storage_class TEXT NOT NULL DEFAULT 'text',
    raw_size INTEGER NOT NULL DEFAULT 0,
    reason_code TEXT NOT NULL DEFAULT 'stored_data_invalid',
    scope_kind TEXT NOT NULL DEFAULT 'global',
    scope_key TEXT NOT NULL DEFAULT '',
    state TEXT NOT NULL DEFAULT 'open',
    detection_count INTEGER NOT NULL DEFAULT 1,
    first_detected_at REAL NOT NULL DEFAULT 0,
    last_detected_at REAL NOT NULL DEFAULT 0,
    revision INTEGER NOT NULL DEFAULT 0,
    resolution_decision TEXT,
    resolution_note TEXT,
    resolved_by TEXT,
    resolved_at REAL,
    UNIQUE(table_name, row_key, column_name, raw_sha256)
);
CREATE TABLE IF NOT EXISTS json_quarantine_control (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    schema_version INTEGER NOT NULL,
    overflowed INTEGER NOT NULL DEFAULT 0 CHECK(overflowed IN (0,1)),
    overflow_count INTEGER NOT NULL DEFAULT 0,
    last_overflow_at REAL
);
CREATE TABLE IF NOT EXISTS http_request_replay (
    agent_id TEXT NOT NULL,
    marker_sha256 TEXT NOT NULL,
    auth_kind TEXT NOT NULL,
    credential_epoch INTEGER NOT NULL,
    request_timestamp REAL NOT NULL,
    accepted_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY(agent_id, marker_sha256),
    CHECK(auth_kind IN ('agent', 'enrollment')),
    CHECK(credential_epoch >= -1),
    CHECK(length(marker_sha256) = 64)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS operator_request_replay (
    principal_id TEXT NOT NULL,
    credential_epoch INTEGER NOT NULL,
    request_id TEXT NOT NULL,
    marker_sha256 TEXT NOT NULL,
    request_timestamp INTEGER NOT NULL,
    accepted_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY(principal_id, credential_epoch, request_id),
    UNIQUE(principal_id, credential_epoch, marker_sha256),
    CHECK(credential_epoch >= 1),
    CHECK(length(request_id) = 32),
    CHECK(length(marker_sha256) = 64)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, created_at);
CREATE INDEX IF NOT EXISTS idx_actions_agent ON actions(agent_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_baseline_promotions_agent
  ON baseline_promotions(agent_id, created_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_promotions_active
  ON baseline_promotions(agent_id) WHERE status='pending';
CREATE UNIQUE INDEX IF NOT EXISTS idx_baseline_promotions_action
  ON baseline_promotions(action_id) WHERE action_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_change_grants_lookup ON change_grants(agent_id, path, expires_at, used_at);
CREATE INDEX IF NOT EXISTS idx_authorizations_lookup ON privileged_authorizations(agent_id, action_type, expires_at, used_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_boots_agent ON telemetry_boots(agent_id, credential_epoch, profile_fingerprint, state);
CREATE INDEX IF NOT EXISTS idx_telemetry_processing_agent ON telemetry_processing(agent_id, created_at);
CREATE INDEX IF NOT EXISTS idx_telemetry_observations_agent
  ON telemetry_observations(agent_id, accepted_at);
CREATE INDEX IF NOT EXISTS idx_alert_occurrences_alert
  ON alert_occurrences(alert_id, occurrence_index);
CREATE INDEX IF NOT EXISTS idx_alert_occurrences_provenance
  ON alert_occurrences(campaign_id, profile_id, profile_fingerprint,
                       release_sha256, agent_version, model_fingerprint);
CREATE INDEX IF NOT EXISTS idx_learning_labels_created
  ON learning_labels(created_at, label_id);
CREATE INDEX IF NOT EXISTS idx_http_request_replay_expiry ON http_request_replay(expires_at);
CREATE INDEX IF NOT EXISTS idx_operator_request_replay_expiry
  ON operator_request_replay(expires_at);
CREATE TRIGGER IF NOT EXISTS trg_telemetry_observations_immutable
BEFORE UPDATE ON telemetry_observations BEGIN
  SELECT RAISE(ABORT, 'telemetry observations are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_alert_occurrences_immutable
BEFORE UPDATE ON alert_occurrences BEGIN
  SELECT RAISE(ABORT, 'alert occurrences are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_learning_labels_immutable
BEFORE UPDATE ON learning_labels BEGIN
  SELECT RAISE(ABORT, 'learning labels are immutable');
END;
CREATE TRIGGER IF NOT EXISTS trg_alert_lineage_creation_immutable
BEFORE UPDATE OF creation_occurrence_id ON alert_lineage
WHEN NEW.creation_occurrence_id!=OLD.creation_occurrence_id BEGIN
  SELECT RAISE(ABORT, 'alert creation occurrence is immutable');
END;
"""


class Store:
    def __init__(self, path: str | Path):
        self.path = str(path)
        database_path = Path(self.path)
        self.database_preexisting = bool(
            self.path != ":memory:" and database_path.exists()
        )
        if self.path != ":memory:":
            database_path.parent.mkdir(parents=True, exist_ok=True)
            if database_path.parent.is_symlink() or not database_path.parent.is_dir():
                raise ValueError("database directory is unavailable or is a symbolic link")
            if database_path.is_symlink():
                raise ValueError("database path must not be a symbolic link")
        self._lock = threading.RLock()
        self._quarantine_boundaries: list[list[dict[str, Any]]] = []
        self._connection = sqlite3.connect(self.path, check_same_thread=False, timeout=5.0)
        self._connection.row_factory = sqlite3.Row
        with self._lock:
            self._connection.execute("PRAGMA busy_timeout=5000")
            self._connection.execute("PRAGMA synchronous=FULL")
            self._connection.execute("PRAGMA foreign_keys=ON")
            self._connection.execute("PRAGMA trusted_schema=OFF")
            self._connection.execute("PRAGMA temp_store=MEMORY")
            existing_lineage_tables = {
                str(row["name"])
                for row in self._connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name IN "
                    "('telemetry_observations','alert_occurrences',"
                    "'alert_lineage','learning_labels')"
                ).fetchall()
            }
            self._connection.executescript(SCHEMA)
            baseline_columns = {
                row[1] for row in self._connection.execute("PRAGMA table_info(baselines)").fetchall()
            }
            if "status" not in baseline_columns:
                self._connection.execute(
                    "ALTER TABLE baselines ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'"
                )
            if "approved_at" not in baseline_columns:
                self._connection.execute("ALTER TABLE baselines ADD COLUMN approved_at REAL")
            for name, definition in {
                "credential_epoch": "INTEGER NOT NULL DEFAULT -1",
                "profile_id": "TEXT NOT NULL DEFAULT ''",
                "profile_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "agent_version": "TEXT NOT NULL DEFAULT ''",
            }.items():
                if name not in baseline_columns:
                    self._connection.execute(
                        f"ALTER TABLE baselines ADD COLUMN {name} {definition}"
                    )
            alert_columns = {
                row[1] for row in self._connection.execute("PRAGMA table_info(alerts)").fetchall()
            }
            if "fingerprint" not in alert_columns:
                self._connection.execute(
                    "ALTER TABLE alerts ADD COLUMN fingerprint TEXT NOT NULL DEFAULT ''"
                )
            for name, definition in {
                "occurrence_count": "INTEGER NOT NULL DEFAULT 1",
                "last_observed_at": "REAL",
                "credential_epoch": "INTEGER NOT NULL DEFAULT -1",
                "profile_id": "TEXT NOT NULL DEFAULT ''",
                "profile_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "agent_version": "TEXT NOT NULL DEFAULT ''",
                "release_sha256": "TEXT NOT NULL DEFAULT ''",
                "model_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "campaign_id": "TEXT NOT NULL DEFAULT ''",
                "last_observation_id": "TEXT NOT NULL DEFAULT ''",
            }.items():
                if name not in alert_columns:
                    self._connection.execute(f"ALTER TABLE alerts ADD COLUMN {name} {definition}")
            agent_columns = {
                row[1] for row in self._connection.execute("PRAGMA table_info(agents)").fetchall()
            }
            for name, definition in {
                "enabled": "INTEGER NOT NULL DEFAULT 1",
                "last_sequence": "INTEGER NOT NULL DEFAULT -1",
                "boot_id": "TEXT NOT NULL DEFAULT ''",
                "agent_secret": "TEXT NOT NULL DEFAULT ''",
                "credential_epoch": "INTEGER NOT NULL DEFAULT 0",
                "profile_id": "TEXT NOT NULL DEFAULT ''",
                "profile_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "agent_version": "TEXT NOT NULL DEFAULT ''",
                "last_observed_at": "REAL NOT NULL DEFAULT 0",
                "latest_payload_sha256": "TEXT NOT NULL DEFAULT ''",
            }.items():
                if name not in agent_columns:
                    self._connection.execute(f"ALTER TABLE agents ADD COLUMN {name} {definition}")
            action_columns = {
                row[1] for row in self._connection.execute("PRAGMA table_info(actions)").fetchall()
            }
            for name, definition in {
                "dispatched_at": "REAL",
                "attempts": "INTEGER NOT NULL DEFAULT 0",
                "automated": "INTEGER NOT NULL DEFAULT 0",
                "risk": "TEXT NOT NULL DEFAULT 'high'",
                "expires_at": "REAL NOT NULL DEFAULT 0",
                "profile_id": "TEXT NOT NULL DEFAULT ''",
                "profile_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "autonomy_mode": "TEXT NOT NULL DEFAULT ''",
                "credential_epoch": "INTEGER NOT NULL DEFAULT -1",
                "agent_version": "TEXT NOT NULL DEFAULT ''",
                "envelope_sha256": "TEXT NOT NULL DEFAULT ''",
                "result_source": "TEXT NOT NULL DEFAULT ''",
            }.items():
                if name not in action_columns:
                    self._connection.execute(f"ALTER TABLE actions ADD COLUMN {name} {definition}")
            change_grant_columns = {
                row[1]
                for row in self._connection.execute(
                    "PRAGMA table_info(change_grants)"
                ).fetchall()
            }
            for name, definition in {
                "observed_sha256": "TEXT",
                "credential_epoch": "INTEGER NOT NULL DEFAULT -1",
                "profile_id": "TEXT NOT NULL DEFAULT ''",
                "profile_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "agent_version": "TEXT NOT NULL DEFAULT ''",
                "revoked_at": "REAL",
                "revocation_reason": "TEXT NOT NULL DEFAULT ''",
            }.items():
                if name not in change_grant_columns:
                    self._connection.execute(
                        f"ALTER TABLE change_grants ADD COLUMN {name} {definition}"
                    )
            authorization_columns = {
                row[1]
                for row in self._connection.execute(
                    "PRAGMA table_info(privileged_authorizations)"
                ).fetchall()
            }
            for name, definition in {
                "credential_epoch": "INTEGER NOT NULL DEFAULT -1",
                "profile_id": "TEXT NOT NULL DEFAULT ''",
                "profile_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "agent_version": "TEXT NOT NULL DEFAULT ''",
                "revoked_at": "REAL",
                "revocation_reason": "TEXT NOT NULL DEFAULT ''",
            }.items():
                if name not in authorization_columns:
                    self._connection.execute(
                        "ALTER TABLE privileged_authorizations "
                        f"ADD COLUMN {name} {definition}"
                    )
            feedback_columns = {
                row[1]
                for row in self._connection.execute(
                    "PRAGMA table_info(learning_feedback)"
                ).fetchall()
            }
            for name, definition in {
                "agent_id": "TEXT NOT NULL DEFAULT ''",
                "credential_epoch": "INTEGER NOT NULL DEFAULT -1",
                "profile_id": "TEXT NOT NULL DEFAULT ''",
                "profile_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "agent_version": "TEXT NOT NULL DEFAULT ''",
                "campaign_id": "TEXT NOT NULL DEFAULT ''",
                "release_sha256": "TEXT NOT NULL DEFAULT ''",
                "model_fingerprint": "TEXT NOT NULL DEFAULT ''",
                "reviewer": "TEXT NOT NULL DEFAULT ''",
                "source": "TEXT NOT NULL DEFAULT ''",
                "provenance_status": "TEXT NOT NULL DEFAULT 'quarantined'",
                "provenance_reason": "TEXT NOT NULL DEFAULT 'legacy-unbound'",
            }.items():
                if name not in feedback_columns:
                    self._connection.execute(
                        f"ALTER TABLE learning_feedback ADD COLUMN {name} {definition}"
                    )
            # Index creation in the base schema can precede ALTER migrations on
            # older databases. Recreate provenance indexes only after columns exist.
            self._connection.execute(
                "CREATE INDEX IF NOT EXISTS idx_feedback_provenance "
                "ON learning_feedback(provenance_status, campaign_id, "
                "profile_fingerprint, release_sha256, created_at)"
            )
            # The old feedback table is retained as bounded forensic evidence
            # only. It lacks immutable observation/occurrence joins and can
            # never silently become training authority after an upgrade.
            self._connection.execute(
                "UPDATE learning_feedback SET provenance_status='quarantined', "
                "provenance_reason='legacy-forensic-only'"
            )
            if existing_lineage_tables != {
                "telemetry_observations",
                "alert_occurrences",
                "alert_lineage",
                "learning_labels",
            }:
                # Pre-lineage alerts have no provable candidate occurrence. They
                # remain forensic evidence but cannot be relabeled as if the
                # missing immutable join had existed at creation time.
                now = time.time()
                self._connection.execute(
                    "UPDATE alerts SET status='invalidated', "
                    "decision='learning_lineage_unavailable', decided_at=? "
                    "WHERE status='open'",
                    (now,),
                )
            enrollment_ticket_columns = {
                row[1]
                for row in self._connection.execute(
                    "PRAGMA table_info(enrollment_tickets)"
                ).fetchall()
            }
            if "credential_epoch" not in enrollment_ticket_columns:
                self._connection.execute(
                    "ALTER TABLE enrollment_tickets ADD COLUMN "
                    "credential_epoch INTEGER NOT NULL DEFAULT -1"
                )
            reenrollment_columns = {
                row[1]
                for row in self._connection.execute(
                    "PRAGMA table_info(agent_reenrollment)"
                ).fetchall()
            }
            if "credential_epoch" not in reenrollment_columns:
                self._connection.execute(
                    "ALTER TABLE agent_reenrollment ADD COLUMN "
                    "credential_epoch INTEGER NOT NULL DEFAULT -1"
                )
            processing_columns = {
                row[1]
                for row in self._connection.execute(
                    "PRAGMA table_info(telemetry_processing)"
                ).fetchall()
            }
            if "attempts" not in processing_columns:
                self._connection.execute(
                    "ALTER TABLE telemetry_processing ADD COLUMN "
                    "attempts INTEGER NOT NULL DEFAULT 0"
                )
            if "last_attempt_at" not in processing_columns:
                self._connection.execute(
                    "ALTER TABLE telemetry_processing ADD COLUMN "
                    "last_attempt_at REAL NOT NULL DEFAULT 0"
                )
            self._validate_learning_lineage_schema_locked()
            self._migrate_storage_quarantine_locked()
            foreign_key_errors = self._connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
            if foreign_key_errors:
                raise RuntimeError("database foreign-key integrity check failed")
            self._connection.commit()
        if os.name == "posix" and self.path != ":memory:" and Path(self.path).exists():
            Path(self.path).chmod(0o600)

    def _validate_learning_lineage_schema_locked(self) -> None:
        expected = {
            "telemetry_observations": {
                "observation_id", "agent_id", "telemetry_sha256",
                "telemetry_json", "observed_at", "queued_at", "accepted_at",
                "boot_id", "sequence", "credential_epoch", "profile_id",
                "profile_fingerprint", "agent_version", "release_sha256",
                "model_fingerprint", "campaign_id", "feature_schema_sha256",
                "admission_status",
            },
            "alert_occurrences": {
                "occurrence_id", "alert_id", "observation_id", "agent_id",
                "incident_group_id", "occurrence_index", "candidate_json",
                "candidate_sha256", "features_json", "features_sha256",
                "feature_schema_sha256", "kind", "observed_at",
                "credential_epoch", "profile_id", "profile_fingerprint",
                "agent_version", "campaign_id", "release_sha256",
                "model_fingerprint", "admission_status",
            },
            "alert_lineage": {
                "alert_id", "creation_occurrence_id", "last_occurrence_id",
                "updated_at",
            },
            "learning_labels": {
                "label_id", "alert_id", "occurrence_id", "kind", "decision",
                "label", "reviewer_principal_id", "label_source", "created_at",
                "provenance_status",
            },
        }
        for table, columns in expected.items():
            observed = {
                str(row["name"])
                for row in self._connection.execute(
                    f"PRAGMA table_info({table})"
                ).fetchall()
            }
            if observed != columns:
                raise RuntimeError(
                    f"learning lineage table {table} does not match this release"
                )

    def _migrate_storage_quarantine_locked(self) -> None:
        columns = {
            row[1]
            for row in self._connection.execute(
                "PRAGMA table_info(json_quarantine)"
            ).fetchall()
        }
        additions = {
            "locator_sha256": "TEXT NOT NULL DEFAULT ''",
            "raw_storage_class": "TEXT NOT NULL DEFAULT 'legacy'",
            "raw_size": "INTEGER NOT NULL DEFAULT 0",
            "reason_code": "TEXT NOT NULL DEFAULT 'stored_data_invalid'",
            "scope_kind": "TEXT NOT NULL DEFAULT 'global'",
            "scope_key": "TEXT NOT NULL DEFAULT ''",
            "state": "TEXT NOT NULL DEFAULT 'open'",
            "detection_count": "INTEGER NOT NULL DEFAULT 1",
            "first_detected_at": "REAL NOT NULL DEFAULT 0",
            "last_detected_at": "REAL NOT NULL DEFAULT 0",
            "revision": "INTEGER NOT NULL DEFAULT 0",
            "resolution_decision": "TEXT",
            "resolution_note": "TEXT",
            "resolved_by": "TEXT",
            "resolved_at": "REAL",
        }
        for name, definition in additions.items():
            if name not in columns:
                self._connection.execute(
                    f"ALTER TABLE json_quarantine ADD COLUMN {name} {definition}"
                )
        rows = self._connection.execute(
            "SELECT quarantine_id, table_name, row_key, column_name, "
            "detected_at, locator_sha256, first_detected_at, last_detected_at "
            "FROM json_quarantine"
        ).fetchall()
        for row in rows:
            locator = str(row["locator_sha256"] or "")
            if len(locator) != 64:
                locator = _quarantine_locator_sha256(
                    str(row["table_name"]),
                    str(row["row_key"]),
                    str(row["column_name"]),
                )
            detected = float(row["detected_at"])
            first = float(row["first_detected_at"] or detected)
            last = float(row["last_detected_at"] or detected)
            scope_kind, scope_key = self._quarantine_scope(
                str(row["table_name"]), str(row["row_key"]), None
            )
            self._connection.execute(
                "UPDATE json_quarantine SET locator_sha256=?, "
                "first_detected_at=?, last_detected_at=?, scope_kind=?, "
                "scope_key=? WHERE quarantine_id=?",
                (locator, first, last, scope_kind, scope_key, row["quarantine_id"]),
            )

        # Old releases allowed one row per changing digest. Consolidate them
        # into one open case per exact locator without dropping forensic history.
        duplicates = self._connection.execute(
            "SELECT locator_sha256 FROM json_quarantine WHERE state='open' "
            "GROUP BY locator_sha256 HAVING COUNT(*)>1"
        ).fetchall()
        for duplicate in duplicates:
            group = self._connection.execute(
                "SELECT quarantine_id, detected_at, detection_count "
                "FROM json_quarantine WHERE state='open' AND locator_sha256=? "
                "ORDER BY detected_at DESC, quarantine_id DESC",
                (duplicate["locator_sha256"],),
            ).fetchall()
            keeper = group[0]
            first = min(float(item["detected_at"]) for item in group)
            count = sum(max(1, int(item["detection_count"])) for item in group)
            self._connection.execute(
                "UPDATE json_quarantine SET detection_count=?, "
                "first_detected_at=? WHERE quarantine_id=?",
                (count, first, keeper["quarantine_id"]),
            )
            for stale in group[1:]:
                self._connection.execute(
                    "UPDATE json_quarantine SET state='resolved', "
                    "resolution_decision='resolve', "
                    "resolution_note='deduplicated during schema migration', "
                    "resolved_by='migration', resolved_at=?, revision=revision+1 "
                    "WHERE quarantine_id=?",
                    (time.time(), stale["quarantine_id"]),
                )
        self._connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_json_quarantine_open_locator "
            "ON json_quarantine(locator_sha256) WHERE state='open'"
        )
        self._connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_json_quarantine_state "
            "ON json_quarantine(state, last_detected_at)"
        )
        control = self._connection.execute(
            "SELECT schema_version FROM json_quarantine_control WHERE singleton=1"
        ).fetchone()
        if control is not None and int(control["schema_version"]) > STORAGE_QUARANTINE_SCHEMA:
            raise RuntimeError("storage quarantine schema is newer than this runtime")
        self._connection.execute(
            "INSERT INTO json_quarantine_control(singleton, schema_version) "
            "VALUES(1, ?) ON CONFLICT(singleton) DO UPDATE SET "
            "schema_version=excluded.schema_version",
            (STORAGE_QUARANTINE_SCHEMA,),
        )
        open_count = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM json_quarantine WHERE state='open'"
            ).fetchone()[0]
        )
        if open_count > MAX_OPEN_STORAGE_QUARANTINES:
            self._connection.execute(
                "UPDATE json_quarantine_control SET overflowed=1, "
                "overflow_count=overflow_count+?, last_overflow_at=? "
                "WHERE singleton=1",
                (open_count - MAX_OPEN_STORAGE_QUARANTINES, time.time()),
            )
        resolved = self._connection.execute(
            "SELECT quarantine_id FROM json_quarantine WHERE state='resolved' "
            "ORDER BY resolved_at DESC, quarantine_id DESC"
        ).fetchall()
        for row in resolved[MAX_RESOLVED_STORAGE_QUARANTINES:]:
            self._connection.execute(
                "DELETE FROM json_quarantine WHERE quarantine_id=? AND state='resolved'",
                (row["quarantine_id"],),
            )

    @staticmethod
    def _quarantine_scope(
        table_name: str, row_key: str, raw: object
    ) -> tuple[str, str]:
        if table_name in FORENSIC_ONLY_QUARANTINE_TABLES:
            return "forensic", ""
        if table_name in {
            "learning_feedback",
            "learning_labels",
            "alert_occurrences",
            "telemetry_observations",
        }:
            return "learning", str(row_key)[:256]
        if isinstance(raw, sqlite3.Row):
            raw = dict(raw)
        if isinstance(raw, dict) and isinstance(raw.get("agent_id"), str):
            return "agent", str(raw["agent_id"])[:256]
        if table_name in {"agents", "baselines"}:
            return "agent", str(row_key)[:256]
        if table_name == "alerts":
            return "alert", str(row_key)[:256]
        if table_name == "actions":
            return "action", str(row_key)[:256]
        return "global", ""

    def close(self) -> None:
        with self._lock:
            try:
                self._connection.execute("PRAGMA wal_checkpoint(PASSIVE)")
            except sqlite3.Error:
                pass
            self._connection.close()

    def _quarantine_json(
        self,
        table_name: str,
        row_key: str,
        column_name: str,
        raw: object,
        reason: str,
    ) -> None:
        """Record bounded corruption metadata and revoke dependent authority."""
        normalized_table = str(table_name)[:64]
        normalized_key = str(row_key)[:1024]
        normalized_column = str(column_name)[:64]
        storage_class, encoded = _stored_value_evidence(raw)
        incident = {
            "table_name": normalized_table,
            "row_key": normalized_key,
            "column_name": normalized_column,
            "locator_sha256": _quarantine_locator_sha256(
                normalized_table, str(row_key), normalized_column
            ),
            "raw_sha256": hashlib.sha256(encoded).hexdigest(),
            "raw_storage_class": storage_class[:32],
            "raw_size": len(encoded),
            "reason": "".join(
                character if character.isprintable() else "?"
                for character in str(reason)
            )[:256]
            or "invalid stored JSON",
            "reason_code": (
                "stored_row_semantics_invalid"
                if normalized_column in {"row_semantics", "dashboard_row"}
                else "stored_json_invalid"
            ),
            "raw": raw,
        }
        with self._lock:
            transaction_was_active = self._connection.in_transaction
            self._record_quarantine_locked(incident)
            self._isolate_quarantine_locked(incident)
            if transaction_was_active and self._quarantine_boundaries:
                self._quarantine_boundaries[-1].append(dict(incident))
            if not transaction_was_active:
                self._connection.commit()

    def _record_quarantine_locked(self, incident: dict[str, Any]) -> str | None:
        now = time.time()
        self._prune_resolved_quarantine_locked()
        scope_kind, scope_key = self._quarantine_scope(
            str(incident["table_name"]),
            str(incident["row_key"]),
            incident.get("raw"),
        )
        existing = self._connection.execute(
            "SELECT quarantine_id FROM json_quarantine "
            "WHERE locator_sha256=? AND state='open'",
            (incident["locator_sha256"],),
        ).fetchone()
        if existing is not None:
            self._connection.execute(
                "UPDATE json_quarantine SET raw_sha256=?, raw_storage_class=?, "
                "raw_size=?, reason=?, reason_code=?, scope_kind=?, scope_key=?, "
                "last_detected_at=?, detected_at=?, "
                "detection_count=detection_count+1, revision=revision+1 "
                "WHERE quarantine_id=? AND state='open'",
                (
                    incident["raw_sha256"],
                    incident["raw_storage_class"],
                    incident["raw_size"],
                    incident["reason"],
                    incident["reason_code"],
                    scope_kind,
                    scope_key,
                    now,
                    now,
                    existing["quarantine_id"],
                ),
            )
            return str(existing["quarantine_id"])

        open_count = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM json_quarantine WHERE state='open'"
            ).fetchone()[0]
        )
        if open_count >= MAX_OPEN_STORAGE_QUARANTINES:
            self._connection.execute(
                "UPDATE json_quarantine_control SET overflowed=1, "
                "overflow_count=overflow_count+1, last_overflow_at=? "
                "WHERE singleton=1",
                (now,),
            )
            return None

        # The legacy table has a uniqueness constraint that predates case
        # state. Re-open an exact old case rather than growing a duplicate.
        reusable = self._connection.execute(
            "SELECT quarantine_id FROM json_quarantine WHERE table_name=? "
            "AND row_key=? AND column_name=? AND raw_sha256=? "
            "AND state='resolved' LIMIT 1",
            (
                incident["table_name"],
                incident["row_key"],
                incident["column_name"],
                incident["raw_sha256"],
            ),
        ).fetchone()
        if reusable is not None:
            quarantine_id = str(reusable["quarantine_id"])
            self._connection.execute(
                "UPDATE json_quarantine SET locator_sha256=?, "
                "raw_storage_class=?, raw_size=?, reason=?, reason_code=?, "
                "scope_kind=?, scope_key=?, state='open', detection_count=1, "
                "first_detected_at=?, last_detected_at=?, detected_at=?, "
                "revision=revision+1, resolution_decision=NULL, "
                "resolution_note=NULL, resolved_by=NULL, resolved_at=NULL "
                "WHERE quarantine_id=?",
                (
                    incident["locator_sha256"],
                    incident["raw_storage_class"],
                    incident["raw_size"],
                    incident["reason"],
                    incident["reason_code"],
                    scope_kind,
                    scope_key,
                    now,
                    now,
                    now,
                    quarantine_id,
                ),
            )
            return quarantine_id

        quarantine_id = str(uuid.uuid4())
        self._connection.execute(
            """
            INSERT INTO json_quarantine(
              quarantine_id, table_name, row_key, column_name,
              raw_sha256, reason, detected_at, locator_sha256,
              raw_storage_class, raw_size, reason_code, scope_kind,
              scope_key, state, detection_count, first_detected_at,
              last_detected_at, revision
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', 1, ?, ?, 0)
            """,
            (
                quarantine_id,
                incident["table_name"],
                incident["row_key"],
                incident["column_name"],
                incident["raw_sha256"],
                incident["reason"],
                now,
                incident["locator_sha256"],
                incident["raw_storage_class"],
                incident["raw_size"],
                incident["reason_code"],
                scope_kind,
                scope_key,
                now,
                now,
            ),
        )
        return quarantine_id

    def _prune_resolved_quarantine_locked(
        self, *, cutoff: float | None = None
    ) -> int:
        removed = 0
        if cutoff is not None:
            cursor = self._connection.execute(
                "DELETE FROM json_quarantine WHERE state='resolved' "
                "AND resolved_at IS NOT NULL AND resolved_at<?",
                (cutoff,),
            )
            removed += cursor.rowcount
        stale = self._connection.execute(
            "SELECT quarantine_id FROM json_quarantine WHERE state='resolved' "
            "ORDER BY resolved_at DESC, quarantine_id DESC "
            "LIMIT -1 OFFSET ?",
            (MAX_RESOLVED_STORAGE_QUARANTINES,),
        ).fetchall()
        for row in stale:
            cursor = self._connection.execute(
                "DELETE FROM json_quarantine WHERE quarantine_id=? "
                "AND state='resolved'",
                (row["quarantine_id"],),
            )
            removed += cursor.rowcount
        return removed

    def _isolate_quarantine_locked(self, incident: dict[str, Any]) -> None:
        table_name = str(incident["table_name"])
        row_key = str(incident["row_key"])
        now = time.time()
        if table_name in FORENSIC_ONLY_QUARANTINE_TABLES:
            return
        if table_name == "alerts":
            self._connection.execute(
                "UPDATE alerts SET status='decided', decision='json_quarantined', "
                "decided_at=? WHERE alert_id=? AND status='open'",
                (now, row_key),
            )
            self._connection.execute(
                "UPDATE actions SET status=CASE status WHEN 'queued' THEN 'failed' "
                "ELSE 'outcome_unknown' END, completed_at=CASE status "
                "WHEN 'queued' THEN ? ELSE NULL END, result_json=?, "
                "result_source='controller' WHERE alert_id=? "
                "AND status IN ('queued','dispatched')",
                (now, ACTION_STORAGE_QUARANTINED_RESULT, row_key),
            )
            return
        if table_name == "actions":
            self._connection.execute(
                "UPDATE actions SET status=CASE "
                "WHEN status='queued' OR (status='failed' AND attempts=0 "
                "AND dispatched_at IS NULL) THEN 'failed' "
                "ELSE 'outcome_unknown' END, completed_at=CASE "
                "WHEN status='queued' OR (status='failed' AND attempts=0 "
                "AND dispatched_at IS NULL) THEN COALESCE(completed_at, ?) "
                "ELSE NULL END, result_json=CASE "
                "WHEN status='queued' OR (status='failed' AND attempts=0 "
                "AND dispatched_at IS NULL) THEN ? ELSE result_json END, "
                "result_source=CASE "
                "WHEN status='queued' OR (status='failed' AND attempts=0 "
                "AND dispatched_at IS NULL) THEN 'controller' "
                "ELSE result_source END WHERE action_id=? "
                "AND status IN ('queued','dispatched','completed','failed','reconciled')",
                (now, ACTION_STORAGE_QUARANTINED_RESULT, row_key),
            )
            self._connection.execute(
                "UPDATE baseline_promotions SET status='blocked', "
                "failure_reason='action_storage_quarantined', updated_at=?, "
                "completed_at=? WHERE action_id=? AND status='pending'",
                (now, now, row_key),
            )
            return
        if table_name == "baselines":
            self._connection.execute(
                "UPDATE baselines SET status='invalid', approved_at=NULL "
                "WHERE agent_id=?",
                (row_key,),
            )
            self._connection.execute(
                "UPDATE baseline_promotions SET status='blocked', "
                "failure_reason='baseline_storage_quarantined', updated_at=?, "
                "completed_at=? WHERE agent_id=? AND status='pending'",
                (now, now, row_key),
            )
            self._connection.execute(
                "UPDATE actions SET status=CASE status WHEN 'queued' THEN 'failed' "
                "ELSE 'outcome_unknown' END, completed_at=CASE status "
                "WHEN 'queued' THEN ? ELSE NULL END, result_json=?, "
                "result_source='controller' WHERE agent_id=? "
                "AND action_type IN ('restore_integrity','rollback_integrity',"
                "'capture_restore_point') AND status IN ('queued','dispatched')",
                (now, ACTION_STORAGE_QUARANTINED_RESULT, row_key),
            )
            return
        if table_name == "baseline_promotions":
            promotion = self._connection.execute(
                "SELECT action_id FROM baseline_promotions WHERE promotion_id=?",
                (row_key,),
            ).fetchone()
            self._connection.execute(
                "UPDATE baseline_promotions SET status='blocked', "
                "failure_reason='promotion_storage_quarantined', updated_at=?, "
                "completed_at=? WHERE promotion_id=? AND status='pending'",
                (now, now, row_key),
            )
            if promotion is not None and promotion["action_id"]:
                self._isolate_quarantine_locked(
                    {"table_name": "actions", "row_key": str(promotion["action_id"])}
                )
            return
        if table_name == "learning_feedback":
            self._connection.execute(
                "UPDATE learning_feedback SET provenance_status='quarantined', "
                "provenance_reason='stored_data_invalid' WHERE feedback_id=?",
                (row_key,),
            )
            return
        if table_name in {
            "learning_labels",
            "alert_occurrences",
            "telemetry_observations",
        }:
            # Immutable lineage is isolated by permanent query exclusion. Never
            # mutate the evidentiary row in response to discovering corruption.
            return
        if table_name == "agents":
            self._revoke_corrupt_agent_locked(
                row_key, now, "agent_storage_quarantined"
            )
            return
        if table_name in {"telemetry_boots", "telemetry_processing"}:
            raw = incident.get("raw")
            if isinstance(raw, sqlite3.Row):
                raw = dict(raw)
            agent_id = raw.get("agent_id") if isinstance(raw, dict) else None
            if isinstance(agent_id, str) and agent_id:
                self._revoke_corrupt_agent_locked(
                    agent_id, now, "telemetry_storage_quarantined"
                )
            return
        if table_name == "controller_state":
            self._connection.execute(
                "UPDATE actions SET status=CASE status WHEN 'queued' THEN 'failed' "
                "ELSE 'outcome_unknown' END, completed_at=CASE status "
                "WHEN 'queued' THEN ? ELSE NULL END, result_json=?, "
                "result_source='controller' WHERE status IN ('queued','dispatched')",
                (now, ACTION_STORAGE_QUARANTINED_RESULT),
            )

    def _start_quarantine_boundary_locked(self) -> None:
        self._quarantine_boundaries.append([])

    def _finish_quarantine_boundary_locked(self) -> None:
        if self._quarantine_boundaries:
            self._quarantine_boundaries.pop()

    def _rollback_preserving_quarantine_locked(self) -> None:
        incidents = self._quarantine_boundaries.pop() if self._quarantine_boundaries else []
        if self._connection.in_transaction:
            self._connection.rollback()
        if not incidents:
            return
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            for incident in incidents:
                self._record_quarantine_locked(incident)
                self._isolate_quarantine_locked(incident)
            self._connection.commit()
        except Exception:
            if self._connection.in_transaction:
                self._connection.rollback()
            raise

    def _decode_stored_json(
        self,
        raw: object,
        *,
        table_name: str,
        row_key: str,
        column_name: str,
        expected_type: type | tuple[type, ...] | None = None,
        fallback: Any = None,
    ) -> Any:
        try:
            value = strict_json_loads(str(raw), max_bytes=MAX_STORED_JSON_BYTES)
            if expected_type is not None and not isinstance(value, expected_type):
                raise ValueError("stored JSON has the wrong top-level type")
            return value
        except ValueError as exc:
            self._quarantine_json(
                table_name, row_key, column_name, raw, str(exc)
            )
            if isinstance(fallback, dict):
                return dict(fallback)
            if isinstance(fallback, list):
                return list(fallback)
            return fallback

    def stored_json_readiness(self) -> dict[str, Any]:
        """Expose a bounded fail-closed summary for operator readiness."""
        with self._lock:
            count = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM json_quarantine WHERE state='open'"
                ).fetchone()[0]
            )
            blocking = int(
                self._connection.execute(
                    "SELECT COUNT(*) FROM json_quarantine "
                    "WHERE state='open' AND scope_kind!='forensic'"
                ).fetchone()[0]
            )
            control = self._connection.execute(
                "SELECT * FROM json_quarantine_control WHERE singleton=1"
            ).fetchone()
            rows = self._connection.execute(
                """
                SELECT quarantine_id, table_name, row_key, column_name,
                       raw_sha256, raw_storage_class, raw_size, reason,
                       reason_code, scope_kind, scope_key, detection_count,
                       first_detected_at, last_detected_at, revision
                FROM json_quarantine WHERE state='open'
                ORDER BY last_detected_at DESC LIMIT 32
                """
            ).fetchall()
        overflowed = bool(control and int(control["overflowed"]) == 1)
        return {
            "ready": blocking == 0 and not overflowed,
            "quarantined_rows": count,
            "blocking_rows": blocking,
            "forensic_rows": count - blocking,
            "overflowed": overflowed,
            "overflow_count": int(control["overflow_count"]) if control else 0,
            "schema_version": int(control["schema_version"]) if control else 0,
            "recent": [dict(row) for row in rows],
        }

    def _has_blocking_quarantine_locked(self) -> bool:
        control = self._connection.execute(
            "SELECT overflowed FROM json_quarantine_control WHERE singleton=1"
        ).fetchone()
        if control is None or type(control["overflowed"]) is not int:
            return True
        if control["overflowed"] != 0:
            return True
        return self._connection.execute(
            "SELECT 1 FROM json_quarantine WHERE state='open' "
            "AND scope_kind!='forensic' LIMIT 1"
        ).fetchone() is not None

    def list_storage_quarantines(
        self, *, state: str = "open", limit: int = 100
    ) -> list[dict[str, Any]]:
        if state not in {"open", "resolved"}:
            raise ValueError("storage quarantine state is invalid")
        bounded_limit = max(1, min(int(limit), 256))
        with self._lock:
            rows = self._connection.execute(
                "SELECT quarantine_id, table_name, row_key, column_name, "
                "raw_sha256, raw_storage_class, raw_size, reason, reason_code, "
                "scope_kind, scope_key, state, detection_count, "
                "first_detected_at, last_detected_at, revision, "
                "resolution_decision, resolution_note, resolved_by, resolved_at "
                "FROM json_quarantine WHERE state=? "
                "ORDER BY last_detected_at DESC, quarantine_id DESC LIMIT ?",
                (state, bounded_limit),
            ).fetchall()
        return [dict(row) for row in rows]

    def _quarantine_source_raw_locked(
        self, table_name: str, row_key: str, column_name: str
    ) -> tuple[bool, object]:
        json_columns = {
            ("agents", "latest_telemetry"): ("agents", "agent_id"),
            ("baselines", "baseline_json"): ("baselines", "agent_id"),
            ("baseline_promotions", "candidate_json"): (
                "baseline_promotions",
                "promotion_id",
            ),
            ("alerts", "evidence_json"): ("alerts", "alert_id"),
            ("actions", "parameters_json"): ("actions", "action_id"),
            ("actions", "result_json"): ("actions", "action_id"),
            ("learning_feedback", "features_json"): (
                "learning_feedback",
                "feedback_id",
            ),
            ("telemetry_observations", "telemetry_json"): (
                "telemetry_observations",
                "observation_id",
            ),
            ("alert_occurrences", "candidate_json"): (
                "alert_occurrences",
                "occurrence_id",
            ),
            ("alert_occurrences", "features_json"): (
                "alert_occurrences",
                "occurrence_id",
            ),
            ("audit_log", "detail_json"): ("audit_log", "audit_id"),
            ("controller_state", "state_value"): (
                "controller_state",
                "state_key",
            ),
        }
        location = json_columns.get((table_name, column_name))
        if location is not None:
            # Both identifiers come exclusively from the fixed registry above.
            row = self._connection.execute(
                f"SELECT {column_name} AS raw FROM {location[0]} "
                f"WHERE {location[1]}=?",
                (row_key,),
            ).fetchone()
            return (row is not None, row["raw"] if row is not None else None)
        row_tables = {
            "agents": ("agent_id",),
            "baselines": ("agent_id",),
            "baseline_promotions": ("promotion_id",),
            "alerts": ("alert_id",),
            "actions": ("action_id",),
            "learning_feedback": ("feedback_id",),
            "learning_labels": ("label_id",),
            "alert_occurrences": ("occurrence_id",),
            "telemetry_observations": ("observation_id",),
            "audit_log": ("audit_id",),
            "controller_state": ("state_key",),
        }
        if column_name in {
            "row_semantics",
            "dashboard_row",
            "latest_telemetry_semantics",
            "action_result_binding",
            "envelope_sha256",
        } and table_name in row_tables:
            primary_key = row_tables[table_name][0]
            row = self._connection.execute(
                f"SELECT * FROM {table_name} WHERE {primary_key}=?",
                (row_key,),
            ).fetchone()
            return (row is not None, dict(row) if row is not None else None)
        return False, None

    def _delete_quarantine_source_locked(
        self, table_name: str, row_key: str, column_name: str
    ) -> bool:
        placeholder = canonical_json_dumps(INVALID_JSON_PLACEHOLDER)
        if table_name == "alerts" and column_name == "evidence_json":
            return self._connection.execute(
                "UPDATE alerts SET evidence_json=? WHERE alert_id=?",
                (placeholder, row_key),
            ).rowcount == 1
        if table_name == "actions" and column_name in {
            "parameters_json",
            "result_json",
        }:
            return self._connection.execute(
                f"UPDATE actions SET {column_name}=? WHERE action_id=? "
                "AND status IN ('failed','outcome_unknown')",
                (placeholder, row_key),
            ).rowcount == 1
        if table_name == "baselines" and column_name in {
            "baseline_json",
            "row_semantics",
        }:
            return self._connection.execute(
                "DELETE FROM baselines WHERE agent_id=? "
                "AND status IN ('invalid','invalidated')",
                (row_key,),
            ).rowcount == 1
        if table_name == "baseline_promotions" and column_name == "candidate_json":
            return self._connection.execute(
                "UPDATE baseline_promotions SET candidate_json=? "
                "WHERE promotion_id=? AND status='blocked'",
                (placeholder, row_key),
            ).rowcount == 1
        if table_name == "learning_feedback" and column_name == "features_json":
            return self._connection.execute(
                "DELETE FROM learning_feedback WHERE feedback_id=? "
                "AND provenance_status='quarantined'",
                (row_key,),
            ).rowcount == 1
        if table_name == "audit_log" and column_name == "detail_json":
            return self._connection.execute(
                "UPDATE audit_log SET detail_json=? WHERE audit_id=?",
                (placeholder, row_key),
            ).rowcount == 1
        # Agent telemetry is already cleared by the epoch-revocation isolation
        # policy. Controller state and whole-row semantic damage require an
        # offline recovery workflow rather than a generic field deletion.
        return False

    def resolve_storage_quarantine(
        self,
        quarantine_id: str,
        *,
        decision: str,
        expected_revision: int,
        expected_raw_sha256: str,
        operator_id: str,
        note: str,
    ) -> dict[str, Any] | None:
        """Resolve or safely discard one exact case without restoring authority."""
        if decision not in {"resolve", "delete"}:
            raise ValueError("storage quarantine decision must be resolve or delete")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("storage quarantine revision is invalid")
        if (
            not isinstance(expected_raw_sha256, str)
            or len(expected_raw_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_raw_sha256)
        ):
            raise ValueError("storage quarantine digest is invalid")
        if not isinstance(operator_id, str) or not 1 <= len(operator_id) <= 128:
            raise ValueError("storage quarantine operator identity is invalid")
        if not isinstance(note, str) or not 1 <= len(note) <= 512:
            raise ValueError("storage quarantine resolution note is invalid")
        with self._lock, _ImmediateTransaction(self._connection):
            row = self._connection.execute(
                "SELECT * FROM json_quarantine WHERE quarantine_id=?",
                (quarantine_id,),
            ).fetchone()
            if row is None:
                self._connection.rollback()
                return None
            if row["state"] == "resolved":
                if (
                    row["resolution_decision"] == decision
                    and int(row["revision"]) == expected_revision + 1
                    and hmac.compare_digest(str(row["raw_sha256"]), expected_raw_sha256)
                ):
                    self._connection.rollback()
                    return dict(row)
                raise RuntimeError("storage quarantine resolution conflicts")
            if (
                int(row["revision"]) != expected_revision
                or not hmac.compare_digest(str(row["raw_sha256"]), expected_raw_sha256)
            ):
                raise RuntimeError("storage quarantine case changed concurrently")
            exists, current_raw = self._quarantine_source_raw_locked(
                str(row["table_name"]), str(row["row_key"]), str(row["column_name"])
            )
            current_matches = False
            if exists:
                current_class, current_encoded = _stored_value_evidence(current_raw)
                current_matches = (
                    current_class == str(row["raw_storage_class"])
                    and hmac.compare_digest(
                        hashlib.sha256(current_encoded).hexdigest(),
                        str(row["raw_sha256"]),
                    )
                )
            if decision == "resolve" and current_matches:
                raise RuntimeError(
                    "unchanged invalid storage cannot be acknowledged as resolved"
                )
            if decision == "delete" and current_matches and not self._delete_quarantine_source_locked(
                str(row["table_name"]), str(row["row_key"]), str(row["column_name"])
            ):
                raise RuntimeError(
                    "this storage case requires conservative offline recovery"
                )
            now = time.time()
            cursor = self._connection.execute(
                "UPDATE json_quarantine SET state='resolved', "
                "resolution_decision=?, resolution_note=?, resolved_by=?, "
                "resolved_at=?, revision=revision+1 WHERE quarantine_id=? "
                "AND state='open' AND revision=? AND raw_sha256=?",
                (
                    decision,
                    note,
                    operator_id,
                    now,
                    quarantine_id,
                    expected_revision,
                    expected_raw_sha256,
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("storage quarantine case changed concurrently")
            self._connection.execute(
                "INSERT INTO audit_log(audit_id, actor, operation, subject, "
                "detail_json, created_at) VALUES(?, ?, 'resolve_storage_quarantine', "
                "?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    operator_id,
                    quarantine_id,
                    canonical_json_dumps(
                        {
                            "decision": decision,
                            "raw_sha256": expected_raw_sha256,
                            "note": note,
                        }
                    ),
                    now,
                ),
            )
            self._prune_resolved_quarantine_locked()
            resolved = self._connection.execute(
                "SELECT * FROM json_quarantine WHERE quarantine_id=?",
                (quarantine_id,),
            ).fetchone()
            self._connection.commit()
            return dict(resolved)

    @staticmethod
    def _binding_values(binding: dict[str, Any]) -> tuple[int, str, str, str]:
        return (
            int(binding.get("credential_epoch", -1)),
            str(binding.get("profile_id", "")),
            str(binding.get("profile_fingerprint", "")),
            str(binding.get("agent_version", "")),
        )

    def _invalidate_stale_actions_for_binding_locked(
        self,
        agent_id: str,
        binding_values: tuple[int, str, str, str],
        now: float,
    ) -> None:
        """Remove old authority before it can consume quota or reach delivery."""
        epoch, profile_id, profile_fingerprint, agent_version = binding_values
        self._connection.execute(
            """
            UPDATE actions SET
              status=CASE status
                WHEN 'queued' THEN 'failed'
                ELSE 'outcome_unknown'
              END,
              completed_at=CASE status
                WHEN 'queued' THEN ?
                ELSE NULL
              END,
              result_json=?, result_source='controller'
            WHERE agent_id=? AND status IN ('queued','dispatched')
              AND NOT (
                credential_epoch=? AND profile_id=?
                AND profile_fingerprint=? AND agent_version=?
              )
            """,
            (
                now,
                ACTION_BINDING_INVALIDATED_RESULT,
                agent_id,
                epoch,
                profile_id,
                profile_fingerprint,
                agent_version,
            ),
        )

    def agent_binding(
        self,
        agent_id: str,
        *,
        require_fresh: bool = False,
        freshness_seconds: float = 90.0,
        validate_current_telemetry: bool = False,
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT a.credential_epoch, a.profile_id,
                       a.profile_fingerprint, a.agent_version, a.last_seen,
                       a.latest_telemetry, a.enabled, a.last_sequence,
                       a.boot_id, a.last_observed_at,
                       a.latest_payload_sha256,
                       b.max_sequence AS history_max_sequence,
                       b.max_observed_at AS history_max_observed_at,
                       b.last_payload_sha256 AS history_payload_sha256,
                       b.state AS history_state
                FROM agents a LEFT JOIN telemetry_boots b
                  ON b.agent_id=a.agent_id
                 AND b.credential_epoch=a.credential_epoch
                 AND b.profile_fingerprint=a.profile_fingerprint
                 AND b.boot_id=a.boot_id
                WHERE a.agent_id=?
                """,
                (agent_id,),
            ).fetchone()
            release_row = self._connection.execute(
                """
                SELECT state_value FROM controller_state
                WHERE state_key='active_release_binding'
                """
            ).fetchone()
        if not row or type(row["enabled"]) is not int or row["enabled"] != 1:
            return None
        reset_tuple = (
            row["profile_id"] == ""
            and row["profile_fingerprint"] == ""
            and row["agent_version"] == ""
            and row["latest_telemetry"] is None
            and row["last_sequence"] == -1
            and row["boot_id"] == ""
            and row["last_observed_at"] == 0
            and row["latest_payload_sha256"] == ""
            and row["last_seen"] == 0
        )
        if reset_tuple:
            return None
        try:
            result = {
                "credential_epoch": int(row["credential_epoch"]),
                "profile_id": str(row["profile_id"]),
                "profile_fingerprint": str(row["profile_fingerprint"]),
                "agent_version": str(row["agent_version"]),
            }
            if (
                type(row["credential_epoch"]) is not int
                or not 0 <= result["credential_epoch"] <= 2**63 - 1
                or not result["profile_id"]
                or len(result["profile_id"]) > 128
                or len(result["profile_fingerprint"]) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in result["profile_fingerprint"]
                )
                or not result["agent_version"]
                or len(result["agent_version"]) > 64
                or type(row["last_seen"]) not in {int, float}
                or not math.isfinite(row["last_seen"])
                or not 0 <= row["last_seen"] <= 2**63 - 1
            ):
                raise ValueError("stored agent release binding is invalid")
            if release_row is not None:
                active = strict_json_loads(
                    str(release_row["state_value"]), max_bytes=64 * 1024
                )
                if (
                    not isinstance(active, dict)
                    or set(active)
                    != {
                        "schema",
                        "profile_id",
                        "profile_fingerprint",
                        "agent_version",
                        "release_sha256",
                    }
                    or type(active.get("schema")) is not int
                    or active.get("schema") != 1
                    or not isinstance(active.get("release_sha256"), str)
                    or (
                        str(active.get("release_sha256")) != ""
                        and (
                            len(str(active.get("release_sha256"))) != 64
                            or any(
                                character not in "0123456789abcdef"
                                for character in str(active.get("release_sha256"))
                            )
                        )
                    )
                    or (
                        str(active.get("profile_id")),
                        str(active.get("profile_fingerprint")),
                        str(active.get("agent_version")),
                    )
                    != (
                        result["profile_id"],
                        result["profile_fingerprint"],
                        result["agent_version"],
                    )
                ):
                    raise ValueError(
                        "agent release binding does not match the active controller release"
                    )
        except (TypeError, ValueError, OverflowError) as exc:
            self._quarantine_json(
                "agents", agent_id, "row_semantics", dict(row), str(exc)
            )
            return None
        if require_fresh or validate_current_telemetry:
            if (
                row["latest_telemetry"] is None
                or (
                    require_fresh
                    and time.time() - float(row["last_seen"])
                    > max(15.0, float(freshness_seconds))
                )
            ):
                return None
            telemetry = self._decode_stored_json(
                row["latest_telemetry"],
                table_name="agents",
                row_key=agent_id,
                column_name="latest_telemetry",
                expected_type=dict,
            )
            try:
                if telemetry is None:
                    raise ValueError("latest telemetry is unavailable")
                # Stored JSON must remain a complete valid wire sample, not
                # merely an object containing four attacker-selected binding
                # strings.  Import locally to keep persistence initialization
                # independent of wire-schema module loading.
                from .validation import validate_telemetry

                normalized = validate_telemetry(
                    telemetry,
                    expected_agent_id=agent_id,
                    # Freshness is enforced independently above.  Validate
                    # immutable storage semantics against the receipt time so
                    # an offline but authentic row is not quarantined by age.
                    now=float(row["last_seen"]),
                )
                encoded = canonical_json_dumps(
                    normalized, max_bytes=MAX_STORED_JSON_BYTES
                )
                raw_encoded = canonical_json_dumps(
                    telemetry, max_bytes=MAX_STORED_JSON_BYTES
                )
                digest = hashlib.sha256(raw_encoded.encode()).hexdigest()
                if not hmac_compare_json(encoded, raw_encoded):
                    raise ValueError("latest telemetry is not canonically normalized")
                if (
                    normalized.get("profile_id"),
                    normalized.get("profile_fingerprint"),
                    normalized.get("agent_version"),
                    normalized.get("boot_id"),
                    normalized.get("sequence"),
                    float(normalized.get("observed_at", -1)),
                    digest,
                ) != (
                    result["profile_id"],
                    result["profile_fingerprint"],
                    result["agent_version"],
                    str(row["boot_id"]),
                    int(row["last_sequence"]),
                    float(row["last_observed_at"]),
                    str(row["latest_payload_sha256"]),
                ):
                    raise ValueError(
                        "latest telemetry does not match the active agent high-water state"
                    )
                if (
                    row["history_state"] != "active"
                    or type(row["history_max_sequence"]) is not int
                    or int(row["history_max_sequence"])
                    != int(row["last_sequence"])
                    or type(row["history_max_observed_at"]) not in {int, float}
                    or float(row["history_max_observed_at"])
                    != float(row["last_observed_at"])
                    or str(row["history_payload_sha256"])
                    != str(row["latest_payload_sha256"])
                ):
                    raise ValueError(
                        "latest telemetry has no exact active boot-history authority"
                    )
            except (TypeError, ValueError, OverflowError) as exc:
                self._quarantine_json(
                    "agents",
                    agent_id,
                    "latest_telemetry_semantics",
                    row["latest_telemetry"],
                    str(exc),
                )
                return None
        return result


    def binding_matches(
        self,
        agent_id: str,
        binding: dict[str, Any],
        *,
        require_fresh: bool = False,
        freshness_seconds: float = 90.0,
    ) -> bool:
        current = self.agent_binding(
            agent_id,
            require_fresh=require_fresh,
            freshness_seconds=freshness_seconds,
        )
        return current is not None and self._binding_values(current) == self._binding_values(binding)

    def _validate_recovery_schema_locked(self) -> None:
        from .recovery import (
            CONTROLLER_ALLOWED_TABLES,
            CONTROLLER_TRIGGER_CONTRACTS,
        )

        tables = {
            str(row["name"])
            for row in self._connection.execute(
                "SELECT name FROM sqlite_schema WHERE type='table'"
            ).fetchall()
        }
        if tables != set(CONTROLLER_ALLOWED_TABLES):
            raise ValueError(
                "controller schema is not the exact recovery-capable schema"
            )
        triggers = {
            str(row["name"]): " ".join(str(row["sql"] or "").split()).casefold()
            for row in self._connection.execute(
                "SELECT name, sql FROM sqlite_schema WHERE type='trigger'"
            ).fetchall()
        }
        expected_triggers = {
            name: " ".join(sql.split()).casefold()
            for name, sql in CONTROLLER_TRIGGER_CONTRACTS.items()
        }
        if triggers != expected_triggers:
            raise ValueError(
                "controller immutable-trigger schema is not recovery-capable"
            )

    def _recovery_identity_locked(self) -> dict[str, Any]:
        from .recovery import (
            CONTROLLER_APPLICATION_ID,
            CONTROLLER_USER_VERSION,
        )

        application_id = int(
            self._connection.execute("PRAGMA application_id").fetchone()[0]
        )
        user_version = int(
            self._connection.execute("PRAGMA user_version").fetchone()[0]
        )
        rows = {
            str(row["state_key"]): str(row["state_value"])
            for row in self._connection.execute(
                """
                SELECT state_key, state_value FROM controller_state
                WHERE state_key IN (
                  'controller_instance_id', 'recovery_generation',
                  'backup_sequence'
                )
                """
            ).fetchall()
        }
        if (
            application_id != CONTROLLER_APPLICATION_ID
            or user_version != CONTROLLER_USER_VERSION
            or set(rows)
            != {
                "controller_instance_id",
                "recovery_generation",
                "backup_sequence",
            }
        ):
            raise ValueError("controller recovery identity is not initialized")
        try:
            instance_id = str(uuid.UUID(rows["controller_instance_id"]))
        except (ValueError, AttributeError) as exc:
            raise ValueError("controller recovery instance identity is invalid") from exc
        if instance_id != rows["controller_instance_id"]:
            raise ValueError("controller recovery instance identity is invalid")
        for name, minimum in (("recovery_generation", 1), ("backup_sequence", 0)):
            value = rows[name]
            if (
                not value.isascii()
                or not value.isdecimal()
                or (len(value) > 1 and value.startswith("0"))
            ):
                raise ValueError(f"controller {name} is not canonical")
            numeric = int(value)
            if not minimum <= numeric <= 2**63 - 1:
                raise ValueError(f"controller {name} is outside its range")
            rows[name] = numeric
        return {
            "application_id": application_id,
            "user_version": user_version,
            "controller_instance_id": instance_id,
            "recovery_generation": int(rows["recovery_generation"]),
            "backup_sequence": int(rows["backup_sequence"]),
        }

    def initialize_recovery_identity(
        self, *, controller_instance_id: str | None = None
    ) -> dict[str, Any]:
        """Offline-only initialization of recovery pragmas and identity."""
        from .recovery import (
            CONTROLLER_APPLICATION_ID,
            CONTROLLER_USER_VERSION,
        )

        requested = controller_instance_id or str(uuid.uuid4())
        try:
            canonical_instance = str(uuid.UUID(requested))
        except (ValueError, AttributeError) as exc:
            raise ValueError("controller recovery instance identity is invalid") from exc
        if canonical_instance != requested:
            raise ValueError("controller recovery instance identity is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._validate_recovery_schema_locked()
                application_id = int(
                    self._connection.execute("PRAGMA application_id").fetchone()[0]
                )
                user_version = int(
                    self._connection.execute("PRAGMA user_version").fetchone()[0]
                )
                existing = self._connection.execute(
                    """
                    SELECT COUNT(*) FROM controller_state
                    WHERE state_key IN (
                      'controller_instance_id', 'recovery_generation',
                      'backup_sequence'
                    )
                    """
                ).fetchone()[0]
                if existing:
                    identity = self._recovery_identity_locked()
                    if (
                        controller_instance_id is not None
                        and identity["controller_instance_id"]
                        != canonical_instance
                    ):
                        raise ValueError(
                            "controller recovery identity already belongs to another instance"
                        )
                    self._connection.commit()
                    return identity
                if application_id != 0 or user_version != 0:
                    raise ValueError(
                        "unbound database pragmas require explicit offline migration"
                    )
                now = time.time()
                self._connection.execute(
                    f"PRAGMA application_id={CONTROLLER_APPLICATION_ID}"
                )
                self._connection.execute(
                    f"PRAGMA user_version={CONTROLLER_USER_VERSION}"
                )
                self._connection.executemany(
                    """
                    INSERT INTO controller_state(state_key, state_value, updated_at)
                    VALUES(?, ?, ?)
                    """,
                    (
                        ("controller_instance_id", canonical_instance, now),
                        ("recovery_generation", "1", now),
                        ("backup_sequence", "0", now),
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO audit_log(
                      audit_id, actor, operation, subject, detail_json, created_at
                    ) VALUES(?, 'offline-operator', 'initialize_recovery', ?, '{}', ?)
                    """,
                    (str(uuid.uuid4()), canonical_instance, now),
                )
                self._connection.commit()
                return self._recovery_identity_locked()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def recovery_identity(self) -> dict[str, Any]:
        with self._lock:
            self._validate_recovery_schema_locked()
            return self._recovery_identity_locked()

    def advance_recovery_backup_sequence(self) -> dict[str, Any]:
        """Advance the durable backup sequence before copying the database."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                identity = self._recovery_identity_locked()
                current = int(identity["backup_sequence"])
                if current >= 2**63 - 1:
                    raise OverflowError("controller backup sequence is exhausted")
                next_sequence = current + 1
                now = time.time()
                cursor = self._connection.execute(
                    """
                    UPDATE controller_state SET state_value=?, updated_at=?
                    WHERE state_key='backup_sequence' AND state_value=?
                    """,
                    (str(next_sequence), now, str(current)),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError(
                        "controller backup sequence changed concurrently"
                    )
                self._connection.execute(
                    """
                    INSERT INTO audit_log(
                      audit_id, actor, operation, subject, detail_json, created_at
                    ) VALUES(?, 'controller', 'advance_backup_sequence', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        identity["controller_instance_id"],
                        canonical_json_dumps({"backup_sequence": next_sequence}),
                        now,
                    ),
                )
                self._connection.commit()
                identity["backup_sequence"] = next_sequence
                return identity
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def activate_release_binding(
        self,
        *,
        profile_id: str,
        profile_fingerprint: str,
        agent_version: str,
        release_sha256: str,
        strict: bool,
    ) -> bool:
        """Activate one controller release and invalidate every stale authority.

        Agent credentials are deliberately preserved.  The next exact, fresh
        sample re-establishes an operational binding after a profile upgrade.
        """
        desired = {
            "schema": 1,
            "profile_id": str(profile_id),
            "profile_fingerprint": str(profile_fingerprint),
            "agent_version": str(agent_version),
            "release_sha256": str(release_sha256),
        }
        encoded = canonical_json_dumps(desired)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                now = time.time()
                row = self._connection.execute(
                    "SELECT state_value FROM controller_state "
                    "WHERE state_key='active_release_binding'"
                ).fetchone()
                current: Any = None
                if row is not None:
                    try:
                        current = strict_json_loads(
                            str(row["state_value"]), max_bytes=64 * 1024
                        )
                        if (
                            not isinstance(current, dict)
                            or set(current) != set(desired)
                            or type(current.get("schema")) is not int
                            or current.get("schema") != 1
                            or any(
                                not isinstance(current.get(name), str)
                                for name in (
                                    "profile_id",
                                    "profile_fingerprint",
                                    "agent_version",
                                    "release_sha256",
                                )
                            )
                            or not current.get("profile_id")
                            or len(current.get("profile_id", "")) > 128
                            or not current.get("agent_version")
                            or len(current.get("agent_version", "")) > 64
                            or len(current.get("profile_fingerprint", "")) != 64
                            or any(
                                character not in "0123456789abcdef"
                                for character in current.get(
                                    "profile_fingerprint", ""
                                )
                            )
                            or (
                                current.get("release_sha256", "")
                                and (
                                    len(current["release_sha256"]) != 64
                                    or any(
                                        character not in "0123456789abcdef"
                                        for character in current["release_sha256"]
                                    )
                                )
                            )
                        ):
                            raise ValueError(
                                "active release binding has invalid semantics"
                            )
                    except (TypeError, ValueError) as exc:
                        # The binding is corrupt and therefore unequal.  Its
                        # replacement and every authority invalidation remain
                        # in this same transaction with bounded evidence.
                        self._quarantine_json(
                            "controller_state",
                            "active_release_binding",
                            "state_value",
                            row["state_value"],
                            str(exc),
                        )
                        current = None
                changed = current != desired
                if changed:
                    self._connection.execute(
                        "UPDATE baselines SET status='invalidated', approved_at=NULL "
                        "WHERE status IN ('pending','approved')"
                    )
                    self._connection.execute(
                        "UPDATE baseline_promotions SET status='blocked', "
                        "failure_reason='release_binding_changed', updated_at=?, "
                        "completed_at=? WHERE status='pending'",
                        (now, now),
                    )
                    self._connection.execute(
                        """
                        UPDATE alerts SET status='invalidated',
                          decision='release_binding_changed', decided_at=?
                        WHERE status='open'
                        """,
                        (now,),
                    )
                    self._connection.execute(
                        """
                        UPDATE actions SET
                          status=CASE status
                            WHEN 'queued' THEN 'failed'
                            ELSE 'outcome_unknown'
                          END,
                          completed_at=CASE status
                            WHEN 'queued' THEN ?
                            ELSE NULL
                          END,
                          result_json=?, result_source='controller'
                        WHERE status IN ('queued','dispatched')
                        """,
                        (now, ACTION_BINDING_INVALIDATED_RESULT),
                    )
                    self._connection.execute(
                        """
                        UPDATE change_grants SET revoked_at=?,
                          revocation_reason='release_binding_changed'
                        WHERE used_at IS NULL AND revoked_at IS NULL
                        """,
                        (now,),
                    )
                    self._connection.execute(
                        """
                        UPDATE privileged_authorizations SET revoked_at=?,
                          revocation_reason='release_binding_changed'
                        WHERE used_at IS NULL AND revoked_at IS NULL
                        """,
                        (now,),
                    )
                    self._connection.execute(
                        """
                        UPDATE agents SET profile_id='', profile_fingerprint='',
                          agent_version='', last_seen=0, latest_telemetry=NULL,
                          last_sequence=-1, boot_id='', last_observed_at=0,
                          latest_payload_sha256=''
                        """
                    )
                    self._connection.execute("DELETE FROM telemetry_boots")
                    self._connection.execute("DELETE FROM telemetry_processing")
                self._connection.execute(
                    """
                    INSERT INTO controller_state(state_key, state_value, updated_at)
                    VALUES('active_release_binding', ?, ?)
                    ON CONFLICT(state_key) DO UPDATE SET
                      state_value=excluded.state_value,
                      updated_at=excluded.updated_at
                    """,
                    (encoded, now),
                )
                self._connection.commit()
                return changed
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def begin_controller_session(self) -> tuple[str, bool]:
        """Durably mark this database as owned by an unclean-until-closed run."""
        session_id = str(uuid.uuid4())
        now = time.time()
        value = canonical_json_dumps(
            {"schema": 1, "session_id": session_id, "started_at": now}
        )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                prior = self._connection.execute(
                    "SELECT state_value FROM controller_state "
                    "WHERE state_key='controller_unclean_session'"
                ).fetchone()
                self._connection.execute(
                    """
                    INSERT INTO controller_state(state_key, state_value, updated_at)
                    VALUES('controller_unclean_session', ?, ?)
                    ON CONFLICT(state_key) DO UPDATE SET
                      state_value=excluded.state_value, updated_at=excluded.updated_at
                    """,
                    (value, now),
                )
                self._connection.commit()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise
        return session_id, prior is not None

    def initialize_campaign_id(self, requested: str | None = None) -> str:
        """Bind learning/evidence to one database campaign, never a profile alias."""
        candidate = str(requested or uuid.uuid4())
        if (
            not 1 <= len(candidate) <= 128
            or any(
                not (character.isalnum() or character in "_.:@+-")
                for character in candidate
            )
        ):
            raise ValueError("campaign_id is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT state_value FROM controller_state "
                    "WHERE state_key='campaign_id'"
                ).fetchone()
                if row:
                    persisted = str(row["state_value"])
                    if requested is not None and persisted != candidate:
                        raise ValueError(
                            "database campaign_id does not match the requested campaign"
                        )
                    self._connection.rollback()
                    return persisted
                self._connection.execute(
                    "INSERT INTO controller_state(state_key,state_value,updated_at) "
                    "VALUES('campaign_id', ?, ?)",
                    (candidate, time.time()),
                )
                self._connection.commit()
                return candidate
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def end_controller_session(self, session_id: str) -> bool:
        """Clear only this exact clean controller run's durable dirty marker."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT state_value FROM controller_state "
                    "WHERE state_key='controller_unclean_session'"
                ).fetchone()
                if not row:
                    self._connection.rollback()
                    return False
                value = strict_json_loads(
                    str(row["state_value"]), max_bytes=64 * 1024
                )
                if (
                    not isinstance(value, dict)
                    or set(value) != {"schema", "session_id", "started_at"}
                    or type(value.get("schema")) is not int
                    or value.get("schema") != 1
                    or value.get("session_id") != session_id
                ):
                    self._connection.rollback()
                    return False
                cursor = self._connection.execute(
                    "DELETE FROM controller_state "
                    "WHERE state_key='controller_unclean_session' AND state_value=?",
                    (str(row["state_value"]),),
                )
                self._connection.commit()
                return cursor.rowcount == 1
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def load_governance(
        self,
        *,
        profile_fingerprint: str,
        default_mode: str,
        strict: bool,
        allowed_modes: set[str] | frozenset[str] | None = None,
        force_safe: bool = False,
    ) -> dict[str, Any]:
        """Load profile-bound governance; missing/corrupt strict state is stopped."""
        admitted_modes = frozenset(allowed_modes or GOVERNANCE_MODES)
        if "observe" not in admitted_modes or not admitted_modes <= GOVERNANCE_MODES:
            raise ValueError("governance allowed modes are invalid")
        safe_default = default_mode if default_mode in admitted_modes else "observe"
        with self._lock, _ImmediateTransaction(self._connection):
            now = time.time()
            row = self._connection.execute(
                "SELECT state_value FROM controller_state WHERE state_key='governance'"
            ).fetchone()
            value: Any = None
            if row is not None:
                try:
                    value = strict_json_loads(
                        str(row["state_value"]), max_bytes=64 * 1024
                    )
                except ValueError as exc:
                    self._quarantine_json(
                        "controller_state", "governance", "state_value",
                        row["state_value"], str(exc)
                    )
            valid = (
                isinstance(value, dict)
                and set(value) == GOVERNANCE_FIELDS
                and type(value.get("schema")) is int
                and value.get("schema") == 1
                and value.get("profile_fingerprint") == profile_fingerprint
                and value.get("autonomy_mode") in admitted_modes
                and type(value.get("emergency_stopped")) is bool
                and type(value.get("revision")) is int
                and 0 <= value["revision"] <= 2**63 - 1
            )
            if valid and not force_safe:
                self._connection.rollback()
                return dict(value)
            prior_revision = (
                int(value["revision"])
                if isinstance(value, dict)
                and type(value.get("revision")) is int
                and 0 <= value["revision"] <= 2**63 - 1
                else -1
            )
            safe = {
                "schema": 1,
                "profile_fingerprint": profile_fingerprint,
                "autonomy_mode": "observe" if strict or force_safe else safe_default,
                "emergency_stopped": bool(strict or force_safe),
                "revision": min(2**63 - 1, prior_revision + 1),
            }
            self._connection.execute(
                """
                INSERT INTO controller_state(state_key, state_value, updated_at)
                VALUES('governance', ?, ?)
                ON CONFLICT(state_key) DO UPDATE SET
                  state_value=excluded.state_value, updated_at=excluded.updated_at
                """,
                (canonical_json_dumps(safe), now),
            )
            self._connection.execute(
                """
                UPDATE actions SET
                  status=CASE status
                    WHEN 'queued' THEN 'failed'
                    ELSE 'outcome_unknown'
                  END,
                  completed_at=CASE status
                    WHEN 'queued' THEN ?
                    ELSE NULL
                  END,
                  result_json=?, result_source='controller'
                WHERE status IN ('queued','dispatched')
                """,
                (now, ACTION_GOVERNANCE_CHANGED_RESULT),
            )
            self._connection.execute(
                """
                INSERT INTO audit_log(
                  audit_id, actor, operation, subject,
                  detail_json, created_at
                ) VALUES(?, 'controller', 'governance_startup_safe_reset', ?, ?, ?)
                """,
                (
                    str(uuid.uuid4()),
                    str(profile_fingerprint),
                    canonical_json_dumps(
                        {
                            "force_safe": bool(force_safe),
                            "prior_valid": bool(valid),
                            "revision": safe["revision"],
                        }
                    ),
                    now,
                ),
            )
            self._connection.commit()
            return safe

    def update_governance(
        self,
        *,
        profile_fingerprint: str,
        mode: str,
        emergency_stopped: bool,
        expected_revision: int,
    ) -> dict[str, Any]:
        if mode not in GOVERNANCE_MODES:
            raise ValueError("unsupported governance mode")
        if type(emergency_stopped) is not bool:
            raise ValueError("governance emergency stop must be a boolean")
        if type(expected_revision) is not int or not 0 <= expected_revision < 2**63 - 1:
            raise ValueError("governance revision is invalid")
        next_value = {
            "schema": 1,
            "profile_fingerprint": profile_fingerprint,
            "autonomy_mode": mode,
            "emergency_stopped": bool(emergency_stopped),
            "revision": int(expected_revision) + 1,
        }
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                now = time.time()
                row = self._connection.execute(
                    "SELECT state_value FROM controller_state WHERE state_key='governance'"
                ).fetchone()
                if not row:
                    raise RuntimeError("governance state is unavailable")
                current = strict_json_loads(
                    str(row["state_value"]), max_bytes=64 * 1024
                )
                if (
                    not isinstance(current, dict)
                    or set(current) != GOVERNANCE_FIELDS
                    or type(current.get("schema")) is not int
                    or current.get("schema") != 1
                    or current.get("profile_fingerprint") != profile_fingerprint
                    or current.get("autonomy_mode") not in GOVERNANCE_MODES
                    or type(current.get("emergency_stopped")) is not bool
                    or type(current.get("revision")) is not int
                    or current.get("revision") != expected_revision
                ):
                    raise RuntimeError("governance state changed concurrently")
                cursor = self._connection.execute(
                    """
                    UPDATE controller_state SET state_value=?, updated_at=?
                    WHERE state_key='governance' AND state_value=?
                    """,
                    (
                        canonical_json_dumps(next_value),
                        now,
                        str(row["state_value"]),
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("governance state changed concurrently")
                self._connection.execute(
                    """
                    UPDATE actions SET
                      status=CASE status
                        WHEN 'queued' THEN 'failed'
                        ELSE 'outcome_unknown'
                      END,
                      completed_at=CASE status
                        WHEN 'queued' THEN ?
                        ELSE NULL
                      END,
                      result_json=?, result_source='controller'
                    WHERE status IN ('queued','dispatched')
                    """,
                    (now, ACTION_GOVERNANCE_CHANGED_RESULT),
                )
                self._connection.execute(
                    """
                    INSERT INTO audit_log(
                      audit_id, actor, operation, subject, detail_json, created_at
                    ) VALUES(?, 'operator', 'governance_transition', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        str(profile_fingerprint),
                        canonical_json_dumps(
                            {
                                "from_mode": current["autonomy_mode"],
                                "from_stopped": current["emergency_stopped"],
                                "to_mode": mode,
                                "to_stopped": emergency_stopped,
                                "revision": next_value["revision"],
                            }
                        ),
                        now,
                    ),
                )
                self._connection.commit()
                return next_value
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def force_safe_governance(self, profile_fingerprint: str) -> None:
        """Best-effort independent fail-safe used after a governance write error."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT state_value FROM controller_state WHERE state_key='governance'"
                ).fetchone()
                revision = 0
                if row:
                    try:
                        current = strict_json_loads(
                            str(row["state_value"]), max_bytes=64 * 1024
                        )
                        if (
                            isinstance(current, dict)
                            and type(current.get("revision")) is int
                            and 0 <= current["revision"] < 2**63 - 1
                        ):
                            revision = current["revision"] + 1
                    except ValueError:
                        revision = 0
                safe = {
                    "schema": 1,
                    "profile_fingerprint": str(profile_fingerprint),
                    "autonomy_mode": "observe",
                    "emergency_stopped": True,
                    "revision": revision,
                }
                self._connection.execute(
                    """
                    INSERT INTO controller_state(state_key, state_value, updated_at)
                    VALUES('governance', ?, ?)
                    ON CONFLICT(state_key) DO UPDATE SET
                      state_value=excluded.state_value, updated_at=excluded.updated_at
                    """,
                    (canonical_json_dumps(safe), time.time()),
                )
                self._connection.execute(
                    """
                    UPDATE actions SET
                      status=CASE status
                        WHEN 'queued' THEN 'failed'
                        ELSE 'outcome_unknown'
                      END,
                      completed_at=CASE status
                        WHEN 'queued' THEN ?
                        ELSE NULL
                      END,
                      result_json=?, result_source='controller'
                    WHERE status IN ('queued','dispatched')
                    """,
                    (time.time(), ACTION_GOVERNANCE_CHANGED_RESULT),
                )
                self._connection.execute(
                    """
                    INSERT INTO audit_log(
                      audit_id, actor, operation, subject,
                      detail_json, created_at
                    ) VALUES(?, 'controller', 'governance_force_safe', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        str(profile_fingerprint),
                        canonical_json_dumps(
                            {
                                "autonomy_mode": "observe",
                                "emergency_stopped": True,
                                "revision": revision,
                            }
                        ),
                        time.time(),
                    ),
                )
                self._connection.commit()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def enroll_agent_once(
        self,
        *,
        agent_id: str,
        hostname: str,
        platform: str,
        agent_version: str,
        profile_id: str,
        profile_fingerprint: str,
        ticket: str,
        request_sha256: str,
        deadline: float,
        max_agents: int,
    ) -> tuple[str, bool]:
        """Atomically consume a host ticket and create one independent credential."""
        if (
            not isinstance(ticket, str)
            or not 32 <= len(ticket) <= 256
            or any(
                character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                for character in ticket
            )
            or not isinstance(request_sha256, str)
            or len(request_sha256) != 64
            or any(
                character not in "0123456789abcdef"
                for character in request_sha256
            )
        ):
            raise ValueError("enrollment ticket/request digest is invalid")
        ticket_hash = hashlib.sha256(ticket.encode()).hexdigest()
        generated = secrets.token_urlsafe(48)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                now = time.time()
                existing = self._connection.execute(
                    """
                    SELECT a.agent_secret, a.credential_epoch AS agent_epoch,
                           a.enabled, a.profile_id, a.latest_telemetry,
                           t.request_sha256, t.consumed_at, t.expires_at,
                           t.credential_epoch AS ticket_epoch,
                           t.profile_fingerprint AS ticket_profile_fingerprint,
                           t.agent_version AS ticket_agent_version,
                           r.authorized_at AS reenrollment_authorized_at,
                           r.expires_at AS reenrollment_expires_at,
                           r.credential_epoch AS reenrollment_epoch
                    FROM agents a LEFT JOIN enrollment_tickets t
                      ON t.ticket_hash=? AND t.agent_id=a.agent_id
                    LEFT JOIN agent_reenrollment r ON r.agent_id=a.agent_id
                    WHERE a.agent_id=?
                    """,
                    (ticket_hash, agent_id),
                ).fetchone()
                if existing:
                    ticket_present = existing["request_sha256"] is not None
                    credential = existing["agent_secret"]
                    ticket_valid = bool(
                        ticket_present
                        and isinstance(existing["request_sha256"], str)
                        and len(existing["request_sha256"]) == 64
                        and all(
                            character in "0123456789abcdef"
                            for character in existing["request_sha256"]
                        )
                        and type(existing["consumed_at"]) in {int, float}
                        and math.isfinite(existing["consumed_at"])
                        and 0 <= float(existing["consumed_at"]) <= now + 600.0
                        and type(existing["expires_at"]) in {int, float}
                        and math.isfinite(existing["expires_at"])
                        and float(existing["expires_at"]) >= 0
                        and type(existing["agent_epoch"]) is int
                        and 0 <= existing["agent_epoch"] <= 2**63 - 1
                        and type(existing["ticket_epoch"]) is int
                        and existing["agent_epoch"] == existing["ticket_epoch"]
                        and type(existing["enabled"]) is int
                        and existing["enabled"] == 1
                        and isinstance(credential, str)
                        and 32 <= len(credential) <= 256
                        and all(
                            character
                            in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
                            for character in credential
                        )
                        and existing["ticket_profile_fingerprint"]
                        == profile_fingerprint
                        and existing["ticket_agent_version"] == agent_version
                    )
                    if ticket_present and not ticket_valid:
                        self._quarantine_json(
                            "enrollment_tickets",
                            f"{agent_id}:{ticket_hash}",
                            "row_semantics",
                            dict(existing),
                            "consumed enrollment ticket semantics are invalid",
                        )
                        self._connection.commit()
                        raise PermissionError(
                            "consumed enrollment ticket requires operator review"
                        )
                    exact_retry = (
                        ticket_valid
                        and existing["request_sha256"] == request_sha256
                        and now <= float(existing["consumed_at"]) + 300.0
                    )
                    if exact_retry:
                        self._connection.commit()
                        return str(existing["agent_secret"]), False
                    reenrollment_present = (
                        existing["reenrollment_expires_at"] is not None
                    )
                    reenrollment_structurally_valid = bool(
                        reenrollment_present
                        and type(existing["reenrollment_authorized_at"])
                        in {int, float}
                        and math.isfinite(
                            existing["reenrollment_authorized_at"]
                        )
                        and type(existing["reenrollment_expires_at"])
                        in {int, float}
                        and math.isfinite(existing["reenrollment_expires_at"])
                        and 0
                        <= float(existing["reenrollment_expires_at"])
                        - float(existing["reenrollment_authorized_at"])
                        <= 300.0
                        and float(existing["reenrollment_authorized_at"]) >= 0
                        and type(existing["reenrollment_epoch"]) is int
                        and existing["reenrollment_epoch"]
                        == existing["agent_epoch"]
                    )
                    if reenrollment_present and not reenrollment_structurally_valid:
                        self._quarantine_json(
                            "agent_reenrollment",
                            agent_id,
                            "row_semantics",
                            dict(existing),
                            "reenrollment authority semantics are invalid",
                        )
                        self._connection.execute(
                            "DELETE FROM agent_reenrollment WHERE agent_id=?",
                            (agent_id,),
                        )
                        self._connection.commit()
                        raise PermissionError(
                            "agent reenrollment authority requires operator review"
                        )
                    if (
                        reenrollment_structurally_valid
                        and now > float(existing["reenrollment_expires_at"])
                    ):
                        self._connection.execute(
                            "DELETE FROM agent_reenrollment WHERE agent_id=?",
                            (agent_id,),
                        )
                        self._connection.execute(
                            """
                            INSERT INTO audit_log(
                              audit_id, actor, operation, subject,
                              detail_json, created_at
                            ) VALUES(?, 'controller',
                              'agent_reenrollment_expired', ?, '{}', ?)
                            """,
                            (str(uuid.uuid4()), agent_id, now),
                        )
                        self._connection.commit()
                        raise PermissionError(
                            "agent reenrollment authority has expired"
                        )
                    reenrollment = (
                        reenrollment_structurally_valid
                        and reenrollment_present
                        and float(existing["reenrollment_authorized_at"])
                        <= now
                        <= float(existing["reenrollment_expires_at"])
                        and
                        type(existing["enabled"]) is int
                        and existing["enabled"] == 0
                        and existing["profile_id"] == ""
                        and existing["latest_telemetry"] is None
                        and type(existing["agent_epoch"]) is int
                        and 0 <= existing["agent_epoch"] <= 2**63 - 1
                    )
                    if not reenrollment:
                        raise PermissionError(
                            "this agent identity is already enrolled; its credential cannot be rotated by enrollment"
                        )
                    self._connection.execute(
                        """
                        INSERT INTO enrollment_tickets(
                          ticket_hash, agent_id, profile_fingerprint,
                          agent_version, expires_at, consumed_at,
                          request_sha256, credential_epoch
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            ticket_hash,
                            agent_id,
                            profile_fingerprint,
                            agent_version,
                            float(existing["reenrollment_expires_at"]),
                            now,
                            request_sha256,
                            int(existing["agent_epoch"]),
                        ),
                    )
                    updated = self._connection.execute(
                        """
                        UPDATE agents SET enabled=1, hostname=?, platform=?, agent_secret=?,
                          profile_id=?, profile_fingerprint=?, agent_version=?,
                          last_seen=0
                        WHERE agent_id=? AND enabled=0 AND credential_epoch=?
                          AND profile_id='' AND latest_telemetry IS NULL
                        """,
                        (
                            hostname,
                            platform,
                            generated,
                            profile_id,
                            profile_fingerprint,
                            agent_version,
                            agent_id,
                            int(existing["agent_epoch"]),
                        ),
                    )
                    if updated.rowcount != 1:
                        raise RuntimeError("agent reenrollment authority changed")
                    self._connection.execute(
                        "DELETE FROM agent_reenrollment WHERE agent_id=?",
                        (agent_id,),
                    )
                    self._connection.commit()
                    return generated, True
                if now >= float(deadline):
                    raise PermissionError("the controller enrollment window is closed")
                count = int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM agents WHERE agent_id!='sentinel-relay-probes'"
                    ).fetchone()[0]
                )
                if count >= max(1, int(max_agents)):
                    raise PermissionError("the controller agent limit has been reached")
                self._connection.execute(
                    """
                    INSERT INTO enrollment_tickets(
                      ticket_hash, agent_id, profile_fingerprint, agent_version,
                      expires_at, consumed_at, request_sha256, credential_epoch
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, 0)
                    """,
                    (
                        ticket_hash, agent_id, profile_fingerprint, agent_version,
                        float(deadline), now, request_sha256,
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO agents(
                      agent_id, hostname, platform, registered_at, last_seen,
                      agent_secret, credential_epoch, profile_id,
                      profile_fingerprint, agent_version
                    ) VALUES(?, ?, ?, ?, 0, ?, 0, ?, ?, ?)
                    """,
                    (
                        agent_id, hostname, platform, now, generated,
                        profile_id, profile_fingerprint, agent_version,
                    ),
                )
                self._connection.commit()
            except Exception:
                self._connection.rollback()
                raise
        return generated, True

    def commit_bound_telemetry(
        self,
        agent_id: str,
        telemetry: dict[str, Any],
        *,
        expected_agent_secret: str,
        freshness_seconds: float,
        release_sha256: str = "",
        model_fingerprint: str = "",
        campaign_id: str = "",
        feature_schema_sha256: str = "",
    ) -> str:
        """Commit one current bound sample without letting stale spool mutate state."""
        encoded = canonical_json_dumps(telemetry, max_bytes=MAX_STORED_JSON_BYTES)
        payload_sha256 = hashlib.sha256(encoded.encode()).hexdigest()
        boot_id = str(telemetry["boot_id"])
        sequence = int(telemetry["sequence"])
        observed_at = float(telemetry["observed_at"])
        queued_at = float(telemetry["queued_at"])
        profile_id = str(telemetry["profile_id"])
        profile_fingerprint = str(telemetry["profile_fingerprint"])
        agent_version = str(telemetry["agent_version"])
        lineage_digests = (
            str(release_sha256).casefold(),
            str(model_fingerprint).casefold(),
            str(feature_schema_sha256).casefold(),
        )
        lineage_complete = (
            all(
                len(value) == 64
                and all(character in "0123456789abcdef" for character in value)
                for value in lineage_digests
            )
            and isinstance(campaign_id, str)
            and 1 <= len(campaign_id) <= 128
            and all(
                character.isalnum() or character in "_.:@+-"
                for character in campaign_id
            )
        )
        if any(lineage_digests) or campaign_id:
            if not lineage_complete:
                raise ValueError("telemetry learning lineage binding is incomplete")
        fresh_limit = max(15.0, float(freshness_seconds))
        if not math.isfinite(fresh_limit):
            raise ValueError("telemetry freshness policy is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                now = time.time()
                current = (
                    observed_at >= now - fresh_limit
                    and queued_at >= now - fresh_limit
                    and observed_at <= now + 600.0
                    and queued_at <= now + 600.0
                )
                row = self._connection.execute(
                    """
                    SELECT agent_secret, enabled, credential_epoch, profile_id,
                           profile_fingerprint, agent_version, last_sequence, boot_id,
                           last_observed_at, latest_payload_sha256
                    FROM agents WHERE agent_id=?
                    """,
                    (agent_id,),
                ).fetchone()
                if not row:
                    self._connection.rollback()
                    raise ValueError("agent credential epoch changed before telemetry commit")
                try:
                    if type(row["enabled"]) is not int or row["enabled"] not in {0, 1}:
                        raise ValueError("stored agent enabled flag is invalid")
                    if (
                        type(row["credential_epoch"]) is not int
                        or not 0 <= row["credential_epoch"] <= 2**63 - 1
                    ):
                        raise ValueError("stored agent credential epoch is invalid")
                    if (
                        type(row["last_sequence"]) is not int
                        or not -1 <= row["last_sequence"] <= 2**63 - 1
                    ):
                        raise ValueError("stored agent sequence is invalid")
                    if type(row["last_observed_at"]) not in {int, float} or not math.isfinite(
                        row["last_observed_at"]
                    ) or not 0 <= row["last_observed_at"] <= 2**63 - 1:
                        raise ValueError("stored agent observation time is invalid")
                    for name, limit in (
                        ("agent_secret", 256),
                        ("profile_id", 128),
                        ("profile_fingerprint", 64),
                        ("agent_version", 64),
                        ("boot_id", 256),
                        ("latest_payload_sha256", 64),
                    ):
                        value = row[name]
                        if not isinstance(value, str) or len(value) > limit:
                            raise ValueError(f"stored agent {name} is invalid")
                    stored_digest = str(row["latest_payload_sha256"])
                    if stored_digest and (
                        len(stored_digest) != 64
                        or any(character not in "0123456789abcdef" for character in stored_digest)
                    ):
                        raise ValueError("stored agent payload digest is invalid")
                except (TypeError, ValueError, OverflowError) as exc:
                    self._quarantine_json(
                        "agents", agent_id, "row_semantics", dict(row), str(exc)
                    )
                    self._revoke_corrupt_agent_locked(
                        agent_id, time.time(), "agent_binding_corruption"
                    )
                    self._connection.commit()
                    raise ValueError(
                        "stored agent binding requires operator review"
                    ) from exc
                if (
                    row["enabled"] != 1
                    or not hmac.compare_digest(
                        str(row["agent_secret"]), str(expected_agent_secret)
                    )
                ):
                    self._connection.rollback()
                    raise ValueError("agent credential epoch changed before telemetry commit")
                if str(row["profile_id"]) not in {"", profile_id}:
                    self._connection.rollback()
                    raise ValueError("telemetry profile changed within a credential epoch")
                if str(row["profile_fingerprint"]) not in {"", profile_fingerprint} or str(
                    row["agent_version"]
                ) not in {"", agent_version}:
                    self._connection.rollback()
                    raise ValueError("telemetry release binding changed within a credential epoch")

                # Historical spool is evidence only.  It must not move a global
                # sequence high-water mark, retire a boot, refresh liveness, or
                # establish a release binding.
                if not current:
                    exact_pending = self._connection.execute(
                        """
                        SELECT 1 FROM telemetry_processing
                        WHERE agent_id=? AND credential_epoch=?
                          AND profile_fingerprint=? AND boot_id=?
                          AND sequence=? AND payload_sha256=?
                        """,
                        (
                            agent_id,
                            int(row["credential_epoch"]),
                            profile_fingerprint,
                            boot_id,
                            sequence,
                            payload_sha256,
                        ),
                    ).fetchone()
                    if exact_pending and (
                        int(row["last_sequence"]),
                        str(row["boot_id"]),
                        str(row["latest_payload_sha256"]),
                    ) == (sequence, boot_id, payload_sha256):
                        self._connection.rollback()
                        return "pending_retry"
                    self._connection.rollback()
                    return "historical"

                last_sequence = int(row["last_sequence"])
                if sequence < last_sequence:
                    self._connection.rollback()
                    raise ValueError(
                        "telemetry sequence moved backwards within the credential epoch"
                    )
                if sequence == last_sequence:
                    if hmac.compare_digest(
                        str(row["latest_payload_sha256"]), payload_sha256
                    ):
                        pending_retry = self._connection.execute(
                            """
                            SELECT 1 FROM telemetry_processing
                            WHERE agent_id=? AND credential_epoch=?
                              AND profile_fingerprint=? AND boot_id=?
                              AND sequence=? AND payload_sha256=?
                            """,
                            (
                                agent_id,
                                int(row["credential_epoch"]),
                                profile_fingerprint,
                                boot_id,
                                sequence,
                                payload_sha256,
                            ),
                        ).fetchone()
                        self._connection.rollback()
                        return "pending_retry" if pending_retry else "exact_retry"
                    self._connection.rollback()
                    raise ValueError(
                        "telemetry sequence was reused with a different payload"
                    )
                if observed_at < float(row["last_observed_at"]):
                    self._connection.rollback()
                    raise ValueError("telemetry observation time moved backwards")

                epoch = int(row["credential_epoch"])
                if self._connection.execute(
                    "SELECT 1 FROM telemetry_processing WHERE agent_id=? LIMIT 1",
                    (agent_id,),
                ).fetchone():
                    self._connection.rollback()
                    return "processing_backlog"
                known_boot = self._connection.execute(
                    """
                    SELECT max_sequence, max_observed_at, last_payload_sha256, state
                    FROM telemetry_boots
                    WHERE agent_id=? AND credential_epoch=?
                      AND profile_fingerprint=? AND boot_id=?
                    """,
                    (agent_id, epoch, profile_fingerprint, boot_id),
                ).fetchone()
                current_boot = str(row["boot_id"])
                if current_boot:
                    current_history = self._connection.execute(
                        """
                        SELECT state, max_sequence, max_observed_at,
                               last_payload_sha256
                        FROM telemetry_boots
                        WHERE agent_id=? AND credential_epoch=?
                          AND profile_fingerprint=? AND boot_id=?
                        """,
                        (agent_id, epoch, profile_fingerprint, current_boot),
                    ).fetchone()
                    if (
                        not current_history
                        or current_history["state"] != "active"
                        or type(current_history["max_sequence"]) is not int
                        or current_history["max_sequence"]
                        != row["last_sequence"]
                        or type(current_history["max_observed_at"])
                        not in {int, float}
                        or not math.isfinite(
                            current_history["max_observed_at"]
                        )
                        or float(current_history["max_observed_at"])
                        != float(row["last_observed_at"])
                        or not isinstance(
                            current_history["last_payload_sha256"], str
                        )
                        or current_history["last_payload_sha256"]
                        != row["latest_payload_sha256"]
                    ):
                        self._quarantine_json(
                            "telemetry_boots",
                            f"{agent_id}:{epoch}:{profile_fingerprint}:{current_boot}",
                            "missing_current_boot",
                            dict(row),
                            "current agent boot has no exact active history row",
                        )
                        self._revoke_corrupt_agent_locked(
                            agent_id, time.time(), "telemetry_boot_history_missing"
                        )
                        self._connection.commit()
                        raise ValueError(
                            "stored telemetry boot history requires operator review"
                        )
                if known_boot:
                    try:
                        if known_boot["state"] not in {"active", "retired"}:
                            raise ValueError("stored telemetry boot state is invalid")
                        if (
                            type(known_boot["max_sequence"]) is not int
                            or not 0 <= known_boot["max_sequence"] <= 2**63 - 1
                        ):
                            raise ValueError("stored telemetry boot sequence is invalid")
                        if type(known_boot["max_observed_at"]) not in {
                            int,
                            float,
                        } or not math.isfinite(known_boot["max_observed_at"]):
                            raise ValueError("stored telemetry boot time is invalid")
                        known_digest = known_boot["last_payload_sha256"]
                        if (
                            not isinstance(known_digest, str)
                            or len(known_digest) != 64
                            or any(
                                character not in "0123456789abcdef"
                                for character in known_digest
                            )
                        ):
                            raise ValueError(
                                "stored telemetry boot digest is invalid"
                            )
                        if known_boot["state"] == "active" and (
                            boot_id != current_boot
                            or (
                                known_boot["max_sequence"],
                                float(known_boot["max_observed_at"]),
                                known_digest,
                            )
                            != (
                                int(row["last_sequence"]),
                                float(row["last_observed_at"]),
                                str(row["latest_payload_sha256"]),
                            )
                        ):
                            raise ValueError(
                                "active telemetry boot does not match the agent high-water mark"
                            )
                    except (TypeError, ValueError, OverflowError) as exc:
                        self._quarantine_json(
                            "telemetry_boots",
                            f"{agent_id}:{epoch}:{profile_fingerprint}:{boot_id}",
                            "row_semantics",
                            dict(known_boot),
                            str(exc),
                        )
                        self._revoke_corrupt_agent_locked(
                            agent_id, time.time(), "telemetry_boot_history_corrupt"
                        )
                        self._connection.commit()
                        raise ValueError(
                            "stored telemetry boot history requires operator review"
                        ) from exc
                    if known_boot["state"] == "retired":
                        self._connection.rollback()
                        raise ValueError(
                            "telemetry attempted to return to a retired boot identifier"
                        )
                    if current_boot and current_boot != boot_id:
                        self._connection.rollback()
                        raise ValueError(
                            "telemetry boot history contains multiple active identifiers"
                        )
                    if sequence <= int(known_boot["max_sequence"]):
                        self._connection.rollback()
                        raise ValueError("telemetry boot sequence was replayed")
                else:
                    boot_count = int(
                        self._connection.execute(
                            """
                            SELECT COUNT(*) FROM telemetry_boots
                            WHERE agent_id=? AND credential_epoch=?
                              AND profile_fingerprint=?
                            """,
                            (agent_id, epoch, profile_fingerprint),
                        ).fetchone()[0]
                    )
                    if boot_count >= MAX_BOOT_EPOCHS_PER_AGENT:
                        self._connection.rollback()
                        raise ValueError(
                            "telemetry boot history is full and requires review"
                        )
                    if current_boot and current_boot != boot_id:
                        retired = self._connection.execute(
                            """
                            UPDATE telemetry_boots SET state='retired', last_seen_at=?
                            WHERE agent_id=? AND credential_epoch=?
                              AND profile_fingerprint=? AND boot_id=? AND state='active'
                            """,
                            (
                                now,
                                agent_id,
                                epoch,
                                profile_fingerprint,
                                current_boot,
                            ),
                        )
                        if retired.rowcount != 1:
                            raise ValueError(
                                "current telemetry boot could not be retired atomically"
                            )
                    self._connection.execute(
                        """
                        INSERT INTO telemetry_boots(
                          agent_id, credential_epoch, profile_fingerprint, boot_id,
                          max_sequence, max_observed_at, last_payload_sha256, state,
                          first_seen_at, last_seen_at
                        ) VALUES(?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                        """,
                        (
                            agent_id,
                            epoch,
                            profile_fingerprint,
                            boot_id,
                            sequence,
                            observed_at,
                            payload_sha256,
                            now,
                            now,
                        ),
                    )
                if known_boot:
                    cursor = self._connection.execute(
                        """
                        UPDATE telemetry_boots
                        SET max_sequence=?, max_observed_at=?,
                            last_payload_sha256=?, last_seen_at=?
                        WHERE agent_id=? AND credential_epoch=?
                          AND profile_fingerprint=? AND boot_id=? AND state='active'
                        """,
                        (
                            sequence,
                            observed_at,
                            payload_sha256,
                            now,
                            agent_id,
                            epoch,
                            profile_fingerprint,
                            boot_id,
                        ),
                    )
                    if cursor.rowcount != 1:
                        raise ValueError("telemetry boot state changed concurrently")
                cursor = self._connection.execute(
                    """
                    UPDATE agents SET hostname=?, platform=?, last_seen=?,
                      latest_telemetry=?, last_sequence=?, boot_id=?,
                      profile_id=?, profile_fingerprint=?, agent_version=?,
                      last_observed_at=?, latest_payload_sha256=?
                    WHERE agent_id=? AND enabled=1 AND credential_epoch=?
                    """,
                    (
                        str(telemetry.get("hostname", agent_id)),
                        str(telemetry.get("platform", "unknown")),
                        now,
                        encoded,
                        sequence,
                        boot_id,
                        profile_id,
                        profile_fingerprint,
                        agent_version,
                        observed_at,
                        payload_sha256,
                        agent_id,
                        epoch,
                    ),
                )
                if cursor.rowcount != 1:
                    raise ValueError(
                        "agent credential epoch changed before telemetry commit"
                    )
                self._connection.execute(
                    """
                    INSERT INTO telemetry_observations(
                      observation_id, agent_id, telemetry_sha256, telemetry_json,
                      observed_at, queued_at, accepted_at, boot_id, sequence,
                      credential_epoch, profile_id, profile_fingerprint,
                      agent_version, release_sha256, model_fingerprint,
                      campaign_id, feature_schema_sha256, admission_status
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        payload_sha256,
                        agent_id,
                        payload_sha256,
                        encoded,
                        observed_at,
                        queued_at,
                        now,
                        boot_id,
                        sequence,
                        epoch,
                        profile_id,
                        profile_fingerprint,
                        agent_version,
                        lineage_digests[0],
                        lineage_digests[1],
                        str(campaign_id),
                        lineage_digests[2],
                        "eligible" if lineage_complete else "quarantined",
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO telemetry_processing(
                      agent_id, credential_epoch, profile_fingerprint, boot_id,
                      sequence, payload_sha256, telemetry_json, created_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        agent_id,
                        epoch,
                        profile_fingerprint,
                        boot_id,
                        sequence,
                        payload_sha256,
                        encoded,
                        now,
                    ),
                )
                self._connection.commit()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise
        return "current"

    def pending_telemetry_processing(
        self, *, agent_id: str | None = None, limit: int = 32
    ) -> list[dict[str, Any]]:
        selection_now = time.time()
        retry_cutoff = selection_now - 300.0
        clauses = (
            "WHERE (attempts<3 OR last_attempt_at<=? "
            "OR last_attempt_at>? OR typeof(attempts)!='integer' "
            "OR attempts<0 OR attempts>2147483647 "
            "OR typeof(last_attempt_at) NOT IN ('integer','real'))"
        )
        values: list[Any] = [retry_cutoff, selection_now + 600.0]
        if agent_id is not None:
            clauses += " AND agent_id=?"
            values.append(agent_id)
        output_limit = max(1, min(int(limit), 128))
        values.append(max(128, min(output_limit * 4, 512)))
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM telemetry_processing " + clauses
                + " ORDER BY created_at, agent_id LIMIT ?",
                values,
            ).fetchall()
        pending: list[dict[str, Any]] = []
        for row in rows:
            authority_current = True
            row_key = (
                f"{row['agent_id']}:{row['credential_epoch']}:"
                f"{row['boot_id']}:{row['sequence']}"
            )
            telemetry = self._decode_stored_json(
                row["telemetry_json"],
                table_name="telemetry_processing",
                row_key=row_key,
                column_name="telemetry_json",
                expected_type=dict,
            )
            try:
                if telemetry is None:
                    raise ValueError("processing telemetry failed strict JSON decoding")
                from .validation import validate_telemetry

                if (
                    type(row["created_at"]) not in {int, float}
                    or not math.isfinite(row["created_at"])
                    or not 0 <= float(row["created_at"]) <= 2**63 - 1
                ):
                    raise ValueError("processing receipt time is invalid")
                normalized = validate_telemetry(
                    telemetry,
                    expected_agent_id=str(row["agent_id"]),
                    # This payload was freshness-validated before the outbox
                    # row committed.  Revalidate against that immutable
                    # receipt time so a long outage is not mislabeled as DB
                    # corruption.
                    now=float(row["created_at"]),
                )
                encoded = canonical_json_dumps(
                    normalized, max_bytes=MAX_STORED_JSON_BYTES
                )
                if not hmac_compare_json(encoded, str(row["telemetry_json"])):
                    raise ValueError("processing telemetry is not canonically normalized")
                digest = hashlib.sha256(encoded.encode()).hexdigest()
                if (
                    type(row["credential_epoch"]) is not int
                    or type(row["sequence"]) is not int
                    or type(row["attempts"]) is not int
                    or not 0 <= row["attempts"] <= 2**31 - 1
                    or type(row["last_attempt_at"]) not in {int, float}
                    or not math.isfinite(row["last_attempt_at"])
                    or not 0 <= float(row["last_attempt_at"])
                    <= time.time() + 600.0
                    or (
                        normalized["profile_fingerprint"],
                        normalized["boot_id"],
                        normalized["sequence"],
                        digest,
                    )
                    != (
                        str(row["profile_fingerprint"]),
                        str(row["boot_id"]),
                        int(row["sequence"]),
                        str(row["payload_sha256"]),
                    )
                ):
                    raise ValueError("processing telemetry binding is inconsistent")
                with self._lock:
                    exact_checkpoint = self._connection.execute(
                        """
                        SELECT 1 FROM telemetry_processing
                        WHERE agent_id=? AND credential_epoch=?
                          AND profile_fingerprint=? AND boot_id=?
                          AND sequence=? AND payload_sha256=?
                        """,
                        (
                            row["agent_id"],
                            row["credential_epoch"],
                            row["profile_fingerprint"],
                            row["boot_id"],
                            row["sequence"],
                            row["payload_sha256"],
                        ),
                    ).fetchone()
                    if not exact_checkpoint:
                        continue
                    agent = self._connection.execute(
                        """
                        SELECT enabled, credential_epoch, profile_id,
                               profile_fingerprint, agent_version, boot_id,
                               last_sequence, last_observed_at,
                               latest_payload_sha256, latest_telemetry
                        FROM agents WHERE agent_id=?
                        """,
                        (row["agent_id"],),
                    ).fetchone()
                    if not agent or (
                        agent["enabled"],
                        agent["credential_epoch"],
                        agent["profile_fingerprint"],
                    ) != (
                        1,
                        row["credential_epoch"],
                        row["profile_fingerprint"],
                    ):
                        authority_current = False
                        raise ValueError(
                            "processing checkpoint authority is no longer current"
                        )
                    if (
                        str(agent["profile_id"]),
                        str(agent["agent_version"]),
                        str(agent["boot_id"]),
                        agent["last_sequence"],
                        agent["last_observed_at"],
                        str(agent["latest_payload_sha256"]),
                        str(agent["latest_telemetry"]),
                    ) != (
                        str(normalized["profile_id"]),
                        str(normalized["agent_version"]),
                        str(row["boot_id"]),
                        row["sequence"],
                        normalized["observed_at"],
                        str(row["payload_sha256"]),
                        encoded,
                    ):
                        raise ValueError(
                            "processing checkpoint does not match the agent high-water mark"
                        )
                    boot = self._connection.execute(
                        """
                        SELECT state, max_sequence, max_observed_at,
                               last_payload_sha256
                        FROM telemetry_boots
                        WHERE agent_id=? AND credential_epoch=?
                          AND profile_fingerprint=? AND boot_id=?
                        """,
                        (
                            row["agent_id"],
                            row["credential_epoch"],
                            row["profile_fingerprint"],
                            row["boot_id"],
                        ),
                    ).fetchone()
                    if not boot or (
                        str(boot["state"]),
                        boot["max_sequence"],
                        boot["max_observed_at"],
                        str(boot["last_payload_sha256"]),
                    ) != (
                        "active",
                        row["sequence"],
                        normalized["observed_at"],
                        str(row["payload_sha256"]),
                    ):
                        raise ValueError(
                            "processing checkpoint boot history is inconsistent"
                        )
            except (TypeError, ValueError, OverflowError) as exc:
                self._quarantine_json(
                    "telemetry_processing",
                    row_key,
                    "row_semantics",
                    dict(row),
                    str(exc),
                )
                if authority_current:
                    disabled = self.set_agent_enabled(
                        str(row["agent_id"]), False
                    )
                else:
                    disabled = False
                if not disabled:
                    with self._lock:
                        self._connection.execute(
                            """
                            DELETE FROM telemetry_processing
                            WHERE agent_id=? AND credential_epoch=?
                              AND profile_fingerprint=? AND boot_id=?
                              AND sequence=? AND payload_sha256=?
                            """,
                            (
                                str(row["agent_id"]),
                                row["credential_epoch"],
                                row["profile_fingerprint"],
                                row["boot_id"],
                                row["sequence"],
                                row["payload_sha256"],
                            ),
                        )
                        self._connection.commit()
                continue
            item = dict(row)
            item["telemetry"] = normalized
            pending.append(item)
            if len(pending) >= output_limit:
                break
        return pending

    def record_telemetry_processing_failure(
        self, item: dict[str, Any], reason: str
    ) -> None:
        agent_id = str(item.get("agent_id", ""))
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    """
                    SELECT attempts FROM telemetry_processing
                    WHERE agent_id=? AND credential_epoch=?
                      AND profile_fingerprint=? AND boot_id=?
                      AND sequence=? AND payload_sha256=?
                    """,
                    (
                        agent_id,
                        item.get("credential_epoch"),
                        item.get("profile_fingerprint"),
                        item.get("boot_id"),
                        item.get("sequence"),
                        item.get("payload_sha256"),
                    ),
                ).fetchone()
                if not row or type(row["attempts"]) is not int:
                    self._connection.rollback()
                    return
                attempts = min(int(row["attempts"]) + 1, 2**31 - 1)
                attempted_at = time.time()
                if attempts < 3:
                    self._connection.execute(
                        """
                        UPDATE telemetry_processing
                        SET attempts=?, last_attempt_at=?
                        WHERE agent_id=? AND credential_epoch=?
                          AND profile_fingerprint=? AND boot_id=?
                          AND sequence=? AND payload_sha256=?
                        """,
                        (
                            attempts,
                            attempted_at,
                            agent_id,
                            item.get("credential_epoch"),
                            item.get("profile_fingerprint"),
                            item.get("boot_id"),
                            item.get("sequence"),
                            item.get("payload_sha256"),
                        ),
                    )
                    self._connection.commit()
                    return
                now = attempted_at
                self._connection.execute(
                    """
                    UPDATE telemetry_processing
                    SET attempts=?, last_attempt_at=?
                    WHERE agent_id=? AND credential_epoch=?
                      AND profile_fingerprint=? AND boot_id=?
                      AND sequence=? AND payload_sha256=?
                    """,
                    (
                        attempts,
                        attempted_at,
                        agent_id,
                        item.get("credential_epoch"),
                        item.get("profile_fingerprint"),
                        item.get("boot_id"),
                        item.get("sequence"),
                        item.get("payload_sha256"),
                    ),
                )
                if attempts != 3 and attempts & (attempts - 1):
                    self._connection.commit()
                    return
                self._connection.execute(
                    """
                    INSERT INTO audit_log(
                      audit_id, actor, operation, subject,
                      detail_json, created_at
                    ) VALUES(?, 'controller',
                      'telemetry_derivative_held', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        agent_id,
                        canonical_json_dumps(
                            {
                                "attempts": attempts,
                                "payload_sha256": str(
                                    item.get("payload_sha256", "")
                                )[:64],
                                "reason": str(reason)[:256],
                            }
                        ),
                        now,
                    ),
                )
                self._connection.commit()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def mark_telemetry_processed(
        self,
        agent_id: str,
        credential_epoch: int,
        profile_fingerprint: str,
        boot_id: str,
        sequence: int,
        payload_sha256: str,
    ) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """
                DELETE FROM telemetry_processing
                WHERE agent_id=? AND credential_epoch=?
                  AND profile_fingerprint=? AND boot_id=?
                  AND sequence=? AND payload_sha256=?
                """,
                (
                    agent_id,
                    credential_epoch,
                    profile_fingerprint,
                    boot_id,
                    sequence,
                    payload_sha256,
                ),
            )
            self._connection.commit()
        return cursor.rowcount == 1


    def register_agent(
        self, agent_id: str, hostname: str, platform: str, *, touch_last_seen: bool = True
    ) -> None:
        now = time.time()
        inserted_last_seen = now if touch_last_seen else 0.0
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO agents(agent_id, hostname, platform, registered_at, last_seen)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                  hostname=excluded.hostname,
                  platform=excluded.platform,
                  last_seen=CASE WHEN ? THEN excluded.last_seen ELSE agents.last_seen END
                """,
                (
                    agent_id,
                    hostname,
                    platform,
                    now,
                    inserted_last_seen,
                    int(touch_last_seen),
                ),
            )
            self._connection.commit()

    def agent_count(self) -> int:
        with self._lock:
            row = self._connection.execute("SELECT COUNT(*) AS count FROM agents").fetchone()
        return int(row["count"])

    def agent_enabled(self, agent_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT enabled FROM agents WHERE agent_id=?", (agent_id,)
            ).fetchone()
        return bool(
            row
            and type(row["enabled"]) is int
            and row["enabled"] == 1
        )

    def agent_exists(self, agent_id: str) -> bool:
        with self._lock:
            row = self._connection.execute(
                "SELECT 1 FROM agents WHERE agent_id=?", (agent_id,)
            ).fetchone()
        return row is not None

    def _http_request_replay_state_locked(self) -> dict[str, float | int]:
        row = self._connection.execute(
            "SELECT state_value FROM controller_state WHERE state_key=?",
            (HTTP_REQUEST_REPLAY_STATE_KEY,),
        ).fetchone()
        if row is None:
            raise ValueError("persistent HTTP replay protection is not initialized")
        try:
            decoded = strict_json_loads(str(row["state_value"]), max_bytes=4096)
        except ValueError as exc:
            raise ValueError("persistent HTTP replay state is invalid") from exc
        if (
            not isinstance(decoded, dict)
            or set(decoded)
            != {
                "schema",
                "max_clock_skew",
                "migration_floor",
                "clock_high_water",
            }
            or type(decoded.get("schema")) is not int
            or decoded.get("schema") != HTTP_REQUEST_REPLAY_SCHEMA
        ):
            raise ValueError("persistent HTTP replay state is invalid")
        for field in ("max_clock_skew", "migration_floor", "clock_high_water"):
            value = decoded.get(field)
            if (
                type(value) not in {int, float}
                or not math.isfinite(float(value))
                or not 0 <= float(value) <= 2**63 - 1
            ):
                raise ValueError("persistent HTTP replay state is invalid")
        if float(decoded["max_clock_skew"]) < 1.0:
            raise ValueError("persistent HTTP replay state is invalid")
        return {
            "schema": HTTP_REQUEST_REPLAY_SCHEMA,
            "max_clock_skew": float(decoded["max_clock_skew"]),
            "migration_floor": float(decoded["migration_floor"]),
            "clock_high_water": float(decoded["clock_high_water"]),
        }

    def _validate_http_request_replay_schema_locked(self) -> None:
        expected = [
            ("agent_id", "TEXT", 1, 1),
            ("marker_sha256", "TEXT", 1, 2),
            ("auth_kind", "TEXT", 1, 0),
            ("credential_epoch", "INTEGER", 1, 0),
            ("request_timestamp", "REAL", 1, 0),
            ("accepted_at", "REAL", 1, 0),
            ("expires_at", "REAL", 1, 0),
        ]
        observed = [
            (
                str(row["name"]),
                str(row["type"]).upper(),
                int(row["notnull"]),
                int(row["pk"]),
            )
            for row in self._connection.execute(
                "PRAGMA table_info(http_request_replay)"
            ).fetchall()
        ]
        if observed != expected:
            raise ValueError("persistent HTTP replay table schema is invalid")

    def initialize_http_request_replay(
        self,
        max_clock_skew: float,
        *,
        now: float | None = None,
    ) -> None:
        """Initialize the durable request barrier without opening an upgrade gap.

        A database first opened by an older controller can contain accepted
        requests whose in-memory markers were lost.  Such a database receives
        a one-time timestamp floor one skew window in the future.  Agents can
        retry with fresh signatures after that bounded migration fence.
        """
        if isinstance(max_clock_skew, bool):
            raise ValueError("HTTP replay clock skew must be finite and positive")
        skew = float(max_clock_skew)
        current = float(time.time() if now is None else now)
        if (
            not math.isfinite(skew)
            or skew < 1.0
            or not math.isfinite(current)
            or not 0 <= current <= 2**63 - 1
            or current + skew > 2**63 - 1
        ):
            raise ValueError("HTTP replay clock state is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._validate_http_request_replay_schema_locked()
                row = self._connection.execute(
                    "SELECT state_value FROM controller_state WHERE state_key=?",
                    (HTTP_REQUEST_REPLAY_STATE_KEY,),
                ).fetchone()
                if row is None:
                    state = {
                        "schema": HTTP_REQUEST_REPLAY_SCHEMA,
                        "max_clock_skew": skew,
                        "migration_floor": (
                            current + skew if self.database_preexisting else 0.0
                        ),
                        "clock_high_water": current,
                    }
                    self._connection.execute(
                        """
                        INSERT INTO controller_state(
                          state_key, state_value, updated_at
                        ) VALUES(?, ?, ?)
                        """,
                        (
                            HTTP_REQUEST_REPLAY_STATE_KEY,
                            canonical_json_dumps(state),
                            current,
                        ),
                    )
                else:
                    state = self._http_request_replay_state_locked()
                    if not math.isclose(
                        float(state["max_clock_skew"]),
                        skew,
                        rel_tol=0.0,
                        abs_tol=0.0,
                    ):
                        raise ValueError(
                            "persistent HTTP replay clock-skew binding changed"
                        )
                self._connection.commit()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def _operator_auth_state_locked(self) -> dict[str, Any]:
        row = self._connection.execute(
            "SELECT state_value FROM controller_state WHERE state_key=?",
            (OPERATOR_AUTH_STATE_KEY,),
        ).fetchone()
        if row is None:
            raise ValueError("persistent operator authentication is not initialized")
        try:
            decoded = strict_json_loads(str(row["state_value"]), max_bytes=4096)
        except ValueError as exc:
            raise ValueError("persistent operator authentication state is invalid") from exc
        expected_fields = {
            "schema",
            "principal_id",
            "key_fingerprint",
            "credential_epoch",
            "max_clock_skew",
            "migration_floor",
            "clock_high_water",
        }
        if (
            not isinstance(decoded, dict)
            or set(decoded) != expected_fields
            or type(decoded.get("schema")) is not int
            or decoded.get("schema") != OPERATOR_AUTH_STATE_SCHEMA
            or type(decoded.get("credential_epoch")) is not int
            or not 1 <= int(decoded["credential_epoch"]) <= 2**63 - 1
        ):
            raise ValueError("persistent operator authentication state is invalid")
        from .operator_auth import validate_operator_principal

        try:
            principal = validate_operator_principal(decoded["principal_id"])
        except ValueError as exc:
            raise ValueError("persistent operator authentication state is invalid") from exc
        fingerprint = decoded.get("key_fingerprint")
        if (
            not isinstance(fingerprint, str)
            or len(fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in fingerprint)
        ):
            raise ValueError("persistent operator authentication state is invalid")
        for field in ("max_clock_skew", "migration_floor", "clock_high_water"):
            value = decoded.get(field)
            if (
                type(value) not in {int, float}
                or not math.isfinite(float(value))
                or not 0 <= float(value) <= 2**63 - 1
            ):
                raise ValueError("persistent operator authentication state is invalid")
        if float(decoded["max_clock_skew"]) < 1.0:
            raise ValueError("persistent operator authentication state is invalid")
        return {
            "schema": OPERATOR_AUTH_STATE_SCHEMA,
            "principal_id": principal,
            "key_fingerprint": fingerprint,
            "credential_epoch": int(decoded["credential_epoch"]),
            "max_clock_skew": float(decoded["max_clock_skew"]),
            "migration_floor": float(decoded["migration_floor"]),
            "clock_high_water": float(decoded["clock_high_water"]),
        }

    def _validate_operator_request_replay_schema_locked(self) -> None:
        expected = [
            ("principal_id", "TEXT", 1, 1),
            ("credential_epoch", "INTEGER", 1, 2),
            ("request_id", "TEXT", 1, 3),
            ("marker_sha256", "TEXT", 1, 0),
            ("request_timestamp", "INTEGER", 1, 0),
            ("accepted_at", "REAL", 1, 0),
            ("expires_at", "REAL", 1, 0),
        ]
        observed = [
            (
                str(row["name"]),
                str(row["type"]).upper(),
                int(row["notnull"]),
                int(row["pk"]),
            )
            for row in self._connection.execute(
                "PRAGMA table_info(operator_request_replay)"
            ).fetchall()
        ]
        if observed != expected:
            raise ValueError("persistent operator replay table schema is invalid")

    def initialize_operator_auth(
        self,
        *,
        principal_id: str,
        key_fingerprint: str,
        credential_epoch: int,
        max_clock_skew: float,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Bind one operator signing authority and rotate it only by epoch CAS.

        A pre-existing database without this state came from a bearer-auth
        release.  It must start at epoch two or later so an operator cannot
        accidentally reuse the previously browser-exposed credential.
        """
        from .operator_auth import validate_operator_principal

        principal = validate_operator_principal(principal_id)
        if (
            not isinstance(key_fingerprint, str)
            or len(key_fingerprint) != 64
            or any(
                character not in "0123456789abcdef"
                for character in key_fingerprint
            )
            or type(credential_epoch) is not int
            or not 1 <= credential_epoch <= 2**63 - 1
            or isinstance(max_clock_skew, bool)
            or isinstance(now, bool)
        ):
            raise ValueError("operator authority binding is invalid")
        current = float(time.time() if now is None else now)
        skew = float(max_clock_skew)
        if (
            not math.isfinite(current)
            or not 0 <= current <= 2**63 - 1
            or not math.isfinite(skew)
            or skew < 1.0
            or current + skew > 2**63 - 1
        ):
            raise ValueError("operator authentication clock state is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                self._validate_operator_request_replay_schema_locked()
                row = self._connection.execute(
                    "SELECT state_value FROM controller_state WHERE state_key=?",
                    (OPERATOR_AUTH_STATE_KEY,),
                ).fetchone()
                if row is None:
                    if self.database_preexisting and credential_epoch < 2:
                        raise ValueError(
                            "an upgraded database requires a fresh operator key "
                            "and --operator-credential-epoch 2 or later"
                        )
                    state = {
                        "schema": OPERATOR_AUTH_STATE_SCHEMA,
                        "principal_id": principal,
                        "key_fingerprint": key_fingerprint,
                        "credential_epoch": credential_epoch,
                        "max_clock_skew": skew,
                        "migration_floor": current if self.database_preexisting else 0.0,
                        "clock_high_water": current,
                    }
                    self._connection.execute(
                        """
                        INSERT INTO controller_state(state_key, state_value, updated_at)
                        VALUES(?, ?, ?)
                        """,
                        (
                            OPERATOR_AUTH_STATE_KEY,
                            canonical_json_dumps(state),
                            current,
                        ),
                    )
                else:
                    state = self._operator_auth_state_locked()
                    if not math.isclose(
                        float(state["max_clock_skew"]),
                        skew,
                        rel_tol=0.0,
                        abs_tol=0.0,
                    ):
                        raise ValueError(
                            "persistent operator authentication clock-skew binding changed"
                        )
                    same_principal = hmac.compare_digest(
                        str(state["principal_id"]), principal
                    )
                    same_key = hmac.compare_digest(
                        str(state["key_fingerprint"]), key_fingerprint
                    )
                    same_epoch = int(state["credential_epoch"]) == credential_epoch
                    effective_now = max(current, float(state["clock_high_water"]))
                    if same_principal and same_key and same_epoch:
                        state["clock_high_water"] = effective_now
                    else:
                        if (
                            same_key
                            or credential_epoch != int(state["credential_epoch"]) + 1
                        ):
                            raise ValueError(
                                "operator key rotation requires a new key and the next credential epoch"
                            )
                        state = {
                            "schema": OPERATOR_AUTH_STATE_SCHEMA,
                            "principal_id": principal,
                            "key_fingerprint": key_fingerprint,
                            "credential_epoch": credential_epoch,
                            "max_clock_skew": skew,
                            "migration_floor": effective_now,
                            "clock_high_water": effective_now,
                        }
                    self._connection.execute(
                        """
                        UPDATE controller_state SET state_value=?, updated_at=?
                        WHERE state_key=?
                        """,
                        (
                            canonical_json_dumps(state),
                            effective_now,
                            OPERATOR_AUTH_STATE_KEY,
                        ),
                    )
                self._connection.commit()
                return {
                    "principal_id": str(state["principal_id"]),
                    "credential_epoch": int(state["credential_epoch"]),
                    "key_fingerprint": str(state["key_fingerprint"]),
                    "request_not_before": (
                        math.floor(float(state["migration_floor"])) + 1
                    ),
                }
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def operator_auth_info(self) -> dict[str, Any]:
        """Return public, non-secret metadata needed to sign an operator request."""
        with self._lock:
            state = self._operator_auth_state_locked()
        return {
            "principal_id": str(state["principal_id"]),
            "credential_epoch": int(state["credential_epoch"]),
            "request_not_before": (
                math.floor(float(state["migration_floor"])) + 1
            ),
        }

    def admit_operator_request(
        self,
        *,
        principal_id: str,
        credential_epoch: int,
        request_id: str,
        marker_sha256: str,
        request_timestamp: int,
        expected_key_fingerprint: str,
        method: str,
        target: str,
        max_entries: int,
        max_clock_skew: float,
        now: float | None = None,
    ) -> str:
        """Persist authenticated operator authority before endpoint effects."""
        from .operator_auth import validate_operator_principal

        principal = validate_operator_principal(principal_id)
        try:
            target_bytes = target.encode("ascii", "strict")
        except (AttributeError, UnicodeEncodeError) as exc:
            raise ValueError("operator replay admission arguments are invalid") from exc
        if (
            type(credential_epoch) is not int
            or not 1 <= credential_epoch <= 2**63 - 1
            or not isinstance(request_id, str)
            or len(request_id) != 32
            or any(character not in "0123456789abcdef" for character in request_id)
            or not isinstance(marker_sha256, str)
            or len(marker_sha256) != 64
            or any(character not in "0123456789abcdef" for character in marker_sha256)
            or not isinstance(expected_key_fingerprint, str)
            or len(expected_key_fingerprint) != 64
            or any(
                character not in "0123456789abcdef"
                for character in expected_key_fingerprint
            )
            or type(request_timestamp) is not int
            or not 0 <= request_timestamp <= 2**63 - 1
            or not isinstance(method, str)
            or not 1 <= len(method) <= 16
            or any(character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" for character in method)
            or not isinstance(target, str)
            or not target.startswith("/")
            or target.startswith("//")
            or "#" in target
            or "\\" in target
            or any(ord(character) < 0x21 or ord(character) == 0x7F for character in target)
            or not 1 <= len(target_bytes) <= 2048
            or type(max_entries) is not int
            or max_entries < 1
            or isinstance(max_clock_skew, bool)
            or isinstance(now, bool)
        ):
            raise ValueError("operator replay admission arguments are invalid")
        current = float(time.time() if now is None else now)
        skew = float(max_clock_skew)
        if (
            not math.isfinite(current)
            or not 0 <= current <= 2**63 - 1
            or not math.isfinite(skew)
            or skew < 1.0
            or request_timestamp + skew > 2**63 - 1
        ):
            raise ValueError("operator authentication clock state is invalid")
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._operator_auth_state_locked()
                if not math.isclose(
                    float(state["max_clock_skew"]),
                    skew,
                    rel_tol=0.0,
                    abs_tol=0.0,
                ):
                    raise ValueError(
                        "persistent operator authentication clock-skew binding changed"
                    )
                effective_now = max(current, float(state["clock_high_water"]))
                state["clock_high_water"] = effective_now

                def finish(reason: str) -> str:
                    self._connection.execute(
                        """
                        UPDATE controller_state SET state_value=?, updated_at=?
                        WHERE state_key=?
                        """,
                        (
                            canonical_json_dumps(state),
                            effective_now,
                            OPERATOR_AUTH_STATE_KEY,
                        ),
                    )
                    self._connection.commit()
                    return reason

                if (
                    not hmac.compare_digest(str(state["principal_id"]), principal)
                    or int(state["credential_epoch"]) != credential_epoch
                    or not hmac.compare_digest(
                        str(state["key_fingerprint"]), expected_key_fingerprint
                    )
                ):
                    return finish("authority_changed")
                if (
                    abs(effective_now - request_timestamp) > skew
                    or request_timestamp <= float(state["migration_floor"])
                ):
                    return finish("stale")
                self._connection.execute(
                    """
                    DELETE FROM operator_request_replay
                    WHERE typeof(expires_at) IN ('integer','real')
                      AND expires_at < ?
                    """,
                    (effective_now,),
                )
                duplicate = self._connection.execute(
                    """
                    SELECT marker_sha256 FROM operator_request_replay
                    WHERE principal_id=? AND credential_epoch=? AND request_id=?
                    """,
                    (principal, credential_epoch, request_id),
                ).fetchone()
                if duplicate is not None:
                    return finish(
                        "duplicate"
                        if hmac.compare_digest(
                            str(duplicate["marker_sha256"]), marker_sha256
                        )
                        else "request_id_conflict"
                    )
                duplicate_marker = self._connection.execute(
                    """
                    SELECT 1 FROM operator_request_replay
                    WHERE principal_id=? AND credential_epoch=? AND marker_sha256=?
                    """,
                    (principal, credential_epoch, marker_sha256),
                ).fetchone()
                if duplicate_marker is not None:
                    return finish("duplicate")
                count = int(
                    self._connection.execute(
                        """
                        SELECT COUNT(*) FROM operator_request_replay
                        WHERE principal_id=? AND credential_epoch=?
                        """,
                        (principal, credential_epoch),
                    ).fetchone()[0]
                )
                if count >= max_entries:
                    return finish("capacity")
                self._connection.execute(
                    """
                    INSERT INTO operator_request_replay(
                      principal_id, credential_epoch, request_id, marker_sha256,
                      request_timestamp, accepted_at, expires_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        principal,
                        credential_epoch,
                        request_id,
                        marker_sha256,
                        request_timestamp,
                        effective_now,
                        request_timestamp + skew,
                    ),
                )
                self._connection.execute(
                    """
                    INSERT INTO audit_log(
                      audit_id, actor, operation, subject, detail_json, created_at
                    ) VALUES(?, ?, 'operator_request_admitted', ?, ?, ?)
                    """,
                    (
                        str(
                            uuid.uuid5(
                                uuid.NAMESPACE_URL,
                                f"operator-request:{principal}:{credential_epoch}:{request_id}",
                            )
                        ),
                        principal,
                        target[:512],
                        canonical_json_dumps(
                            {
                                "credential_epoch": credential_epoch,
                                "marker_sha256": marker_sha256,
                                "method": method,
                                "request_id": request_id,
                            }
                        ),
                        effective_now,
                    ),
                )
                return finish("accepted")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def agent_http_auth_snapshot(self, agent_id: str) -> dict[str, Any] | None:
        """Return one validated credential snapshot for HTTP authentication."""
        with self._lock:
            row = self._connection.execute(
                """
                SELECT agent_secret, credential_epoch, enabled
                FROM agents WHERE agent_id=?
                """,
                (agent_id,),
            ).fetchone()
        if row is None:
            return None
        if (
            type(row["credential_epoch"]) is not int
            or not 0 <= int(row["credential_epoch"]) <= 2**63 - 1
            or type(row["enabled"]) is not int
            or row["enabled"] not in {0, 1}
            or not isinstance(row["agent_secret"], str)
            or len(row["agent_secret"]) > 256
        ):
            raise ValueError("stored agent HTTP authority is invalid")
        return {
            "agent_secret": str(row["agent_secret"]),
            "credential_epoch": int(row["credential_epoch"]),
            "enabled": bool(row["enabled"]),
        }

    def admit_http_request(
        self,
        agent_id: str,
        supplied_signature: str,
        request_timestamp: str,
        *,
        auth_kind: str,
        expected_credential_epoch: int,
        expected_agent_secret: str | None = None,
        max_entries: int,
        max_principals: int,
        max_clock_skew: float,
        now: float | None = None,
    ) -> str:
        """Atomically persist one authenticated request before any side effect."""
        if (
            not isinstance(agent_id, str)
            or not 1 <= len(agent_id) <= 128
            or any(character not in HTTP_REQUEST_AGENT_ID_CHARACTERS for character in agent_id)
            or not isinstance(supplied_signature, str)
            or len(supplied_signature) != 64
            or any(character not in "0123456789abcdef" for character in supplied_signature)
            or auth_kind not in HTTP_REQUEST_AUTH_KINDS
            or type(expected_credential_epoch) is not int
            or not -1 <= expected_credential_epoch <= 2**63 - 1
            or type(max_entries) is not int
            or max_entries < 1
            or type(max_principals) is not int
            or max_principals < 1
            or isinstance(max_clock_skew, bool)
        ):
            raise ValueError("HTTP replay admission arguments are invalid")
        if auth_kind == "agent" and not isinstance(expected_agent_secret, str):
            raise ValueError("agent HTTP replay admission requires a credential snapshot")
        try:
            request_time = float(request_timestamp)
            current = float(time.time() if now is None else now)
            skew = float(max_clock_skew)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("HTTP replay clock state is invalid") from exc
        if (
            not math.isfinite(request_time)
            or not 0 <= request_time <= 2**63 - 1
            or not math.isfinite(current)
            or not 0 <= current <= 2**63 - 1
            or not math.isfinite(skew)
            or skew < 1.0
            or request_time + skew > 2**63 - 1
        ):
            raise ValueError("HTTP replay clock state is invalid")
        marker = hashlib.sha256(
            b"sentinel-blue-http-replay-v1\x00"
            + supplied_signature.encode("ascii")
        ).hexdigest()
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                state = self._http_request_replay_state_locked()
                if not math.isclose(
                    float(state["max_clock_skew"]),
                    skew,
                    rel_tol=0.0,
                    abs_tol=0.0,
                ):
                    raise ValueError(
                        "persistent HTTP replay clock-skew binding changed"
                    )
                authority = self._connection.execute(
                    """
                    SELECT agent_secret, credential_epoch, enabled
                    FROM agents WHERE agent_id=?
                    """,
                    (agent_id,),
                ).fetchone()
                authority_matches = False
                if auth_kind == "agent":
                    authority_matches = bool(
                        authority is not None
                        and type(authority["credential_epoch"]) is int
                        and authority["credential_epoch"]
                        == expected_credential_epoch
                        and type(authority["enabled"]) is int
                        and authority["enabled"] == 1
                        and isinstance(authority["agent_secret"], str)
                        and hmac.compare_digest(
                            str(authority["agent_secret"]),
                            str(expected_agent_secret),
                        )
                    )
                elif expected_credential_epoch == -1:
                    authority_matches = authority is None
                else:
                    authority_matches = bool(
                        authority is not None
                        and type(authority["credential_epoch"]) is int
                        and authority["credential_epoch"]
                        == expected_credential_epoch
                    )

                effective_now = max(current, float(state["clock_high_water"]))
                state["clock_high_water"] = effective_now

                def finish(reason: str) -> str:
                    self._connection.execute(
                        """
                        UPDATE controller_state SET state_value=?, updated_at=?
                        WHERE state_key=?
                        """,
                        (
                            canonical_json_dumps(state),
                            effective_now,
                            HTTP_REQUEST_REPLAY_STATE_KEY,
                        ),
                    )
                    self._connection.commit()
                    return reason

                if not authority_matches:
                    return finish("authority_changed")
                if (
                    abs(effective_now - request_time) > skew
                    or request_time <= float(state["migration_floor"])
                ):
                    return finish("stale")
                self._connection.execute(
                    """
                    DELETE FROM http_request_replay
                    WHERE typeof(expires_at) IN ('integer','real')
                      AND expires_at < ?
                    """,
                    (effective_now,),
                )
                duplicate = self._connection.execute(
                    """
                    SELECT 1 FROM http_request_replay
                    WHERE agent_id=? AND marker_sha256=?
                    """,
                    (agent_id, marker),
                ).fetchone()
                if duplicate is not None:
                    return finish("duplicate")
                principal_exists = self._connection.execute(
                    "SELECT 1 FROM http_request_replay WHERE agent_id=? LIMIT 1",
                    (agent_id,),
                ).fetchone()
                if principal_exists is None:
                    principal_count = int(
                        self._connection.execute(
                            "SELECT COUNT(DISTINCT agent_id) FROM http_request_replay"
                        ).fetchone()[0]
                    )
                    if principal_count >= max_principals:
                        return finish("principal_capacity")
                marker_count = int(
                    self._connection.execute(
                        "SELECT COUNT(*) FROM http_request_replay WHERE agent_id=?",
                        (agent_id,),
                    ).fetchone()[0]
                )
                if marker_count >= max_entries:
                    return finish("capacity")
                self._connection.execute(
                    """
                    INSERT INTO http_request_replay(
                      agent_id, marker_sha256, auth_kind, credential_epoch,
                      request_timestamp, accepted_at, expires_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        agent_id,
                        marker,
                        auth_kind,
                        expected_credential_epoch,
                        request_time,
                        effective_now,
                        request_time + skew,
                    ),
                )
                return finish("accepted")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def enabled_agents_missing_credentials(self) -> list[str]:
        """Return enabled external rows that cannot authenticate safely."""
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT agent_id FROM agents
                WHERE enabled=1 AND (agent_secret IS NULL OR agent_secret='')
                ORDER BY agent_id
                """
            ).fetchall()
        return [str(row["agent_id"]) for row in rows]

    def initialize_enrollment_deadline(self, window: float, now: float) -> float:
        """Persist the first absolute enrollment deadline without extending it.

        A database created by an earlier release has no state row. Treat that
        migration as closed instead of reopening enrollment on upgrade.
        """
        with self._lock:
            row = self._connection.execute(
                "SELECT state_value FROM controller_state WHERE state_key='enrollment_deadline'"
            ).fetchone()
            if row is not None:
                try:
                    deadline = float(row["state_value"])
                except (TypeError, ValueError) as exc:
                    raise ValueError("persisted enrollment deadline is invalid") from exc
                if not math.isfinite(deadline) or deadline < 0:
                    raise ValueError("persisted enrollment deadline is invalid")
                return deadline
            deadline = 0.0 if self.database_preexisting else float(now) + max(
                0.0, float(window)
            )
            if not math.isfinite(deadline) or deadline < 0:
                raise ValueError("enrollment deadline is invalid")
            self._connection.execute(
                """
                INSERT INTO controller_state(state_key, state_value, updated_at)
                VALUES('enrollment_deadline', ?, ?)
                """,
                (repr(deadline), float(now)),
            )
            self._connection.commit()
            return deadline

    def ensure_agent_secret(self, agent_id: str) -> str:
        with self._lock:
            row = self._connection.execute(
                "SELECT agent_secret FROM agents WHERE agent_id=?", (agent_id,)
            ).fetchone()
            if not row:
                raise ValueError("agent is not registered")
            existing = str(row["agent_secret"] or "")
            if existing:
                return existing
            value = secrets.token_urlsafe(48)
            self._connection.execute(
                "UPDATE agents SET agent_secret=? WHERE agent_id=? AND agent_secret=''",
                (value, agent_id),
            )
            self._connection.commit()
            row = self._connection.execute(
                "SELECT agent_secret FROM agents WHERE agent_id=?", (agent_id,)
            ).fetchone()
            return str(row["agent_secret"])

    def agent_secret(self, agent_id: str) -> str | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT agent_secret FROM agents WHERE agent_id=?", (agent_id,)
            ).fetchone()
        return str(row["agent_secret"]) if row and row["agent_secret"] else None

    def rotate_agent_credential(self, agent_id: str) -> str:
        """Start a fresh enrollment epoch and invalidate prior delivery state."""
        value = secrets.token_urlsafe(48)
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                now = time.time()
                row = self._connection.execute(
                    "SELECT credential_epoch FROM agents WHERE agent_id=?",
                    (agent_id,),
                ).fetchone()
                if (
                    not row
                    or type(row["credential_epoch"]) is not int
                    or not 0 <= row["credential_epoch"] < 2**63 - 1
                ):
                    raise ValueError("agent is not registered or its epoch is invalid")
                self._connection.execute(
                    """
                    UPDATE agents SET agent_secret=?,
                      credential_epoch=credential_epoch+1, last_sequence=-1,
                      boot_id='', latest_telemetry=NULL, profile_id='',
                      profile_fingerprint='', agent_version='', last_seen=0,
                      last_observed_at=0, latest_payload_sha256=''
                    WHERE agent_id=?
                    """,
                    (value, agent_id),
                )
                self._invalidate_agent_authority_locked(
                    agent_id, now, "credential_rotation",
                    ACTION_CREDENTIAL_ROTATED_RESULT,
                )
                self._connection.execute(
                    "DELETE FROM telemetry_boots WHERE agent_id=?", (agent_id,)
                )
                self._connection.execute(
                    "DELETE FROM telemetry_processing WHERE agent_id=?", (agent_id,)
                )
                self._connection.execute(
                    "DELETE FROM enrollment_tickets WHERE agent_id=?", (agent_id,)
                )
                self._connection.execute(
                    "DELETE FROM agent_reenrollment WHERE agent_id=?", (agent_id,)
                )
                self.audit("controller", "rotate_agent_credential", agent_id, {})
                self._connection.commit()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise
        return value

    def _invalidate_agent_authority_locked(
        self,
        agent_id: str,
        now: float,
        reason: str,
        action_result: str,
    ) -> None:
        self._connection.execute(
            """
            UPDATE actions SET
              status=CASE status
                WHEN 'queued' THEN 'failed'
                ELSE 'outcome_unknown'
              END,
              completed_at=CASE status
                WHEN 'queued' THEN ?
                ELSE NULL
              END,
              result_json=?, result_source='controller'
            WHERE agent_id=? AND status IN ('queued','dispatched')
            """,
            (now, action_result, agent_id),
        )
        self._connection.execute(
            "UPDATE baselines SET status='invalidated', approved_at=NULL "
            "WHERE agent_id=? AND status IN ('pending','approved')",
            (agent_id,),
        )
        self._connection.execute(
            "UPDATE baseline_promotions SET status='blocked', failure_reason=?, "
            "updated_at=?, completed_at=? WHERE agent_id=? AND status='pending'",
            (reason, now, now, agent_id),
        )
        self._connection.execute(
            "UPDATE alerts SET status='invalidated', decision=?, decided_at=? "
            "WHERE agent_id=? AND status='open'",
            (reason, now, agent_id),
        )
        self._connection.execute(
            "UPDATE change_grants SET revoked_at=?, revocation_reason=? "
            "WHERE agent_id=? AND used_at IS NULL AND revoked_at IS NULL",
            (now, reason, agent_id),
        )
        self._connection.execute(
            "UPDATE privileged_authorizations SET revoked_at=?, revocation_reason=? "
            "WHERE agent_id=? AND used_at IS NULL AND revoked_at IS NULL",
            (now, reason, agent_id),
        )

    def _revoke_corrupt_agent_locked(
        self, agent_id: str, now: float, reason: str
    ) -> None:
        """Terminalize corrupt authority before an operator can re-enable it."""
        replacement = secrets.token_urlsafe(48)
        cursor = self._connection.execute(
            """
            UPDATE agents SET enabled=0, agent_secret=?,
              credential_epoch=CASE
                WHEN typeof(credential_epoch)='integer'
                  AND credential_epoch>=0
                  AND credential_epoch<9223372036854775807
                THEN credential_epoch+1
                ELSE 9223372036854775807
              END,
              profile_id='', profile_fingerprint='', agent_version='',
              last_seen=0, latest_telemetry=NULL, last_sequence=-1,
              boot_id='', last_observed_at=0, latest_payload_sha256=''
            WHERE agent_id=?
            """,
            (replacement, agent_id),
        )
        if not cursor.rowcount:
            return
        self._invalidate_agent_authority_locked(
            agent_id, now, reason, ACTION_BINDING_INVALIDATED_RESULT
        )
        for table in (
            "telemetry_boots",
            "telemetry_processing",
            "enrollment_tickets",
            "agent_reenrollment",
        ):
            self._connection.execute(
                f"DELETE FROM {table} WHERE agent_id=?", (agent_id,)
            )

    def set_agent_enabled(self, agent_id: str, enabled: bool) -> bool:
        changed = False
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                now = time.time()
                if enabled:
                    cursor = self._connection.execute(
                        """
                        INSERT INTO agent_reenrollment(
                          agent_id, authorized_at, expires_at,
                          credential_epoch
                        ) SELECT agent_id, ?, ?, credential_epoch
                          FROM agents
                         WHERE agent_id=? AND enabled=0
                           AND typeof(credential_epoch)='integer'
                           AND credential_epoch>=0
                           AND credential_epoch<9223372036854775807
                           AND profile_id='' AND latest_telemetry IS NULL
                        ON CONFLICT(agent_id) DO UPDATE SET
                          authorized_at=excluded.authorized_at,
                          expires_at=excluded.expires_at,
                          credential_epoch=excluded.credential_epoch
                        """,
                        (now, now + 300.0, agent_id),
                    )
                else:
                    replacement = secrets.token_urlsafe(48)
                    cursor = self._connection.execute(
                        """
                        UPDATE agents SET enabled=0, agent_secret=?,
                          credential_epoch=credential_epoch+1,
                          profile_id='', profile_fingerprint='', agent_version='',
                          last_seen=0, latest_telemetry=NULL, last_sequence=-1,
                          boot_id='', last_observed_at=0,
                          latest_payload_sha256=''
                        WHERE agent_id=? AND enabled=1
                          AND credential_epoch<9223372036854775807
                        """,
                        (replacement, agent_id),
                    )
                    if cursor.rowcount:
                        self._invalidate_agent_authority_locked(
                            agent_id,
                            now,
                            "agent_revoked",
                            ACTION_CREDENTIAL_ROTATED_RESULT,
                        )
                        self._connection.execute(
                            "DELETE FROM telemetry_boots WHERE agent_id=?", (agent_id,)
                        )
                        self._connection.execute(
                            "DELETE FROM telemetry_processing WHERE agent_id=?",
                            (agent_id,),
                        )
                        self._connection.execute(
                            "DELETE FROM enrollment_tickets WHERE agent_id=?", (agent_id,)
                        )
                        self._connection.execute(
                            "DELETE FROM agent_reenrollment WHERE agent_id=?",
                            (agent_id,),
                        )
                    else:
                        stored = self._connection.execute(
                            "SELECT enabled, credential_epoch FROM agents "
                            "WHERE agent_id=?",
                            (agent_id,),
                        ).fetchone()
                        pending_reenrollment = bool(
                            stored
                            and type(stored["enabled"]) is int
                            and stored["enabled"] == 0
                            and self._connection.execute(
                                "SELECT 1 FROM agent_reenrollment "
                                "WHERE agent_id=?",
                                (agent_id,),
                            ).fetchone()
                        )
                        if pending_reenrollment:
                            self._connection.execute(
                                "DELETE FROM agent_reenrollment WHERE agent_id=?",
                                (agent_id,),
                            )
                            self._connection.execute(
                                "DELETE FROM enrollment_tickets WHERE agent_id=?",
                                (agent_id,),
                            )
                            changed = True
                        corrupt_authority = bool(
                            stored
                            and (
                                type(stored["enabled"]) is not int
                                or stored["enabled"] not in {0, 1}
                                or type(stored["credential_epoch"]) is not int
                                or not 0 <= stored["credential_epoch"] <= 2**63 - 1
                                or (
                                    stored["enabled"] == 1
                                    and stored["credential_epoch"] == 2**63 - 1
                                )
                            )
                        )
                        if corrupt_authority:
                            self._quarantine_json(
                                "agents",
                                agent_id,
                                "row_semantics",
                                dict(stored),
                                "agent authority could not be revoked normally",
                            )
                            self._revoke_corrupt_agent_locked(
                                agent_id, now, "agent_authority_corrupt"
                            )
                            changed = True
                changed = changed or cursor.rowcount == 1
                if changed:
                    self.audit(
                        "operator",
                        (
                            "agent_reenrollment_authorized"
                            if enabled
                            else "agent_revoked"
                        ),
                        agent_id,
                        {},
                    )
                self._connection.commit()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise
        return changed

    def save_telemetry(
        self,
        agent_id: str,
        telemetry: dict[str, Any],
        expected_agent_secret: str | None = None,
    ) -> bool:
        """Persist a new sample; return False for an exact delivery retry.

        Known boot identifiers make the persistent sequence counter a replay barrier
        even after the controller restarts. Legacy/agentless samples use ``unknown``
        and remain compatible without sequence enforcement.
        """
        now = time.time()
        encoded = canonical_json_dumps(telemetry, max_bytes=MAX_STORED_JSON_BYTES)
        with self._lock:
            row = self._connection.execute(
                """
                SELECT latest_telemetry, last_sequence, boot_id, agent_secret
                FROM agents WHERE agent_id=?
                """,
                (agent_id,),
            ).fetchone()
            if expected_agent_secret is not None and (
                not row
                or not hmac.compare_digest(
                    str(row["agent_secret"] or ""), str(expected_agent_secret)
                )
            ):
                raise ValueError("agent credential epoch changed before telemetry commit")
            boot_id = str(telemetry.get("boot_id", "unknown"))
            sequence = int(telemetry.get("sequence", 0))
            if row and boot_id not in {"", "unknown"} and str(row["boot_id"]) == boot_id:
                last_sequence = int(row["last_sequence"])
                if sequence < last_sequence:
                    raise ValueError("telemetry sequence moved backwards within the same boot")
                if sequence == last_sequence and row["latest_telemetry"]:
                    stored = self._decode_stored_json(
                        row["latest_telemetry"],
                        table_name="agents",
                        row_key=agent_id,
                        column_name="latest_telemetry",
                        expected_type=dict,
                    )
                    if stored is None:
                        raise ValueError("stored telemetry requires operator review")
                    stored_encoded = canonical_json_dumps(stored)
                    if hmac_compare_json(stored_encoded, encoded):
                        return False
                    raise ValueError("telemetry sequence was reused with a different payload")
            self._connection.execute(
                """
                UPDATE agents SET last_seen=?, latest_telemetry=?, last_sequence=?, boot_id=?
                WHERE agent_id=?
                """,
                (
                    now,
                    encoded,
                    sequence,
                    boot_id,
                    agent_id,
                ),
            )
            self._connection.commit()
        return True

    def get_baseline(
        self, agent_id: str, binding: dict[str, Any] | None = None
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM baselines WHERE agent_id=?", (agent_id,)
            ).fetchone()
        if not row:
            return None
        baseline = self._decode_stored_json(
            row["baseline_json"],
            table_name="baselines",
            row_key=agent_id,
            column_name="baseline_json",
            expected_type=dict,
        )
        if baseline is None:
            with self._lock:
                self._connection.execute(
                    "UPDATE baselines SET status='invalid' WHERE agent_id=?",
                    (agent_id,),
                )
                self._connection.commit()
            return None
        try:
            if (
                type(row["credential_epoch"]) is not int
                or not -1 <= row["credential_epoch"] <= 2**63 - 1
                or row["status"]
                not in {"pending", "approved", "invalid", "invalidated"}
                or not isinstance(row["profile_id"], str)
                or not isinstance(row["profile_fingerprint"], str)
                or not isinstance(row["agent_version"], str)
                or not isinstance(baseline.get("platform", "unknown"), str)
            ):
                raise ValueError("stored baseline row semantics are invalid")
            integrity = baseline.get("integrity", [])
            if not isinstance(integrity, list) or len(integrity) > 2048:
                raise ValueError("stored baseline integrity inventory is invalid")
            for index, item in enumerate(integrity):
                if not isinstance(item, dict):
                    raise ValueError(
                        f"stored baseline integrity[{index}] is not an object"
                    )
                path = item.get("path")
                digest = item.get("sha256")
                security = item.get("security_descriptor_sha256", "")
                if (
                    not isinstance(path, str)
                    or not path
                    or len(path) > 1024
                    or not isinstance(digest, str)
                    or len(digest) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in digest
                    )
                    or not isinstance(security, str)
                    or (
                        security
                        and (
                            len(security) != 64
                            or any(
                                character not in "0123456789abcdef"
                                for character in security
                            )
                        )
                    )
                ):
                    raise ValueError(
                        f"stored baseline integrity[{index}] is invalid"
                    )
        except (TypeError, ValueError, OverflowError) as exc:
            self._quarantine_json(
                "baselines",
                agent_id,
                "row_semantics",
                dict(row),
                str(exc),
            )
            with self._lock:
                self._connection.execute(
                    "UPDATE baselines SET status='invalid', approved_at=NULL "
                    "WHERE agent_id=?",
                    (agent_id,),
                )
                self._connection.commit()
            return None
        if binding is not None and (
            row["credential_epoch"],
            row["profile_id"],
            row["profile_fingerprint"],
            row["agent_version"],
        ) != self._binding_values(binding):
            return None
        return baseline

    def baseline_status(
        self, agent_id: str, binding: dict[str, Any] | None = None
    ) -> str | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT status, credential_epoch, profile_id, profile_fingerprint, "
                "agent_version FROM baselines WHERE agent_id=?",
                (agent_id,),
            ).fetchone()
        if row and binding is not None and (
            int(row["credential_epoch"]),
            str(row["profile_id"]),
            str(row["profile_fingerprint"]),
            str(row["agent_version"]),
        ) != self._binding_values(binding):
            return None
        return str(row["status"]) if row else None

    def latest_telemetry_for_agent(self, agent_id: str) -> dict[str, Any] | None:
        """Return the exact latest telemetry sample retained for one agent."""
        with self._lock:
            row = self._connection.execute(
                "SELECT latest_telemetry FROM agents WHERE agent_id=?",
                (agent_id,),
            ).fetchone()
        if not row or row["latest_telemetry"] is None:
            return None
        fallback = {
            **INVALID_JSON_PLACEHOLDER,
            "agent_id": agent_id,
            "platform": "unknown",
            "collector_errors": ["stored telemetry requires operator review"],
            "integrity": [],
            "probes": [],
            "services": [],
            "interfaces": [],
        }
        return self._decode_stored_json(
            row["latest_telemetry"],
            table_name="agents",
            row_key=agent_id,
            column_name="latest_telemetry",
            expected_type=dict,
            fallback=fallback,
        )

    def create_baseline(
        self,
        agent_id: str,
        telemetry: dict[str, Any],
        binding: dict[str, Any] | None = None,
    ) -> None:
        epoch, profile_id, profile_fingerprint, agent_version = self._binding_values(
            binding or {}
        )
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO baselines(
                  agent_id, baseline_json, created_at, credential_epoch,
                  profile_id, profile_fingerprint, agent_version
                ) VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_id) DO UPDATE SET
                  baseline_json=excluded.baseline_json,
                  created_at=excluded.created_at,
                  status='pending', approved_at=NULL,
                  credential_epoch=excluded.credential_epoch,
                  profile_id=excluded.profile_id,
                  profile_fingerprint=excluded.profile_fingerprint,
                  agent_version=excluded.agent_version
                WHERE baselines.status IN ('invalid','invalidated')
                   OR baselines.credential_epoch!=excluded.credential_epoch
                   OR baselines.profile_fingerprint!=excluded.profile_fingerprint
                   OR baselines.agent_version!=excluded.agent_version
                """,
                (
                    agent_id,
                    canonical_json_dumps(
                        telemetry, max_bytes=MAX_STORED_JSON_BYTES
                    ),
                    time.time(),
                    epoch,
                    profile_id,
                    profile_fingerprint,
                    agent_version,
                ),
            )
            self._connection.commit()

    def approve_baseline(
        self,
        agent_id: str,
        expected_telemetry: dict[str, Any] | None = None,
        binding: dict[str, Any] | None = None,
    ) -> bool:
        """Promote only a sample that has no protected-file capture scope.

        ``expected_telemetry`` lets the controller bind its health decision to the
        exact authenticated sample that is promoted.  A newer sample arriving
        between assessment and this update makes the conditional update fail so
        the caller can reassess it.  Any integrity row requires the receipt-bound
        ``begin_baseline_promotion`` transaction and can never use this legacy
        no-file fast path.  Approved baselines are never rewritten here.
        """
        expected_encoded = (
            canonical_json_dumps(
                expected_telemetry, max_bytes=MAX_STORED_JSON_BYTES
            )
            if expected_telemetry is not None
            else None
        )
        now = time.time()
        expected_binding = self._binding_values(binding or {})
        with self._lock:
            row = self._connection.execute(
                """
                SELECT a.latest_telemetry, a.credential_epoch, a.profile_id,
                       a.profile_fingerprint, a.agent_version,
                       b.credential_epoch AS baseline_epoch,
                       b.profile_id AS baseline_profile_id,
                       b.profile_fingerprint AS baseline_profile_fingerprint,
                       b.agent_version AS baseline_agent_version
                FROM agents a JOIN baselines b ON b.agent_id=a.agent_id
                WHERE a.agent_id=? AND b.status='pending'
                """,
                (agent_id,),
            ).fetchone()
            if not row or row["latest_telemetry"] is None:
                return False
            actual_binding = (
                int(row["credential_epoch"]),
                str(row["profile_id"]),
                str(row["profile_fingerprint"]),
                str(row["agent_version"]),
            )
            baseline_binding = (
                int(row["baseline_epoch"]),
                str(row["baseline_profile_id"]),
                str(row["baseline_profile_fingerprint"]),
                str(row["baseline_agent_version"]),
            )
            if binding is not None and (
                actual_binding != expected_binding or baseline_binding != expected_binding
            ):
                return False
            latest_encoded = str(row["latest_telemetry"])
            latest = self._decode_stored_json(
                latest_encoded,
                table_name="agents",
                row_key=agent_id,
                column_name="latest_telemetry",
                expected_type=dict,
            )
            if latest is None:
                return False
            try:
                if baseline_capture_files(latest):
                    return False
            except (TypeError, ValueError, OverflowError):
                return False
            latest_canonical = canonical_json_dumps(latest)
            if expected_encoded is not None and not hmac_compare_json(
                latest_canonical, expected_encoded
            ):
                return False
            # Legacy/non-release-bound stores deliberately have no binding
            # contract.  Persistent release-bound controllers always supply a
            # binding and use the stronger conditional update below.  Keeping
            # those paths separate avoids manufacturing a false relationship
            # between legacy ``-1`` baseline epochs and agent epoch zero.
            if binding is None:
                cursor = self._connection.execute(
                    """
                    UPDATE baselines
                    SET baseline_json=?, created_at=?, status='approved', approved_at=?
                    WHERE agent_id=? AND status='pending'
                      AND EXISTS (
                        SELECT 1 FROM agents
                        WHERE agents.agent_id=baselines.agent_id
                          AND agents.latest_telemetry=?
                      )
                    """,
                    (latest_canonical, now, now, agent_id, latest_encoded),
                )
            else:
                cursor = self._connection.execute(
                    """
                    UPDATE baselines
                    SET baseline_json=?, created_at=?, status='approved', approved_at=?
                    WHERE agent_id=? AND status='pending'
                      AND credential_epoch=? AND profile_id=?
                      AND profile_fingerprint=? AND agent_version=?
                      AND EXISTS (
                        SELECT 1 FROM agents
                        WHERE agents.agent_id=baselines.agent_id
                          AND agents.latest_telemetry=?
                          AND agents.credential_epoch=baselines.credential_epoch
                          AND agents.profile_id=baselines.profile_id
                          AND agents.profile_fingerprint=baselines.profile_fingerprint
                          AND agents.agent_version=baselines.agent_version
                      )
                    """,
                    (
                        latest_canonical,
                        now,
                        now,
                        agent_id,
                        *actual_binding,
                        latest_encoded,
                    ),
                )
            self._connection.commit()
        return cursor.rowcount == 1

    def latest_baseline_promotion(
        self, agent_id: str, *, pending_only: bool = False
    ) -> dict[str, Any] | None:
        clauses = " AND status='pending'" if pending_only else ""
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM baseline_promotions WHERE agent_id=?"
                + clauses
                + " ORDER BY created_at DESC, promotion_id DESC LIMIT 1",
                (agent_id,),
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        candidate = self._decode_stored_json(
            item.pop("candidate_json"),
            table_name="baseline_promotions",
            row_key=str(item["promotion_id"]),
            column_name="candidate_json",
            expected_type=dict,
        )
        if candidate is None:
            with self._lock:
                self._connection.execute(
                    "UPDATE baseline_promotions SET status='blocked', "
                    "failure_reason='candidate_json_invalid', updated_at=? "
                    "WHERE promotion_id=? AND status='pending'",
                    (time.time(), item["promotion_id"]),
                )
                self._connection.commit()
            return None
        item["candidate"] = candidate
        return item

    def begin_baseline_promotion(
        self,
        agent_id: str,
        candidate: dict[str, Any],
        expected_telemetry: dict[str, Any],
        *,
        source: str,
        alert_id: str | None = None,
        binding: dict[str, Any] | None = None,
        expires_at: float,
        profile_id: str,
        profile_fingerprint: str,
        autonomy_mode: str,
    ) -> dict[str, Any]:
        """Atomically freeze a candidate and queue its aggregate capture.

        Neither the baseline nor an ``accept_change`` alert is promoted here.
        The exact action result later performs that transition in the same
        transaction as receipt verification.
        """

        if source not in {"initial", "accepted_change"}:
            raise ValueError("baseline promotion source is invalid")
        if source == "initial" and alert_id is not None:
            raise ValueError("initial baseline promotion cannot bind an alert")
        if source == "accepted_change" and not alert_id:
            raise ValueError("accepted change promotion requires an alert")
        if not isinstance(candidate, dict) or not isinstance(expected_telemetry, dict):
            raise ValueError("baseline promotion requires object candidates")
        if str(candidate.get("agent_id", "")) != agent_id or str(
            expected_telemetry.get("agent_id", "")
        ) != agent_id:
            raise ValueError("baseline promotion agent identity is inconsistent")
        files = baseline_capture_files(candidate)
        candidate_json = canonical_json_dumps(
            candidate, max_bytes=MAX_STORED_JSON_BYTES
        )
        telemetry_json = canonical_json_dumps(
            expected_telemetry, max_bytes=MAX_STORED_JSON_BYTES
        )
        candidate_sha256 = hashlib.sha256(candidate_json.encode()).hexdigest()
        telemetry_sha256 = hashlib.sha256(telemetry_json.encode()).hexdigest()
        binding_values = self._binding_values(binding or {})
        observed_at = expected_telemetry.get("observed_at")
        sequence = expected_telemetry.get("sequence", -1)
        boot_id = expected_telemetry.get("boot_id", "")
        if (
            type(observed_at) not in {int, float}
            or not math.isfinite(observed_at)
            or not 0 <= observed_at <= 2**63 - 1
            or type(sequence) is not int
            or not -1 <= sequence <= 2**63 - 1
            or not isinstance(boot_id, str)
            or len(boot_id) > 256
        ):
            raise ValueError("baseline promotion telemetry observation is invalid")

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            self._start_quarantine_boundary_locked()
            try:
                active = self._connection.execute(
                    "SELECT * FROM baseline_promotions "
                    "WHERE agent_id=? AND status='pending'",
                    (agent_id,),
                ).fetchone()
                if active:
                    same = (
                        str(active["source"]),
                        str(active["alert_id"] or ""),
                        str(active["candidate_sha256"]),
                        str(active["telemetry_sha256"]),
                        int(active["credential_epoch"]),
                        str(active["profile_id"]),
                        str(active["profile_fingerprint"]),
                        str(active["agent_version"]),
                    ) == (
                        source,
                        str(alert_id or ""),
                        candidate_sha256,
                        telemetry_sha256,
                        *binding_values,
                    )
                    if not same:
                        self._connection.rollback()
                        raise RuntimeError(
                            "a different baseline promotion is already pending"
                        )
                    result = {
                        "promotion_id": str(active["promotion_id"]),
                        "status": "pending",
                        "action_id": active["action_id"],
                    }
                    self._connection.rollback()
                    self._finish_quarantine_boundary_locked()
                    return result

                agent = self._connection.execute(
                    "SELECT latest_telemetry, credential_epoch, profile_id, "
                    "profile_fingerprint, agent_version, enabled "
                    "FROM agents WHERE agent_id=?",
                    (agent_id,),
                ).fetchone()
                baseline_row = self._connection.execute(
                    "SELECT * FROM baselines WHERE agent_id=?", (agent_id,)
                ).fetchone()
                if not agent or agent["enabled"] != 1 or not baseline_row:
                    raise PermissionError("baseline promotion authority is unavailable")
                if binding is not None and (
                    int(agent["credential_epoch"]),
                    str(agent["profile_id"]),
                    str(agent["profile_fingerprint"]),
                    str(agent["agent_version"]),
                ) != binding_values:
                    raise PermissionError("baseline promotion binding changed")
                latest = self._decode_stored_json(
                    agent["latest_telemetry"],
                    table_name="agents",
                    row_key=agent_id,
                    column_name="latest_telemetry",
                    expected_type=dict,
                )
                if latest is None or not hmac_compare_json(
                    canonical_json_dumps(latest), telemetry_json
                ):
                    raise RuntimeError(
                        "telemetry changed before baseline promotion was frozen"
                    )
                prior = self._decode_stored_json(
                    baseline_row["baseline_json"],
                    table_name="baselines",
                    row_key=agent_id,
                    column_name="baseline_json",
                    expected_type=dict,
                )
                if prior is None:
                    raise ValueError("stored baseline requires operator review")
                prior_json = canonical_json_dumps(
                    prior, max_bytes=MAX_STORED_JSON_BYTES
                )
                prior_sha256 = hashlib.sha256(prior_json.encode()).hexdigest()
                if binding is not None and (
                    int(baseline_row["credential_epoch"]),
                    str(baseline_row["profile_id"]),
                    str(baseline_row["profile_fingerprint"]),
                    str(baseline_row["agent_version"]),
                ) != binding_values:
                    raise PermissionError("baseline promotion baseline binding changed")

                if source == "initial":
                    if baseline_row["status"] != "pending":
                        raise ValueError("initial baseline is not pending")
                    if not hmac_compare_json(candidate_json, telemetry_json):
                        raise ValueError(
                            "initial baseline candidate must be the exact observation"
                        )
                else:
                    if baseline_row["status"] != "approved":
                        raise ValueError("approved baseline is unavailable")
                    alert = self._connection.execute(
                        "SELECT * FROM alerts WHERE alert_id=? AND agent_id=? "
                        "AND status='open' AND kind='critical_file_changed'",
                        (alert_id, agent_id),
                    ).fetchone()
                    if not alert:
                        raise PermissionError("accepted-change alert is no longer open")
                    if binding is not None and (
                        int(alert["credential_epoch"]),
                        str(alert["profile_id"]),
                        str(alert["profile_fingerprint"]),
                        str(alert["agent_version"]),
                    ) != binding_values:
                        raise PermissionError("accepted-change alert binding changed")
                    evidence = self._decode_stored_json(
                        alert["evidence_json"],
                        table_name="alerts",
                        row_key=str(alert_id),
                        column_name="evidence_json",
                        expected_type=dict,
                    )
                    current = evidence.get("current") if evidence else None
                    if not isinstance(current, dict) or not current.get("path"):
                        raise ValueError("accepted-change evidence is invalid")
                    path = str(current["path"])
                    telemetry_matches = [
                        item
                        for item in latest.get("integrity", [])
                        if isinstance(item, dict) and item.get("path") == path
                    ]
                    if len(telemetry_matches) != 1 or not hmac_compare_json(
                        canonical_json_dumps(telemetry_matches[0]),
                        canonical_json_dumps(current),
                    ):
                        raise PermissionError(
                            "accepted change is not the exact current observation"
                        )
                    expected_candidate = dict(prior)
                    expected_candidate["integrity"] = [
                        item
                        for item in prior.get("integrity", [])
                        if isinstance(item, dict) and item.get("path") != path
                    ] + [dict(current)]
                    if not hmac_compare_json(
                        canonical_json_dumps(expected_candidate), candidate_json
                    ):
                        raise ValueError(
                            "accepted change candidate alters unrelated baseline state"
                        )

                promotion_id = str(uuid.uuid4())
                now = time.time()
                if not files:
                    if source != "initial":
                        raise ValueError("accepted change has no integrity capture scope")
                    cursor = self._connection.execute(
                        "UPDATE baselines SET baseline_json=?, created_at=?, "
                        "status='approved', approved_at=? "
                        "WHERE agent_id=? AND status='pending' AND baseline_json=?",
                        (candidate_json, now, now, agent_id, prior_json),
                    )
                    if cursor.rowcount != 1:
                        raise RuntimeError("baseline changed during promotion")
                    status = "completed"
                    action_id = None
                    completed_at: float | None = now
                else:
                    action_id = self.queue_action(
                        agent_id,
                        "capture_restore_point",
                        {"files": files},
                        alert_id,
                        automated=True,
                        expires_at=expires_at,
                        profile_id=profile_id,
                        profile_fingerprint=profile_fingerprint,
                        autonomy_mode=autonomy_mode,
                        binding=binding,
                        _commit=False,
                    )
                    action = self._connection.execute(
                        "SELECT status FROM actions WHERE action_id=?", (action_id,)
                    ).fetchone()
                    if not action or action["status"] != "queued":
                        raise RuntimeError(
                            "an unresolved prior capture prevents promotion retry"
                        )
                    status = "pending"
                    completed_at = None
                self._connection.execute(
                    """
                    INSERT INTO baseline_promotions(
                      promotion_id, agent_id, source, alert_id, candidate_json,
                      candidate_sha256, prior_baseline_sha256, telemetry_sha256,
                      telemetry_observed_at, telemetry_boot_id, telemetry_sequence,
                      credential_epoch, profile_id, profile_fingerprint,
                      agent_version, action_id, status, created_at, updated_at,
                      completed_at
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        promotion_id,
                        agent_id,
                        source,
                        alert_id,
                        candidate_json,
                        candidate_sha256,
                        prior_sha256,
                        telemetry_sha256,
                        float(observed_at),
                        boot_id,
                        sequence,
                        *binding_values,
                        action_id,
                        status,
                        now,
                        now,
                        completed_at,
                    ),
                )
                self.audit(
                    "operator",
                    "begin_baseline_promotion",
                    promotion_id,
                    {
                        "agent_id": agent_id,
                        "source": source,
                        "action_id": action_id,
                        "candidate_sha256": candidate_sha256,
                        "file_count": len(files),
                    },
                )
                self._connection.commit()
                self._finish_quarantine_boundary_locked()
                return {
                    "promotion_id": promotion_id,
                    "status": status,
                    "action_id": action_id,
                }
            except Exception:
                self._rollback_preserving_quarantine_locked()
                raise

    def abort_baseline_promotion(self, agent_id: str) -> dict[str, Any] | None:
        """Idempotently stop candidate promotion without changing its baseline."""

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self._connection.execute(
                    "SELECT * FROM baseline_promotions WHERE agent_id=? "
                    "ORDER BY created_at DESC, promotion_id DESC LIMIT 1",
                    (agent_id,),
                ).fetchone()
                if not row:
                    self._connection.rollback()
                    return None
                if row["status"] == "pending":
                    now = time.time()
                    self._connection.execute(
                        "UPDATE baseline_promotions SET status='aborted', "
                        "failure_reason='operator_aborted', updated_at=?, "
                        "completed_at=? WHERE promotion_id=? AND status='pending'",
                        (now, now, row["promotion_id"]),
                    )
                    if row["action_id"]:
                        self._connection.execute(
                            "UPDATE actions SET status='failed', completed_at=?, "
                            "result_json=?, result_source='controller' "
                            "WHERE action_id=? AND status='queued'",
                            (
                                now,
                                canonical_json_dumps(
                                    {
                                        "success": False,
                                        "message": "baseline promotion aborted before capture delivery",
                                    }
                                ),
                                row["action_id"],
                            ),
                        )
                    self.audit(
                        "operator",
                        "abort_baseline_promotion",
                        str(row["promotion_id"]),
                        {"agent_id": agent_id},
                    )
                    self._connection.commit()
                    return {
                        "promotion_id": str(row["promotion_id"]),
                        "status": "aborted",
                    }
                result = {
                    "promotion_id": str(row["promotion_id"]),
                    "status": str(row["status"]),
                }
                self._connection.rollback()
                return result
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def replace_baseline(
        self,
        agent_id: str,
        telemetry: dict[str, Any],
        binding: dict[str, Any] | None = None,
    ) -> bool:
        epoch, profile_id, profile_fingerprint, agent_version = self._binding_values(
            binding or {}
        )
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE baselines
                SET baseline_json=?, created_at=?, status='pending', approved_at=NULL,
                    credential_epoch=?, profile_id=?, profile_fingerprint=?, agent_version=?
                WHERE agent_id=?
                """,
                (
                    canonical_json_dumps(
                        telemetry, max_bytes=MAX_STORED_JSON_BYTES
                    ),
                    time.time(),
                    epoch,
                    profile_id,
                    profile_fingerprint,
                    agent_version,
                    agent_id,
                ),
            )
            self._connection.commit()
        return cursor.rowcount == 1

    def update_baseline_integrity(
        self,
        agent_id: str,
        current: dict[str, Any],
        binding: dict[str, Any] | None = None,
    ) -> bool:
        """Refuse the retired direct integrity-baseline mutation path."""
        del agent_id, current, binding
        raise PermissionError(
            "integrity baselines require an exact receipt-bound baseline promotion"
        )

    def create_change_grant(
        self,
        agent_id: str,
        path: str,
        ttl_seconds: float = 300.0,
        binding: dict[str, Any] | None = None,
    ) -> str:
        ttl = max(30.0, min(float(ttl_seconds), 900.0))
        now = time.time()
        grant_id = str(uuid.uuid4())
        epoch, profile_id, profile_fingerprint, agent_version = self._binding_values(
            binding or {}
        )
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO change_grants(
                  grant_id, agent_id, path, created_at, expires_at,
                  credential_epoch, profile_id, profile_fingerprint, agent_version
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    grant_id, agent_id, path, now, now + ttl, epoch,
                    profile_id, profile_fingerprint, agent_version,
                ),
            )
            self._connection.commit()
        self.audit("operator", "authorize_monitored_change", grant_id, {"agent_id": agent_id, "path": path, "ttl_seconds": ttl})
        return grant_id

    def consume_change_grant(
        self,
        agent_id: str,
        path: str,
        observed_sha256: str | None = None,
        binding: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Claim one grant and keep it attached to the exact observed change.

        Repeated telemetry for the same change returns the already-claimed grant
        until it expires. A different digest cannot reuse it.
        """
        observation = observed_sha256 or "__missing__"
        expected = self._binding_values(binding or {})
        with self._lock, _ImmediateTransaction(self._connection):
            now = time.time()
            row = self._connection.execute(
                """
                SELECT * FROM change_grants
                WHERE agent_id=? AND path=? AND expires_at>=?
                  AND revoked_at IS NULL
                  AND (used_at IS NULL OR observed_sha256=?)
                ORDER BY CASE WHEN observed_sha256=? THEN 0 ELSE 1 END, created_at
                LIMIT 1
                """,
                (agent_id, path, now, observation, observation),
            ).fetchone()
            if not row:
                self._connection.rollback()
                return None
            if binding is not None and (
                int(row["credential_epoch"]), str(row["profile_id"]),
                str(row["profile_fingerprint"]), str(row["agent_version"]),
            ) != expected:
                self._connection.rollback()
                return None
            first_use = row["used_at"] is None
            if first_use:
                self._connection.execute(
                    """
                    UPDATE change_grants SET used_at=?, observed_sha256=?
                    WHERE grant_id=? AND used_at IS NULL
                    """,
                    (now, observation, row["grant_id"]),
                )
            if first_use:
                self.audit(
                    "policy",
                    "consume_monitored_change",
                    str(row["grant_id"]),
                    {
                        "agent_id": agent_id,
                        "path": path,
                        "observed_sha256": observation,
                    },
                )
            self._connection.commit()
            result = dict(row)
            result["used_at"] = row["used_at"] or now
            result["observed_sha256"] = observation
        return result

    def alert_occurrence_count(self, alert_id: str) -> int:
        with self._lock:
            row = self._connection.execute(
                "SELECT occurrence_count FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone()
        return int(row["occurrence_count"]) if row else 0

    def get_alert(self, alert_id: str) -> sqlite3.Row | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone()
        if not row:
            return None
        evidence = self._decode_stored_json(
            row["evidence_json"],
            table_name="alerts",
            row_key=alert_id,
            column_name="evidence_json",
            expected_type=dict,
        )
        if evidence is None:
            with self._lock:
                self._connection.execute(
                    """
                    UPDATE alerts SET status='decided', decision='json_quarantined',
                      decided_at=? WHERE alert_id=? AND status='open'
                    """,
                    (time.time(), alert_id),
                )
                self._connection.commit()
            return None
        return row

    def change_grants(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(row)
                for row in self._connection.execute(
                    "SELECT * FROM change_grants ORDER BY created_at DESC LIMIT 100"
                )
            ]

    def issue_privileged_authorization(
        self,
        agent_id: str,
        action_type: str,
        subject: str,
        ttl_seconds: float = 120.0,
        binding: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Issue one short-lived code and retain only its digest."""
        ttl = max(30.0, min(float(ttl_seconds), 300.0))
        code = secrets.token_urlsafe(24)
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        authorization_id = str(uuid.uuid4())
        now = time.time()
        epoch, profile_id, profile_fingerprint, agent_version = self._binding_values(
            binding or {}
        )
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO privileged_authorizations(
                  authorization_id, code_hash, agent_id, action_type, subject,
                  created_at, expires_at, credential_epoch, profile_id,
                  profile_fingerprint, agent_version
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    authorization_id, code_hash, agent_id, action_type, subject,
                    now, now + ttl, epoch, profile_id, profile_fingerprint,
                    agent_version,
                ),
            )
            self._connection.commit()
        self.audit(
            "operator",
            "issue_privileged_authorization",
            authorization_id,
            {"agent_id": agent_id, "action_type": action_type, "subject": subject, "ttl_seconds": ttl},
        )
        return {
            "authorization_id": authorization_id,
            "authorization_code": code,
            "agent_id": agent_id,
            "action_type": action_type,
            "subject": subject,
            "expires_at": now + ttl,
        }

    def consume_privileged_authorization(
        self,
        code: str,
        agent_id: str,
        action_type: str,
        subject: str,
        binding: dict[str, Any] | None = None,
        *,
        _commit: bool = True,
    ) -> bool:
        """Atomically consume an exact identity/host/action/subject authorization."""
        if not isinstance(code, str) or len(code) > 256:
            return False
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        expected = self._binding_values(binding or {})
        with self._lock:
            now = time.time()
            clauses = ""
            values: list[Any] = [now, code_hash, agent_id, action_type, subject, now]
            if binding is not None:
                clauses = (
                    " AND credential_epoch=? AND profile_id=? "
                    "AND profile_fingerprint=? AND agent_version=?"
                )
                values.extend(expected)
            cursor = self._connection.execute(
                f"""
                UPDATE privileged_authorizations SET used_at=?
                WHERE code_hash=? AND agent_id=? AND action_type=? AND subject=?
                  AND used_at IS NULL AND revoked_at IS NULL AND expires_at>=?
                  {clauses}
                """,
                values,
            )
            if _commit:
                self._connection.commit()
        accepted = cursor.rowcount == 1
        if _commit:
            self.audit(
                "operator",
                "consume_privileged_authorization" if accepted else "reject_privileged_authorization",
                code_hash[:16],
                {"agent_id": agent_id, "action_type": action_type, "subject": subject},
            )
        return accepted

    def protected_accounts(self, agent_id: str) -> set[str]:
        with self._lock:
            rows = self._connection.execute(
                "SELECT account_name FROM protected_accounts WHERE agent_id IN (?, '*')",
                (agent_id,),
            ).fetchall()
        return {row["account_name"].casefold() for row in rows}

    def protect_account(
        self, agent_id: str, account_name: str, role: str, source: str = "operator"
    ) -> None:
        with self._lock:
            self._connection.execute(
                """
                INSERT INTO protected_accounts(agent_id, account_name, role, source, created_at)
                VALUES(?, ?, ?, ?, ?)
                ON CONFLICT(agent_id, account_name) DO UPDATE SET
                  role=excluded.role, source=excluded.source
                """,
                (agent_id, account_name, role, source, time.time()),
            )
            self._connection.commit()
        self.audit(
            "operator",
            "protect_account",
            f"{agent_id}:{account_name}",
            {"role": role, "source": source},
        )

    def audit(
        self,
        actor: str,
        operation: str,
        subject: str,
        detail: dict[str, Any] | None = None,
    ) -> str:
        audit_id = str(uuid.uuid4())
        with self._lock:
            outer_transaction = self._connection.in_transaction
            try:
                self._connection.execute(
                    """
                    INSERT INTO audit_log(audit_id, actor, operation, subject, detail_json, created_at)
                    VALUES(?, ?, ?, ?, ?, ?)
                    """,
                    (
                        audit_id,
                        str(actor)[:128],
                        str(operation)[:128],
                        str(subject)[:512],
                        canonical_json_dumps(
                            detail or {}, max_bytes=MAX_STORED_JSON_BYTES
                        ),
                        time.time(),
                    ),
                )
                if not outer_transaction:
                    self._connection.commit()
            except Exception:
                if not outer_transaction and self._connection.in_transaction:
                    self._connection.rollback()
                raise
        return audit_id

    def protected_account_rows(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                dict(row)
                for row in self._connection.execute(
                    "SELECT agent_id, account_name, role, source, created_at FROM protected_accounts ORDER BY agent_id, account_name"
                )
            ]

    @staticmethod
    def _exact_candidate_lineage(
        candidate: AlertCandidate,
    ) -> tuple[str, str, str, str]:
        """Return canonical candidate/features JSON and their exact digests."""
        from .validation import (
            ExactModelFeatures,
            MODEL_FEATURE_BINDING_FIELD,
            MODEL_FEATURE_SCHEMA_SHA256,
        )

        raw_features = getattr(candidate, "model_features", None)
        exact = ExactModelFeatures(raw_features)
        if getattr(candidate, "model_features_sha256", "") != exact.sha256:
            raise ValueError("alert candidate model feature digest is inconsistent")
        evidence = candidate.evidence
        if not isinstance(evidence, dict):
            raise ValueError("alert candidate evidence must be an object")
        expected_binding = exact.as_binding()
        if evidence.get(MODEL_FEATURE_BINDING_FIELD) != expected_binding:
            raise ValueError("alert candidate evidence feature binding is inconsistent")
        confidence = candidate.confidence
        if (
            type(confidence) not in {int, float}
            or not math.isfinite(confidence)
            or not 0.0 <= float(confidence) <= 1.0
        ):
            raise ValueError("alert candidate confidence is invalid")
        features_json = canonical_json_dumps(exact.as_dict())
        candidate_json = canonical_json_dumps(
            {
                "schema": 1,
                "kind": candidate.kind,
                "title": candidate.title,
                "summary": candidate.summary,
                "severity": candidate.severity,
                "confidence": float(confidence),
                "evidence": evidence,
                "recommendation": candidate.recommendation,
                "recommended_action": candidate.recommended_action,
                "features_sha256": exact.sha256,
                "feature_schema_sha256": MODEL_FEATURE_SCHEMA_SHA256,
            },
            max_bytes=MAX_STORED_JSON_BYTES,
        )
        return (
            candidate_json,
            hashlib.sha256(candidate_json.encode()).hexdigest(),
            features_json,
            exact.sha256,
        )

    @staticmethod
    def _incident_group_id(
        agent_id: str,
        binding_values: tuple[int, str, str, str],
        candidate: AlertCandidate,
    ) -> str:
        """Group related variants without using volatile evidence values."""
        evidence = candidate.evidence if isinstance(candidate.evidence, dict) else {}
        kind = str(candidate.kind)
        subject: Any
        if kind == "critical_file_changed":
            subject = {"path": evidence.get("path")}
        elif kind in {"baseline_service_stopped", "service_startup_disabled", "service_restart_loop"}:
            subject = {"service": evidence.get("service")}
        elif kind == "service_probe_failed":
            probe = evidence.get("probe", {})
            subject = {
                "name": probe.get("name") if isinstance(probe, dict) else None,
                "target": probe.get("target") if isinstance(probe, dict) else None,
            }
        elif kind in {"unverified_privileged_account", "privilege_membership_changed"}:
            account = evidence.get("account", {})
            subject = {
                "account": account.get("name") if isinstance(account, dict) else None
            }
        elif kind == "unverified_privileged_session":
            session = evidence.get("session", {})
            subject = {
                "username": session.get("username") if isinstance(session, dict) else None,
                "source": session.get("source") if isinstance(session, dict) else None,
            }
        elif kind == "new_network_listener":
            listener = evidence.get("listener", {})
            subject = {
                name: listener.get(name) if isinstance(listener, dict) else None
                for name in ("protocol", "address", "port")
            }
        elif kind in {"persistence_changed", "new_persistence_item"}:
            persistence = evidence.get("persistence", {})
            subject = {
                name: persistence.get(name) if isinstance(persistence, dict) else None
                for name in ("kind", "name")
            }
        else:
            # A broad kind-level group is safer than splitting attack variants
            # across training and holdout on volatile evidence.
            subject = {"kind": kind}
        encoded = canonical_json_dumps(
            ["sentinel-blue-incident-group-v1", agent_id, *binding_values, kind, subject],
            max_bytes=64 * 1024,
        )
        return hashlib.sha256(encoded.encode()).hexdigest()

    def _insert_alert_occurrence_locked(
        self,
        *,
        occurrence_id: str,
        alert_id: str,
        observation: sqlite3.Row | None,
        incident_group_id: str,
        occurrence_index: int,
        candidate: AlertCandidate,
        candidate_lineage: tuple[str, str, str, str] | None,
    ) -> None:
        if observation is None or candidate_lineage is None:
            raise ValueError("alert occurrence requires exact telemetry and candidate lineage")
        from .validation import MODEL_FEATURE_SCHEMA_SHA256

        candidate_json, candidate_sha256, features_json, features_sha256 = (
            candidate_lineage
        )
        self._connection.execute(
            """
            INSERT INTO alert_occurrences(
              occurrence_id, alert_id, observation_id, agent_id,
              incident_group_id, occurrence_index, candidate_json,
              candidate_sha256, features_json, features_sha256,
              feature_schema_sha256, kind, observed_at, credential_epoch,
              profile_id, profile_fingerprint, agent_version, campaign_id,
              release_sha256, model_fingerprint, admission_status
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'eligible')
            """,
            (
                occurrence_id,
                alert_id,
                observation["observation_id"],
                observation["agent_id"],
                incident_group_id,
                occurrence_index,
                candidate_json,
                candidate_sha256,
                features_json,
                features_sha256,
                MODEL_FEATURE_SCHEMA_SHA256,
                str(candidate.kind),
                observation["observed_at"],
                observation["credential_epoch"],
                observation["profile_id"],
                observation["profile_fingerprint"],
                observation["agent_version"],
                observation["campaign_id"],
                observation["release_sha256"],
                observation["model_fingerprint"],
            ),
        )

    def add_alert(
        self,
        agent_id: str,
        candidate: AlertCandidate,
        *,
        binding: dict[str, Any] | None = None,
        release_sha256: str = "",
        model_fingerprint: str = "",
        campaign_id: str = "",
        observation_id: str = "",
    ) -> str | None:
        """Add or coalesce an alert within severity-reserved per-agent quotas.

        Returning ``None`` means that a new open alert could not be admitted.
        Existing matching alerts are always updated, even when the quota is
        full, so repeat evidence is not lost or multiplied.
        """
        evidence = candidate.evidence
        semantic: Any = evidence
        if candidate.kind == "service_probe_failed":
            probe = evidence.get("probe", {})
            semantic = {"name": probe.get("name"), "target": probe.get("target")}
        elif candidate.kind == "unverified_privileged_account":
            semantic = {"account": evidence.get("account", {}).get("name")}
        elif candidate.kind == "unverified_privileged_session":
            session = evidence.get("session", {})
            semantic = {
                "username": session.get("username"),
                "source": session.get("source"),
                "session_id": session.get("session_id"),
            }
        elif candidate.kind == "baseline_service_stopped":
            semantic = {"service": evidence.get("service")}
        elif candidate.kind == "critical_file_changed":
            semantic = {
                "path": evidence.get("path"),
                "observed_sha256": evidence.get("observed_sha256"),
                "observed_security_descriptor_sha256": evidence.get(
                    "observed_security_descriptor_sha256"
                ),
            }
        elif candidate.kind == "new_network_listener":
            listener = evidence.get("listener", {})
            semantic = {
                "protocol": listener.get("protocol"),
                "address": listener.get("address"),
                "port": listener.get("port"),
            }
        binding_values = self._binding_values(binding or {})
        fingerprint_source = canonical_json_dumps(
            [agent_id, *binding_values, candidate.kind, semantic],
            max_bytes=MAX_STORED_JSON_BYTES,
        )
        fingerprint = str(uuid.uuid5(uuid.NAMESPACE_URL, fingerprint_source))
        alert_id = str(uuid.uuid4())
        now = time.time()
        candidate_lineage: tuple[str, str, str, str] | None = None
        occurrence_id = ""
        incident_group_id = ""
        if observation_id and binding is not None:
            for name, value in (
                ("release_sha256", release_sha256),
                ("model_fingerprint", model_fingerprint),
            ):
                if (
                    not isinstance(value, str)
                    or len(value) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in value
                    )
                ):
                    raise ValueError(f"alert {name} is invalid")
            if (
                not isinstance(campaign_id, str)
                or not 1 <= len(campaign_id) <= 128
                or any(
                    not (character.isalnum() or character in "_.:@+-")
                    for character in campaign_id
                )
            ):
                raise ValueError("alert campaign_id is invalid")
            if (
                not isinstance(observation_id, str)
                or len(observation_id) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in observation_id
                )
            ):
                raise ValueError("alert observation_id is invalid")
            candidate_lineage = self._exact_candidate_lineage(candidate)
            occurrence_id = str(
                uuid.uuid5(
                    uuid.NAMESPACE_URL,
                    canonical_json_dumps(
                        [
                            "sentinel-blue-alert-occurrence-v1",
                            observation_id,
                            candidate_lineage[1],
                        ]
                    ),
                )
            )
            incident_group_id = self._incident_group_id(
                agent_id, binding_values, candidate
            )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                if binding is not None:
                    current_agent = self._connection.execute(
                        """
                        SELECT enabled, credential_epoch, profile_id,
                               profile_fingerprint, agent_version
                        FROM agents WHERE agent_id=?
                        """,
                        (agent_id,),
                    ).fetchone()
                    try:
                        current_values = (
                            int(current_agent["credential_epoch"]),
                            str(current_agent["profile_id"]),
                            str(current_agent["profile_fingerprint"]),
                            str(current_agent["agent_version"]),
                        ) if current_agent else None
                    except (TypeError, ValueError, OverflowError):
                        current_values = None
                    if (
                        not current_agent
                        or type(current_agent["enabled"]) is not int
                        or current_agent["enabled"] != 1
                        or current_values != binding_values
                    ):
                        self._connection.rollback()
                        return None

                lineage_enabled = False
                observation: sqlite3.Row | None = None
                if candidate_lineage is not None:
                    from .validation import MODEL_FEATURE_SCHEMA_SHA256

                    observation = self._connection.execute(
                        "SELECT * FROM telemetry_observations WHERE observation_id=?",
                        (observation_id,),
                    ).fetchone()
                    if observation is None:
                        raise ValueError("alert observation lineage is unavailable")
                    if observation["admission_status"] == "eligible":
                        expected_observation = (
                            agent_id,
                            *binding_values,
                            str(release_sha256),
                            str(model_fingerprint),
                            str(campaign_id),
                            MODEL_FEATURE_SCHEMA_SHA256,
                            str(observation_id),
                        )
                        actual_observation = (
                            str(observation["agent_id"]),
                            int(observation["credential_epoch"]),
                            str(observation["profile_id"]),
                            str(observation["profile_fingerprint"]),
                            str(observation["agent_version"]),
                            str(observation["release_sha256"]),
                            str(observation["model_fingerprint"]),
                            str(observation["campaign_id"]),
                            str(observation["feature_schema_sha256"]),
                            str(observation["telemetry_sha256"]),
                        )
                        if actual_observation != expected_observation:
                            raise ValueError("alert observation provenance is inconsistent")
                        lineage_enabled = True
                    elif observation["admission_status"] != "quarantined":
                        raise ValueError("alert observation admission state is invalid")

                existing = self._connection.execute(
                    "SELECT alert_id, last_observation_id, occurrence_count FROM alerts "
                    "WHERE agent_id=? AND fingerprint=? AND status='open'",
                    (agent_id, fingerprint),
                ).fetchone()
                if existing:
                    if lineage_enabled:
                        duplicate = self._connection.execute(
                            "SELECT alert_id, candidate_sha256 FROM alert_occurrences "
                            "WHERE observation_id=? AND alert_id=?",
                            (observation_id, existing["alert_id"]),
                        ).fetchone()
                        if duplicate:
                            if not hmac.compare_digest(
                                str(duplicate["candidate_sha256"]),
                                candidate_lineage[1],
                            ):
                                raise ValueError(
                                    "one alert observation produced conflicting candidates"
                                )
                            self._connection.rollback()
                            return str(existing["alert_id"])
                        occurrence_index = int(existing["occurrence_count"]) + 1
                        self._insert_alert_occurrence_locked(
                            occurrence_id=occurrence_id,
                            alert_id=str(existing["alert_id"]),
                            observation=observation,
                            incident_group_id=incident_group_id,
                            occurrence_index=occurrence_index,
                            candidate=candidate,
                            candidate_lineage=candidate_lineage,
                        )
                        cursor = self._connection.execute(
                            "UPDATE alert_lineage SET last_occurrence_id=?, updated_at=? "
                            "WHERE alert_id=?",
                            (occurrence_id, now, existing["alert_id"]),
                        )
                        if cursor.rowcount != 1:
                            raise ValueError("alert lineage is unavailable")
                    elif observation_id and hmac.compare_digest(
                        str(existing["last_observation_id"]), str(observation_id)
                    ):
                        self._connection.rollback()
                        return str(existing["alert_id"])
                    self._connection.execute(
                        """
                        UPDATE alerts SET occurrence_count=occurrence_count+1,
                          last_observed_at=?, last_observation_id=?
                        WHERE alert_id=?
                        """,
                        (now, str(observation_id), existing["alert_id"]),
                    )
                    self._connection.commit()
                    return str(existing["alert_id"])

                recent = self._connection.execute(
                    """
                    SELECT alert_id FROM alerts
                    WHERE agent_id=? AND fingerprint=? AND decided_at IS NOT NULL AND decided_at>?
                      AND COALESCE(decision, '')!='automatic_restore'
                    ORDER BY decided_at DESC LIMIT 1
                    """,
                    (agent_id, fingerprint, now - 900),
                ).fetchone()
                if recent:
                    self._connection.rollback()
                    return str(recent["alert_id"])
                severity = str(candidate.severity).casefold()
                counts = {
                    str(row["severity"]).casefold(): int(row["count"])
                    for row in self._connection.execute(
                        """
                        SELECT severity, COUNT(*) AS count FROM alerts
                        WHERE agent_id=? AND status='open' GROUP BY severity
                        """,
                        (agent_id,),
                    ).fetchall()
                }
                total_open = sum(counts.values())
                severity_limit = OPEN_ALERT_LIMITS_BY_SEVERITY.get(
                    severity, OPEN_ALERT_LIMITS_BY_SEVERITY["low"]
                )
                if (
                    total_open >= MAX_OPEN_ALERTS_PER_AGENT
                    or counts.get(severity, 0) >= severity_limit
                ):
                    self._connection.rollback()
                    return None
                self._connection.execute(
                    """
                    INSERT INTO alerts(
                      alert_id, agent_id, kind, title, summary, severity, confidence,
                      evidence_json, recommendation, recommended_action, fingerprint, status,
                      created_at, last_observed_at, credential_epoch, profile_id,
                      profile_fingerprint, agent_version, release_sha256,
                      model_fingerprint, campaign_id, last_observation_id
                    ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        alert_id,
                        agent_id,
                        candidate.kind,
                        candidate.title,
                        candidate.summary,
                        candidate.severity,
                        candidate.confidence,
                        canonical_json_dumps(
                            candidate.evidence, max_bytes=MAX_STORED_JSON_BYTES
                        ),
                        candidate.recommendation,
                        candidate.recommended_action,
                        fingerprint,
                        now,
                        now,
                        *binding_values,
                        str(release_sha256),
                        str(model_fingerprint),
                        str(campaign_id),
                        str(observation_id),
                    ),
                )
                if lineage_enabled:
                    self._insert_alert_occurrence_locked(
                        occurrence_id=occurrence_id,
                        alert_id=alert_id,
                        observation=observation,
                        incident_group_id=incident_group_id,
                        occurrence_index=1,
                        candidate=candidate,
                        candidate_lineage=candidate_lineage,
                    )
                    self._connection.execute(
                        "INSERT INTO alert_lineage(alert_id, creation_occurrence_id, "
                        "last_occurrence_id, updated_at) VALUES(?, ?, ?, ?)",
                        (alert_id, occurrence_id, occurrence_id, now),
                    )
                self._connection.commit()
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise
        return alert_id

    def resolve_alert(self, alert_id: str, decision: str) -> bool:
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE alerts SET status='decided', decision=?, decided_at=?
                WHERE alert_id=? AND status='open'
                """,
                (decision, time.time(), alert_id),
            )
            self._connection.commit()
        if cursor.rowcount:
            self.audit("policy", "resolve_alert", alert_id, {"decision": decision})
        return cursor.rowcount == 1

    def resolve_heartbeat_alerts(
        self, agent_id: str, binding: dict[str, Any] | None = None
    ) -> int:
        """Close stale-host evidence when the same exact authority resumes."""
        clauses = ""
        values: list[Any] = [time.time(), agent_id]
        if binding is not None:
            clauses = (
                " AND credential_epoch=? AND profile_id=? "
                "AND profile_fingerprint=? AND agent_version=?"
            )
            values.extend(self._binding_values(binding))
        with self._lock:
            cursor = self._connection.execute(
                """
                UPDATE alerts SET status='decided', decision='telemetry_resumed',
                                  decided_at=?
                WHERE agent_id=? AND kind='agent_heartbeat_missing'
                  AND status='open'
                """ + clauses,
                values,
            )
            self._connection.commit()
        if cursor.rowcount:
            self.audit(
                "policy",
                "resolve_heartbeat_alerts",
                agent_id,
                {"resolved": cursor.rowcount},
            )
        return int(cursor.rowcount)

    def decide_alert(
        self,
        alert_id: str,
        decision: str,
        binding: dict[str, Any] | None = None,
        *,
        _commit: bool = True,
    ) -> sqlite3.Row | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM alerts WHERE alert_id=?", (alert_id,)
            ).fetchone()
            if not row or row["status"] != "open":
                return None
            if binding is not None and (
                int(row["credential_epoch"]),
                str(row["profile_id"]),
                str(row["profile_fingerprint"]),
                str(row["agent_version"]),
            ) != self._binding_values(binding):
                return None
            clauses = ""
            values: list[Any] = [decision, time.time(), alert_id]
            if binding is not None:
                clauses = (
                    " AND credential_epoch=? AND profile_id=? "
                    "AND profile_fingerprint=? AND agent_version=?"
                )
                values.extend(self._binding_values(binding))
            cursor = self._connection.execute(
                "UPDATE alerts SET status='decided', decision=?, decided_at=? "
                "WHERE alert_id=? AND status='open'" + clauses,
                values,
            )
            if _commit:
                self._connection.commit()
            if cursor.rowcount != 1:
                return None
            self.audit("operator", f"alert_{decision}", alert_id, {"kind": row["kind"]})
            return row

    def alert_learning_lineage(self, alert_id: str) -> dict[str, Any] | None:
        """Return the immutable creation and current occurrence identifiers."""
        with self._lock:
            row = self._connection.execute(
                """
                SELECT l.alert_id, l.creation_occurrence_id,
                       l.last_occurrence_id, l.updated_at,
                       c.candidate_sha256 AS creation_candidate_sha256,
                       c.observation_id AS creation_observation_id,
                       n.candidate_sha256 AS last_candidate_sha256,
                       n.observation_id AS last_observation_id
                FROM alert_lineage l
                JOIN alert_occurrences c
                  ON c.occurrence_id=l.creation_occurrence_id
                 AND c.alert_id=l.alert_id
                JOIN alert_occurrences n
                  ON n.occurrence_id=l.last_occurrence_id
                 AND n.alert_id=l.alert_id
                WHERE l.alert_id=?
                """,
                (alert_id,),
            ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _learning_principal(value: str, label: str) -> str:
        if (
            not isinstance(value, str)
            or not 1 <= len(value) <= 128
            or any(
                not (character.isalnum() or character in "_.:@+-")
                for character in value
            )
        ):
            raise ValueError(f"learning {label} is invalid")
        return value

    def _record_learning_label_locked(
        self,
        *,
        alert_id: str,
        occurrence_id: str,
        decision: str,
        label: int,
        reviewer_principal_id: str,
        label_source: str,
        expected_kind: str | None = None,
        expected_features: dict[str, float] | None = None,
    ) -> str:
        """Insert one exact label by copying immutable occurrence authority."""
        if type(label) is not int or label not in {0, 1}:
            raise ValueError("learning label must be exactly zero or one")
        reviewer = self._learning_principal(
            reviewer_principal_id, "reviewer principal"
        )
        source = self._learning_principal(label_source, "label source")
        row = self._connection.execute(
            """
            SELECT a.alert_id, a.kind AS alert_kind, a.status, a.decision,
                   l.creation_occurrence_id, l.last_occurrence_id,
                   o.*, t.telemetry_json, t.telemetry_sha256,
                   t.admission_status AS telemetry_admission_status
            FROM alerts a
            JOIN alert_lineage l ON l.alert_id=a.alert_id
            JOIN alert_occurrences o
              ON o.occurrence_id=? AND o.alert_id=a.alert_id
            JOIN telemetry_observations t
              ON t.observation_id=o.observation_id
            WHERE a.alert_id=?
            """,
            (occurrence_id, alert_id),
        ).fetchone()
        if row is None:
            raise ValueError("learning occurrence lineage is unavailable")
        if row["status"] != "decided" or row["decision"] != decision:
            raise ValueError("learning decision does not match the decided alert")
        # The operational alert row displays its creation evidence. Until the
        # controller explicitly presents another immutable occurrence, only
        # that creation occurrence can receive the decision label.
        if occurrence_id != row["creation_occurrence_id"]:
            raise ValueError("learning decision occurrence was not the displayed evidence")
        if row["admission_status"] != "eligible" or row[
            "telemetry_admission_status"
        ] != "eligible":
            raise ValueError("learning occurrence is not eligible")
        if expected_kind is not None and (
            expected_kind != row["kind"] or row["kind"] != row["alert_kind"]
        ):
            raise ValueError("learning kind does not match the stored occurrence")
        try:
            features = _learning_features(
                strict_json_loads(
                    str(row["features_json"]), max_bytes=MAX_STORED_JSON_BYTES
                )
            )
        except ValueError as exc:
            raise ValueError("stored learning occurrence features are invalid") from exc
        features_json = canonical_json_dumps(features)
        if (
            hashlib.sha256(features_json.encode()).hexdigest()
            != row["features_sha256"]
        ):
            # The feature digest uses the schema-bound representation rather
            # than raw JSON alone; validate it through the canonical primitive.
            from .validation import ExactModelFeatures

            if ExactModelFeatures(features).sha256 != row["features_sha256"]:
                raise ValueError("stored learning occurrence feature digest changed")
        if expected_features is not None and _learning_features(
            expected_features
        ) != features:
            raise ValueError("caller-supplied features do not match the scored occurrence")
        candidate_raw = str(row["candidate_json"])
        telemetry_raw = str(row["telemetry_json"])
        if hashlib.sha256(candidate_raw.encode()).hexdigest() != row[
            "candidate_sha256"
        ]:
            raise ValueError("stored alert candidate digest changed")
        if hashlib.sha256(telemetry_raw.encode()).hexdigest() != row[
            "telemetry_sha256"
        ]:
            raise ValueError("stored telemetry observation digest changed")
        quarantined = self._connection.execute(
            """
            SELECT 1 FROM json_quarantine
            WHERE (table_name='alerts' AND row_key=?)
               OR (table_name='alert_occurrences' AND row_key=?)
               OR (table_name='telemetry_observations' AND row_key=?)
            LIMIT 1
            """,
            (alert_id, occurrence_id, row["observation_id"]),
        ).fetchone()
        if quarantined:
            raise ValueError("learning lineage is quarantined")
        label_id = str(
            uuid.uuid5(
                uuid.NAMESPACE_URL,
                f"sentinel-blue-learning-label-v1:{occurrence_id}",
            )
        )
        existing = self._connection.execute(
            "SELECT * FROM learning_labels WHERE occurrence_id=?",
            (occurrence_id,),
        ).fetchone()
        expected = (
            label_id,
            alert_id,
            occurrence_id,
            str(row["kind"]),
            decision,
            label,
            reviewer,
            source,
            "eligible",
        )
        if existing:
            actual = (
                str(existing["label_id"]),
                str(existing["alert_id"]),
                str(existing["occurrence_id"]),
                str(existing["kind"]),
                str(existing["decision"]),
                int(existing["label"]),
                str(existing["reviewer_principal_id"]),
                str(existing["label_source"]),
                str(existing["provenance_status"]),
            )
            if actual != expected:
                raise ValueError("learning occurrence already has a conflicting label")
            return label_id
        count = int(
            self._connection.execute(
                "SELECT COUNT(*) FROM learning_labels"
            ).fetchone()[0]
        )
        if count >= MAX_LEARNING_FEEDBACK:
            raise OverflowError("immutable learning label ledger is full")
        self._connection.execute(
            """
            INSERT INTO learning_labels(
              label_id, alert_id, occurrence_id, kind, decision, label,
              reviewer_principal_id, label_source, created_at,
              provenance_status
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 'eligible')
            """,
            (
                label_id,
                alert_id,
                occurrence_id,
                row["kind"],
                decision,
                label,
                reviewer,
                source,
                time.time(),
            ),
        )
        return label_id

    def decide_alert_with_learning_label(
        self,
        alert_id: str,
        decision: str,
        label: int,
        *,
        occurrence_id: str,
        reviewer_principal_id: str,
        label_source: str,
        binding: dict[str, Any] | None = None,
    ) -> sqlite3.Row | None:
        """Atomically decide an alert and label its exact displayed occurrence."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self.decide_alert(
                    alert_id, decision, binding=binding, _commit=False
                )
                if row is None:
                    self._connection.rollback()
                    return None
                self._record_learning_label_locked(
                    alert_id=alert_id,
                    occurrence_id=occurrence_id,
                    decision=decision,
                    label=label,
                    reviewer_principal_id=reviewer_principal_id,
                    label_source=label_source,
                )
                self._connection.commit()
                return row
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def decide_alert_with_feedback(
        self,
        alert_id: str,
        decision: str,
        kind: str,
        label: int,
        features: dict[str, float],
        *,
        binding: dict[str, Any] | None = None,
        reviewer: str = "operator",
        source: str = "controller-decision",
        occurrence_id: str | None = None,
        reviewer_principal_id: str | None = None,
    ) -> sqlite3.Row | None:
        """Commit the decision, immutable provenance, and audit as one CAS."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                row = self.decide_alert(
                    alert_id, decision, binding=binding, _commit=False
                )
                if row is None:
                    self._connection.rollback()
                    return None
                self.record_feedback(
                    alert_id,
                    kind,
                    decision,
                    label,
                    features,
                    reviewer=reviewer,
                    source=source,
                    occurrence_id=occurrence_id,
                    reviewer_principal_id=reviewer_principal_id,
                    _commit=False,
                )
                self._connection.commit()
                return row
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def record_feedback(
        self,
        alert_id: str,
        kind: str,
        decision: str,
        label: int,
        features: dict[str, float],
        *,
        reviewer: str = "operator",
        source: str = "controller-decision",
        occurrence_id: str | None = None,
        reviewer_principal_id: str | None = None,
        _commit: bool = True,
    ) -> None:
        """Persist immutable feedback, copying provenance from the decided alert."""
        if type(label) is not int or label not in {0, 1}:
            raise ValueError("learning label must be exactly zero or one")
        if not isinstance(decision, str) or not decision or len(decision) > 128:
            raise ValueError("learning decision is invalid")
        if (
            not isinstance(reviewer, str)
            or not reviewer
            or len(reviewer) > 128
            or not isinstance(source, str)
            or not source
            or len(source) > 128
        ):
            raise ValueError("learning reviewer/source provenance is invalid")
        bounded_features = _learning_features(features)
        feedback_id = str(
            uuid.uuid5(uuid.NAMESPACE_URL, f"{alert_id}:{decision}:{label}")
        )
        now = time.time()
        with self._lock:
            alert = self._connection.execute(
                """
                SELECT agent_id, kind, decision, status, credential_epoch,
                       profile_id, profile_fingerprint, agent_version,
                       campaign_id, release_sha256, model_fingerprint
                FROM alerts WHERE alert_id=?
                """,
                (alert_id,),
            ).fetchone()
            lineage = self._connection.execute(
                "SELECT creation_occurrence_id FROM alert_lineage WHERE alert_id=?",
                (alert_id,),
            ).fetchone()
            if lineage is not None:
                if occurrence_id is None:
                    raise ValueError(
                        "bound learning feedback requires an exact occurrence_id"
                    )
                self._record_learning_label_locked(
                    alert_id=alert_id,
                    occurrence_id=occurrence_id,
                    decision=decision,
                    label=label,
                    reviewer_principal_id=(
                        reviewer_principal_id
                        if reviewer_principal_id is not None
                        else reviewer
                    ),
                    label_source=source,
                    expected_kind=kind,
                    expected_features=bounded_features,
                )
                if _commit:
                    self._connection.commit()
                return
            provenance_status = "quarantined"
            provenance_reason = "legacy-unbound"
            values = {
                "agent_id": "",
                "credential_epoch": -1,
                "profile_id": "",
                "profile_fingerprint": "",
                "agent_version": "",
                "campaign_id": "",
                "release_sha256": "",
                "model_fingerprint": "",
            }
            if alert is not None:
                values = {
                    "agent_id": str(alert["agent_id"]),
                    "credential_epoch": int(alert["credential_epoch"]),
                    "profile_id": str(alert["profile_id"]),
                    "profile_fingerprint": str(alert["profile_fingerprint"]),
                    "agent_version": str(alert["agent_version"]),
                    "campaign_id": str(alert["campaign_id"]),
                    "release_sha256": str(alert["release_sha256"]),
                    "model_fingerprint": str(alert["model_fingerprint"]),
                }
                digest_fields = (
                    values["profile_fingerprint"],
                    values["release_sha256"],
                    values["model_fingerprint"],
                )
                exact_alert = (
                    decision
                    in {"approve", "mark_protected", "reject", "accept_change"}
                    and
                    alert["status"] == "decided"
                    and alert["decision"] == decision
                    and alert["kind"] == kind
                    and values["agent_id"] != ""
                    and 0 <= values["credential_epoch"] <= 2**63 - 1
                    and values["profile_id"] != ""
                    and values["agent_version"] != ""
                    and values["campaign_id"] != ""
                    and all(
                        len(value) == 64
                        and all(
                            character in "0123456789abcdef"
                            for character in value
                        )
                        for value in digest_fields
                    )
                )
                if exact_alert:
                    provenance_status = "eligible"
                    provenance_reason = ""
                else:
                    provenance_reason = "alert-provenance-incomplete"
            self._connection.execute(
                """
                INSERT INTO learning_feedback(
                  feedback_id, alert_id, kind, label, features_json, decision,
                  created_at, agent_id, credential_epoch, profile_id,
                  profile_fingerprint, agent_version, campaign_id,
                  release_sha256, model_fingerprint, reviewer, source,
                  provenance_status, provenance_reason
                ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(feedback_id) DO NOTHING
                """,
                (
                    feedback_id,
                    alert_id,
                    kind,
                    label,
                    canonical_json_dumps(bounded_features),
                    decision,
                    now,
                    values["agent_id"],
                    values["credential_epoch"],
                    values["profile_id"],
                    values["profile_fingerprint"],
                    values["agent_version"],
                    values["campaign_id"],
                    values["release_sha256"],
                    values["model_fingerprint"],
                    reviewer,
                    source,
                    provenance_status,
                    provenance_reason,
                ),
            )
            if _commit:
                self._connection.commit()

    def learning_samples(
        self,
        *,
        provenance_filter: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return only fully revalidated immutable occurrence-bound labels.

        This is the sole deployable-learning reader.  Legacy tuple feedback,
        incomplete provenance, and any row named by durable JSON quarantine are
        permanently excluded instead of being repaired or reinterpreted.
        """
        expected_fields = {
            "campaign_id",
            "profile_id",
            "profile_fingerprint",
            "release_sha256",
            "agent_version",
            "model_fingerprint",
        }
        if not isinstance(provenance_filter, dict) or set(
            provenance_filter
        ) != expected_fields:
            raise ValueError("learning provenance filter is incomplete")
        normalized: dict[str, str] = {}
        for name in expected_fields:
            value = provenance_filter[name]
            if (
                not isinstance(value, str)
                or not value
                or len(value) > 128
                or any(
                    not (character.isalnum() or character in "_.:@+-")
                    for character in value
                )
            ):
                raise ValueError(f"learning provenance filter {name} is invalid")
            normalized[name] = (
                value.casefold()
                if name.endswith("sha256") or name.endswith("fingerprint")
                else value
            )
        for name in (
            "profile_fingerprint",
            "release_sha256",
            "model_fingerprint",
        ):
            if (
                len(normalized[name]) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in normalized[name]
                )
            ):
                raise ValueError(f"learning provenance filter {name} is invalid")
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT
                  l.label_id, l.alert_id, l.occurrence_id,
                  l.kind AS label_kind, l.decision, l.label,
                  l.reviewer_principal_id, l.label_source,
                  o.observation_id, o.agent_id AS occurrence_agent_id,
                  o.incident_group_id, o.candidate_json, o.candidate_sha256,
                  o.features_json, o.features_sha256,
                  o.feature_schema_sha256 AS occurrence_feature_schema_sha256,
                  o.kind AS occurrence_kind, o.observed_at AS occurrence_observed_at,
                  o.credential_epoch AS occurrence_credential_epoch,
                  o.profile_id AS occurrence_profile_id,
                  o.profile_fingerprint AS occurrence_profile_fingerprint,
                  o.agent_version AS occurrence_agent_version,
                  o.campaign_id AS occurrence_campaign_id,
                  o.release_sha256 AS occurrence_release_sha256,
                  o.model_fingerprint AS occurrence_model_fingerprint,
                  t.telemetry_json, t.telemetry_sha256,
                  t.agent_id AS telemetry_agent_id,
                  t.observed_at AS telemetry_observed_at,
                  t.queued_at AS telemetry_queued_at,
                  t.boot_id AS telemetry_boot_id,
                  t.sequence AS telemetry_sequence,
                  t.credential_epoch AS telemetry_credential_epoch,
                  t.profile_id AS telemetry_profile_id,
                  t.profile_fingerprint AS telemetry_profile_fingerprint,
                  t.agent_version AS telemetry_agent_version,
                  t.campaign_id AS telemetry_campaign_id,
                  t.release_sha256 AS telemetry_release_sha256,
                  t.model_fingerprint AS telemetry_model_fingerprint,
                  t.feature_schema_sha256 AS telemetry_feature_schema_sha256
                FROM learning_labels l
                JOIN alert_occurrences o
                  ON o.occurrence_id=l.occurrence_id
                 AND o.alert_id=l.alert_id
                JOIN telemetry_observations t
                  ON t.observation_id=o.observation_id
                WHERE l.provenance_status='eligible'
                  AND o.admission_status='eligible'
                  AND t.admission_status='eligible'
                  AND o.campaign_id=?
                  AND o.profile_id=?
                  AND o.profile_fingerprint=?
                  AND o.release_sha256=?
                  AND o.agent_version=?
                  AND o.model_fingerprint=?
                  AND NOT EXISTS (
                    SELECT 1 FROM json_quarantine q
                    WHERE q.state='open' AND (
                      (q.table_name='alerts' AND q.row_key=l.alert_id)
                      OR (q.table_name='alert_occurrences'
                          AND q.row_key=l.occurrence_id)
                      OR (q.table_name='telemetry_observations'
                          AND q.row_key=o.observation_id)
                      OR (q.table_name='learning_labels'
                          AND q.row_key=l.label_id)
                    )
                  )
                ORDER BY l.created_at, l.label_id
                LIMIT ?
                """,
                (
                    normalized["campaign_id"],
                    normalized["profile_id"],
                    normalized["profile_fingerprint"],
                    normalized["release_sha256"],
                    normalized["agent_version"],
                    normalized["model_fingerprint"],
                    MAX_LEARNING_FEEDBACK,
                ),
            ).fetchall()

        from .validation import (
            ExactModelFeatures,
            MODEL_FEATURE_BINDING_FIELD,
            MODEL_FEATURE_SCHEMA_SHA256,
        )

        samples: list[dict[str, Any]] = []
        candidate_fields = {
            "schema",
            "kind",
            "title",
            "summary",
            "severity",
            "confidence",
            "evidence",
            "recommendation",
            "recommended_action",
            "features_sha256",
            "feature_schema_sha256",
        }
        for row in rows:
            occurrence_id = str(row["occurrence_id"])
            observation_id = str(row["observation_id"])
            label_id = str(row["label_id"])
            try:
                features_payload = strict_json_loads(
                    str(row["features_json"]), max_bytes=MAX_STORED_JSON_BYTES
                )
                exact_features = ExactModelFeatures(features_payload)
                if not hmac.compare_digest(
                    exact_features.sha256, str(row["features_sha256"])
                ):
                    raise ValueError("stored learning feature digest changed")
                candidate_raw = str(row["candidate_json"])
                if not hmac.compare_digest(
                    hashlib.sha256(candidate_raw.encode()).hexdigest(),
                    str(row["candidate_sha256"]),
                ):
                    raise ValueError("stored alert candidate digest changed")
                candidate = strict_json_loads(
                    candidate_raw, max_bytes=MAX_STORED_JSON_BYTES
                )
                if (
                    not isinstance(candidate, dict)
                    or set(candidate) != candidate_fields
                    or candidate.get("schema") != 1
                    or candidate.get("features_sha256") != exact_features.sha256
                    or candidate.get("feature_schema_sha256")
                    != MODEL_FEATURE_SCHEMA_SHA256
                    or not isinstance(candidate.get("evidence"), dict)
                    or candidate["evidence"].get(MODEL_FEATURE_BINDING_FIELD)
                    != exact_features.as_binding()
                ):
                    raise ValueError("stored alert candidate lineage changed")
                telemetry_raw = str(row["telemetry_json"])
                telemetry_digest = hashlib.sha256(
                    telemetry_raw.encode()
                ).hexdigest()
                if (
                    not hmac.compare_digest(
                        telemetry_digest, str(row["telemetry_sha256"])
                    )
                    or not hmac.compare_digest(telemetry_digest, observation_id)
                ):
                    raise ValueError("stored telemetry observation digest changed")
                telemetry = strict_json_loads(
                    telemetry_raw, max_bytes=MAX_STORED_JSON_BYTES
                )
                if not isinstance(telemetry, dict):
                    raise ValueError("stored telemetry observation is not an object")
                label = row["label"]
                if type(label) is not int or label not in {0, 1}:
                    raise ValueError("stored learning label is invalid")
                reviewer = self._learning_principal(
                    row["reviewer_principal_id"], "reviewer principal"
                )
                source = self._learning_principal(
                    row["label_source"], "label source"
                )
                kind = str(row["occurrence_kind"])
                if (
                    str(row["label_kind"]) != kind
                    or candidate.get("kind") != kind
                    or str(row["occurrence_feature_schema_sha256"])
                    != MODEL_FEATURE_SCHEMA_SHA256
                    or str(row["telemetry_feature_schema_sha256"])
                    != MODEL_FEATURE_SCHEMA_SHA256
                ):
                    raise ValueError("stored learning kind or schema binding changed")
                occurrence_provenance = (
                    str(row["occurrence_agent_id"]),
                    int(row["occurrence_credential_epoch"]),
                    str(row["occurrence_profile_id"]),
                    str(row["occurrence_profile_fingerprint"]),
                    str(row["occurrence_agent_version"]),
                    str(row["occurrence_campaign_id"]),
                    str(row["occurrence_release_sha256"]),
                    str(row["occurrence_model_fingerprint"]),
                )
                telemetry_provenance = (
                    str(row["telemetry_agent_id"]),
                    int(row["telemetry_credential_epoch"]),
                    str(row["telemetry_profile_id"]),
                    str(row["telemetry_profile_fingerprint"]),
                    str(row["telemetry_agent_version"]),
                    str(row["telemetry_campaign_id"]),
                    str(row["telemetry_release_sha256"]),
                    str(row["telemetry_model_fingerprint"]),
                )
                if occurrence_provenance != telemetry_provenance:
                    raise ValueError("stored learning provenance binding changed")
                if (
                    telemetry.get("agent_id") != row["telemetry_agent_id"]
                    or telemetry.get("profile_id") != row["telemetry_profile_id"]
                    or telemetry.get("profile_fingerprint")
                    != row["telemetry_profile_fingerprint"]
                    or telemetry.get("agent_version")
                    != row["telemetry_agent_version"]
                    or telemetry.get("boot_id") != row["telemetry_boot_id"]
                    or telemetry.get("sequence") != row["telemetry_sequence"]
                    or float(telemetry.get("observed_at"))
                    != float(row["telemetry_observed_at"])
                    or float(telemetry.get("queued_at"))
                    != float(row["telemetry_queued_at"])
                    or float(row["occurrence_observed_at"])
                    != float(row["telemetry_observed_at"])
                ):
                    raise ValueError("stored telemetry lineage fields changed")
                incident_group_id = str(row["incident_group_id"])
                if (
                    len(incident_group_id) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in incident_group_id
                    )
                ):
                    raise ValueError("stored incident group identifier is invalid")
                samples.append(
                    {
                        "label_id": label_id,
                        "alert_id": str(row["alert_id"]),
                        "occurrence_id": occurrence_id,
                        "observation_id": observation_id,
                        "incident_group_id": incident_group_id,
                        "features": exact_features.as_dict(),
                        "features_sha256": exact_features.sha256,
                        "candidate_sha256": str(row["candidate_sha256"]),
                        "telemetry_sha256": telemetry_digest,
                        "label": int(label),
                        "reviewer_principal_id": reviewer,
                        "label_source": source,
                    }
                )
            except (TypeError, ValueError, OverflowError) as exc:
                # Immutable rows cannot be repaired safely.  Naming the exact
                # occurrence gives future readers a durable exclusion marker.
                self._quarantine_json(
                    "alert_occurrences",
                    occurrence_id,
                    "candidate_json",
                    row["candidate_json"],
                    str(exc),
                )
        return samples

    def feedback_samples(
        self,
        *,
        provenance_filter: dict[str, str] | None = None,
    ) -> list[tuple[dict[str, float], int]]:
        values: list[Any] = []
        where = ""
        if provenance_filter is not None:
            expected_fields = {
                "campaign_id",
                "profile_id",
                "profile_fingerprint",
                "release_sha256",
                "agent_version",
                "model_fingerprint",
            }
            if not isinstance(provenance_filter, dict) or set(
                provenance_filter
            ) != expected_fields:
                raise ValueError("learning provenance filter is incomplete")
            normalized: dict[str, str] = {}
            for name in expected_fields:
                value = provenance_filter[name]
                if not isinstance(value, str) or not value or len(value) > 128:
                    raise ValueError(
                        f"learning provenance filter {name} is invalid"
                    )
                normalized[name] = value.casefold() if name.endswith("sha256") or name.endswith("fingerprint") else value
            for name in (
                "profile_fingerprint",
                "release_sha256",
                "model_fingerprint",
            ):
                if (
                    len(normalized[name]) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in normalized[name]
                    )
                ):
                    raise ValueError(
                        f"learning provenance filter {name} is invalid"
                    )
            where = (
                "WHERE provenance_status='eligible' AND campaign_id=? "
                "AND profile_id=? AND profile_fingerprint=? "
                "AND release_sha256=? AND agent_version=? "
                "AND model_fingerprint=?"
            )
            values.extend(
                (
                    normalized["campaign_id"],
                    normalized["profile_id"],
                    normalized["profile_fingerprint"],
                    normalized["release_sha256"],
                    normalized["agent_version"],
                    normalized["model_fingerprint"],
                )
            )
        values.append(MAX_LEARNING_FEEDBACK)
        with self._lock:
            rows = self._connection.execute(
                f"""
                SELECT feedback_id, features_json, label
                FROM learning_feedback {where}
                ORDER BY created_at DESC, feedback_id DESC LIMIT ?
                """,
                values,
            ).fetchall()
        result: list[tuple[dict[str, float], int]] = []
        for row in reversed(rows):
            label = row["label"]
            if type(label) is not int or label not in {0, 1}:
                self._quarantine_json(
                    "learning_feedback",
                    str(row["feedback_id"]),
                    "features_json",
                    row["features_json"],
                    "stored learning label is invalid",
                )
                continue
            decoded = self._decode_stored_json(
                row["features_json"],
                table_name="learning_feedback",
                row_key=str(row["feedback_id"]),
                column_name="features_json",
                expected_type=dict,
            )
            if decoded is None:
                continue
            try:
                result.append((_learning_features(decoded), label))
            except ValueError as exc:
                self._quarantine_json(
                    "learning_feedback",
                    str(row["feedback_id"]),
                    "features_json",
                    row["features_json"],
                    str(exc),
                )
        return result


    def add_external_event(self, source: str, message: str, severity: str) -> str:
        event_id = str(uuid.uuid4())
        with self._lock:
            self._connection.execute(
                "INSERT INTO external_events(event_id, source, message, severity, created_at) VALUES(?, ?, ?, ?, ?)",
                (event_id, source, message[:8192], severity, time.time()),
            )
            self._connection.commit()
        return event_id

    def _mark_stale_dispatched_actions_locked(
        self,
        *,
        now: float,
        lease_seconds: float,
        max_attempts: int,
        agent_id: str | None = None,
    ) -> int:
        """Move delivered-but-unacknowledged envelopes out of active quota."""
        clauses = [
            "status='dispatched'",
            "((typeof(expires_at) IN ('integer','real') AND expires_at<=?) "
            "OR (typeof(attempts)='integer' AND attempts>=? "
            "AND typeof(dispatched_at) IN ('integer','real') "
            "AND dispatched_at<=?))",
        ]
        values: list[Any] = [
            now,
            max(1, min(int(max_attempts), 2**31 - 1)),
            now - max(1.0, float(lease_seconds)),
        ]
        if agent_id is not None:
            clauses.append("agent_id=?")
            values.append(agent_id)
        rows = self._connection.execute(
            "SELECT action_id FROM actions WHERE " + " AND ".join(clauses),
            values,
        ).fetchall()
        changed = 0
        for row in rows:
            action_id = str(row["action_id"])
            cursor = self._connection.execute(
                """
                UPDATE actions SET status='outcome_unknown', completed_at=NULL,
                  result_json=?, result_source='controller'
                WHERE action_id=? AND status='dispatched'
                """,
                (ACTION_OUTCOME_UNKNOWN_RESULT, action_id),
            )
            if cursor.rowcount != 1:
                continue
            changed += 1
            self._connection.execute(
                """
                INSERT OR IGNORE INTO audit_log(
                  audit_id, actor, operation, subject,
                  detail_json, created_at
                ) VALUES(?, 'controller', 'action_outcome_unknown', ?, ?, ?)
                """,
                (
                    str(
                        uuid.uuid5(
                            uuid.NAMESPACE_URL,
                            f"action-outcome-unknown:{action_id}",
                        )
                    ),
                    action_id,
                    canonical_json_dumps(
                        {
                            "reason": "delivery_acknowledgement_window_closed",
                        }
                    ),
                    now,
                ),
            )
        return changed

    def mark_stale_dispatched_actions(
        self,
        *,
        lease_seconds: float = 90.0,
        max_attempts: int = 5,
    ) -> int:
        with self._lock, _ImmediateTransaction(self._connection):
            changed = self._mark_stale_dispatched_actions_locked(
                now=time.time(),
                lease_seconds=lease_seconds,
                max_attempts=max_attempts,
            )
            self._connection.commit()
            return changed

    def queue_action(
        self,
        agent_id: str,
        action_type: str,
        parameters: dict[str, Any],
        alert_id: str | None = None,
        *,
        automated: bool = False,
        expires_at: float | None = None,
        profile_id: str = "",
        profile_fingerprint: str = "",
        autonomy_mode: str = "",
        binding: dict[str, Any] | None = None,
        _commit: bool = True,
    ) -> str:
        from .policy import action_risk, validate_action_parameters

        validate_action_parameters(action_type, parameters)
        parameters_json = canonical_json_dumps(
            parameters, max_bytes=MAX_STORED_JSON_BYTES
        )
        risk = action_risk(action_type)
        action_id = str(uuid.uuid4())
        now = time.time()
        effective_expires_at = float(expires_at or (now + 300.0))
        binding_values = self._binding_values(binding or {})
        from .validation import canonical_action_envelope_sha256

        queued_envelope_sha256 = canonical_action_envelope_sha256(
            asdict(
                ActionRequest(
                    action_id=action_id,
                    agent_id=agent_id,
                    action_type=action_type,
                    parameters=parameters,
                    status="dispatched",
                    created_at=now,
                    automated=bool(automated),
                    risk=risk,
                    expires_at=effective_expires_at,
                    profile_id=str(profile_id),
                    profile_fingerprint=str(profile_fingerprint),
                    autonomy_mode=str(autonomy_mode),
                )
            )
        )
        existing_id: str | None = None
        quota_reason: str | None = None
        with self._lock:
            if self._has_blocking_quarantine_locked():
                raise ActionQuotaExceeded("stored_data_quarantine_blocks_mutation")
            if binding is not None:
                current = self._connection.execute(
                    """
                    SELECT credential_epoch, profile_id, profile_fingerprint,
                           agent_version, latest_telemetry
                    FROM agents WHERE agent_id=? AND enabled=1
                    """,
                    (agent_id,),
                ).fetchone()
                if (
                    not current
                    or current["latest_telemetry"] is None
                    or (
                        int(current["credential_epoch"]),
                        str(current["profile_id"]),
                        str(current["profile_fingerprint"]),
                        str(current["agent_version"]),
                    )
                    != binding_values
                ):
                    raise PermissionError("agent release binding is not current")
                self._invalidate_stale_actions_for_binding_locked(
                    agent_id, binding_values, now
                )
            if alert_id is not None:
                alert = self._connection.execute(
                    """
                    SELECT agent_id, status, credential_epoch, profile_id,
                           profile_fingerprint, agent_version
                    FROM alerts WHERE alert_id=?
                    """,
                    (alert_id,),
                ).fetchone()
                alert_identity = (
                    str(alert["agent_id"]), str(alert["status"])
                ) if alert else None
                if alert_identity != (agent_id, "open"):
                    raise PermissionError("alert authority is no longer open")
                if binding is not None and (
                    int(alert["credential_epoch"]),
                    str(alert["profile_id"]),
                    str(alert["profile_fingerprint"]),
                    str(alert["agent_version"]),
                ) != binding_values:
                    raise PermissionError(
                        "alert authority is no longer open on this agent binding"
                    )
            self._connection.execute(
                """
                UPDATE actions SET status='failed', completed_at=?, result_json=?,
                                  result_source='controller'
                WHERE agent_id=? AND status='queued'
                  AND expires_at>0 AND expires_at<=?
                """,
                (now, ACTION_AUTHORIZATION_EXPIRED_RESULT, agent_id, now),
            )
            self._mark_stale_dispatched_actions_locked(
                now=now,
                lease_seconds=90.0,
                max_attempts=5,
                agent_id=agent_id,
            )
            if alert_id:
                existing_rows = self._connection.execute(
                    """
                    SELECT action_id, status, result_json FROM actions
                    WHERE alert_id=? AND action_type=?
                      AND status IN (
                        'queued','dispatched','outcome_unknown',
                        'completed','reconciled'
                      )
                    ORDER BY created_at DESC LIMIT 64
                    """,
                    (alert_id, action_type),
                ).fetchall()
                for existing in existing_rows:
                    if existing["status"] in {
                        "queued",
                        "dispatched",
                        "outcome_unknown",
                        "reconciled",
                    }:
                        existing_id = str(existing["action_id"])
                        break
                    completed_result = self._decode_stored_json(
                        existing["result_json"],
                        table_name="actions",
                        row_key=str(existing["action_id"]),
                        column_name="result_json",
                        expected_type=dict,
                    )
                    if completed_result is None:
                        # The operation may have executed.  Unknown terminal
                        # outcome must hold duplicates for operator review.
                        existing_id = str(existing["action_id"])
                        break
                    if (
                        completed_result.get("success") is True
                        and completed_result.get("dry_run") is not True
                    ):
                        existing_id = str(existing["action_id"])
                        break
            if existing_id is None:
                # Delivered envelopes with no linked alert (capture, rollback,
                # release, and operator maintenance) still need exact effect
                # suppression while their outcome is unknown.
                unknown_rows = self._connection.execute(
                    """
                    SELECT action_id, parameters_json FROM actions
                    WHERE agent_id=? AND action_type=?
                      AND status='outcome_unknown'
                    ORDER BY created_at DESC, action_id DESC LIMIT 64
                    """,
                    (agent_id, action_type),
                ).fetchall()
                for unknown in unknown_rows:
                    stored_parameters = self._decode_stored_json(
                        unknown["parameters_json"],
                        table_name="actions",
                        row_key=str(unknown["action_id"]),
                        column_name="parameters_json",
                        expected_type=dict,
                    )
                    if stored_parameters is None:
                        # A delivered effect with corrupt parameters is even
                        # less safe to repeat; hold the whole action type for
                        # operator reconciliation.
                        existing_id = str(unknown["action_id"])
                        break
                    stored_encoded = canonical_json_dumps(
                        stored_parameters, max_bytes=MAX_STORED_JSON_BYTES
                    )
                    if hmac_compare_json(stored_encoded, parameters_json):
                        existing_id = str(unknown["action_id"])
                        break
                if existing_id is None and len(unknown_rows) >= 64:
                    # A saturated unresolved-effect set is not safe authority
                    # for yet another mutation even when the first bounded
                    # comparison window did not find an exact match.
                    existing_id = str(unknown_rows[0]["action_id"])
            if existing_id is None and automated and action_type == "snapshot":
                existing = self._connection.execute(
                    """
                    SELECT action_id FROM actions
                    WHERE agent_id=? AND action_type='snapshot' AND automated=1
                      AND status IN ('queued','dispatched','outcome_unknown')
                      AND profile_id=? AND profile_fingerprint=? AND autonomy_mode=?
                      AND (expires_at=0 OR expires_at>=?)
                    ORDER BY created_at, action_id LIMIT 1
                    """,
                    (
                        agent_id,
                        str(profile_id),
                        str(profile_fingerprint),
                        str(autonomy_mode),
                        now,
                    ),
                ).fetchone()
                if existing:
                    existing_id = str(existing["action_id"])
            if existing_id is None:
                counts = self._connection.execute(
                    """
                    SELECT COUNT(*) AS total,
                           COALESCE(SUM(CASE WHEN automated=1 THEN 1 ELSE 0 END), 0)
                             AS automatic
                    FROM actions
                    WHERE agent_id=? AND status IN ('queued','dispatched')
                    """,
                    (agent_id,),
                ).fetchone()
                outstanding = int(counts["total"])
                outstanding_automatic = int(counts["automatic"])
                if outstanding >= MAX_OUTSTANDING_ACTIONS_PER_AGENT:
                    quota_reason = "total_outstanding_action_quota"
                elif (
                    automated
                    and outstanding_automatic
                    >= MAX_AUTOMATED_OUTSTANDING_ACTIONS_PER_AGENT
                ):
                    quota_reason = "automatic_outstanding_action_quota"
            if existing_id is None and quota_reason is None:
                self._connection.execute(
                    """
                    INSERT INTO actions(action_id, alert_id, agent_id, action_type,
                                        parameters_json, status, created_at, automated, risk,
                                        expires_at, profile_id, profile_fingerprint, autonomy_mode,
                                        credential_epoch, agent_version, envelope_sha256)
                    VALUES(?, ?, ?, ?, ?, 'queued', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        action_id,
                        alert_id,
                        agent_id,
                        action_type,
                        parameters_json,
                        now,
                        int(automated),
                        risk,
                        effective_expires_at,
                        str(profile_id),
                        str(profile_fingerprint),
                        str(autonomy_mode),
                        binding_values[0],
                        binding_values[3],
                        queued_envelope_sha256,
                    ),
                )
            if _commit:
                self._connection.commit()
        if existing_id is not None:
            return existing_id
        if quota_reason is not None:
            raise ActionQuotaExceeded(quota_reason)
        if _commit:
            self.audit(
                "policy" if automated else "operator",
                "queue_action",
                action_id,
                {"agent_id": agent_id, "action_type": action_type, "risk": risk},
            )
        return action_id

    def queue_action_with_authorization(
        self,
        *,
        authorization_code: str,
        authorization_subject: str,
        agent_id: str,
        action_type: str,
        parameters: dict[str, Any],
        alert_id: str | None,
        automated: bool,
        expires_at: float,
        profile_id: str,
        profile_fingerprint: str,
        autonomy_mode: str,
        binding: dict[str, Any] | None,
    ) -> str:
        """Consume one code and create its action in one SQLite transaction."""
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                if alert_id is not None:
                    existing = self.action_for_alert(alert_id, action_type)
                    if existing is not None:
                        self._connection.commit()
                        return str(existing["action_id"])
                if not self.consume_privileged_authorization(
                    authorization_code,
                    agent_id,
                    action_type,
                    authorization_subject,
                    binding=binding,
                    _commit=False,
                ):
                    raise PermissionError(
                        "a fresh one-use authorization bound to this action is required"
                    )
                action_id = self.queue_action(
                    agent_id,
                    action_type,
                    parameters,
                    alert_id,
                    automated=automated,
                    expires_at=expires_at,
                    profile_id=profile_id,
                    profile_fingerprint=profile_fingerprint,
                    autonomy_mode=autonomy_mode,
                    binding=binding,
                    _commit=False,
                )
                now = time.time()
                for operation, subject, detail in (
                    (
                        "consume_privileged_authorization",
                        hashlib.sha256(authorization_code.encode()).hexdigest()[:16],
                        {
                            "agent_id": agent_id,
                            "action_type": action_type,
                            "subject": authorization_subject,
                        },
                    ),
                    (
                        "queue_action",
                        action_id,
                        {
                            "agent_id": agent_id,
                            "action_type": action_type,
                            "risk": "high",
                        },
                    ),
                ):
                    self._connection.execute(
                        """
                        INSERT INTO audit_log(
                          audit_id, actor, operation, subject,
                          detail_json, created_at
                        ) VALUES(?, 'operator', ?, ?, ?, ?)
                        """,
                        (
                            str(uuid.uuid4()),
                            operation,
                            subject,
                            canonical_json_dumps(detail),
                            now,
                        ),
                    )
                self._connection.commit()
                return action_id
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def action_for_alert(self, alert_id: str, action_type: str) -> dict[str, Any] | None:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT * FROM actions WHERE alert_id=? AND action_type=?
                  AND status IN (
                    'queued','dispatched','outcome_unknown',
                    'completed','reconciled'
                  )
                ORDER BY created_at DESC LIMIT 64
                """,
                (alert_id, action_type),
            ).fetchall()
        for row in rows:
            if row["status"] in {
                "queued",
                "dispatched",
                "outcome_unknown",
                "reconciled",
            }:
                return dict(row)
            result = self._decode_stored_json(
                row["result_json"],
                table_name="actions",
                row_key=str(row["action_id"]),
                column_name="result_json",
                expected_type=dict,
            )
            if result is None:
                return dict(row)
            if (
                result.get("success") is True
                and result.get("dry_run") is not True
            ):
                return dict(row)
        return None

    def pending_actions(
        self,
        agent_id: str,
        lease_seconds: float = 90.0,
        max_attempts: int = 5,
        allowed_action_types: set[str] | frozenset[str] | None = None,
        allowed_automated_action_types: set[str] | frozenset[str] | None = None,
        allowed_manual_action_types: set[str] | frozenset[str] | None = None,
        max_items: int = MAX_PENDING_ACTIONS_PER_RESPONSE,
        max_serialized_bytes: int = MAX_AGENT_EGRESS_BYTES,
        binding: dict[str, Any] | None = None,
    ) -> list[ActionRequest]:
        delivery_limit = max(
            1, min(int(max_items), MAX_PENDING_ACTIONS_PER_RESPONSE)
        )
        byte_limit = max(
            256, min(int(max_serialized_bytes), MAX_AGENT_EGRESS_BYTES)
        )
        oversized_action_ids: list[str] = []
        with self._lock, _ImmediateTransaction(self._connection):
            now = time.time()
            if self._has_blocking_quarantine_locked():
                self._connection.rollback()
                return []
            if binding is not None:
                binding_values = self._binding_values(binding)
                current = self._connection.execute(
                    """
                    SELECT credential_epoch, profile_id, profile_fingerprint,
                           agent_version, latest_telemetry
                    FROM agents WHERE agent_id=? AND enabled=1
                    """,
                    (agent_id,),
                ).fetchone()
                if (
                    not current
                    or current["latest_telemetry"] is None
                    or (
                        int(current["credential_epoch"]),
                        str(current["profile_id"]),
                        str(current["profile_fingerprint"]),
                        str(current["agent_version"]),
                    )
                    != binding_values
                ):
                    self._connection.rollback()
                    return []
                if self._connection.execute(
                    "SELECT 1 FROM telemetry_processing "
                    "WHERE agent_id=? LIMIT 1",
                    (agent_id,),
                ).fetchone():
                    # The accepted sample is authoritative, but its alerts,
                    # baseline and automation derivatives are not durable yet.
                    # Do not lease host-changing work from an older view.
                    self._connection.rollback()
                    return []
                self._invalidate_stale_actions_for_binding_locked(
                    agent_id, binding_values, now
                )
            self._connection.execute(
                """
                UPDATE actions SET status='failed', completed_at=?, result_json=?,
                                  result_source='controller'
                WHERE agent_id=? AND status='queued'
                  AND expires_at>0 AND expires_at<=?
                """,
                (now, ACTION_AUTHORIZATION_EXPIRED_RESULT, agent_id, now),
            )
            self._mark_stale_dispatched_actions_locked(
                now=now,
                lease_seconds=lease_seconds,
                max_attempts=max_attempts,
                agent_id=agent_id,
            )
            query = """
                SELECT * FROM actions
                WHERE agent_id=? AND (
                  status='queued' OR
                  (status='dispatched' AND attempts<? AND dispatched_at IS NOT NULL AND dispatched_at<?)
                ) AND expires_at>?
            """
            values: list[Any] = [
                agent_id,
                max_attempts,
                now - lease_seconds,
                now,
            ]
            if binding is not None:
                epoch, profile_id, profile_fingerprint, agent_version = self._binding_values(
                    binding
                )
                query += (
                    " AND credential_epoch=? AND profile_id=? "
                    "AND profile_fingerprint=? AND agent_version=?"
                )
                values.extend(
                    (epoch, profile_id, profile_fingerprint, agent_version)
                )
            if (
                allowed_automated_action_types is not None
                or allowed_manual_action_types is not None
            ):
                automatic = sorted(set(allowed_automated_action_types or set()))
                manual = sorted(set(allowed_manual_action_types or set()))
                clauses: list[str] = []
                if automatic:
                    placeholders = ",".join("?" for _ in automatic)
                    clauses.append(f"(automated=1 AND action_type IN ({placeholders}))")
                    values.extend(automatic)
                if manual:
                    placeholders = ",".join("?" for _ in manual)
                    clauses.append(f"(automated=0 AND action_type IN ({placeholders}))")
                    values.extend(manual)
                if clauses:
                    query += " AND (" + " OR ".join(clauses) + ")"
                else:
                    query = ""
            elif allowed_action_types is not None:
                allowed = sorted(set(allowed_action_types))
                if not allowed:
                    query = ""
                else:
                    placeholders = ",".join("?" for _ in allowed)
                    query += f" AND action_type IN ({placeholders})"
                    values.extend(allowed)
            if query:
                # Scan the bounded outstanding queue, rather than only the
                # response-size prefix.  A poisoned first row must not starve a
                # valid follower indefinitely.
                query += " ORDER BY created_at, action_id LIMIT ?"
                values.append(MAX_OUTSTANDING_ACTIONS_PER_AGENT)
                rows = self._connection.execute(query, values).fetchall()
            else:
                rows = []

            selected: list[ActionRequest] = []
            selected_digests: dict[str, str] = {}
            for row in rows:
                if len(selected) >= delivery_limit:
                    break
                action_id = str(row["action_id"])
                try:
                    parameters = self._decode_stored_json(
                        row["parameters_json"],
                        table_name="actions",
                        row_key=action_id,
                        column_name="parameters_json",
                        expected_type=dict,
                    )
                    if parameters is None:
                        raise ValueError(
                            "action parameters failed strict stored-JSON validation"
                        )
                    from .policy import action_risk, validate_action_parameters
                    from .validation import (
                        canonical_action_envelope_sha256,
                        validate_action_request,
                    )

                    validate_action_parameters(str(row["action_type"]), parameters)
                    if (
                        type(row["automated"]) is not int
                        or row["automated"] not in {0, 1}
                    ):
                        raise ValueError("stored action automated flag is invalid")
                    if type(row["attempts"]) is not int or row["attempts"] < 0:
                        raise ValueError("stored action attempt count is invalid")
                    if str(row["status"]) == "queued":
                        if row["attempts"] != 0 or row["dispatched_at"] is not None:
                            raise ValueError("queued action contains delivery state")
                    elif str(row["status"]) == "dispatched":
                        if row["attempts"] < 1 or type(row["dispatched_at"]) not in {
                            int,
                            float,
                        } or not math.isfinite(row["dispatched_at"]):
                            raise ValueError("dispatched action delivery state is invalid")
                    else:
                        raise ValueError("stored action status is invalid")
                    for name in (
                        "action_id", "agent_id", "action_type", "risk", "profile_id",
                        "profile_fingerprint", "autonomy_mode", "agent_version",
                    ):
                        if not isinstance(row[name], str):
                            raise ValueError(f"stored action {name} type is invalid")
                    if row["agent_id"] != agent_id:
                        raise ValueError("stored action agent binding is invalid")
                    if row["risk"] != action_risk(str(row["action_type"])):
                        raise ValueError("stored action risk is invalid")
                    if type(row["credential_epoch"]) is not int or row["credential_epoch"] < -1:
                        raise ValueError("stored action credential epoch is invalid")
                    if type(row["created_at"]) not in {int, float} or not math.isfinite(
                        row["created_at"]
                    ):
                        raise ValueError("stored action created_at is invalid")
                    if type(row["expires_at"]) not in {int, float} or not math.isfinite(
                        row["expires_at"]
                    ) or row["expires_at"] <= 0:
                        raise ValueError("stored action expiry is invalid")
                    action = ActionRequest(
                        action_id=row["action_id"],
                        agent_id=row["agent_id"],
                        action_type=row["action_type"],
                        parameters=parameters,
                        status="dispatched",
                        created_at=row["created_at"],
                        automated=bool(row["automated"]),
                        risk=row["risk"],
                        expires_at=row["expires_at"],
                        profile_id=row["profile_id"],
                        profile_fingerprint=row["profile_fingerprint"],
                        autonomy_mode=row["autonomy_mode"],
                    )
                    normalized = validate_action_request(
                        asdict(action),
                        expected_agent_id=agent_id,
                        expected_profile_id=str(row["profile_id"]),
                        expected_profile_fingerprint=str(row["profile_fingerprint"]),
                        expected_autonomy_mode=str(row["autonomy_mode"]),
                        require_binding=int(row["credential_epoch"]) >= 0,
                        now=now,
                    )
                    envelope_sha256 = canonical_action_envelope_sha256(normalized)
                    persisted_envelope = str(row["envelope_sha256"] or "")
                    if len(persisted_envelope) != 64 or not hmac.compare_digest(
                        persisted_envelope, envelope_sha256
                    ):
                        raise ValueError("dispatched action envelope changed in storage")
                except (TypeError, ValueError, OverflowError) as exc:
                    self._quarantine_json(
                        "actions",
                        action_id,
                        "row_semantics",
                        dict(row),
                        str(exc),
                    )
                    self._connection.execute(
                        """
                        UPDATE actions SET
                          status=CASE status
                            WHEN 'queued' THEN 'failed'
                            ELSE 'outcome_unknown'
                          END,
                          completed_at=CASE status
                            WHEN 'queued' THEN ?
                            ELSE NULL
                          END,
                          result_json=?, result_source='controller'
                        WHERE action_id=? AND status IN ('queued','dispatched')
                        """,
                        (
                            now,
                            canonical_json_dumps(
                                {
                                    "success": False,
                                    "message": "action row failed semantic storage validation",
                                }
                            ),
                            action_id,
                        ),
                    )
                    continue
                single_body = canonical_json_dumps(
                    {"actions": [asdict(action)]},
                ).encode("utf-8")
                if len(single_body) > byte_limit:
                    oversized_action_ids.append(str(row["action_id"]))
                    self._connection.execute(
                        """
                        UPDATE actions SET
                          status=CASE status
                            WHEN 'queued' THEN 'failed'
                            ELSE 'outcome_unknown'
                          END,
                          completed_at=CASE status
                            WHEN 'queued' THEN ?
                            ELSE NULL
                          END,
                          result_json=?, result_source='controller'
                        WHERE action_id=? AND status IN ('queued','dispatched')
                        """,
                        (now, ACTION_DELIVERY_OVERSIZED_RESULT, row["action_id"]),
                    )
                    continue
                try:
                    candidate_body = canonical_json_dumps(
                        {"actions": [asdict(item) for item in (*selected, action)]},
                    ).encode("utf-8")
                except ValueError as exc:
                    self._quarantine_json(
                        "actions", action_id, "row_semantics", dict(row), str(exc)
                    )
                    self._connection.execute(
                        """
                        UPDATE actions SET
                          status=CASE status
                            WHEN 'queued' THEN 'failed'
                            ELSE 'outcome_unknown'
                          END,
                          completed_at=CASE status
                            WHEN 'queued' THEN ?
                            ELSE NULL
                          END,
                          result_json=?, result_source='controller'
                        WHERE action_id=? AND status IN ('queued','dispatched')
                        """,
                        (
                            now,
                            canonical_json_dumps(
                                {"success": False, "message": "action envelope is not serializable"}
                            ),
                            action_id,
                        ),
                    )
                    continue
                if len(candidate_body) > byte_limit:
                    continue
                selected.append(action)
                selected_digests[action.action_id] = envelope_sha256

            # A malformed row discovered while scanning is isolated in this
            # transaction. Do not lease otherwise-valid followers once that
            # durable mutation gate has closed.
            if self._has_blocking_quarantine_locked():
                selected = []
                selected_digests.clear()
            for action in selected:
                self._connection.execute(
                    """
                    UPDATE actions SET status='dispatched', dispatched_at=?,
                      attempts=attempts+1, envelope_sha256=?
                    WHERE action_id=?
                    """,
                    (now, selected_digests[action.action_id], action.action_id),
                )
            self._connection.commit()
        if oversized_action_ids:
            self.audit(
                "controller",
                "action_delivery_overflow",
                agent_id,
                {
                    "egress_limit_bytes": byte_limit,
                    "failed_action_ids": sorted(oversized_action_ids),
                },
            )
        return selected

    def _block_baseline_promotion_locked(
        self, promotion_id: str, reason: str, now: float
    ) -> None:
        self._connection.execute(
            "UPDATE baseline_promotions SET status='blocked', failure_reason=?, "
            "updated_at=?, completed_at=? WHERE promotion_id=? AND status='pending'",
            (str(reason)[:256], now, now, promotion_id),
        )
        self.audit(
            "controller",
            "block_baseline_promotion",
            promotion_id,
            {"reason": str(reason)[:256]},
        )

    def _finalize_baseline_promotion_locked(
        self,
        promotion: sqlite3.Row,
        action: sqlite3.Row,
        parameters: dict[str, Any],
        result: dict[str, Any],
        *,
        now: float,
    ) -> str | None:
        """Promote one frozen candidate, or return its durable block reason."""

        promotion_id = str(promotion["promotion_id"])
        if (
            promotion["status"] != "pending"
            or promotion["action_id"] != action["action_id"]
            or action["action_type"] != "capture_restore_point"
            or action["agent_id"] != promotion["agent_id"]
        ):
            return "promotion_action_binding_mismatch"
        action_binding = (
            int(action["credential_epoch"]),
            str(action["profile_id"]),
            str(action["profile_fingerprint"]),
            str(action["agent_version"]),
        )
        promotion_binding = (
            int(promotion["credential_epoch"]),
            str(promotion["profile_id"]),
            str(promotion["profile_fingerprint"]),
            str(promotion["agent_version"]),
        )
        if action_binding[0] >= 0 and action_binding != promotion_binding:
            return "promotion_action_binding_mismatch"
        candidate = self._decode_stored_json(
            promotion["candidate_json"],
            table_name="baseline_promotions",
            row_key=promotion_id,
            column_name="candidate_json",
            expected_type=dict,
        )
        if candidate is None:
            return "promotion_candidate_invalid"
        candidate_json = canonical_json_dumps(
            candidate, max_bytes=MAX_STORED_JSON_BYTES
        )
        if not hmac.compare_digest(
            hashlib.sha256(candidate_json.encode()).hexdigest(),
            str(promotion["candidate_sha256"]),
        ):
            return "promotion_candidate_digest_mismatch"
        try:
            expected_files = baseline_capture_files(candidate)
        except (TypeError, ValueError, OverflowError):
            return "promotion_candidate_scope_invalid"
        if parameters != {"files": expected_files}:
            return "promotion_capture_scope_mismatch"
        receipt_error = capture_receipt_error(expected_files, result)
        if receipt_error is not None:
            return receipt_error

        agent = self._connection.execute(
            "SELECT enabled, latest_telemetry, credential_epoch, profile_id, "
            "profile_fingerprint, agent_version, last_observed_at, boot_id, "
            "last_sequence FROM agents WHERE agent_id=?",
            (promotion["agent_id"],),
        ).fetchone()
        if not agent or int(agent["enabled"]) != 1:
            return "promotion_agent_binding_stale"
        # Persistent checksum-bound deployments always carry a non-negative
        # credential epoch.  The negative sentinel exists only for legacy and
        # in-memory compatibility, where manufacturing a relationship to the
        # agent's epoch zero would make every safe capture impossible.
        if promotion_binding[0] >= 0 and (
            int(agent["credential_epoch"]),
            str(agent["profile_id"]),
            str(agent["profile_fingerprint"]),
            str(agent["agent_version"]),
        ) != promotion_binding:
            return "promotion_agent_binding_stale"
        latest = self._decode_stored_json(
            agent["latest_telemetry"],
            table_name="agents",
            row_key=str(promotion["agent_id"]),
            column_name="latest_telemetry",
            expected_type=dict,
        )
        if latest is None:
            return "promotion_telemetry_unavailable"
        latest_json = canonical_json_dumps(
            latest, max_bytes=MAX_STORED_JSON_BYTES
        )
        if (
            not hmac.compare_digest(
                hashlib.sha256(latest_json.encode()).hexdigest(),
                str(promotion["telemetry_sha256"]),
            )
            or (
                promotion_binding[0] >= 0
                and (
                    agent["last_observed_at"]
                    != promotion["telemetry_observed_at"]
                    or str(agent["boot_id"])
                    != str(promotion["telemetry_boot_id"])
                    or int(agent["last_sequence"])
                    != int(promotion["telemetry_sequence"])
                )
            )
        ):
            return "promotion_telemetry_observation_stale"

        baseline = self._connection.execute(
            "SELECT * FROM baselines WHERE agent_id=?",
            (promotion["agent_id"],),
        ).fetchone()
        if not baseline:
            return "promotion_baseline_missing"
        prior = self._decode_stored_json(
            baseline["baseline_json"],
            table_name="baselines",
            row_key=str(promotion["agent_id"]),
            column_name="baseline_json",
            expected_type=dict,
        )
        if prior is None:
            return "promotion_prior_baseline_invalid"
        prior_json = canonical_json_dumps(prior, max_bytes=MAX_STORED_JSON_BYTES)
        if not hmac.compare_digest(
            hashlib.sha256(prior_json.encode()).hexdigest(),
            str(promotion["prior_baseline_sha256"]),
        ):
            return "promotion_prior_baseline_changed"
        expected_status = (
            "pending" if promotion["source"] == "initial" else "approved"
        )
        if baseline["status"] != expected_status or (
            int(baseline["credential_epoch"]),
            str(baseline["profile_id"]),
            str(baseline["profile_fingerprint"]),
            str(baseline["agent_version"]),
        ) != promotion_binding:
            return "promotion_prior_baseline_changed"

        if promotion["source"] == "accepted_change":
            alert_id = str(promotion["alert_id"] or "")
            alert = self._connection.execute(
                "SELECT kind FROM alerts WHERE alert_id=? AND agent_id=? "
                "AND status='open'",
                (alert_id, promotion["agent_id"]),
            ).fetchone()
            if not alert or alert["kind"] != "critical_file_changed":
                return "promotion_alert_authority_stale"
            decided = self.decide_alert(
                alert_id,
                "accept_change",
                binding={
                    "credential_epoch": promotion_binding[0],
                    "profile_id": promotion_binding[1],
                    "profile_fingerprint": promotion_binding[2],
                    "agent_version": promotion_binding[3],
                }
                if promotion_binding[0] >= 0
                else None,
                _commit=False,
            )
            if decided is None:
                return "promotion_alert_authority_stale"
            from .risk import features_for_kind

            self.record_feedback(
                alert_id,
                "critical_file_changed",
                "accept_change",
                0,
                features_for_kind("critical_file_changed"),
                source="baseline-capture-promotion",
                _commit=False,
            )
        elif promotion["source"] != "initial":
            return "promotion_source_invalid"

        cursor = self._connection.execute(
            "UPDATE baselines SET baseline_json=?, created_at=?, status='approved', "
            "approved_at=? WHERE agent_id=? AND status=?",
            (
                candidate_json,
                now,
                now,
                promotion["agent_id"],
                expected_status,
            ),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("baseline promotion CAS failed")
        cursor = self._connection.execute(
            "UPDATE baseline_promotions SET status='completed', failure_reason='', "
            "updated_at=?, completed_at=? WHERE promotion_id=? AND status='pending'",
            (now, now, promotion_id),
        )
        if cursor.rowcount != 1:
            raise RuntimeError("baseline promotion state CAS failed")
        self.audit(
            "controller",
            "complete_baseline_promotion",
            promotion_id,
            {
                "agent_id": promotion["agent_id"],
                "candidate_sha256": promotion["candidate_sha256"],
                "file_count": len(expected_files),
            },
        )
        return None

    def complete_action(
        self,
        action_id: str,
        result: dict[str, Any],
        expected_agent_id: str | None = None,
    ) -> str | None:
        """Atomically accept one exact result for one delivered immutable envelope."""
        from .policy import action_risk, validate_action_parameters
        from .validation import (
            canonical_action_envelope_sha256,
            validate_action_request,
            validate_action_result,
        )

        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            try:
                now = time.time()
                row = self._connection.execute(
                    "SELECT * FROM actions WHERE action_id=?", (action_id,)
                ).fetchone()
                if not row or (
                    expected_agent_id is not None
                    and row["agent_id"] != expected_agent_id
                ):
                    self._connection.rollback()
                    return None
                promotion = self._connection.execute(
                    "SELECT * FROM baseline_promotions "
                    "WHERE action_id=? AND status='pending'",
                    (action_id,),
                ).fetchone()

                try:
                    normalized_result = validate_action_result(
                        result,
                        require_envelope_sha256=(
                            type(row["credential_epoch"]) is int
                            and row["credential_epoch"] >= 0
                        ),
                    )
                    encoded = canonical_json_dumps(
                        normalized_result, max_bytes=MAX_STORED_JSON_BYTES
                    )
                except (TypeError, ValueError, OverflowError):
                    self._connection.rollback()
                    return "conflict"
                if (
                    normalized_result["action_id"] != action_id
                    or normalized_result["action_type"] != row["action_type"]
                ):
                    self._connection.rollback()
                    return "conflict"

                status = str(row["status"])
                if status == "queued":
                    # Knowing a UUID is not proof that the signed agent ever
                    # received this envelope.
                    self._connection.rollback()
                    return "conflict"
                bound = (
                    type(row["credential_epoch"]) is int
                    and row["credential_epoch"] >= 0
                )
                try:
                    if status not in {
                        "dispatched",
                        "outcome_unknown",
                        "completed",
                        "failed",
                        "reconciled",
                    }:
                        raise ValueError("stored action status is invalid")
                    for name in (
                        "action_id",
                        "agent_id",
                        "action_type",
                        "risk",
                        "profile_id",
                        "profile_fingerprint",
                        "autonomy_mode",
                        "agent_version",
                        "envelope_sha256",
                        "result_source",
                    ):
                        if not isinstance(row[name], str):
                            raise ValueError(f"stored action {name} type is invalid")
                    if row["action_id"] != action_id:
                        raise ValueError("stored action identity is invalid")
                    if (
                        type(row["automated"]) is not int
                        or row["automated"] not in {0, 1}
                    ):
                        raise ValueError("stored action automated flag is invalid")
                    if (
                        type(row["attempts"]) is not int
                        or not 1 <= row["attempts"] <= 2**31 - 1
                    ):
                        raise ValueError("stored action delivery count is invalid")
                    if (
                        type(row["credential_epoch"]) is not int
                        or not -1 <= row["credential_epoch"] <= 2**63 - 1
                    ):
                        raise ValueError("stored action credential epoch is invalid")
                    if row["risk"] != action_risk(str(row["action_type"])):
                        raise ValueError("stored action risk is invalid")
                    for name in ("created_at", "dispatched_at", "expires_at"):
                        if (
                            type(row[name]) not in {int, float}
                            or not math.isfinite(row[name])
                            or not 0 < row[name] <= 2**63 - 1
                        ):
                            raise ValueError(f"stored action {name} is invalid")
                    if not row["created_at"] <= row["dispatched_at"] < row["expires_at"]:
                        raise ValueError("stored action delivery times are invalid")
                    parameters = self._decode_stored_json(
                        row["parameters_json"],
                        table_name="actions",
                        row_key=action_id,
                        column_name="parameters_json",
                        expected_type=dict,
                    )
                    if parameters is None:
                        raise ValueError(
                            "stored action parameters failed strict validation"
                        )
                    validate_action_parameters(str(row["action_type"]), parameters)
                    envelope = ActionRequest(
                        action_id=row["action_id"],
                        agent_id=row["agent_id"],
                        action_type=row["action_type"],
                        parameters=parameters,
                        status="dispatched",
                        created_at=row["created_at"],
                        automated=bool(row["automated"]),
                        risk=row["risk"],
                        expires_at=row["expires_at"],
                        profile_id=row["profile_id"],
                        profile_fingerprint=row["profile_fingerprint"],
                        autonomy_mode=row["autonomy_mode"],
                    )
                    normalized_envelope = validate_action_request(
                        asdict(envelope),
                        expected_agent_id=str(row["agent_id"]),
                        expected_profile_id=str(row["profile_id"]),
                        expected_profile_fingerprint=str(
                            row["profile_fingerprint"]
                        ),
                        expected_autonomy_mode=str(row["autonomy_mode"]),
                        require_binding=bound,
                        now=float(row["dispatched_at"]),
                    )
                    recomputed_envelope_sha256 = (
                        canonical_action_envelope_sha256(normalized_envelope)
                    )
                except (TypeError, ValueError, OverflowError) as exc:
                    self._quarantine_json(
                        "actions",
                        action_id,
                        "row_semantics",
                        dict(row),
                        str(exc),
                    )
                    if status in {"dispatched", "outcome_unknown"}:
                        self._connection.execute(
                            """
                            UPDATE actions SET status='outcome_unknown',
                              completed_at=NULL, result_source='controller'
                            WHERE action_id=?
                              AND status IN ('dispatched','outcome_unknown')
                            """,
                            (action_id,),
                        )
                    self._connection.commit()
                    return "conflict"

                persisted_envelope_sha256 = str(row["envelope_sha256"])
                if (
                    len(persisted_envelope_sha256) != 64
                    or any(
                        character not in "0123456789abcdef"
                        for character in persisted_envelope_sha256
                    )
                    or not hmac.compare_digest(
                        persisted_envelope_sha256,
                        recomputed_envelope_sha256,
                    )
                ):
                    # Only a mismatch between two controller-owned values is
                    # evidence of storage corruption.
                    self._quarantine_json(
                        "actions",
                        action_id,
                        "envelope_sha256",
                        persisted_envelope_sha256,
                        "persisted action envelope does not match its stored fields",
                    )
                    if status in {"dispatched", "outcome_unknown"}:
                        self._connection.execute(
                            """
                            UPDATE actions SET status='outcome_unknown',
                              completed_at=NULL, result_source='controller'
                            WHERE action_id=?
                              AND status IN ('dispatched','outcome_unknown')
                            """,
                            (action_id,),
                        )
                    self._connection.commit()
                    return "conflict"
                supplied_envelope_sha256 = str(
                    normalized_result.get("action_envelope_sha256", "")
                )
                if (
                    (bound and not supplied_envelope_sha256)
                    or (
                        supplied_envelope_sha256
                        and not hmac.compare_digest(
                            supplied_envelope_sha256,
                            persisted_envelope_sha256,
                        )
                    )
                ):
                    # An authenticated but conflicting peer result is not
                    # evidence that controller storage is corrupt.
                    self._connection.rollback()
                    return "conflict"

                if status == "reconciled":
                    # An operator has resolved this unknown delivered envelope.
                    # Do not let a late peer report overwrite that explicit
                    # reconciliation or create a second terminal effect.
                    self._connection.rollback()
                    return "conflict"

                if status in {"completed", "failed"}:
                    if row["result_source"] != "agent" or not row["result_json"]:
                        self._connection.rollback()
                        return "conflict"
                    stored = self._decode_stored_json(
                        row["result_json"],
                        table_name="actions",
                        row_key=action_id,
                        column_name="result_json",
                        expected_type=dict,
                    )
                    if stored is None:
                        self._connection.commit()
                        return "conflict"
                    try:
                        stored_normalized = validate_action_result(
                            stored, require_envelope_sha256=bound
                        )
                        stored_encoded = canonical_json_dumps(
                            stored_normalized, max_bytes=MAX_STORED_JSON_BYTES
                        )
                    except (TypeError, ValueError, OverflowError) as exc:
                        self._quarantine_json(
                            "actions",
                            action_id,
                            "result_json",
                            row["result_json"],
                            str(exc),
                        )
                        self._connection.commit()
                        return "conflict"
                    outcome = (
                        "exact_retry"
                        if hmac_compare_json(stored_encoded, encoded)
                        else "conflict"
                    )
                    self._connection.rollback()
                    return outcome

                expires_at = float(row["expires_at"])
                if (
                    normalized_result["started_at"] > expires_at + 600.0
                    or now
                    > expires_at + MAX_ACTION_RESULT_REPORT_GRACE_SECONDS
                ):
                    # Expiry prevents a new delivery/start.  It cannot prove a
                    # dispatched operation did not execute, so retain the
                    # unknown envelope for reconciliation rather than forging
                    # a controller failure or enabling a duplicate effect.
                    self._connection.rollback()
                    return "conflict"
                if (
                    normalized_result["started_at"] < float(row["created_at"]) - 600.0
                    or normalized_result["completed_at"] > now + 600.0
                ):
                    self._connection.rollback()
                    return "conflict"

                binding_current = True
                if bound:
                    agent = self._connection.execute(
                        """
                        SELECT credential_epoch, profile_id, profile_fingerprint,
                               agent_version, enabled
                        FROM agents WHERE agent_id=?
                        """,
                        (row["agent_id"],),
                    ).fetchone()
                    if agent is not None and (
                        type(agent["enabled"]) is not int
                        or agent["enabled"] not in {0, 1}
                        or type(agent["credential_epoch"]) is not int
                        or not 0 <= agent["credential_epoch"] <= 2**63 - 1
                        or not isinstance(agent["profile_id"], str)
                        or not isinstance(agent["profile_fingerprint"], str)
                        or not isinstance(agent["agent_version"], str)
                    ):
                        self._quarantine_json(
                            "agents",
                            str(row["agent_id"]),
                            "action_result_binding",
                            dict(agent),
                            "agent authority row has invalid result-binding semantics",
                        )
                        self._connection.commit()
                        return "conflict"
                    binding_current = agent is not None and (
                        agent["enabled"],
                        agent["credential_epoch"],
                        agent["profile_id"],
                        agent["profile_fingerprint"],
                        agent["agent_version"],
                    ) == (
                        1,
                        int(row["credential_epoch"]),
                        str(row["profile_id"]),
                        str(row["profile_fingerprint"]),
                        str(row["agent_version"]),
                    )
                    if not binding_current and not (
                        status == "outcome_unknown"
                        and expected_agent_id == row["agent_id"]
                        and agent is not None
                        and type(agent["enabled"]) is int
                        and agent["enabled"] == 1
                    ):
                        self._connection.rollback()
                        return "conflict"

                promotion_error: str | None = None
                try:
                    _require_success_result_contract(
                        str(row["action_type"]), parameters, normalized_result
                    )
                except (TypeError, ValueError, OverflowError):
                    if promotion is None:
                        self._connection.rollback()
                        return "conflict"
                    promotion_error = "action_specific_evidence_invalid"

                if (
                    normalized_result["success"] is True
                    and row["action_type"] == "capture_restore_point"
                ):
                    expected_paths = [
                        str(item.get("path", ""))
                        for item in parameters.get("files", [])
                    ]
                    if (
                        normalized_result.get("dry_run") is True
                        or normalized_result.get("rejected", [])
                        or normalized_result.get("captured") != expected_paths
                    ):
                        if promotion is None:
                            self._connection.rollback()
                            return "conflict"
                        promotion_error = "capture_paths_incomplete"
                if promotion is not None and promotion_error is None:
                    promotion_error = capture_receipt_error(
                        list(parameters.get("files", [])), normalized_result
                    )
                terminal_success = (
                    normalized_result["success"] is True
                    and normalized_result.get("dry_run") is not True
                    and promotion_error is None
                )

                cursor = self._connection.execute(
                    """
                    UPDATE actions SET status=?, result_json=?, completed_at=?,
                                       result_source='agent'
                    WHERE action_id=? AND status IN ('dispatched','outcome_unknown')
                    """,
                    (
                        (
                            "completed"
                            if terminal_success
                            else "failed"
                        ),
                        encoded,
                        now,
                        action_id,
                    ),
                )
                if cursor.rowcount != 1:
                    self._connection.rollback()
                    return "conflict"

                if promotion is not None:
                    if promotion_error is None:
                        promotion_error = self._finalize_baseline_promotion_locked(
                            promotion,
                            row,
                            parameters,
                            normalized_result,
                            now=now,
                        )
                    if promotion_error is not None:
                        self._block_baseline_promotion_locked(
                            str(promotion["promotion_id"]),
                            promotion_error,
                            now,
                        )

                success_restore = (
                    normalized_result["success"] is True
                    and normalized_result.get("dry_run") is not True
                    and row["action_type"] == "restore_integrity"
                    and bool(row["alert_id"])
                    and binding_current
                )
                if success_restore:
                    clauses = ""
                    values: list[Any] = [now, row["alert_id"], row["agent_id"]]
                    if bound:
                        clauses = (
                            " AND credential_epoch=? AND profile_id=? "
                            "AND profile_fingerprint=? AND agent_version=?"
                        )
                        values.extend(
                            (
                                int(row["credential_epoch"]),
                                str(row["profile_id"]),
                                str(row["profile_fingerprint"]),
                                str(row["agent_version"]),
                            )
                        )
                    self._connection.execute(
                        """
                        UPDATE alerts SET status='decided',
                          decision='automatic_restore', decided_at=?
                        WHERE alert_id=? AND agent_id=? AND status='open'
                        """
                        + clauses,
                        values,
                    )

                failure_alert_admitted = False
                if (
                    binding_current
                    and (
                        not terminal_success
                        or normalized_result.get("rolled_back") is True
                    )
                ):
                    rolled_back = normalized_result.get("rolled_back") is True
                    severity = "medium" if rolled_back else "high"
                    counts = {
                        str(item["severity"]).casefold(): int(item["count"])
                        for item in self._connection.execute(
                            """
                            SELECT severity, COUNT(*) AS count FROM alerts
                            WHERE agent_id=? AND status='open'
                            GROUP BY severity
                            """,
                            (row["agent_id"],),
                        ).fetchall()
                    }
                    if (
                        sum(counts.values()) < MAX_OPEN_ALERTS_PER_AGENT
                        and counts.get(severity, 0)
                        < OPEN_ALERT_LIMITS_BY_SEVERITY[severity]
                    ):
                        effect_key = f"automation-action-failed:{action_id}"
                        failure_alert_id = str(
                            uuid.uuid5(uuid.NAMESPACE_URL, effect_key)
                        )
                        failure_fingerprint = str(
                            uuid.uuid5(
                                uuid.NAMESPACE_URL,
                                f"fingerprint:{effect_key}",
                            )
                        )
                        failure_evidence = canonical_json_dumps(
                            {
                                "action_id": action_id,
                                "action_type": str(row["action_type"]),
                                "result": normalized_result,
                            },
                            max_bytes=MAX_STORED_JSON_BYTES,
                        )
                        cursor = self._connection.execute(
                            """
                            INSERT OR IGNORE INTO alerts(
                              alert_id, agent_id, kind, title, summary, severity,
                              confidence, evidence_json, recommendation,
                              recommended_action, fingerprint, status, created_at,
                              last_observed_at, credential_epoch, profile_id,
                              profile_fingerprint, agent_version
                            ) VALUES(?, ?, 'automation_action_failed', ?, ?, ?,
                              0.99, ?, ?, 'observe', ?, 'open', ?, ?, ?, ?, ?, ?)
                            """,
                            (
                                failure_alert_id,
                                row["agent_id"],
                                "Automated action failed"
                                + (
                                    " and was rolled back"
                                    if rolled_back
                                    else ""
                                ),
                                str(
                                    normalized_result.get(
                                        "message",
                                        "The agent could not complete the approved action.",
                                    )
                                )[:8192],
                                severity,
                                failure_evidence,
                                (
                                    "Review the result and service health. "
                                    "The previous state was restored."
                                    if rolled_back
                                    else "Review the host directly; automatic "
                                    "rollback could not be confirmed."
                                ),
                                failure_fingerprint,
                                now,
                                now,
                                int(row["credential_epoch"]),
                                str(row["profile_id"]),
                                str(row["profile_fingerprint"]),
                                str(row["agent_version"]),
                            ),
                        )
                        failure_alert_admitted = cursor.rowcount == 1

                audit_id = str(
                    uuid.uuid5(uuid.NAMESPACE_URL, f"complete-action:{action_id}")
                )
                self._connection.execute(
                    """
                    INSERT INTO audit_log(
                      audit_id, actor, operation, subject, detail_json, created_at
                    ) VALUES(?, ?, 'complete_action', ?, ?, ?)
                    """,
                    (
                        audit_id,
                        str(expected_agent_id or "agent")[:128],
                        action_id,
                        canonical_json_dumps(
                            {
                                "success": terminal_success,
                                "failure_alert_admitted": failure_alert_admitted,
                                "binding_current": binding_current,
                            }
                        ),
                        now,
                    ),
                )
                self._connection.commit()
                return "new"
            except Exception:
                if self._connection.in_transaction:
                    self._connection.rollback()
                raise

    def reconcile_action_outcome(
        self,
        action_id: str,
        resolution: str,
    ) -> dict[str, Any] | None:
        """Resolve a delivered envelope whose execution outcome is unknown.

        ``executed`` preserves duplicate suppression without fabricating an
        agent attestation. ``not_executed`` releases duplicate suppression so
        an operator can make a fresh, newly authorized decision if the linked
        alert is still open. Reconciliation and its audit record commit as one
        transaction and exact retries are idempotent.
        """
        if not isinstance(action_id, str) or not 1 <= len(action_id) <= 128:
            raise ValueError("action identity is invalid")
        if not isinstance(resolution, str) or resolution not in {
            "executed",
            "not_executed",
        }:
            raise ValueError(
                "action outcome resolution must be executed or not_executed"
            )
        with self._lock:
            self._connection.execute("BEGIN IMMEDIATE")
            self._start_quarantine_boundary_locked()
            try:
                now = time.time()
                row = self._connection.execute(
                    "SELECT status, result_json, result_source, alert_id, "
                    "credential_epoch, profile_id, profile_fingerprint, "
                    "agent_version FROM actions "
                    "WHERE action_id=?",
                    (action_id,),
                ).fetchone()
                if row is None:
                    self._connection.rollback()
                    self._finish_quarantine_boundary_locked()
                    return None

                terminal_status = (
                    "reconciled" if resolution == "executed" else "failed"
                )
                existing_resolution: str | None = None
                if row["result_source"] == "operator" and row["result_json"]:
                    stored = self._decode_stored_json(
                        row["result_json"],
                        table_name="actions",
                        row_key=action_id,
                        column_name="result_json",
                        expected_type=dict,
                    )
                    if stored is not None and stored.get("reconciled") is True:
                        value = stored.get("resolution")
                        if value in {"executed", "not_executed"}:
                            existing_resolution = str(value)
                if (
                    row["status"] == terminal_status
                    and existing_resolution == resolution
                ):
                    self._connection.rollback()
                    self._finish_quarantine_boundary_locked()
                    return {
                        "action_id": action_id,
                        "resolution": resolution,
                        "status": terminal_status,
                        "completion": "exact_retry",
                    }
                if row["status"] != "outcome_unknown":
                    raise RuntimeError(
                        "action is not awaiting outcome reconciliation"
                    )

                result = {
                    "success": resolution == "executed",
                    "reconciled": True,
                    "resolution": resolution,
                    "message": (
                        "operator confirmed the delivered action executed"
                        if resolution == "executed"
                        else "operator confirmed the delivered action did not execute"
                    ),
                }
                cursor = self._connection.execute(
                    """
                    UPDATE actions SET status=?, completed_at=?, result_json=?,
                      result_source='operator'
                    WHERE action_id=? AND status='outcome_unknown'
                    """,
                    (
                        terminal_status,
                        now,
                        canonical_json_dumps(result),
                        action_id,
                    ),
                )
                if cursor.rowcount != 1:
                    raise RuntimeError("action outcome changed concurrently")
                alert_reopened = False
                if resolution == "not_executed" and row["alert_id"]:
                    reopened = self._connection.execute(
                        """
                        UPDATE alerts SET status='open', decision=NULL,
                          decided_at=NULL
                        WHERE alert_id=? AND status='decided'
                          AND decision IN ('approve','release','accept_change')
                          AND credential_epoch=? AND profile_id=?
                          AND profile_fingerprint=? AND agent_version=?
                        """,
                        (
                            row["alert_id"],
                            row["credential_epoch"],
                            row["profile_id"],
                            row["profile_fingerprint"],
                            row["agent_version"],
                        ),
                    )
                    alert_reopened = reopened.rowcount == 1
                self._connection.execute(
                    """
                    INSERT INTO audit_log(
                      audit_id, actor, operation, subject,
                      detail_json, created_at
                    ) VALUES(?, 'operator', 'reconcile_action_outcome', ?, ?, ?)
                    """,
                    (
                        str(uuid.uuid4()),
                        action_id,
                        canonical_json_dumps(
                            {
                                "resolution": resolution,
                                "alert_reopened": alert_reopened,
                            }
                        ),
                        now,
                    ),
                )
                self._connection.commit()
                self._finish_quarantine_boundary_locked()
                return {
                    "action_id": action_id,
                    "resolution": resolution,
                    "status": terminal_status,
                    "completion": "new",
                    "alert_reopened": alert_reopened,
                }
            except Exception:
                self._rollback_preserving_quarantine_locked()
                raise


    def get_action(self, action_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                "SELECT * FROM actions WHERE action_id=?", (action_id,)
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["parameters"] = self._decode_stored_json(
            item.pop("parameters_json"),
            table_name="actions",
            row_key=action_id,
            column_name="parameters_json",
            expected_type=dict,
            fallback=INVALID_JSON_PLACEHOLDER,
        )
        item["result"] = (
            self._decode_stored_json(
                item["result_json"],
                table_name="actions",
                row_key=action_id,
                column_name="result_json",
                expected_type=dict,
                fallback=INVALID_JSON_PLACEHOLDER,
            )
            if item.get("result_json")
            else None
        )
        item.pop("result_json", None)
        return item

    def latest_action_for_agent(
        self, agent_id: str, action_type: str
    ) -> dict[str, Any] | None:
        with self._lock:
            row = self._connection.execute(
                """
                SELECT * FROM actions
                WHERE agent_id=? AND action_type=?
                ORDER BY created_at DESC LIMIT 1
                """,
                (agent_id, action_type),
            ).fetchone()
        if not row:
            return None
        item = dict(row)
        item["parameters"] = self._decode_stored_json(
            item.pop("parameters_json"),
            table_name="actions",
            row_key=str(item["action_id"]),
            column_name="parameters_json",
            expected_type=dict,
            fallback=INVALID_JSON_PLACEHOLDER,
        )
        item["result"] = (
            self._decode_stored_json(
                item["result_json"],
                table_name="actions",
                row_key=str(item["action_id"]),
                column_name="result_json",
                expected_type=dict,
                fallback=INVALID_JSON_PLACEHOLDER,
            )
            if item.get("result_json")
            else None
        )
        item.pop("result_json", None)
        item["automated"] = bool(item.get("automated"))
        return item

    def matching_capture_for_agent(
        self,
        agent_id: str,
        files: list[dict[str, Any]],
        *,
        binding: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Return the newest fully attested capture for an exact baseline."""

        expected_parameters = {"files": files}
        binding_values = self._binding_values(binding or {})
        with self._lock:
            rows = self._connection.execute(
                "SELECT * FROM actions WHERE agent_id=? "
                "AND action_type='capture_restore_point' AND status='completed' "
                "ORDER BY created_at DESC, action_id DESC LIMIT 128",
                (agent_id,),
            ).fetchall()
        for row in rows:
            if binding is not None and (
                int(row["credential_epoch"]),
                str(row["profile_id"]),
                str(row["profile_fingerprint"]),
                str(row["agent_version"]),
            ) != binding_values:
                continue
            parameters = self._decode_stored_json(
                row["parameters_json"],
                table_name="actions",
                row_key=str(row["action_id"]),
                column_name="parameters_json",
                expected_type=dict,
            )
            result = self._decode_stored_json(
                row["result_json"],
                table_name="actions",
                row_key=str(row["action_id"]),
                column_name="result_json",
                expected_type=dict,
            )
            if (
                parameters != expected_parameters
                or result is None
                or capture_receipt_error(files, result) is not None
            ):
                continue
            item = dict(row)
            item.pop("parameters_json", None)
            item.pop("result_json", None)
            item["parameters"] = parameters
            item["result"] = result
            item["automated"] = bool(item.get("automated"))
            return item
        return None

    def dashboard(self, stale_after: float = 90.0) -> dict[str, Any]:
        with self._lock:
            agents = [
                dict(row)
                for row in self._connection.execute(
                    """
                    SELECT a.agent_id, a.hostname, a.platform, a.registered_at, a.last_seen,
                           a.enabled, a.last_sequence, a.boot_id,
                           COALESCE(b.status, 'missing') AS baseline_status
                    FROM agents a LEFT JOIN baselines b ON a.agent_id=b.agent_id
                    ORDER BY a.hostname
                    """
                )
            ]
            alerts = [dict(row) for row in self._connection.execute(
                "SELECT * FROM alerts ORDER BY CASE status WHEN 'open' THEN 0 ELSE 1 END, created_at DESC LIMIT 100"
            )]
            actions = [dict(row) for row in self._connection.execute(
                "SELECT * FROM actions ORDER BY created_at DESC LIMIT 100"
            )]
            events = [
                dict(row)
                for row in self._connection.execute(
                    "SELECT * FROM external_events ORDER BY created_at DESC LIMIT 100"
                )
            ]
            audit = [
                dict(row)
                for row in self._connection.execute(
                    "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 100"
                )
            ]
        for alert in alerts:
            alert["evidence"] = self._decode_stored_json(
                alert.pop("evidence_json"),
                table_name="alerts",
                row_key=str(alert["alert_id"]),
                column_name="evidence_json",
                expected_type=dict,
                fallback=INVALID_JSON_PLACEHOLDER,
            )
            if alert["evidence"].get("unavailable") and alert["status"] == "open":
                with self._lock:
                    self._connection.execute(
                        """
                        UPDATE alerts SET status='decided', decision='json_quarantined',
                          decided_at=? WHERE alert_id=? AND status='open'
                        """,
                        (time.time(), alert["alert_id"]),
                    )
                    self._connection.commit()
                alert["status"] = "decided"
                alert["decision"] = "json_quarantined"
        for action in actions:
            action["parameters"] = self._decode_stored_json(
                action.pop("parameters_json"),
                table_name="actions",
                row_key=str(action["action_id"]),
                column_name="parameters_json",
                expected_type=dict,
                fallback=INVALID_JSON_PLACEHOLDER,
            )
            if (
                action["parameters"].get("unavailable")
                and action["status"] in {"queued", "dispatched"}
            ):
                with self._lock:
                    self._connection.execute(
                        """
                        UPDATE actions SET
                          status=CASE status
                            WHEN 'queued' THEN 'failed'
                            ELSE 'outcome_unknown'
                          END,
                          completed_at=CASE status
                            WHEN 'queued' THEN ?
                            ELSE NULL
                          END,
                          result_json=?, result_source='controller'
                        WHERE action_id=? AND status IN ('queued','dispatched')
                        """,
                        (
                            time.time(),
                            canonical_json_dumps(
                                {
                                    "success": False,
                                    "message": "action parameters failed strict stored-JSON validation",
                                }
                            ),
                            action["action_id"],
                        ),
                    )
                    self._connection.commit()
                action["status"] = (
                    "failed"
                    if action["status"] == "queued"
                    else "outcome_unknown"
                )
            action["result"] = (
                self._decode_stored_json(
                    action["result_json"],
                    table_name="actions",
                    row_key=str(action["action_id"]),
                    column_name="result_json",
                    expected_type=dict,
                    fallback=INVALID_JSON_PLACEHOLDER,
                )
                if action["result_json"]
                else None
            )
            action.pop("result_json")
            action["automated"] = bool(action.get("automated"))
        for item in audit:
            item["detail"] = self._decode_stored_json(
                item.pop("detail_json"),
                table_name="audit_log",
                row_key=str(item["audit_id"]),
                column_name="detail_json",
                expected_type=dict,
                fallback=INVALID_JSON_PLACEHOLDER,
            )
        now = time.time()
        for agent in agents:
            try:
                if (
                    not isinstance(agent.get("agent_id"), str)
                    or not isinstance(agent.get("hostname"), str)
                    or not isinstance(agent.get("platform"), str)
                    or type(agent.get("enabled")) is not int
                    or agent["enabled"] not in {0, 1}
                    or type(agent.get("last_sequence")) is not int
                    or not -1 <= agent["last_sequence"] <= 2**63 - 1
                    or not isinstance(agent.get("boot_id"), str)
                    or type(agent.get("last_seen")) not in {int, float}
                    or not math.isfinite(agent["last_seen"])
                    or not 0 <= agent["last_seen"] <= 2**63 - 1
                    or type(agent.get("registered_at")) not in {int, float}
                    or not math.isfinite(agent["registered_at"])
                    or not 0 <= agent["registered_at"] <= 2**63 - 1
                    or agent.get("baseline_status")
                    not in {"missing", "pending", "approved", "invalid", "invalidated"}
                ):
                    raise ValueError("stored dashboard agent row is invalid")
                agent["enabled"] = bool(agent["enabled"])
                age = max(0.0, now - float(agent["last_seen"]))
            except (TypeError, ValueError, OverflowError) as exc:
                row_key = str(agent.get("agent_id", "unknown"))[:128]
                self._quarantine_json(
                    "agents", row_key, "dashboard_row", agent, str(exc)
                )
                agent.clear()
                agent.update(
                    {
                        "agent_id": row_key,
                        "hostname": "stored agent requires review",
                        "platform": "unknown",
                        "enabled": False,
                        "baseline_status": "invalid",
                        "health": "invalid",
                    }
                )
                continue
            agent["health"] = (
                "revoked"
                if not agent["enabled"]
                else "stale"
                if age > max(15.0, stale_after)
                else "online"
            )
        return {
            "agents": agents,
            "alerts": alerts,
            "actions": actions,
            "protected_accounts": self.protected_account_rows(),
            "events": events,
            "audit": audit,
            "change_grants": self.change_grants(),
            "stored_json": self.stored_json_readiness(),
            "server_time": now,
        }

    def latest_telemetry(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT agent_id, latest_telemetry, last_seen FROM agents
                WHERE latest_telemetry IS NOT NULL
                """
            ).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            agent_id = str(row["agent_id"])
            fallback = {
                **INVALID_JSON_PLACEHOLDER,
                "agent_id": agent_id,
                "platform": "unknown",
                "collector_errors": ["stored telemetry requires operator review"],
                "integrity": [],
                "probes": [],
                "services": [],
                "interfaces": [],
            }
            decoded = self._decode_stored_json(
                row["latest_telemetry"],
                table_name="agents",
                row_key=agent_id,
                column_name="latest_telemetry",
                expected_type=dict,
            )
            try:
                if decoded is None:
                    raise ValueError("stored telemetry failed strict JSON validation")
                from .validation import validate_telemetry

                if (
                    type(row["last_seen"]) not in {int, float}
                    or not math.isfinite(row["last_seen"])
                    or not 0 <= float(row["last_seen"]) <= 2**63 - 1
                ):
                    raise ValueError("stored telemetry receipt time is invalid")
                normalized = validate_telemetry(
                    decoded,
                    expected_agent_id=agent_id,
                    now=float(row["last_seen"]),
                )
                if not hmac_compare_json(
                    canonical_json_dumps(normalized),
                    canonical_json_dumps(decoded),
                ):
                    raise ValueError("stored telemetry is not canonically normalized")
                result.append(normalized)
            except (TypeError, ValueError, OverflowError) as exc:
                self._quarantine_json(
                    "agents",
                    agent_id,
                    "latest_telemetry_semantics",
                    row["latest_telemetry"],
                    str(exc),
                )
                result.append(dict(fallback))
        return result

    def stale_agents(self, threshold_seconds: float = 90.0) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._connection.execute(
                """
                SELECT agent_id, hostname, platform, last_seen,
                       credential_epoch, profile_id, profile_fingerprint,
                       agent_version
                FROM agents
                WHERE enabled=1 AND last_seen<?
                ORDER BY last_seen
                """,
                (time.time() - threshold_seconds,),
            ).fetchall()
        return [dict(row) for row in rows]

    def _backup_to(self, output: sqlite3.Connection) -> None:
        self._connection.backup(output)

    def backup(self, destination: str | Path) -> Path:
        target = Path(destination)
        if self.path != ":memory:" and target.resolve() == Path(self.path).resolve():
            raise ValueError("backup destination must differ from the live database")
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.parent.is_symlink() or not target.parent.is_dir():
            raise ValueError("backup directory is unavailable or is a symbolic link")
        if target.is_symlink():
            raise ValueError("backup destination must not be a symbolic link")
        temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
        try:
            with self._lock:
                output = sqlite3.connect(temporary)
                try:
                    self._backup_to(output)
                    integrity = output.execute("PRAGMA integrity_check").fetchone()
                    if not integrity or str(integrity[0]) != "ok":
                        raise sqlite3.DatabaseError("new backup failed its integrity check")
                finally:
                    output.close()
            if os.name == "posix":
                temporary.chmod(0o600)
                with temporary.open("rb") as handle:
                    os.fsync(handle.fileno())
            if target.is_symlink():
                raise ValueError("backup destination became a symbolic link")
            os.replace(temporary, target)
            if os.name == "posix":
                descriptor = os.open(target.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        return target

    def integrity_check(self) -> str:
        with self._lock:
            row = self._connection.execute("PRAGMA integrity_check").fetchone()
        return str(row[0])

    def prune(self, retention_days: int = 30) -> dict[str, int]:
        cutoff = time.time() - max(1, retention_days) * 86400
        removed: dict[str, int] = {}
        with self._lock:
            for table, condition in (
                ("alerts", "status!='open' AND created_at<?"),
                (
                    "actions",
                    "status IN ('completed','failed','reconciled') AND created_at<?",
                ),
                ("external_events", "created_at<?"),
                ("audit_log", "created_at<?"),
                ("learning_feedback", "created_at<?"),
                ("change_grants", "expires_at<?"),
            ):
                cursor = self._connection.execute(
                    f"DELETE FROM {table} WHERE {condition}", (cutoff,)
                )
                removed[table] = cursor.rowcount
            removed["json_quarantine"] = self._prune_resolved_quarantine_locked(
                cutoff=cutoff
            )
            self._connection.commit()
        return removed
