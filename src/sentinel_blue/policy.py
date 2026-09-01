"""Fixed safety policy separating evidence automation from human decisions."""

from __future__ import annotations

import re
from typing import Any

from .process_identity import validate_process_identity


SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
TRANSACTION_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")


ACTION_RISK = {
    "observe": "none",
    "snapshot": "low",
    "validate_service": "low",
    "capture_restore_point": "low",
    "restore_integrity": "high",
    "rollback_integrity": "high",
    "quarantine_session": "high",
    "release_quarantine": "medium",
    "restart_service": "high",
    "rollback_service": "high",
}
ALLOWED_ACTIONS = frozenset(ACTION_RISK)
AUTOMATIC_ACTIONS = frozenset({"snapshot", "validate_service", "capture_restore_point"})


def action_risk(action_type: str) -> str:
    if action_type not in ALLOWED_ACTIONS:
        raise ValueError(f"unsupported action type: {action_type}")
    return ACTION_RISK[action_type]


def should_automate_evidence(action_type: str, severity: str) -> bool:
    return action_type in AUTOMATIC_ACTIONS and severity in {"medium", "high", "critical"}


def validate_action_parameters(
    action_type: str,
    parameters: dict[str, Any],
    *,
    require_process_binding: bool = False,
) -> None:
    action_risk(action_type)
    if not isinstance(parameters, dict):
        raise ValueError("action parameters must be an object")
    if action_type in {"quarantine_session", "release_quarantine"}:
        session = parameters.get("session", parameters)
        if not isinstance(session, dict):
            raise ValueError("session action requires a session object")
        process_id = session.get("process_id")
        if process_id is not None and (type(process_id) is not int or process_id <= 2):
            raise ValueError("session process_id must be a safe positive integer")
        if require_process_binding:
            if type(process_id) is not int or process_id > 2**31 - 1:
                raise ValueError("session action requires an exact safe process_id")
            for field, limit in (
                ("username", 128),
                ("source", 256),
                ("session_id", 256),
            ):
                value = session.get(field)
                if (
                    not isinstance(value, str)
                    or not value
                    or len(value) > limit
                    or "\x00" in value
                    or any(ord(character) < 32 for character in value)
                ):
                    raise ValueError(f"session action requires an exact {field}")
            for field in ("privileged", "interactive"):
                if type(session.get(field)) is not bool:
                    raise ValueError(f"session action requires an exact {field} flag")
            try:
                identity = validate_process_identity(session.get("process_identity"))
            except ValueError as exc:
                raise ValueError(f"session action process identity is invalid: {exc}") from exc
            if identity["process_id"] != process_id:
                raise ValueError("session process identity does not match process_id")
            observation = parameters.get("observation")
            if not isinstance(observation, dict) or set(observation) != {
                "boot_id",
                "sequence",
                "payload_sha256",
            }:
                raise ValueError("session action requires an exact telemetry observation")
            boot_id = observation.get("boot_id")
            sequence = observation.get("sequence")
            payload_sha256 = observation.get("payload_sha256")
            if (
                not isinstance(boot_id, str)
                or not boot_id
                or boot_id == "unknown"
                or len(boot_id) > 256
                or "\x00" in boot_id
            ):
                raise ValueError("session action observation boot_id is invalid")
            if type(sequence) is not int or not 0 <= sequence <= 2**63 - 1:
                raise ValueError("session action observation sequence is invalid")
            if (
                not isinstance(payload_sha256, str)
                or not SHA256.fullmatch(payload_sha256)
                or payload_sha256 != payload_sha256.casefold()
            ):
                raise ValueError("session action observation digest is invalid")
            if identity["boot_id"] != boot_id:
                raise ValueError(
                    "session process identity does not match the observation boot"
                )
    if action_type in {"restart_service", "rollback_service"}:
        service = parameters.get("service")
        if not isinstance(service, str) or not SERVICE_NAME.fullmatch(service):
            raise ValueError(f"{action_type} requires a service name")
    if action_type == "rollback_service" and parameters.get("desired_state") not in {"running", "stopped"}:
        raise ValueError("rollback_service requires a running or stopped desired_state")
    if action_type == "capture_restore_point":
        files = parameters.get("files")
        if not isinstance(files, list) or not files or len(files) > 256:
            raise ValueError("capture_restore_point requires 1 to 256 files")
        for item in files:
            if not isinstance(item, dict):
                raise ValueError("each restore-point file requires a path and SHA-256 digest")
            path = item.get("path")
            digest = item.get("sha256")
            if (
                not isinstance(path, str)
                or not path
                or len(path) > 1024
                or "\x00" in path
                or not isinstance(digest, str)
                or not SHA256.fullmatch(digest)
            ):
                raise ValueError("restore-point path or SHA-256 digest is invalid")
            security_digest = item.get("security_descriptor_sha256", "")
            if security_digest and (
                not isinstance(security_digest, str)
                or not SHA256.fullmatch(security_digest)
            ):
                raise ValueError("restore-point security descriptor digest is invalid")
    if action_type == "restore_integrity":
        if not isinstance(parameters.get("path"), str) or not parameters.get("path"):
            raise ValueError("restore_integrity requires a path")
        if not isinstance(parameters.get("baseline_sha256"), str):
            raise ValueError("restore_integrity requires baseline_sha256")
        if (
            len(parameters["path"]) > 1024
            or "\x00" in parameters["path"]
            or not SHA256.fullmatch(parameters["baseline_sha256"])
        ):
            raise ValueError("restore_integrity path or baseline digest is invalid")
        observed = parameters.get("observed_sha256")
        if observed is not None and (
            not isinstance(observed, str) or not SHA256.fullmatch(observed)
        ):
            raise ValueError("restore_integrity observed digest is invalid")
        if "observed_missing" in parameters and type(parameters["observed_missing"]) is not bool:
            raise ValueError("restore_integrity observed_missing must be a boolean")
        for name in (
            "baseline_security_descriptor_sha256",
            "observed_security_descriptor_sha256",
        ):
            digest = parameters.get(name)
            if digest not in (None, "") and (
                not isinstance(digest, str) or not SHA256.fullmatch(digest)
            ):
                raise ValueError(f"restore_integrity {name} is invalid")
    if action_type == "rollback_integrity":
        transaction_id = parameters.get("transaction_id")
        if not isinstance(transaction_id, str) or not TRANSACTION_ID.fullmatch(
            transaction_id
        ):
            raise ValueError("rollback_integrity requires a transaction_id")
    probes = parameters.get("probes")
    if probes is not None and (not isinstance(probes, list) or len(probes) > 256):
        raise ValueError("probes must be an array of at most 256 entries")
    if isinstance(probes, list) and any(not isinstance(probe, dict) for probe in probes):
        raise ValueError("probes must contain objects")
