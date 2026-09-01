"""Reversible agent-side response actions."""

from __future__ import annotations

import json
import hashlib
import math
import os
import platform
import re
import signal
import subprocess
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .probes import run_probes
from .json_codec import canonical_json_bytes
from .policy import validate_action_parameters
from .process_identity import (
    ProcessIdentityMismatch,
    inspect_process_identity,
    signal_verified_process,
    validate_process_identity,
)
from .restoration import RestorePointStore
from .state import read_private_json, remove_private_file, write_private_json
from .validation import validate_telemetry


SERVICE_NAME = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
MAX_SNAPSHOTS = 256
MAX_SERVICE_TRANSACTIONS = 256
MAX_QUARANTINE_TTL = 3600.0


class ActionExecutor:
    def __init__(
        self,
        state_dir: str | Path,
        allow_containment: bool = False,
        authorized_networks: list[str] | None = None,
        quarantine_ttl: float = 300.0,
        allow_restoration: bool = False,
        default_probes: list[dict[str, Any]] | None = None,
        authorized_hosts: list[str] | tuple[str, ...] | None = None,
        excluded_hosts: list[str] | tuple[str, ...] | None = None,
    ):
        if (
            type(quarantine_ttl) not in {int, float}
            or not math.isfinite(float(quarantine_ttl))
        ):
            raise ValueError("quarantine TTL must be a finite number")
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.allow_containment = allow_containment
        self.authorized_networks = authorized_networks or []
        self.authorized_hosts = list(authorized_hosts or [])
        self.excluded_hosts = list(excluded_hosts or [])
        self.quarantine_ttl = max(
            30.0, min(float(quarantine_ttl), MAX_QUARANTINE_TTL)
        )
        self.quarantine_file = self.state_dir / "quarantine.json"
        self.allow_restoration = allow_restoration
        self.default_probes = default_probes or []
        self.restore_points = RestorePointStore(
            self.state_dir,
            self.authorized_networks,
            authorized_hosts=self.authorized_hosts,
            excluded_hosts=self.excluded_hosts,
        )
        self.restore_recovery = self.restore_points.recover_incomplete()
        self.quarantine_recovery = self._recover_incomplete_quarantines()
        self.service_recovery = self._recover_incomplete_service_transactions()

    def refresh_restore_recovery(self) -> dict[str, Any]:
        """Re-evaluate restoration transactions after in-process mutations."""
        try:
            self.restore_recovery = self.restore_points.recover_incomplete()
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self.restore_recovery = {
                "healthy": False,
                "recovered": [],
                "unresolved": [],
                "error": f"restoration recovery scan failed: {exc}",
            }
        return dict(self.restore_recovery)

    def refresh_quarantine_recovery(
        self, current_boot_id: str = "unknown", *, release_expired: bool = True
    ) -> dict[str, Any]:
        """Re-evaluate durable quarantine transactions without losing failures."""
        scan_error = ""
        try:
            recovery = self._recover_incomplete_quarantines(current_boot_id)
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            scan_error = f"quarantine recovery scan failed: {exc}"[:500]
            recovery = {"healthy": False, "recovered": [], "unresolved": [scan_error]}
        release_error = ""
        if release_expired:
            try:
                self.release_expired_quarantines(current_boot_id)
            except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
                release_error = f"expired quarantine release failed: {exc}"[:500]
            try:
                recovery = self._recover_incomplete_quarantines(
                    current_boot_id, retry_unresolved=False
                )
            except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
                scan_error = f"quarantine recovery scan failed: {exc}"[:500]
                recovery = {"healthy": False, "recovered": [], "unresolved": [scan_error]}
        for error in (scan_error, release_error):
            if error and error not in recovery.setdefault("unresolved", []):
                recovery["unresolved"].append(error)
                recovery["healthy"] = False
        self.quarantine_recovery = recovery
        return dict(self.quarantine_recovery)

    def refresh_service_recovery(self) -> dict[str, Any]:
        """Re-evaluate service transactions after in-process mutations."""
        try:
            self.service_recovery = self._recover_incomplete_service_transactions()
        except (OSError, RuntimeError, TypeError, ValueError, json.JSONDecodeError) as exc:
            self.service_recovery = {
                "healthy": False,
                "recovered": [],
                "unresolved": [
                    {
                        "transaction": "*",
                        "reason": f"service recovery scan failed: {exc}"[:500],
                    }
                ],
            }
        return dict(self.service_recovery)

    def refresh_recovery(self, current_boot_id: str = "unknown") -> dict[str, dict[str, Any]]:
        """Refresh every durable action recovery gate for the current cycle."""
        return {
            "restoration": self.refresh_restore_recovery(),
            "quarantine": self.refresh_quarantine_recovery(current_boot_id),
            "service": self.refresh_service_recovery(),
        }

    def execute(
        self, action_type: str, parameters: dict[str, Any], current_telemetry: dict[str, Any]
    ) -> dict[str, Any]:
        started = time.time()
        if action_type == "observe":
            return self._result(action_type, True, "observation recorded", started)
        if action_type == "snapshot":
            destination = self.state_dir / f"snapshot-{time.time_ns()}.json"
            try:
                write_private_json(destination, current_telemetry)
            except (OSError, TypeError, ValueError) as exc:
                return self._result(action_type, False, f"snapshot failed: {exc}", started)
            warnings = self._prune_snapshots()
            return self._result(
                action_type,
                True,
                f"snapshot written to {destination.name}",
                started,
                retention_warnings=warnings,
            )
        if action_type == "capture_restore_point":
            try:
                result = self.restore_points.capture(list(parameters.get("files", [])))
                return self._result(
                    action_type,
                    bool(result.pop("success")),
                    result.pop("message"),
                    started,
                    # A baseline-promotion receipt must positively attest that
                    # bytes were stored.  Do not rely on an omitted flag being
                    # interpreted as a non-dry-run operation downstream.
                    dry_run=False,
                    **result,
                )
            except (OSError, TypeError, ValueError) as exc:
                return self._result(action_type, False, f"restore-point capture failed: {exc}", started)
        if action_type == "restore_integrity":
            try:
                result = self.restore_points.restore(
                    parameters,
                    allowed=self.allow_restoration,
                    probes=list(parameters.get("probes") or self.default_probes),
                )
                return self._result(action_type, bool(result.pop("success")), result.pop("message"), started, **result)
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                return self._result(action_type, False, f"file restoration failed: {exc}", started)
        if action_type == "rollback_integrity":
            try:
                result = self.restore_points.rollback(
                    str(parameters.get("transaction_id", "")),
                    allowed=self.allow_restoration,
                    probes=list(parameters.get("probes") or self.default_probes),
                )
                return self._result(action_type, bool(result.pop("success")), result.pop("message"), started, **result)
            except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
                return self._result(action_type, False, f"restoration rollback failed: {exc}", started)
        if action_type == "quarantine_session":
            return self._quarantine(parameters, started, current_telemetry)
        if action_type == "release_quarantine":
            return self._release(parameters, started, current_telemetry)
        if action_type == "restart_service":
            return self._restart_service(parameters, started)
        if action_type == "rollback_service":
            return self._rollback_service(parameters, started)
        if action_type == "validate_service":
            results = run_probes(
                list(parameters.get("probes", [])),
                self.authorized_networks,
                authorized_hosts=self.authorized_hosts,
                excluded_hosts=self.excluded_hosts,
            )
            healthy = bool(results) and all(item.healthy for item in results)
            return self._result(
                action_type,
                healthy,
                "all service probes passed" if healthy else "one or more service probes failed",
                started,
                probes=[asdict(item) for item in results],
            )
        return self._result(action_type, False, "unsupported action", started)

    def _quarantine(
        self, parameters: dict[str, Any], started: float, current_telemetry: dict[str, Any]
    ) -> dict[str, Any]:
        session = parameters.get("session", parameters)
        process_id = session.get("process_id") if isinstance(session, dict) else None
        if not self.allow_containment:
            return self._result(
                "quarantine_session", True, "dry run: containment is disabled", started, dry_run=True
            )
        if not isinstance(process_id, int) or process_id <= 2 or process_id == os.getpid():
            return self._result(
                "quarantine_session", False, "no safe session process ID was supplied", started
            )
        suspended = False
        suspend_attempted = False
        resume_confirmed = False
        prepared = False
        record: dict[str, Any] = {}
        try:
            (
                session,
                identity,
                source_observation,
                execution_observation,
            ) = self._validate_current_session_authority(
                "quarantine_session", parameters, current_telemetry
            )
            existing = self._read_quarantine()
            quarantined_at = time.time()
            if not math.isfinite(quarantined_at):
                raise OSError("system clock is unavailable for bounded quarantine")
            record = {
                "process_id": process_id,
                "process_identity": identity,
                "username": session["username"],
                "source": session["source"],
                "session_id": session["session_id"],
                "privileged": session["privileged"],
                "interactive": session["interactive"],
                "target_observation": source_observation,
                "execution_observation": execution_observation,
                "quarantined_at": quarantined_at,
                "expires_at": quarantined_at + self.quarantine_ttl,
                "boot_id": execution_observation["boot_id"],
                "status": "preparing",
            }
            existing[str(process_id)] = record
            self._write_quarantine(existing)
            prepared = True
            suspend_attempted = True
            self._suspend_process(process_id, identity)
            suspended = True
            if self._process_identity(
                process_id, boot_id=execution_observation["boot_id"]
            ) != identity:
                raise ProcessIdentityMismatch(
                    "process identity changed after suspension; operator review is required"
                )
            record["status"] = "active"
            existing[str(process_id)] = record
            self._write_quarantine(existing)
            probes = run_probes(
                list(parameters.get("probes", [])),
                self.authorized_networks,
                authorized_hosts=self.authorized_hosts,
                excluded_hosts=self.excluded_hosts,
            )
            if probes and not all(item.healthy for item in probes):
                self._resume_process(process_id, identity)
                resume_confirmed = True
                suspended = False
                existing.pop(str(process_id), None)
                self._write_quarantine(existing)
                return self._result(
                    "quarantine_session",
                    False,
                    "session suspension failed health validation and was rolled back",
                    started,
                    rolled_back=True,
                    probes=[asdict(item) for item in probes],
                )
            return self._result("quarantine_session", True, "session process suspended", started, record=record)
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            rolled_back = resume_confirmed
            rollback_error = ""
            if (
                suspend_attempted
                and not resume_confirmed
                and (suspended or not isinstance(exc, ProcessIdentityMismatch))
            ):
                try:
                    self._resume_process(process_id, identity)
                    resume_confirmed = True
                    suspended = False
                    rolled_back = True
                except (OSError, PermissionError, RuntimeError, ValueError) as resume_exc:
                    rollback_error = f"process resume failed: {resume_exc}"[:500]
            if prepared:
                try:
                    existing = self._read_quarantine()
                    if resume_confirmed:
                        existing.pop(str(process_id), None)
                    else:
                        failed = existing.get(str(process_id))
                        if not isinstance(failed, dict):
                            failed = dict(record)
                        failed["status"] = "rollback_failed"
                        failed["failure_at"] = time.time()
                        failed["last_error"] = rollback_error or str(exc)[:500]
                        existing[str(process_id)] = failed
                    self._write_quarantine(existing)
                except (OSError, RuntimeError, TypeError, ValueError) as state_exc:
                    detail = rollback_error or str(exc)
                    self._set_quarantine_recovery_unhealthy(
                        str(process_id), f"{detail}; quarantine state update failed: {state_exc}"
                    )
                else:
                    if not resume_confirmed:
                        self._set_quarantine_recovery_unhealthy(
                            str(process_id), rollback_error or str(exc)
                        )
            return self._result(
                "quarantine_session",
                False,
                f"suspension transaction failed: {exc}",
                started,
                rolled_back=rolled_back and not suspended,
                review_required=isinstance(exc, ProcessIdentityMismatch),
            )

    def _validate_current_session_authority(
        self,
        action_type: str,
        parameters: dict[str, Any],
        current_telemetry: dict[str, Any],
    ) -> tuple[
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
        dict[str, Any],
    ]:
        """Bind source provenance to the same exact live session and process.

        A manually approved action is normally fetched in a later collection
        cycle than the observation that justified it.  The signed source
        digest remains immutable provenance, while same-boot monotonic sequence,
        exact current session fields, and native process identity establish that
        the target still exists.  The action envelope expiry bounds how old that
        source authority may become.
        """
        validate_action_parameters(
            action_type, parameters, require_process_binding=True
        )
        normalized = validate_telemetry(current_telemetry)
        expected_observation = dict(parameters["observation"])
        current_observation = {
            "boot_id": str(normalized["boot_id"]),
            "sequence": int(normalized["sequence"]),
            "payload_sha256": hashlib.sha256(
                canonical_json_bytes(normalized)
            ).hexdigest(),
        }
        if current_observation["boot_id"] != expected_observation["boot_id"]:
            raise ProcessIdentityMismatch(
                "host boot changed after the source observation; no process was signaled"
            )
        if current_observation["sequence"] < expected_observation["sequence"]:
            raise ProcessIdentityMismatch(
                "current telemetry predates the source observation; no process was signaled"
            )
        if (
            current_observation["sequence"] == expected_observation["sequence"]
            and current_observation["payload_sha256"]
            != expected_observation["payload_sha256"]
        ):
            raise ProcessIdentityMismatch(
                "telemetry changed within the source sequence; no process was signaled"
            )
        supplied = parameters.get("session")
        assert isinstance(supplied, dict)  # enforced by validate_action_parameters
        expected_identity = validate_process_identity(supplied["process_identity"])
        exact_fields = (
            "username",
            "source",
            "session_id",
            "process_id",
            "privileged",
            "interactive",
            "process_identity",
        )
        matches = [
            item
            for item in normalized.get("sessions", [])
            if all(item.get(field) == supplied.get(field) for field in exact_fields)
        ]
        if len(matches) != 1:
            raise ProcessIdentityMismatch(
                "current session context changed; no process was signaled and operator review is required"
            )
        process_id = int(supplied["process_id"])
        current_identity = self._process_identity(
            process_id, boot_id=expected_observation["boot_id"]
        )
        if current_identity != expected_identity:
            raise ProcessIdentityMismatch(
                "process identity changed; no process was signaled and operator review is required"
            )
        return (
            dict(matches[0]),
            expected_identity,
            expected_observation,
            current_observation,
        )

    def _set_quarantine_recovery_unhealthy(self, key: str, error: str) -> None:
        self.quarantine_recovery = {
            "healthy": False,
            "recovered": [],
            "unresolved": [f"{key}: {error}"[:500]],
        }

    def _persist_quarantine_failure(
        self,
        records: dict[str, Any],
        key: str,
        status: str,
        error: str,
    ) -> str:
        raw_record = records.get(key)
        record = dict(raw_record) if isinstance(raw_record, dict) else {}
        try:
            record.setdefault("process_id", int(key))
        except ValueError:
            pass
        record["status"] = status
        record["failure_at"] = time.time()
        record["last_error"] = str(error)[:500]
        records[key] = record
        detail = str(error)[:500]
        try:
            self._write_quarantine(records)
        except (OSError, RuntimeError, TypeError, ValueError) as state_exc:
            detail = f"{detail}; quarantine failure state write failed: {state_exc}"[:500]
        self._set_quarantine_recovery_unhealthy(key, detail)
        return detail

    def _release(
        self, parameters: dict[str, Any], started: float, current_telemetry: dict[str, Any]
    ) -> dict[str, Any]:
        session = parameters.get("session", parameters)
        process_id = session.get("process_id") if isinstance(session, dict) else None
        try:
            current_session, action_identity, _source_observation, _current_observation = (
                self._validate_current_session_authority(
                    "release_quarantine", parameters, current_telemetry
                )
            )
        except (OSError, PermissionError, RuntimeError, TypeError, ValueError) as exc:
            return self._result(
                "release_quarantine",
                False,
                f"release refused without signaling a process: {exc}",
                started,
                review_required=True,
            )
        records = self._read_quarantine()
        if not isinstance(process_id, int) or str(process_id) not in records:
            return self._result("release_quarantine", False, "quarantine record not found", started)
        key = str(process_id)
        record = records[key]
        if not isinstance(record, dict):
            detail = self._persist_quarantine_failure(
                records, key, "release_failed", "quarantine record is not an object"
            )
            return self._result("release_quarantine", False, f"release failed: {detail}", started)
        record_boot = str(record.get("boot_id", "unknown"))
        current_boot = str(current_telemetry.get("boot_id", "unknown"))
        if record_boot not in {"", "unknown"} and current_boot not in {"", "unknown"} and record_boot != current_boot:
            records.pop(key, None)
            self._write_quarantine(records)
            return self._result(
                "release_quarantine",
                True,
                "stale quarantine record cleared after host reboot; no process was changed",
                started,
            )
        try:
            expected_identity = validate_process_identity(record.get("process_identity"))
        except ValueError as exc:
            detail = self._persist_quarantine_failure(
                records,
                key,
                "release_failed",
                f"process identity is missing or invalid; refusing to signal a PID: {exc}",
            )
            return self._result(
                "release_quarantine",
                False,
                f"release failed: {detail}",
                started,
                review_required=True,
            )
        record_fields = (
            "username",
            "source",
            "session_id",
            "process_id",
            "privileged",
            "interactive",
            "process_identity",
        )
        if (
            action_identity != expected_identity
            or any(record.get(field) != current_session.get(field) for field in record_fields)
        ):
            detail = self._persist_quarantine_failure(
                records,
                key,
                "release_failed",
                "quarantine session binding changed; no process was signaled and operator review is required",
            )
            return self._result(
                "release_quarantine",
                False,
                f"release failed: {detail}",
                started,
                review_required=True,
            )
        try:
            self._resume_process(process_id, expected_identity)
        except (OSError, PermissionError, RuntimeError, ValueError) as exc:
            detail = self._persist_quarantine_failure(records, key, "release_failed", str(exc))
            return self._result(
                "release_quarantine",
                False,
                f"release failed: {detail}",
                started,
                review_required=isinstance(exc, ProcessIdentityMismatch),
            )
        records.pop(key, None)
        try:
            self._write_quarantine(records)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            self._set_quarantine_recovery_unhealthy(
                key, f"process resumed but quarantine state cleanup failed: {exc}"
            )
            return self._result(
                "release_quarantine",
                False,
                f"process resumed but quarantine state cleanup failed: {exc}",
                started,
            )
        return self._result("release_quarantine", True, "session process resumed", started)

    def release_expired_quarantines(self, current_boot_id: str = "unknown") -> list[int]:
        records = self._read_quarantine()
        now = time.time()
        released: list[int] = []
        unresolved: list[str] = []
        changed = False
        for key, record in list(records.items()):
            if not isinstance(record, dict):
                unresolved.append(f"{key}: quarantine record is not an object"[:500])
                continue
            try:
                expires_at = float(record["expires_at"])
                if not math.isfinite(expires_at):
                    raise ValueError("expiry is not finite")
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                record["status"] = "release_failed"
                record["failure_at"] = time.time()
                record["last_error"] = f"invalid quarantine expiry: {exc}"[:500]
                unresolved.append(f"{key}: {record['last_error']}"[:500])
                changed = True
                continue
            if expires_at > now:
                continue
            record_boot = str(record.get("boot_id", "unknown"))
            if (
                record_boot not in {"", "unknown"}
                and current_boot_id not in {"", "unknown"}
                and record_boot != current_boot_id
            ):
                records.pop(key, None)
                changed = True
                continue
            status = str(record.get("status", "active"))
            if status != "active":
                unresolved.append(
                    f"{key}: quarantine status {status!r} requires recovery"[:500]
                )
                continue
            try:
                process_id = int(key)
                recorded_process_id = record.get("process_id")
                if type(recorded_process_id) is not int or recorded_process_id != process_id:
                    raise ValueError("process ID does not match its quarantine key")
                expected_identity = validate_process_identity(
                    record.get("process_identity")
                )
                current_identity = self._process_identity(
                    process_id, boot_id=record_boot
                )
                if current_identity != expected_identity:
                    raise ProcessIdentityMismatch(
                        "process identity changed; refusing to signal a PID and requiring operator review"
                    )
                self._resume_process(process_id, expected_identity)
                released.append(process_id)
                records.pop(key, None)
                changed = True
            except (OSError, PermissionError, RuntimeError, ValueError) as exc:
                record["status"] = "release_failed"
                record["failure_at"] = time.time()
                record["last_error"] = str(exc)[:500]
                records[key] = record
                unresolved.append(f"{key}: {exc}"[:500])
                changed = True
        if changed:
            try:
                self._write_quarantine(records)
            except (OSError, RuntimeError, TypeError, ValueError) as exc:
                self._set_quarantine_recovery_unhealthy(
                    "*", f"expired quarantine state write failed: {exc}"
                )
                raise
        if unresolved:
            self.quarantine_recovery = {
                "healthy": False,
                "recovered": released,
                "unresolved": unresolved,
            }
        return released

    def _process_identity(
        self, process_id: int, *, boot_id: str | None = None
    ) -> dict[str, Any]:
        return inspect_process_identity(process_id, boot_id=boot_id)

    def _recover_incomplete_quarantines(
        self,
        current_boot_id: str = "unknown",
        *,
        retry_unresolved: bool = True,
    ) -> dict[str, Any]:
        try:
            records = self._read_quarantine()
        except (OSError, RuntimeError, ValueError) as exc:
            return {"healthy": False, "recovered": [], "unresolved": [str(exc)[:500]]}
        recovered: list[int] = []
        unresolved: list[str] = []
        changed = False
        for key, record in list(records.items()):
            if not isinstance(record, dict):
                unresolved.append(f"{key}: quarantine record is not an object"[:500])
                continue
            status = str(record.get("status", "active"))
            if status == "active":
                continue
            if status not in {"preparing", "rollback_failed", "release_failed"}:
                unresolved.append(f"{key}: unsupported quarantine status {status!r}"[:500])
                continue
            record_boot = str(record.get("boot_id", "unknown"))
            if (
                record_boot not in {"", "unknown"}
                and current_boot_id not in {"", "unknown"}
                and record_boot != current_boot_id
            ):
                records.pop(key, None)
                changed = True
                continue
            if not retry_unresolved:
                unresolved.append(
                    f"{key}: {record.get('last_error', 'quarantine recovery remains unresolved')}"[:500]
                )
                continue
            try:
                process_id = int(key)
                recorded_process_id = record.get("process_id")
                if type(recorded_process_id) is not int or recorded_process_id != process_id:
                    raise ValueError("process ID does not match its quarantine key")
                expected = validate_process_identity(record.get("process_identity"))
                if self._process_identity(
                    process_id, boot_id=record_boot
                ) != expected:
                    raise ProcessIdentityMismatch(
                        "process identity changed; refusing recovery signaling and requiring operator review"
                    )
                self._resume_process(process_id, expected)
                recovered.append(process_id)
                records.pop(key, None)
                changed = True
            except (OSError, PermissionError, RuntimeError, ValueError) as exc:
                unresolved.append(f"{key}: {exc}"[:500])
        if changed:
            try:
                self._write_quarantine(records)
            except (OSError, RuntimeError, ValueError) as exc:
                unresolved.append(f"quarantine recovery state write failed: {exc}"[:500])
        return {"healthy": not unresolved, "recovered": recovered, "unresolved": unresolved}

    def _suspend_process(
        self, process_id: int, expected_identity: dict[str, Any]
    ) -> None:
        signal_verified_process(process_id, expected_identity, "suspend")

    def _resume_process(
        self, process_id: int, expected_identity: dict[str, Any]
    ) -> None:
        signal_verified_process(process_id, expected_identity, "resume")

    def _service_state(self, service: str) -> str:
        if not SERVICE_NAME.fullmatch(service):
            raise ValueError("invalid service name")
        if platform.system().casefold() == "windows":
            result = subprocess.run(
                ["sc.exe", "query", service], text=True, capture_output=True, timeout=12, check=False
            )
            output = result.stdout.casefold()
            if "running" in output:
                return "running"
            if "stopped" in output:
                return "stopped"
            return "unknown"
        result = subprocess.run(
            ["systemctl", "is-active", service], text=True, capture_output=True, timeout=12, check=False
        )
        return "running" if result.stdout.strip() == "active" else "stopped"

    def _set_service_state(self, service: str, desired: str) -> None:
        if not SERVICE_NAME.fullmatch(service):
            raise ValueError("invalid service name")
        if platform.system().casefold() == "windows":
            if desired == "running":
                command = ["sc.exe", "start", service]
            else:
                command = ["sc.exe", "stop", service]
        else:
            command = ["systemctl", "start" if desired == "running" else "stop", service]
        result = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
        if result.returncode != 0:
            raise OSError(result.stderr.strip() or result.stdout.strip() or "service command failed")

    def _restart_service(self, parameters: dict[str, Any], started: float) -> dict[str, Any]:
        service = str(parameters.get("service", ""))
        if not SERVICE_NAME.fullmatch(service):
            return self._result("restart_service", False, "invalid or missing service name", started)
        if not self.allow_containment:
            return self._result(
                "restart_service", True, f"dry run: would start {service}", started, dry_run=True
            )
        try:
            before = self._service_state(service)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            return self._result(
                "restart_service", False, f"service state inspection failed: {exc}", started
            )
        transaction = {
            "transaction_id": str(uuid.uuid4()),
            "operation": "restart_service",
            "service": service,
            "before": before,
            "desired": "running",
            "created_at": started,
            "probes": parameters.get("probes", []),
            "status": "prepared",
        }
        transaction_path = self.state_dir / f"service-transaction-{transaction['transaction_id']}.json"
        try:
            write_private_json(transaction_path, transaction)
        except (OSError, TypeError, ValueError) as exc:
            return self._result(
                "restart_service", False, f"service transaction record failed: {exc}", started
            )
        try:
            self._set_service_state(service, "running")
            probes = run_probes(
                list(parameters.get("probes", [])),
                self.authorized_networks,
                authorized_hosts=self.authorized_hosts,
                excluded_hosts=self.excluded_hosts,
            )
            state_ok = self._service_state(service) == "running"
            probes_ok = not probes or all(item.healthy for item in probes)
            if not state_ok or not probes_ok:
                self._set_service_state(service, before if before in {"running", "stopped"} else "stopped")
                transaction["status"] = "rolled_back"
                transaction["completed_at"] = time.time()
                write_private_json(transaction_path, transaction)
                self._prune_service_transactions()
                return self._result(
                    "restart_service",
                    False,
                    "service recovery failed validation and was rolled back",
                    started,
                    rolled_back=True,
                    probes=[asdict(item) for item in probes],
                )
            transaction["status"] = "committed"
            transaction["completed_at"] = time.time()
            write_private_json(transaction_path, transaction)
            self._prune_service_transactions()
            return self._result(
                "restart_service",
                True,
                f"{service} is running and passed validation",
                started,
                pre_state={"service": service, "desired_state": before},
                probes=[asdict(item) for item in probes],
            )
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            try:
                if before in {"running", "stopped"}:
                    self._set_service_state(service, before)
                rolled_back = True
            except Exception:
                rolled_back = False
            try:
                transaction["status"] = "rolled_back" if rolled_back else "rollback_failed"
                transaction["completed_at"] = time.time()
                write_private_json(transaction_path, transaction)
                self._prune_service_transactions()
            except (OSError, TypeError, ValueError):
                rolled_back = False
            return self._result(
                "restart_service",
                False,
                f"service recovery failed: {exc}",
                started,
                rolled_back=rolled_back,
            )

    def _rollback_service(self, parameters: dict[str, Any], started: float) -> dict[str, Any]:
        service = str(parameters.get("service", ""))
        desired = str(parameters.get("desired_state", ""))
        if not SERVICE_NAME.fullmatch(service) or desired not in {"running", "stopped"}:
            return self._result("rollback_service", False, "invalid service rollback state", started)
        if not self.allow_containment:
            return self._result(
                "rollback_service",
                True,
                f"dry run: would restore {service} to {desired}",
                started,
                dry_run=True,
            )
        try:
            before = self._service_state(service)
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            return self._result(
                "rollback_service", False, f"service state inspection failed: {exc}", started
            )
        transaction = {
            "transaction_id": str(uuid.uuid4()),
            "operation": "rollback_service",
            "service": service,
            "before": before,
            "desired": desired,
            "created_at": started,
            "status": "prepared",
        }
        transaction_path = self.state_dir / f"service-transaction-{transaction['transaction_id']}.json"
        try:
            write_private_json(transaction_path, transaction)
        except (OSError, TypeError, ValueError) as exc:
            return self._result(
                "rollback_service", False, f"service transaction record failed: {exc}", started
            )
        try:
            self._set_service_state(service, desired)
            verified = self._service_state(service) == desired
            if not verified:
                self._set_service_state(service, before)
                transaction["status"] = "rolled_back"
                transaction["completed_at"] = time.time()
                write_private_json(transaction_path, transaction)
                self._prune_service_transactions()
                return self._result(
                    "rollback_service",
                    False,
                    "rollback validation failed; the immediate prior state was restored",
                    started,
                    rolled_back=True,
                )
            transaction["status"] = "committed"
            transaction["completed_at"] = time.time()
            write_private_json(transaction_path, transaction)
            self._prune_service_transactions()
            return self._result(
                "rollback_service",
                True,
                f"{service} restored to {desired}",
                started,
                pre_state={"service": service, "desired_state": before},
            )
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            try:
                self._set_service_state(service, before)
                restored = True
            except Exception:
                restored = False
            try:
                transaction["status"] = "rolled_back" if restored else "rollback_failed"
                transaction["completed_at"] = time.time()
                write_private_json(transaction_path, transaction)
                self._prune_service_transactions()
            except (OSError, TypeError, ValueError):
                restored = False
            return self._result(
                "rollback_service",
                False,
                f"rollback failed: {exc}",
                started,
                rolled_back=restored,
            )

    def _read_quarantine(self) -> dict[str, Any]:
        if not self.quarantine_file.exists() and not self.quarantine_file.is_symlink():
            return {}
        data = read_private_json(self.quarantine_file, 1024 * 1024)
        if not isinstance(data, dict) or len(data) > 1024:
            raise ValueError("quarantine state is invalid or exceeds its entry limit")
        return data

    def _write_quarantine(self, records: dict[str, Any]) -> None:
        write_private_json(self.quarantine_file, records)

    def _recover_incomplete_service_transactions(self) -> dict[str, Any]:
        recovered: list[str] = []
        unresolved: list[dict[str, str]] = []
        self._prune_service_transactions()
        records = sorted(self.state_dir.glob("service-transaction-*.json"))
        if len(records) > 1024:
            unresolved.append(
                {"transaction": "*", "reason": "more than 1,024 service transactions require cleanup"}
            )
        for path in records[:1024]:
            try:
                transaction = read_private_json(path, 128 * 1024)
                if not isinstance(transaction, dict):
                    raise ValueError("service transaction is not an object")
                identifier = str(transaction.get("transaction_id", ""))
                if path.name != f"service-transaction-{identifier}.json":
                    raise ValueError("service transaction identifier does not match its filename")
                status = str(transaction.get("status", ""))
                if status in {"committed", "rolled_back", "recovered"}:
                    continue
                if status not in {"prepared", "rollback_failed"}:
                    raise ValueError(f"unsupported service transaction status {status!r}")
                service = str(transaction.get("service", ""))
                before = str(transaction.get("before", ""))
                desired = str(transaction.get("desired", ""))
                if not SERVICE_NAME.fullmatch(service) or before not in {"running", "stopped"}:
                    raise ValueError("incomplete service transaction has invalid state")
                current = self._service_state(service)
                if current != before:
                    raise ValueError(
                        f"service is {current} after interrupted {transaction.get('operation')}; "
                        f"automatic rollback to {before} requires operator review"
                    )
                transaction["status"] = "recovered"
                transaction["completed_at"] = time.time()
                write_private_json(path, transaction)
                recovered.append(identifier)
            except (OSError, RuntimeError, ValueError, json.JSONDecodeError) as exc:
                unresolved.append({"transaction": path.name, "reason": str(exc)[:500]})
        return {"healthy": not unresolved, "recovered": recovered, "unresolved": unresolved}

    def _prune_snapshots(self) -> list[str]:
        warnings: list[str] = []
        records = sorted(self.state_dir.glob("snapshot-*.json"))
        safe = [path for path in records if path.is_file() and not path.is_symlink()]
        for path in safe[: max(0, len(safe) - MAX_SNAPSHOTS)]:
            try:
                remove_private_file(path)
            except (OSError, ValueError) as exc:
                warnings.append(f"{path.name}: {exc}"[:500])
        return warnings

    def _prune_service_transactions(self) -> list[str]:
        warnings: list[str] = []
        terminal: list[tuple[float, Path]] = []
        for path in self.state_dir.glob("service-transaction-*.json"):
            try:
                record = read_private_json(path, 128 * 1024)
                if not isinstance(record, dict):
                    continue
                if record.get("status") in {"committed", "rolled_back", "recovered"}:
                    terminal.append(
                        (float(record.get("completed_at", record.get("created_at", 0.0))), path)
                    )
            except (OSError, TypeError, ValueError, json.JSONDecodeError):
                continue
        terminal.sort(key=lambda item: (item[0], item[1].name))
        for _, path in terminal[: max(0, len(terminal) - MAX_SERVICE_TRANSACTIONS)]:
            try:
                remove_private_file(path)
            except (OSError, ValueError) as exc:
                warnings.append(f"{path.name}: {exc}"[:500])
        return warnings

    @staticmethod
    def _result(action: str, success: bool, message: str, started: float, **extra: Any) -> dict[str, Any]:
        return {
            "action_type": action,
            "success": success,
            "message": message,
            "started_at": started,
            "completed_at": time.time(),
            **extra,
        }
