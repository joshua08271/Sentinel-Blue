"""Journaled config restoration + native service recovery as one operation."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import subprocess
import time
import uuid
from dataclasses import asdict
from typing import Any

from .policy import validate_action_parameters
from .probes import run_probes
from .restoration import MAX_FILE_BYTES, validate_restored_configuration
from .service_recovery import check_recovery_observation
from .service_repair import local_probe, plan_digest
from .state import read_private_json, write_private_json


class ServiceRepairExecutor:
    def __init__(self, executor: Any):
        self.executor = executor
        self.store = executor.restore_points

    def _path(self, identifier: str) -> Path:
        # IDs are generated UUIDs. Do not accept a path, glob or alternate spelling.
        if not isinstance(identifier, str) or str(uuid.UUID(identifier)) != identifier:
            raise ValueError("invalid service repair transaction identifier")
        return self.executor.state_dir / f"service-repair-{identifier}.json"

    def bind_profile(self, fingerprint: str) -> None:
        if self.executor.repair_profile_fingerprint not in {"", fingerprint}:
            raise ValueError("local service repair executor belongs to a different profile")
        self.executor.repair_profile_fingerprint = fingerprint

    def _write(self, transaction: dict[str, Any]) -> None:
        write_private_json(self._path(transaction["transaction_id"]), transaction)

    def _transition(self, service: str, desired: str) -> None:
        self.executor._set_service_state(service, desired)
        deadline = time.monotonic() + 15
        while self.executor._service_state(service) != desired:
            if time.monotonic() >= deadline:
                raise ValueError(f"native service did not reach {desired}")
            time.sleep(0.2)

    def _probe(self, specs: list[dict[str, Any]]) -> list[Any]:
        return run_probes(specs, self.executor.authorized_networks,
                          authorized_hosts=self.executor.authorized_hosts,
                          excluded_hosts=self.executor.excluded_hosts)

    def _verify_files(self, parameters: dict[str, Any]) -> None:
        for item in parameters["recovery_guard"]["files"]:
            data, metadata = self.store._read_target(Path(item["path"]))
            if (hashlib.sha256(data).hexdigest() != item["sha256"] or
                self.store._metadata_security_descriptor_sha256(metadata) != item["security_descriptor_sha256"]):
                raise ValueError(f"configuration is not the approved state: {item['path']}")

    def _verify_sources(self, parameters: dict[str, Any]) -> None:
        manifest = self.store._read_manifest()
        total = 0
        for item in parameters["repair"]["restore_files"]:
            path, expected = self.store._validate_item(item)
            record = manifest.get(str(path))
            if not isinstance(record, dict) or record.get("sha256") != expected:
                raise ValueError("no exact approved restore point for repair")
            if self.store._metadata_security_descriptor_sha256(record) != item["baseline_security_descriptor_sha256"]:
                raise ValueError("repair source security metadata differs from baseline")
            data = self.store._read_private_file(self.store.blobs / expected, MAX_FILE_BYTES)
            total += len(data)
            if total > 64 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != expected:
                raise ValueError("repair source integrity or total byte budget failed")
            current = self.store._read_target_if_present(path)
            if item["observed_missing"]:
                if current is not None:
                    raise ValueError("repair target reappeared after observation")
            elif current is None or hashlib.sha256(current[0]).hexdigest() != item["observed_sha256"]:
                raise ValueError("repair target changed after observation")
            elif self.store._metadata_security_descriptor_sha256(current[1]) != item["observed_security_descriptor_sha256"]:
                raise ValueError("repair target security changed after observation")

    def _validate_application(self, transaction: dict[str, Any]) -> tuple[list[Any], int]:
        parameters = transaction["parameters"]
        self._verify_files(parameters)
        for item in parameters["repair"]["restore_files"]:
            validation = validate_restored_configuration(Path(item["path"]))
            if validation["applicable"] and validation["available"] and validation["healthy"] is False:
                raise ValueError("restored configuration failed native validation")
        guard = parameters["recovery_guard"]
        for name in guard["dependencies"]:
            if self.executor._service_state(name) != "running":
                raise ValueError("dependency became unavailable during repair")
        if guard["dependency_probes"]:
            results = self._probe(guard["dependency_probes"])
            if len(results) != len(guard["dependency_probes"]) or not all(item.healthy for item in results):
                raise ValueError("dependency became unhealthy during repair")
        if self.executor._service_state(transaction["service"]) != "running":
            raise ValueError("repaired service is not running")
        probes, attempts, healthy = self.executor._wait_for_service_probes(
            parameters["probes"], grace_seconds=parameters["repair"]["validation_timeout_seconds"])
        if not healthy or not probes:
            raise ValueError("repaired service did not pass stable application validation")
        # A process or file can change during the validation window.
        self._verify_files(parameters)
        if self.executor._service_state(transaction["service"]) != "running":
            raise ValueError("service stopped during final validation")
        return probes, attempts

    def _undo(self, transaction: dict[str, Any]) -> None:
        """Undo only this journal's exact file effects; never overwrite a third state."""
        service = transaction["service"]
        current = self.executor._service_state(service)
        if current not in {"running", "stopped"}:
            raise ValueError("unknown service state holds repair rollback")
        children = []
        for child, planned in zip(transaction["children"], transaction["parameters"]["repair"]["restore_files"]):
            path = self.store.transactions / f"{child['transaction_id']}.json"
            raw = self.store._read_private_file_if_present(path, 128 * 1024)
            if raw is None:
                current_file = self.store._read_target_if_present(Path(child["path"]))
                if (planned["observed_missing"] and current_file is not None or
                    not planned["observed_missing"] and (current_file is None or
                    hashlib.sha256(current_file[0]).hexdigest() != planned["observed_sha256"] or
                    self.store._metadata_security_descriptor_sha256(current_file[1]) != planned["observed_security_descriptor_sha256"])):
                    raise ValueError("unmodified repair target differs from its original observation")
                continue  # Reserved before a write; this child never began.
            record = json.loads(raw)
            if (not isinstance(record, dict) or record.get("transaction_id") != child["transaction_id"]
                or record.get("path") != child["path"]):
                raise ValueError("child restoration journal does not match its parent")
            if record.get("status") in {"rolled_back", "recovered"}:
                current_file = self.store._read_target_if_present(Path(child["path"]))
                if (record["existed"] and (current_file is None or
                    hashlib.sha256(current_file[0]).hexdigest() != record["before_sha256"] or
                    not self.store._metadata_matches(record["before_metadata"], current_file[1])) or
                    not record["existed"] and current_file is not None):
                    raise ValueError("previously rolled-back file no longer matches its prior state")
                continue
            if record.get("status") != "committed":
                raise ValueError("child restoration requires recovery before parent rollback")
            # Check every child before stopping anything or undoing any sibling.
            data, metadata = self.store._read_target(Path(child["path"]))
            if (hashlib.sha256(data).hexdigest() != record["restored_sha256"]
                or not self.store._metadata_matches(record["restored_metadata"], metadata)):
                raise ValueError("repair rollback held because a target changed after repair")
            children.append(child)
        transaction["status"] = "undo_prepared"
        self._write(transaction)
        if current == "running" and (children or transaction["before"] == "stopped"):
            self._transition(service, "stopped")
        for child in reversed(children):
            result = self.store.rollback(child["transaction_id"], allowed=True, probes=[])
            if result.get("success") is not True or result.get("dry_run"):
                raise ValueError("child restoration rollback did not complete")
        if self.executor._service_state(service) != transaction["before"]:
            self._transition(service, transaction["before"])
        if self.executor._service_state(service) != transaction["before"]:
            raise ValueError("repair rollback did not restore the prior native state")
        transaction["status"] = "rolled_back"
        transaction["completed_at"] = time.time()
        self._write(transaction)

    def execute(self, action_type: str, parameters: dict[str, Any], telemetry: dict[str, Any], started: float) -> dict[str, Any]:
        ex = self.executor
        transaction = None
        try:
            validate_action_parameters(action_type, parameters)
            if not ex.allow_service_recovery or not ex.allow_restoration:
                return ex._result(action_type, True, "dry run: coordinated repair requires service and restoration permission",
                                  started, dry_run=True)
            if action_type == "rollback_service_repair":
                transaction = self._read(self._path(parameters["transaction_id"]))
                if (transaction["service"] != parameters["service"] or transaction["status"] != "committed"
                    or transaction.get("profile_fingerprint") != ex.repair_profile_fingerprint):
                    raise ValueError("service repair is not available for exact rollback")
                before = ex._service_state(transaction["service"])
                self._undo(transaction)
                return ex._result(action_type, True, "service repair restored its exact prior files and service state", started,
                                  pre_state={"service": transaction["service"], "desired_state": before})
            check_recovery_observation(parameters, telemetry)
            service = parameters["service"]
            before = ex._service_state(service)
            if before != parameters["repair"]["observed_state"]:
                raise ValueError("service state changed after repair diagnosis")
            changed = tuple(item["path"] for item in parameters["repair"]["restore_files"])
            ex._service_recovery_preflight(parameters, skip_paths=changed)
            self._verify_sources(parameters)
            if before == "running":
                if not parameters["repair"]["restart_unhealthy"]:
                    raise ValueError("restarting a running service is not authorized")
                specs = [spec for spec in parameters["probes"] if local_probe(spec)]
                results = self._probe(specs)
                if not specs or len(results) != len(specs) or all(item.healthy for item in results):
                    raise ValueError("local application recovered or cannot confirm the fault; no restart performed")
            transaction = {"transaction_id": str(uuid.uuid4()), "operation": "repair_service", "service": service,
                           "profile_fingerprint": ex.repair_profile_fingerprint,
                           "before": before, "desired": "running", "created_at": started, "status": "prepared",
                           "parameters": parameters, "plan_sha256": plan_digest(parameters),
                           "children": [{"path": item["path"], "transaction_id": str(uuid.uuid4())} for item in parameters["repair"]["restore_files"]]}
            self._write(transaction)
            if before == "running":
                self._transition(service, "stopped")
            for item, child in zip(parameters["repair"]["restore_files"], transaction["children"]):
                result = self.store.restore(item, allowed=True, probes=[], transaction_id=child["transaction_id"], defer_validation=True)
                if result.get("success") is not True or result.get("dry_run"):
                    raise ValueError("configuration restoration failed during coordinated repair")
            ex._service_recovery_preflight(parameters, ignore_transaction_id=transaction["transaction_id"])
            for item in parameters["repair"]["restore_files"]:
                validation = validate_restored_configuration(Path(item["path"]))
                if validation["applicable"] and validation["available"] and validation["healthy"] is False:
                    raise ValueError("restored configuration failed native validation before service start")
            self._transition(service, "running")
            probes, attempts = self._validate_application(transaction)
            transaction["status"] = "committed"
            transaction["completed_at"] = time.time()
            self._write(transaction)
            return ex._result(action_type, True, "approved configuration and service recovered; stable application checks passed",
                              started, stable_health=True, probe_attempts=attempts, probes=[asdict(item) for item in probes],
                              pre_state={"service": service, "desired_state": before, "transaction_id": transaction["transaction_id"]},
                              record={"plan_sha256": transaction["plan_sha256"], "files": parameters["recovery_guard"]["files"],
                                      "transaction_id": transaction["transaction_id"]})
        except (OSError, KeyError, TypeError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
            rolled_back = False
            errors = [str(exc)[:500]]
            if transaction is not None and action_type == "repair_service":
                try:
                    self._undo(transaction)
                    rolled_back = True
                except (OSError, KeyError, TypeError, ValueError, RuntimeError, subprocess.TimeoutExpired) as undo_error:
                    errors.append(str(undo_error)[:500])
                    transaction["status"] = "rollback_failed"
                    try:
                        self._write(transaction)
                    except (OSError, TypeError, ValueError):
                        pass
            return ex._result(action_type, False, f"coordinated service repair held or failed: {exc}"[:1000], started,
                              rolled_back=rolled_back, errors=errors)

    def _read(self, path: Path) -> dict[str, Any]:
        record = read_private_json(path, 1024 * 1024)
        if not isinstance(record, dict) or self._path(record["transaction_id"]) != path:
            raise ValueError("invalid service repair journal")
        validate_action_parameters("repair_service", record["parameters"])
        if record["parameters"]["service"] != record["service"] or record["plan_sha256"] != plan_digest(record["parameters"]):
            raise ValueError("service repair journal plan does not match its binding")
        if (record["before"] != record["parameters"]["repair"]["observed_state"] or record["desired"] != "running"
            or record.get("operation") != "repair_service"):
            raise ValueError("invalid service repair journal states")
        if type(record["created_at"]) not in {int, float} or not math.isfinite(record["created_at"]):
            raise ValueError("invalid service repair journal timestamp")
        children = record["children"]
        if not isinstance(children, list) or [item["path"] for item in children] != [item["path"] for item in record["parameters"]["repair"]["restore_files"]]:
            raise ValueError("service repair journal children differ from its plan")
        if any(not isinstance(item.get("transaction_id"), str) for item in children):
            raise ValueError("invalid child restoration identities")
        ids = [str(uuid.UUID(item["transaction_id"])) for item in children]
        if ids != [item["transaction_id"] for item in children] or len(set(ids)) != len(ids):
            raise ValueError("invalid child restoration identities")
        return record

    def reconcile(self) -> dict[str, Any]:
        """Validate completed effects; roll back exact unfinished work with permission."""
        recovered, unresolved = [], []
        records = list(self.executor.state_dir.glob("service-repair-*.json"))
        if len(records) > 256:
            return {"healthy": False, "recovered": [], "unresolved": [{"transaction": "*", "reason": "service repair history budget exceeded"}]}
        for path in records:
            try:
                record = self._read(path)
                if record["status"] in {"committed", "rolled_back", "recovered"}:
                    continue
                if record.get("profile_fingerprint") != self.executor.repair_profile_fingerprint:
                    raise ValueError("interrupted repair belongs to a different approved profile")
                if record["status"] not in {"prepared", "undo_prepared", "rollback_failed"}:
                    raise ValueError("invalid service repair journal status")
                if not self.executor.allow_service_recovery or not self.executor.allow_restoration:
                    raise ValueError("unfinished repair requires current local repair permissions")
                if record["status"] == "prepared" and self.executor._service_state(record["service"]) == "running":
                    try:
                        self._validate_application(record)
                    except (OSError, ValueError, subprocess.TimeoutExpired):
                        pass
                    else:
                        record["status"] = "committed"
                        record["completed_at"] = time.time()
                        self._write(record)
                        recovered.append(record["transaction_id"])
                        continue
                self._undo(record)
                recovered.append(record["transaction_id"])
            except (OSError, KeyError, TypeError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                unresolved.append({"transaction": path.name, "reason": str(exc)[:500]})
        return {"healthy": not unresolved, "recovered": recovered, "unresolved": unresolved}
