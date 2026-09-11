"""Evidence-based service diagnosis and declarative, bounded repair contracts.

Diagnosis never treats probe error text as commands or trusts the first scan as
a repair source. Mutations require an approved baseline and explicit per-service
authority; the executor independently verifies the native state and saved bytes.
"""

from __future__ import annotations

import hashlib
import ipaddress
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlparse

from .json_codec import canonical_json_bytes
from .policy import SHA256

MAX_REPAIR_FILES = 16
MAX_REPAIR_VALIDATION_SECONDS = 120


def path_key(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 1024 or "\x00" in value:
        raise ValueError("repair requires bounded absolute paths")
    windows = PureWindowsPath(value)
    path = windows if windows.is_absolute() else PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("repair requires absolute paths without parent traversal")
    return path.as_posix().casefold() if windows.is_absolute() else path.as_posix()


def normalize_repair_policy(value: Any, manifest: dict[str, Any]) -> dict[str, Any]:
    fields = {"restore_files", "restart_unhealthy", "validation_timeout_seconds"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("repair_policy requires restore_files, restart_unhealthy and validation_timeout_seconds")
    files = value["restore_files"]
    if not isinstance(files, list) or len(files) > MAX_REPAIR_FILES:
        raise ValueError("repair_policy permits at most 16 configuration files")
    keys = [path_key(path) for path in files]
    required = {path_key(path) for path in manifest.get("required_files", [])}
    if len(set(keys)) != len(keys) or not set(keys) <= required:
        raise ValueError("repair files must be unique declared required_files")
    if type(value["restart_unhealthy"]) is not bool:
        raise ValueError("restart_unhealthy must be an explicit boolean")
    timeout = value["validation_timeout_seconds"]
    if type(timeout) is not int or not 5 <= timeout <= MAX_REPAIR_VALIDATION_SECONDS:
        raise ValueError("repair validation timeout must be an integer from 5 to 120 seconds")
    return {"restore_files": list(files), "restart_unhealthy": value["restart_unhealthy"],
            "validation_timeout_seconds": timeout}


def _one(rows: list[dict[str, Any]], field: str, value: str) -> dict[str, Any]:
    matches = [row for row in rows if row.get(field) == value]
    if len(matches) != 1:
        raise ValueError(f"missing or ambiguous {field}: {value}")
    return matches[0]


def _manifest(profile: Any, host: str, service: str) -> dict[str, Any]:
    return _one([row for row in profile.services if row["host"] == host], "service_id", service)


def local_probe(probe: dict[str, Any]) -> bool:
    """Only a numeric loopback target proves this probe checks this host."""
    target = str(probe.get("target", ""))
    try:
        host = urlparse(target).hostname if "://" in target else target
        return ipaddress.ip_address(host or "").is_loopback
    except ValueError:
        return False


def probe_health(specs: list[dict[str, Any]], telemetry: dict[str, Any]) -> list[bool | None]:
    health = []
    for spec in specs:
        rows = [row for row in telemetry.get("probes", [])
                if row.get("name") == spec.get("name", spec.get("target"))
                and row.get("target") == spec.get("target")]
        health.append(rows[0].get("healthy") if len(rows) == 1
                      and type(rows[0].get("healthy")) is bool else None)
    return health


def diagnose_service(profile: Any, agent_id: str, service: str,
                     baseline: dict[str, Any] | None, telemetry: dict[str, Any]) -> dict[str, Any]:
    """Structured observations, not a claim to have proven an attack's cause."""
    from .service_recovery import _fresh
    import time
    findings: list[dict[str, Any]] = []
    try:
        _fresh(telemetry, time.time())
        manifest = _manifest(profile, agent_id, service)
        current = _one(telemetry.get("services", []), "name", service)
        if not baseline:
            raise ValueError("approved baseline is unavailable")
        prior = _one(baseline.get("services", []), "name", service)
        if prior.get("state") != "running":
            findings.append({"code": "no_running_baseline", "subject": service})
        if str(current.get("start_mode", "")).casefold() in {"disabled", "masked", "masked-runtime"}:
            findings.append({"code": "startup_configuration_changed", "subject": service})
        if current.get("state") in {"stopped", "inactive", "failed"}:
            findings.append({"code": "service_stopped", "subject": service})
        elif current.get("state") != "running":
            findings.append({"code": "native_state_unknown", "subject": service})
        visited: set[str] = set()
        active: set[str] = set()

        def dependencies(item: dict[str, Any]) -> None:
            name = item["service_id"]
            if name in active:
                raise ValueError("service dependency cycle")
            if name in visited:
                return
            if len(visited) + len(active) >= 128:
                raise ValueError("service dependency diagnosis budget exceeded")
            active.add(name)
            for dependency in item["dependencies"]:
                child = _manifest(profile, agent_id, dependency)
                dependencies(child)
                row = _one(telemetry.get("services", []), "name", dependency)
                if row.get("state") != "running":
                    findings.append({"code": "dependency_unavailable", "subject": dependency})
                elif not all(value is True for value in probe_health(child["expected_transactions"], telemetry)):
                    findings.append({"code": "dependency_unhealthy", "subject": dependency})
            active.remove(name)
            visited.add(name)

        dependencies(manifest)
        for name in manifest["required_accounts"]:
            row = _one(telemetry.get("accounts", []), "name", name)
            if row.get("enabled") is not True:
                findings.append({"code": "required_account_unavailable", "subject": name})
        for path in manifest["required_files"]:
            before = _one(baseline.get("integrity", []), "path", path)
            matches = [row for row in telemetry.get("integrity", []) if row.get("path") == path]
            if not matches:
                findings.append({"code": "configuration_missing", "subject": path})
            elif len(matches) != 1 or matches[0].get("readable") is False:
                findings.append({"code": "configuration_unverified", "subject": path})
            elif any(matches[0].get(field, "") != before.get(field, "")
                     for field in ("sha256", "security_descriptor_sha256")):
                findings.append({"code": "configuration_changed", "subject": path})
        health = probe_health(manifest["expected_transactions"], telemetry)
        local = [value for spec, value in zip(manifest["expected_transactions"], health) if local_probe(spec)]
        if current.get("state") == "running":
            if any(value is False for value in local):
                findings.append({"code": "local_application_unhealthy", "subject": service})
            elif any(value is False for value in health):
                findings.append({"code": "external_path_or_access_failure" if local and all(local)
                                 else "application_failure_location_unknown", "subject": service})
        if any(value is None for value in health):
            findings.append({"code": "transaction_evidence_missing", "subject": service})
        return {"code": "healthy" if not findings else findings[0]["code"], "findings": findings,
                "repair_order": list(dict.fromkeys(item["subject"] for item in findings
                                                   if item["code"].startswith("dependency_"))) + [service]}
    except (KeyError, TypeError, ValueError, RecursionError) as exc:
        return {"code": "insufficient_evidence", "findings": findings,
                "reason": str(exc)[:500], "repair_order": []}


def _approved_files(contract: dict[str, Any], baseline: dict[str, Any],
                    telemetry: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    files, changed = [], []
    windows = str(telemetry.get("platform", "")).casefold().startswith("windows")
    for path in contract["files"]:
        before = _one(baseline.get("integrity", []), "path", path)
        digest, security = before.get("sha256", ""), before.get("security_descriptor_sha256", "")
        if not SHA256.fullmatch(digest) or windows and not SHA256.fullmatch(security):
            raise ValueError(f"required file lacks approved content/security metadata: {path}")
        files.append({"path": path, "sha256": digest, "security_descriptor_sha256": security})
        rows = [row for row in telemetry.get("integrity", []) if row.get("path") == path]
        if len(rows) > 1 or rows and (rows[0].get("readable") is False or not SHA256.fullmatch(rows[0].get("sha256", ""))):
            raise ValueError(f"required file is unreadable or ambiguous: {path}")
        current = rows[0] if rows else None
        if current is not None and current.get("sha256") == digest and current.get("security_descriptor_sha256", "") == security:
            continue
        observed_security = current.get("security_descriptor_sha256", "") if current else ""
        if windows and current and not SHA256.fullmatch(observed_security):
            raise ValueError(f"changed file lacks Windows security metadata: {path}")
        changed.append({"path": path, "baseline_sha256": digest,
                        "baseline_security_descriptor_sha256": security,
                        "observed_sha256": current.get("sha256") if current else None,
                        "observed_security_descriptor_sha256": observed_security,
                        "observed_missing": current is None})
    return files, changed


def _check_file_authority(profile: Any, agent_id: str, manifest: dict[str, Any],
                          changed: list[dict[str, Any]]) -> None:
    allowed = {path_key(path) for path in manifest["repair_policy"]["restore_files"]}
    for item in changed:
        key = path_key(item["path"])
        if key not in allowed:
            raise ValueError(f"file repair is not authorized: {item['path']}")
        for other in profile.services:
            if other["host"] != agent_id:
                continue
            if other["service_id"] != manifest["service_id"] and key in {
                path_key(path) for path in other["required_files"]
            }:
                raise ValueError("shared configuration requires a coordinated multi-service contract")
            for data in other["required_data"]:
                root = path_key(data).rstrip("/")
                if key == root or key.startswith(root + "/"):
                    raise ValueError("service repair cannot overwrite declared business data")


def repair_parameters(profile: Any, agent_id: str, service: str, baseline: dict[str, Any],
                      telemetry: dict[str, Any]) -> dict[str, Any]:
    from .service_recovery import _fresh, check_recovery_observation, recovery_contract
    import time
    _fresh(telemetry, time.time())
    manifest = _manifest(profile, agent_id, service)
    policy = manifest.get("repair_policy")
    if not policy:
        raise ValueError("coordinated repair requires an explicit repair_policy")
    contract = recovery_contract(profile, agent_id, service, action="repair_service")
    prior = _one(baseline.get("services", []), "name", service)
    current = _one(telemetry.get("services", []), "name", service)
    if prior.get("state") != "running":
        raise ValueError("repair requires an approved running-service baseline")
    state = current.get("state")
    stopped = {"stopped"}
    if str(telemetry.get("platform", "")).casefold().startswith("linux"):
        stopped.update({"inactive", "failed"})
    if state not in stopped | {"running"}:
        raise ValueError("unknown native state holds repair")
    if str(current.get("start_mode", "")).casefold() in {"disabled", "masked", "masked-runtime"}:
        raise ValueError("disabled or masked service needs a startup-configuration contract")
    if current.get("restart_count", 0) - prior.get("restart_count", 0) >= 3:
        raise ValueError("native restart loop holds repair")
    files, changed = _approved_files(contract, baseline, telemetry)
    _check_file_authority(profile, agent_id, manifest, changed)
    if state == "running":
        health = probe_health(contract["probes"], telemetry)
        if not policy["restart_unhealthy"] or not any(
            value is False and local_probe(spec) for spec, value in zip(contract["probes"], health)
        ):
            raise ValueError("running service needs authorized restart and a failed local application transaction")
    guard = {"files": files, "dependencies": contract["dependencies"],
             "dependency_probes": contract["dependency_probes"], "required_accounts": contract["required_accounts"],
             "boot_id": telemetry["boot_id"], "sequence": telemetry["sequence"], "observed_at": telemetry["observed_at"]}
    parameters = {"service": service, "probes": contract["probes"], "recovery_guard": guard,
                  "repair": {"restore_files": changed, "observed_state": "running" if state == "running" else "stopped",
                             "restart_unhealthy": policy["restart_unhealthy"],
                             "validation_timeout_seconds": policy["validation_timeout_seconds"]}}
    check_recovery_observation(parameters, telemetry)
    return parameters


def validate_repair_shape(parameters: dict[str, Any]) -> None:
    from .policy import validate_action_parameters
    if set(parameters) != {"service", "probes", "recovery_guard", "repair"}:
        raise ValueError("service repair requires its exact guarded contract")
    value = parameters["repair"]
    fields = {"restore_files", "observed_state", "restart_unhealthy", "validation_timeout_seconds"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("service repair plan fields are invalid")
    if value["observed_state"] not in {"running", "stopped"} or type(value["restart_unhealthy"]) is not bool:
        raise ValueError("service repair state or restart authority is invalid")
    timeout = value["validation_timeout_seconds"]
    if type(timeout) is not int or not 5 <= timeout <= MAX_REPAIR_VALIDATION_SECONDS:
        raise ValueError("service repair validation timeout is invalid")
    files = value["restore_files"]
    if not isinstance(files, list) or len(files) > MAX_REPAIR_FILES:
        raise ValueError("service repair file budget exceeded")
    keys = []
    for item in files:
        if not isinstance(item, dict) or set(item) != {
            "path", "baseline_sha256", "baseline_security_descriptor_sha256", "observed_sha256",
            "observed_security_descriptor_sha256", "observed_missing"
        }:
            raise ValueError("service repair file observation is incomplete")
        validate_action_parameters("restore_integrity", item)
        if item["observed_missing"] != (item["observed_sha256"] is None):
            raise ValueError("service repair missing-file evidence is inconsistent")
        keys.append(path_key(item["path"]))
    if len(set(keys)) != len(keys):
        raise ValueError("service repair contains duplicate file targets")


def validate_repair_contract(profile: Any, agent_id: str, parameters: dict[str, Any],
                            telemetry: dict[str, Any]) -> None:
    """Agent recomputes the plan from the signed baseline pins and its observation."""
    from .policy import validate_action_parameters
    validate_action_parameters("repair_service", parameters)
    guard = parameters["recovery_guard"]
    current = _one(telemetry.get("services", []), "name", parameters["service"])
    baseline = {"services": [{"name": parameters["service"], "state": "running",
                              "restart_count": current.get("restart_count", 0)}],
                "integrity": guard["files"]}
    expected = repair_parameters(profile, agent_id, parameters["service"], baseline, telemetry)
    # A newer observation can authorize the same fault, but cannot change the
    # plan, boot, file state, dependencies or policy while an action is queued.
    for field in ("sequence", "observed_at"):
        expected["recovery_guard"][field] = guard[field]
    if expected != parameters:
        raise ValueError("service repair differs from the exact manifest and observation")
    from .service_recovery import check_recovery_observation
    check_recovery_observation(parameters, telemetry)


def plan_digest(parameters: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(parameters)).hexdigest()
