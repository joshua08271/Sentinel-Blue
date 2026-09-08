"""Bounded service recovery from approved manifests and fresh observations."""

from __future__ import annotations

import hashlib
import math
import threading
import time
from typing import Any

from .event_profile import EventProfile
from .json_codec import canonical_json_bytes
from .policy import SERVICE_NAME, SHA256


RECOVERY_CONFIRMATIONS = 2
RECOVERY_COOLDOWN_SECONDS = 300
RECOVERY_WINDOW_SECONDS = 3600
RECOVERY_MAX_ATTEMPTS = 3
RECOVERY_FRESHNESS_SECONDS = 90


def _one(rows: list[dict[str, Any]], key: str, value: str) -> dict[str, Any]:
    matches = [row for row in rows if row.get(key) == value]
    if len(matches) != 1:
        raise ValueError(f"missing or ambiguous {key}: {value}")
    return matches[0]


def recovery_contract(profile: EventProfile, agent_id: str, service: str) -> dict[str, Any]:
    if not profile.services_confirmed:
        raise ValueError("service manifests are not confirmed")
    manifests = [item for item in profile.services if item["host"] == agent_id]
    target = _one(manifests, "service_id", service)
    if not SERVICE_NAME.fullmatch(service):
        raise ValueError("invalid native service name")
    if "restart_service" not in target["allowed_automatic_actions"]:
        raise ValueError("manifest does not authorize automatic service recovery")
    visited: set[str] = set()
    active: set[str] = set()
    dependencies: list[dict[str, Any]] = []

    def visit(item: dict[str, Any]) -> None:
        name = item["service_id"]
        if name in active:
            raise ValueError("service dependency cycle")
        if name in visited:
            return
        if not SERVICE_NAME.fullmatch(name):
            raise ValueError("invalid dependency service name")
        active.add(name)
        for dependency in item["dependencies"]:
            visit(_one(manifests, "service_id", dependency))
        active.remove(name)
        visited.add(name)
        if name != service:
            dependencies.append(item)

    visit(target)
    dependency_probes = [probe for item in dependencies for probe in item["expected_transactions"]]
    if len(dependency_probes) > 256:
        raise ValueError("dependency probe budget exceeded")
    if not target["required_files"]:
        raise ValueError("automatic recovery requires approved configuration files")
    chain = [target, *dependencies]
    files = sorted({path for item in chain for path in item["required_files"]})
    accounts = sorted({name for item in chain for name in item["required_accounts"]})
    if len(files) > 256 or len(accounts) > 256:
        raise ValueError("dependency configuration budget exceeded")
    return {
        "probes": target["expected_transactions"],
        "files": files,
        "dependencies": [item["service_id"] for item in dependencies],
        "dependency_probes": dependency_probes,
        "required_accounts": accounts,
    }


def _fresh(telemetry: dict[str, Any], now: float) -> None:
    observed = telemetry.get("observed_at")
    if (
        type(observed) not in {int, float}
        or not math.isfinite(observed)
        or not 0 <= now - observed <= RECOVERY_FRESHNESS_SECONDS
        or telemetry.get("boot_id") in {None, "", "unknown"}
        or type(telemetry.get("sequence")) is not int
        or telemetry["sequence"] < 1
    ):
        raise ValueError("service recovery needs fresh sequenced telemetry")
    if telemetry.get("collector_errors"):
        raise ValueError("incomplete collection holds service recovery")


def recovery_parameters(
    profile: EventProfile, agent_id: str, service: str,
    baseline: dict[str, Any], telemetry: dict[str, Any], *, now: float | None = None,
) -> dict[str, Any]:
    _fresh(telemetry, time.time() if now is None else now)
    contract = recovery_contract(profile, agent_id, service)
    previous = _one(baseline.get("services", []), "name", service)
    current = _one(telemetry.get("services", []), "name", service)
    stopped_states = {"stopped"}
    if str(telemetry.get("platform", "")).casefold().startswith("linux"):
        stopped_states.update({"inactive", "failed"})
    if previous.get("state") != "running" or current.get("state") not in stopped_states:
        raise ValueError("recovery requires an explicitly stopped approved running service")
    if str(current.get("start_mode", "")).casefold() in {"disabled", "masked", "masked-runtime"}:
        raise ValueError("disabled or masked service needs configuration review")
    if current.get("restart_count", 0) - previous.get("restart_count", 0) >= 3:
        raise ValueError("native restart loop holds recovery")
    files = []
    for path in contract["files"]:
        prior = _one(baseline.get("integrity", []), "path", path)
        item = _one(telemetry.get("integrity", []), "path", path)
        digest = prior.get("sha256", "")
        security = prior.get("security_descriptor_sha256", "")
        if not SHA256.fullmatch(digest) or item.get("sha256") != digest or item.get("readable") is False:
            raise ValueError(f"required file is changed or unverified: {path}")
        if security != item.get("security_descriptor_sha256", ""):
            raise ValueError(f"required file security metadata changed: {path}")
        if str(telemetry.get("platform", "")).casefold().startswith("windows") and not SHA256.fullmatch(security):
            raise ValueError(f"required file lacks approved Windows security metadata: {path}")
        files.append({"path": path, "sha256": digest, "security_descriptor_sha256": security})
    guard = {
        "files": files,
        "dependencies": contract["dependencies"],
        "dependency_probes": contract["dependency_probes"],
        "required_accounts": contract["required_accounts"],
        "boot_id": telemetry["boot_id"],
        "sequence": telemetry["sequence"],
        "observed_at": telemetry["observed_at"],
    }
    parameters = {"service": service, "probes": contract["probes"], "recovery_guard": guard}
    check_recovery_observation(parameters, telemetry, now=now)
    return parameters


def check_recovery_observation(
    parameters: dict[str, Any], telemetry: dict[str, Any], *, now: float | None = None,
) -> None:
    instant = time.time() if now is None else now
    _fresh(telemetry, instant)
    guard = parameters["recovery_guard"]
    if (
        telemetry["boot_id"] != guard["boot_id"]
        or telemetry["sequence"] < guard["sequence"]
        or not 0 <= instant - guard["observed_at"] <= RECOVERY_FRESHNESS_SECONDS
    ):
        raise ValueError("service recovery observation is stale or belongs to another boot")
    for name in guard["dependencies"]:
        if _one(telemetry.get("services", []), "name", name).get("state") != "running":
            raise ValueError(f"dependency is not running: {name}")
    for probe in guard["dependency_probes"]:
        matches = [row for row in telemetry.get("probes", []) if
                   row.get("name") == probe.get("name", probe.get("target"))
                   and row.get("target") == probe.get("target")]
        if len(matches) != 1 or matches[0].get("healthy") is not True:
            raise ValueError("dependency application health is unavailable")
    for name in guard["required_accounts"]:
        if _one(telemetry.get("accounts", []), "name", name).get("enabled") is not True:
            raise ValueError(f"required account is unavailable: {name}")


def validate_automatic_recovery(
    profile: EventProfile, agent_id: str, parameters: dict[str, Any], telemetry: dict[str, Any]
) -> None:
    """Agent-side policy cannot be weakened by omitting a controller guard."""
    contract = recovery_contract(profile, agent_id, parameters["service"])
    guard = parameters.get("recovery_guard")
    if not isinstance(guard, dict) or parameters.get("probes") != contract["probes"]:
        raise ValueError("automatic service recovery lacks its exact manifest contract")
    for field in ("dependencies", "dependency_probes", "required_accounts"):
        if guard.get(field) != contract[field]:
            raise ValueError(f"automatic service recovery {field} differs from manifest")
    if [item["path"] for item in guard["files"]] != contract["files"]:
        raise ValueError("automatic service recovery files differ from manifest")
    check_recovery_observation(parameters, telemetry)


class ServiceRecoveryPlanner:
    """A restart clears confirmations; durable action budgets remain in Store."""

    def __init__(self, profile: EventProfile):
        self.profile = profile
        self._observations: dict[tuple[str, str], dict[str, Any]] = {}
        self._status: dict[tuple[str, str], str] = {}
        self._lock = threading.Lock()

    def observe(self, agent_id: str, baseline: dict[str, Any] | None,
                approved: bool, telemetry: dict[str, Any]) -> dict[str, dict[str, Any]]:
        ready = {}
        binding = hashlib.sha256(canonical_json_bytes(baseline)).hexdigest() if baseline else ""
        with self._lock:
            for manifest in self.profile.services:
                if manifest["host"] != agent_id:
                    continue
                service = manifest["service_id"]
                key = (agent_id, service)
                try:
                    if not approved or not baseline:
                        raise ValueError("baseline is not approved")
                    parameters = recovery_parameters(self.profile, agent_id, service, baseline, telemetry)
                except (KeyError, TypeError, ValueError) as exc:
                    self._observations.pop(key, None)
                    self._status[key] = str(exc)
                    continue
                prior = self._observations.get(key, {})
                sequence = telemetry["sequence"]
                consecutive = (
                    prior.get("boot_id") == telemetry["boot_id"]
                    and prior.get("baseline") == binding
                    and prior.get("sequence") == sequence - 1
                    and 0 < telemetry["observed_at"] - prior.get("observed_at", 0) <= RECOVERY_FRESHNESS_SECONDS
                )
                count = min(RECOVERY_CONFIRMATIONS, prior.get("count", 0) + 1) if consecutive else 1
                self._observations[key] = {
                    "boot_id": telemetry["boot_id"], "sequence": sequence,
                    "baseline": binding, "observed_at": telemetry["observed_at"], "count": count,
                }
                self._status[key] = "ready" if count >= RECOVERY_CONFIRMATIONS else "awaiting consecutive observations"
                if count >= RECOVERY_CONFIRMATIONS:
                    ready[service] = parameters
        return ready

    def status(self) -> list[dict[str, str]]:
        with self._lock:
            return [{"agent_id": host, "service": service, "status": status}
                    for (host, service), status in sorted(self._status.items())]
