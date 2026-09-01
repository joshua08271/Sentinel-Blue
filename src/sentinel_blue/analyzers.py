"""Hyper-focused defensive analyzers combined by the central detector."""

from __future__ import annotations

from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from .protocol import AlertCandidate
from .risk import RiskModel
from .validation import ModelBoundAlertCandidate


def _confidence(model: RiskModel, features: dict[str, float], floor: float) -> float:
    return round(max(floor, min(0.99, model.predict(features))), 3)


def _index(items: list[dict[str, Any]], key: str = "name") -> dict[str, dict[str, Any]]:
    return {str(item.get(key, "")).casefold(): item for item in items if item.get(key)}


def analyze_identity(
    telemetry: dict[str, Any],
    baseline: dict[str, Any] | None,
    protected_accounts: set[str],
    model: RiskModel,
) -> list[AlertCandidate]:
    if not baseline:
        return []
    previous = _index(baseline.get("accounts", []))
    current = _index(telemetry.get("accounts", []))
    alerts: list[AlertCandidate] = []
    for name, old in previous.items():
        new = current.get(name)
        if name in protected_accounts and (not new or not new.get("enabled", True)):
            features = {"protected_identity_loss": 1.0}
            alerts.append(
                ModelBoundAlertCandidate(
                    kind="protected_identity_unavailable",
                    title="Protected competition identity is unavailable",
                    summary=f"Protected account {old.get('name', name)} is missing or disabled.",
                    severity="critical",
                    confidence=_confidence(model, features, 0.94),
                    model_features=features,
                    evidence={"account": old, "current": new},
                    recommendation=(
                        "Confirm whether Black Team or a scored service requires this identity. "
                        "Preserve evidence before restoring it through an event-approved procedure."
                    ),
                    recommended_action="snapshot",
                )
            )
        if new and not old.get("privileged") and new.get("privileged") and name not in protected_accounts:
            added_groups = sorted(
                set(map(str.casefold, new.get("groups", [])))
                - set(map(str.casefold, old.get("groups", [])))
            )
            features = {"privilege_membership_change": 1.0}
            alerts.append(
                ModelBoundAlertCandidate(
                    kind="privilege_membership_changed",
                    title="Existing account gained privileged access",
                    summary=f"{new.get('name', name)} became privileged after the approved baseline.",
                    severity="critical",
                    confidence=_confidence(model, features, 0.92),
                    model_features=features,
                    evidence={"account": new, "baseline": old, "added_groups": added_groups},
                    recommendation=(
                        "Verify the account and group change with the team. Do not remove it "
                        "automatically because it may be a required administrative identity."
                    ),
                    recommended_action="snapshot",
                )
            )
    return alerts


def analyze_services(
    telemetry: dict[str, Any], baseline: dict[str, Any] | None, model: RiskModel
) -> list[AlertCandidate]:
    if not baseline:
        return []
    previous = _index(baseline.get("services", []))
    current = _index(telemetry.get("services", []))
    alerts: list[AlertCandidate] = []
    automatic_modes = {"auto", "automatic", "enabled", "delayed-auto"}
    disabled_modes = {"disabled", "masked"}
    for name, old in previous.items():
        new = current.get(name)
        if not new:
            continue
        old_mode = str(old.get("start_mode", "unknown")).casefold()
        new_mode = str(new.get("start_mode", "unknown")).casefold()
        if old_mode in automatic_modes and new_mode in disabled_modes:
            features = {"service_configuration_change": 1.0}
            alerts.append(
                ModelBoundAlertCandidate(
                    kind="service_startup_disabled",
                    title="Baseline service startup was disabled",
                    summary=f"{new.get('name', name)} changed from {old_mode} to {new_mode} startup.",
                    severity="high",
                    confidence=_confidence(model, features, 0.86),
                    model_features=features,
                    evidence={"service": new.get("name", name), "baseline": old, "current": new},
                    recommendation=(
                        "Confirm the service is scored and inspect associated account and persistence "
                        "changes before restoring its startup mode."
                    ),
                    recommended_action="snapshot",
                )
            )
        previous_restarts = int(old.get("restart_count", 0) or 0)
        current_restarts = int(new.get("restart_count", 0) or 0)
        restart_delta = max(0, current_restarts - previous_restarts)
        failed_result = str(new.get("result", "")).casefold() not in {
            "",
            "success",
            "done",
            "unknown",
        }
        if restart_delta >= 3 or (failed_result and current_restarts >= 3):
            features = {"critical_service_stopped": 1.0}
            alerts.append(
                ModelBoundAlertCandidate(
                    kind="service_restart_loop",
                    title="Service is repeatedly failing or restarting",
                    summary=(
                        f"{new.get('name', name)} recorded {current_restarts} recent restarts "
                        f"with result {new.get('result', 'unknown')}."
                    ),
                    severity="high",
                    confidence=_confidence(model, features, 0.88),
                    model_features=features,
                    evidence={
                        "service": new.get("name", name),
                        "baseline": old,
                        "current": new,
                        "restart_delta": restart_delta,
                    },
                    recommendation=(
                        "Inspect service logs, configuration validation, dependencies, and scorer "
                        "reachability before another restart. Repeated blind restarts can extend downtime."
                    ),
                    recommended_action="snapshot",
                )
            )
    return alerts


def _persistence_key(item: dict[str, Any]) -> tuple[str, str]:
    return str(item.get("kind", "")).casefold(), str(item.get("name", "")).casefold()


def analyze_persistence(
    telemetry: dict[str, Any], baseline: dict[str, Any] | None, model: RiskModel
) -> list[AlertCandidate]:
    if not baseline:
        return []
    previous = {_persistence_key(item): item for item in baseline.get("persistence", [])}
    alerts: list[AlertCandidate] = []
    for item in telemetry.get("persistence", []):
        key = _persistence_key(item)
        old = previous.get(key)
        changed = bool(old and item.get("sha256") and old.get("sha256") != item.get("sha256"))
        if old and not changed:
            continue
        owner = str(item.get("owner", "unknown")).casefold()
        privileged_owner = owner in {"root", "system", "administrator", "nt authority\\system"}
        features = {"persistence_change": 1.0, "privileged_persistence": 1.0 if privileged_owner else 0.0}
        alerts.append(
            ModelBoundAlertCandidate(
                kind="persistence_changed" if changed else "new_persistence_item",
                title="Persistence configuration changed" if changed else "New persistence item",
                summary=(
                    f"{item.get('kind', 'startup')} item {item.get('name', 'unknown')} "
                    + ("changed." if changed else "appeared after the baseline.")
                ),
                severity="high" if privileged_owner else "medium",
                confidence=_confidence(model, features, 0.78 if privileged_owner else 0.62),
                model_features=features,
                evidence={"persistence": item, "baseline": old},
                recommendation=(
                    "Review the owner, target, creation time, and related authentication activity. "
                    "Preserve the item before any removal."
                ),
                recommended_action="snapshot",
            )
        )
    return alerts


def analyze_firewall(
    telemetry: dict[str, Any], baseline: dict[str, Any] | None, model: RiskModel
) -> list[AlertCandidate]:
    if not baseline:
        return []
    old = baseline.get("firewall") or {}
    new = telemetry.get("firewall") or {}
    if old.get("enabled") and not new.get("enabled"):
        features = {"firewall_disabled": 1.0}
        return [
            ModelBoundAlertCandidate(
                kind="host_firewall_disabled",
                title="Host firewall was disabled",
                summary=f"{new.get('provider', old.get('provider', 'Host firewall'))} is no longer active.",
                severity="critical",
                confidence=_confidence(model, features, 0.94),
                model_features=features,
                evidence={"baseline": old, "current": new},
                recommendation=(
                    "Confirm the firewall provider is still available and review recent privileged "
                    "activity. Restoring a generic ruleset can break scoring, so use the approved baseline."
                ),
                recommended_action="snapshot",
            )
        ]
    old_hash = str(old.get("rules_sha256", ""))
    new_hash = str(new.get("rules_sha256", ""))
    if old.get("enabled") and new.get("enabled") and old_hash and new_hash and old_hash != new_hash:
        features = {"firewall_rule_change": 1.0}
        return [
            ModelBoundAlertCandidate(
                kind="host_firewall_rules_changed",
                title="Host firewall rules changed",
                summary="The active host firewall rules no longer match the approved baseline.",
                severity="high",
                confidence=_confidence(model, features, 0.84),
                model_features=features,
                evidence={"baseline": old, "current": new},
                recommendation="Compare the change with team activity and scored service paths before rollback.",
                recommended_action="snapshot",
            )
        ]
    return []


def _temporary_path(path: str) -> bool:
    normalized = path.replace("\\", "/").casefold()
    posix = PurePosixPath(normalized)
    windows = PureWindowsPath(path)
    return (
        normalized.startswith(("/tmp/", "/var/tmp/", "/dev/shm/"))
        or "/appdata/local/temp/" in normalized
        or str(windows).casefold().startswith(("c:\\windows\\temp\\", "c:\\temp\\"))
        or (len(posix.parts) > 2 and posix.parts[1:3] == ("home", "tmp"))
    )


def analyze_processes(
    telemetry: dict[str, Any], baseline: dict[str, Any] | None, model: RiskModel
) -> list[AlertCandidate]:
    if not baseline:
        return []
    baseline_paths = {str(item.get("path", "")).casefold() for item in baseline.get("processes", [])}
    alerts: list[AlertCandidate] = []
    for process in telemetry.get("processes", []):
        path = str(process.get("path", ""))
        if not path or path.casefold() in baseline_paths or not _temporary_path(path):
            continue
        if not process.get("privileged"):
            continue
        features = {"suspicious_process_path": 1.0}
        alerts.append(
            ModelBoundAlertCandidate(
                kind="privileged_temporary_process",
                title="Privileged process launched from a temporary directory",
                summary=f"{process.get('name', 'process')} is running as {process.get('username')} from {path}.",
                severity="high",
                confidence=_confidence(model, features, 0.86),
                model_features=features,
                evidence={"process": process},
                recommendation=(
                    "Correlate the process with a verified administrator session and preserve the "
                    "binary path. Do not terminate it automatically without dependency context."
                ),
                recommended_action="snapshot",
            )
        )
    return alerts[:32]


def analyze_security_events(
    telemetry: dict[str, Any],
    baseline: dict[str, Any] | None,
    protected_accounts: set[str],
    model: RiskModel,
) -> list[AlertCandidate]:
    if not baseline:
        return []
    baseline_time = float(baseline.get("observed_at", 0) or 0)
    current_accounts = _index(telemetry.get("accounts", []))
    alerts: list[AlertCandidate] = []
    failed: dict[tuple[str, str], list[dict[str, Any]]] = {}
    seen: set[str] = set()
    for event in telemetry.get("security_events", []):
        event_id = str(event.get("event_id", ""))
        if not event_id or event_id in seen:
            continue
        seen.add(event_id)
        if float(event.get("occurred_at", 0) or 0) <= baseline_time:
            continue
        category = str(event.get("category", "")).casefold()
        account = str(event.get("account", "unknown"))
        normalized = account.casefold()
        remote = str(event.get("remote_address", "unknown"))
        if category == "auth_failure":
            failed.setdefault((normalized, remote), []).append(event)
            continue
        if category == "auth_success":
            current = current_accounts.get(normalized, {})
            if not current.get("privileged") or normalized in protected_accounts:
                continue
            if remote.casefold() in {"", "-", "unknown", "local", "127.0.0.1", "::1"}:
                continue
            title = "Unverified privileged authentication succeeded"
            severity = "critical"
            summary = f"{account} authenticated successfully from {remote}."
        elif category == "audit_cleared":
            title = "Security audit log was cleared"
            severity = "critical"
            summary = "The operating system recorded an audit-log clear event."
        elif category == "service_installed":
            title = "New system service was installed"
            severity = "high"
            summary = f"{event.get('actor', 'unknown')} installed a system service."
        elif category == "account_created":
            title = "New local account was created"
            severity = "high"
            summary = f"{event.get('actor', 'unknown')} created account {account}."
        elif category == "privilege_change":
            title = "Privileged group membership changed"
            severity = "critical"
            summary = f"{event.get('actor', 'unknown')} changed privileged access for {account}."
        elif category == "account_disabled_or_deleted":
            title = "Account was disabled or deleted"
            severity = "critical" if normalized in protected_accounts else "high"
            summary = f"{event.get('actor', 'unknown')} disabled or deleted account {account}."
        elif category == "account_changed":
            title = "Account security properties changed"
            severity = "high"
            summary = f"{event.get('actor', 'unknown')} changed account {account}."
        elif category == "audit_policy_changed":
            title = "Security audit policy changed"
            severity = "critical"
            summary = f"{event.get('actor', 'unknown')} changed security audit policy."
        elif category == "scheduled_task_changed":
            title = "Scheduled task changed"
            severity = "high"
            summary = f"{event.get('actor', 'unknown')} changed scheduled task {account}."
        elif category == "firewall_changed":
            title = "Host firewall configuration changed"
            severity = "high"
            summary = f"{event.get('actor', 'unknown')} changed Windows Firewall configuration."
        elif category == "account_deleted":
            title = "Local account was deleted"
            severity = "critical" if normalized in protected_accounts else "high"
            summary = f"{event.get('actor', 'unknown')} deleted account {account}."
        else:
            continue
        features = {"persistence_change": 1.0}
        alerts.append(
            ModelBoundAlertCandidate(
                kind=f"security_event_{category}",
                title=title,
                summary=summary,
                severity=severity,
                confidence=_confidence(model, features, 0.9),
                model_features=features,
                evidence={"security_event": event},
                recommendation=(
                    "Correlate the event with a known team decision and protected identity list. "
                    "Preserve evidence and use only the typed, reversible response offered by the controller."
                ),
                recommended_action="snapshot",
            )
        )
    for (account, remote), events in failed.items():
        if len(events) < 5:
            continue
        features = {"external_source": 1.0}
        alerts.append(
            ModelBoundAlertCandidate(
                kind="authentication_failure_burst",
                title="Repeated authentication failures",
                summary=f"{len(events)} authentication failures targeted {account} from {remote}.",
                severity="high" if len(events) >= 10 else "medium",
                confidence=_confidence(model, features, 0.76),
                model_features=features,
                evidence={"account": account, "remote_address": remote, "events": events[:20]},
                recommendation=(
                    "Check whether the source is a scoring or administration system before changing "
                    "access controls. Review successful logons and account state for the same identity."
                ),
                recommended_action="snapshot",
            )
        )
    return alerts[:64]


def analyze_all(
    telemetry: dict[str, Any],
    baseline: dict[str, Any] | None,
    protected_accounts: set[str],
    model: RiskModel,
) -> list[AlertCandidate]:
    return [
        *analyze_identity(telemetry, baseline, protected_accounts, model),
        *analyze_services(telemetry, baseline, model),
        *analyze_persistence(telemetry, baseline, model),
        *analyze_firewall(telemetry, baseline, model),
        *analyze_processes(telemetry, baseline, model),
        *analyze_security_events(telemetry, baseline, protected_accounts, model),
    ]
