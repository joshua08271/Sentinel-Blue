"""Explainable defensive detections and recommendation generation."""

from __future__ import annotations

import hashlib
from typing import Any

from .protocol import AlertCandidate
from .process_identity import validate_process_identity
from .risk import RiskModel
from .validation import ModelBoundAlertCandidate


BUILTIN_PRIVILEGED = {"root", "administrator"}


def _confidence(model: RiskModel, features: dict[str, float], floor: float = 0.5) -> float:
    return round(max(floor, min(0.99, model.predict(features))), 3)


def detect(
    telemetry: dict[str, Any],
    baseline: dict[str, Any] | None,
    protected_accounts: set[str],
    model: RiskModel | None = None,
) -> list[AlertCandidate]:
    model = model or RiskModel()
    candidates: list[AlertCandidate] = []
    from .analyzers import analyze_all
    baseline_accounts = {
        account.get("name", "").casefold(): account
        for account in (baseline or {}).get("accounts", [])
    }
    current_accounts = {
        account.get("name", "").casefold(): account for account in telemetry.get("accounts", [])
    }

    for normalized, account in current_accounts.items():
        if not account.get("privileged") or not account.get("enabled", True):
            continue
        if normalized in protected_accounts:
            continue
        is_builtin = normalized in BUILTIN_PRIVILEGED
        is_new = normalized not in baseline_accounts
        # Built-in root/Administrator accounts are expected to exist. Their
        # interactive use is reviewed separately, where source and session
        # evidence are available.
        if is_builtin:
            continue
        features = {
            "unknown_privileged_account": 1.0,
            "new_privileged_account": 1.0 if is_new else 0.0,
            "protected_identity": 0.0,
        }
        confidence = _confidence(model, features, 0.68)
        candidates.append(
            ModelBoundAlertCandidate(
                kind="unverified_privileged_account",
                title="Unverified privileged account",
                summary=(
                    f"{account.get('name', 'unknown')} has root/Administrator-equivalent "
                    "access but is not in the protected competition manifest."
                ),
                severity="high",
                confidence=confidence,
                model_features=features,
                evidence={"account": account, "new_since_baseline": is_new},
                recommendation=(
                    "Verify the identity against the event account list. Until verified, "
                    "observe or quarantine only its interactive session; do not disable "
                    "service processes or the account itself."
                ),
                recommended_action="snapshot",
            )
        )

    for session in telemetry.get("sessions", []):
        normalized = session.get("username", "").casefold()
        if not session.get("interactive", True) or not session.get("privileged"):
            continue
        if normalized in protected_accounts:
            continue
        source = session.get("source", "unknown")
        external = source not in {"", "local", "localhost", "127.0.0.1", "::1", "unknown"}
        indicators: list[str] = []
        if external:
            indicators.append("external_interactive_origin")
        account = current_accounts.get(normalized, {})
        if account and normalized not in baseline_accounts and normalized not in BUILTIN_PRIVILEGED:
            indicators.append("new_unverified_privileged_account")
        for event in telemetry.get("security_events", []):
            category = str(event.get("category", "")).casefold()
            event_account = str(event.get("account", "")).casefold()
            event_remote = str(event.get("remote_address", "unknown"))
            if event_account != normalized:
                continue
            if category == "auth_success" and external and event_remote == source:
                indicators.append("matching_external_authentication")
            elif category in {"account_created", "privilege_change"}:
                indicators.append(f"security_event_{category}")
        indicators = list(dict.fromkeys(indicators))
        try:
            identity = validate_process_identity(session.get("process_identity"))
            identity_supported = identity["process_id"] == session.get("process_id")
        except ValueError:
            identity_supported = False
        restriction_supported = len(indicators) >= 2 and identity_supported
        features = {
            "interactive_privileged_session": 1.0,
            "external_source": 1.0 if external else 0.0,
            "protected_identity": 0.0,
        }
        candidates.append(
            ModelBoundAlertCandidate(
                kind="unverified_privileged_session",
                title="Privileged interactive session needs verification",
                summary=f"{session.get('username', 'unknown')} opened a privileged session from {source}.",
                severity="critical" if external else "high",
                confidence=_confidence(model, features, 0.72),
                model_features=features,
                evidence={
                    "session": session,
                    "behavioral_indicators": indicators,
                    "restriction_threshold": 2,
                    "restriction_supported": restriction_supported,
                    "process_identity_supported": identity_supported,
                },
                recommendation=(
                    "Review the account, source, and session activity. "
                    + (
                        "Multiple independent indicators support an approved, session-scoped "
                        "quarantine while preserving services."
                        if restriction_supported
                        else (
                            "Do not restrict the session until immutable process identity is "
                            "available and another independent behavioral indicator corroborates it."
                        )
                    )
                ),
                recommended_action="quarantine_session" if restriction_supported else "snapshot",
            )
        )

    if baseline:
        baseline_running = {
            service.get("name", ""): service
            for service in baseline.get("services", [])
            if service.get("state") == "running"
        }
        current_services = {
            service.get("name", ""): service for service in telemetry.get("services", [])
        }
        for name, prior in baseline_running.items():
            current = current_services.get(name)
            if current and current.get("state") == "running":
                continue
            features = {"critical_service_stopped": 1.0}
            candidates.append(
                ModelBoundAlertCandidate(
                    kind="baseline_service_stopped",
                    title="Baseline service is not running",
                    summary=f"Service {name} was running in the baseline and is now unavailable.",
                    severity="high",
                    confidence=_confidence(model, features, 0.8),
                    model_features=features,
                    evidence={"service": name, "baseline": prior, "current": current},
                    recommendation=(
                        "Validate the service dependency chain and scoring reachability, then "
                        "approve a snapshot and service-specific recovery action."
                    ),
                    recommended_action="restart_service",
                )
            )

        baseline_integrity = {
            item.get("path", ""): item for item in baseline.get("integrity", []) if item.get("path")
        }
        current_integrity = {
            item.get("path", ""): item for item in telemetry.get("integrity", []) if item.get("path")
        }
        for path, previous in baseline_integrity.items():
            current = current_integrity.get(path)
            content_changed = current is None or current.get("sha256") != previous.get("sha256")
            baseline_security_digest = previous.get("security_descriptor_sha256", "")
            observed_security_digest = (
                current.get("security_descriptor_sha256", "") if current else None
            )
            security_metadata_changed = current is None or (
                observed_security_digest != baseline_security_digest
            )
            if not content_changed and not security_metadata_changed:
                continue
            change_types = []
            if content_changed:
                change_types.append("content")
            if security_metadata_changed:
                change_types.append("security_metadata")
            security_baseline_upgrade = bool(
                current and not baseline_security_digest and observed_security_digest
            )
            observation_material = "\x00".join(
                (
                    str(current.get("sha256", "")) if current else "__missing__",
                    str(observed_security_digest or "__missing__"),
                )
            )
            features = {"integrity_change": 1.0}
            candidates.append(
                ModelBoundAlertCandidate(
                    kind="critical_file_changed",
                    title="Security-critical file changed",
                    summary=(
                        f"{path} is missing from telemetry."
                        if current is None
                        else (
                            f"{path} security metadata requires explicit baseline approval."
                            if security_baseline_upgrade and not content_changed
                            else f"{path} no longer matches the approved host baseline."
                        )
                    ),
                    severity="critical",
                    confidence=_confidence(model, features, 0.86),
                    model_features=features,
                    evidence={
                        "path": path,
                        "baseline": previous,
                        "current": current,
                        "baseline_sha256": previous.get("sha256"),
                        "observed_sha256": current.get("sha256") if current else None,
                        "baseline_security_descriptor_sha256": baseline_security_digest,
                        "observed_security_descriptor_sha256": observed_security_digest,
                        "observed_missing": current is None,
                        "security_metadata_changed": security_metadata_changed,
                        "security_baseline_upgrade": security_baseline_upgrade,
                        "change_types": change_types,
                        "change_observation_sha256": hashlib.sha256(
                            observation_material.encode("utf-8")
                        ).hexdigest(),
                    },
                    recommendation=(
                        "Preserve the changed file for evidence, restore only from the locally "
                        "verified approved restore point, and revalidate scored services."
                    ),
                    recommended_action="restore_integrity",
                )
            )

        def default_routes(source: dict[str, Any]) -> set[tuple[str, str, str]]:
            return {
                (
                    str(route.get("destination", "")),
                    str(route.get("gateway", "")),
                    str(route.get("interface", "")),
                )
                for route in source.get("routes", [])
                if route.get("destination") in {"default", "0.0.0.0/0", "::/0"}
            }

        old_defaults = default_routes(baseline)
        new_defaults = default_routes(telemetry)
        if old_defaults and new_defaults != old_defaults:
            features = {"default_route_change": 1.0}
            candidates.append(
                ModelBoundAlertCandidate(
                    kind="default_route_changed",
                    title="Default route changed",
                    summary="The host default gateway or egress interface differs from its baseline.",
                    severity="critical",
                    confidence=_confidence(model, features, 0.85),
                    model_features=features,
                    evidence={"baseline": sorted(old_defaults), "current": sorted(new_defaults)},
                    recommendation=(
                        "Confirm the change against the competition topology before restoring the "
                        "previous route. An incorrect automatic route rollback can disconnect scoring."
                    ),
                    recommended_action="snapshot",
                )
            )

        old_listeners = {
            (str(item.get("protocol", "tcp")), str(item.get("address", "")), int(item.get("port", 0)))
            for item in baseline.get("listeners", [])
            if item.get("port")
        }
        for item in telemetry.get("listeners", []):
            key = (
                str(item.get("protocol", "tcp")),
                str(item.get("address", "")),
                int(item.get("port", 0)),
            )
            if not key[2] or key in old_listeners:
                continue
            features = {"new_listener": 1.0}
            candidates.append(
                ModelBoundAlertCandidate(
                    kind="new_network_listener",
                    title="New listening service",
                    summary=f"A new {key[0]} listener appeared on {key[1]}:{key[2]}.",
                    severity="medium",
                    confidence=_confidence(model, features, 0.58),
                    model_features=features,
                    evidence={"listener": item},
                    recommendation="Identify the owning process and verify that the listener is required.",
                    recommended_action="observe",
                )
            )

    for probe in telemetry.get("probes", []):
        if probe.get("healthy", False):
            continue
        features = {"probe_failure": 1.0}
        candidates.append(
            ModelBoundAlertCandidate(
                kind="service_probe_failed",
                title="Service health probe failed",
                summary=f"{probe.get('name', 'service')} failed its validation check.",
                severity="critical",
                confidence=_confidence(model, features, 0.88),
                model_features=features,
                evidence={"probe": probe},
                recommendation=(
                    "Check the local service, dependencies, firewall path, and credentials before "
                    "approving service-specific recovery."
                ),
                recommended_action="snapshot",
            )
        )

    if telemetry.get("collector_errors"):
        features = {"collector_failure": 1.0}
        candidates.append(
            ModelBoundAlertCandidate(
                kind="telemetry_degraded",
                title="Telemetry collection is incomplete",
                summary="One or more host collectors failed; conclusions may be incomplete.",
                severity="medium",
                confidence=_confidence(model, features, 0.55),
                model_features=features,
                evidence={"errors": telemetry["collector_errors"]},
                recommendation="Inspect collector errors before approving a disruptive response.",
                recommended_action="observe",
            )
        )

    candidates.extend(analyze_all(telemetry, baseline, protected_accounts, model))

    return candidates
