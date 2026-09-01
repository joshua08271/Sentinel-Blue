"""Disposable competition-legality training and adversarial policy campaign."""

from __future__ import annotations

import argparse
import json
import random
import tempfile
import time
from pathlib import Path
from typing import Any

from . import __version__
from .event_profile import CAPABILITIES, EventProfile
from .store import Store


CASES = (
    "exact-host-scope",
    "excluded-host",
    "approved-route",
    "approved-path",
    "unknown-capability",
    "single-live-network",
    "non-authoritative-staging",
    "live-service-migration",
    "automatic-vm-replacement",
    "network-fork",
    "hivestorm-snapshot",
    "ccdc-cloud-processing",
    "range-mode-on-live",
    "guarded-action-allowlist",
    "observe-mode-write",
    "emergency-stop-write",
    "emergency-rollback",
    "release-version-binding",
    "service-contract",
    "multiple-indicator-restriction",
    "one-use-authorization",
)


def _payload(
    *,
    competition: str = "custom",
    autonomy_mode: str = "approval-based",
    capabilities: dict[str, bool] | None = None,
    automatic_actions: list[str] | None = None,
) -> dict[str, Any]:
    enabled = {name: False for name in CAPABILITIES}
    enabled.update(
        {
            "in_place_repair": True,
            "structured_rollback": True,
            "configuration_backups": True,
            "network_monitoring": True,
            "external_controller": True,
            "file_restoration": True,
            "session_containment": True,
        }
    )
    enabled.update(capabilities or {})
    return {
        "profile_version": 1,
        "profile_id": f"policy-lab-{competition}-{autonomy_mode}",
        "competition": competition,
        "environment": "live-competition",
        "autonomy_mode": autonomy_mode,
        "architecture": {
            "single_live_scored_network": True,
            "blue_staging_non_authoritative": True,
        },
        "scope": {
            "authorized_networks": ["192.0.2.0/24"],
            "authorized_hosts": ["192.0.2.10"],
            "excluded_hosts": ["192.0.2.99"],
            "approved_deployment_paths": [
                "/opt/sentinel-blue",
                "C:\\ProgramData\\SentinelBlue",
            ],
        },
        "deployment": {"approved_routes": ["ssh", "winrm"]},
        "capabilities": enabled,
        "organizer_exceptions": [],
        "allowed_automatic_actions": automatic_actions or [],
        "official_identities": [
            {
                "agent_id": "*",
                "name": "scoring-service-example",
                "class": "scoring",
                "source": "policy-lab",
            }
        ],
        "services": [
            {
                "service_id": "web-example",
                "host": "192.0.2.10",
                "protocol": "https",
                "port": 443,
                "implementation": "example only",
                "dependencies": [],
                "required_accounts": ["scoring-service-example"],
                "required_files": ["/srv/example/config"],
                "required_data": ["business-data-example"],
                "credential_source": "event-issued secret store",
                "expected_transactions": [{"kind": "https", "path": "/health"}],
                "local_checks": ["service state and configuration validation"],
                "allowed_automatic_actions": ["validate_service"],
                "approval_actions": ["restart_service", "rollback_service"],
                "backup_method": "versioned configuration backup",
                "recovery_method": "least-disruptive in-place repair",
                "rollback_method": "restore exact pre-state and revalidate",
            }
        ],
        "services_confirmed": True,
        "recovery": {"baseline_promotion_delay_seconds": 60},
        "approval": {"status": "approved", "approved_by": "disposable-policy-lab"},
        "release": {
            "version": __version__,
            "approved": True,
            "sha256": "a" * 64,
            "public_url": f"https://example.invalid/sentinel-blue-{__version__}.pyz",
            "frozen": True,
            "submitted_to_officials": True,
            "submission_approved": True,
            "public_and_equal_access": True,
            "cloud_processing": False,
            "external_telemetry_export": False,
            "public_days_before_event": 120,
            "submitted_days_before_event": 45,
        },
    }


def _rejected(payload: dict[str, Any], text: str = "") -> bool:
    try:
        EventProfile.from_dict(payload)
    except ValueError as exc:
        return not text or text.casefold() in str(exc).casefold()
    return False


def _exercise(case: str) -> tuple[bool, str]:
    payload = _payload()
    if case == "exact-host-scope":
        profile = EventProfile.from_dict(payload)
        try:
            profile.assert_target("192.0.2.11")
        except ValueError:
            return True, "undeclared host refused"
    elif case == "excluded-host":
        payload["scope"]["authorized_hosts"].append("192.0.2.99")
        return _rejected(payload, "both authorized and excluded"), "exclusion wins"
    elif case == "approved-route":
        profile = EventProfile.from_dict(payload)
        try:
            profile.assert_route("portal-upload")
        except ValueError:
            return True, "unapproved deployment route refused"
    elif case == "approved-path":
        profile = EventProfile.from_dict(payload)
        try:
            profile.assert_deployment_path("/tmp/unapproved")
        except ValueError:
            return True, "unapproved deployment path refused"
    elif case == "unknown-capability":
        payload["capabilities"]["invented_override"] = True
        return _rejected(payload, "unknown keys"), "unknown rule key failed closed"
    elif case == "single-live-network":
        payload["architecture"]["single_live_scored_network"] = False
        return _rejected(payload, "single_live_scored_network"), "fork architecture refused"
    elif case == "non-authoritative-staging":
        payload["architecture"]["blue_staging_non_authoritative"] = False
        return _rejected(payload, "blue_staging_non_authoritative"), "authoritative staging refused"
    elif case in {"live-service-migration", "automatic-vm-replacement", "network-fork"}:
        capability = {
            "live-service-migration": "scored_service_migration",
            "automatic-vm-replacement": "automatic_vm_replacement",
            "network-fork": "network_forks",
        }[case]
        payload["capabilities"][capability] = True
        return _rejected(payload, "prohibited"), f"{capability} refused"
    elif case == "hivestorm-snapshot":
        payload["competition"] = "hivestorm"
        payload["capabilities"]["host_snapshots"] = True
        return _rejected(payload, "prohibited"), "Hivestorm snapshot refused"
    elif case == "ccdc-cloud-processing":
        payload["competition"] = "ccdc-strict"
        payload["capabilities"]["external_cloud_processing"] = True
        return _rejected(payload, "prohibited"), "CCDC cloud processing refused"
    elif case == "range-mode-on-live":
        payload["autonomy_mode"] = "range-autonomous"
        return _rejected(payload, "cannot be used"), "live range autonomy refused"
    elif case == "guarded-action-allowlist":
        payload = _payload(
            autonomy_mode="guarded-autonomous",
            capabilities={"guarded_autonomy": True},
            automatic_actions=["restart_service"],
        )
        profile = EventProfile.from_dict(payload)
        return (
            profile.action_allowed("restart_service", automated=True)
            and not profile.action_allowed("restore_integrity", automated=True),
            "only enumerated automatic action allowed",
        )
    elif case == "observe-mode-write":
        profile = EventProfile.from_dict(_payload(autonomy_mode="observe"))
        return not profile.action_allowed("restart_service", automated=False), "observe mode refused write"
    elif case == "emergency-stop-write":
        profile = EventProfile.from_dict(payload)
        return not profile.action_allowed(
            "restart_service", automated=False, emergency_stopped=True
        ), "emergency stop refused new change"
    elif case == "emergency-rollback":
        profile = EventProfile.from_dict(payload)
        return profile.action_allowed(
            "rollback_service", automated=False, emergency_stopped=True
        ), "bounded rollback remained available"
    elif case == "release-version-binding":
        profile = EventProfile.from_dict(payload)
        try:
            profile.require_live_ready("0.0.0")
        except ValueError:
            return True, "unapproved release version refused"
    elif case == "service-contract":
        del payload["services"][0]["rollback_method"]
        return _rejected(payload, "missing required fields"), "incomplete recovery contract refused"
    elif case == "multiple-indicator-restriction":
        from .detection import detect

        baseline = {
            "accounts": [{"name": "root", "privileged": True, "enabled": True}],
            "sessions": [],
            "services": [],
        }
        session = {
            "username": "root",
            "source": "192.0.2.44",
            "session_id": "pts/policy-lab",
            "process_id": 4242,
            "privileged": True,
            "interactive": True,
            "process_identity": {
                "schema": "sentinel-process-v1",
                "platform": "linux",
                "process_id": 4242,
                "boot_id": "policy-lab-boot-0001",
                "start_time": "123456",
                "executable_path": "/usr/sbin/sshd",
                "executable_file_id": "dev:1:ino:2",
                "user_id": "uid:0:0",
                "kernel_session_id": "4242",
            },
        }
        single = detect({**baseline, "sessions": [session]}, baseline, set())
        corroborated = detect(
            {
                **baseline,
                "sessions": [session],
                "security_events": [
                    {
                        "event_id": "policy-auth-1",
                        "category": "auth_success",
                        "account": "root",
                        "remote_address": "192.0.2.44",
                        "occurred_at": 1,
                    }
                ],
            },
            baseline,
            set(),
        )
        single_session = next(item for item in single if item.kind == "unverified_privileged_session")
        corroborated_session = next(
            item for item in corroborated if item.kind == "unverified_privileged_session"
        )
        return (
            single_session.recommended_action == "snapshot"
            and corroborated_session.recommended_action == "quarantine_session",
            "session restriction required two independent indicators",
        )
    elif case == "one-use-authorization":
        with tempfile.TemporaryDirectory(prefix="sentinel-blue-policy-auth-") as directory:
            store = Store(Path(directory) / "policy.db")
            try:
                issued = store.issue_privileged_authorization(
                    "agent-example", "restart_service", "alert-example", 30
                )
                code = str(issued["authorization_code"])
                first = store.consume_privileged_authorization(
                    code, "agent-example", "restart_service", "alert-example"
                )
                replay = store.consume_privileged_authorization(
                    code, "agent-example", "restart_service", "alert-example"
                )
                rebound = store.consume_privileged_authorization(
                    code, "different-agent", "restart_service", "alert-example"
                )
                return first and not replay and not rebound, "authorization consumed once and exactly bound"
            finally:
                store.close()
    return False, "case produced no expected policy decision"


def competition_policy_campaign(iterations: int = 200, seed: int = 1800) -> dict[str, Any]:
    total = max(len(CASES), min(int(iterations), 10_000))
    randomizer = random.Random(seed)
    selected = list(CASES)
    selected.extend(randomizer.choice(CASES) for _ in range(total - len(CASES)))
    counts = {name: 0 for name in CASES}
    failures: list[dict[str, str]] = []
    started = time.perf_counter()
    for case in selected:
        counts[case] += 1
        try:
            passed, detail = _exercise(case)
        except Exception as exc:  # Evidence is retained; campaign continues boundedly.
            passed, detail = False, f"{type(exc).__name__}: {exc}"
        if not passed:
            failures.append({"case": case, "detail": detail})
    return {
        "mode": "disposable competition-legality adversarial policy campaign",
        "scenarios": total,
        "passed_scenarios": total - len(failures),
        "failed_scenarios": len(failures),
        "case_coverage": counts,
        "failures": failures[:20],
        "passed": not failures,
        "real_hosts_modified": False,
        "real_competition_attacks": False,
        "readiness_claim": "synthetic policy validation only",
        "duration_seconds": round(time.perf_counter() - started, 3),
    }


def run(args: argparse.Namespace) -> int:
    report = competition_policy_campaign(max(1, min(args.runs, 10_000)))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("Sentinel Blue competition-legality policy lab")
        for key, value in report.items():
            print(f"{key}: {value}")
    return 0 if report["passed"] else 1


__all__ = ["CASES", "competition_policy_campaign"]
