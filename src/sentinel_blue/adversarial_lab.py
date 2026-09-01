"""Deterministic hostile-input and state-machine validation for the local lab."""

from __future__ import annotations

import copy
import random
import time
from typing import Any, Callable

from .auth import response_signature, signature, verify, verify_response
from .validation import ValidationError, validate_telemetry


def valid_payload(now: float | None = None) -> dict[str, Any]:
    observed = time.time() if now is None else now
    return {
        "agent_id": "fuzz-agent",
        "hostname": "fuzz-host",
        "platform": "Linux lab",
        "observed_at": observed,
        "accounts": [{"name": "root", "account_id": "0", "privileged": True, "enabled": True}],
        "sessions": [],
        "services": [{"name": "web.service", "state": "running", "start_mode": "enabled"}],
        "interfaces": [{"name": "eth0", "addresses": ["192.0.2.10"]}],
        "routes": [{"destination": "default", "gateway": "192.0.2.1", "interface": "eth0"}],
        "neighbors": [],
        "listeners": [{"protocol": "tcp", "address": "0.0.0.0", "port": 80}],
        "integrity": [{"path": "/etc/passwd", "sha256": "a" * 64, "size": 100, "modified_at": observed}],
        "probes": [{"name": "web", "target": "http://192.0.2.10", "healthy": True}],
        "processes": [{"name": "init", "path": "/sbin/init", "username": "root", "process_id": 1, "parent_id": 0, "privileged": True}],
        "persistence": [],
        "firewall": {"enabled": True, "provider": "nftables", "rules_sha256": "b" * 64},
        "collector_errors": [],
    }


def _mutators(now: float) -> list[tuple[str, Callable[[dict[str, Any]], None]]]:
    return [
        ("agent-path-traversal", lambda value: value.update(agent_id="../../controller")),
        ("identity-mismatch", lambda value: value.update(agent_id="other-agent")),
        ("stale-replay", lambda value: value.update(observed_at=now - 8 * 86400)),
        ("future-timestamp", lambda value: value.update(observed_at=now + 3600)),
        ("nan-timestamp", lambda value: value.update(observed_at=float("nan"))),
        ("oversized-hostname", lambda value: value.update(hostname="x" * 10000)),
        ("control-character", lambda value: value.update(hostname="host\x00name")),
        ("accounts-not-array", lambda value: value.update(accounts={})),
        ("account-flood", lambda value: value.update(accounts=[value["accounts"][0]] * 4097)),
        ("boolean-pid", lambda value: value.update(processes=[{**value["processes"][0], "process_id": True}])),
        ("invalid-port", lambda value: value.update(listeners=[{**value["listeners"][0], "port": 70000}])),
        ("invalid-digest", lambda value: value.update(integrity=[{**value["integrity"][0], "sha256": "not-a-hash"}])),
        (
            "invalid-security-descriptor-digest",
            lambda value: value.update(
                integrity=[
                    {
                        **value["integrity"][0],
                        "security_descriptor_sha256": "not-a-hash",
                    }
                ]
            ),
        ),
        ("probe-health-string", lambda value: value.update(probes=[{**value["probes"][0], "healthy": "yes"}])),
        ("firewall-bool-string", lambda value: value.update(firewall={"enabled": "true"})),
        ("negative-sequence", lambda value: value.update(sequence=-1)),
    ]


def protocol_fuzz(iterations: int = 1500, seed: int = 9090) -> dict[str, Any]:
    randomizer = random.Random(seed)
    now = time.time()
    mutators = _mutators(now)
    total = max(len(mutators), int(iterations))
    rejected = accepted_invalid = 0
    by_case: dict[str, int] = {name: 0 for name, _ in mutators}
    selected = list(mutators)
    selected.extend(randomizer.choice(mutators) for _ in range(total - len(mutators)))
    for name, mutate in selected:
        payload = copy.deepcopy(valid_payload(now))
        mutate(payload)
        try:
            validate_telemetry(payload, "fuzz-agent", now=now)
            accepted_invalid += 1
        except ValidationError:
            rejected += 1
            by_case[name] += 1
    valid_accepted = 0
    for index in range(100):
        payload = valid_payload(now)
        payload["sequence"] = index
        payload["hostname"] = f"valid-host-{index}"
        validate_telemetry(payload, "fuzz-agent", now=now)
        valid_accepted += 1
    return {
        "mode": "bounded hostile telemetry-schema fuzz",
        "invalid_cases": total,
        "invalid_rejected": rejected,
        "invalid_accepted": accepted_invalid,
        "valid_cases": 100,
        "valid_accepted": valid_accepted,
        "case_coverage": by_case,
        "passed": (
            accepted_invalid == 0
            and valid_accepted == 100
            and all(count > 0 for count in by_case.values())
        ),
    }


def authentication_boundary_campaign() -> dict[str, Any]:
    """Deterministically verify request/response freshness rejects non-finite time."""
    token = "a" * 32
    path = "/api/v1/agent/telemetry"
    body = b"{}"
    now = 1_800_000_000.0
    finite_timestamp = str(now)
    finite_request = signature(token, finite_timestamp, "POST", path, body)
    finite_response = response_signature(
        token,
        finite_timestamp,
        202,
        path,
        finite_request,
        body,
    )
    finite_control = verify(
        token,
        finite_timestamp,
        "POST",
        path,
        body,
        finite_request,
        now=now,
    ) and verify_response(
        token,
        finite_timestamp,
        202,
        path,
        finite_request,
        body,
        finite_response,
        now=now,
    )
    rejected: dict[str, dict[str, bool]] = {}
    for label, timestamp in (
        ("nan-lower", "nan"),
        ("nan-upper", "NaN"),
        ("positive-infinity", "inf"),
        ("negative-infinity", "-inf"),
    ):
        request = signature(token, timestamp, "POST", path, body)
        response = response_signature(token, timestamp, 202, path, request, body)
        rejected[label] = {
            "request": not verify(
                token, timestamp, "POST", path, body, request, now=now
            ),
            "request_after_replay_lifetime": not verify(
                token, timestamp, "POST", path, body, request, now=now + 10_000.0
            ),
            "response": not verify_response(
                token, timestamp, 202, path, request, body, response, now=now
            ),
        }
    nonfinite_current_rejected = not verify(
        token,
        finite_timestamp,
        "POST",
        path,
        body,
        finite_request,
        now=float("nan"),
    )
    passed = bool(
        finite_control
        and nonfinite_current_rejected
        and all(all(result.values()) for result in rejected.values())
    )
    return {
        "mode": "deterministic authentication freshness boundary",
        "passed": passed,
        "finite_control": bool(finite_control),
        "nonfinite_cases": len(rejected),
        "nonfinite_rejected": sum(
            1 for result in rejected.values() if all(result.values())
        ),
        "nonfinite_current_rejected": nonfinite_current_rejected,
        "case_results": rejected,
    }
