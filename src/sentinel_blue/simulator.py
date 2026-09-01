"""Labeled, local-only defensive range simulation and model evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import time
from pathlib import Path
from typing import Any

from .detection import detect
from .risk import FEATURES, RiskModel


def training_samples(seed: int = 1337, count: int = 4000) -> list[tuple[dict[str, float], int]]:
    randomizer = random.Random(seed)
    samples: list[tuple[dict[str, float], int]] = []
    for _ in range(count):
        features = {name: 0.0 for name in FEATURES}
        scenario = randomizer.choice(
            [
                "normal",
                "protected",
                "rogue_admin",
                "remote_root",
                "service_loss",
                "integrity_change",
                "route_change",
                "probe_failure",
                "new_listener",
                "collector_gap",
                "protected_identity_loss",
                "privilege_membership_change",
                "service_configuration_change",
                "persistence_change",
                "firewall_disabled",
                "firewall_rule_change",
                "suspicious_process_path",
                "agent_heartbeat_missing",
            ]
        )
        label = 0
        if scenario == "protected":
            features["interactive_privileged_session"] = 1.0
            features["external_source"] = randomizer.choice((0.0, 1.0))
            features["protected_identity"] = 1.0
        elif scenario == "rogue_admin":
            features["unknown_privileged_account"] = 1.0
            features["new_privileged_account"] = 1.0
            label = 1
        elif scenario == "remote_root":
            features["interactive_privileged_session"] = 1.0
            features["external_source"] = 1.0
            label = 1
        elif scenario == "service_loss":
            features["critical_service_stopped"] = 1.0
            label = 1
        elif scenario == "integrity_change":
            features["integrity_change"] = 1.0
            label = 1
        elif scenario == "route_change":
            features["default_route_change"] = 1.0
            label = 1
        elif scenario == "probe_failure":
            features["probe_failure"] = 1.0
            label = 1
        elif scenario == "new_listener":
            features["new_listener"] = 1.0
        elif scenario == "collector_gap":
            features["collector_failure"] = 1.0
        elif scenario == "protected_identity_loss":
            features["protected_identity_loss"] = 1.0
            label = 1
        elif scenario == "privilege_membership_change":
            features["privilege_membership_change"] = 1.0
            label = 1
        elif scenario == "service_configuration_change":
            features["service_configuration_change"] = 1.0
            label = 1
        elif scenario == "persistence_change":
            features["persistence_change"] = 1.0
            features["privileged_persistence"] = 1.0
            label = 1
        elif scenario == "firewall_disabled":
            features["firewall_disabled"] = 1.0
            label = 1
        elif scenario == "firewall_rule_change":
            features["firewall_rule_change"] = 1.0
            label = 1
        elif scenario == "suspicious_process_path":
            features["suspicious_process_path"] = 1.0
            label = 1
        elif scenario == "agent_heartbeat_missing":
            features["agent_heartbeat_missing"] = 1.0
            label = 1
        for name in FEATURES:
            if randomizer.random() < 0.035:
                features[name] = max(features[name], randomizer.random() * 0.35)
        samples.append((features, label))
    return samples


def _telemetry_scenarios(
    seed: int = 2026, generated: int = 500
) -> list[tuple[str, dict[str, Any], dict[str, Any], set[str], bool]]:
    baseline = {
        "accounts": [
            {"name": "root", "account_id": "0", "privileged": True, "enabled": True},
            {"name": "student", "account_id": "1000", "privileged": True, "enabled": True},
            {"name": "www-data", "account_id": "33", "privileged": False, "enabled": False},
            {"name": "service-monitor-example", "account_id": "998", "privileged": False, "enabled": True},
            {"name": "analyst", "account_id": "1001", "privileged": False, "enabled": True, "groups": ["users"]},
        ],
        "sessions": [],
        "services": [
            {"name": "web.service", "state": "running", "start_mode": "enabled"},
            {"name": "db.service", "state": "running", "start_mode": "enabled"},
        ],
        "integrity": [
            {"path": "/etc/passwd", "sha256": "a" * 64, "size": 100, "modified_at": 1.0},
            {"path": "/etc/ssh/sshd_config", "sha256": "b" * 64, "size": 200, "modified_at": 1.0}
        ],
        "routes": [{"destination": "default", "gateway": "192.0.2.1", "interface": "eth0"}],
        "listeners": [{"protocol": "tcp", "address": "0.0.0.0", "port": 80, "process": "web"}],
        "probes": [],
        "processes": [{"name": "init", "path": "/sbin/init", "username": "root", "process_id": 1, "parent_id": 0, "privileged": True}],
        "persistence": [{"kind": "systemd-unit", "name": "web.service", "owner": "root", "enabled": True, "sha256": ""}],
        "firewall": {"enabled": True, "provider": "nftables", "rules_sha256": "d" * 64, "detail": "rules present"},
    }

    def telemetry(accounts=None, sessions=None, services=None, errors=None):
        return {
            "agent_id": "range-linux-1",
            "hostname": "range-linux-1",
            "platform": "Linux range",
            "observed_at": time.time(),
            "accounts": baseline["accounts"] if accounts is None else accounts,
            "sessions": [] if sessions is None else sessions,
            "services": baseline["services"] if services is None else services,
            "interfaces": [],
            "integrity": json.loads(json.dumps(baseline["integrity"])),
            "routes": json.loads(json.dumps(baseline["routes"])),
            "neighbors": [],
            "listeners": json.loads(json.dumps(baseline["listeners"])),
            "probes": [],
            "processes": json.loads(json.dumps(baseline["processes"])),
            "persistence": json.loads(json.dumps(baseline["persistence"])),
            "firewall": json.loads(json.dumps(baseline["firewall"])),
            "collector_errors": [] if errors is None else errors,
        }

    rogue_accounts = baseline["accounts"] + [
        {"name": "backup-maint", "account_id": "0", "privileged": True, "enabled": True}
    ]
    scenarios = [
        ("normal baseline", telemetry(), baseline, {"student"}, False),
        (
            "protected black-team login",
            telemetry(sessions=[{"username": "protected-admin-example", "source": "198.51.100.5", "privileged": True, "interactive": True, "process_id": 2001}]),
            baseline,
            {"student", "protected-admin-example"},
            False,
        ),
        ("rogue UID-0 account", telemetry(accounts=rogue_accounts), baseline, {"student"}, True),
        (
            "unverified remote root",
            telemetry(sessions=[{"username": "root", "source": "198.51.100.66", "privileged": True, "interactive": True, "process_id": 2110}]),
            baseline,
            {"student"},
            True,
        ),
        (
            "web scoring service stopped",
            telemetry(services=[{"name": "web.service", "state": "stopped"}, {"name": "db.service", "state": "running"}]),
            baseline,
            {"student"},
            True,
        ),
        ("collector degraded", telemetry(errors=["systemctl unavailable"]), baseline, {"student"}, False),
        (
            "critical file changed",
            telemetry(),
            baseline,
            {"student"},
            True,
        ),
        (
            "default gateway changed",
            telemetry(),
            baseline,
            {"student"},
            True,
        ),
        (
            "scoring probe failed",
            telemetry(),
            baseline,
            {"student"},
            True,
        ),
        (
            "new listener for approved inject",
            telemetry(),
            baseline,
            {"student"},
            False,
        ),
    ]
    scenarios[-4][1]["integrity"] = [
        {"path": "/etc/passwd", "sha256": "c" * 64, "size": 140, "modified_at": 2.0},
        baseline["integrity"][1],
    ]
    scenarios[-3][1]["routes"] = [
        {"destination": "default", "gateway": "192.0.2.254", "interface": "eth0"}
    ]
    scenarios[-2][1]["probes"] = [
        {"name": "web", "target": "http://192.0.2.10", "healthy": False, "detail": "timeout"}
    ]
    scenarios[-1][1]["listeners"] = baseline["listeners"] + [
        {"protocol": "tcp", "address": "0.0.0.0", "port": 8443, "process": "inject-app"}
    ]

    protected_missing = telemetry(
        accounts=[item for item in baseline["accounts"] if item["name"] != "service-monitor-example"]
    )
    escalated_accounts = json.loads(json.dumps(baseline["accounts"]))
    for item in escalated_accounts:
        if item["name"] == "analyst":
            item["privileged"] = True
            item["groups"] = ["users", "sudo"]
    startup_disabled = telemetry(
        services=[
            {"name": "web.service", "state": "running", "start_mode": "disabled"},
            baseline["services"][1],
        ]
    )
    new_persistence = telemetry()
    new_persistence["persistence"] = baseline["persistence"] + [
        {"kind": "cron", "name": "/etc/cron.d/.update", "owner": "root", "enabled": True, "sha256": "e" * 64}
    ]
    firewall_disabled = telemetry()
    firewall_disabled["firewall"] = {
        "enabled": False,
        "provider": "nftables",
        "rules_sha256": hashlib.sha256(b"").hexdigest(),
        "detail": "no rules",
    }
    firewall_changed = telemetry()
    firewall_changed["firewall"] = {
        "enabled": True,
        "provider": "nftables",
        "rules_sha256": "f" * 64,
        "detail": "rules present",
    }
    temp_process = telemetry()
    temp_process["processes"] = baseline["processes"] + [
        {"name": "update", "path": "/tmp/.update", "username": "root", "process_id": 2400, "parent_id": 1, "privileged": True}
    ]
    missing_file = telemetry()
    missing_file["integrity"] = [baseline["integrity"][1]]
    scenarios.extend(
        [
            ("protected scorer account removed", protected_missing, baseline, {"student", "service-monitor-example"}, True),
            ("existing analyst promoted to sudo", telemetry(accounts=escalated_accounts), baseline, {"student"}, True),
            ("scored service startup disabled", startup_disabled, baseline, {"student"}, True),
            ("new root cron persistence", new_persistence, baseline, {"student"}, True),
            ("host firewall disabled", firewall_disabled, baseline, {"student"}, True),
            ("host firewall rules replaced", firewall_changed, baseline, {"student"}, True),
            ("privileged temporary process", temp_process, baseline, {"student"}, True),
            ("critical file deleted", missing_file, baseline, {"student"}, True),
        ]
    )

    randomizer = random.Random(seed)
    templates = list(scenarios)
    for index in range(generated):
        name, current, prior, protected, incident = randomizer.choice(templates)
        clone = json.loads(json.dumps(current))
        # Keep large deterministic campaigns inside the authenticated protocol's
        # future-skew boundary; scenario order is carried by the list, not wall time.
        clone["observed_at"] = time.time() + (index % 100) * 0.001
        if randomizer.random() < 0.2:
            clone["collector_errors"] = clone.get("collector_errors", []) + ["synthetic transient gap"]
        scenarios.append((f"generated-{index}-{name}", clone, prior, set(protected), incident))
    return scenarios


def evaluate(model: RiskModel) -> dict[str, Any]:
    details: list[dict[str, Any]] = []
    true_positive = false_positive = true_negative = false_negative = 0
    for name, telemetry, baseline, protected, incident in _telemetry_scenarios():
        alerts = detect(telemetry, baseline, protected, model)
        high_priority = [item for item in alerts if item.severity in {"high", "critical"}]
        detected = bool(high_priority)
        if incident and detected:
            true_positive += 1
        elif incident:
            false_negative += 1
        elif detected:
            false_positive += 1
        else:
            true_negative += 1
        details.append(
            {
                "scenario": name,
                "incident": incident,
                "detected": detected,
                "alerts": [
                    {"kind": item.kind, "severity": item.severity, "confidence": item.confidence}
                    for item in alerts
                ],
            }
        )
    precision = true_positive / max(1, true_positive + false_positive)
    recall = true_positive / max(1, true_positive + false_negative)
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "true_negative": true_negative,
        "false_negative": false_negative,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "details": details[:20],
        "scenario_count": len(details),
    }


def model_accuracy(model: RiskModel, samples: list[tuple[dict[str, float], int]]) -> float:
    correct = sum((model.predict(features) >= 0.5) == bool(label) for features, label in samples)
    return correct / max(1, len(samples))


def run(args: argparse.Namespace) -> None:
    samples = training_samples()
    split = int(len(samples) * 0.8)
    base_model = RiskModel()
    before = model_accuracy(base_model, samples[split:])
    before_scenarios = evaluate(base_model)
    candidate = RiskModel(weights=dict(base_model.weights), bias=base_model.bias)
    candidate.train(samples[:split], epochs=args.epochs)
    candidate_accuracy = model_accuracy(candidate, samples[split:])
    candidate_scenarios = evaluate(candidate)
    accepted = (
        candidate_accuracy >= before - 0.005
        and candidate_scenarios["precision"] >= before_scenarios["precision"]
        and candidate_scenarios["recall"] >= before_scenarios["recall"]
    )
    model = candidate if accepted else base_model
    selected_accuracy = model_accuracy(model, samples[split:])
    model.save(args.model_output)
    report = {
        "mode": "local labeled simulation",
        "training_samples": split,
        "evaluation_samples": len(samples) - split,
        "model_accuracy_before": round(before, 3),
        "model_accuracy_candidate": round(candidate_accuracy, 3),
        "model_accuracy_after": round(selected_accuracy, 3),
        "candidate_accepted": accepted,
        "regression_gate": "retained trusted base model" if not accepted else "accepted candidate",
        "defensive_scenarios": evaluate(model),
        "model_output": str(Path(args.model_output).resolve()),
    }
    if args.json:
        print(json.dumps(report, indent=2))
        return
    print("Sentinel Blue simulated range")
    print(
        f"Model holdout accuracy: {report['model_accuracy_before']:.1%} -> "
        f"candidate {report['model_accuracy_candidate']:.1%} -> selected "
        f"{report['model_accuracy_after']:.1%}"
    )
    print(f"Regression gate: {report['regression_gate']}")
    scenario = report["defensive_scenarios"]
    print(f"High-priority detection precision: {scenario['precision']:.1%}")
    print(f"High-priority detection recall: {scenario['recall']:.1%}")
    for item in scenario["details"]:
        print(f"- {item['scenario']}: {'DETECTED' if item['detected'] else 'clear'}")
    print(f"Model saved to {report['model_output']}")
