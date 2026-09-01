"""Disposable end-to-end controller/decision/action range campaign."""

from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .actions import ActionExecutor
from .adversarial_lab import protocol_fuzz
from .controller import ControllerApp
from .risk import RiskModel
from .simulator import _telemetry_scenarios
from .store import Store


def _materialize_disposable_integrity(
    root: Path,
    baseline: dict[str, Any],
    current: dict[str, Any] | None = None,
) -> list[tuple[Path, bytes, dict[str, Any]]]:
    """Back integrity telemetry with real files while preserving its semantics.

    The simulator's well-known placeholder paths and digests are useful to the
    detector, but they cannot prove that a restore point captured any bytes.
    Replace those placeholders with private per-scenario files.  Changed
    current observations are prepared as deferred writes so callers can first
    capture the exact approved baseline.
    """

    root.mkdir(parents=True, exist_ok=True)
    baseline_rows = baseline.get("integrity", [])
    if not isinstance(baseline_rows, list):
        raise ValueError("disposable baseline integrity must be an array")
    original_rows = json.loads(json.dumps(baseline_rows))
    mapped: dict[str, tuple[dict[str, Any], dict[str, Any]]] = {}
    materialized: list[dict[str, Any]] = []
    for index, original in enumerate(original_rows):
        if not isinstance(original, dict) or not isinstance(original.get("path"), str):
            raise ValueError("disposable baseline integrity row is invalid")
        target = root / f"protected-{index:03d}.conf"
        content = (
            f"sentinel-blue disposable approved state {index}\n"
        ).encode("utf-8")
        target.write_bytes(content)
        row = {
            **original,
            "path": str(target),
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
            "modified_at": target.stat().st_mtime,
        }
        materialized.append(row)
        mapped[str(original["path"])] = (original, row)
    baseline["integrity"] = materialized

    deferred: list[tuple[Path, bytes, dict[str, Any]]] = []
    if current is None:
        return deferred
    current_rows = current.get("integrity", [])
    if not isinstance(current_rows, list):
        raise ValueError("disposable current integrity must be an array")
    updated_current: list[dict[str, Any]] = []
    for index, current_row in enumerate(json.loads(json.dumps(current_rows))):
        if not isinstance(current_row, dict):
            raise ValueError("disposable current integrity row is invalid")
        original_path = current_row.get("path")
        if not isinstance(original_path, str) or original_path not in mapped:
            raise ValueError("current integrity is outside the disposable baseline fixture")
        original_baseline, approved_row = mapped[original_path]
        if current_row.get("sha256") == original_baseline.get("sha256"):
            updated_current.append(dict(approved_row))
            continue
        target = Path(str(approved_row["path"]))
        content = (
            f"sentinel-blue disposable changed state {index}\n"
        ).encode("utf-8")
        changed_row = {
            **current_row,
            "path": str(target),
            "sha256": hashlib.sha256(content).hexdigest(),
            "size": len(content),
        }
        updated_current.append(changed_row)
        deferred.append((target, content, changed_row))
    current["integrity"] = updated_current
    return deferred


def _apply_disposable_integrity_changes(
    changes: list[tuple[Path, bytes, dict[str, Any]]],
) -> None:
    for path, content, telemetry_row in changes:
        path.write_bytes(content)
        telemetry_row["modified_at"] = path.stat().st_mtime


def _complete_disposable_baseline_promotion(
    app: ControllerApp,
    store: Store,
    executor: ActionExecutor,
    agent_id: str,
    telemetry: dict[str, Any],
) -> dict[str, int]:
    """Promote through the real controller/action/result transaction."""

    approval = app.approve_baseline(agent_id)
    if not approval:
        raise RuntimeError("disposable baseline approval did not start")
    if approval.get("approved") is True:
        if telemetry.get("integrity"):
            raise RuntimeError("integrity-bearing baseline bypassed restore-point capture")
        return {"actions": 0, "receipts": 0}
    action_id = str(approval.get("restore_point_action_id", ""))
    actions = [
        action
        for action in app.pending_actions_for_agent(agent_id)
        if action.action_id == action_id
    ]
    if len(actions) != 1 or actions[0].action_type != "capture_restore_point":
        raise RuntimeError("exact baseline capture action was not dispatched")
    action = actions[0]
    result = executor.execute(action.action_type, action.parameters, telemetry)
    if result.get("success") is not True or result.get("dry_run") is not False:
        detail = str(result.get("message", "capture returned no diagnostic"))[:500]
        raise RuntimeError(
            "baseline capture was not a successful non-dry-run operation: " + detail
        )
    receipts = result.get("capture_receipts")
    if not isinstance(receipts, list) or len(receipts) != len(action.parameters["files"]):
        raise RuntimeError("baseline capture did not return an exact receipt set")
    completion = app.complete_action(
        {**result, "action_id": action.action_id},
        agent_id,
    )
    if completion != "new" or store.baseline_status(agent_id) != "approved":
        raise RuntimeError("baseline capture result did not atomically promote the baseline")
    return {"actions": 1, "receipts": len(receipts)}


def campaign(runs: int = 200) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="sentinel-blue-range-") as directory:
        store = Store(Path(directory) / "range.db")
        app = ControllerApp(
            store,
            "r" * 32,
            RiskModel(),
            ["192.0.2.0/24"],
            operator_token="o" * 32,
        )
        true_positive = false_positive = true_negative = false_negative = 0
        actions_queued = actions_completed = 0
        baseline_capture_actions = baseline_capture_receipts = 0
        scenarios = _telemetry_scenarios(generated=max(0, runs - 10))[:runs]
        try:
            for index, (name, current, baseline, protected, incident) in enumerate(scenarios):
                agent_id = f"range-agent-{index}"
                boot_id = f"disposable-range-boot-{index}"
                # A deployed agent owns one private state tree.  Keeping every
                # synthetic host in a shared restore-point manifest both
                # misrepresents that boundary and turns a long campaign into
                # quadratic manifest rewrites that eventually hit the bounded
                # state limit.
                executor = ActionExecutor(
                    Path(directory) / "agent-state" / agent_id,
                    allow_containment=False,
                )
                base_payload = {
                    "agent_id": agent_id,
                    "hostname": agent_id,
                    "platform": "Linux disposable range",
                    "observed_at": time.time() + index * 0.001,
                    "boot_id": boot_id,
                    "sequence": 0,
                    "interfaces": [],
                    "neighbors": [],
                    "collector_errors": [],
                    **json.loads(json.dumps(baseline)),
                }
                current_payload = json.loads(json.dumps(current))
                current_payload.update(
                    {
                        "agent_id": agent_id,
                        "hostname": agent_id,
                        "platform": "Linux disposable range",
                        "observed_at": time.time() + index * 0.001,
                        "boot_id": boot_id,
                        "sequence": 1,
                    }
                )
                changes = _materialize_disposable_integrity(
                    Path(directory) / "fixtures" / f"scenario-{index}",
                    base_payload,
                    current_payload,
                )
                for account in protected:
                    store.protect_account(agent_id, account, "range-protected", "range-ground-truth")
                app.ingest(base_payload)
                capture = _complete_disposable_baseline_promotion(
                    app,
                    store,
                    executor,
                    agent_id,
                    base_payload,
                )
                baseline_capture_actions += capture["actions"]
                baseline_capture_receipts += capture["receipts"]
                _apply_disposable_integrity_changes(changes)
                app.ingest(current_payload)
                open_alerts = [
                    item
                    for item in store.dashboard()["alerts"]
                    if item["agent_id"] == agent_id
                    and item["status"] == "open"
                    and item["severity"] in {"high", "critical"}
                ]
                detected = bool(open_alerts)
                if incident and detected:
                    true_positive += 1
                elif incident:
                    false_negative += 1
                elif detected:
                    false_positive += 1
                else:
                    true_negative += 1
                for alert in open_alerts:
                    decision = "approve" if incident else "reject"
                    result = app.decision(str(alert["alert_id"]), decision)
                    if result and result.get("status") == "queued":
                        actions_queued += 1
                for action in store.pending_actions(agent_id):
                    result = executor.execute(action.action_type, action.parameters, current_payload)
                    if app.complete_action({**result, "action_id": action.action_id}):
                        actions_completed += 1
            precision = true_positive / max(1, true_positive + false_positive)
            recall = true_positive / max(1, true_positive + false_negative)
            feedback = store.feedback_samples()
            return {
                "mode": "disposable end-to-end simulated range",
                "scenarios": len(scenarios),
                "true_positive": true_positive,
                "false_positive": false_positive,
                "true_negative": true_negative,
                "false_negative": false_negative,
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "actions_queued": actions_queued,
                "actions_completed": actions_completed,
                "baseline_capture_actions": baseline_capture_actions,
                "baseline_capture_receipts": baseline_capture_receipts,
                "baseline_capture_mode": "non-dry-run disposable files",
                "agent_state_isolation": "per-agent",
                "feedback_records": len(feedback),
                "containment_mode": "dry-run",
                "protocol_fuzz": protocol_fuzz(min(5000, max(300, runs * 3))),
            }
        finally:
            store.close()


def run(args: argparse.Namespace) -> int:
    report = campaign(max(1, min(args.runs, 5000)))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("Sentinel Blue end-to-end range")
        for key, value in report.items():
            print(f"{key}: {value}")
    passed = (
        report["false_negative"] == 0
        and report["false_positive"] == 0
        and report["actions_queued"] == report["actions_completed"]
        and report["protocol_fuzz"]["passed"]
    )
    return 0 if passed else 1
