"""Deterministic disposable attack campaign for restoration policy behavior."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import random
import tempfile
from pathlib import Path
from unittest.mock import patch

from .actions import ActionExecutor
from .protocol import ProbeResult


CASES = (
    "confirmed-tamper",
    "stale-observation",
    "deleted-file",
    "failed-health-validation",
    "operator-undo",
    "corrupt-restore-blob",
    "corrupt-manifest",
    "interrupted-replacement",
    "failed-config-validation",
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _restore_parameters(
    target: Path,
    approved: str,
    security_descriptor_sha256: str,
    *,
    observed_sha256: str | None = None,
) -> dict[str, object]:
    parameters: dict[str, object] = {
        "path": str(target),
        "baseline_sha256": approved,
    }
    if security_descriptor_sha256:
        parameters["baseline_security_descriptor_sha256"] = (
            security_descriptor_sha256
        )
    if observed_sha256 is not None:
        parameters["observed_sha256"] = observed_sha256
        if security_descriptor_sha256:
            parameters["observed_security_descriptor_sha256"] = (
                security_descriptor_sha256
            )
    return parameters


def restoration_policy_campaign(iterations: int = 120, seed: int = 1212) -> dict[str, object]:
    """Exercise expected allow/refuse/rollback outcomes without touching real services."""
    total = max(len(CASES), min(int(iterations), 5000))
    randomizer = random.Random(seed)
    selected = list(CASES)
    selected.extend(randomizer.choice(CASES) for _ in range(total - len(CASES)))
    counts = {name: 0 for name in CASES}
    failures: list[dict[str, str]] = []

    with tempfile.TemporaryDirectory(prefix="sentinel-blue-restoration-range-") as directory:
        root = Path(directory)
        for index, case in enumerate(selected):
            counts[case] += 1
            scenario = root / str(index)
            scenario.mkdir()
            target = scenario / "protected.conf"
            target.write_text("approved\n", encoding="utf-8")
            approved = _sha256(target)
            executor = ActionExecutor(scenario / "state", allow_restoration=True)
            capture_item = {"path": str(target), "sha256": approved}
            security_descriptor_sha256 = ""
            if os.name == "nt":
                _data, metadata = executor.restore_points._read_target(target)
                security_descriptor_sha256 = (
                    executor.restore_points._metadata_security_descriptor_sha256(
                        metadata
                    )
                )
                if not security_descriptor_sha256:
                    failures.append(
                        {"case": case, "reason": "security metadata capture failed"}
                    )
                    continue
                capture_item["security_descriptor_sha256"] = (
                    security_descriptor_sha256
                )
            captured = executor.execute(
                "capture_restore_point",
                {"files": [capture_item]},
                {},
            )
            if not captured.get("success"):
                failures.append({"case": case, "reason": "restore-point capture failed"})
                continue

            passed = False
            if case == "confirmed-tamper":
                target.write_text("tampered\n", encoding="utf-8")
                result = executor.execute(
                    "restore_integrity",
                    _restore_parameters(
                        target,
                        approved,
                        security_descriptor_sha256,
                        observed_sha256=_sha256(target),
                    ),
                    {},
                )
                passed = bool(result.get("success")) and target.read_text() == "approved\n"
            elif case == "stale-observation":
                target.write_text("newer-change\n", encoding="utf-8")
                result = executor.execute(
                    "restore_integrity",
                    _restore_parameters(
                        target,
                        approved,
                        security_descriptor_sha256,
                        observed_sha256="a" * 64,
                    ),
                    {},
                )
                passed = not result.get("success") and target.read_text() == "newer-change\n"
            elif case == "deleted-file":
                target.unlink()
                result = executor.execute(
                    "restore_integrity",
                    _restore_parameters(
                        target, approved, security_descriptor_sha256
                    ),
                    {},
                )
                passed = bool(result.get("success")) and target.read_text() == "approved\n"
            elif case == "failed-health-validation":
                target.write_text("service-required-change\n", encoding="utf-8")
                unhealthy = ProbeResult("service-monitor-example", "local", False, 1.0, "synthetic failure")
                with patch("sentinel_blue.restoration.run_probes", return_value=[unhealthy]):
                    result = executor.execute(
                        "restore_integrity",
                        {
                            **_restore_parameters(
                                target,
                                approved,
                                security_descriptor_sha256,
                                observed_sha256=_sha256(target),
                            ),
                            "probes": [{"name": "service-monitor-example"}],
                        },
                        {},
                    )
                passed = (
                    not result.get("success")
                    and result.get("rolled_back")
                    and target.read_text() == "service-required-change\n"
                )
            elif case == "operator-undo":
                target.write_text("tampered\n", encoding="utf-8")
                restored = executor.execute(
                    "restore_integrity",
                    _restore_parameters(
                        target,
                        approved,
                        security_descriptor_sha256,
                        observed_sha256=_sha256(target),
                    ),
                    {},
                )
                result = executor.execute(
                    "rollback_integrity", dict(restored.get("pre_state", {})), {}
                )
                passed = bool(result.get("success")) and target.read_text() == "tampered\n"
            elif case == "corrupt-restore-blob":
                blob = executor.restore_points.blobs / approved
                blob.write_text("corrupt", encoding="utf-8")
                target.write_text("tampered\n", encoding="utf-8")
                result = executor.execute(
                    "restore_integrity",
                    _restore_parameters(
                        target, approved, security_descriptor_sha256
                    ),
                    {},
                )
                passed = not result.get("success") and target.read_text() == "tampered\n"
            elif case == "corrupt-manifest":
                executor.restore_points.manifest_path.write_text("{corrupt", encoding="utf-8")
                target.write_text("tampered\n", encoding="utf-8")
                result = executor.execute(
                    "restore_integrity",
                    _restore_parameters(
                        target, approved, security_descriptor_sha256
                    ),
                    {},
                )
                passed = (
                    not result.get("success")
                    and "manifest is corrupt" in str(result.get("message"))
                    and target.read_text() == "tampered\n"
                )
            elif case == "failed-config-validation":
                target.write_text("service-required-change\n", encoding="utf-8")
                validation = {
                    "applicable": True,
                    "available": True,
                    "healthy": False,
                    "validator": "synthetic",
                    "detail": "invalid configuration",
                }
                with patch(
                    "sentinel_blue.restoration.validate_restored_configuration",
                    return_value=validation,
                ):
                    result = executor.execute(
                        "restore_integrity",
                        _restore_parameters(
                            target, approved, security_descriptor_sha256
                        ),
                        {},
                    )
                passed = (
                    not result.get("success")
                    and result.get("rolled_back")
                    and target.read_text() == "service-required-change\n"
                )
            else:
                target.write_text("prechange\n", encoding="utf-8")
                original = executor.restore_points._replace_target
                calls = 0

                def interrupt_once(path, data, metadata):
                    nonlocal calls
                    calls += 1
                    original(path, data, metadata)
                    if calls == 1:
                        raise OSError("synthetic interrupted replacement")

                with patch.object(
                    executor.restore_points,
                    "_replace_target",
                    side_effect=interrupt_once,
                ):
                    result = executor.execute(
                        "restore_integrity",
                        _restore_parameters(
                            target, approved, security_descriptor_sha256
                        ),
                        {},
                    )
                passed = not result.get("success") and target.read_text() == "prechange\n"

            if not passed:
                failures.append({"case": case, "reason": str(result.get("message", "unexpected outcome"))})

    return {
        "mode": "disposable restoration policy attack campaign",
        "scenarios": total,
        "passed_scenarios": total - len(failures),
        "failed_scenarios": len(failures),
        "case_coverage": counts,
        "failures": failures[:20],
        "passed": not failures,
        "real_hosts_modified": False,
        "platform": os.name,
    }


def run(args: argparse.Namespace) -> int:
    """Run the bounded disposable campaign from the public CLI."""
    report = restoration_policy_campaign(max(1, min(args.runs, 5000)))
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("Sentinel Blue restoration policy attack campaign")
        for key, value in report.items():
            print(f"{key}: {value}")
    return 0 if report["passed"] else 1
