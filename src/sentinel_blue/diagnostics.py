"""Readiness diagnostics and consistent controller database backups."""

from __future__ import annotations

import argparse
import importlib.resources
import json
import os
import platform
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from .store import Store


def doctor(state_dir: str | Path, database: str | Path | None = None) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def add(name: str, passed: bool, detail: str, required: bool = False) -> None:
        checks.append({"name": name, "passed": passed, "detail": detail, "required": required})

    add(
        "python-version",
        sys.version_info >= (3, 11),
        platform.python_version(),
        required=True,
    )
    state = Path(state_dir)
    try:
        state.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix="sentinel-doctor-", dir=state, delete=True):
            pass
        add("state-directory", True, str(state.resolve()), required=True)
    except OSError as exc:
        add("state-directory", False, str(exc), required=True)

    for command, required in (
        ("python3", True),
        ("ssh", False),
        ("scp", False),
        ("systemctl", False),
        ("ip", False),
        ("ss", False),
        ("pwsh", False),
        ("powershell.exe", False),
    ):
        path = shutil.which(command)
        add(f"command:{command}", bool(path), path or "not installed", required=required)

    try:
        package = importlib.resources.files("sentinel_blue")
        web = package.joinpath("web/index.html").read_text(encoding="utf-8")
        models = [item.name for item in package.joinpath("models").iterdir() if item.name.endswith(".json")]
        add("bundled-dashboard", "SENTINEL BLUE" in web, "web/index.html", required=True)
        add("bundled-model", bool(models), ", ".join(models), required=True)
    except (OSError, FileNotFoundError) as exc:
        add("package-resources", False, str(exc), required=True)

    if database:
        db_path = Path(database)
        if not db_path.exists():
            add("database", False, f"not found: {db_path}", required=True)
        else:
            store = Store(db_path)
            try:
                integrity = store.integrity_check()
                add("database-integrity", integrity == "ok", integrity, required=True)
            finally:
                store.close()

    required_failures = [item for item in checks if item["required"] and not item["passed"]]
    optional_failures = [item for item in checks if not item["required"] and not item["passed"]]
    return {
        "mode": "local readiness diagnostics",
        "platform": f"{platform.system()} {platform.release()}",
        "checks": checks,
        "ready": not required_failures,
        "required_failures": len(required_failures),
        "optional_gaps": len(optional_failures),
        "containment_default": "dry-run",
    }


def run(args: argparse.Namespace) -> int:
    if args.command == "backup":
        store = Store(args.database)
        try:
            destination = store.backup(args.output)
            report = {
                "database": str(Path(args.database).resolve()),
                "backup": str(destination.resolve()),
                "integrity": store.integrity_check(),
                "size_bytes": destination.stat().st_size,
            }
        finally:
            store.close()
        print(json.dumps(report, indent=2))
        return 0
    report = doctor(args.state_dir, args.database)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Sentinel Blue doctor: {'READY' if report['ready'] else 'NOT READY'}")
        for item in report["checks"]:
            marker = "PASS" if item["passed"] else "WARN" if not item["required"] else "FAIL"
            print(f"[{marker}] {item['name']}: {item['detail']}")
    return 0 if report["ready"] else 1
