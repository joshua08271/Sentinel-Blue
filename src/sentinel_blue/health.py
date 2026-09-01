"""Low-cost local health checks for the long-running host agent."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import sys
from pathlib import Path
from typing import Any


SHA256 = re.compile(r"^[0-9a-f]{64}$")
MINIMUM_FREE_BYTES = 16 * 1024 * 1024


def _digest(path: Path) -> str:
    value = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("runtime is not a regular file")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                value.update(chunk)
    finally:
        os.close(descriptor)
    return value.hexdigest()


def assess_agent_health(
    state_dir: str | Path,
    expected_package_sha256: str | None = None,
    runtime_path: str | Path | None = None,
) -> dict[str, Any]:
    """Return bounded self-health evidence and whether remote actions are safe."""
    errors: list[str] = []
    critical: list[str] = []
    root = Path(state_dir)
    try:
        info = root.stat()
        if not root.is_dir() or root.is_symlink():
            critical.append("self-health: state directory is unavailable or is a symbolic link")
        elif os.name == "posix" and info.st_mode & 0o077:
            critical.append("self-health: state directory permissions are broader than 0700")
        elif os.name == "posix" and info.st_uid != os.geteuid():
            critical.append("self-health: state directory is not owned by the agent identity")
        free = shutil.disk_usage(root).free
        if free < MINIMUM_FREE_BYTES:
            critical.append(f"self-health: state volume has only {free} free bytes")
        if os.name == "posix":
            volume = os.statvfs(root)
            if volume.f_favail < 128:
                critical.append(
                    f"self-health: state volume has only {volume.f_favail} free file entries"
                )
        for name in ("identity.json", "sequence.json", "action-journal.json"):
            child = root / name
            if not child.exists() and not child.is_symlink():
                continue
            if child.is_symlink() or not child.is_file():
                critical.append(f"self-health: {name} is not a regular non-symlink file")
            elif os.name == "posix" and child.stat().st_mode & 0o077:
                critical.append(f"self-health: {name} permissions are broader than 0600")
    except OSError as exc:
        critical.append(f"self-health: state directory check failed: {exc}")

    observed_digest = None
    if expected_package_sha256:
        expected = expected_package_sha256.casefold()
        if not SHA256.fullmatch(expected):
            critical.append("self-health: expected runtime digest is invalid")
        else:
            runtime = Path(runtime_path if runtime_path is not None else sys.argv[0])
            try:
                if runtime.is_symlink() or not runtime.is_file():
                    raise OSError("runtime is unavailable or is a symbolic link")
                if os.name == "posix" and runtime.stat().st_mode & 0o022:
                    critical.append("self-health: runtime package is writable by group or other users")
                observed_digest = _digest(runtime)
                if observed_digest != expected:
                    critical.append("self-health: runtime package digest mismatch")
            except OSError as exc:
                critical.append(f"self-health: runtime package check failed: {exc}")

    return {
        "healthy": not errors and not critical,
        "action_safe": not critical,
        "errors": [*critical, *errors],
        "critical_errors": critical,
        "runtime_sha256": observed_digest,
    }
