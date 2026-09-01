"""Operational, evidence-only controller backup integration.

No function in this module replaces a live database.  Initialization, status,
backup creation, and verification are the only supported operations; restore
remains an explicit offline reconciliation procedure.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import time
from typing import Any
import uuid

from .auth import MAX_CLOCK_SKEW_SECONDS
from .recovery import (
    CONTROLLER_ALLOWED_TABLES,
    CONTROLLER_APPLICATION_ID,
    CONTROLLER_REQUIRED_TABLES,
    CONTROLLER_USER_VERSION,
    CrashAction,
    DATABASE_FILENAME,
    MANIFEST_FILENAME,
    _fsync_directory,
    _require_private_directory,
    advance_backup_anchor,
    build_backup_manifest,
    decide_crash_state,
    initialize_anchor,
    inspect_controller_database,
    load_anchor,
    load_recovery_key,
    make_committed_anchor,
    verify_backup_bundle,
    write_backup_manifest,
)
from .store import Store


MAX_BACKUP_BUNDLES = 10_000


def controller_recovery_status(
    database: str | Path,
    anchor_path: str | Path,
    key: bytes,
) -> dict[str, Any]:
    """Inspect a quiescent live database against its protected anchor."""
    inspection = inspect_controller_database(
        database,
        expected_application_id=CONTROLLER_APPLICATION_ID,
        expected_user_version=CONTROLLER_USER_VERSION,
        required_tables=CONTROLLER_REQUIRED_TABLES,
        allowed_tables=CONTROLLER_ALLOWED_TABLES,
        require_recovery_state=True,
        require_state_hashes=False,
    )
    anchor = load_anchor(anchor_path, key)
    decision = decide_crash_state(
        anchor,
        live_controller_instance_id=str(inspection.controller_instance_id),
        live_recovery_generation=int(inspection.recovery_generation or 0),
        live_database_sha256=inspection.sha256,
        live_backup_sequence=int(inspection.backup_sequence or 0),
    )
    ready = bool(
        anchor["phase"] == "committed" and decision.action is CrashAction.START
    )
    return {
        "ready": ready,
        "action": decision.action.value,
        "reason": decision.reason,
        "controller_instance_id": inspection.controller_instance_id,
        "recovery_generation": inspection.recovery_generation,
        "backup_sequence": inspection.backup_sequence,
        "protected_sequence_floor": anchor.get("backup_sequence_floor"),
        "anchor_phase": anchor["phase"],
        "latest_backup": anchor.get("latest_backup"),
        "database_sha256": inspection.sha256,
    }


def initialize_controller_recovery(
    database: str | Path,
    anchor_path: str | Path,
    key: bytes,
    *,
    enrollment_window: float = 3600.0,
) -> dict[str, Any]:
    """Initialize one exact database and create its protected anchor offline."""
    anchor = Path(anchor_path)
    _require_private_directory(anchor.parent)
    store = Store(database)
    try:
        # Seed durable request replay state while Store still knows whether it
        # created this database.  A genuinely new controller can enroll at
        # once; a legacy database retains the bounded migration fence.
        store.initialize_http_request_replay(
            MAX_CLOCK_SKEW_SECONDS,
            now=time.time(),
        )
        store.initialize_enrollment_deadline(
            enrollment_window,
            time.time(),
        )
        identity = store.initialize_recovery_identity()
    finally:
        store.close()
    if int(identity["backup_sequence"]) != 0:
        raise ValueError(
            "a missing recovery anchor cannot be recreated after backups exist"
        )
    inspection = inspect_controller_database(
        database,
        expected_application_id=CONTROLLER_APPLICATION_ID,
        expected_user_version=CONTROLLER_USER_VERSION,
        required_tables=CONTROLLER_REQUIRED_TABLES,
        allowed_tables=CONTROLLER_ALLOWED_TABLES,
        require_recovery_state=True,
        require_state_hashes=False,
    )
    committed = make_committed_anchor(
        str(inspection.controller_instance_id),
        recovery_generation=int(inspection.recovery_generation or 0),
        backup_sequence_floor=int(inspection.backup_sequence or 0),
    )
    initialize_anchor(anchor, key, committed)
    return controller_recovery_status(database, anchor, key)


def create_controller_backup(
    store: Store,
    backup_root: str | Path,
    anchor_path: str | Path,
    key: bytes,
) -> dict[str, Any]:
    """Create, authenticate, verify, publish, and anchor one backup bundle."""
    root = Path(backup_root)
    _require_private_directory(root)
    anchor = load_anchor(anchor_path, key)
    identity = store.recovery_identity()
    if (
        anchor["phase"] != "committed"
        or anchor["controller_instance_id"]
        != identity["controller_instance_id"]
        or int(anchor["recovery_generation"])
        != int(identity["recovery_generation"])
        or int(identity["backup_sequence"])
        < int(anchor["backup_sequence_floor"])
    ):
        raise ValueError(
            "live controller recovery state does not match its committed anchor"
        )
    identity = store.advance_recovery_backup_sequence()
    sequence = int(identity["backup_sequence"])
    suffix = uuid.uuid4().hex
    stamp = time.strftime("%Y%m%d-%H%M%S", time.gmtime())
    pending = root / f".sentinel-blue-{stamp}-b{sequence}-{suffix}.pending"
    final = root / f"sentinel-blue-{stamp}-b{sequence}-{suffix}.sbbackup"
    pending.mkdir(mode=0o700)
    if os.name == "posix":
        pending.chmod(0o700)
    database_copy = store.backup(pending / DATABASE_FILENAME)
    if os.name == "posix":
        database_copy.chmod(0o600)
    inspection = inspect_controller_database(
        database_copy,
        expected_application_id=CONTROLLER_APPLICATION_ID,
        expected_user_version=CONTROLLER_USER_VERSION,
        required_tables=CONTROLLER_REQUIRED_TABLES,
        allowed_tables=CONTROLLER_ALLOWED_TABLES,
        require_recovery_state=True,
        require_state_hashes=True,
    )
    binding = inspection.active_release_binding
    if binding is None:
        raise ValueError("controller backup lacks an active release binding")
    record = build_backup_manifest(
        database_copy,
        key,
        release_version=str(binding["agent_version"]),
        release_sha256=str(binding["release_sha256"]),
        profile_id=str(binding["profile_id"]),
        profile_fingerprint=str(binding["profile_fingerprint"]),
        expected_application_id=CONTROLLER_APPLICATION_ID,
        expected_user_version=CONTROLLER_USER_VERSION,
        required_tables=CONTROLLER_REQUIRED_TABLES,
        allowed_tables=CONTROLLER_ALLOWED_TABLES,
    )
    write_backup_manifest(pending / MANIFEST_FILENAME, record, key)
    verify_backup_bundle(
        pending,
        key,
        expected_application_id=CONTROLLER_APPLICATION_ID,
        expected_user_version=CONTROLLER_USER_VERSION,
        required_tables=CONTROLLER_REQUIRED_TABLES,
        allowed_tables=CONTROLLER_ALLOWED_TABLES,
        expected_controller_instance_id=str(identity["controller_instance_id"]),
        expected_release_sha256=str(binding["release_sha256"]),
        expected_profile_fingerprint=str(binding["profile_fingerprint"]),
    )
    os.rename(pending, final)
    _fsync_directory(root)
    verified = verify_backup_bundle(
        final,
        key,
        expected_application_id=CONTROLLER_APPLICATION_ID,
        expected_user_version=CONTROLLER_USER_VERSION,
        required_tables=CONTROLLER_REQUIRED_TABLES,
        allowed_tables=CONTROLLER_ALLOWED_TABLES,
        expected_controller_instance_id=str(identity["controller_instance_id"]),
        expected_release_sha256=str(binding["release_sha256"]),
        expected_profile_fingerprint=str(binding["profile_fingerprint"]),
    )
    advanced = advance_backup_anchor(anchor_path, key, anchor, verified)
    return {
        "created": True,
        "bundle": str(final),
        "backup_id": verified.manifest["backup_id"],
        "backup_sequence": sequence,
        "database_sha256": verified.inspection.sha256,
        "manifest_sha256": verified.manifest_sha256,
        "protected_sequence_floor": advanced["backup_sequence_floor"],
    }


def verify_controller_backup(
    bundle: str | Path,
    anchor_path: str | Path,
    key: bytes,
) -> dict[str, Any]:
    anchor = load_anchor(anchor_path, key)
    verified = verify_backup_bundle(
        bundle,
        key,
        expected_application_id=CONTROLLER_APPLICATION_ID,
        expected_user_version=CONTROLLER_USER_VERSION,
        required_tables=CONTROLLER_REQUIRED_TABLES,
        allowed_tables=CONTROLLER_ALLOWED_TABLES,
        anchor=anchor,
        expected_controller_instance_id=str(anchor["controller_instance_id"]),
    )
    return {
        "verified": True,
        "backup_id": verified.manifest["backup_id"],
        "backup_sequence": verified.manifest["backup_sequence"],
        "recovery_generation": verified.manifest["recovery_generation"],
        "anchor_binding": verified.anchor_binding,
        "database_sha256": verified.inspection.sha256,
        "manifest_sha256": verified.manifest_sha256,
        "requires_offline_reconciliation": verified.requires_reconciliation,
    }


def prune_recovery_backups(
    backup_root: str | Path,
    anchor_path: str | Path,
    key: bytes,
    *,
    keep: int,
) -> list[str]:
    """Remove only authenticated historical bundles, never the anchored latest."""
    root = Path(backup_root)
    _require_private_directory(root)
    limit = max(2, min(int(keep), MAX_BACKUP_BUNDLES))
    anchor = load_anchor(anchor_path, key)
    latest = anchor.get("latest_backup") or {}
    protected_id = str(latest.get("backup_id", ""))
    candidates: list[tuple[int, str, Path]] = []
    with os.scandir(root) as iterator:
        entries = []
        for index, entry in enumerate(iterator):
            if index >= MAX_BACKUP_BUNDLES:
                raise OverflowError("recovery backup directory entry limit exceeded")
            entries.append(entry)
    for entry in entries:
        if (
            not entry.name.startswith("sentinel-blue-")
            or not entry.name.endswith(".sbbackup")
            or entry.is_symlink()
            or not entry.is_dir(follow_symlinks=False)
        ):
            continue
        try:
            verified = verify_backup_bundle(
                Path(entry.path),
                key,
                expected_application_id=CONTROLLER_APPLICATION_ID,
                expected_user_version=CONTROLLER_USER_VERSION,
                required_tables=CONTROLLER_REQUIRED_TABLES,
                allowed_tables=CONTROLLER_ALLOWED_TABLES,
                anchor=anchor,
                expected_controller_instance_id=str(
                    anchor["controller_instance_id"]
                ),
            )
        except Exception:
            continue
        candidates.append(
            (
                int(verified.manifest["backup_sequence"]),
                str(verified.manifest["backup_id"]),
                Path(entry.path),
            )
        )
    candidates.sort(reverse=True)
    keep_paths = {path for _sequence, _backup_id, path in candidates[:limit]}
    removed: list[str] = []
    for _sequence, backup_id, path in candidates[limit:]:
        if backup_id == protected_id or path in keep_paths:
            continue
        for name in (DATABASE_FILENAME, MANIFEST_FILENAME):
            child = path / name
            if child.is_symlink() or not child.is_file():
                raise ValueError("authenticated backup changed before pruning")
            child.unlink()
        path.rmdir()
        removed.append(path.name)
    if removed:
        _fsync_directory(root)
    return removed


def run(args: Any) -> int:
    """CLI entry point for explicit offline recovery operations."""
    key = load_recovery_key(args.recovery_key_file)
    if args.command == "recovery-verify":
        result = verify_controller_backup(
            args.bundle, args.recovery_anchor, key
        )
    else:
        from .controller import ControllerDatabaseLock

        with ControllerDatabaseLock(args.database):
            if args.command == "recovery-init":
                result = initialize_controller_recovery(
                    args.database,
                    args.recovery_anchor,
                    key,
                    enrollment_window=args.enrollment_window,
                )
            elif args.command == "recovery-status":
                result = controller_recovery_status(
                    args.database, args.recovery_anchor, key
                )
            elif args.command == "recovery-backup":
                store = Store(args.database)
                try:
                    result = create_controller_backup(
                        store,
                        args.output_directory,
                        args.recovery_anchor,
                        key,
                    )
                finally:
                    store.close()
            else:  # pragma: no cover - parser owns the command set
                raise ValueError("unsupported recovery command")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ready", result.get("verified", True)) else 1
