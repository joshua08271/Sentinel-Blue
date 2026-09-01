"""Authenticated, fail-closed controller backup and recovery primitives.

This module deliberately does not replace the live controller database or
preserve any operational authority.  It provides the independently testable
substrate for an offline restore workflow:

* domain-separated authenticated manifests and recovery anchors;
* private, bounded, non-symlink file handling and atomic anchor transitions;
* immutable/read-only SQLite inspection; and
* deterministic decisions after a crash during an anchor transition.

The controller and Store integrations are intentionally separate.  A signed
manifest proves authenticity, not freshness; callers must compare the database
generation with a protected anchor that is not part of the backup bundle.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import sqlite3
import stat
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from .json_codec import canonical_json_bytes, strict_json_loads


MANIFEST_FORMAT = "sentinel-blue-controller-backup"
ANCHOR_FORMAT = "sentinel-blue-recovery-anchor"
LEGACY_RECOVERY_SCHEMA = 1
RECOVERY_SCHEMA = 2
SIGNATURE_ALGORITHM = "hmac-sha256-v1"

# These constants describe the first controller schema that can participate in
# authenticated recovery.  Store/controller integration must set the pragmas
# and recovery identity explicitly before using these defaults; recovery.py
# must never infer them from a manifest supplied by the backup itself.
CONTROLLER_APPLICATION_ID = 0x53424C55  # "SBLU"
CONTROLLER_USER_VERSION = 8
CONTROLLER_REQUIRED_TABLES = frozenset(
    {
        "actions",
        "agent_reenrollment",
        "agents",
        "alert_lineage",
        "alert_occurrences",
        "alerts",
        "audit_log",
        "baseline_promotions",
        "baselines",
        "change_grants",
        "controller_state",
        "enrollment_tickets",
        "external_events",
        "http_request_replay",
        "json_quarantine",
        "json_quarantine_control",
        "learning_feedback",
        "learning_labels",
        "operator_request_replay",
        "privileged_authorizations",
        "protected_accounts",
        "telemetry_boots",
        "telemetry_observations",
        "telemetry_processing",
    }
)
CONTROLLER_ALLOWED_TABLES = CONTROLLER_REQUIRED_TABLES
CONTROLLER_TRIGGER_CONTRACTS = {
    "trg_alert_lineage_creation_immutable": (
        "create trigger trg_alert_lineage_creation_immutable before update of "
        "creation_occurrence_id on alert_lineage when "
        "new.creation_occurrence_id!=old.creation_occurrence_id begin select "
        "raise(abort, 'alert creation occurrence is immutable'); end"
    ),
    "trg_alert_occurrences_immutable": (
        "create trigger trg_alert_occurrences_immutable before update on "
        "alert_occurrences begin select raise(abort, 'alert occurrences are "
        "immutable'); end"
    ),
    "trg_learning_labels_immutable": (
        "create trigger trg_learning_labels_immutable before update on "
        "learning_labels begin select raise(abort, 'learning labels are "
        "immutable'); end"
    ),
    "trg_telemetry_observations_immutable": (
        "create trigger trg_telemetry_observations_immutable before update on "
        "telemetry_observations begin select raise(abort, 'telemetry "
        "observations are immutable'); end"
    ),
}

MAX_MANIFEST_BYTES = 64 * 1024
MAX_ANCHOR_BYTES = 16 * 1024
MAX_RECOVERY_KEY_BYTES = 4096
MIN_RECOVERY_KEY_BYTES = 32
DEFAULT_MAX_DATABASE_BYTES = 16 * 1024 * 1024 * 1024
MAX_SCHEMA_OBJECTS = 512
MAX_SCHEMA_SQL_CHARS = 1_000_000
MAX_STATE_VALUE_BYTES = 64 * 1024
MAX_INT64 = 2**63 - 1

DATABASE_FILENAME = "controller.db"
MANIFEST_FILENAME = "manifest.json"
STATE_HASH_KEYS = frozenset(
    {"active_release_binding_sha256", "governance_sha256"}
)
RECOVERY_STATE_KEYS = frozenset(
    {
        "controller_instance_id",
        "recovery_generation",
        "backup_sequence",
        "active_release_binding",
        "governance",
    }
)

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PROFILE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_VERSION = re.compile(r"^[A-Za-z0-9_.+\-]{1,128}$")
_DECIMAL = re.compile(r"^(?:0|[1-9][0-9]*)$")
_AUTONOMY_MODES = frozenset(
    {
        "observe",
        "interactive",
        "approval-based",
        "guarded-autonomous",
        "range-autonomous",
    }
)
_PURPOSE_DOMAINS = {
    "manifest": b"sentinel-blue-backup-manifest-v1\x00",
    "anchor": b"sentinel-blue-recovery-anchor-v1\x00",
}


class RecoveryError(ValueError):
    """Base class for recovery validation failures."""


class RecoveryAuthenticationError(RecoveryError):
    """An authenticated recovery document did not verify."""


class RecoveryPathError(RecoveryError):
    """A recovery path, file type, ownership, or permission was unsafe."""


class RecoverySemanticError(RecoveryError):
    """A structurally valid SQLite file failed application-safe inspection."""


class AnchorConflictError(RecoveryError):
    """The protected anchor changed instead of matching the expected state."""


class CrashAction(str, Enum):
    """Only safe actions after inspecting a live DB and protected anchor."""

    START = "start"
    ABORT_PENDING = "abort-pending"
    COMMIT_PENDING = "commit-pending"
    BLOCK = "block"


@dataclass(frozen=True, slots=True)
class CrashDecision:
    action: CrashAction
    reason: str


@dataclass(frozen=True, slots=True)
class DatabaseInspection:
    path: Path
    sha256: str
    size_bytes: int
    application_id: int
    user_version: int
    tables: tuple[str, ...]
    indexes: tuple[str, ...]
    state_hashes: dict[str, str]
    active_release_binding: dict[str, Any] | None
    governance: dict[str, Any] | None
    controller_instance_id: str | None
    recovery_generation: int | None
    backup_sequence: int | None


@dataclass(frozen=True, slots=True)
class VerifiedBackup:
    bundle: Path
    database: Path
    manifest: dict[str, Any]
    inspection: DatabaseInspection
    manifest_sha256: str
    anchor_binding: str = "not-checked"
    requires_reconciliation: bool = True


@contextmanager
def open_verified_database(
    backup: VerifiedBackup,
    *,
    maximum_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
) -> Iterator[int]:
    """Open the authenticated database for a same-descriptor staging copy.

    Restore integration must copy from the yielded descriptor, not reopen
    ``backup.database`` by name.  The signed hash and stable identity are checked
    before and after use, closing the verification-to-copy rename window.
    """
    if not isinstance(backup, VerifiedBackup):
        raise TypeError("backup must be a VerifiedBackup")
    descriptor, before = _open_regular_file(
        backup.database, maximum=maximum_bytes, private=True
    )
    try:
        digest, size = _hash_descriptor(descriptor, maximum=maximum_bytes)
        expected = backup.manifest.get("database", {})
        if (
            size != backup.inspection.size_bytes
            or size != expected.get("size_bytes")
            or not hmac.compare_digest(digest, backup.inspection.sha256)
            or not hmac.compare_digest(digest, str(expected.get("sha256", "")))
        ):
            raise RecoveryAuthenticationError(
                "verified backup database changed before staging"
            )
        os.lseek(descriptor, 0, os.SEEK_SET)
        yield descriptor
        after_descriptor = os.fstat(descriptor)
        after_digest, after_size = _hash_descriptor(
            descriptor, maximum=maximum_bytes
        )
        try:
            after_path = os.lstat(backup.database)
        except OSError as exc:
            raise RecoveryPathError(
                "verified backup database changed during staging"
            ) from exc
        if (
            _file_identity(before) != _file_identity(after_descriptor)
            or _file_identity(before) != _file_identity(after_path)
            or after_size != size
            or not hmac.compare_digest(after_digest, digest)
        ):
            raise RecoveryPathError(
                "verified backup database changed during staging"
            )
    finally:
        os.close(descriptor)


def _require_exact_keys(value: Any, expected: set[str] | frozenset[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != set(expected):
        raise RecoveryError(f"{label} must contain exactly: {', '.join(sorted(expected))}")
    return value


def _require_int(value: Any, label: str, minimum: int = 0, maximum: int = MAX_INT64) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise RecoveryError(f"{label} must be an integer from {minimum} to {maximum}")
    return value


def _require_text(value: Any, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise RecoveryError(f"{label} must be a non-empty bounded string")
    if any(ord(character) < 32 for character in value):
        raise RecoveryError(f"{label} contains control characters")
    try:
        value.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise RecoveryError(f"{label} contains invalid Unicode") from exc
    return value


def _require_digest(value: Any, label: str, *, empty: bool = False) -> str:
    if empty and value == "":
        return ""
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise RecoveryError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _require_uuid(value: Any, label: str) -> str:
    if not isinstance(value, str):
        raise RecoveryError(f"{label} must be a canonical UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise RecoveryError(f"{label} must be a canonical UUID") from exc
    if str(parsed) != value:
        raise RecoveryError(f"{label} must be a canonical lowercase UUID")
    return value


def _validate_key(key: bytes | bytearray | memoryview) -> bytes:
    if not isinstance(key, (bytes, bytearray, memoryview)):
        raise RecoveryError("the recovery key must be bytes")
    result = bytes(key)
    if not MIN_RECOVERY_KEY_BYTES <= len(result) <= MAX_RECOVERY_KEY_BYTES:
        raise RecoveryError(
            f"the recovery key must be {MIN_RECOVERY_KEY_BYTES} to "
            f"{MAX_RECOVERY_KEY_BYTES} bytes"
        )
    return result


def recovery_key_id(key: bytes | bytearray | memoryview) -> str:
    root = _validate_key(key)
    return hashlib.sha256(b"sentinel-blue-recovery-key-id-v1\x00" + root).hexdigest()


def _purpose_key(key: bytes, purpose: str) -> bytes:
    if purpose not in _PURPOSE_DOMAINS:
        raise RecoveryError("unsupported recovery signature purpose")
    return hmac.new(
        key,
        b"sentinel-blue-recovery-kdf-v1\x00" + purpose.encode("ascii"),
        hashlib.sha256,
    ).digest()


def sign_payload(payload: dict[str, Any], key: bytes, *, purpose: str) -> dict[str, Any]:
    """Return one exact signed-document envelope for a bounded JSON object."""
    root = _validate_key(key)
    if not isinstance(payload, dict):
        raise RecoveryError("signed recovery payload must be an object")
    encoded = canonical_json_bytes(payload, max_bytes=MAX_MANIFEST_BYTES)
    digest = hmac.new(
        _purpose_key(root, purpose),
        _PURPOSE_DOMAINS[purpose] + encoded,
        hashlib.sha256,
    ).hexdigest()
    return {
        "signed": payload,
        "signature": {
            "algorithm": SIGNATURE_ALGORITHM,
            "key_id": recovery_key_id(root),
            "value": digest,
        },
    }


def verify_signed_payload(record: Any, key: bytes, *, purpose: str) -> dict[str, Any]:
    """Authenticate an already strictly decoded signed-document envelope."""
    root = _validate_key(key)
    try:
        envelope = _require_exact_keys(
            record, {"signed", "signature"}, "signed document"
        )
        payload = envelope["signed"]
        if not isinstance(payload, dict):
            raise RecoveryError("signed recovery payload is not an object")
        signature = _require_exact_keys(
            envelope["signature"], {"algorithm", "key_id", "value"}, "signature"
        )
        if signature["algorithm"] != SIGNATURE_ALGORITHM:
            raise RecoveryError("unsupported recovery signature algorithm")
        expected_key_id = recovery_key_id(root)
        if not isinstance(signature["key_id"], str) or not hmac.compare_digest(
            signature["key_id"], expected_key_id
        ):
            raise RecoveryError("recovery signature key identifier does not match")
        supplied = _require_digest(signature["value"], "signature.value")
        encoded = canonical_json_bytes(payload, max_bytes=MAX_MANIFEST_BYTES)
    except RecoveryAuthenticationError:
        raise
    except (RecoveryError, ValueError) as exc:
        raise RecoveryAuthenticationError(str(exc)) from exc
    expected = hmac.new(
        _purpose_key(root, purpose),
        _PURPOSE_DOMAINS[purpose] + encoded,
        hashlib.sha256,
    ).hexdigest()
    if not hmac.compare_digest(supplied, expected):
        raise RecoveryAuthenticationError("recovery signature is invalid")
    return dict(payload)


def _reject_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(path))
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current = current / component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(info.st_mode):
            raise RecoveryPathError(f"recovery path contains a symbolic link: {current}")


def _require_private_mode(info: os.stat_result, label: str) -> None:
    if os.name != "posix":
        return
    if info.st_uid != os.geteuid():
        raise RecoveryPathError(f"{label} is owned by another identity")
    if stat.S_IMODE(info.st_mode) & 0o077:
        raise RecoveryPathError(f"{label} permits group or other access")


def _require_private_directory(path: Path) -> os.stat_result:
    _reject_symlink_components(path)
    try:
        info = os.lstat(path)
    except FileNotFoundError as exc:
        raise RecoveryPathError(f"private recovery directory does not exist: {path}") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise RecoveryPathError(f"private recovery path is not a directory: {path}")
    _require_private_mode(info, "recovery directory")
    return info


def _open_regular_file(
    path: Path,
    *,
    maximum: int,
    private: bool,
) -> tuple[int, os.stat_result]:
    if type(maximum) is not int or maximum < 1:
        raise ValueError("maximum file size must be a positive integer")
    _reject_symlink_components(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except (FileNotFoundError, IsADirectoryError, OSError) as exc:
        raise RecoveryPathError(f"recovery file is unavailable: {path}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RecoveryPathError(f"recovery file is not regular: {path}")
        if info.st_nlink != 1:
            raise RecoveryPathError(f"recovery file has multiple hard links: {path}")
        if info.st_size > maximum:
            raise RecoveryPathError(f"recovery file exceeds its size limit: {path}")
        if private:
            _require_private_mode(info, "recovery file")
        return descriptor, info
    except Exception:
        os.close(descriptor)
        raise


def _read_regular_bytes(path: Path, *, maximum: int, private: bool = True) -> bytes:
    descriptor, before = _open_regular_file(path, maximum=maximum, private=private)
    try:
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > maximum:
            raise RecoveryPathError(f"recovery file exceeds its size limit: {path}")
        try:
            after_descriptor = os.fstat(descriptor)
            after_path = os.lstat(path)
        except OSError as exc:
            raise RecoveryPathError(
                f"recovery file changed while it was read: {path}"
            ) from exc
        if (
            len(data) != int(before.st_size)
            or _file_identity(before) != _file_identity(after_descriptor)
            or _file_identity(before) != _file_identity(after_path)
        ):
            raise RecoveryPathError(
                f"recovery file changed while it was read: {path}"
            )
        return data
    finally:
        os.close(descriptor)


def _hash_descriptor(descriptor: int, *, maximum: int) -> tuple[str, int]:
    """Hash an already validated descriptor from its first byte."""
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    total = 0
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise RecoveryPathError("recovery file exceeds its size limit")
        digest.update(chunk)
    return digest.hexdigest(), total


def _file_identity(info: os.stat_result) -> tuple[int, ...]:
    """Return the metadata that must remain stable across offline inspection."""
    identity = (
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_mode),
        int(info.st_nlink),
        int(info.st_uid),
        int(info.st_size),
        int(info.st_mtime_ns),
    )
    # Python 3.12 deprecated st_ctime_ns on Windows because it represents
    # creation time there and can disagree between path and handle queries.
    # Device/inode still bind the opened object; size, mode, link count, owner,
    # and mtime retain the mutation gate. POSIX ctime remains a useful metadata
    # change signal and is therefore preserved on those platforms.
    if os.name != "nt":
        identity += (int(info.st_ctime_ns),)
    return identity


def _same_file(left: os.stat_result, right: os.stat_result) -> bool:
    return int(left.st_dev) == int(right.st_dev) and int(left.st_ino) == int(
        right.st_ino
    )


@contextmanager
def _immutable_sqlite_source(
    descriptor: int,
    database: Path,
    *,
    expected_sha256: str,
    expected_size: int,
) -> Iterator[str]:
    """Yield a SQLite URI bound to the bytes hashed on ``descriptor``.

    Linux and other Unix hosts with descriptor pseudo-files can reopen the held
    inode directly, so a rename cannot redirect SQLite to another database.  On
    platforms without that facility, a private byte-for-byte snapshot provides
    the same binding before SQLite sees the file.
    """
    held = os.fstat(descriptor)
    for root in (Path("/proc/self/fd"), Path("/dev/fd")):
        candidate = root / str(descriptor)
        try:
            candidate_info = os.stat(candidate)
        except OSError:
            continue
        if _same_file(held, candidate_info):
            yield candidate.as_uri() + "?mode=ro&immutable=1"
            return

    with tempfile.TemporaryDirectory(prefix="sentinel-blue-recovery-inspect-") as name:
        temporary_root = Path(name)
        if os.name == "posix":
            temporary_root.chmod(0o700)
        _require_private_directory(temporary_root)
        snapshot = temporary_root / DATABASE_FILENAME
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        output = os.open(snapshot, flags, 0o600)
        copied_hash = hashlib.sha256()
        copied_size = 0
        try:
            os.lseek(descriptor, 0, os.SEEK_SET)
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                copied_size += len(chunk)
                if copied_size > expected_size:
                    raise RecoveryPathError(
                        f"controller database changed while snapshotting: {database}"
                    )
                copied_hash.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(output, view)
                    if written <= 0:
                        raise RecoveryPathError(
                            "controller database snapshot write did not advance"
                        )
                    view = view[written:]
            os.fsync(output)
        finally:
            os.close(output)
        if copied_size != expected_size or not hmac.compare_digest(
            copied_hash.hexdigest(), expected_sha256
        ):
            raise RecoveryPathError(
                f"controller database changed while snapshotting: {database}"
            )
        if os.name == "posix":
            snapshot.chmod(0o400)
        yield snapshot.as_uri() + "?mode=ro&immutable=1"


def load_recovery_key(path: str | Path) -> bytes:
    """Load a raw private recovery key without following links or trimming bytes."""
    return _validate_key(
        _read_regular_bytes(
            Path(path), maximum=MAX_RECOVERY_KEY_BYTES, private=True
        )
    )


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private_write(
    path: Path,
    encoded: bytes,
    *,
    maximum: int,
    replace: bool = True,
) -> None:
    if len(encoded) > maximum:
        raise RecoveryPathError("recovery document exceeds its size limit")
    parent = path.parent
    _require_private_directory(parent)
    if os.path.lexists(path):
        if not replace:
            raise FileExistsError(path)
        descriptor, _info = _open_regular_file(path, maximum=maximum, private=True)
        os.close(descriptor)
    temporary = parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            descriptor = -1
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            os.chmod(temporary, 0o600)
        if replace:
            if os.path.lexists(path) and os.path.islink(path):
                raise RecoveryPathError(
                    "refusing to replace a symbolic-link recovery file"
                )
            os.replace(temporary, path)
        elif os.name == "posix":
            # link(2) publishes a new name without the overwrite semantics of
            # rename(2); removing the temporary name leaves one private inode.
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
        else:
            # On Windows rename fails when the destination already exists.
            os.rename(temporary, path)
        _fsync_directory(parent)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


@contextmanager
def _anchor_transition_lock(path: Path) -> Iterator[None]:
    """Take a crash-safe advisory lock for one anchor transition.

    The lock inode is deliberately persistent.  Ownership is attached to the
    open descriptor by the operating system, so process death releases it and
    cannot leave a stale create-only file that blocks recovery forever.
    """
    parent = path.parent
    _require_private_directory(parent)
    lock_path = parent / f".{path.name}.transition.lock"
    _reject_symlink_components(lock_path)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise RecoveryPathError("recovery-anchor lock could not be created") from exc
    locked = False
    windows_lock = False
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise RecoveryPathError(
                "recovery-anchor lock is not a private regular file"
            )
        _require_private_mode(metadata, "recovery-anchor lock")
        if os.name == "nt":  # pragma: no cover - native Windows acceptance
            import msvcrt

            if metadata.st_size == 0:
                os.write(descriptor, b"\x00")
                os.fsync(descriptor)
                metadata = os.fstat(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise AnchorConflictError(
                    "another recovery-anchor transition is active"
                ) from exc
            windows_lock = True
        else:
            import fcntl

            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except (BlockingIOError, OSError) as exc:
                raise AnchorConflictError(
                    "another recovery-anchor transition is active"
                ) from exc
        locked = True
        lock_identity = _file_identity(metadata)
        try:
            current = os.lstat(lock_path)
        except OSError as exc:
            raise RecoveryPathError(
                "recovery-anchor lock changed while it was acquired"
            ) from exc
        if _file_identity(current) != lock_identity:
            raise RecoveryPathError(
                "recovery-anchor lock changed while it was acquired"
            )
        yield
        try:
            current = os.lstat(lock_path)
        except OSError as exc:
            raise RecoveryPathError(
                "recovery-anchor lock changed during the transition"
            ) from exc
        if _file_identity(current) != lock_identity:
            raise RecoveryPathError(
                "recovery-anchor lock changed during the transition"
            )
    finally:
        try:
            if locked:
                if windows_lock:  # pragma: no cover - native Windows acceptance
                    import msvcrt

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _read_signed_document(path: Path, key: bytes, *, purpose: str, maximum: int) -> dict[str, Any]:
    encoded = _read_regular_bytes(path, maximum=maximum, private=True)
    try:
        record = strict_json_loads(encoded, max_bytes=maximum)
    except ValueError as exc:
        raise RecoveryError(f"recovery document is not strict JSON: {exc}") from exc
    return verify_signed_payload(record, key, purpose=purpose)


def _write_signed_document(
    path: Path,
    payload: dict[str, Any],
    key: bytes,
    *,
    purpose: str,
    maximum: int,
    replace: bool = True,
) -> None:
    record = sign_payload(payload, key, purpose=purpose)
    encoded = canonical_json_bytes(record, max_bytes=maximum)
    _atomic_private_write(path, encoded, maximum=maximum, replace=replace)


_LEGACY_ANCHOR_KEYS = frozenset(
    {
        "format",
        "schema",
        "controller_instance_id",
        "recovery_generation",
        "previous_recovery_generation",
        "phase",
        "previous_database_sha256",
        "pending_database_sha256",
        "updated_at_ns",
    }
)
_ANCHOR_KEYS = _LEGACY_ANCHOR_KEYS | frozenset(
    {
        "backup_sequence_floor",
        "pending_backup_sequence",
        "latest_backup",
    }
)
_LATEST_BACKUP_KEYS = frozenset(
    {
        "backup_id",
        "recovery_generation",
        "backup_sequence",
        "database_sha256",
        "manifest_sha256",
    }
)


def _validate_latest_backup(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    latest = _require_exact_keys(value, _LATEST_BACKUP_KEYS, "latest backup")
    _require_uuid(latest["backup_id"], "latest backup_id")
    _require_int(
        latest["recovery_generation"], "latest recovery_generation", 1
    )
    _require_int(latest["backup_sequence"], "latest backup_sequence", 0)
    _require_digest(latest["database_sha256"], "latest database_sha256")
    _require_digest(latest["manifest_sha256"], "latest manifest_sha256")
    return dict(latest)


def validate_anchor(anchor: Any) -> dict[str, Any]:
    if not isinstance(anchor, dict):
        raise RecoveryError("recovery anchor must be an object")
    schema = anchor.get("schema")
    if type(schema) is not int or schema not in {
        LEGACY_RECOVERY_SCHEMA,
        RECOVERY_SCHEMA,
    }:
        raise RecoveryError("unsupported recovery-anchor format or schema")
    expected_keys = (
        _LEGACY_ANCHOR_KEYS
        if schema == LEGACY_RECOVERY_SCHEMA
        else _ANCHOR_KEYS
    )
    value = _require_exact_keys(anchor, expected_keys, "recovery anchor")
    if value["format"] != ANCHOR_FORMAT:
        raise RecoveryError("unsupported recovery-anchor format or schema")
    _require_uuid(value["controller_instance_id"], "controller_instance_id")
    generation = _require_int(value["recovery_generation"], "recovery_generation", 1)
    previous = _require_int(
        value["previous_recovery_generation"], "previous_recovery_generation", 1
    )
    _require_int(value["updated_at_ns"], "updated_at_ns", 1)
    sequence_floor = 0
    pending_sequence = 0
    latest: dict[str, Any] | None = None
    if schema == RECOVERY_SCHEMA:
        sequence_floor = _require_int(
            value["backup_sequence_floor"], "backup_sequence_floor", 0
        )
        pending_sequence = _require_int(
            value["pending_backup_sequence"], "pending_backup_sequence", 0
        )
        latest = _validate_latest_backup(value["latest_backup"])
        if latest is not None:
            if latest["backup_sequence"] > sequence_floor:
                raise RecoveryError(
                    "latest backup sequence exceeds the protected floor"
                )
            maximum_generation = (
                previous if value.get("phase") == "pending" else generation
            )
            if latest["recovery_generation"] > maximum_generation:
                raise RecoveryError(
                    "latest backup generation exceeds the protected generation"
                )
    phase = value["phase"]
    if phase == "committed":
        if (
            previous != generation
            or value["previous_database_sha256"] != ""
            or value["pending_database_sha256"] != ""
            or pending_sequence != 0
        ):
            raise RecoveryError("committed recovery anchor contains pending state")
    elif phase == "pending":
        if generation != previous + 1:
            raise RecoveryError("pending recovery generation must advance exactly once")
        _require_digest(
            value["previous_database_sha256"], "previous_database_sha256"
        )
        _require_digest(
            value["pending_database_sha256"], "pending_database_sha256"
        )
        if schema == RECOVERY_SCHEMA and pending_sequence <= sequence_floor:
            raise RecoveryError(
                "pending backup sequence must advance beyond the protected floor"
            )
    else:
        raise RecoveryError("recovery anchor phase must be committed or pending")
    return dict(value)


def make_committed_anchor(
    controller_instance_id: str | None = None,
    *,
    recovery_generation: int = 1,
    backup_sequence_floor: int = 0,
    latest_backup: dict[str, Any] | None = None,
    updated_at_ns: int | None = None,
) -> dict[str, Any]:
    instance_id = controller_instance_id or str(uuid.uuid4())
    generation = _require_int(recovery_generation, "recovery_generation", 1)
    value = {
        "format": ANCHOR_FORMAT,
        "schema": RECOVERY_SCHEMA,
        "controller_instance_id": _require_uuid(instance_id, "controller_instance_id"),
        "recovery_generation": generation,
        "previous_recovery_generation": generation,
        "phase": "committed",
        "previous_database_sha256": "",
        "pending_database_sha256": "",
        "backup_sequence_floor": _require_int(
            backup_sequence_floor, "backup_sequence_floor", 0
        ),
        "pending_backup_sequence": 0,
        "latest_backup": _validate_latest_backup(latest_backup),
        "updated_at_ns": _require_int(
            time.time_ns() if updated_at_ns is None else updated_at_ns,
            "updated_at_ns",
            1,
        ),
    }
    return validate_anchor(value)


def load_anchor(path: str | Path, key: bytes) -> dict[str, Any]:
    return validate_anchor(
        _read_signed_document(
            Path(path), key, purpose="anchor", maximum=MAX_ANCHOR_BYTES
        )
    )


def initialize_anchor(path: str | Path, key: bytes, anchor: dict[str, Any]) -> dict[str, Any]:
    target = Path(path)
    value = validate_anchor(anchor)
    if value["schema"] != RECOVERY_SCHEMA:
        raise RecoveryError(
            "a legacy recovery anchor requires an explicit offline upgrade"
        )
    if value["phase"] != "committed":
        raise RecoveryError("a new recovery anchor must be committed")
    with _anchor_transition_lock(target):
        if os.path.lexists(target):
            raise AnchorConflictError("recovery anchor already exists")
        try:
            _write_signed_document(
                target,
                value,
                key,
                purpose="anchor",
                maximum=MAX_ANCHOR_BYTES,
                replace=False,
            )
        except FileExistsError as exc:
            raise AnchorConflictError("recovery anchor already exists") from exc
    return value


def _transition_anchor(
    path: Path,
    key: bytes,
    expected: dict[str, Any],
    replacement: dict[str, Any],
    *,
    allow_schema_upgrade: bool = False,
) -> dict[str, Any]:
    expected_value = validate_anchor(expected)
    replacement_value = validate_anchor(replacement)
    if replacement_value["controller_instance_id"] != expected_value["controller_instance_id"]:
        raise RecoveryError("anchor transition changed the controller instance")
    if replacement_value["schema"] != expected_value["schema"] and not (
        allow_schema_upgrade
        and expected_value["schema"] == LEGACY_RECOVERY_SCHEMA
        and replacement_value["schema"] == RECOVERY_SCHEMA
    ):
        raise RecoveryError("anchor transition changed the recovery schema")
    if (
        expected_value["schema"] == RECOVERY_SCHEMA
        and replacement_value["schema"] == RECOVERY_SCHEMA
        and replacement_value["backup_sequence_floor"]
        < expected_value["backup_sequence_floor"]
    ):
        raise RecoveryError("anchor transition regressed the backup sequence floor")
    if replacement_value["updated_at_ns"] <= expected_value["updated_at_ns"]:
        raise RecoveryError("anchor transition timestamp must advance")
    with _anchor_transition_lock(path):
        current = load_anchor(path, key)
        if not hmac.compare_digest(
            canonical_json_bytes(current), canonical_json_bytes(expected_value)
        ):
            raise AnchorConflictError("recovery anchor no longer matches expected state")
        _write_signed_document(
            path,
            replacement_value,
            key,
            purpose="anchor",
            maximum=MAX_ANCHOR_BYTES,
        )
    return replacement_value


def begin_pending_anchor(
    path: str | Path,
    key: bytes,
    committed: dict[str, Any],
    pending_database_sha256: str,
    *,
    previous_database_sha256: str,
    pending_backup_sequence: int,
    updated_at_ns: int | None = None,
) -> dict[str, Any]:
    current = validate_anchor(committed)
    if current["schema"] != RECOVERY_SCHEMA:
        raise RecoveryError(
            "a legacy recovery anchor must be upgraded before a new restore"
        )
    if current["phase"] != "committed":
        raise RecoveryError("only a committed anchor can begin a restore")
    if current["recovery_generation"] >= MAX_INT64:
        raise RecoveryError("recovery generation is exhausted")
    replacement = {
        **current,
        "recovery_generation": current["recovery_generation"] + 1,
        "previous_recovery_generation": current["recovery_generation"],
        "phase": "pending",
        "previous_database_sha256": _require_digest(
            previous_database_sha256, "previous_database_sha256"
        ),
        "pending_database_sha256": _require_digest(
            pending_database_sha256, "pending_database_sha256"
        ),
        "pending_backup_sequence": _require_int(
            pending_backup_sequence,
            "pending_backup_sequence",
            int(current["backup_sequence_floor"]) + 1,
        ),
        "updated_at_ns": _require_int(
            time.time_ns() if updated_at_ns is None else updated_at_ns,
            "updated_at_ns",
            1,
        ),
    }
    return _transition_anchor(Path(path), key, current, replacement)


def commit_pending_anchor(
    path: str | Path,
    key: bytes,
    pending: dict[str, Any],
    *,
    live_controller_instance_id: str,
    live_recovery_generation: int,
    live_database_sha256: str,
    live_backup_sequence: int | None = None,
    updated_at_ns: int | None = None,
) -> dict[str, Any]:
    current = validate_anchor(pending)
    if current["phase"] != "pending":
        raise RecoveryError("only a pending anchor can be committed")
    decision = decide_crash_state(
        current,
        live_controller_instance_id=live_controller_instance_id,
        live_recovery_generation=live_recovery_generation,
        live_database_sha256=live_database_sha256,
        live_backup_sequence=live_backup_sequence,
    )
    if decision.action is not CrashAction.COMMIT_PENDING:
        raise AnchorConflictError(
            f"pending recovery anchor cannot commit: {decision.reason}"
        )
    replacement = {
        **current,
        "previous_recovery_generation": current["recovery_generation"],
        "phase": "committed",
        "previous_database_sha256": "",
        "pending_database_sha256": "",
        "updated_at_ns": _require_int(
            time.time_ns() if updated_at_ns is None else updated_at_ns,
            "updated_at_ns",
            1,
        ),
    }
    if current["schema"] == RECOVERY_SCHEMA:
        replacement["backup_sequence_floor"] = current[
            "pending_backup_sequence"
        ]
        replacement["pending_backup_sequence"] = 0
    return _transition_anchor(Path(path), key, current, replacement)


def abort_pending_anchor(
    path: str | Path,
    key: bytes,
    pending: dict[str, Any],
    *,
    live_controller_instance_id: str,
    live_recovery_generation: int,
    live_database_sha256: str,
    live_backup_sequence: int | None = None,
    updated_at_ns: int | None = None,
) -> dict[str, Any]:
    current = validate_anchor(pending)
    if current["phase"] != "pending":
        raise RecoveryError("only a pending anchor can be aborted")
    decision = decide_crash_state(
        current,
        live_controller_instance_id=live_controller_instance_id,
        live_recovery_generation=live_recovery_generation,
        live_database_sha256=live_database_sha256,
        live_backup_sequence=live_backup_sequence,
    )
    if decision.action is not CrashAction.ABORT_PENDING:
        raise AnchorConflictError(
            f"pending recovery anchor cannot abort: {decision.reason}"
        )
    previous = int(current["previous_recovery_generation"])
    replacement = {
        **current,
        "recovery_generation": previous,
        "previous_recovery_generation": previous,
        "phase": "committed",
        "previous_database_sha256": "",
        "pending_database_sha256": "",
        "updated_at_ns": _require_int(
            time.time_ns() if updated_at_ns is None else updated_at_ns,
            "updated_at_ns",
            1,
        ),
    }
    if current["schema"] == RECOVERY_SCHEMA:
        replacement["pending_backup_sequence"] = 0
    return _transition_anchor(Path(path), key, current, replacement)


def decide_crash_state(
    anchor: dict[str, Any],
    *,
    live_controller_instance_id: str,
    live_recovery_generation: int,
    live_database_sha256: str,
    live_backup_sequence: int | None = None,
) -> CrashDecision:
    """Select a fail-closed recovery action without changing any files."""
    try:
        current = validate_anchor(anchor)
        instance_id = _require_uuid(
            live_controller_instance_id, "live_controller_instance_id"
        )
        generation = _require_int(
            live_recovery_generation, "live_recovery_generation", 1
        )
        digest = _require_digest(live_database_sha256, "live_database_sha256")
        sequence = (
            None
            if live_backup_sequence is None
            else _require_int(live_backup_sequence, "live_backup_sequence", 0)
        )
    except RecoveryError as exc:
        return CrashDecision(CrashAction.BLOCK, str(exc))
    if instance_id != current["controller_instance_id"]:
        return CrashDecision(CrashAction.BLOCK, "live database belongs to another controller instance")
    if current["schema"] == LEGACY_RECOVERY_SCHEMA:
        if current["phase"] == "committed":
            return CrashDecision(
                CrashAction.BLOCK,
                "legacy committed anchor lacks a backup sequence floor; explicit upgrade is required",
            )
    elif sequence is None:
        return CrashDecision(
            CrashAction.BLOCK,
            "live backup sequence is required by the recovery anchor",
        )
    if current["phase"] == "committed":
        if generation == current["recovery_generation"] and sequence is not None:
            if sequence < current["backup_sequence_floor"]:
                return CrashDecision(
                    CrashAction.BLOCK,
                    "live database backup sequence is below the protected floor",
                )
            return CrashDecision(
                CrashAction.START,
                "live database matches the committed generation and sequence floor",
            )
        return CrashDecision(CrashAction.BLOCK, "live database generation does not match the anchor")
    if generation == current["previous_recovery_generation"]:
        sequence_valid = (
            current["schema"] == LEGACY_RECOVERY_SCHEMA
            or (
                sequence is not None
                and sequence >= current["backup_sequence_floor"]
            )
        )
        if sequence_valid and hmac.compare_digest(
            digest, current["previous_database_sha256"]
        ):
            return CrashDecision(
                CrashAction.ABORT_PENDING,
                "the exact pre-restore database is still live; the pending anchor may be aborted",
            )
        return CrashDecision(
            CrashAction.BLOCK,
            "the live pre-restore database does not match the pending anchor",
        )
    if generation == current["recovery_generation"]:
        sequence_valid = (
            current["schema"] == LEGACY_RECOVERY_SCHEMA
            or sequence == current["pending_backup_sequence"]
        )
        if sequence_valid and hmac.compare_digest(
            digest, current["pending_database_sha256"]
        ):
            return CrashDecision(
                CrashAction.COMMIT_PENDING,
                "the exact staged database is live; the pending anchor may be committed",
            )
        return CrashDecision(
            CrashAction.BLOCK,
            "the live restored database does not match the pending digest",
        )
    return CrashDecision(CrashAction.BLOCK, "live database is in an unexpected recovery generation")


def upgrade_legacy_anchor(
    path: str | Path,
    key: bytes,
    legacy: dict[str, Any],
    *,
    live_controller_instance_id: str,
    live_recovery_generation: int,
    live_backup_sequence: int,
    updated_at_ns: int | None = None,
) -> dict[str, Any]:
    """Explicitly bind a committed v1 anchor to an inspected live sequence.

    A v1 committed anchor cannot prove a same-generation rollback did not
    occur, so normal crash decisions block it.  This offline-only transition
    requires the caller to supply the identity, generation, and sequence from
    its independently inspected live database.  Pending v1 anchors must first
    be resolved using their exact pre/pending database digest.
    """
    current = validate_anchor(legacy)
    if current["schema"] != LEGACY_RECOVERY_SCHEMA:
        raise RecoveryError("only a legacy recovery anchor can be upgraded")
    if current["phase"] != "committed":
        raise RecoveryError("a pending legacy anchor must be resolved before upgrade")
    instance_id = _require_uuid(
        live_controller_instance_id, "live_controller_instance_id"
    )
    generation = _require_int(
        live_recovery_generation, "live_recovery_generation", 1
    )
    sequence = _require_int(live_backup_sequence, "live_backup_sequence", 0)
    if instance_id != current["controller_instance_id"]:
        raise AnchorConflictError(
            "legacy anchor and live database controller instances differ"
        )
    if generation != current["recovery_generation"]:
        raise AnchorConflictError(
            "legacy anchor and live database generations differ"
        )
    replacement = make_committed_anchor(
        instance_id,
        recovery_generation=generation,
        backup_sequence_floor=sequence,
        updated_at_ns=(
            time.time_ns() if updated_at_ns is None else updated_at_ns
        ),
    )
    return _transition_anchor(
        Path(path),
        key,
        current,
        replacement,
        allow_schema_upgrade=True,
    )


def _parse_state_integer(value: str, label: str, minimum: int) -> int:
    if not isinstance(value, str) or not _DECIMAL.fullmatch(value):
        raise RecoverySemanticError(f"controller_state {label} is not a canonical integer")
    numeric = int(value)
    if not minimum <= numeric <= MAX_INT64:
        raise RecoverySemanticError(f"controller_state {label} is outside its accepted range")
    return numeric


def _canonical_state_object(raw: str, label: str) -> tuple[dict[str, Any], str]:
    try:
        parsed = strict_json_loads(raw, max_bytes=MAX_STATE_VALUE_BYTES)
        if not isinstance(parsed, dict):
            raise RecoverySemanticError(f"controller_state {label} is not an object")
        encoded = canonical_json_bytes(parsed, max_bytes=MAX_STATE_VALUE_BYTES)
    except ValueError as exc:
        if isinstance(exc, RecoverySemanticError):
            raise
        raise RecoverySemanticError(f"controller_state {label} is invalid: {exc}") from exc
    return dict(parsed), hashlib.sha256(encoded).hexdigest()


def _validate_active_release_binding(value: dict[str, Any]) -> dict[str, Any]:
    try:
        binding = _require_exact_keys(
            value,
            {
                "schema",
                "profile_id",
                "profile_fingerprint",
                "agent_version",
                "release_sha256",
            },
            "active release binding",
        )
        if type(binding["schema"]) is not int or binding["schema"] != 1:
            raise RecoveryError("active release binding schema is unsupported")
        profile_id = _require_text(
            binding["profile_id"], "active release binding profile_id", 128
        )
        if not _PROFILE_ID.fullmatch(profile_id):
            raise RecoveryError(
                "active release binding profile_id contains unsupported characters"
            )
        _require_digest(
            binding["profile_fingerprint"],
            "active release binding profile_fingerprint",
        )
        version = _require_text(
            binding["agent_version"], "active release binding agent_version", 128
        )
        if not _VERSION.fullmatch(version):
            raise RecoveryError(
                "active release binding agent_version contains unsupported characters"
            )
        _require_digest(
            binding["release_sha256"], "active release binding release_sha256"
        )
    except RecoveryError as exc:
        raise RecoverySemanticError(f"controller_state active_release_binding is invalid: {exc}") from exc
    return dict(binding)


def _validate_governance(value: dict[str, Any]) -> dict[str, Any]:
    try:
        governance = _require_exact_keys(
            value,
            {
                "schema",
                "profile_fingerprint",
                "autonomy_mode",
                "emergency_stopped",
                "revision",
            },
            "governance",
        )
        if type(governance["schema"]) is not int or governance["schema"] != 1:
            raise RecoveryError("governance schema is unsupported")
        _require_digest(
            governance["profile_fingerprint"], "governance profile_fingerprint"
        )
        mode = _require_text(governance["autonomy_mode"], "governance autonomy_mode", 32)
        if mode not in _AUTONOMY_MODES:
            raise RecoveryError("governance autonomy_mode is unsupported")
        if type(governance["emergency_stopped"]) is not bool:
            raise RecoveryError("governance emergency_stopped must be Boolean")
        _require_int(governance["revision"], "governance revision", 0)
    except RecoveryError as exc:
        raise RecoverySemanticError(f"controller_state governance is invalid: {exc}") from exc
    return dict(governance)


def _table_expectations(
    value: set[str] | frozenset[str] | None, label: str
) -> frozenset[str] | None:
    if value is None:
        return None
    if not isinstance(value, (set, frozenset)) or len(value) > MAX_SCHEMA_OBJECTS:
        raise ValueError(f"{label} must be a bounded set of table names")
    normalized: set[str] = set()
    for name in value:
        if not isinstance(name, str) or not name or len(name) > 256 or "\x00" in name:
            raise ValueError(f"{label} contains an invalid table name")
        normalized.add(name)
    return frozenset(normalized)


def _expected_pragma(value: int | None, label: str) -> int | None:
    if value is None:
        return None
    if type(value) is not int or not 0 <= value <= 2**31 - 1:
        raise ValueError(f"{label} must be an unsigned 31-bit integer")
    return value


def _recovery_constraints(
    expected_application_id: int,
    expected_user_version: int,
    required_tables: set[str] | frozenset[str],
    allowed_tables: set[str] | frozenset[str],
) -> tuple[int, int, frozenset[str], frozenset[str]]:
    application_id = _expected_pragma(
        expected_application_id, "expected_application_id"
    )
    user_version = _expected_pragma(
        expected_user_version, "expected_user_version"
    )
    required = _table_expectations(required_tables, "required_tables")
    allowed = _table_expectations(allowed_tables, "allowed_tables")
    if application_id is None or user_version is None:
        raise ValueError("recovery database pragmas must be explicit")
    if not required or not allowed:
        raise ValueError("recovery database table constraints must be non-empty")
    if not required.issubset(allowed):
        raise ValueError("required recovery tables must be allowed")
    return application_id, user_version, required, allowed


def _inspect_sqlite_semantics(
    connection: sqlite3.Connection,
    *,
    expected_application_id: int | None,
    expected_user_version: int | None,
    required_tables: frozenset[str],
    allowed_tables: frozenset[str] | None,
    require_recovery_state: bool,
    require_state_hashes: bool,
) -> tuple[
    int,
    int,
    list[str],
    list[str],
    dict[str, str],
    dict[str, Any] | None,
    dict[str, Any] | None,
    str | None,
    int | None,
    int | None,
]:
    try:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA trusted_schema=OFF")
        integrity_rows = connection.execute("PRAGMA integrity_check(1)").fetchmany(2)
        if len(integrity_rows) != 1 or str(integrity_rows[0][0]) != "ok":
            raise RecoverySemanticError("controller database failed integrity_check")
        if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise RecoverySemanticError("controller database failed foreign_key_check")
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        if expected_application_id is not None and application_id != expected_application_id:
            raise RecoverySemanticError("controller database application_id does not match")
        if expected_user_version is not None and user_version != expected_user_version:
            raise RecoverySemanticError("controller database user_version does not match")

        rows = connection.execute(
            "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name"
        ).fetchmany(MAX_SCHEMA_OBJECTS + 1)
        if len(rows) > MAX_SCHEMA_OBJECTS:
            raise RecoverySemanticError("controller database schema is unbounded")
        tables: list[str] = []
        indexes: list[str] = []
        schema_chars = 0
        for row in rows:
            if (
                not isinstance(row["type"], str)
                or not isinstance(row["name"], str)
                or not isinstance(row["tbl_name"], str)
                or (row["sql"] is not None and not isinstance(row["sql"], str))
            ):
                raise RecoverySemanticError(
                    "controller database schema contains non-text metadata"
                )
            object_type = row["type"]
            name = row["name"]
            sql = "" if row["sql"] is None else row["sql"]
            schema_chars += len(name) + len(row["tbl_name"]) + len(sql)
            if schema_chars > MAX_SCHEMA_SQL_CHARS:
                raise RecoverySemanticError("controller database schema text is unbounded")
            if object_type == "table":
                if sql.lstrip().casefold().startswith("create virtual table"):
                    raise RecoverySemanticError(
                        "virtual tables are forbidden in controller backups"
                    )
                tables.append(name)
            elif object_type == "index":
                indexes.append(name)
            elif object_type == "trigger":
                expected_trigger = CONTROLLER_TRIGGER_CONTRACTS.get(name)
                normalized_sql = " ".join(sql.split()).casefold()
                if expected_trigger is None or not hmac.compare_digest(
                    normalized_sql,
                    " ".join(expected_trigger.split()).casefold(),
                ):
                    raise RecoverySemanticError(
                        f"controller database contains forbidden trigger: {name}"
                    )
            else:
                raise RecoverySemanticError(
                    f"controller database contains forbidden schema object: {object_type}"
                )
        table_set = set(tables)
        missing = set(required_tables) - table_set
        if missing:
            raise RecoverySemanticError(
                "controller database is missing required tables: "
                + ", ".join(sorted(missing))
            )
        if allowed_tables is not None:
            unexpected = table_set - set(allowed_tables)
            if unexpected:
                raise RecoverySemanticError(
                    "controller database contains unexpected tables: "
                    + ", ".join(sorted(unexpected))
                )

        state_values: dict[str, str] = {}
        if "controller_state" in table_set:
            state_rows = connection.execute(
                "SELECT state_key, state_value FROM controller_state "
                "WHERE state_key IN (?, ?, ?, ?, ?)",
                tuple(sorted(RECOVERY_STATE_KEYS)),
            ).fetchmany(len(RECOVERY_STATE_KEYS) + 1)
            if len(state_rows) > len(RECOVERY_STATE_KEYS):
                raise RecoverySemanticError(
                    "controller database contains duplicate recovery state"
                )
            for row in state_rows:
                if not isinstance(row["state_key"], str) or not isinstance(
                    row["state_value"], str
                ):
                    raise RecoverySemanticError(
                        "controller recovery state must use exact text values"
                    )
                key = row["state_key"]
                raw = row["state_value"]
                if key in state_values:
                    raise RecoverySemanticError(
                        f"controller database contains duplicate recovery state: {key}"
                    )
                if len(raw.encode("utf-8", "strict")) > MAX_STATE_VALUE_BYTES:
                    raise RecoverySemanticError(
                        f"controller_state {key} exceeds its size limit"
                    )
                state_values[key] = raw

        state_hashes: dict[str, str] = {}
        active_release_binding: dict[str, Any] | None = None
        governance: dict[str, Any] | None = None
        if "active_release_binding" in state_values:
            parsed, digest = _canonical_state_object(
                state_values["active_release_binding"], "active_release_binding"
            )
            active_release_binding = _validate_active_release_binding(parsed)
            state_hashes["active_release_binding_sha256"] = digest
        if "governance" in state_values:
            parsed, digest = _canonical_state_object(
                state_values["governance"], "governance"
            )
            governance = _validate_governance(parsed)
            state_hashes["governance_sha256"] = digest
        if require_state_hashes and set(state_hashes) != set(STATE_HASH_KEYS):
            raise RecoverySemanticError(
                "controller database lacks bound release/governance state"
            )
        if (
            active_release_binding is not None
            and governance is not None
            and active_release_binding["profile_fingerprint"]
            != governance["profile_fingerprint"]
        ):
            raise RecoverySemanticError(
                "controller release and governance profile bindings differ"
            )

        instance_id: str | None = None
        generation: int | None = None
        sequence: int | None = None
        if "controller_instance_id" in state_values:
            try:
                instance_id = _require_uuid(
                    state_values["controller_instance_id"], "controller_instance_id"
                )
            except RecoveryError as exc:
                raise RecoverySemanticError(str(exc)) from exc
        if "recovery_generation" in state_values:
            generation = _parse_state_integer(
                state_values["recovery_generation"], "recovery_generation", 1
            )
        if "backup_sequence" in state_values:
            sequence = _parse_state_integer(
                state_values["backup_sequence"], "backup_sequence", 0
            )
        if require_recovery_state and (
            instance_id is None or generation is None or sequence is None
        ):
            raise RecoverySemanticError(
                "controller database lacks recovery identity state"
            )
    except (sqlite3.Error, UnicodeError) as exc:
        if isinstance(exc, RecoverySemanticError):
            raise
        raise RecoverySemanticError(
            f"controller database semantic inspection failed: {exc}"
        ) from exc
    return (
        application_id,
        user_version,
        tables,
        indexes,
        state_hashes,
        active_release_binding,
        governance,
        instance_id,
        generation,
        sequence,
    )


def inspect_controller_database(
    path: str | Path,
    *,
    maximum_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
    expected_application_id: int | None = None,
    expected_user_version: int | None = None,
    required_tables: set[str] | frozenset[str] = frozenset(),
    allowed_tables: set[str] | frozenset[str] | None = None,
    require_recovery_state: bool = False,
    require_state_hashes: bool = False,
) -> DatabaseInspection:
    """Inspect the exact bytes hashed from one static SQLite backup.

    The controller must be quiesced before its database is copied.  This routine
    keeps the validated file descriptor open, binds SQLite to that inode (or to a
    private exact snapshot), and hashes it again before returning.
    """
    if type(maximum_bytes) is not int or maximum_bytes < 1:
        raise ValueError("maximum database bytes must be a positive integer")
    expected_application_id = _expected_pragma(
        expected_application_id, "expected_application_id"
    )
    expected_user_version = _expected_pragma(
        expected_user_version, "expected_user_version"
    )
    required = _table_expectations(required_tables, "required_tables")
    allowed = _table_expectations(allowed_tables, "allowed_tables")
    assert required is not None
    database = Path(path)
    descriptor, before = _open_regular_file(
        database, maximum=maximum_bytes, private=True
    )
    try:
        digest, size_bytes = _hash_descriptor(descriptor, maximum=maximum_bytes)
        if size_bytes != int(before.st_size):
            raise RecoveryPathError("controller database changed before inspection")
        if size_bytes < 100:
            raise RecoverySemanticError("controller database is too small to be SQLite")
        with _immutable_sqlite_source(
            descriptor,
            database,
            expected_sha256=digest,
            expected_size=size_bytes,
        ) as uri:
            try:
                connection = sqlite3.connect(uri, uri=True, timeout=5.0)
            except (OSError, sqlite3.Error) as exc:
                raise RecoverySemanticError(
                    "controller database could not be opened read-only"
                ) from exc
            try:
                (
                    application_id,
                    user_version,
                    tables,
                    indexes,
                    state_hashes,
                    active_release_binding,
                    governance,
                    instance_id,
                    generation,
                    sequence,
                ) = _inspect_sqlite_semantics(
                    connection,
                    expected_application_id=expected_application_id,
                    expected_user_version=expected_user_version,
                    required_tables=required,
                    allowed_tables=allowed,
                    require_recovery_state=require_recovery_state,
                    require_state_hashes=require_state_hashes,
                )
            finally:
                connection.close()

        after_descriptor = os.fstat(descriptor)
        after_digest, after_size = _hash_descriptor(
            descriptor, maximum=maximum_bytes
        )
        try:
            after_path = os.lstat(database)
        except OSError as exc:
            raise RecoveryPathError(
                "controller database changed during inspection"
            ) from exc
        if (
            _file_identity(before) != _file_identity(after_descriptor)
            or _file_identity(before) != _file_identity(after_path)
            or not stat.S_ISREG(after_path.st_mode)
            or after_size != size_bytes
            or not hmac.compare_digest(after_digest, digest)
        ):
            raise RecoveryPathError("controller database changed during inspection")
    finally:
        os.close(descriptor)
    return DatabaseInspection(
        path=database,
        sha256=digest,
        size_bytes=size_bytes,
        application_id=application_id,
        user_version=user_version,
        tables=tuple(sorted(tables)),
        indexes=tuple(sorted(indexes)),
        state_hashes=dict(sorted(state_hashes.items())),
        active_release_binding=(
            None if active_release_binding is None else dict(active_release_binding)
        ),
        governance=None if governance is None else dict(governance),
        controller_instance_id=instance_id,
        recovery_generation=generation,
        backup_sequence=sequence,
    )


def validate_manifest(manifest: Any) -> dict[str, Any]:
    value = _require_exact_keys(
        manifest,
        {
            "format",
            "schema",
            "backup_id",
            "controller_instance_id",
            "recovery_generation",
            "backup_sequence",
            "created_at_ns",
            "database",
            "release",
            "state_hashes",
        },
        "backup manifest",
    )
    if (
        value["format"] != MANIFEST_FORMAT
        or type(value["schema"]) is not int
        or value["schema"] not in {LEGACY_RECOVERY_SCHEMA, RECOVERY_SCHEMA}
    ):
        raise RecoveryError("unsupported backup-manifest format or schema")
    _require_uuid(value["backup_id"], "backup_id")
    _require_uuid(value["controller_instance_id"], "controller_instance_id")
    _require_int(value["recovery_generation"], "recovery_generation", 1)
    _require_int(value["backup_sequence"], "backup_sequence", 0)
    _require_int(value["created_at_ns"], "created_at_ns", 1)
    database = _require_exact_keys(
        value["database"],
        {"filename", "sha256", "size_bytes", "application_id", "user_version"},
        "manifest.database",
    )
    if database["filename"] != DATABASE_FILENAME:
        raise RecoveryError("manifest database filename is not the fixed bundle name")
    _require_digest(database["sha256"], "database.sha256")
    _require_int(
        database["size_bytes"],
        "database.size_bytes",
        1,
        DEFAULT_MAX_DATABASE_BYTES,
    )
    _require_int(database["application_id"], "database.application_id", 0, 2**31 - 1)
    _require_int(database["user_version"], "database.user_version", 0, 2**31 - 1)
    release = _require_exact_keys(
        value["release"], {"version", "sha256", "profile_id", "profile_fingerprint"}, "manifest.release"
    )
    version = _require_text(release["version"], "release.version", 128)
    if not _VERSION.fullmatch(version):
        raise RecoveryError("release.version contains unsupported characters")
    _require_digest(release["sha256"], "release.sha256")
    profile_id = _require_text(release["profile_id"], "release.profile_id", 128)
    if not _PROFILE_ID.fullmatch(profile_id):
        raise RecoveryError("release.profile_id contains unsupported characters")
    _require_digest(release["profile_fingerprint"], "release.profile_fingerprint")
    hashes = _require_exact_keys(value["state_hashes"], STATE_HASH_KEYS, "manifest.state_hashes")
    for key, digest in hashes.items():
        _require_digest(digest, f"state_hashes.{key}")
    return dict(value)


def _require_release_state_match(
    inspection: DatabaseInspection, release: dict[str, Any]
) -> None:
    binding = inspection.active_release_binding
    governance = inspection.governance
    if binding is None or governance is None:
        raise RecoverySemanticError(
            "controller database lacks exact release/governance bindings"
        )
    expected = {
        "version": binding["agent_version"],
        "sha256": binding["release_sha256"],
        "profile_id": binding["profile_id"],
        "profile_fingerprint": binding["profile_fingerprint"],
    }
    if release != expected:
        raise RecoverySemanticError(
            "backup release metadata does not match controller release state"
        )
    if governance["profile_fingerprint"] != release["profile_fingerprint"]:
        raise RecoverySemanticError(
            "backup governance does not match the release profile"
        )


def build_backup_manifest(
    database_path: str | Path,
    key: bytes,
    *,
    release_version: str,
    release_sha256: str,
    profile_id: str,
    profile_fingerprint: str,
    expected_application_id: int,
    expected_user_version: int,
    required_tables: set[str] | frozenset[str],
    allowed_tables: set[str] | frozenset[str],
    backup_id: str | None = None,
    created_at_ns: int | None = None,
    maximum_database_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
) -> dict[str, Any]:
    """Inspect a completed static SQLite copy and return its signed manifest."""
    (
        expected_application_id,
        expected_user_version,
        required,
        allowed,
    ) = _recovery_constraints(
        expected_application_id,
        expected_user_version,
        required_tables,
        allowed_tables,
    )
    inspection = inspect_controller_database(
        database_path,
        maximum_bytes=maximum_database_bytes,
        expected_application_id=expected_application_id,
        expected_user_version=expected_user_version,
        required_tables=required,
        allowed_tables=allowed,
        require_recovery_state=True,
        require_state_hashes=True,
    )
    assert inspection.controller_instance_id is not None
    assert inspection.recovery_generation is not None
    assert inspection.backup_sequence is not None
    release = {
        "version": release_version,
        "sha256": release_sha256,
        "profile_id": profile_id,
        "profile_fingerprint": profile_fingerprint,
    }
    payload = {
        "format": MANIFEST_FORMAT,
        "schema": RECOVERY_SCHEMA,
        "backup_id": _require_uuid(
            backup_id or str(uuid.uuid4()), "backup_id"
        ),
        "controller_instance_id": inspection.controller_instance_id,
        "recovery_generation": inspection.recovery_generation,
        "backup_sequence": inspection.backup_sequence,
        "created_at_ns": _require_int(
            time.time_ns() if created_at_ns is None else created_at_ns,
            "created_at_ns",
            1,
        ),
        "database": {
            "filename": DATABASE_FILENAME,
            "sha256": inspection.sha256,
            "size_bytes": inspection.size_bytes,
            "application_id": inspection.application_id,
            "user_version": inspection.user_version,
        },
        "release": release,
        "state_hashes": inspection.state_hashes,
    }
    validated = validate_manifest(payload)
    _require_release_state_match(inspection, validated["release"])
    return sign_payload(validated, key, purpose="manifest")


def write_backup_manifest(path: str | Path, record: dict[str, Any], key: bytes) -> None:
    payload = verify_signed_payload(record, key, purpose="manifest")
    validate_manifest(payload)
    encoded = canonical_json_bytes(record, max_bytes=MAX_MANIFEST_BYTES)
    target = Path(path)
    if target.name != MANIFEST_FILENAME:
        raise RecoveryPathError(
            f"backup manifest must use the fixed name {MANIFEST_FILENAME}"
        )
    try:
        _atomic_private_write(
            target, encoded, maximum=MAX_MANIFEST_BYTES, replace=False
        )
    except FileExistsError as exc:
        raise RecoveryPathError("backup manifest already exists") from exc


def load_backup_manifest(path: str | Path, key: bytes) -> dict[str, Any]:
    return validate_manifest(
        _read_signed_document(
            Path(path), key, purpose="manifest", maximum=MAX_MANIFEST_BYTES
        )
    )


def _load_backup_manifest_with_digest(
    path: Path, key: bytes
) -> tuple[dict[str, Any], str]:
    encoded = _read_regular_bytes(path, maximum=MAX_MANIFEST_BYTES, private=True)
    try:
        record = strict_json_loads(encoded, max_bytes=MAX_MANIFEST_BYTES)
    except ValueError as exc:
        raise RecoveryError(f"recovery document is not strict JSON: {exc}") from exc
    payload = validate_manifest(
        verify_signed_payload(record, key, purpose="manifest")
    )
    canonical_record = canonical_json_bytes(record, max_bytes=MAX_MANIFEST_BYTES)
    return payload, hashlib.sha256(canonical_record).hexdigest()


def verify_backup_bundle(
    bundle_path: str | Path,
    key: bytes,
    *,
    expected_application_id: int,
    expected_user_version: int,
    required_tables: set[str] | frozenset[str],
    allowed_tables: set[str] | frozenset[str],
    anchor: dict[str, Any] | None = None,
    expected_controller_instance_id: str | None = None,
    expected_release_sha256: str | None = None,
    expected_profile_fingerprint: str | None = None,
    maximum_database_bytes: int = DEFAULT_MAX_DATABASE_BYTES,
) -> VerifiedBackup:
    """Authenticate and inspect one complete private backup bundle.

    Older generations are accepted only as recovery input and the returned object
    is always marked ``requires_reconciliation``.  A generation newer than the
    supplied committed anchor is a split-brain condition and is rejected.
    """
    if type(maximum_database_bytes) is not int or maximum_database_bytes < 1:
        raise ValueError("maximum database bytes must be a positive integer")
    (
        expected_application_id,
        expected_user_version,
        required,
        allowed,
    ) = _recovery_constraints(
        expected_application_id,
        expected_user_version,
        required_tables,
        allowed_tables,
    )
    expected_instance = (
        None
        if expected_controller_instance_id is None
        else _require_uuid(
            expected_controller_instance_id, "expected_controller_instance_id"
        )
    )
    expected_release = (
        None
        if expected_release_sha256 is None
        else _require_digest(expected_release_sha256, "expected_release_sha256")
    )
    expected_profile = (
        None
        if expected_profile_fingerprint is None
        else _require_digest(
            expected_profile_fingerprint, "expected_profile_fingerprint"
        )
    )
    current_anchor: dict[str, Any] | None = None
    if anchor is not None:
        current_anchor = validate_anchor(anchor)
        if current_anchor["schema"] != RECOVERY_SCHEMA:
            raise RecoveryError(
                "legacy recovery anchor must be explicitly upgraded before backup verification"
            )
        if current_anchor["phase"] != "committed":
            raise RecoveryError("backup verification requires a committed anchor")
    bundle = Path(bundle_path)
    _require_private_directory(bundle)
    with os.scandir(bundle) as iterator:
        entries = {entry.name: entry for entry in iterator}
    if set(entries) != {DATABASE_FILENAME, MANIFEST_FILENAME}:
        raise RecoveryPathError("backup bundle must contain exactly controller.db and manifest.json")
    for entry in entries.values():
        if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
            raise RecoveryPathError("backup bundle contains a non-regular entry")
    manifest, manifest_sha256 = _load_backup_manifest_with_digest(
        bundle / MANIFEST_FILENAME, key
    )
    database_meta = manifest["database"]
    if int(database_meta["size_bytes"]) > maximum_database_bytes:
        raise RecoveryPathError("manifest database size exceeds the configured limit")
    if int(database_meta["application_id"]) != expected_application_id:
        raise RecoverySemanticError(
            "backup manifest application_id does not match the trusted constraint"
        )
    if int(database_meta["user_version"]) != expected_user_version:
        raise RecoverySemanticError(
            "backup manifest user_version does not match the trusted constraint"
        )
    inspection = inspect_controller_database(
        bundle / DATABASE_FILENAME,
        maximum_bytes=maximum_database_bytes,
        expected_application_id=expected_application_id,
        expected_user_version=expected_user_version,
        required_tables=required,
        allowed_tables=allowed,
        require_recovery_state=True,
        require_state_hashes=True,
    )
    if inspection.sha256 != database_meta["sha256"] or inspection.size_bytes != database_meta["size_bytes"]:
        raise RecoveryAuthenticationError("backup database hash or size does not match the manifest")
    if (
        inspection.controller_instance_id != manifest["controller_instance_id"]
        or inspection.recovery_generation != manifest["recovery_generation"]
        or inspection.backup_sequence != manifest["backup_sequence"]
        or inspection.state_hashes != manifest["state_hashes"]
    ):
        raise RecoverySemanticError("backup database state does not match the signed manifest")
    _require_release_state_match(inspection, manifest["release"])
    if expected_instance is not None and manifest["controller_instance_id"] != expected_instance:
        raise RecoveryAuthenticationError("backup belongs to another controller instance")
    if expected_release is not None and manifest["release"]["sha256"] != expected_release:
        raise RecoveryAuthenticationError("backup release does not match the expected release")
    if expected_profile is not None and manifest["release"]["profile_fingerprint"] != expected_profile:
        raise RecoveryAuthenticationError("backup profile does not match the expected profile")
    anchor_binding = "not-checked"
    if current_anchor is not None:
        if manifest["controller_instance_id"] != current_anchor["controller_instance_id"]:
            raise RecoveryAuthenticationError("backup and anchor controller instances differ")
        if manifest["recovery_generation"] > current_anchor["recovery_generation"]:
            raise RecoveryAuthenticationError("backup generation is newer than the protected anchor")
        anchor_binding = "historical"
        sequence = int(manifest["backup_sequence"])
        floor = int(current_anchor["backup_sequence_floor"])
        if sequence > floor:
            raise RecoveryAuthenticationError(
                "backup sequence is newer than the protected anchor"
            )
        latest = current_anchor["latest_backup"]
        if (
            latest is not None
            and manifest["recovery_generation"]
            == int(latest["recovery_generation"])
            and manifest["backup_sequence"] == int(latest["backup_sequence"])
        ):
            expected_latest = {
                "backup_id": manifest["backup_id"],
                "recovery_generation": manifest["recovery_generation"],
                "backup_sequence": manifest["backup_sequence"],
                "database_sha256": manifest["database"]["sha256"],
                "manifest_sha256": manifest_sha256,
            }
            if latest != expected_latest:
                raise RecoveryAuthenticationError(
                    "backup conflicts with the protected latest-backup binding"
                )
            anchor_binding = "latest"
    return VerifiedBackup(
        bundle=bundle,
        database=bundle / DATABASE_FILENAME,
        manifest=manifest,
        inspection=inspection,
        manifest_sha256=manifest_sha256,
        anchor_binding=anchor_binding,
    )


def advance_backup_anchor(
    path: str | Path,
    key: bytes,
    committed: dict[str, Any],
    backup: VerifiedBackup,
    *,
    updated_at_ns: int | None = None,
) -> dict[str, Any]:
    """CAS-bind one fully verified backup as the protected latest backup."""
    current = validate_anchor(committed)
    if current["schema"] != RECOVERY_SCHEMA:
        raise RecoveryError(
            "a legacy recovery anchor must be upgraded before binding backups"
        )
    if current["phase"] != "committed":
        raise RecoveryError("only a committed anchor can bind a backup")
    if not isinstance(backup, VerifiedBackup):
        raise TypeError("backup must be a VerifiedBackup")
    manifest = validate_manifest(backup.manifest)
    on_disk_manifest, on_disk_manifest_sha256 = _load_backup_manifest_with_digest(
        backup.bundle / MANIFEST_FILENAME, key
    )
    if (
        not hmac.compare_digest(
            canonical_json_bytes(on_disk_manifest),
            canonical_json_bytes(manifest),
        )
        or not hmac.compare_digest(
            on_disk_manifest_sha256, backup.manifest_sha256
        )
    ):
        raise RecoveryAuthenticationError(
            "verified backup manifest changed before anchor binding"
        )
    with open_verified_database(backup):
        pass
    if backup.inspection.sha256 != manifest["database"]["sha256"]:
        raise RecoveryAuthenticationError(
            "verified backup inspection no longer matches its manifest"
        )
    _require_digest(backup.manifest_sha256, "manifest_sha256")
    if manifest["controller_instance_id"] != current["controller_instance_id"]:
        raise RecoveryAuthenticationError(
            "backup and anchor controller instances differ"
        )
    if manifest["recovery_generation"] != current["recovery_generation"]:
        raise RecoveryAuthenticationError(
            "only a backup from the committed generation can advance the anchor"
        )
    sequence = _require_int(
        manifest["backup_sequence"], "backup_sequence", 0
    )
    if sequence <= current["backup_sequence_floor"]:
        raise AnchorConflictError(
            "backup sequence does not advance the protected floor"
        )
    replacement = {
        **current,
        "backup_sequence_floor": sequence,
        "latest_backup": {
            "backup_id": manifest["backup_id"],
            "recovery_generation": manifest["recovery_generation"],
            "backup_sequence": sequence,
            "database_sha256": manifest["database"]["sha256"],
            "manifest_sha256": backup.manifest_sha256,
        },
        "updated_at_ns": _require_int(
            time.time_ns() if updated_at_ns is None else updated_at_ns,
            "updated_at_ns",
            1,
        ),
    }
    return _transition_anchor(Path(path), key, current, replacement)
