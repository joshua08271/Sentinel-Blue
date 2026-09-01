"""Crash-safe bounded agent telemetry spool and action idempotency journal."""

from __future__ import annotations

import os
import stat
import time
import uuid
from pathlib import Path
from typing import Any

from .json_codec import canonical_json_bytes, strict_json_loads


MAX_STATE_BYTES = 4 * 1024 * 1024
DEFAULT_ACTION_TOMBSTONE_RETENTION = 7 * 24 * 60 * 60


def _replace_with_retry(source: Path, destination: Path) -> None:
    """Atomically replace state, tolerating only bounded Windows sharing locks."""
    attempts = 8 if os.name == "nt" else 1
    for attempt in range(attempts):
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            sharing_violation = getattr(exc, "winerror", None) in {32, 33}
            if os.name != "nt" or not sharing_violation or attempt + 1 >= attempts:
                raise
            time.sleep(0.025 * (attempt + 1))


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _read_private_json(path: Path, maximum: int = MAX_STATE_BYTES) -> Any:
    if path.is_symlink() or not path.is_file():
        raise ValueError("state file is not a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("state file is invalid or exceeds its size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("state file exceeds its size limit")
    finally:
        os.close(descriptor)
    return strict_json_loads(raw, max_bytes=maximum)


def _atomic_bytes(path: Path, encoded: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValueError("state directory must not be a symbolic link")
    if path.is_symlink():
        raise ValueError("refusing to replace a symbolic-link state file")
    if len(encoded) > MAX_STATE_BYTES:
        raise ValueError("state payload exceeds its size limit")
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        # Windows refuses to replace an open file. Transfer ownership of the
        # descriptor to the file object so it is closed before os.replace().
        handle = os.fdopen(descriptor, "wb")
        descriptor = -1
        with handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        if os.name == "posix":
            os.chmod(temporary, 0o600)
        if path.is_symlink():
            raise ValueError("refusing to replace a symbolic-link state file")
        _replace_with_retry(temporary, path)
        _fsync_directory(path.parent)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_json(path: Path, payload: Any) -> None:
    encoded = canonical_json_bytes(payload, max_bytes=MAX_STATE_BYTES)
    _atomic_bytes(path, encoded)


class TelemetrySpool:
    def __init__(self, state_dir: str | Path, max_items: int = 256, max_bytes: int = 64 * 1024 * 1024):
        self.directory = Path(state_dir) / "telemetry-spool"
        if self.directory.is_symlink():
            raise ValueError("telemetry spool directory must not be a symbolic link")
        self.directory.mkdir(parents=True, exist_ok=True)
        if not self.directory.is_dir():
            raise ValueError("telemetry spool path is not a directory")
        if os.name == "posix":
            self.directory.chmod(0o700)
        self.max_items = max(1, max_items)
        self.max_bytes = max(1024, max_bytes)

    def enqueue(self, payload: dict[str, Any]) -> Path:
        item = dict(payload)
        item.setdefault("queued_at", time.time())
        path = self.directory / f"{time.time_ns():020d}-{uuid.uuid4().hex}.json"
        _atomic_json(path, item)
        self._prune()
        return path

    def pending(self, limit: int = 32) -> list[tuple[Path, dict[str, Any]]]:
        result: list[tuple[Path, dict[str, Any]]] = []
        for path in sorted(self.directory.glob("*.json"))[: max(1, limit)]:
            try:
                value = _read_private_json(path)
                if not isinstance(value, dict):
                    raise ValueError("spooled telemetry is not an object")
                result.append((path, value))
            except (OSError, ValueError):
                path.rename(path.with_suffix(".corrupt"))
                _fsync_directory(self.directory)
                self._prune_auxiliary()
        return result

    @staticmethod
    def acknowledge(path: Path) -> None:
        path.unlink(missing_ok=True)
        _fsync_directory(path.parent)

    def reject(self, path: Path, reason: str = "rejected") -> Path:
        safe_reason = "".join(
            character for character in reason if character.isalnum() or character in "-_"
        )[:32]
        destination = path.with_suffix(f".{safe_reason or 'rejected'}.rejected")
        path.replace(destination)
        _fsync_directory(path.parent)
        self._prune_auxiliary()
        return destination

    def _prune(self) -> None:
        paths = sorted(self.directory.glob("*.json"))
        total = sum(path.stat().st_size for path in paths)
        while paths and (len(paths) > self.max_items or total > self.max_bytes):
            oldest = paths.pop(0)
            try:
                size = oldest.stat().st_size
                oldest.unlink(missing_ok=True)
                total -= size
                _fsync_directory(self.directory)
            except OSError:
                break

    def _prune_auxiliary(self) -> None:
        paths = sorted([*self.directory.glob("*.rejected"), *self.directory.glob("*.corrupt")])
        for path in paths[: max(0, len(paths) - self.max_items)]:
            path.unlink(missing_ok=True)
        if len(paths) > self.max_items:
            _fsync_directory(self.directory)


class ActionJournal:
    def __init__(
        self,
        state_dir: str | Path,
        maximum: int = 1024,
        *,
        retention_seconds: float = DEFAULT_ACTION_TOMBSTONE_RETENTION,
        profile_fingerprint: str = "",
    ):
        self.path = Path(state_dir) / "action-journal.json"
        self.maximum = max(1, maximum)
        if (
            type(retention_seconds) not in {int, float}
            or not 0 <= retention_seconds <= 365 * 24 * 60 * 60
        ):
            raise ValueError("action journal retention must be between zero and one year")
        if profile_fingerprint and not self._valid_digest(profile_fingerprint):
            raise ValueError("action journal profile fingerprint must be a SHA-256 digest")
        self.retention_seconds = float(retention_seconds)
        self.profile_fingerprint = profile_fingerprint
        self.healthy = True
        self.error = ""
        self._records = self._read()

    @staticmethod
    def _valid_digest(value: Any) -> bool:
        return (
            isinstance(value, str)
            and len(value) == 64
            and all(character in "0123456789abcdef" for character in value)
        )

    @staticmethod
    def _finite_number(value: Any) -> bool:
        return (
            type(value) in {int, float}
            and value == value
            and abs(value) != float("inf")
            and abs(value) <= 2**63 - 1
        )

    def _read(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists() and not self.path.is_symlink():
            return {}
        try:
            value = _read_private_json(self.path)
            if not isinstance(value, dict):
                raise ValueError("action journal is not an object")
            for action_id, record in value.items():
                if (
                    not isinstance(action_id, str)
                    or len(action_id) > 128
                    or not isinstance(record, dict)
                    or record.get("status", "completed") not in {"in_progress", "completed"}
                ):
                    raise ValueError("action journal contains an invalid record")
                envelope_sha256 = record.get("envelope_sha256")
                if envelope_sha256 is not None and not self._valid_digest(
                    envelope_sha256
                ):
                    raise ValueError("action journal contains an invalid envelope digest")
                profile_fingerprint = record.get("profile_fingerprint", "")
                if profile_fingerprint and not self._valid_digest(profile_fingerprint):
                    raise ValueError("action journal contains an invalid profile epoch")
                for field in (
                    "started_at",
                    "completed_at",
                    "expires_at",
                    "retain_until",
                ):
                    if field in record and not self._finite_number(record[field]):
                        raise ValueError(
                            f"action journal contains an invalid {field} timestamp"
                        )
            return value
        except (OSError, ValueError) as exc:
            self.healthy = False
            self.error = f"action journal requires review: {exc}"
            return {}

    def _require_healthy(self) -> None:
        if not self.healthy:
            raise RuntimeError(self.error or "action journal is unhealthy")

    def _require_matching_envelope(
        self, record: dict[str, Any], envelope_sha256: str | None
    ) -> None:
        if envelope_sha256 is None:
            return
        if not self._valid_digest(envelope_sha256):
            raise ValueError("action envelope digest must be a lowercase SHA-256")
        recorded = record.get("envelope_sha256")
        if recorded != envelope_sha256:
            if recorded is None:
                raise RuntimeError(
                    "legacy action journal record lacks an envelope digest; "
                    "operator migration review is required"
                )
            raise RuntimeError(
                "action identifier was reused with a different envelope; refusing replay"
            )

    def record(
        self, action_id: str, envelope_sha256: str | None = None
    ) -> dict[str, Any] | None:
        self._require_healthy()
        record = self._records.get(action_id)
        if isinstance(record, dict):
            self._require_matching_envelope(record, envelope_sha256)
        return dict(record) if isinstance(record, dict) else None

    def get(
        self, action_id: str, envelope_sha256: str | None = None
    ) -> dict[str, Any] | None:
        self._require_healthy()
        record = self._records.get(action_id)
        if isinstance(record, dict):
            self._require_matching_envelope(record, envelope_sha256)
        if record and record.get("status", "completed") == "completed" and isinstance(record.get("result"), dict):
            return dict(record["result"])
        return None

    def begin(
        self,
        action_id: str,
        action_type: str,
        envelope_sha256: str | None = None,
        *,
        expires_at: float = 0.0,
        profile_fingerprint: str = "",
        now: float | None = None,
    ) -> bool:
        """Durably claim an action before any side effect can occur."""
        self._require_healthy()
        current = time.time() if now is None else now
        if not self._finite_number(current) or not self._finite_number(expires_at):
            raise ValueError("action journal timestamps must be finite")
        if envelope_sha256 is not None and not self._valid_digest(envelope_sha256):
            raise ValueError("action envelope digest must be a lowercase SHA-256")
        epoch = profile_fingerprint or self.profile_fingerprint
        if epoch and not self._valid_digest(epoch):
            raise ValueError("action journal profile fingerprint must be a SHA-256 digest")
        existing = self._records.get(action_id)
        if isinstance(existing, dict):
            self._require_matching_envelope(existing, envelope_sha256)
            return False
        self._prune_expired(float(current))
        if len(self._records) >= self.maximum:
            raise RuntimeError(
                "action journal capacity is exhausted by protected replay tombstones"
            )
        retain_until = max(float(current), float(expires_at)) + self.retention_seconds
        self._records[action_id] = {
            "status": "in_progress",
            "action_type": action_type,
            "started_at": current,
            "expires_at": expires_at,
            "retain_until": retain_until,
            "profile_fingerprint": epoch,
        }
        if envelope_sha256 is not None:
            self._records[action_id]["envelope_sha256"] = envelope_sha256
        self._commit()
        return True

    def remember(
        self,
        action_id: str,
        result: dict[str, Any],
        envelope_sha256: str | None = None,
        *,
        expires_at: float = 0.0,
        profile_fingerprint: str = "",
        now: float | None = None,
    ) -> None:
        self._require_healthy()
        current = time.time() if now is None else now
        if not self._finite_number(current) or not self._finite_number(expires_at):
            raise ValueError("action journal timestamps must be finite")
        existing = self._records.get(action_id)
        if isinstance(existing, dict):
            self._require_matching_envelope(existing, envelope_sha256)
            record = dict(existing)
        else:
            if envelope_sha256 is not None and not self._valid_digest(envelope_sha256):
                raise ValueError("action envelope digest must be a lowercase SHA-256")
            self._prune_expired(float(current))
            if len(self._records) >= self.maximum:
                raise RuntimeError(
                    "action journal capacity is exhausted by protected replay tombstones"
                )
            record = {}
        epoch = (
            profile_fingerprint
            or str(record.get("profile_fingerprint", ""))
            or self.profile_fingerprint
        )
        if epoch and not self._valid_digest(epoch):
            raise ValueError("action journal profile fingerprint must be a SHA-256 digest")
        prior_expiry = record.get("expires_at", 0.0)
        prior_retain_until = record.get("retain_until", 0.0)
        retain_until = max(
            float(current) + self.retention_seconds,
            float(expires_at) + self.retention_seconds,
            float(prior_expiry) + self.retention_seconds,
            float(prior_retain_until),
        )
        record.update(
            {
                "status": "completed",
                "completed_at": current,
                "expires_at": max(float(expires_at), float(prior_expiry)),
                "retain_until": retain_until,
                "profile_fingerprint": epoch,
                "result": result,
            }
        )
        if envelope_sha256 is not None:
            record["envelope_sha256"] = envelope_sha256
        self._records[action_id] = record
        self._commit()

    def _prune_expired(self, now: float) -> None:
        removable: list[str] = []
        for action_id, record in self._records.items():
            if record.get("status", "completed") != "completed":
                continue
            # A profile fingerprint is an action-authority epoch.  Current-epoch
            # tombstones are never discarded merely to make room; exhaustion
            # closes the action gate.  Old-epoch and unbound test records become
            # eligible only after their authorization and recent-review window.
            if (
                self.profile_fingerprint
                and record.get("profile_fingerprint") == self.profile_fingerprint
            ):
                continue
            retain_until = record.get("retain_until")
            if retain_until is None:
                completed_at = record.get("completed_at")
                if not self._finite_number(completed_at):
                    continue
                retain_until = float(completed_at) + self.retention_seconds
            if self._finite_number(retain_until) and float(retain_until) <= now:
                removable.append(action_id)
        if removable:
            for action_id in removable:
                del self._records[action_id]
            self._commit()

    def _commit(self) -> None:
        _atomic_json(self.path, self._records)


class SequenceCounter:
    def __init__(self, state_dir: str | Path):
        self.path = Path(state_dir) / "sequence.json"
        self.healthy = True
        self.error = ""
        if not self.path.exists() and not self.path.is_symlink():
            self.value = 0
            return
        try:
            value = _read_private_json(self.path, 64 * 1024)
            if not isinstance(value, dict) or type(value.get("sequence")) is not int:
                raise ValueError("sequence state is invalid")
            self.value = int(value["sequence"])
            if not 0 <= self.value < 2**63 - 1:
                raise ValueError("sequence state is outside its accepted range")
        except (OSError, ValueError) as exc:
            self.value = 0
            self.healthy = False
            self.error = f"sequence state requires review: {exc}"

    def next(self) -> int:
        if not self.healthy:
            raise RuntimeError(self.error or "sequence state is unhealthy")
        self.value += 1
        _atomic_json(self.path, {"sequence": self.value})
        return self.value


class AgentProcessLock:
    """Hold one operating-system lock per agent state directory."""

    def __init__(self, state_dir: str | Path):
        self.path = Path(state_dir) / "agent.lock"
        self._descriptor: int | None = None

    def acquire(self) -> "AgentProcessLock":
        if self._descriptor is not None:
            return self
        if self.path.is_symlink():
            raise ValueError("agent process lock must not be a symbolic link")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("agent process lock is not a regular file")
            os.lseek(descriptor, 0, os.SEEK_SET)
            if os.name == "nt":
                import msvcrt

                if info.st_size == 0:
                    os.write(descriptor, b"0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.ftruncate(descriptor, 0)
            os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
            os.fsync(descriptor)
        except (OSError, ValueError) as exc:
            os.close(descriptor)
            if isinstance(exc, ValueError):
                raise
            raise RuntimeError(
                "another Sentinel Blue agent already owns this state directory"
            ) from exc
        self._descriptor = descriptor
        return self

    def close(self) -> None:
        descriptor = self._descriptor
        if descriptor is None:
            return
        self._descriptor = None
        try:
            if os.name == "nt":
                import msvcrt

                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def __enter__(self) -> "AgentProcessLock":
        return self.acquire()

    def __exit__(self, *_args: Any) -> None:
        self.close()


def write_private_json(path: str | Path, payload: Any) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    _atomic_json(destination, payload)


def read_private_json(path: str | Path, maximum: int = MAX_STATE_BYTES) -> Any:
    return _read_private_json(Path(path), maximum)


def write_private_text(path: str | Path, value: str) -> None:
    if not isinstance(value, str):
        raise ValueError("private text value must be a string")
    _atomic_bytes(Path(path), value.encode("utf-8"))


def read_private_text(path: str | Path, maximum: int = MAX_STATE_BYTES) -> str:
    target = Path(path)
    if target.is_symlink() or not target.is_file():
        raise ValueError("private text file is not a regular non-symlink file")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(target, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("private text file is invalid or exceeds its size limit")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(maximum + 1)
        if len(raw) > maximum:
            raise ValueError("private text file exceeds its size limit")
    finally:
        os.close(descriptor)
    return raw.decode("utf-8")


def remove_private_file(path: str | Path) -> None:
    target = Path(path)
    if target.is_symlink():
        raise ValueError("refusing to remove a symbolic-link state file")
    if target.exists() and not target.is_file():
        raise ValueError("state path is not a regular file")
    target.unlink(missing_ok=True)
    _fsync_directory(target.parent)
