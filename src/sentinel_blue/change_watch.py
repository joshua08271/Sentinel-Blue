"""Low-latency protected-file change notification with a portable fallback."""

from __future__ import annotations

import ctypes
import os
import select
import stat
import struct
import threading
from pathlib import Path
from typing import Any


INOTIFY_EVENT = struct.Struct("iIII")
IN_NONBLOCK = getattr(os, "O_NONBLOCK", 0x800)
IN_CLOEXEC = getattr(os, "O_CLOEXEC", 0x80000)
IN_MASK = 0x00000002 | 0x00000004 | 0x00000008 | 0x00000040 | 0x00000080
IN_MASK |= 0x00000100 | 0x00000200 | 0x00000400 | 0x00000800
IN_Q_OVERFLOW = 0x00004000
MAX_PATHS = 256


def _fingerprint(path: Path) -> tuple[Any, ...]:
    try:
        info = path.lstat()
    except OSError as exc:
        return ("missing", type(exc).__name__, getattr(exc, "errno", None))
    kind = (
        "file"
        if stat.S_ISREG(info.st_mode)
        else "symlink"
        if stat.S_ISLNK(info.st_mode)
        else "other"
    )
    return (
        kind,
        int(info.st_dev),
        int(info.st_ino),
        int(info.st_size),
        int(info.st_mode),
        int(getattr(info, "st_mtime_ns", int(info.st_mtime * 1_000_000_000))),
        int(getattr(info, "st_ctime_ns", int(info.st_ctime * 1_000_000_000))),
    )


class ChangeWatcher:
    """Wake the agent promptly while retaining periodic full-collection semantics."""

    def __init__(self, paths: list[str], poll_interval: float = 1.0):
        unique: list[Path] = []
        seen: set[str] = set()
        for raw in paths:
            value = str(raw)
            if not value or len(value) > 1024:
                continue
            path = Path(value)
            if not path.is_absolute() or value in seen:
                continue
            seen.add(value)
            unique.append(path)
            if len(unique) >= MAX_PATHS:
                break
        self.paths = unique
        self.poll_interval = max(0.1, min(float(poll_interval), 30.0))
        self.backend = "linux-inotify+fingerprint" if os.name == "posix" else "portable-fingerprint"
        self._fingerprints = {str(path): _fingerprint(path) for path in self.paths}
        self._event = threading.Event()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._changed: set[str] = set()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if not self.paths or (self._thread and self._thread.is_alive()):
            return
        self._thread = threading.Thread(target=self._run, name="sentinel-change-watch", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=max(1.0, self.poll_interval * 2))

    def wait(self, timeout: float) -> bool:
        changed = self._event.wait(max(0.0, timeout))
        if changed:
            self._event.clear()
        return changed

    def changed_paths(self) -> list[str]:
        with self._lock:
            result = sorted(self._changed)
            self._changed.clear()
        return result

    def _mark(self, paths: set[str]) -> None:
        if not paths:
            return
        with self._lock:
            self._changed.update(paths)
        self._event.set()

    def _scan(self) -> None:
        changed: set[str] = set()
        for path in self.paths:
            key = str(path)
            current = _fingerprint(path)
            if current != self._fingerprints.get(key):
                self._fingerprints[key] = current
                changed.add(key)
        self._mark(changed)

    def _open_inotify(self) -> tuple[int, dict[int, dict[str, set[str]]]]:
        if os.name != "posix":
            return -1, {}
        try:
            library = ctypes.CDLL(None, use_errno=True)
            initialize = library.inotify_init1
            add_watch = library.inotify_add_watch
        except (AttributeError, OSError):
            self.backend = "portable-fingerprint"
            return -1, {}
        initialize.argtypes = [ctypes.c_int]
        initialize.restype = ctypes.c_int
        add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        add_watch.restype = ctypes.c_int
        descriptor = int(initialize(IN_NONBLOCK | IN_CLOEXEC))
        if descriptor < 0:
            self.backend = "portable-fingerprint"
            return -1, {}
        watches: dict[int, dict[str, set[str]]] = {}
        for path in self.paths:
            try:
                parent = os.fsencode(path.parent)
                watch = int(add_watch(descriptor, parent, IN_MASK))
            except (OSError, ValueError):
                continue
            if watch >= 0:
                watches.setdefault(watch, {}).setdefault(path.name, set()).add(str(path))
        if not watches:
            os.close(descriptor)
            self.backend = "portable-fingerprint"
            return -1, {}
        return descriptor, watches

    def _consume_inotify(
        self, descriptor: int, watches: dict[int, dict[str, set[str]]]
    ) -> None:
        try:
            data = os.read(descriptor, 256 * 1024)
        except BlockingIOError:
            return
        offset = 0
        changed: set[str] = set()
        all_paths = {str(path) for path in self.paths}
        while offset + INOTIFY_EVENT.size <= len(data):
            watch, mask, _cookie, length = INOTIFY_EVENT.unpack_from(data, offset)
            offset += INOTIFY_EVENT.size
            name_bytes = data[offset : offset + length]
            offset += length
            name = os.fsdecode(name_bytes.split(b"\0", 1)[0]) if name_bytes else ""
            if mask & IN_Q_OVERFLOW:
                changed.update(all_paths)
                continue
            expected = watches.get(watch, {})
            if not name:
                for paths in expected.values():
                    changed.update(paths)
                continue
            changed.update(expected.get(name, set()))
        self._mark(changed)

    def _run(self) -> None:
        descriptor, watches = self._open_inotify()
        try:
            while not self._stop.is_set():
                if descriptor >= 0:
                    readable, _, _ = select.select([descriptor], [], [], self.poll_interval)
                    if readable:
                        self._consume_inotify(descriptor, watches)
                else:
                    self._stop.wait(self.poll_interval)
                self._scan()
        finally:
            if descriptor >= 0:
                os.close(descriptor)


__all__ = ["ChangeWatcher"]
