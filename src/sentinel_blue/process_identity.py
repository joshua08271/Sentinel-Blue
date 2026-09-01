"""Race-resistant process identities and verified process control.

Containment must never treat a numeric PID as an authority.  This module binds
the PID to immutable kernel/process metadata and performs the final comparison
while holding a pidfd (Linux) or process handle (Windows) immediately before a
signal is delivered.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import platform
import re
import signal
import stat
from pathlib import Path
from typing import Any


PROCESS_IDENTITY_SCHEMA = "sentinel-process-v1"
PROCESS_IDENTITY_FIELDS = frozenset(
    {
        "schema",
        "platform",
        "process_id",
        "boot_id",
        "start_time",
        "executable_path",
        "executable_file_id",
        "user_id",
        "kernel_session_id",
    }
)
_DIGITS = re.compile(r"^[0-9]{1,32}$")
_FILE_ID = re.compile(r"^[A-Za-z0-9_.:-]{3,192}$")


class ProcessIdentityMismatch(PermissionError):
    """The numeric PID no longer names the authorized process."""


def validate_process_identity(value: Any) -> dict[str, Any]:
    """Return a normalized, exact process identity or fail closed."""
    if not isinstance(value, dict) or set(value) != set(PROCESS_IDENTITY_FIELDS):
        raise ValueError("process identity has an incomplete or unknown field set")
    schema = value.get("schema")
    system = value.get("platform")
    process_id = value.get("process_id")
    if schema != PROCESS_IDENTITY_SCHEMA:
        raise ValueError("process identity schema is unsupported")
    if system not in {"linux", "windows"}:
        raise ValueError("process identity platform is unsupported")
    if type(process_id) is not int or not 3 <= process_id <= 2**31 - 1:
        raise ValueError("process identity has an unsafe process ID")
    result: dict[str, Any] = {
        "schema": PROCESS_IDENTITY_SCHEMA,
        "platform": str(system),
        "process_id": process_id,
    }
    for field, maximum in (
        ("boot_id", 256),
        ("start_time", 32),
        ("executable_path", 2048),
        ("executable_file_id", 192),
        ("user_id", 256),
        ("kernel_session_id", 64),
    ):
        item = value.get(field)
        if (
            not isinstance(item, str)
            or not item
            or len(item) > maximum
            or "\x00" in item
            or any(ord(character) < 32 for character in item)
        ):
            raise ValueError(f"process identity {field} is missing or invalid")
        result[field] = item
    if result["boot_id"] == "unknown":
        raise ValueError("process identity requires an exact host boot identifier")
    if not _DIGITS.fullmatch(result["start_time"]):
        raise ValueError("process identity start time is invalid")
    if not _FILE_ID.fullmatch(result["executable_file_id"]):
        raise ValueError("process identity executable file identifier is invalid")
    if not _DIGITS.fullmatch(result["kernel_session_id"]):
        raise ValueError("process identity kernel session identifier is invalid")
    return result


def _read_proc_text(directory_descriptor: int, name: str, maximum: int) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(name, flags, dir_fd=directory_descriptor)
    try:
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(maximum + 1)
        if len(raw) > maximum:
            raise OSError(f"process {name} metadata exceeds its accepted size")
        return raw.decode("utf-8", "strict")
    finally:
        os.close(descriptor)


def _linux_stat_fields(raw: str) -> list[str]:
    close = raw.rfind(")")
    fields = raw[close + 2 :].split() if close >= 2 else []
    # Fields begin with Linux /proc stat field 3 (state).  Field 22
    # (starttime) is therefore index 19.
    if len(fields) <= 19 or not fields[19].isdigit():
        raise OSError("Linux process identity metadata is incomplete")
    return fields


def _linux_proc_path(process_id: int) -> Path:
    """Resolve a PID even when /proc is mounted from an outer PID namespace."""
    direct = Path("/proc") / str(process_id)
    if direct.is_dir():
        return direct
    matches: list[Path] = []
    inspected = 0
    try:
        entries = Path("/proc").iterdir()
    except OSError as exc:
        raise OSError("Linux process filesystem is unavailable") from exc
    for entry in entries:
        if not entry.name.isdigit():
            continue
        inspected += 1
        if inspected > 131_072:
            raise OSError("Linux PID namespace mapping exceeds its safety bound")
        try:
            status = (entry / "status").read_text(
                encoding="utf-8", errors="strict"
            )
        except OSError:
            continue
        for line in status.splitlines():
            if not line.startswith("NSpid:"):
                continue
            identifiers = line.split()[1:]
            if identifiers and identifiers[-1] == str(process_id):
                matches.append(entry)
            break
        if len(matches) > 1:
            raise OSError("Linux PID namespace identity is ambiguous")
    if len(matches) != 1:
        raise ProcessLookupError(process_id, "Linux process identity is unavailable")
    return matches[0]


def _linux_process_identity(process_id: int, boot_id: str | None) -> dict[str, Any]:
    proc_path = _linux_proc_path(process_id)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_descriptor = os.open(proc_path, flags)
    try:
        before = _linux_stat_fields(_read_proc_text(directory_descriptor, "stat", 64 * 1024))
        status = _read_proc_text(directory_descriptor, "status", 256 * 1024)
        effective_uid = ""
        for line in status.splitlines():
            if line.startswith("Uid:"):
                identifiers = line.split()[1:]
                if len(identifiers) >= 2 and all(item.isdigit() for item in identifiers[:2]):
                    effective_uid = f"uid:{identifiers[0]}:{identifiers[1]}"
                break
        if not effective_uid:
            raise OSError("Linux process user identity is unavailable")
        executable_path = os.readlink("exe", dir_fd=directory_descriptor)
        if not executable_path or "\x00" in executable_path:
            raise OSError("Linux process executable path is unavailable")
        executable_descriptor = os.open(
            "exe",
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
            dir_fd=directory_descriptor,
        )
        try:
            executable_info = os.fstat(executable_descriptor)
            if not stat.S_ISREG(executable_info.st_mode):
                raise OSError("Linux process executable is not a regular file")
        finally:
            os.close(executable_descriptor)
        after = _linux_stat_fields(_read_proc_text(directory_descriptor, "stat", 64 * 1024))
        if (before[19], before[3]) != (after[19], after[3]):
            raise OSError("Linux process identity changed during inspection")
    finally:
        os.close(directory_descriptor)
    kernel_boot = Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="utf-8", errors="strict"
    ).strip()
    if not kernel_boot or kernel_boot == "unknown" or len(kernel_boot) > 256:
        raise OSError("Linux boot identity is unavailable")
    if boot_id is not None and boot_id != kernel_boot:
        raise OSError("Linux process observation belongs to a different host boot")
    return validate_process_identity(
        {
            "schema": PROCESS_IDENTITY_SCHEMA,
            "platform": "linux",
            "process_id": process_id,
            "boot_id": kernel_boot,
            "start_time": before[19],
            "executable_path": os.path.normpath(executable_path),
            "executable_file_id": f"dev:{executable_info.st_dev:x}:ino:{executable_info.st_ino:x}",
            "user_id": effective_uid,
            "kernel_session_id": before[3],
        }
    )


def _windows_filetime_ticks(value: Any) -> int:
    return (int(value.dwHighDateTime) << 32) | int(value.dwLowDateTime)


def _windows_process_identity_from_handle(
    handle: Any, process_id: int, boot_id: str
) -> dict[str, Any]:  # pragma: no cover - exercised on the native Windows gate
    from ctypes import wintypes

    if not boot_id or boot_id == "unknown" or len(boot_id) > 256:
        raise OSError("Windows process identity requires an exact host boot identifier")
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)

    class FileTime(ctypes.Structure):
        _fields_ = [("dwLowDateTime", wintypes.DWORD), ("dwHighDateTime", wintypes.DWORD)]

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", FileTime),
            ("ftLastAccessTime", FileTime),
            ("ftLastWriteTime", FileTime),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    get_process_id = kernel32.GetProcessId
    get_process_id.argtypes = [wintypes.HANDLE]
    get_process_id.restype = wintypes.DWORD
    if int(get_process_id(handle)) != process_id:
        raise OSError("Windows process handle does not match the requested process ID")
    get_times = kernel32.GetProcessTimes
    get_times.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
        ctypes.POINTER(FileTime),
    ]
    get_times.restype = wintypes.BOOL
    created = FileTime()
    exited = FileTime()
    kernel = FileTime()
    user = FileTime()
    if not get_times(handle, ctypes.byref(created), ctypes.byref(exited), ctypes.byref(kernel), ctypes.byref(user)):
        raise OSError(ctypes.get_last_error(), "Windows process creation time is unavailable")

    query_image = kernel32.QueryFullProcessImageNameW
    query_image.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    query_image.restype = wintypes.BOOL
    capacity = wintypes.DWORD(32768)
    buffer = ctypes.create_unicode_buffer(capacity.value)
    if not query_image(handle, 0, buffer, ctypes.byref(capacity)):
        raise OSError(ctypes.get_last_error(), "Windows process executable path is unavailable")
    executable_path = ntpath.normpath(buffer.value)
    if not executable_path or "\x00" in executable_path:
        raise OSError("Windows process executable path is invalid")

    session_value = wintypes.DWORD()
    process_to_session = kernel32.ProcessIdToSessionId
    process_to_session.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    process_to_session.restype = wintypes.BOOL
    if not process_to_session(process_id, ctypes.byref(session_value)):
        raise OSError(ctypes.get_last_error(), "Windows process session identity is unavailable")

    token = wintypes.HANDLE()
    open_token = advapi32.OpenProcessToken
    open_token.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    open_token.restype = wintypes.BOOL
    if not open_token(handle, 0x0008, ctypes.byref(token)):
        raise OSError(ctypes.get_last_error(), "Windows process user token is unavailable")
    try:
        needed = wintypes.DWORD()
        get_token = advapi32.GetTokenInformation
        get_token.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
        get_token.restype = wintypes.BOOL
        get_token(token, 1, None, 0, ctypes.byref(needed))
        if needed.value <= ctypes.sizeof(ctypes.c_void_p) or needed.value > 64 * 1024:
            raise OSError("Windows process user identity has an invalid size")
        token_buffer = ctypes.create_string_buffer(needed.value)
        if not get_token(token, 1, token_buffer, needed, ctypes.byref(needed)):
            raise OSError(ctypes.get_last_error(), "Windows process user identity is unavailable")
        sid_pointer = ctypes.c_void_p.from_buffer(token_buffer).value
        if not sid_pointer:
            raise OSError("Windows process user SID is unavailable")
        sid_text = wintypes.LPWSTR()
        convert_sid = advapi32.ConvertSidToStringSidW
        convert_sid.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
        convert_sid.restype = wintypes.BOOL
        if not convert_sid(sid_pointer, ctypes.byref(sid_text)):
            raise OSError(ctypes.get_last_error(), "Windows process user SID could not be encoded")
        try:
            user_id = str(sid_text.value or "")
        finally:
            kernel32.LocalFree(sid_text)
    finally:
        kernel32.CloseHandle(token)

    create_file = kernel32.CreateFileW
    create_file.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    create_file.restype = wintypes.HANDLE
    file_handle = create_file(executable_path, 0x80, 0x1 | 0x2 | 0x4, None, 3, 0x80, None)
    invalid_handle = ctypes.c_void_p(-1).value
    if not file_handle or int(file_handle) == int(invalid_handle):
        raise OSError(ctypes.get_last_error(), "Windows process executable identity is unavailable")
    try:
        information = ByHandleFileInformation()
        get_information = kernel32.GetFileInformationByHandle
        get_information.argtypes = [wintypes.HANDLE, ctypes.POINTER(ByHandleFileInformation)]
        get_information.restype = wintypes.BOOL
        if not get_information(file_handle, ctypes.byref(information)):
            raise OSError(ctypes.get_last_error(), "Windows executable file identity is unavailable")
    finally:
        kernel32.CloseHandle(file_handle)
    file_index = (int(information.nFileIndexHigh) << 32) | int(information.nFileIndexLow)
    return validate_process_identity(
        {
            "schema": PROCESS_IDENTITY_SCHEMA,
            "platform": "windows",
            "process_id": process_id,
            "boot_id": boot_id,
            "start_time": str(_windows_filetime_ticks(created)),
            "executable_path": executable_path,
            "executable_file_id": f"vol:{int(information.dwVolumeSerialNumber):x}:file:{file_index:x}",
            "user_id": user_id,
            "kernel_session_id": str(int(session_value.value)),
        }
    )


def inspect_process_identity(process_id: int, *, boot_id: str | None = None) -> dict[str, Any]:
    """Inspect one process using immutable metadata; weak PID-only fallbacks are forbidden."""
    if type(process_id) is not int or not 3 <= process_id <= 2**31 - 1:
        raise ValueError("process identity requires a safe positive process ID")
    system = platform.system().casefold()
    if system != "windows":
        return _linux_process_identity(process_id, boot_id)
    if not isinstance(boot_id, str):
        raise OSError("Windows process identity requires an exact host boot identifier")
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    handle = open_process(0x1000 | 0x00100000, False, process_id)
    if not handle:
        raise OSError(ctypes.get_last_error(), "Windows process identity handle could not be opened")
    try:
        return _windows_process_identity_from_handle(handle, process_id, boot_id)
    finally:
        kernel32.CloseHandle(handle)


def signal_verified_process(
    process_id: int,
    expected_identity: dict[str, Any],
    operation: str,
) -> None:
    """Revalidate and signal the exact process while holding a native identity handle."""
    expected = validate_process_identity(expected_identity)
    if expected["process_id"] != process_id:
        raise ValueError("process ID does not match its immutable identity")
    if operation not in {"suspend", "resume"}:
        raise ValueError("unsupported verified process operation")
    system = platform.system().casefold()
    if system != "windows":
        if expected["platform"] != "linux":
            raise ValueError("process identity platform does not match this host")
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise OSError("Linux pidfd process control is unavailable; refusing PID-only signaling")
        descriptor = os.pidfd_open(process_id, 0)
        try:
            current = _linux_process_identity(process_id, expected["boot_id"])
            if current != expected:
                raise ProcessIdentityMismatch(
                    "process identity changed; operator review is required"
                )
            signal.pidfd_send_signal(
                descriptor, signal.SIGSTOP if operation == "suspend" else signal.SIGCONT
            )
        finally:
            os.close(descriptor)
        return
    if expected["platform"] != "windows":
        raise ValueError("process identity platform does not match this host")
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    ntdll = ctypes.WinDLL("ntdll.dll")
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    handle = open_process(0x0800 | 0x1000 | 0x00100000, False, process_id)
    if not handle:
        raise OSError(ctypes.get_last_error(), "Windows process control handle could not be opened")
    try:  # pragma: no cover - exercised on the native Windows gate
        current = _windows_process_identity_from_handle(
            handle, process_id, expected["boot_id"]
        )
        if current != expected:
            raise ProcessIdentityMismatch(
                "process identity changed; operator review is required"
            )
        procedure = ntdll.NtSuspendProcess if operation == "suspend" else ntdll.NtResumeProcess
        procedure.argtypes = [wintypes.HANDLE]
        procedure.restype = ctypes.c_long
        status = int(procedure(handle))
        if status != 0:
            raise OSError(f"Windows {operation} operation returned NTSTATUS {status:#x}")
    finally:
        kernel32.CloseHandle(handle)
