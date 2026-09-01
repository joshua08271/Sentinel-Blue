"""Agent-local, reversible restore points for approved security-critical files."""

from __future__ import annotations

import hashlib
import hmac
import functools
import base64
import ctypes
import json
import ntpath
import os
import re
import secrets
import stat
import subprocess
import threading
import time
import uuid
from contextlib import contextmanager, nullcontext
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .json_codec import canonical_json_bytes, strict_json_loads
from .probes import run_probes
from .config_validation import validate_restored_configuration


SHA256 = re.compile(r"^[0-9a-f]{64}$")
TRANSACTION_ID = re.compile(r"^[0-9a-f-]{36}$")
MAX_FILES = 256
MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_XATTRS = 128
MAX_XATTR_BYTES = 64 * 1024
MAX_WINDOWS_SECURITY_DESCRIPTOR_BYTES = 64 * 1024
MAX_WINDOWS_SECURITY_DESCRIPTOR_TEXT = ((MAX_WINDOWS_SECURITY_DESCRIPTOR_BYTES + 2) // 3) * 4
MAX_TRANSACTION_BYTES = 512 * 1024
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
WINDOWS_REPARSE_POINT_ATTRIBUTE = 0x00000400
WINDOWS_SECURITY_DESCRIPTOR_VERSION = 3
WINDOWS_BACKUP_SECURITY_INFORMATION = 0x00010000
WINDOWS_OWNER_SECURITY_INFORMATION = 0x00000001
WINDOWS_GROUP_SECURITY_INFORMATION = 0x00000002
WINDOWS_DACL_SECURITY_INFORMATION = 0x00000004
WINDOWS_SACL_SECURITY_INFORMATION = 0x00000008
WINDOWS_CORE_SECURITY_INFORMATION = (
    WINDOWS_OWNER_SECURITY_INFORMATION
    | WINDOWS_GROUP_SECURITY_INFORMATION
    | WINDOWS_DACL_SECURITY_INFORMATION
    | WINDOWS_SACL_SECURITY_INFORMATION
)
WINDOWS_SECURITY_INFORMATION = (
    WINDOWS_BACKUP_SECURITY_INFORMATION | WINDOWS_CORE_SECURITY_INFORMATION
)
WINDOWS_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
WINDOWS_UNPROTECTED_DACL_SECURITY_INFORMATION = 0x20000000
WINDOWS_PROTECTED_SACL_SECURITY_INFORMATION = 0x40000000
WINDOWS_UNPROTECTED_SACL_SECURITY_INFORMATION = 0x10000000
WINDOWS_SE_DACL_PROTECTED = 0x1000
WINDOWS_SE_SACL_PROTECTED = 0x2000
WINDOWS_SE_RM_CONTROL_VALID = 0x4000
# Target objects are regular files, so ACL auto-inheritance bookkeeping cannot
# govern children. ACE inheritance flags are still compared byte-for-byte.
WINDOWS_SEMANTIC_CONTROL_MASK = (
    WINDOWS_SE_DACL_PROTECTED | WINDOWS_SE_SACL_PROTECTED
)
WINDOWS_FILE_ATTRIBUTE_READONLY = 0x00000001
WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
WINDOWS_FILE_ATTRIBUTE_NORMAL = 0x00000080
WINDOWS_FILE_LIST_DIRECTORY = 0x00000001
WINDOWS_FILE_TRAVERSE = 0x00000020
WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
WINDOWS_DELETE = 0x00010000
WINDOWS_READ_CONTROL = 0x00020000
WINDOWS_WRITE_DAC = 0x00040000
WINDOWS_WRITE_OWNER = 0x00080000
WINDOWS_SYNCHRONIZE = 0x00100000
WINDOWS_ACCESS_SYSTEM_SECURITY = 0x01000000
WINDOWS_GENERIC_READ = 0x80000000
WINDOWS_GENERIC_WRITE = 0x40000000
WINDOWS_FILE_SHARE_READ = 0x00000001
WINDOWS_FILE_SHARE_WRITE = 0x00000002
WINDOWS_FILE_SHARE_DELETE = 0x00000004
WINDOWS_CREATE_NEW = 1
WINDOWS_OPEN_EXISTING = 3
WINDOWS_FILE_FLAG_WRITE_THROUGH = 0x80000000
WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
WINDOWS_FILE_BASIC_INFO_CLASS = 0
WINDOWS_FILE_RENAME_INFO_CLASS = 3
WINDOWS_FILE_DISPOSITION_INFO_CLASS = 4
WINDOWS_VOLUME_NAME_GUID = 0x00000001
WINDOWS_ERROR_FILE_NOT_FOUND = 2
WINDOWS_ERROR_PATH_NOT_FOUND = 3
WINDOWS_ERROR_FILE_EXISTS = 80
WINDOWS_ERROR_ALREADY_EXISTS = 183
WINDOWS_TEMP_RECORD_LIMIT = 256
WINDOWS_TEMP_RECORD_BYTES = 4096
WINDOWS_TEMP_KEY_BYTES = 32
WINDOWS_TEMP_RECORD = re.compile(r"^[0-9a-f]{32}\.json$")
_WINDOWS_PRIVILEGE_LOCK = threading.RLock()
_WINDOWS_EXPECTED_UNSPECIFIED = object()


class _WindowsFileTime(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


class _WindowsByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTime", _WindowsFileTime),
        ("ftLastAccessTime", _WindowsFileTime),
        ("ftLastWriteTime", _WindowsFileTime),
        ("dwVolumeSerialNumber", ctypes.c_uint32),
        ("nFileSizeHigh", ctypes.c_uint32),
        ("nFileSizeLow", ctypes.c_uint32),
        ("nNumberOfLinks", ctypes.c_uint32),
        ("nFileIndexHigh", ctypes.c_uint32),
        ("nFileIndexLow", ctypes.c_uint32),
    ]


class _WindowsFileBasicInformation(ctypes.Structure):
    _fields_ = [
        ("CreationTime", ctypes.c_int64),
        ("LastAccessTime", ctypes.c_int64),
        ("LastWriteTime", ctypes.c_int64),
        ("ChangeTime", ctypes.c_int64),
        ("FileAttributes", ctypes.c_uint32),
    ]


class _WindowsRenameChoice(ctypes.Union):
    _fields_ = [("ReplaceIfExists", ctypes.c_ubyte), ("Flags", ctypes.c_uint32)]


class _WindowsFileDispositionInformation(ctypes.Structure):
    # FILE_DISPOSITION_INFO uses BOOLEAN, which is one byte rather than Win32 BOOL.
    _fields_ = [("DeleteFile", ctypes.c_ubyte)]


class _WindowsFileRenameInformationHeader(ctypes.Structure):
    """Fixed Win32 FILE_RENAME_INFO footprint, including FileName[1]."""

    _anonymous_ = ("choice",)
    _fields_ = [
        ("choice", _WindowsRenameChoice),
        ("RootDirectory", ctypes.c_void_p),
        ("FileNameLength", ctypes.c_uint32),
        ("FileName", ctypes.c_uint16 * 1),
    ]


def _windows_file_rename_information(
    parent_handle,
    target_name: str,
    *,
    replace_if_exists: bool = True,
):
    """Build an ABI-correct variable-length FILE_RENAME_INFO value."""
    root_value = int(getattr(parent_handle, "value", parent_handle) or 0)
    if not isinstance(target_name, str) or not target_name or "\x00" in target_name:
        raise ValueError("Windows restoration target has an unsafe file name")
    if root_value:
        if (
            target_name in {".", ".."}
            or any(character in target_name for character in "\\/:")
        ):
            raise ValueError("Windows restoration target has an unsafe file name")
    elif (
        len(target_name) > 32767
        or not re.match(
            r"^\\\\\?\\Volume\{[0-9A-Fa-f-]{36}\}\\[^\x00]+$",
            target_name,
        )
    ):
        raise ValueError("Windows restoration target is not a canonical volume path")
    encoded = target_name.encode("utf-16-le")

    # SetFileInformationByHandle requires sizeof(FILE_RENAME_INFO) plus
    # FileNameLength. Allocate enough storage for that documented footprint,
    # including the structure's inline FileName[1] and native tail padding.
    required_size = ctypes.sizeof(_WindowsFileRenameInformationHeader) + len(encoded)
    tail_bytes = required_size - _WindowsFileRenameInformationHeader.FileName.offset
    units = (tail_bytes + ctypes.sizeof(ctypes.c_uint16) - 1) // ctypes.sizeof(
        ctypes.c_uint16
    )

    class FileRenameInformation(ctypes.Structure):
        _anonymous_ = ("choice",)
        _fields_ = [
            ("choice", _WindowsRenameChoice),
            ("RootDirectory", ctypes.c_void_p),
            ("FileNameLength", ctypes.c_uint32),
            ("FileName", ctypes.c_uint16 * units),
        ]

    information = FileRenameInformation()
    information.ReplaceIfExists = 1 if replace_if_exists else 0
    information.RootDirectory = root_value
    information.FileNameLength = len(encoded)
    ctypes.memmove(
        ctypes.addressof(information) + FileRenameInformation.FileName.offset,
        encoded,
        len(encoded),
    )
    return information


def _windows_file_rename_information_size(information) -> int:
    """Return the documented minimum Win32 FILE_RENAME_INFO buffer size."""
    file_name_length = int(information.FileNameLength)
    size = ctypes.sizeof(_WindowsFileRenameInformationHeader) + file_name_length
    if size > ctypes.sizeof(information):
        raise ValueError("Windows restoration rename information is truncated")
    return size


def _windows_path_components(path: Path) -> tuple[str, list[str], str]:
    """Return a local drive root, parent components, and leaf without resolving names."""
    raw = str(path)
    if not raw or "\x00" in raw or len(raw) > 1024 or raw.startswith(("\\\\", "//")):
        raise ValueError(
            "Windows restoration supports local filesystem paths without namespace or stream syntax"
        )
    drive, tail = ntpath.splitdrive(raw)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith(("\\", "/")):
        raise ValueError("Windows restoration path must be an absolute local drive path")
    if ":" in tail:
        raise ValueError(
            "Windows restoration supports local filesystem paths without namespace or stream syntax"
        )
    tail = tail.replace("/", "\\")
    if tail.endswith("\\"):
        raise ValueError("Windows restoration path must identify a file")
    components = tail[1:].split("\\")
    forbidden = set('<>:"|?*')
    reserved = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\$|CONOUT\$)(?:\..*)?$", re.I)
    for component in components:
        if (
            not component
            or component in {".", ".."}
            or component[-1] in {" ", "."}
            or any(ord(character) < 32 or character in forbidden for character in component)
            or reserved.fullmatch(component)
        ):
            raise ValueError("Windows restoration path contains an unsafe component")
    return f"{drive.upper()}\\", components[:-1], components[-1]


def _windows_privilege_fail_stop() -> None:
    """Terminate if a temporary Windows privilege cannot be safely withdrawn."""
    os._exit(70)


@contextmanager
def _windows_privileges_unlocked(*names: str):
    """Attach a disposable privileged copy of this thread's effective token."""
    import ctypes
    from ctypes import wintypes

    class Luid(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LuidAndAttributes(ctypes.Structure):
        _fields_ = [("Luid", Luid), ("Attributes", wintypes.DWORD)]

    class TokenPrivileges(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD), ("Privileges", LuidAndAttributes * 1)]

    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    source_token = wintypes.HANDLE()
    scoped_token = wintypes.HANDLE()
    open_thread_token = advapi32.OpenThreadToken
    open_thread_token.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.BOOL,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    open_thread_token.restype = wintypes.BOOL
    open_process_token = advapi32.OpenProcessToken
    open_process_token.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    open_process_token.restype = wintypes.BOOL
    get_thread = kernel32.GetCurrentThread
    get_thread.argtypes = []
    get_thread.restype = wintypes.HANDLE
    get_process = kernel32.GetCurrentProcess
    get_process.argtypes = []
    get_process.restype = wintypes.HANDLE
    get_thread_id = kernel32.GetCurrentThreadId
    get_thread_id.argtypes = []
    get_thread_id.restype = wintypes.DWORD
    duplicate_token = advapi32.DuplicateTokenEx
    duplicate_token.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    duplicate_token.restype = wintypes.BOOL
    set_thread_token = advapi32.SetThreadToken
    set_thread_token.argtypes = [ctypes.POINTER(wintypes.HANDLE), wintypes.HANDLE]
    set_thread_token.restype = wintypes.BOOL
    revert_to_self = advapi32.RevertToSelf
    revert_to_self.argtypes = []
    revert_to_self.restype = wintypes.BOOL
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    lookup = advapi32.LookupPrivilegeValueW
    lookup.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, ctypes.POINTER(Luid)]
    lookup.restype = wintypes.BOOL
    adjust = advapi32.AdjustTokenPrivileges
    adjust.argtypes = [
        wintypes.HANDLE,
        wintypes.BOOL,
        ctypes.POINTER(TokenPrivileges),
        wintypes.DWORD,
        ctypes.POINTER(TokenPrivileges),
        ctypes.POINTER(wintypes.DWORD),
    ]
    adjust.restype = wintypes.BOOL
    entry_thread_id = int(get_thread_id())
    had_thread_token = False
    attached = False
    try:
        if open_thread_token(
            get_thread(), 0x0002 | 0x0004 | 0x0008, True, ctypes.byref(source_token)
        ):
            had_thread_token = True
        else:
            error = ctypes.get_last_error()
            if error != 1008:
                raise OSError(error, "Windows thread token could not be opened")
            if not open_process_token(
                get_process(), 0x0002 | 0x0008, ctypes.byref(source_token)
            ):
                raise OSError(
                    ctypes.get_last_error(), "Windows process token could not be opened"
                )
        if not duplicate_token(
            source_token,
            0x0020 | 0x0002 | 0x0004 | 0x0008,
            None,
            2,
            2,
            ctypes.byref(scoped_token),
        ):
            raise OSError(
                ctypes.get_last_error(), "Windows effective token could not be duplicated"
            )
        for name in names:
            luid = Luid()
            if not lookup(None, name, ctypes.byref(luid)):
                raise OSError(ctypes.get_last_error(), "required Windows privilege is unavailable")
            requested = TokenPrivileges()
            requested.PrivilegeCount = 1
            requested.Privileges[0].Luid = luid
            requested.Privileges[0].Attributes = 0x00000002
            ctypes.set_last_error(0)
            adjusted = adjust(
                scoped_token,
                False,
                ctypes.byref(requested),
                0,
                None,
                None,
            )
            error = ctypes.get_last_error()
            if not adjusted or error == 1300:
                raise PermissionError(
                    error or ctypes.get_last_error(),
                    "required Windows privilege was not assigned to the scoped thread token",
                )
        if not set_thread_token(None, scoped_token):
            raise OSError(
                ctypes.get_last_error(), "privileged Windows thread token could not be attached"
            )
        attached = True
        yield
    finally:
        cleanup_error: OSError | None = None
        privilege_state_failed = False
        if attached:
            if int(get_thread_id()) != entry_thread_id:
                privilege_state_failed = True
                cleanup_error = OSError(
                    0, "Windows privilege scope exited on a different native thread"
                )
            elif had_thread_token:
                if not set_thread_token(None, source_token):
                    privilege_state_failed = True
                    cleanup_error = OSError(
                        ctypes.get_last_error(), "prior Windows thread token could not be restored"
                    )
            elif not revert_to_self():
                privilege_state_failed = True
                cleanup_error = OSError(
                    ctypes.get_last_error(), "Windows thread impersonation could not be reverted"
                )
        for token, description in (
            (scoped_token, "scoped Windows thread token"),
            (source_token, "source Windows token"),
        ):
            if token.value and not close_handle(token) and cleanup_error is None:
                cleanup_error = OSError(
                    ctypes.get_last_error(), f"{description} could not be closed"
                )
        if privilege_state_failed:
            _windows_privilege_fail_stop()
            raise RuntimeError("Windows privilege fail-stop unexpectedly returned")
        if cleanup_error is not None:
            raise cleanup_error


@contextmanager
def _windows_privileges(*names: str):
    """Serialize native privilege scopes while preserving thread-token isolation."""
    with _WINDOWS_PRIVILEGE_LOCK:
        with _windows_privileges_unlocked(*names):
            yield


class _WindowsNativeFileOps:
    """Small injectable Win32 file API surface used by guarded restoration."""

    def __init__(self):
        kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
        self._create_file = kernel32.CreateFileW
        self._create_file.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        self._create_file.restype = ctypes.c_void_p
        self._get_information = kernel32.GetFileInformationByHandle
        self._get_information.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(_WindowsByHandleFileInformation),
        ]
        self._get_information.restype = ctypes.c_int32
        self._get_information_ex = kernel32.GetFileInformationByHandleEx
        self._get_information_ex.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self._get_information_ex.restype = ctypes.c_int32
        self._get_final_path = kernel32.GetFinalPathNameByHandleW
        self._get_final_path.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_wchar),
            ctypes.c_uint32,
            ctypes.c_uint32,
        ]
        self._get_final_path.restype = ctypes.c_uint32
        self._write_file = kernel32.WriteFile
        self._write_file.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        self._write_file.restype = ctypes.c_int32
        self._read_file = kernel32.ReadFile
        self._read_file.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
        ]
        self._read_file.restype = ctypes.c_int32
        self._flush_file = kernel32.FlushFileBuffers
        self._flush_file.argtypes = [ctypes.c_void_p]
        self._flush_file.restype = ctypes.c_int32
        self._set_information = kernel32.SetFileInformationByHandle
        self._set_information.argtypes = [
            ctypes.c_void_p,
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        self._set_information.restype = ctypes.c_int32
        self._close_handle = kernel32.CloseHandle
        self._close_handle.argtypes = [ctypes.c_void_p]
        self._close_handle.restype = ctypes.c_int32

    @staticmethod
    def _raise(message: str) -> None:
        raise OSError(ctypes.get_last_error(), message)

    def open_file(
        self,
        path: str,
        desired_access: int,
        share_mode: int,
        creation_disposition: int,
        flags_and_attributes: int,
    ):
        handle = self._create_file(
            path,
            desired_access,
            share_mode,
            None,
            creation_disposition,
            flags_and_attributes,
            None,
        )
        if handle in (None, ctypes.c_void_p(-1).value):
            self._raise("Windows restoration file could not be opened")
        return handle

    def _file_information(self, handle) -> _WindowsByHandleFileInformation:
        information = _WindowsByHandleFileInformation()
        if not self._get_information(handle, ctypes.byref(information)):
            self._raise("Windows restoration file attributes could not be verified")
        return information

    def file_attributes(self, handle) -> int:
        return int(self._file_information(handle).dwFileAttributes)

    def file_snapshot(self, handle) -> dict[str, Any]:
        """Read stable file identity and basic metadata from an existing handle."""
        information = self._file_information(handle)
        creation_ticks = (
            int(information.ftCreationTime.dwHighDateTime) << 32
        ) | int(information.ftCreationTime.dwLowDateTime)
        modified_ticks = (
            int(information.ftLastWriteTime.dwHighDateTime) << 32
        ) | int(information.ftLastWriteTime.dwLowDateTime)
        return {
            "attributes": int(information.dwFileAttributes),
            "size": (int(information.nFileSizeHigh) << 32)
            | int(information.nFileSizeLow),
            "modified_at": max(
                0.0, modified_ticks / 10_000_000.0 - 11_644_473_600.0
            ),
            "creation_ticks": creation_ticks,
            "modified_ticks": modified_ticks,
            "identity": (
                int(information.dwVolumeSerialNumber),
                int(information.nFileIndexHigh),
                int(information.nFileIndexLow),
            ),
            "links": int(information.nNumberOfLinks),
        }

    def final_path(self, handle) -> str:
        size = 1024
        while size <= 32768:
            buffer = ctypes.create_unicode_buffer(size)
            length = int(
                self._get_final_path(
                    handle,
                    buffer,
                    size,
                    WINDOWS_VOLUME_NAME_GUID,
                )
            )
            if length == 0:
                self._raise("Windows restoration directory identity could not be resolved")
            if length < size:
                return buffer.value
            size = length + 1
        raise ValueError("Windows restoration directory path exceeds the accepted size")

    def write_file(self, handle, data: bytes) -> None:
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + 1024 * 1024]
            buffer = ctypes.create_string_buffer(chunk, len(chunk))
            written = ctypes.c_uint32()
            if not self._write_file(
                handle,
                buffer,
                len(chunk),
                ctypes.byref(written),
                None,
            ):
                self._raise("Windows restoration temporary file could not be written")
            if not 1 <= int(written.value) <= len(chunk):
                raise OSError("Windows restoration write made no forward progress")
            offset += int(written.value)

    def read_file(self, handle, maximum: int) -> bytes:
        """Read at most maximum + 1 bytes so callers can enforce a hard bound."""
        if not 0 <= maximum <= 0xFFFFFFFE:
            raise ValueError("Windows restoration read limit is invalid")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk_size = min(1024 * 1024, remaining)
            buffer = ctypes.create_string_buffer(chunk_size)
            read = ctypes.c_uint32()
            if not self._read_file(
                handle,
                buffer,
                chunk_size,
                ctypes.byref(read),
                None,
            ):
                self._raise("Windows restoration file could not be read")
            count = int(read.value)
            if count == 0:
                break
            if not 1 <= count <= chunk_size:
                raise OSError("Windows restoration read returned an invalid byte count")
            chunks.append(buffer.raw[:count])
            remaining -= count
        return b"".join(chunks)

    def flush_file(self, handle) -> None:
        if not self._flush_file(handle):
            self._raise("Windows restoration temporary file could not be flushed")

    def _set_file_information(
        self,
        handle,
        information_class: int,
        information,
        *,
        buffer_size: int | None = None,
    ) -> None:
        size = ctypes.sizeof(information) if buffer_size is None else int(buffer_size)
        if not 1 <= size <= ctypes.sizeof(information):
            raise ValueError("Windows restoration file information size is invalid")
        if not self._set_information(
            handle,
            information_class,
            ctypes.byref(information),
            size,
        ):
            self._raise("Windows restoration file information could not be changed")

    def apply_mode(self, handle, mode: int) -> None:
        information = _WindowsFileBasicInformation()
        if not self._get_information_ex(
            handle,
            WINDOWS_FILE_BASIC_INFO_CLASS,
            ctypes.byref(information),
            ctypes.sizeof(information),
        ):
            self._raise("Windows restoration file mode could not be read")
        attributes = int(information.FileAttributes) & ~WINDOWS_FILE_ATTRIBUTE_NORMAL
        if mode & 0o222:
            attributes &= ~WINDOWS_FILE_ATTRIBUTE_READONLY
        else:
            attributes |= WINDOWS_FILE_ATTRIBUTE_READONLY
        information.FileAttributes = attributes or WINDOWS_FILE_ATTRIBUTE_NORMAL
        self._set_file_information(handle, WINDOWS_FILE_BASIC_INFO_CLASS, information)

    def set_delete_disposition(self, handle, delete: bool) -> None:
        self._set_file_information(
            handle,
            WINDOWS_FILE_DISPOSITION_INFO_CLASS,
            _WindowsFileDispositionInformation(1 if delete else 0),
        )

    def rename_file(
        self,
        handle,
        parent_path: str,
        leaf: str,
        *,
        replace_if_exists: bool = True,
    ) -> None:
        information = _windows_file_rename_information(
            None,
            _windows_child_path(parent_path, leaf),
            replace_if_exists=replace_if_exists,
        )
        self._set_file_information(
            handle,
            WINDOWS_FILE_RENAME_INFO_CLASS,
            information,
            buffer_size=_windows_file_rename_information_size(information),
        )

    def close(self, handle) -> None:
        if not self._close_handle(handle):
            self._raise("Windows restoration handle could not be closed")


def _windows_child_path(parent_path: str, leaf: str) -> str:
    return parent_path.rstrip("\\") + "\\" + leaf


@contextmanager
def _windows_pinned_parent(
    path: Path,
    native: _WindowsNativeFileOps,
    *,
    allow_final_write_share: bool = False,
):
    """Hold a non-reparse handle for every ancestor until the mutation completes."""
    root, components, leaf = _windows_path_components(path)
    handles: list[Any] = []
    try:
        candidate = root
        for index, component in enumerate([None, *components]):
            if component is not None:
                candidate = _windows_child_path(candidate, component)
            desired_access = (
                WINDOWS_FILE_LIST_DIRECTORY
                | WINDOWS_FILE_TRAVERSE
                | WINDOWS_FILE_READ_ATTRIBUTES
                | WINDOWS_SYNCHRONIZE
            )
            share_mode = WINDOWS_FILE_SHARE_READ
            if allow_final_write_share and index == len(components):
                # An absolute FILE_RENAME_INFO publication opens the target
                # directory for write. Permit that compatible open only on the
                # final parent; every ancestor still denies write sharing and
                # every held directory continues to deny delete sharing.
                share_mode |= WINDOWS_FILE_SHARE_WRITE
            handle = native.open_file(
                candidate,
                desired_access,
                share_mode,
                WINDOWS_OPEN_EXISTING,
                WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
                | WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
            )
            handles.append(handle)
            attributes = native.file_attributes(handle)
            if not attributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
                raise ValueError("Windows restoration parent component is not a directory")
            if attributes & WINDOWS_REPARSE_POINT_ATTRIBUTE:
                raise ValueError("Windows restoration path must not traverse a reparse point")
            candidate = native.final_path(handle)
            if not candidate.casefold().startswith("\\\\?\\volume{"):
                raise ValueError("Windows restoration directory did not resolve to a local volume")
        yield handles[-1], candidate, leaf
    finally:
        cleanup_error: OSError | None = None
        for handle in reversed(handles):
            try:
                native.close(handle)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        if cleanup_error is not None:
            raise cleanup_error


def _windows_snapshot_open_handle(
    path: Path,
    handle,
    maximum: int,
    *,
    capture_security: bool,
    allow_security_failure: bool,
    native: _WindowsNativeFileOps,
) -> tuple[bytes, dict[str, Any]]:
    """Capture one stable regular-file snapshot from an already pinned handle."""
    before = native.file_snapshot(handle)
    attributes = int(before["attributes"])
    if attributes & WINDOWS_REPARSE_POINT_ATTRIBUTE:
        raise ValueError("Windows restoration target is a reparse point")
    if attributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
        raise ValueError("Windows restoration target is a directory")
    if int(before["links"]) != 1:
        raise ValueError("Windows restoration target must have exactly one hard link")
    if int(before["size"]) > maximum:
        raise ValueError(
            f"Windows restoration file exceeds its {maximum} byte limit"
        )
    data = native.read_file(handle, maximum)
    if len(data) > maximum:
        raise ValueError(
            f"Windows restoration file exceeds its {maximum} byte limit"
        )

    security_descriptor: str | None = None
    security_error = ""
    if capture_security:
        try:
            security_descriptor = _capture_windows_security_descriptor(
                path,
                native_handle=handle,
            )
        except (OSError, ValueError) as exc:
            if not allow_security_failure:
                raise
            security_error = str(exc)

    after = native.file_snapshot(handle)
    stable_fields = (
        "attributes",
        "size",
        "creation_ticks",
        "modified_ticks",
        "identity",
        "links",
    )
    if any(before.get(field) != after.get(field) for field in stable_fields):
        raise OSError("Windows restoration file changed during its snapshot")
    if len(data) != int(after["size"]):
        raise OSError("Windows restoration file length changed during its snapshot")
    snapshot = dict(after)
    snapshot["windows_security_descriptor"] = security_descriptor
    snapshot["security_descriptor_error"] = security_error
    return data, snapshot


def _windows_read_file_snapshot(
    path: Path,
    maximum: int,
    *,
    capture_security: bool = True,
    allow_security_failure: bool = False,
    native: _WindowsNativeFileOps | None = None,
) -> tuple[bytes, dict[str, Any]]:
    """Read bytes and metadata from one leaf handle under a pinned parent chain."""
    if (
        not isinstance(maximum, int)
        or isinstance(maximum, bool)
        or not 0 <= maximum <= 0xFFFFFFFE
    ):
        raise ValueError("Windows restoration read limit is invalid")
    owns_native = native is None
    native = native or _WindowsNativeFileOps()
    privilege_names = ["SeBackupPrivilege"]
    if capture_security:
        privilege_names.append("SeSecurityPrivilege")
    privilege_scope = (
        _windows_privileges(*privilege_names) if owns_native else nullcontext()
    )
    with privilege_scope:
        with _windows_pinned_parent(path, native) as (
            parent_handle,
            parent_path,
            leaf,
        ):
            del parent_handle
            desired_access = (
                WINDOWS_GENERIC_READ
                | WINDOWS_FILE_READ_ATTRIBUTES
                | WINDOWS_SYNCHRONIZE
            )
            if capture_security:
                desired_access |= WINDOWS_READ_CONTROL | WINDOWS_ACCESS_SYSTEM_SECURITY
            handle = native.open_file(
                _windows_child_path(parent_path, leaf),
                desired_access,
                # Denying write/delete sharing prevents a concurrent mutating handle
                # from coexisting with this content-and-metadata snapshot.
                WINDOWS_FILE_SHARE_READ,
                WINDOWS_OPEN_EXISTING,
                WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
                | WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
            )
            try:
                return _windows_snapshot_open_handle(
                    path,
                    handle,
                    maximum,
                    capture_security=capture_security,
                    allow_security_failure=allow_security_failure,
                    native=native,
                )
            finally:
                native.close(handle)


def _windows_read_file_snapshot_if_present(
    path: Path,
    maximum: int,
    *,
    capture_security: bool = True,
    allow_security_failure: bool = False,
    native: _WindowsNativeFileOps | None = None,
) -> tuple[bytes, dict[str, Any]] | None:
    """Return a pinned snapshot or None only for native file/path-not-found."""
    try:
        return _windows_read_file_snapshot(
            path,
            maximum,
            capture_security=capture_security,
            allow_security_failure=allow_security_failure,
            native=native,
        )
    except OSError as exc:
        code = getattr(exc, "winerror", None)
        if code is None:
            code = exc.errno
        if code in {WINDOWS_ERROR_FILE_NOT_FOUND, WINDOWS_ERROR_PATH_NOT_FOUND}:
            return None
        raise


def _windows_security_descriptor_semantics(
    encoded_descriptor: str,
) -> tuple[Any, ...]:
    """Return owner, group, ordered ACL entries, and operational control flags."""
    if os.name != "nt":
        raise OSError("Windows security descriptor comparison is unavailable")
    if (
        not isinstance(encoded_descriptor, str)
        or not encoded_descriptor
        or len(encoded_descriptor) > MAX_WINDOWS_SECURITY_DESCRIPTOR_TEXT
        or "\x00" in encoded_descriptor
    ):
        raise ValueError("Windows file security descriptor is invalid")
    try:
        raw_descriptor = base64.b64decode(
            encoded_descriptor.encode("ascii"), validate=True
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Windows file security descriptor is invalid") from exc
    if not 1 <= len(raw_descriptor) <= MAX_WINDOWS_SECURITY_DESCRIPTOR_BYTES:
        raise ValueError("Windows file security descriptor is outside its accepted size")

    buffer = ctypes.create_string_buffer(raw_descriptor, len(raw_descriptor))
    descriptor = ctypes.cast(buffer, ctypes.c_void_p)
    from ctypes import wintypes

    class AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    is_valid_descriptor = advapi32.IsValidSecurityDescriptor
    is_valid_descriptor.argtypes = [ctypes.c_void_p]
    is_valid_descriptor.restype = wintypes.BOOL
    get_descriptor_length = advapi32.GetSecurityDescriptorLength
    get_descriptor_length.argtypes = [ctypes.c_void_p]
    get_descriptor_length.restype = wintypes.DWORD
    if (
        not is_valid_descriptor(descriptor)
        or int(get_descriptor_length(descriptor)) != len(raw_descriptor)
    ):
        raise ValueError("Windows file security descriptor is malformed")

    def sid_semantics(getter, label: str) -> bytes:
        sid = ctypes.c_void_p()
        defaulted = wintypes.BOOL()
        if not getter(descriptor, ctypes.byref(sid), ctypes.byref(defaulted)):
            raise OSError(
                ctypes.get_last_error(),
                f"Windows security descriptor {label} SID is invalid",
            )
        if not sid.value:
            raise ValueError(f"Windows security descriptor {label} SID is absent")
        is_valid_sid = advapi32.IsValidSid
        is_valid_sid.argtypes = [ctypes.c_void_p]
        is_valid_sid.restype = wintypes.BOOL
        if not is_valid_sid(sid):
            raise ValueError(f"Windows security descriptor {label} SID is malformed")
        get_sid_length = advapi32.GetLengthSid
        get_sid_length.argtypes = [ctypes.c_void_p]
        get_sid_length.restype = wintypes.DWORD
        length = int(get_sid_length(sid))
        if not 1 <= length <= MAX_WINDOWS_SECURITY_DESCRIPTOR_BYTES:
            raise ValueError(f"Windows security descriptor {label} SID is malformed")
        return ctypes.string_at(sid, length)

    def acl_semantics(getter, label: str) -> tuple[Any, ...]:
        present = wintypes.BOOL()
        acl = ctypes.c_void_p()
        defaulted = wintypes.BOOL()
        if not getter(
            descriptor,
            ctypes.byref(present),
            ctypes.byref(acl),
            ctypes.byref(defaulted),
        ):
            raise OSError(
                ctypes.get_last_error(),
                f"Windows security descriptor {label} is invalid",
            )
        if not present.value:
            return ("absent",)
        if not acl.value:
            return ("null",)

        is_valid_acl = advapi32.IsValidAcl
        is_valid_acl.argtypes = [ctypes.c_void_p]
        is_valid_acl.restype = wintypes.BOOL
        information = AclSizeInformation()
        get_acl_information = advapi32.GetAclInformation
        get_acl_information.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        get_acl_information.restype = wintypes.BOOL
        if not is_valid_acl(acl) or not get_acl_information(
            acl,
            ctypes.byref(information),
            ctypes.sizeof(information),
            2,
        ):
            raise OSError(
                ctypes.get_last_error(),
                f"Windows security descriptor {label} is malformed",
            )
        bytes_in_use = int(information.AclBytesInUse)
        ace_count = int(information.AceCount)
        if (
            not 8 <= bytes_in_use <= MAX_WINDOWS_SECURITY_DESCRIPTOR_BYTES
            or ace_count > 4096
        ):
            raise ValueError(
                f"Windows security descriptor {label} is outside its accepted size"
            )

        get_ace = advapi32.GetAce
        get_ace.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        get_ace.restype = wintypes.BOOL
        entries: list[bytes] = []
        total = 8
        for index in range(ace_count):
            ace = ctypes.c_void_p()
            if not get_ace(acl, index, ctypes.byref(ace)) or not ace.value:
                raise OSError(
                    ctypes.get_last_error(),
                    f"Windows security descriptor {label} entry is invalid",
                )
            header = ctypes.string_at(ace, 4)
            ace_size = int.from_bytes(header[2:4], "little")
            total += ace_size
            if ace_size < 4 or total > bytes_in_use:
                raise ValueError(
                    f"Windows security descriptor {label} entry is malformed"
                )
            entries.append(ctypes.string_at(ace, ace_size))
        if total != bytes_in_use:
            raise ValueError(
                f"Windows security descriptor {label} has unbound trailing data"
            )
        revision = int(ctypes.string_at(acl, 1)[0])
        return ("present", revision, tuple(entries))

    get_owner = advapi32.GetSecurityDescriptorOwner
    get_owner.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_owner.restype = wintypes.BOOL
    get_group = advapi32.GetSecurityDescriptorGroup
    get_group.argtypes = get_owner.argtypes
    get_group.restype = wintypes.BOOL
    get_dacl = advapi32.GetSecurityDescriptorDacl
    get_dacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_dacl.restype = wintypes.BOOL
    get_sacl = advapi32.GetSecurityDescriptorSacl
    get_sacl.argtypes = get_dacl.argtypes
    get_sacl.restype = wintypes.BOOL

    control = wintypes.WORD()
    revision = wintypes.DWORD()
    get_control = advapi32.GetSecurityDescriptorControl
    get_control.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_control.restype = wintypes.BOOL
    if not get_control(descriptor, ctypes.byref(control), ctypes.byref(revision)):
        raise OSError(
            ctypes.get_last_error(), "Windows security descriptor control is invalid"
        )
    rm_control_value = 0
    if int(control.value) & WINDOWS_SE_RM_CONTROL_VALID:
        rm_control = ctypes.c_ubyte()
        get_rm_control = advapi32.GetSecurityDescriptorRMControl
        get_rm_control.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte)]
        get_rm_control.restype = wintypes.BOOL
        if not get_rm_control(descriptor, ctypes.byref(rm_control)):
            raise OSError(
                ctypes.get_last_error(),
                "Windows security descriptor resource-manager control is invalid",
            )
        rm_control_value = int(rm_control.value)
    return (
        int(revision.value),
        int(control.value) & WINDOWS_SEMANTIC_CONTROL_MASK,
        rm_control_value,
        sid_semantics(get_owner, "owner"),
        sid_semantics(get_group, "group"),
        acl_semantics(get_dacl, "DACL"),
        acl_semantics(get_sacl, "SACL"),
    )


def _windows_security_descriptor_mismatch(
    expected_descriptor: object,
    observed_descriptor: object,
) -> str | None:
    """Return a bounded semantic mismatch category, or None for equivalence."""
    if (
        not isinstance(expected_descriptor, str)
        or not expected_descriptor
        or not isinstance(observed_descriptor, str)
        or not observed_descriptor
    ):
        return "missing"
    if expected_descriptor == observed_descriptor:
        return None
    if os.name != "nt":
        return "platform"
    try:
        expected = _windows_security_descriptor_semantics(expected_descriptor)
        observed = _windows_security_descriptor_semantics(observed_descriptor)
    except Exception as exc:
        code = getattr(exc, "winerror", None) or getattr(exc, "errno", None)
        suffix = str(code) if isinstance(code, int) else "unknown"
        return f"parse-{type(exc).__name__}-{suffix}"
    names = ("revision", "control", "rm-control", "owner", "group", "DACL", "SACL")
    for name, expected_value, observed_value in zip(
        names, expected, observed, strict=True
    ):
        if expected_value != observed_value:
            return name
    return None


def _windows_security_descriptors_equivalent(
    expected_descriptor: object,
    observed_descriptor: object,
) -> bool:
    """Compare access semantics while rejecting absent, malformed, or changed ACLs."""
    return (
        _windows_security_descriptor_mismatch(
            expected_descriptor, observed_descriptor
        )
        is None
    )


def _windows_expected_snapshot_mismatch(
    expected_data: bytes,
    expected_metadata: dict[str, Any],
    observed_data: bytes,
    observed: dict[str, Any],
) -> str | None:
    """Return a bounded mismatch category for a conditional native mutation."""
    if (
        not isinstance(expected_data, bytes)
        or not isinstance(expected_metadata, dict)
        or not isinstance(observed_data, bytes)
        or not isinstance(observed, dict)
    ):
        return "invalid-state"
    if observed_data != expected_data:
        return "bytes"
    try:
        expected_mode = int(expected_metadata.get("mode", 0))
        observed_mode = (
            0o444
            if int(observed["attributes"]) & WINDOWS_FILE_ATTRIBUTE_READONLY
            else 0o666
        )
    except (KeyError, TypeError, ValueError):
        return "mode-invalid"
    if expected_mode != observed_mode:
        return "mode"
    if not _windows_security_descriptors_equivalent(
        expected_metadata.get("windows_security_descriptor"),
        observed.get("windows_security_descriptor"),
    ):
        return "security-descriptor"
    exact_fields = {
        "windows_file_identity": "identity",
        "windows_creation_ticks": "creation-ticks",
        "windows_modified_ticks": "modified-ticks",
        "windows_file_size": "size",
        "windows_hard_links": "links",
        "windows_file_attributes": "attributes",
    }
    snapshot_names = {
        "windows_file_identity": "identity",
        "windows_creation_ticks": "creation_ticks",
        "windows_modified_ticks": "modified_ticks",
        "windows_file_size": "size",
        "windows_hard_links": "links",
        "windows_file_attributes": "attributes",
    }
    for metadata_name, mismatch_name in exact_fields.items():
        if metadata_name not in expected_metadata:
            continue
        expected_value = expected_metadata[metadata_name]
        observed_value = observed.get(snapshot_names[metadata_name])
        if metadata_name == "windows_file_identity":
            try:
                expected_value = tuple(int(value) for value in expected_value)
                observed_value = tuple(int(value) for value in observed_value)
            except (TypeError, ValueError):
                return "identity-invalid"
        elif isinstance(expected_value, bool) or not isinstance(expected_value, int):
            return f"{mismatch_name}-invalid"
        if expected_value != observed_value:
            return mismatch_name
    return None


def _windows_expected_snapshot_matches(
    expected_data: bytes,
    expected_metadata: dict[str, Any],
    observed_data: bytes,
    observed: dict[str, Any],
) -> bool:
    """Bind a conditional mutation to the bytes, ACL, and native file identity read earlier."""
    return (
        _windows_expected_snapshot_mismatch(
            expected_data,
            expected_metadata,
            observed_data,
            observed,
        )
        is None
    )


def _windows_atomic_write(
    destination: Path,
    data: bytes,
    mode: int,
    metadata: dict[str, Any] | None,
    *,
    native: _WindowsNativeFileOps | None = None,
    expected_current: tuple[bytes, dict[str, Any]] | None | object = (
        _WINDOWS_EXPECTED_UNSPECIFIED
    ),
    temp_registry: Any | None = None,
) -> None:
    """Stage and conditionally publish a Windows file under pinned handles."""
    owns_native = native is None
    native = native or _WindowsNativeFileOps()
    encoded_descriptor = (metadata or {}).get("windows_security_descriptor")
    privilege_scope = (
        _windows_privileges(
            "SeBackupPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege"
        )
        if owns_native and (encoded_descriptor or temp_registry is not None)
        else _windows_privileges("SeBackupPrivilege", "SeRestorePrivilege")
        if owns_native
        else nullcontext()
    )
    with privilege_scope:
        with _windows_pinned_parent(
            destination,
            native,
            allow_final_write_share=True,
        ) as (
            parent_handle,
            parent_path,
            leaf,
        ):
            del parent_handle
            handle = None
            expected_handle = None
            verification_handle = None
            expected_data: bytes | None = None
            expected_metadata: dict[str, Any] | None = None
            ownership_record = None
            published = False
            disposition_armed = False
            cleanup_error: OSError | None = None
            try:
                replace_if_exists = expected_current is not None
                if expected_current is not _WINDOWS_EXPECTED_UNSPECIFIED:
                    if expected_current is not None:
                        if (
                            not isinstance(expected_current, tuple)
                            or len(expected_current) != 2
                        ):
                            raise ValueError("Windows conditional replacement state is invalid")
                        expected_data, expected_metadata = expected_current
                        expected_handle = native.open_file(
                            _windows_child_path(parent_path, leaf),
                            WINDOWS_GENERIC_READ
                            | WINDOWS_FILE_READ_ATTRIBUTES
                            | WINDOWS_READ_CONTROL
                            | WINDOWS_ACCESS_SYSTEM_SECURITY
                            | WINDOWS_SYNCHRONIZE,
                            # Existing writers make this open fail. Keeping this
                            # handle through rename prevents any new data writer,
                            # while FILE_SHARE_DELETE lets our rename replace it.
                            WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_DELETE,
                            WINDOWS_OPEN_EXISTING,
                            WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
                            | WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
                        )
                        observed_data, observed_snapshot = _windows_snapshot_open_handle(
                            destination,
                            expected_handle,
                            MAX_FILE_BYTES,
                            capture_security=True,
                            allow_security_failure=False,
                            native=native,
                        )
                        mismatch = _windows_expected_snapshot_mismatch(
                            expected_data,
                            expected_metadata,
                            observed_data,
                            observed_snapshot,
                        )
                        if mismatch is not None:
                            raise ValueError(
                                "Windows restoration target changed before publish; "
                                f"refusing to overwrite newer data ({mismatch})"
                            )
                    else:
                        # FILE_RENAME_INFO with ReplaceIfExists=false is the
                        # atomic absence check. A concurrent creator wins and
                        # the restoration fails instead of replacing its file.
                        replace_if_exists = False
                desired_access = (
                    WINDOWS_GENERIC_WRITE
                    | WINDOWS_DELETE
                    | WINDOWS_FILE_READ_ATTRIBUTES
                    | WINDOWS_SYNCHRONIZE
                )
                if encoded_descriptor or temp_registry is not None:
                    desired_access |= WINDOWS_READ_CONTROL | WINDOWS_ACCESS_SYSTEM_SECURITY
                if encoded_descriptor:
                    desired_access |= (
                        WINDOWS_WRITE_DAC
                        | WINDOWS_WRITE_OWNER
                    )
                for _attempt in range(8):
                    temporary_leaf = f".sentinel-{uuid.uuid4().hex}.tmp"
                    temporary_path = _windows_child_path(parent_path, temporary_leaf)
                    try:
                        handle = native.open_file(
                            temporary_path,
                            desired_access,
                            0,
                            WINDOWS_CREATE_NEW,
                            WINDOWS_FILE_ATTRIBUTE_NORMAL
                            | WINDOWS_FILE_FLAG_WRITE_THROUGH
                            | WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
                            | WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
                        )
                        break
                    except OSError as exc:
                        error = getattr(exc, "winerror", None) or exc.errno
                        if error not in {80, 183}:
                            raise
                if handle is None:
                    raise OSError("Windows restoration could not allocate a unique temporary file")
                attributes = native.file_attributes(handle)
                if attributes & (
                    WINDOWS_FILE_ATTRIBUTE_DIRECTORY | WINDOWS_REPARSE_POINT_ATTRIBUTE
                ):
                    raise ValueError("Windows restoration temporary object is not a regular file")
                native.set_delete_disposition(handle, True)
                disposition_armed = True
                native.write_file(handle, data)
                native.flush_file(handle)
                native.apply_mode(handle, mode & 0o7777 or 0o600)
                if encoded_descriptor:
                    _restore_windows_security_descriptor(
                        destination,
                        encoded_descriptor,
                        native_handle=handle,
                    )
                    observed = _capture_windows_security_descriptor(
                        destination,
                        native_handle=handle,
                    )
                    descriptor_mismatch = _windows_security_descriptor_mismatch(
                        encoded_descriptor, observed
                    )
                    if descriptor_mismatch is not None:
                        raise OSError(
                            "post-restoration Windows security descriptor did not "
                            f"match ({descriptor_mismatch})"
                        )
                if temp_registry is not None:
                    ownership_record = temp_registry.register(
                        destination=destination,
                        parent_path=parent_path,
                        temporary_leaf=temporary_leaf,
                        temporary_handle=handle,
                        data=data,
                        native=native,
                    )
                if expected_handle is not None:
                    # Re-resolve the destination name only after staging and its
                    # durable ownership record are complete. The first handle has
                    # denied data writers throughout; this second exact snapshot
                    # catches a delete/rename/name-substitution as close to the
                    # publish syscall as Win32's non-transactional rename permits.
                    verification_handle = native.open_file(
                        _windows_child_path(parent_path, leaf),
                        WINDOWS_GENERIC_READ
                        | WINDOWS_FILE_READ_ATTRIBUTES
                        | WINDOWS_READ_CONTROL
                        | WINDOWS_ACCESS_SYSTEM_SECURITY
                        | WINDOWS_SYNCHRONIZE,
                        WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_DELETE,
                        WINDOWS_OPEN_EXISTING,
                        WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
                        | WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
                    )
                    verification_data, verification_snapshot = (
                        _windows_snapshot_open_handle(
                            destination,
                            verification_handle,
                            MAX_FILE_BYTES,
                            capture_security=True,
                            allow_security_failure=False,
                            native=native,
                        )
                    )
                    assert expected_data is not None
                    assert expected_metadata is not None
                    mismatch = _windows_expected_snapshot_mismatch(
                        expected_data,
                        expected_metadata,
                        verification_data,
                        verification_snapshot,
                    )
                    if mismatch is not None:
                        raise ValueError(
                            "Windows restoration target name changed before publish; "
                            f"refusing to overwrite newer data ({mismatch})"
                        )
                # Clearing delete-on-close and publishing cannot be one Win32 call. A
                # durable authenticated ownership record is established first, so a
                # hard kill in this narrow boundary leaves a cleanup-verifiable temp.
                native.set_delete_disposition(handle, False)
                disposition_armed = False
                published_snapshot = native.file_snapshot(handle)
                if (
                    int(published_snapshot["links"]) != 1
                    or int(published_snapshot["size"]) != len(data)
                    or int(published_snapshot["attributes"])
                    & (
                        WINDOWS_FILE_ATTRIBUTE_DIRECTORY
                        | WINDOWS_REPARSE_POINT_ATTRIBUTE
                    )
                ):
                    raise OSError(
                        "Windows restoration temporary file did not verify "
                        "after publication"
                    )
                native.rename_file(
                    handle,
                    parent_path,
                    leaf,
                    replace_if_exists=replace_if_exists,
                )
                published = True
            except Exception:
                if handle is not None and not published and not disposition_armed:
                    # A final read-only mode may already have been applied before
                    # rename failed. Make the private temp writable before arming
                    # delete-on-close; the handle's granted rights remain pinned.
                    try:
                        native.apply_mode(handle, 0o600)
                    except OSError:
                        # The disposition call below is authoritative: if it can
                        # still arm deletion, a mode-reset failure is harmless.
                        pass
                    try:
                        native.set_delete_disposition(handle, True)
                        disposition_armed = True
                    except OSError as exc:
                        cleanup_error = exc
                if cleanup_error is not None:
                    raise cleanup_error
                raise
            finally:
                temp_closed = handle is None
                if handle is not None:
                    try:
                        native.close(handle)
                        temp_closed = True
                    except OSError as exc:
                        if cleanup_error is None:
                            cleanup_error = exc
                if expected_handle is not None:
                    try:
                        native.close(expected_handle)
                    except OSError as exc:
                        if cleanup_error is None:
                            cleanup_error = exc
                if verification_handle is not None:
                    try:
                        native.close(verification_handle)
                    except OSError as exc:
                        if cleanup_error is None:
                            cleanup_error = exc
                if (
                    ownership_record is not None
                    and temp_closed
                    and (published or disposition_armed)
                ):
                    try:
                        temp_registry.complete(ownership_record)
                    except (OSError, ValueError):
                        # A stale authenticated record is safe: startup cleanup
                        # removes it after observing that the temp no longer exists.
                        pass
                if cleanup_error is not None:
                    raise cleanup_error


def _windows_unlink(
    path: Path,
    *,
    native: _WindowsNativeFileOps | None = None,
    expected_current: tuple[bytes, dict[str, Any]] | object = (
        _WINDOWS_EXPECTED_UNSPECIFIED
    ),
) -> None:
    """Delete the exact opened leaf while its complete parent chain is pinned."""
    owns_native = native is None
    native = native or _WindowsNativeFileOps()
    privilege_scope = (
        _windows_privileges(
            "SeBackupPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege"
        )
        if owns_native
        else nullcontext()
    )
    with privilege_scope:
        with _windows_pinned_parent(path, native) as (parent_handle, parent_path, leaf):
            del parent_handle
            try:
                conditional = expected_current is not _WINDOWS_EXPECTED_UNSPECIFIED
                handle = native.open_file(
                    _windows_child_path(parent_path, leaf),
                    WINDOWS_DELETE
                    | (WINDOWS_GENERIC_READ if conditional else 0)
                    | WINDOWS_FILE_READ_ATTRIBUTES
                    | (WINDOWS_READ_CONTROL if conditional else 0)
                    | (WINDOWS_ACCESS_SYSTEM_SECURITY if conditional else 0)
                    | WINDOWS_SYNCHRONIZE,
                    # A conditional delete excludes writers and other deleters
                    # until the exact opened object has been marked for deletion.
                    WINDOWS_FILE_SHARE_READ
                    if conditional
                    else WINDOWS_FILE_SHARE_READ | WINDOWS_FILE_SHARE_WRITE,
                    WINDOWS_OPEN_EXISTING,
                    WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
                    | WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
                )
            except OSError as exc:
                error = getattr(exc, "winerror", None) or exc.errno
                if error in {WINDOWS_ERROR_FILE_NOT_FOUND, WINDOWS_ERROR_PATH_NOT_FOUND}:
                    return
                raise
            try:
                attributes = native.file_attributes(handle)
                if attributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
                    raise ValueError("refusing to remove a directory target")
                if attributes & WINDOWS_REPARSE_POINT_ATTRIBUTE:
                    raise ValueError("refusing to remove a reparse-point target")
                if conditional:
                    if (
                        not isinstance(expected_current, tuple)
                        or len(expected_current) != 2
                    ):
                        raise ValueError("Windows conditional removal state is invalid")
                    expected_data, expected_metadata = expected_current
                    observed_data, observed_snapshot = _windows_snapshot_open_handle(
                        path,
                        handle,
                        MAX_FILE_BYTES,
                        capture_security=True,
                        allow_security_failure=False,
                        native=native,
                    )
                    mismatch = _windows_expected_snapshot_mismatch(
                        expected_data,
                        expected_metadata,
                        observed_data,
                        observed_snapshot,
                    )
                    if mismatch is not None:
                        raise ValueError(
                            "Windows restoration target changed before removal; "
                            f"refusing to delete newer data ({mismatch})"
                        )
                native.set_delete_disposition(handle, True)
            finally:
                native.close(handle)


def _windows_metadata_from_native_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    """Return JSON-safe Windows metadata, including conditional-mutation identity."""
    attributes = int(snapshot["attributes"])
    identity = snapshot.get("identity")
    if not isinstance(identity, (tuple, list)) or len(identity) != 3:
        raise ValueError("Windows restoration file identity is invalid")
    return {
        "mode": 0o444 if attributes & WINDOWS_FILE_ATTRIBUTE_READONLY else 0o666,
        "uid": -1,
        "gid": -1,
        "xattrs": {},
        "windows_security_descriptor": snapshot.get(
            "windows_security_descriptor"
        ),
        "windows_security_descriptor_version": WINDOWS_SECURITY_DESCRIPTOR_VERSION,
        "windows_file_identity": [int(value) for value in identity],
        "windows_creation_ticks": int(snapshot.get("creation_ticks", 0)),
        "windows_modified_ticks": int(snapshot["modified_ticks"]),
        "windows_file_size": int(snapshot["size"]),
        "windows_hard_links": int(snapshot["links"]),
        "windows_file_attributes": attributes,
    }


def _windows_write_new_private_file(
    path: Path,
    data: bytes,
    *,
    native: _WindowsNativeFileOps | None = None,
) -> None:
    """Durably create one new private file without an overwrite/rename window."""
    owns_native = native is None
    native = native or _WindowsNativeFileOps()
    scope = (
        _windows_privileges("SeBackupPrivilege", "SeRestorePrivilege")
        if owns_native
        else nullcontext()
    )
    with scope:
        with _windows_pinned_parent(path, native) as (
            parent_handle,
            parent_path,
            leaf,
        ):
            del parent_handle
            handle = native.open_file(
                _windows_child_path(parent_path, leaf),
                WINDOWS_GENERIC_READ
                | WINDOWS_GENERIC_WRITE
                | WINDOWS_DELETE
                | WINDOWS_FILE_READ_ATTRIBUTES
                | WINDOWS_SYNCHRONIZE,
                0,
                WINDOWS_CREATE_NEW,
                WINDOWS_FILE_ATTRIBUTE_NORMAL
                | WINDOWS_FILE_FLAG_WRITE_THROUGH
                | WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
                | WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
            )
            armed = False
            try:
                attributes = native.file_attributes(handle)
                if attributes & (
                    WINDOWS_FILE_ATTRIBUTE_DIRECTORY
                    | WINDOWS_REPARSE_POINT_ATTRIBUTE
                ):
                    raise ValueError("Windows private state object is not a regular file")
                native.set_delete_disposition(handle, True)
                armed = True
                native.write_file(handle, data)
                native.flush_file(handle)
                native.apply_mode(handle, 0o600)
                snapshot = native.file_snapshot(handle)
                # A delete-pending NTFS handle can report zero links until its
                # delete disposition is cleared.  Verify the durable length
                # while cleanup remains armed, then verify the published link
                # count under the same exclusive handle after disarming.  The
                # exception path below re-arms deletion if that second gate
                # fails, so an unverified private file is never retained.
                if int(snapshot["size"]) != len(data):
                    raise OSError("Windows private state file did not verify after creation")
                native.set_delete_disposition(handle, False)
                armed = False
                snapshot = native.file_snapshot(handle)
                if int(snapshot["links"]) != 1 or int(snapshot["size"]) != len(data):
                    raise OSError("Windows private state file did not verify after publication")
            except BaseException:
                if not armed:
                    try:
                        native.set_delete_disposition(handle, True)
                    except OSError:
                        pass
                raise
            finally:
                native.close(handle)


class _WindowsTempOwnershipRegistry:
    """Authenticate and reap only temp objects created by this restoration store."""

    _TEMP_LEAF = re.compile(r"^\.sentinel-[0-9a-f]{32}\.tmp$")
    _RECORD_KEYS = {
        "version",
        "record_id",
        "destination",
        "parent_final_path",
        "temporary_leaf",
        "identity",
        "creation_ticks",
        "modified_ticks",
        "size",
        "attributes",
        "links",
        "content_sha256",
        "security_descriptor_sha256",
        "created_at_ns",
        "mac",
    }

    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)
        if not self.root.is_dir() or self.root.is_symlink():
            raise ValueError("Windows temporary ownership registry is unsafe")
        self.key_path = self.root / "ownership.key"
        self._key = self._load_or_create_key()

    @staticmethod
    def _canonical(payload: dict[str, Any]) -> bytes:
        return json.dumps(
            payload,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")

    def _load_or_create_key(self) -> bytes:
        existing = _windows_read_file_snapshot_if_present(
            self.key_path,
            WINDOWS_TEMP_KEY_BYTES,
            capture_security=False,
        )
        if existing is None:
            candidate = secrets.token_bytes(WINDOWS_TEMP_KEY_BYTES)
            try:
                _windows_write_new_private_file(self.key_path, candidate)
            except OSError as exc:
                error = getattr(exc, "winerror", None) or exc.errno
                if error not in {
                    WINDOWS_ERROR_FILE_EXISTS,
                    WINDOWS_ERROR_ALREADY_EXISTS,
                }:
                    raise
            existing = _windows_read_file_snapshot(
                self.key_path,
                WINDOWS_TEMP_KEY_BYTES,
                capture_security=False,
            )
        data, snapshot = existing
        if (
            len(data) != WINDOWS_TEMP_KEY_BYTES
            or int(snapshot["size"]) != WINDOWS_TEMP_KEY_BYTES
            or int(snapshot["links"]) != 1
        ):
            raise ValueError("Windows temporary ownership key is invalid")
        return data

    def _mac(self, payload: dict[str, Any]) -> str:
        return hmac.new(self._key, self._canonical(payload), hashlib.sha256).hexdigest()

    def _record_path(self, record_id: str) -> Path:
        if not re.fullmatch(r"[0-9a-f]{32}", record_id):
            raise ValueError("Windows temporary ownership record identifier is invalid")
        return self.root / f"{record_id}.json"

    def register(
        self,
        *,
        destination: Path,
        parent_path: str,
        temporary_leaf: str,
        temporary_handle,
        data: bytes,
        native: _WindowsNativeFileOps,
    ) -> dict[str, Any]:
        if not self._TEMP_LEAF.fullmatch(temporary_leaf):
            raise ValueError("Windows restoration temporary name is invalid")
        snapshot = native.file_snapshot(temporary_handle)
        descriptor = _capture_windows_security_descriptor(
            destination,
            native_handle=temporary_handle,
        )
        links = int(snapshot["links"])
        if (
            links not in {0, 1}
            or int(snapshot["size"]) != len(data)
            or int(snapshot["attributes"])
            & (WINDOWS_FILE_ATTRIBUTE_DIRECTORY | WINDOWS_REPARSE_POINT_ATTRIBUTE)
        ):
            raise OSError("Windows restoration temporary file identity is unsafe")
        identity = snapshot.get("identity")
        if not isinstance(identity, (tuple, list)) or len(identity) != 3:
            raise OSError("Windows restoration temporary file identity is invalid")
        record_id = uuid.uuid4().hex
        payload = {
            "version": 1,
            "record_id": record_id,
            "destination": str(destination),
            "parent_final_path": parent_path,
            "temporary_leaf": temporary_leaf,
            "identity": [int(value) for value in identity],
            "creation_ticks": int(snapshot.get("creation_ticks", 0)),
            "modified_ticks": int(snapshot["modified_ticks"]),
            "size": int(snapshot["size"]),
            "attributes": int(snapshot["attributes"]),
            # A delete-pending NTFS handle can report zero links. The durable
            # record describes the only safe post-disarm state; the caller
            # verifies that exact one-link transition before rename.
            "links": 1,
            "content_sha256": hashlib.sha256(data).hexdigest(),
            "security_descriptor_sha256": hashlib.sha256(
                descriptor.encode("ascii")
            ).hexdigest(),
            "created_at_ns": time.time_ns(),
        }
        record = dict(payload)
        record["mac"] = self._mac(payload)
        encoded = self._canonical(record)
        if len(encoded) > WINDOWS_TEMP_RECORD_BYTES:
            raise ValueError("Windows temporary ownership record exceeds its limit")
        record_path = self._record_path(record_id)
        _windows_write_new_private_file(record_path, encoded, native=native)
        record_data, record_snapshot = _windows_read_file_snapshot(
            record_path,
            WINDOWS_TEMP_RECORD_BYTES,
            native=native,
        )
        if record_data != encoded:
            raise OSError("Windows temporary ownership record did not verify")
        return {
            "path": record_path,
            "data": record_data,
            "metadata": _windows_metadata_from_native_snapshot(record_snapshot),
        }

    @classmethod
    def _validate_record(
        cls,
        record: dict[str, Any],
        *,
        expected_id: str,
    ) -> dict[str, Any]:
        if not isinstance(record, dict) or set(record) != cls._RECORD_KEYS:
            raise ValueError("Windows temporary ownership record has an invalid shape")
        if (
            type(record["version"]) is not int
            or record["version"] != 1
            or not isinstance(record["record_id"], str)
            or record["record_id"] != expected_id
        ):
            raise ValueError("Windows temporary ownership record binding is invalid")
        if not isinstance(record["temporary_leaf"], str) or not cls._TEMP_LEAF.fullmatch(
            record["temporary_leaf"]
        ):
            raise ValueError("Windows temporary ownership record name is invalid")
        if (
            not isinstance(record["destination"], str)
            or not record["destination"]
            or len(record["destination"]) > 1024
            or not isinstance(record["parent_final_path"], str)
            or not record["parent_final_path"].casefold().startswith("\\\\?\\volume{")
            or len(record["parent_final_path"]) > 32768
        ):
            raise ValueError("Windows temporary ownership record path is invalid")
        _windows_path_components(Path(record["destination"]))
        identity = record["identity"]
        if (
            not isinstance(identity, list)
            or len(identity) != 3
            or any(type(value) is not int or value < 0 for value in identity)
        ):
            raise ValueError("Windows temporary ownership record identity is invalid")
        for name in (
            "creation_ticks",
            "modified_ticks",
            "size",
            "attributes",
            "links",
            "created_at_ns",
        ):
            if type(record[name]) is not int or record[name] < 0:
                raise ValueError("Windows temporary ownership record value is invalid")
        if (
            record["size"] > MAX_FILE_BYTES
            or record["links"] != 1
            or not isinstance(record["content_sha256"], str)
            or not SHA256.fullmatch(record["content_sha256"])
            or not isinstance(record["security_descriptor_sha256"], str)
            or not SHA256.fullmatch(record["security_descriptor_sha256"])
            or not isinstance(record["mac"], str)
            or not SHA256.fullmatch(record["mac"])
        ):
            raise ValueError("Windows temporary ownership record value is invalid")
        return record

    def _decode_record(self, encoded: bytes, expected_id: str) -> dict[str, Any]:
        def unique_object(pairs):
            result = {}
            for name, value in pairs:
                if name in result:
                    raise ValueError(
                        "Windows temporary ownership record has duplicate fields"
                    )
                result[name] = value
            return result

        try:
            record = json.loads(
                encoded.decode("ascii"),
                object_pairs_hook=unique_object,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Windows temporary ownership record is corrupt") from exc
        record = self._validate_record(record, expected_id=expected_id)
        payload = {name: value for name, value in record.items() if name != "mac"}
        if not hmac.compare_digest(record["mac"], self._mac(payload)):
            raise ValueError("Windows temporary ownership record authentication failed")
        return record

    def _remove_record(self, ownership: dict[str, Any]) -> None:
        _windows_unlink(
            ownership["path"],
            expected_current=(ownership["data"], ownership["metadata"]),
        )

    def complete(self, ownership: dict[str, Any]) -> None:
        self._remove_record(ownership)

    def _cleanup_temp(self, record: dict[str, Any]) -> None:
        destination = Path(record["destination"])
        temporary = destination.parent / record["temporary_leaf"]
        native = _WindowsNativeFileOps()
        with _windows_privileges(
            "SeBackupPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege"
        ):
            with _windows_pinned_parent(temporary, native) as (
                parent_handle,
                parent_path,
                leaf,
            ):
                del parent_handle
                if parent_path.casefold() != record["parent_final_path"].casefold():
                    raise ValueError("Windows temporary ownership parent identity changed")
                try:
                    handle = native.open_file(
                        _windows_child_path(parent_path, leaf),
                        WINDOWS_GENERIC_READ
                        | WINDOWS_DELETE
                        | WINDOWS_FILE_READ_ATTRIBUTES
                        | WINDOWS_READ_CONTROL
                        | WINDOWS_ACCESS_SYSTEM_SECURITY
                        | WINDOWS_SYNCHRONIZE,
                        WINDOWS_FILE_SHARE_READ,
                        WINDOWS_OPEN_EXISTING,
                        WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
                        | WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
                    )
                except OSError as exc:
                    error = getattr(exc, "winerror", None) or exc.errno
                    if error in {
                        WINDOWS_ERROR_FILE_NOT_FOUND,
                        WINDOWS_ERROR_PATH_NOT_FOUND,
                    }:
                        return
                    raise
                try:
                    data, snapshot = _windows_snapshot_open_handle(
                        temporary,
                        handle,
                        MAX_FILE_BYTES,
                        capture_security=True,
                        allow_security_failure=False,
                        native=native,
                    )
                    descriptor = snapshot["windows_security_descriptor"]
                    if not isinstance(descriptor, str) or not descriptor:
                        raise ValueError(
                            "Windows temporary ownership security metadata is unavailable"
                        )
                    observed = {
                        "identity": [int(value) for value in snapshot["identity"]],
                        "creation_ticks": int(snapshot.get("creation_ticks", 0)),
                        "modified_ticks": int(snapshot["modified_ticks"]),
                        "size": int(snapshot["size"]),
                        "attributes": int(snapshot["attributes"]),
                        "links": int(snapshot["links"]),
                        "content_sha256": hashlib.sha256(data).hexdigest(),
                        "security_descriptor_sha256": hashlib.sha256(
                            descriptor.encode("ascii")
                        ).hexdigest(),
                    }
                    for name, value in observed.items():
                        if value != record[name]:
                            raise ValueError(
                                "Windows temporary ownership evidence no longer "
                                "matches the orphan"
                            )
                    native.set_delete_disposition(handle, True)
                finally:
                    native.close(handle)

    def cleanup(self) -> dict[str, Any]:
        """Bound startup cleanup to authenticated records; never scan target directories."""
        names: list[str] = []
        native = _WindowsNativeFileOps()
        with _windows_privileges("SeBackupPrivilege"):
            with _windows_pinned_parent(self.root / "scan.placeholder", native):
                with os.scandir(self.root) as entries:
                    names = sorted(
                        entry.name
                        for entry in entries
                        if WINDOWS_TEMP_RECORD.fullmatch(entry.name)
                    )
        if len(names) > WINDOWS_TEMP_RECORD_LIMIT:
            raise ValueError("too many Windows temporary ownership records")
        cleaned: list[str] = []
        unresolved: list[dict[str, str]] = []
        for name in names:
            path = self.root / name
            try:
                encoded, snapshot = _windows_read_file_snapshot(
                    path,
                    WINDOWS_TEMP_RECORD_BYTES,
                )
                record_id = name[:-5]
                record = self._decode_record(encoded, record_id)
                ownership = {
                    "path": path,
                    "data": encoded,
                    "metadata": _windows_metadata_from_native_snapshot(snapshot),
                }
                self._cleanup_temp(record)
                self._remove_record(ownership)
                cleaned.append(record_id)
            except (OSError, ValueError) as exc:
                unresolved.append({"record": name, "reason": str(exc)[:500]})
        return {"healthy": not unresolved, "cleaned": cleaned, "unresolved": unresolved}


def _windows_open_security_handle(
    path: Path,
    desired_access: int,
    file_descriptor: int | None = None,
):
    """Open a no-reparse native file handle and optionally pin it to an existing CRT handle."""
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    create_file = kernel32.CreateFileW
    create_file.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    handle = create_file(
        str(path),
        desired_access,
        0x00000001 | 0x00000002 | 0x00000004,
        None,
        3,
        0x02000000 | 0x00200000,
        None,
    )
    if handle == wintypes.HANDLE(-1).value:
        raise OSError(ctypes.get_last_error(), "Windows security handle could not be opened")

    class ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("dwFileAttributes", wintypes.DWORD),
            ("ftCreationTime", wintypes.FILETIME),
            ("ftLastAccessTime", wintypes.FILETIME),
            ("ftLastWriteTime", wintypes.FILETIME),
            ("dwVolumeSerialNumber", wintypes.DWORD),
            ("nFileSizeHigh", wintypes.DWORD),
            ("nFileSizeLow", wintypes.DWORD),
            ("nNumberOfLinks", wintypes.DWORD),
            ("nFileIndexHigh", wintypes.DWORD),
            ("nFileIndexLow", wintypes.DWORD),
        ]

    get_information = kernel32.GetFileInformationByHandle
    get_information.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(ByHandleFileInformation),
    ]
    get_information.restype = wintypes.BOOL

    def identity(candidate) -> tuple[int, int, int]:
        information = ByHandleFileInformation()
        if not get_information(candidate, ctypes.byref(information)):
            raise OSError(
                ctypes.get_last_error(), "Windows file identity could not be verified"
            )
        return (
            int(information.dwVolumeSerialNumber),
            int(information.nFileIndexHigh),
            int(information.nFileIndexLow),
        )

    try:
        if file_descriptor is not None:
            existing = wintypes.HANDLE(msvcrt.get_osfhandle(file_descriptor))
            if identity(handle) != identity(existing):
                raise ValueError("Windows security handle does not match the opened file")
        return handle
    except Exception:
        close_handle(handle)
        raise


def _capture_windows_security_descriptor(
    path: Path,
    file_descriptor: int | None = None,
    *,
    native_handle=None,
) -> str:
    import ctypes
    from ctypes import wintypes

    descriptor = ctypes.c_void_p()
    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    local_free = kernel32.LocalFree
    local_free.argtypes = [ctypes.c_void_p]
    local_free.restype = ctypes.c_void_p
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    get_security = advapi32.GetSecurityInfo
    get_security.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    ]
    get_security.restype = wintypes.DWORD
    handle = native_handle
    owns_handle = native_handle is None
    try:
        privilege_scope = (
            _windows_privileges("SeBackupPrivilege", "SeSecurityPrivilege")
            if owns_handle
            else nullcontext()
        )
        with privilege_scope:
            if owns_handle:
                handle = _windows_open_security_handle(
                    path,
                    WINDOWS_READ_CONTROL
                    | WINDOWS_ACCESS_SYSTEM_SECURITY
                    | WINDOWS_FILE_READ_ATTRIBUTES,
                    file_descriptor,
                )
            code = get_security(
                handle,
                1,
                WINDOWS_SECURITY_INFORMATION,
                None,
                None,
                None,
                None,
                ctypes.byref(descriptor),
            )
        if code != 0 or not descriptor.value:
            raise OSError(int(code), "Windows file security descriptor could not be read")
        get_length = advapi32.GetSecurityDescriptorLength
        get_length.argtypes = [ctypes.c_void_p]
        get_length.restype = wintypes.DWORD
        length = int(get_length(descriptor))
        if not 1 <= length <= MAX_WINDOWS_SECURITY_DESCRIPTOR_BYTES:
            raise ValueError("Windows file security descriptor is outside its accepted size")
        return base64.b64encode(ctypes.string_at(descriptor, length)).decode("ascii")
    finally:
        if owns_handle and handle is not None:
            close_handle(handle)
        if descriptor.value:
            local_free(descriptor)


def _windows_restoration_security_information(
    control: int,
    *,
    dacl_present: bool,
    dacl_pointer: int,
    sacl_present: bool,
) -> int:
    """Select safe SetSecurityInfo fields without ever publishing a NULL DACL."""
    if not dacl_present:
        raise ValueError(
            "Windows security descriptor has no DACL; refusing NULL-DACL restoration"
        )
    if not dacl_pointer:
        raise ValueError(
            "Windows security descriptor has a NULL DACL; refusing unrestricted restoration"
        )
    # Set only components that are actually present. An absent SACL is tracked
    # independently and intentionally left absent; same-handle recapture verifies
    # the approved owner, group, DACL, SACL, and ACL-protection semantics.
    security_information = (
        WINDOWS_OWNER_SECURITY_INFORMATION
        | WINDOWS_GROUP_SECURITY_INFORMATION
        | WINDOWS_DACL_SECURITY_INFORMATION
    )
    security_information |= (
        WINDOWS_PROTECTED_DACL_SECURITY_INFORMATION
        if control & WINDOWS_SE_DACL_PROTECTED
        else WINDOWS_UNPROTECTED_DACL_SECURITY_INFORMATION
    )
    if sacl_present:
        security_information |= WINDOWS_SACL_SECURITY_INFORMATION
        security_information |= (
            WINDOWS_PROTECTED_SACL_SECURITY_INFORMATION
            if control & WINDOWS_SE_SACL_PROTECTED
            else WINDOWS_UNPROTECTED_SACL_SECURITY_INFORMATION
        )
    return security_information


def _restore_windows_security_descriptor(
    path: Path,
    encoded_descriptor: str,
    file_descriptor: int | None = None,
    *,
    native_handle=None,
) -> None:
    import ctypes
    from ctypes import wintypes

    try:
        raw_descriptor = base64.b64decode(
            encoded_descriptor.encode("ascii"), validate=True
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError("Windows file security descriptor is invalid") from exc
    if not 1 <= len(raw_descriptor) <= MAX_WINDOWS_SECURITY_DESCRIPTOR_BYTES:
        raise ValueError("Windows file security descriptor is outside its accepted size")
    buffer = ctypes.create_string_buffer(raw_descriptor, len(raw_descriptor))
    descriptor = ctypes.cast(buffer, ctypes.c_void_p)
    advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
    kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
    is_valid = advapi32.IsValidSecurityDescriptor
    is_valid.argtypes = [ctypes.c_void_p]
    is_valid.restype = wintypes.BOOL
    get_length = advapi32.GetSecurityDescriptorLength
    get_length.argtypes = [ctypes.c_void_p]
    get_length.restype = wintypes.DWORD
    if not is_valid(descriptor) or int(get_length(descriptor)) != len(raw_descriptor):
        raise ValueError("Windows file security descriptor is malformed")

    owner = ctypes.c_void_p()
    group = ctypes.c_void_p()
    dacl = ctypes.c_void_p()
    sacl = ctypes.c_void_p()
    owner_defaulted = wintypes.BOOL()
    group_defaulted = wintypes.BOOL()
    dacl_defaulted = wintypes.BOOL()
    sacl_defaulted = wintypes.BOOL()
    dacl_present = wintypes.BOOL()
    sacl_present = wintypes.BOOL()

    get_owner = advapi32.GetSecurityDescriptorOwner
    get_owner.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_owner.restype = wintypes.BOOL
    get_group = advapi32.GetSecurityDescriptorGroup
    get_group.argtypes = get_owner.argtypes
    get_group.restype = wintypes.BOOL
    get_dacl = advapi32.GetSecurityDescriptorDacl
    get_dacl.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    ]
    get_dacl.restype = wintypes.BOOL
    get_sacl = advapi32.GetSecurityDescriptorSacl
    get_sacl.argtypes = get_dacl.argtypes
    get_sacl.restype = wintypes.BOOL
    component_calls = (
        (get_owner, (descriptor, ctypes.byref(owner), ctypes.byref(owner_defaulted))),
        (get_group, (descriptor, ctypes.byref(group), ctypes.byref(group_defaulted))),
        (
            get_dacl,
            (
                descriptor,
                ctypes.byref(dacl_present),
                ctypes.byref(dacl),
                ctypes.byref(dacl_defaulted),
            ),
        ),
        (
            get_sacl,
            (
                descriptor,
                ctypes.byref(sacl_present),
                ctypes.byref(sacl),
                ctypes.byref(sacl_defaulted),
            ),
        ),
    )
    for getter, arguments in component_calls:
        if not getter(*arguments):
            raise OSError(
                ctypes.get_last_error(), "Windows security descriptor component is invalid"
            )
    get_control = advapi32.GetSecurityDescriptorControl
    get_control.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    get_control.restype = wintypes.BOOL
    control = wintypes.WORD()
    revision = wintypes.DWORD()
    if not get_control(descriptor, ctypes.byref(control), ctypes.byref(revision)):
        raise OSError(
            ctypes.get_last_error(), "Windows security descriptor protection state is invalid"
        )
    security_information = _windows_restoration_security_information(
        int(control.value),
        dacl_present=bool(dacl_present.value),
        dacl_pointer=int(dacl.value or 0),
        sacl_present=bool(sacl_present.value),
    )
    set_security = advapi32.SetSecurityInfo
    set_security.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    set_security.restype = wintypes.DWORD
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = [wintypes.HANDLE]
    close_handle.restype = wintypes.BOOL
    handle = native_handle
    owns_handle = native_handle is None
    try:
        privilege_names = ["SeRestorePrivilege"]
        if sacl_present.value:
            privilege_names.append("SeSecurityPrivilege")
        privilege_scope = (
            _windows_privileges(*privilege_names) if owns_handle else nullcontext()
        )
        with privilege_scope:
            if owns_handle:
                desired_access = (
                    WINDOWS_WRITE_DAC
                    | WINDOWS_WRITE_OWNER
                    | WINDOWS_FILE_READ_ATTRIBUTES
                )
                if sacl_present.value:
                    desired_access |= WINDOWS_ACCESS_SYSTEM_SECURITY
                handle = _windows_open_security_handle(
                    path,
                    desired_access,
                    file_descriptor,
                )
            code = set_security(
                handle,
                1,
                security_information,
                owner,
                group,
                dacl,
                sacl,
            )
        if code != 0:
            raise OSError(int(code), "Windows file security descriptor could not be restored")
    finally:
        if owns_handle and handle is not None:
            close_handle(handle)


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _synchronized(method):
    @functools.wraps(method)
    def guarded(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return guarded


class RestorePointStore:
    """Keep known-good bytes off the protected path and restore them transactionally.

    Restore points never leave the host. The controller sends only paths and hashes,
    while the agent verifies that the local bytes match the approved baseline before
    accepting them as known-good.
    """

    def __init__(
        self,
        state_dir: str | Path,
        authorized_networks: list[str] | None = None,
        *,
        authorized_hosts: list[str] | tuple[str, ...] | None = None,
        excluded_hosts: list[str] | tuple[str, ...] | None = None,
    ):
        self._lock = threading.RLock()
        self.root = Path(state_dir) / "restore-points"
        self.blobs = self.root / "blobs"
        self.evidence = self.root / "evidence"
        self.transactions = self.root / "transactions"
        self.manifest_path = self.root / "manifest.json"
        self._windows_temp_registry: _WindowsTempOwnershipRegistry | None = None
        self.authorized_networks = authorized_networks or []
        self.authorized_hosts = list(authorized_hosts or [])
        self.excluded_hosts = list(excluded_hosts or [])
        for directory in (self.root, self.blobs, self.evidence, self.transactions):
            if directory.is_symlink():
                raise ValueError("restoration state directories must not be symbolic links")
            directory.mkdir(parents=True, exist_ok=True)
            if not directory.is_dir():
                raise ValueError("restoration state path is not a directory")
            if os.name == "posix":
                directory.chmod(0o700)
        if os.name == "nt":
            self._windows_temp_registry = _WindowsTempOwnershipRegistry(
                self.root / "windows-temp-ownership"
            )
            cleanup = self._windows_temp_registry.cleanup()
            if not cleanup["healthy"]:
                raise ValueError(
                    "Windows restoration has unresolved authenticated temporary files"
                )

    @_synchronized
    def capture(self, items: list[dict[str, Any]]) -> dict[str, Any]:
        if not isinstance(items, list) or not items or len(items) > MAX_FILES:
            raise ValueError(f"restore point requires 1 to {MAX_FILES} files")
        manifest = self._read_manifest()
        captured: list[str] = []
        capture_receipts: list[dict[str, Any]] = []
        rejected: list[dict[str, str]] = []
        for item in items:
            try:
                path, expected = self._validate_item(item)
                expected_security = self._optional_digest(
                    item,
                    "security_descriptor_sha256",
                )
                data, metadata = self._read_target(path)
                actual = _digest(data)
                if actual != expected:
                    raise ValueError("local bytes no longer match the approved baseline")
                actual_security = self._metadata_security_descriptor_sha256(metadata)
                if os.name == "nt" and not expected_security:
                    raise ValueError(
                        "approved Windows baseline lacks a security descriptor fingerprint"
                    )
                if expected_security and actual_security != expected_security:
                    raise ValueError(
                        "local security metadata no longer matches the approved baseline"
                    )
                blob = self.blobs / expected
                existing_blob = self._read_private_file_if_present(
                    blob, MAX_FILE_BYTES
                )
                if existing_blob is None:
                    self._atomic_write(blob, data, 0o600)
                elif _digest(existing_blob) != expected:
                    raise ValueError("existing restore-point blob failed integrity validation")
                stored_blob = self._read_private_file(blob, MAX_FILE_BYTES)
                backup_sha256 = _digest(stored_blob)
                if backup_sha256 != actual or stored_blob != data:
                    raise ValueError(
                        "captured restore-point bytes do not match the approved source"
                    )
                canonical_path = self._canonical_receipt_path(path)
                record_id = str(uuid.uuid4())
                security_metadata_sha256 = self._metadata_receipt_sha256(metadata)
                captured_at = time.time()
                manifest[canonical_path] = {
                    "sha256": expected,
                    "size": len(data),
                    "mode": metadata["mode"],
                    "uid": metadata["uid"],
                    "gid": metadata["gid"],
                    "xattrs": metadata.get("xattrs", {}),
                    "windows_security_descriptor": metadata.get(
                        "windows_security_descriptor"
                    ),
                    "windows_security_descriptor_version": metadata.get(
                        "windows_security_descriptor_version"
                    ),
                    "captured_at": captured_at,
                    "restore_point_id": record_id,
                    "security_metadata_sha256": security_metadata_sha256,
                }
                captured.append(canonical_path)
                capture_receipts.append(
                    {
                        "path": canonical_path,
                        "source_sha256": actual,
                        "backup_sha256": backup_sha256,
                        "backup_matches_source": True,
                        "byte_size": len(data),
                        "security_metadata_sha256": security_metadata_sha256,
                        "security_descriptor_sha256": actual_security,
                        "restore_point_id": record_id,
                        "stored": True,
                    }
                )
            except (OSError, ValueError) as exc:
                rejected.append({"path": str(item.get("path", "")), "reason": str(exc)})
        self._write_manifest(manifest)
        return {
            "success": not rejected,
            "message": f"captured {len(captured)} approved restore point(s)",
            "captured": captured,
            "capture_receipts": capture_receipts,
            "rejected": rejected,
        }

    @_synchronized
    def restore(
        self,
        parameters: dict[str, Any],
        *,
        allowed: bool,
        probes: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        path, expected = self._validate_item(parameters)
        baseline_security = self._optional_digest(
            parameters,
            "baseline_security_descriptor_sha256",
        )
        observed_security = self._optional_digest(
            parameters,
            "observed_security_descriptor_sha256",
        )
        observed_missing = parameters.get("observed_missing", False)
        if type(observed_missing) is not bool:
            raise ValueError("observed_missing must be a boolean")
        observed = parameters.get("observed_sha256")
        if observed is not None:
            observed = str(observed).casefold()
            if not SHA256.fullmatch(observed):
                raise ValueError("observed_sha256 must be a SHA-256 digest")
        manifest = self._read_manifest()
        record = manifest.get(str(path))
        if not isinstance(record, dict) or record.get("sha256") != expected:
            raise ValueError("no approved restore point exists for this exact path and digest")
        record_security = self._metadata_security_descriptor_sha256(record)
        if os.name == "nt" and not baseline_security:
            raise ValueError(
                "approved Windows baseline lacks a security descriptor fingerprint"
            )
        if baseline_security and record_security != baseline_security:
            raise ValueError(
                "restore-point security metadata does not match the approved baseline"
            )
        if not allowed:
            return {
                "success": True,
                "message": f"dry run: would restore {path}",
                "dry_run": True,
            }
        blob = self.blobs / expected
        trusted = self._read_private_file(blob, MAX_FILE_BYTES)
        if _digest(trusted) != expected:
            raise ValueError("approved restore-point blob failed integrity validation")

        existing_target = self._read_target_if_present(path)
        existed = existing_target is not None
        before = b""
        before_meta = {"mode": 0o600, "uid": -1, "gid": -1}
        if existed:
            assert existing_target is not None
            before, before_meta = existing_target
            if observed_missing:
                raise ValueError("target reappeared after the monitored observation")
            if observed is not None and _digest(before) != observed:
                raise ValueError("target changed again after the monitored observation")
            if observed_security and self._metadata_security_descriptor_sha256(
                before_meta
            ) != observed_security:
                raise ValueError(
                    "target security metadata changed again after the monitored observation"
                )
            if os.name == "nt" and observed is not None and not observed_security:
                raise ValueError(
                    "monitored Windows observation lacks a security descriptor fingerprint"
                )
        elif observed is not None:
            raise ValueError("target disappeared after the monitored observation")

        transaction_id = str(uuid.uuid4())
        evidence_name = f"{transaction_id}.bin"
        if existed:
            self._atomic_write(self.evidence / evidence_name, before, 0o600)
        transaction = {
            "transaction_id": transaction_id,
            "path": str(path),
            "existed": existed,
            "before_sha256": _digest(before) if existed else None,
            "evidence": evidence_name if existed else None,
            "before_metadata": before_meta,
            "restored_sha256": expected,
            "restored_metadata": self._metadata_snapshot(record),
            "created_at": time.time(),
            "status": "prepared",
            "rolled_back": False,
        }
        self._write_json(self.transactions / f"{transaction_id}.json", transaction)

        restored_expected: tuple[bytes, dict[str, Any]] = (
            trusted,
            self._metadata_snapshot(record),
        )
        try:
            self._replace_target(
                path,
                trusted,
                record,
                **(
                    {"expected_current": existing_target}
                    if os.name == "nt"
                    else {}
                ),
            )
            restored_bytes, restored_meta = self._read_target(path)
            if _digest(restored_bytes) != expected or not self._metadata_matches(
                transaction["restored_metadata"], restored_meta
            ):
                raise OSError(
                    "post-restoration bytes or security metadata did not match the approved restore point"
                )
            restored_expected = (restored_bytes, restored_meta)
            validation = validate_restored_configuration(path)
            if (
                validation["applicable"]
                and validation["available"]
                and validation["healthy"] is False
            ):
                self._restore_before_verified(
                    path,
                    existed,
                    before,
                    before_meta,
                    expected_current=restored_expected,
                )
                transaction["rolled_back"] = True
                transaction["status"] = "rolled_back"
                self._write_json(self.transactions / f"{transaction_id}.json", transaction)
                return {
                    "success": False,
                    "message": "file restoration failed configuration validation and was rolled back",
                    "rolled_back": True,
                    "transaction_id": transaction_id,
                    "config_validation": validation,
                    "probes": [],
                }
            results = run_probes(
                probes or [],
                self.authorized_networks,
                authorized_hosts=self.authorized_hosts,
                excluded_hosts=self.excluded_hosts,
            )
            if results and not all(item.healthy for item in results):
                self._restore_before_verified(
                    path,
                    existed,
                    before,
                    before_meta,
                    expected_current=restored_expected,
                )
                transaction["rolled_back"] = True
                transaction["status"] = "rolled_back"
                self._write_json(self.transactions / f"{transaction_id}.json", transaction)
                return {
                    "success": False,
                    "message": "file restoration failed service validation and was rolled back",
                    "rolled_back": True,
                    "transaction_id": transaction_id,
                    "config_validation": validation,
                    "probes": [asdict(item) for item in results],
                }
            transaction["status"] = "committed"
            transaction["committed_at"] = time.time()
            self._write_json(self.transactions / f"{transaction_id}.json", transaction)
            return {
                "success": True,
                "message": f"restored {path} from the approved local restore point",
                "transaction_id": transaction_id,
                "evidence_preserved": bool(existed),
                "pre_state": {"transaction_id": transaction_id},
                "config_validation": validation,
                "probes": [asdict(item) for item in results],
            }
        except Exception:
            try:
                self._restore_before_verified(
                    path,
                    existed,
                    before,
                    before_meta,
                    expected_current=restored_expected,
                )
                transaction["rolled_back"] = True
                transaction["status"] = "rolled_back"
                self._write_json(self.transactions / f"{transaction_id}.json", transaction)
            except Exception:
                transaction["status"] = "rollback_failed"
                transaction["rollback_failed_at"] = time.time()
                try:
                    self._write_json(
                        self.transactions / f"{transaction_id}.json", transaction
                    )
                except Exception:
                    pass
                raise
            raise

    @_synchronized
    def rollback(
        self,
        transaction_id: str,
        *,
        allowed: bool,
        probes: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        if not TRANSACTION_ID.fullmatch(transaction_id):
            raise ValueError("invalid restoration transaction identifier")
        transaction_path = self.transactions / f"{transaction_id}.json"
        transaction = strict_json_loads(
            self._read_private_file(transaction_path, MAX_TRANSACTION_BYTES),
            max_bytes=MAX_TRANSACTION_BYTES,
        )
        if not isinstance(transaction, dict) or transaction.get("transaction_id") != transaction_id:
            raise ValueError("restoration transaction record is invalid")
        if transaction.get("rolled_back"):
            return {"success": True, "message": "restoration was already rolled back"}
        if transaction.get("status", "committed") != "committed":
            raise ValueError("restoration transaction is not ready for operator undo")
        path = Path(str(transaction["path"]))
        if not allowed:
            return {
                "success": True,
                "message": f"dry run: would undo restoration of {path}",
                "dry_run": True,
            }
        existing_target = self._read_target_if_present(path)
        if existing_target is None:
            raise ValueError("restored target is unavailable or is now a symbolic link")
        restored, restored_meta = existing_target
        restored_metadata = transaction.get("restored_metadata") or {}
        if not restored_metadata:
            legacy_record = self._read_manifest().get(str(path))
            if (
                not isinstance(legacy_record, dict)
                or legacy_record.get("sha256") != transaction.get("restored_sha256")
            ):
                raise ValueError("restoration transaction lacks trusted security metadata")
            restored_metadata = self._metadata_snapshot(legacy_record)
            transaction["restored_metadata"] = restored_metadata
        if _digest(restored) != transaction["restored_sha256"] or not self._metadata_matches(
            restored_metadata, restored_meta
        ):
            raise ValueError(
                "target bytes or security metadata changed after restoration; refusing to overwrite newer data"
            )
        existed = bool(transaction.get("existed"))
        before = b""
        before_meta = transaction.get("before_metadata") or {}
        if existed:
            evidence = self.evidence / str(transaction["evidence"])
            if evidence.name != f"{transaction_id}.bin":
                raise ValueError("restoration evidence reference is invalid")
            before = self._read_private_file(evidence, MAX_FILE_BYTES)
            if _digest(before) != transaction["before_sha256"]:
                raise ValueError("preserved pre-restoration evidence failed integrity validation")
        transaction["status"] = "undo_prepared"
        transaction["undo_started_at"] = time.time()
        self._write_json(transaction_path, transaction)
        try:
            self._restore_before(
                path,
                existed,
                before,
                before_meta,
                expected_current=existing_target,
            )
            if existed:
                undo_bytes, undo_meta = self._read_target(path)
                if _digest(undo_bytes) != transaction["before_sha256"] or not self._metadata_matches(
                    before_meta, undo_meta
                ):
                    raise OSError("operator undo did not restore the preserved bytes and metadata")
            elif self._read_target_if_present(path) is not None:
                raise OSError("operator undo did not remove the newly restored target")
            results = run_probes(
                probes or [],
                self.authorized_networks,
                authorized_hosts=self.authorized_hosts,
                excluded_hosts=self.excluded_hosts,
            )
            if results and not all(item.healthy for item in results):
                if existed:
                    undo_expected: tuple[bytes, dict[str, Any]] | None = (
                        before,
                        undo_meta,
                    )
                else:
                    undo_expected = None
                self._replace_target(
                    path,
                    restored,
                    restored_metadata,
                    **(
                        {"expected_current": undo_expected}
                        if os.name == "nt"
                        else {}
                    ),
                )
                reapplied_bytes, reapplied_meta = self._read_target(path)
                if _digest(reapplied_bytes) != transaction["restored_sha256"] or not self._metadata_matches(
                    restored_metadata, reapplied_meta
                ):
                    raise OSError("approved restoration could not be safely reapplied")
                transaction["status"] = "committed"
                transaction["undo_failed_at"] = time.time()
                self._write_json(transaction_path, transaction)
                return {
                    "success": False,
                    "message": "undo failed service validation; approved restoration was reapplied",
                    "rolled_back": True,
                    "probes": [asdict(item) for item in results],
                }
        except Exception as exc:
            try:
                current_after_undo = self._read_target_if_present(path)
                if existed:
                    if current_after_undo is None:
                        raise ValueError(
                            "undo target disappeared; refusing to recreate over an ambiguous state"
                        )
                    current_bytes, current_meta = current_after_undo
                    if _digest(current_bytes) != transaction["before_sha256"] or not self._metadata_matches(
                        before_meta, current_meta
                    ):
                        raise ValueError(
                            "undo target has a newer change; refusing to overwrite it"
                        )
                    undo_expected = current_after_undo
                else:
                    if current_after_undo is not None:
                        raise ValueError(
                            "undo target reappeared; refusing to overwrite it"
                        )
                    undo_expected = None
                self._replace_target(
                    path,
                    restored,
                    restored_metadata,
                    **(
                        {"expected_current": undo_expected}
                        if os.name == "nt"
                        else {}
                    ),
                )
                reapplied_bytes, reapplied_meta = self._read_target(path)
                if _digest(reapplied_bytes) != transaction["restored_sha256"] or not self._metadata_matches(
                    restored_metadata, reapplied_meta
                ):
                    raise OSError("approved restoration could not be safely reapplied")
                transaction["status"] = "committed"
                transaction["undo_failed_at"] = time.time()
                transaction["undo_failure"] = type(exc).__name__
                self._write_json(transaction_path, transaction)
            except Exception:
                transaction["status"] = "undo_failed"
                transaction["undo_failed_at"] = time.time()
                try:
                    self._write_json(transaction_path, transaction)
                except Exception:
                    pass
                raise
            raise
        transaction["rolled_back"] = True
        transaction["status"] = "rolled_back"
        transaction["rolled_back_at"] = time.time()
        self._write_json(transaction_path, transaction)
        return {
            "success": True,
            "message": f"restoration of {path} was undone",
            "probes": [asdict(item) for item in results],
        }

    @_synchronized
    def recover_incomplete(self) -> dict[str, Any]:
        """Undo only our own prepared restoration after an interrupted process."""
        recovered: list[str] = []
        unresolved: list[dict[str, str]] = []
        records = sorted(self.transactions.glob("*.json"))
        if len(records) > 1024:
            unresolved.append(
                {
                    "transaction": "*",
                    "reason": "more than 1,024 restoration transactions require retention cleanup",
                }
            )
        records = records[:1024]
        for transaction_path in records:
            try:
                transaction_id = transaction_path.stem
                if not TRANSACTION_ID.fullmatch(transaction_id):
                    raise ValueError("invalid transaction filename")
                transaction = strict_json_loads(
                    self._read_private_file(transaction_path, MAX_TRANSACTION_BYTES),
                    max_bytes=MAX_TRANSACTION_BYTES,
                )
                if not isinstance(transaction, dict) or transaction.get("transaction_id") != transaction_id:
                    raise ValueError("invalid transaction record")
                # Transactions written before the state field was introduced completed
                # synchronously and are treated as committed for compatibility.
                status = transaction.get("status", "committed")
                if status in {"undo_failed", "rollback_failed"}:
                    raise ValueError(
                        f"prior {status.replace('_', ' ')} requires operator recovery"
                    )
                if status not in {"prepared", "undo_prepared"}:
                    if status not in {"committed", "rolled_back", "recovered"}:
                        raise ValueError("restoration transaction status is invalid")
                    continue
                path = Path(str(transaction.get("path", "")))
                if not path.is_absolute() or (
                    os.name != "nt" and path.is_symlink()
                ):
                    raise ValueError("prepared transaction target is unsafe")
                self._validate_windows_path(path)
                existed = bool(transaction.get("existed"))
                before = b""
                before_meta = transaction.get("before_metadata") or {}
                before_digest = transaction.get("before_sha256")
                restored_digest = str(transaction.get("restored_sha256", ""))
                if not SHA256.fullmatch(restored_digest):
                    raise ValueError("prepared transaction digest is invalid")
                restored_metadata = transaction.get("restored_metadata") or {}
                if not restored_metadata:
                    legacy_record = self._read_manifest().get(str(path))
                    if (
                        not isinstance(legacy_record, dict)
                        or legacy_record.get("sha256") != restored_digest
                    ):
                        raise ValueError("prepared transaction lacks trusted security metadata")
                    restored_metadata = self._metadata_snapshot(legacy_record)
                    transaction["restored_metadata"] = restored_metadata
                if status == "undo_prepared":
                    trusted = self._read_private_file(self.blobs / restored_digest, MAX_FILE_BYTES)
                    if _digest(trusted) != restored_digest:
                        raise ValueError("undo recovery restore-point blob failed integrity validation")
                    current_target = self._read_target_if_present(path)
                    if current_target is not None:
                        current, current_meta = current_target
                        current_digest = _digest(current)
                        if current_digest == restored_digest and self._metadata_matches(
                            restored_metadata, current_meta
                        ):
                            pass
                        elif existed and current_digest == before_digest and self._metadata_matches(
                            before_meta, current_meta
                        ):
                            self._replace_target(
                                path,
                                trusted,
                                restored_metadata,
                                **(
                                    {"expected_current": current_target}
                                    if os.name == "nt"
                                    else {}
                                ),
                            )
                        else:
                            raise ValueError(
                                "undo recovery target has a newer change; refusing startup overwrite"
                            )
                    elif not existed:
                        self._replace_target(
                            path,
                            trusted,
                            restored_metadata,
                            **(
                                {"expected_current": None}
                                if os.name == "nt"
                                else {}
                            ),
                        )
                    else:
                        raise ValueError("undo recovery target is unavailable")
                    recovered_bytes, recovered_meta = self._read_target(path)
                    if _digest(recovered_bytes) != restored_digest or not self._metadata_matches(
                        restored_metadata, recovered_meta
                    ):
                        raise OSError("undo recovery could not reapply the approved restoration")
                    transaction["status"] = "committed"
                    transaction["rolled_back"] = False
                    transaction["undo_recovered_at"] = time.time()
                    self._write_json(transaction_path, transaction)
                    recovered.append(transaction_id)
                    continue
                if existed:
                    evidence_name = str(transaction.get("evidence", ""))
                    if evidence_name != f"{transaction_id}.bin":
                        raise ValueError("prepared transaction evidence reference is invalid")
                    before = self._read_private_file(self.evidence / evidence_name, MAX_FILE_BYTES)
                    if _digest(before) != before_digest:
                        raise ValueError("prepared transaction evidence failed integrity validation")
                    observed_target = self._read_target_if_present(path)
                    if observed_target is None:
                        raise ValueError("prepared transaction target is unavailable")
                    observed_bytes, observed_meta = observed_target
                    observed = _digest(observed_bytes)
                    if observed == before_digest and self._metadata_matches(before_meta, observed_meta):
                        pass
                    elif observed == restored_digest and self._metadata_matches(
                        restored_metadata, observed_meta
                    ):
                        self._replace_target(
                            path,
                            before,
                            before_meta,
                            **(
                                {"expected_current": observed_target}
                                if os.name == "nt"
                                else {}
                            ),
                        )
                    else:
                        raise ValueError("target has a newer change; refusing startup overwrite")
                else:
                    observed_target = self._read_target_if_present(path)
                    if observed_target is None:
                        observed_bytes = None
                        observed_meta = None
                    else:
                        observed_bytes, observed_meta = observed_target
                if not existed and observed_bytes is not None:
                    assert observed_meta is not None
                    if _digest(observed_bytes) != restored_digest or not self._metadata_matches(
                        restored_metadata, observed_meta
                    ):
                        raise ValueError("target has a newer change; refusing startup removal")
                    self._unlink_target(
                        path,
                        **(
                            {"expected_current": observed_target}
                            if os.name == "nt"
                            else {}
                        ),
                    )
                transaction["status"] = "recovered"
                transaction["rolled_back"] = True
                transaction["rolled_back_at"] = time.time()
                self._write_json(transaction_path, transaction)
                recovered.append(transaction_id)
            except (OSError, ValueError, KeyError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                unresolved.append({"transaction": transaction_path.name, "reason": str(exc)[:500]})
        return {
            "healthy": not unresolved,
            "recovered": recovered,
            "unresolved": unresolved,
        }

    @staticmethod
    def _validate_item(item: dict[str, Any]) -> tuple[Path, str]:
        if not isinstance(item, dict):
            raise ValueError("restore-point item must be an object")
        raw_path = str(item.get("path", ""))
        if not raw_path or "\x00" in raw_path or len(raw_path) > 1024:
            raise ValueError("invalid restore-point path")
        path = Path(raw_path)
        if not path.is_absolute():
            raise ValueError("restore-point path must be absolute")
        expected = str(item.get("sha256") or item.get("baseline_sha256") or "").casefold()
        if not SHA256.fullmatch(expected):
            raise ValueError("restore-point digest must be SHA-256")
        return path, expected

    @staticmethod
    def _optional_digest(item: dict[str, Any], name: str) -> str:
        value = item.get(name, "")
        if value in (None, ""):
            return ""
        digest = str(value).casefold()
        if not SHA256.fullmatch(digest):
            raise ValueError(f"{name} must be a SHA-256 digest")
        return digest

    @staticmethod
    def _metadata_security_descriptor_sha256(metadata: dict[str, Any]) -> str:
        descriptor = metadata.get("windows_security_descriptor")
        if not isinstance(descriptor, str) or not descriptor:
            return ""
        try:
            encoded = descriptor.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ValueError("Windows security descriptor metadata is invalid") from exc
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _canonical_receipt_path(path: Path) -> str:
        if os.name == "nt":
            normalized = ntpath.normpath(str(path))
            drive, tail = ntpath.splitdrive(normalized)
            return f"{drive.upper()}{tail}"
        return os.path.normpath(str(path))

    @classmethod
    def _metadata_receipt_sha256(cls, metadata: dict[str, Any]) -> str:
        encoded = json.dumps(
            cls._metadata_snapshot(metadata),
            allow_nan=False,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _capture_xattrs(descriptor: int) -> dict[str, str]:
        if os.name != "posix" or not hasattr(os, "listxattr"):
            return {}
        names = sorted(os.listxattr(descriptor))
        if len(names) > MAX_XATTRS:
            raise ValueError("target has too many extended attributes to restore safely")
        result: dict[str, str] = {}
        total = 0
        for name in names:
            if not isinstance(name, str) or not name or len(name) > 255:
                raise ValueError("target has an invalid extended-attribute name")
            value = os.getxattr(descriptor, name)
            total += len(name.encode("utf-8")) + len(value)
            if total > MAX_XATTR_BYTES:
                raise ValueError("target extended attributes exceed the restoration limit")
            result[name] = base64.b64encode(value).decode("ascii")
        return result

    @staticmethod
    def _windows_acl(path: Path, file_descriptor: int | None = None) -> str | None:
        if os.name != "nt":
            return None
        # This compatibility helper deliberately ignores a path-opened CRT
        # descriptor. The native snapshot is the only supported Windows capture
        # path because it pins every ancestor and binds bytes and ACL to one leaf.
        del file_descriptor
        _data, snapshot = _windows_read_file_snapshot(path, MAX_FILE_BYTES)
        descriptor = snapshot.get("windows_security_descriptor")
        if not isinstance(descriptor, str) or not descriptor:
            raise OSError("Windows file security descriptor could not be read")
        return descriptor

    @staticmethod
    def _windows_target_metadata(snapshot: dict[str, Any]) -> dict[str, Any]:
        return _windows_metadata_from_native_snapshot(snapshot)

    @classmethod
    def _read_target(cls, path: Path) -> tuple[bytes, dict[str, Any]]:
        cls._validate_windows_path(path)
        if os.name == "nt":
            data, snapshot = _windows_read_file_snapshot(path, MAX_FILE_BYTES)
            return data, cls._windows_target_metadata(snapshot)
        if path.is_symlink():
            raise ValueError("target is not a regular non-symlink file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        parent_descriptor = cls._open_parent_descriptor(path)
        try:
            descriptor = (
                os.open(path.name, flags, dir_fd=parent_descriptor)
                if parent_descriptor is not None
                else os.open(path, flags)
            )
        finally:
            if parent_descriptor is not None:
                os.close(parent_descriptor)
        try:
            before_info = os.fstat(descriptor)
            if not stat.S_ISREG(before_info.st_mode):
                raise ValueError("target is not a regular non-symlink file")
            if before_info.st_size > MAX_FILE_BYTES:
                raise ValueError(f"target exceeds {MAX_FILE_BYTES} byte restore-point limit")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
            if len(data) > MAX_FILE_BYTES:
                raise ValueError(f"target exceeds {MAX_FILE_BYTES} byte restore-point limit")
            before_xattrs = cls._capture_xattrs(descriptor)
            after_info = os.fstat(descriptor)
            after_xattrs = cls._capture_xattrs(descriptor)
            stable_fields = (
                "st_dev",
                "st_ino",
                "st_mode",
                "st_uid",
                "st_gid",
                "st_size",
                "st_mtime_ns",
                "st_ctime_ns",
            )
            if any(
                getattr(before_info, field, None) != getattr(after_info, field, None)
                for field in stable_fields
            ) or before_xattrs != after_xattrs:
                raise ValueError(
                    "target bytes or security metadata changed during restore-point capture"
                )
            metadata: dict[str, Any] = {
                "mode": stat.S_IMODE(before_info.st_mode),
                "uid": int(getattr(before_info, "st_uid", -1)),
                "gid": int(getattr(before_info, "st_gid", -1)),
                "xattrs": before_xattrs,
                "windows_security_descriptor": None,
                "windows_security_descriptor_version": None,
            }
            return data, metadata
        finally:
            os.close(descriptor)

    @classmethod
    def _read_target_if_present(
        cls, path: Path
    ) -> tuple[bytes, dict[str, Any]] | None:
        """Preserve POSIX gates; use only pinned native state on Windows."""
        cls._validate_windows_path(path)
        if os.name == "nt":
            result = _windows_read_file_snapshot_if_present(path, MAX_FILE_BYTES)
            if result is None:
                return None
            data, snapshot = result
            return data, cls._windows_target_metadata(snapshot)
        if not path.exists() and not path.is_symlink():
            return None
        return cls._read_target(path)

    def _read_manifest(self) -> dict[str, Any]:
        encoded = self._read_private_file_if_present(
            self.manifest_path, MAX_MANIFEST_BYTES
        )
        if encoded is None:
            return {}
        try:
            payload = strict_json_loads(encoded, max_bytes=MAX_MANIFEST_BYTES)
        except (ValueError, UnicodeError) as exc:
            raise ValueError("restore-point manifest is corrupt; refusing to overwrite it") from exc
        if not isinstance(payload, dict):
            raise ValueError("restore-point manifest is not an object; refusing to overwrite it")
        return payload

    @classmethod
    def _read_private_file(cls, path: Path, maximum: int) -> bytes:
        cls._validate_windows_path(path)
        if os.name == "nt":
            data, _snapshot = _windows_read_file_snapshot(
                path,
                maximum,
                capture_security=False,
            )
            return data
        if path.is_symlink():
            raise ValueError("private restoration state is not a regular non-symlink file")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        parent_descriptor = cls._open_parent_descriptor(path)
        try:
            descriptor = (
                os.open(path.name, flags, dir_fd=parent_descriptor)
                if parent_descriptor is not None
                else os.open(path, flags)
            )
        finally:
            if parent_descriptor is not None:
                os.close(parent_descriptor)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("private restoration state is not a regular non-symlink file")
            if info.st_size > maximum:
                raise ValueError("private restoration state exceeds its size limit")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                data = handle.read(maximum + 1)
            if len(data) > maximum:
                raise ValueError("private restoration state exceeds its size limit")
            return data
        finally:
            os.close(descriptor)

    @classmethod
    def _read_private_file_if_present(cls, path: Path, maximum: int) -> bytes | None:
        """Read optional private state without a Windows path-based existence gate."""
        cls._validate_windows_path(path)
        if os.name == "nt":
            result = _windows_read_file_snapshot_if_present(
                path,
                maximum,
                capture_security=False,
            )
            return None if result is None else result[0]
        if not path.exists() and not path.is_symlink():
            return None
        return cls._read_private_file(path, maximum)

    def _write_manifest(self, manifest: dict[str, Any]) -> None:
        self._write_json(self.manifest_path, manifest)

    def _write_json(self, destination: Path, payload: dict[str, Any]) -> None:
        maximum = (
            MAX_MANIFEST_BYTES
            if destination == self.manifest_path
            else MAX_TRANSACTION_BYTES
            if destination.parent == self.transactions
            else 1024 * 1024
        )
        try:
            canonical_json_bytes(payload, max_bytes=maximum)
            encoded = json.dumps(
                payload,
                allow_nan=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8")
            if len(encoded) > maximum:
                raise ValueError("encoded JSON exceeds the byte limit")
        except (TypeError, ValueError, UnicodeError) as exc:
            raise ValueError("private restoration state is invalid or exceeds its size limit") from exc
        self._atomic_write(
            destination,
            encoded,
            0o600,
        )

    @staticmethod
    def _open_parent_descriptor(path: Path) -> int | None:
        """Open every POSIX parent component without following symbolic links."""
        if os.name != "posix":
            return None
        if not path.is_absolute() or not path.name:
            raise ValueError("restoration path must be an absolute file path")
        components = path.parent.parts[1:]
        if any(component in {"", ".", ".."} for component in components):
            raise ValueError("restoration path contains an unsafe parent component")
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open("/", flags)
        try:
            for component in components:
                child = os.open(component, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except Exception:
            os.close(descriptor)
            raise

    @staticmethod
    def _validate_windows_path(path: Path) -> None:
        if os.name != "nt":
            return
        # Native restoration intentionally accepts only absolute local-drive paths.
        # Namespace aliases, UNC, ADS, dot components, reserved device names, and
        # trailing-dot/space aliases remain outside the supported boundary.
        # Filesystem checks happen only through the pinned native handle walk. A
        # path-based lstat here would reintroduce the ancestor-swap race that the
        # native operations are specifically designed to close.
        _windows_path_components(path)

    @staticmethod
    def _metadata_snapshot(metadata: dict[str, Any]) -> dict[str, Any]:
        return {
            "mode": int(metadata.get("mode", 0o600)),
            "uid": int(metadata.get("uid", -1)),
            "gid": int(metadata.get("gid", -1)),
            "xattrs": dict(metadata.get("xattrs", {})),
            "windows_security_descriptor": metadata.get(
                "windows_security_descriptor"
            ),
            "windows_security_descriptor_version": metadata.get(
                "windows_security_descriptor_version"
            ),
        }

    @classmethod
    def _metadata_matches(cls, expected: dict[str, Any], observed: dict[str, Any]) -> bool:
        if not isinstance(expected, dict) or not isinstance(observed, dict):
            return False
        if os.name == "nt":
            expected_descriptor = expected.get("windows_security_descriptor")
            return bool(
                isinstance(expected_descriptor, str)
                and expected_descriptor
                and expected.get("windows_security_descriptor_version")
                == WINDOWS_SECURITY_DESCRIPTOR_VERSION
                and observed.get("windows_security_descriptor_version")
                == WINDOWS_SECURITY_DESCRIPTOR_VERSION
                and int(expected.get("mode", 0)) == int(observed.get("mode", -1))
                and _windows_security_descriptors_equivalent(
                    expected_descriptor,
                    observed.get("windows_security_descriptor"),
                )
            )
        return cls._metadata_snapshot(expected) == cls._metadata_snapshot(observed)

    def _atomic_write(
        self,
        destination: Path,
        data: bytes,
        mode: int,
        metadata: dict[str, Any] | None = None,
        *,
        expected_current: tuple[bytes, dict[str, Any]] | None | object = (
            _WINDOWS_EXPECTED_UNSPECIFIED
        ),
        temp_registry: _WindowsTempOwnershipRegistry | None = None,
    ) -> None:
        self._validate_windows_path(destination)
        if os.name == "nt":
            registry = temp_registry or self._windows_temp_registry
            if registry is not None:
                cleanup = registry.cleanup()
                if not cleanup["healthy"]:
                    raise ValueError(
                        "Windows restoration has unresolved authenticated temporary files"
                    )
            _windows_atomic_write(
                destination,
                data,
                mode,
                metadata,
                expected_current=expected_current,
                temp_registry=registry,
            )
            return
        if destination.parent.is_symlink() or not destination.parent.is_dir():
            raise ValueError("restoration destination directory is unavailable or unsafe")
        if os.name == "posix":
            parent_descriptor = self._open_parent_descriptor(destination)
            assert parent_descriptor is not None
            temporary_name = f".sentinel-{uuid.uuid4().hex}.tmp"
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = -1
            try:
                descriptor = os.open(temporary_name, flags, 0o600, dir_fd=parent_descriptor)
                with os.fdopen(descriptor, "wb", closefd=False) as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                self._apply_posix_metadata_descriptor(descriptor, metadata or {"mode": mode})
                try:
                    target_info = os.stat(
                        destination.name,
                        dir_fd=parent_descriptor,
                        follow_symlinks=False,
                    )
                    if stat.S_ISLNK(target_info.st_mode):
                        raise ValueError("refusing to replace a symbolic-link target")
                except FileNotFoundError:
                    pass
                os.replace(
                    temporary_name,
                    destination.name,
                    src_dir_fd=parent_descriptor,
                    dst_dir_fd=parent_descriptor,
                )
                os.fsync(parent_descriptor)
                return
            except Exception:
                try:
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
                except OSError:
                    pass
                raise
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
                os.close(parent_descriptor)
        raise RuntimeError("unsupported restoration platform")

    @staticmethod
    def _apply_posix_metadata_descriptor(descriptor: int, metadata: dict[str, Any]) -> None:
        mode = int(metadata.get("mode", 0o600)) & 0o7777 or 0o600
        uid = int(metadata.get("uid", -1))
        gid = int(metadata.get("gid", -1))
        if uid >= 0 or gid >= 0:
            try:
                os.fchown(descriptor, uid, gid)
            except PermissionError:
                info = os.fstat(descriptor)
                if (uid >= 0 and info.st_uid != uid) or (gid >= 0 and info.st_gid != gid):
                    raise
        os.fchmod(descriptor, mode)
        encoded_xattrs = metadata.get("xattrs", {})
        if not isinstance(encoded_xattrs, dict) or len(encoded_xattrs) > MAX_XATTRS:
            raise ValueError("restore-point extended-attribute metadata is invalid")
        total = 0
        for name, encoded in encoded_xattrs.items():
            if not isinstance(name, str) or not isinstance(encoded, str):
                raise ValueError("restore-point extended-attribute metadata is invalid")
            try:
                value = base64.b64decode(encoded.encode("ascii"), validate=True)
            except (ValueError, UnicodeEncodeError) as exc:
                raise ValueError("restore-point extended-attribute value is invalid") from exc
            total += len(name.encode("utf-8")) + len(value)
            if total > MAX_XATTR_BYTES:
                raise ValueError("restore-point extended attributes exceed the restoration limit")
            os.setxattr(descriptor, name, value)

    def _unlink_target(
        self,
        path: Path,
        *,
        expected_current: tuple[bytes, dict[str, Any]] | object = (
            _WINDOWS_EXPECTED_UNSPECIFIED
        ),
    ) -> None:
        self._validate_windows_path(path)
        if os.name == "nt":
            _windows_unlink(path, expected_current=expected_current)
            return
        parent_descriptor = self._open_parent_descriptor(path)
        assert parent_descriptor is not None
        try:
            try:
                info = os.stat(path.name, dir_fd=parent_descriptor, follow_symlinks=False)
            except FileNotFoundError:
                return
            if stat.S_ISLNK(info.st_mode):
                raise ValueError("refusing to remove a symbolic-link target")
            os.unlink(path.name, dir_fd=parent_descriptor)
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)

    @staticmethod
    def _apply_windows_acl(
        path: Path,
        encoded_descriptor: str | None,
        file_descriptor: int | None = None,
    ) -> None:
        if os.name != "nt" or not encoded_descriptor:
            return
        if (
            not isinstance(encoded_descriptor, str)
            or not encoded_descriptor
            or len(encoded_descriptor) > MAX_WINDOWS_SECURITY_DESCRIPTOR_TEXT
            or "\x00" in encoded_descriptor
        ):
            raise ValueError("restore-point Windows security descriptor is invalid")
        if file_descriptor is None:
            _restore_windows_security_descriptor(path, encoded_descriptor)
        else:
            _restore_windows_security_descriptor(path, encoded_descriptor, file_descriptor)

    def _replace_target(
        self,
        path: Path,
        data: bytes,
        metadata: dict[str, Any],
        *,
        expected_current: tuple[bytes, dict[str, Any]] | None | object = (
            _WINDOWS_EXPECTED_UNSPECIFIED
        ),
    ) -> None:
        if os.name == "nt":
            encoded_descriptor = metadata.get("windows_security_descriptor")
            if (
                metadata.get("windows_security_descriptor_version")
                != WINDOWS_SECURITY_DESCRIPTOR_VERSION
                or not isinstance(encoded_descriptor, str)
                or not encoded_descriptor
                or len(encoded_descriptor) > MAX_WINDOWS_SECURITY_DESCRIPTOR_TEXT
                or "\x00" in encoded_descriptor
            ):
                raise ValueError(
                    "approved restore point lacks a complete Windows security descriptor"
                )
        mode = int(metadata.get("mode", 0o600)) & 0o7777
        self._atomic_write(
            path,
            data,
            mode or 0o600,
            metadata,
            expected_current=expected_current,
        )

    def _restore_before(
        self,
        path: Path,
        existed: bool,
        data: bytes,
        metadata: dict[str, Any],
        *,
        expected_current: tuple[bytes, dict[str, Any]] | None | object = (
            _WINDOWS_EXPECTED_UNSPECIFIED
        ),
    ) -> None:
        if existed:
            self._replace_target(
                path,
                data,
                metadata,
                **(
                    {"expected_current": expected_current}
                    if os.name == "nt"
                    else {}
                ),
            )
        else:
            if os.name == "nt" and expected_current is None:
                raise ValueError(
                    "restoration rollback target is unexpectedly absent"
                )
            self._unlink_target(
                path,
                **(
                    {"expected_current": expected_current}
                    if os.name == "nt"
                    else {}
                ),
            )

    def _restore_before_verified(
        self,
        path: Path,
        existed: bool,
        data: bytes,
        metadata: dict[str, Any],
        *,
        expected_current: tuple[bytes, dict[str, Any]] | None | object = (
            _WINDOWS_EXPECTED_UNSPECIFIED
        ),
    ) -> None:
        self._restore_before(
            path,
            existed,
            data,
            metadata,
            expected_current=expected_current,
        )
        if existed:
            restored, restored_metadata = self._read_target(path)
            if _digest(restored) != _digest(data) or not self._metadata_matches(
                metadata, restored_metadata
            ):
                raise OSError("rollback did not restore the preserved bytes and metadata")
        elif self._read_target_if_present(path) is not None:
            raise OSError("rollback did not remove the newly restored target")
