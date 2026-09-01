"""Native, fail-closed protection for Sentinel Blue's Windows state tree.

The guard deliberately has no shell dependency.  It verifies a local-drive path
through no-reparse Win32 handles, pins the complete ancestor chain for its
lifetime, and enforces a narrow security descriptor on the state root.  A
bounded walk rejects unsafe descendants before optionally normalizing children
whose effective ACL is already limited to LocalSystem and Administrators.

The native backend is kept behind a small injectable surface so the policy and
lifecycle can be exercised on non-Windows build hosts.  Absolute child opens
remain Win32 path opens; the retained, non-delete-sharing ancestor handles and
the protected root DACL are the security boundary.  Native acceptance must
therefore exercise the sharing behavior on every supported Windows image.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import re
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SYSTEM_SID = "S-1-5-18"
ADMINISTRATORS_SID = "S-1-5-32-544"
FILE_ALL_ACCESS = 0x001F01FF
ACCESS_ALLOWED_ACE_TYPE = 0
OBJECT_INHERIT_ACE = 0x01
CONTAINER_INHERIT_ACE = 0x02
NO_PROPAGATE_INHERIT_ACE = 0x04
INHERIT_ONLY_ACE = 0x08
INHERITED_ACE = 0x10
SE_DACL_PROTECTED = 0x1000

WINDOWS_FILE_ATTRIBUTE_DIRECTORY = 0x00000010
WINDOWS_FILE_ATTRIBUTE_DEVICE = 0x00000040
WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
WINDOWS_FILE_READ_ATTRIBUTES = 0x00000080
WINDOWS_FILE_LIST_DIRECTORY = 0x00000001
WINDOWS_READ_CONTROL = 0x00020000
WINDOWS_WRITE_DAC = 0x00040000
WINDOWS_WRITE_OWNER = 0x00080000
WINDOWS_SYNCHRONIZE = 0x00100000
WINDOWS_FILE_SHARE_READ = 0x00000001
WINDOWS_FILE_SHARE_WRITE = 0x00000002
WINDOWS_OPEN_EXISTING = 3
WINDOWS_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
WINDOWS_VOLUME_NAME_GUID = 0x00000001
WINDOWS_ERROR_FILE_NOT_FOUND = 2
WINDOWS_ERROR_PATH_NOT_FOUND = 3
WINDOWS_ERROR_ALREADY_EXISTS = 183

OWNER_SECURITY_INFORMATION = 0x00000001
DACL_SECURITY_INFORMATION = 0x00000004
PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
SE_FILE_OBJECT = 1
ACL_REVISION = 2
ACL_SIZE_INFORMATION_CLASS = 2
SECURITY_DESCRIPTOR_REVISION = 1
WIN_LOCAL_SYSTEM_SID = 22
WIN_BUILTIN_ADMINISTRATORS_SID = 26
SECURITY_MAX_SID_SIZE = 68

DEFAULT_MAXIMUM_ENTRIES = 4096
DEFAULT_MAXIMUM_DEPTH = 8

_VOLUME_GUID_PATH = re.compile(r"^\\\\\?\\Volume\{[0-9A-Fa-f-]+\}\\")
_RESERVED_COMPONENT = re.compile(
    r"^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9]|CONIN\$|CONOUT\$)(?:\..*)?$",
    re.I,
)


class WindowsStateSecurityError(ValueError):
    """The Windows state tree cannot be trusted for privileged operation."""


@dataclass(frozen=True, slots=True)
class WindowsAccessAce:
    """The security fields relevant to the private-state policy."""

    sid: str
    mask: int
    flags: int
    ace_type: int = ACCESS_ALLOWED_ACE_TYPE


@dataclass(frozen=True, slots=True)
class WindowsSecurityState:
    """A semantic view of a native owner and DACL."""

    owner_sid: str
    dacl_present: bool
    dacl_protected: bool
    aces: tuple[WindowsAccessAce, ...]


@dataclass(frozen=True, slots=True)
class WindowsStateTreeReport:
    """Bounded evidence returned by a successful state-tree audit."""

    entries: int
    hardened: int
    maximum_entries: int
    maximum_depth: int

    def as_dict(self) -> dict[str, int | bool]:
        return {
            "healthy": True,
            "entries": self.entries,
            "hardened": self.hardened,
            "maximum_entries": self.maximum_entries,
            "maximum_depth": self.maximum_depth,
        }


def _validate_component(component: str) -> None:
    forbidden = set('<>:"|?*')
    if (
        not component
        or component in {".", ".."}
        or component[-1] in {" ", "."}
        or any(ord(character) < 32 or character in forbidden for character in component)
        or _RESERVED_COMPONENT.fullmatch(component)
    ):
        raise WindowsStateSecurityError(
            "Windows state path contains an unsafe component"
        )


def _windows_directory_prefixes(path: str | Path) -> tuple[str, tuple[str, ...]]:
    """Return a canonical local-drive path and every directory prefix."""
    raw = str(path)
    if (
        not raw
        or "\x00" in raw
        or len(raw) > 1024
        or raw.startswith(("\\\\", "//"))
    ):
        raise WindowsStateSecurityError(
            "Windows state must use a bounded local-drive path"
        )
    drive, tail = ntpath.splitdrive(raw)
    if not re.fullmatch(r"[A-Za-z]:", drive) or not tail.startswith(("\\", "/")):
        raise WindowsStateSecurityError(
            "Windows state path must be an absolute local-drive directory"
        )
    if ":" in tail:
        raise WindowsStateSecurityError(
            "Windows state path must not use a namespace alias or alternate stream"
        )
    tail = tail.replace("/", "\\")
    while len(tail) > 1 and tail.endswith("\\"):
        tail = tail[:-1]
    components = tail[1:].split("\\") if len(tail) > 1 else []
    if not components:
        raise WindowsStateSecurityError("a volume root cannot be used as agent state")
    for component in components:
        _validate_component(component)
    root = f"{drive.upper()}\\"
    prefixes = [root]
    candidate = root
    for component in components:
        candidate = ntpath.join(candidate, component)
        prefixes.append(candidate)
    return prefixes[-1], tuple(prefixes)


def _expected_aces(directory: bool, *, inherited: bool = False) -> tuple[WindowsAccessAce, ...]:
    flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE if directory else 0
    if inherited:
        flags |= INHERITED_ACE
    return (
        WindowsAccessAce(SYSTEM_SID, FILE_ALL_ACCESS, flags),
        WindowsAccessAce(ADMINISTRATORS_SID, FILE_ALL_ACCESS, flags),
    )


def _classify_security(
    state: WindowsSecurityState,
    *,
    directory: bool,
    root: bool,
) -> str:
    """Return ``exact`` or ``safe``; raise for any broadened descriptor."""
    if not isinstance(state, WindowsSecurityState):
        raise WindowsStateSecurityError("Windows state security metadata is invalid")
    if state.owner_sid not in {SYSTEM_SID, ADMINISTRATORS_SID}:
        raise WindowsStateSecurityError(
            "Windows state owner is not LocalSystem or Administrators"
        )
    if not state.dacl_present:
        raise WindowsStateSecurityError(
            "Windows state has an absent or NULL DACL"
        )
    if len(state.aces) != 2:
        raise WindowsStateSecurityError(
            "Windows state DACL must contain exactly two access rules"
        )
    observed: dict[str, WindowsAccessAce] = {}
    for ace in state.aces:
        if ace.ace_type != ACCESS_ALLOWED_ACE_TYPE:
            raise WindowsStateSecurityError(
                "Windows state DACL contains a non-allow access rule"
            )
        if ace.sid not in {SYSTEM_SID, ADMINISTRATORS_SID} or ace.sid in observed:
            raise WindowsStateSecurityError(
                "Windows state DACL contains an unexpected or duplicate identity"
            )
        if ace.mask != FILE_ALL_ACCESS:
            raise WindowsStateSecurityError(
                "Windows state DACL does not grant the exact private-state rights"
            )
        if ace.flags & (NO_PROPAGATE_INHERIT_ACE | INHERIT_ONLY_ACE):
            raise WindowsStateSecurityError(
                "Windows state DACL contains an unsafe inheritance rule"
            )
        # Some Windows inheritance paths retain OI/CI on a file ACE even though
        # those flags have no child-propagation effect on a non-container.  They
        # do not broaden the principals or mask and are normalized below.
        allowed_flags = INHERITED_ACE | OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        required_flags = 0
        if directory:
            required_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
        if ace.flags & ~allowed_flags or ace.flags & required_flags != required_flags:
            raise WindowsStateSecurityError(
                "Windows state DACL contains unexpected inheritance flags"
            )
        observed[ace.sid] = ace

    exact_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE if directory else 0
    exact = (
        state.owner_sid == SYSTEM_SID
        and state.dacl_protected
        and all(ace.flags == exact_flags for ace in state.aces)
    )
    if root and not exact:
        raise WindowsStateSecurityError(
            "Windows state root does not have the exact protected private DACL and owner"
        )
    return "exact" if exact else "safe"


class _Acl(ctypes.Structure):
    _fields_ = [
        ("AclRevision", ctypes.c_ubyte),
        ("Sbz1", ctypes.c_ubyte),
        ("AclSize", ctypes.c_uint16),
        ("AceCount", ctypes.c_uint16),
        ("Sbz2", ctypes.c_uint16),
    ]


class _AceHeader(ctypes.Structure):
    _fields_ = [
        ("AceType", ctypes.c_ubyte),
        ("AceFlags", ctypes.c_ubyte),
        ("AceSize", ctypes.c_uint16),
    ]


class _AclSizeInformation(ctypes.Structure):
    _fields_ = [
        ("AceCount", ctypes.c_uint32),
        ("AclBytesInUse", ctypes.c_uint32),
        ("AclBytesFree", ctypes.c_uint32),
    ]


class _SecurityDescriptor(ctypes.Structure):
    _fields_ = [
        ("Revision", ctypes.c_ubyte),
        ("Sbz1", ctypes.c_ubyte),
        ("Control", ctypes.c_uint16),
        ("Owner", ctypes.c_void_p),
        ("Group", ctypes.c_void_p),
        ("Sacl", ctypes.c_void_p),
        ("Dacl", ctypes.c_void_p),
    ]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", ctypes.c_uint32),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", ctypes.c_int32),
    ]


class _ByHandleFileInformation(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes", ctypes.c_uint32),
        ("ftCreationTimeLow", ctypes.c_uint32),
        ("ftCreationTimeHigh", ctypes.c_uint32),
        ("ftLastAccessTimeLow", ctypes.c_uint32),
        ("ftLastAccessTimeHigh", ctypes.c_uint32),
        ("ftLastWriteTimeLow", ctypes.c_uint32),
        ("ftLastWriteTimeHigh", ctypes.c_uint32),
        ("dwVolumeSerialNumber", ctypes.c_uint32),
        ("nFileSizeHigh", ctypes.c_uint32),
        ("nFileSizeLow", ctypes.c_uint32),
        ("nNumberOfLinks", ctypes.c_uint32),
        ("nFileIndexHigh", ctypes.c_uint32),
        ("nFileIndexLow", ctypes.c_uint32),
    ]


@contextmanager
def _restore_privilege():
    """Reuse the agent's disposable thread-token privilege implementation."""
    if os.name != "nt":
        with nullcontext():
            yield
        return
    from .restoration import _windows_privileges

    with _windows_privileges("SeRestorePrivilege"):
        yield


class _NativeWindowsStateBackend:
    """Narrow ctypes backend; all policy remains in WindowsStateTreeGuard."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise RuntimeError("native Windows state protection requires Windows")
        from ctypes import wintypes

        self._wintypes = wintypes
        self._kernel32 = ctypes.WinDLL("Kernel32.dll", use_last_error=True)
        self._advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)

        self._create_file = self._kernel32.CreateFileW
        self._create_file.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.HANDLE,
        ]
        self._create_file.restype = wintypes.HANDLE
        self._create_directory = self._kernel32.CreateDirectoryW
        self._create_directory.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p]
        self._create_directory.restype = wintypes.BOOL
        self._close_handle = self._kernel32.CloseHandle
        self._close_handle.argtypes = [wintypes.HANDLE]
        self._close_handle.restype = wintypes.BOOL
        self._get_information = self._kernel32.GetFileInformationByHandle
        self._get_information.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(_ByHandleFileInformation),
        ]
        self._get_information.restype = wintypes.BOOL
        self._get_final_path = self._kernel32.GetFinalPathNameByHandleW
        self._get_final_path.argtypes = [
            wintypes.HANDLE,
            wintypes.LPWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
        ]
        self._get_final_path.restype = wintypes.DWORD

        self._get_security = self._advapi32.GetSecurityInfo
        self._get_security.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._get_security.restype = wintypes.DWORD
        self._set_security = self._advapi32.SetSecurityInfo
        self._set_security.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        self._set_security.restype = wintypes.DWORD
        self._local_free = self._kernel32.LocalFree
        self._local_free.argtypes = [ctypes.c_void_p]
        self._local_free.restype = ctypes.c_void_p

        self._get_sd_control = self._advapi32.GetSecurityDescriptorControl
        self._get_sd_control.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint16),
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._get_sd_control.restype = wintypes.BOOL
        self._get_sd_owner = self._advapi32.GetSecurityDescriptorOwner
        self._get_sd_owner.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        self._get_sd_owner.restype = wintypes.BOOL
        self._get_sd_dacl = self._advapi32.GetSecurityDescriptorDacl
        self._get_sd_dacl.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.BOOL),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.BOOL),
        ]
        self._get_sd_dacl.restype = wintypes.BOOL
        self._is_valid_acl = self._advapi32.IsValidAcl
        self._is_valid_acl.argtypes = [ctypes.c_void_p]
        self._is_valid_acl.restype = wintypes.BOOL
        self._get_acl_information = self._advapi32.GetAclInformation
        self._get_acl_information.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_int,
        ]
        self._get_acl_information.restype = wintypes.BOOL
        self._get_ace = self._advapi32.GetAce
        self._get_ace.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._get_ace.restype = wintypes.BOOL
        self._is_valid_sid = self._advapi32.IsValidSid
        self._is_valid_sid.argtypes = [ctypes.c_void_p]
        self._is_valid_sid.restype = wintypes.BOOL
        self._get_length_sid = self._advapi32.GetLengthSid
        self._get_length_sid.argtypes = [ctypes.c_void_p]
        self._get_length_sid.restype = wintypes.DWORD
        self._convert_sid = self._advapi32.ConvertSidToStringSidW
        self._convert_sid.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.LPWSTR),
        ]
        self._convert_sid.restype = wintypes.BOOL

        self._create_well_known_sid = self._advapi32.CreateWellKnownSid
        self._create_well_known_sid.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._create_well_known_sid.restype = wintypes.BOOL
        self._initialize_acl = self._advapi32.InitializeAcl
        self._initialize_acl.argtypes = [ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD]
        self._initialize_acl.restype = wintypes.BOOL
        self._add_access_allowed_ace = self._advapi32.AddAccessAllowedAceEx
        self._add_access_allowed_ace.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        self._add_access_allowed_ace.restype = wintypes.BOOL
        self._initialize_sd = self._advapi32.InitializeSecurityDescriptor
        self._initialize_sd.argtypes = [ctypes.c_void_p, wintypes.DWORD]
        self._initialize_sd.restype = wintypes.BOOL
        self._set_sd_owner = self._advapi32.SetSecurityDescriptorOwner
        self._set_sd_owner.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.BOOL,
        ]
        self._set_sd_owner.restype = wintypes.BOOL
        self._set_sd_dacl = self._advapi32.SetSecurityDescriptorDacl
        self._set_sd_dacl.argtypes = [
            ctypes.c_void_p,
            wintypes.BOOL,
            ctypes.c_void_p,
            wintypes.BOOL,
        ]
        self._set_sd_dacl.restype = wintypes.BOOL
        self._set_sd_control = self._advapi32.SetSecurityDescriptorControl
        self._set_sd_control.argtypes = [ctypes.c_void_p, ctypes.c_uint16, ctypes.c_uint16]
        self._set_sd_control.restype = wintypes.BOOL

    @staticmethod
    def _raise(message: str) -> None:
        _NativeWindowsStateBackend._raise_code(ctypes.get_last_error(), message)

    @staticmethod
    def _raise_code(code: int, message: str) -> None:
        if code in {WINDOWS_ERROR_FILE_NOT_FOUND, WINDOWS_ERROR_PATH_NOT_FOUND}:
            raise FileNotFoundError(code, message)
        raise OSError(code, message)

    @staticmethod
    def is_missing(exc: OSError) -> bool:
        code = getattr(exc, "winerror", None)
        if code is None:
            code = exc.errno
        return code in {WINDOWS_ERROR_FILE_NOT_FOUND, WINDOWS_ERROR_PATH_NOT_FOUND}

    def open_node(
        self,
        path: str,
        *,
        write_security: bool = False,
        allow_data_writers: bool = False,
    ):
        desired_access = (
            WINDOWS_FILE_READ_ATTRIBUTES | WINDOWS_READ_CONTROL | WINDOWS_SYNCHRONIZE
        )
        if write_security:
            desired_access |= WINDOWS_WRITE_DAC | WINDOWS_WRITE_OWNER
        scope = _restore_privilege() if write_security else nullcontext()
        with scope:
            handle = self._create_file(
                path,
                desired_access,
                # Refusing write/delete sharing pins each directory name while the
                # guard is retained. Native acceptance verifies service compatibility.
                WINDOWS_FILE_SHARE_READ
                | (WINDOWS_FILE_SHARE_WRITE if allow_data_writers else 0),
                None,
                WINDOWS_OPEN_EXISTING,
                WINDOWS_FILE_FLAG_BACKUP_SEMANTICS
                | WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
            error = ctypes.get_last_error()
        if handle in (None, ctypes.c_void_p(-1).value):
            self._raise_code(error, "Windows state object could not be opened")
        return handle

    def close(self, handle) -> None:
        if not self._close_handle(handle):
            self._raise("Windows state handle could not be closed")

    def attributes(self, handle) -> int:
        information = _ByHandleFileInformation()
        if not self._get_information(handle, ctypes.byref(information)):
            self._raise("Windows state object attributes could not be read")
        return int(information.dwFileAttributes)

    def link_count(self, handle) -> int:
        information = _ByHandleFileInformation()
        if not self._get_information(handle, ctypes.byref(information)):
            self._raise("Windows state object link count could not be read")
        return int(information.nNumberOfLinks)

    def identity(self, handle) -> tuple[int, int, int]:
        """Return the stable volume/file identity for an open object handle."""
        information = _ByHandleFileInformation()
        if not self._get_information(handle, ctypes.byref(information)):
            self._raise("Windows state object identity could not be read")
        return (
            int(information.dwVolumeSerialNumber),
            int(information.nFileIndexHigh),
            int(information.nFileIndexLow),
        )

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
                self._raise("Windows state object identity could not be resolved")
            if length < size:
                return buffer.value
            size = length + 1
        raise WindowsStateSecurityError("Windows state final path exceeds its limit")

    def _well_known_sid(self, kind: int):
        size = self._wintypes.DWORD(SECURITY_MAX_SID_SIZE)
        buffer = ctypes.create_string_buffer(size.value)
        if not self._create_well_known_sid(
            kind, None, buffer, ctypes.byref(size)
        ):
            self._raise("Windows private-state SID could not be created")
        return buffer

    def _private_acl(self, directory: bool):
        system_sid = self._well_known_sid(WIN_LOCAL_SYSTEM_SID)
        administrators_sid = self._well_known_sid(
            WIN_BUILTIN_ADMINISTRATORS_SID
        )
        sid_lengths = [
            int(self._get_length_sid(system_sid)),
            int(self._get_length_sid(administrators_sid)),
        ]
        # ACCESS_ALLOWED_ACE contains the first DWORD of the SID inline.
        acl_size = ctypes.sizeof(_Acl) + sum(8 + length for length in sid_lengths)
        acl = ctypes.create_string_buffer(acl_size)
        if not self._initialize_acl(acl, acl_size, ACL_REVISION):
            self._raise("Windows private-state ACL could not be initialized")
        flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE if directory else 0
        for sid in (system_sid, administrators_sid):
            if not self._add_access_allowed_ace(
                acl,
                ACL_REVISION,
                flags,
                FILE_ALL_ACCESS,
                sid,
            ):
                self._raise("Windows private-state ACL entry could not be added")
        return system_sid, administrators_sid, acl

    def create_directory(self, path: str) -> None:
        system_sid, _administrators_sid, acl = self._private_acl(True)
        descriptor = _SecurityDescriptor()
        if not self._initialize_sd(
            ctypes.byref(descriptor), SECURITY_DESCRIPTOR_REVISION
        ):
            self._raise("Windows private-state descriptor could not be initialized")
        if not self._set_sd_owner(
            ctypes.byref(descriptor), system_sid, False
        ) or not self._set_sd_dacl(ctypes.byref(descriptor), True, acl, False):
            self._raise("Windows private-state descriptor components could not be set")
        if not self._set_sd_control(
            ctypes.byref(descriptor), SE_DACL_PROTECTED, SE_DACL_PROTECTED
        ):
            self._raise("Windows private-state descriptor could not be protected")
        attributes = _SecurityAttributes(
            ctypes.sizeof(_SecurityAttributes),
            ctypes.cast(ctypes.byref(descriptor), ctypes.c_void_p),
            False,
        )
        with _restore_privilege():
            if not self._create_directory(path, ctypes.byref(attributes)):
                self._raise("Windows private-state directory could not be created")

    def list_children(self, path: str, limit: int) -> list[str]:
        result: list[str] = []
        try:
            with os.scandir(path) as entries:
                for entry in entries:
                    _validate_component(entry.name)
                    result.append(entry.name)
                    if len(result) > limit:
                        raise WindowsStateSecurityError(
                            "Windows state tree exceeds its entry budget"
                        )
        except WindowsStateSecurityError:
            raise
        except OSError as exc:
            raise OSError(exc.errno, "Windows state directory could not be enumerated") from exc
        return sorted(result, key=lambda value: (value.casefold(), value))

    def _sid_string(self, sid) -> str:
        if not sid or not self._is_valid_sid(sid):
            raise WindowsStateSecurityError("Windows state contains an invalid SID")
        value = self._wintypes.LPWSTR()
        if not self._convert_sid(sid, ctypes.byref(value)):
            self._raise("Windows state SID could not be rendered")
        try:
            return str(value.value)
        finally:
            if value:
                self._local_free(ctypes.cast(value, ctypes.c_void_p))

    def security_state(self, handle) -> WindowsSecurityState:
        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        descriptor = ctypes.c_void_p()
        code = int(
            self._get_security(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                ctypes.byref(owner),
                None,
                ctypes.byref(dacl),
                None,
                ctypes.byref(descriptor),
            )
        )
        if code != 0 or not descriptor.value:
            raise OSError(code, "Windows state security descriptor could not be read")
        try:
            owner_pointer = ctypes.c_void_p()
            owner_defaulted = self._wintypes.BOOL()
            if not self._get_sd_owner(
                descriptor,
                ctypes.byref(owner_pointer),
                ctypes.byref(owner_defaulted),
            ):
                self._raise("Windows state owner could not be read")
            dacl_present = self._wintypes.BOOL()
            dacl_pointer = ctypes.c_void_p()
            dacl_defaulted = self._wintypes.BOOL()
            if not self._get_sd_dacl(
                descriptor,
                ctypes.byref(dacl_present),
                ctypes.byref(dacl_pointer),
                ctypes.byref(dacl_defaulted),
            ):
                self._raise("Windows state DACL could not be read")
            control = ctypes.c_uint16()
            revision = self._wintypes.DWORD()
            if not self._get_sd_control(
                descriptor, ctypes.byref(control), ctypes.byref(revision)
            ):
                self._raise("Windows state DACL control could not be read")
            if not dacl_present.value or not dacl_pointer.value:
                return WindowsSecurityState(
                    self._sid_string(owner_pointer),
                    False,
                    bool(control.value & SE_DACL_PROTECTED),
                    (),
                )
            if not self._is_valid_acl(dacl_pointer):
                raise WindowsStateSecurityError("Windows state DACL is malformed")
            acl_information = _AclSizeInformation()
            if not self._get_acl_information(
                dacl_pointer,
                ctypes.byref(acl_information),
                ctypes.sizeof(acl_information),
                ACL_SIZE_INFORMATION_CLASS,
            ):
                self._raise("Windows state DACL size could not be read")
            if int(acl_information.AceCount) > 64:
                raise WindowsStateSecurityError("Windows state DACL has too many entries")
            aces: list[WindowsAccessAce] = []
            for index in range(int(acl_information.AceCount)):
                ace_pointer = ctypes.c_void_p()
                if not self._get_ace(dacl_pointer, index, ctypes.byref(ace_pointer)):
                    self._raise("Windows state DACL entry could not be read")
                if not ace_pointer.value:
                    raise WindowsStateSecurityError("Windows state DACL entry is NULL")
                header = _AceHeader.from_address(ace_pointer.value)
                if int(header.AceSize) < 8:
                    raise WindowsStateSecurityError("Windows state DACL entry is malformed")
                mask = int(ctypes.c_uint32.from_address(ace_pointer.value + 4).value)
                if int(header.AceType) != ACCESS_ALLOWED_ACE_TYPE:
                    # Object/callback ACE layouts place the SID at other offsets.
                    # The policy rejects the type, so do not dereference it here.
                    aces.append(
                        WindowsAccessAce(
                            "",
                            mask,
                            int(header.AceFlags),
                            int(header.AceType),
                        )
                    )
                    continue
                if int(header.AceSize) < 16:
                    raise WindowsStateSecurityError("Windows state DACL SID is truncated")
                sid_pointer = ctypes.c_void_p(ace_pointer.value + 8)
                subauthority_count = int(
                    ctypes.c_ubyte.from_address(ace_pointer.value + 9).value
                )
                bounded_sid_length = 8 + 4 * subauthority_count
                if 8 + bounded_sid_length > int(header.AceSize):
                    raise WindowsStateSecurityError("Windows state DACL SID is out of bounds")
                if not self._is_valid_sid(sid_pointer):
                    raise WindowsStateSecurityError("Windows state DACL SID is malformed")
                sid_length = int(self._get_length_sid(sid_pointer))
                if (
                    sid_length != bounded_sid_length
                    or 8 + sid_length > int(header.AceSize)
                ):
                    raise WindowsStateSecurityError("Windows state DACL SID is out of bounds")
                aces.append(
                    WindowsAccessAce(
                        self._sid_string(sid_pointer),
                        mask,
                        int(header.AceFlags),
                        int(header.AceType),
                    )
                )
            return WindowsSecurityState(
                self._sid_string(owner_pointer),
                True,
                bool(control.value & SE_DACL_PROTECTED),
                tuple(aces),
            )
        finally:
            self._local_free(descriptor)

    def apply_private_security(self, handle, directory: bool) -> None:
        system_sid, _administrators_sid, acl = self._private_acl(directory)
        with _restore_privilege():
            code = int(
                self._set_security(
                    handle,
                    SE_FILE_OBJECT,
                    OWNER_SECURITY_INFORMATION
                    | DACL_SECURITY_INFORMATION
                    | PROTECTED_DACL_SECURITY_INFORMATION,
                    system_sid,
                    None,
                    acl,
                    None,
                )
            )
        if code != 0:
            # SetSecurityInfo returns the error directly; GetLastError is irrelevant.
            raise OSError(code, "Windows private-state security could not be applied")


class WindowsStateTreeGuard:
    """Retain the trusted Windows path handles and audit its bounded contents."""

    def __init__(
        self,
        path: str,
        prefixes: tuple[str, ...],
        handles: list[Any],
        backend: Any,
        *,
        maximum_entries: int,
        maximum_depth: int,
    ) -> None:
        self.path = Path(path)
        self._native_path = path
        self._prefixes = prefixes
        self._handles = handles
        self._backend = backend
        self.maximum_entries = maximum_entries
        self.maximum_depth = maximum_depth
        self.closed = False

    @classmethod
    def acquire(
        cls,
        path: str | Path,
        *,
        initialize: bool = False,
        harden_safe_descendants: bool = True,
        maximum_entries: int = DEFAULT_MAXIMUM_ENTRIES,
        maximum_depth: int = DEFAULT_MAXIMUM_DEPTH,
        backend: Any | None = None,
    ) -> "WindowsStateTreeGuard | None":
        """Open and pin a private tree, optionally creating an empty safe root.

        On non-Windows systems the default backend is a no-op so callers can keep
        one integration path.  Passing an injected backend always exercises the
        Windows policy, which is how the contract tests run on Linux.
        """
        if backend is None and os.name != "nt":
            return None
        if (
            type(maximum_entries) is not int
            or not 1 <= maximum_entries <= 65536
            or type(maximum_depth) is not int
            or not 1 <= maximum_depth <= 64
        ):
            raise ValueError("Windows state traversal bounds are invalid")
        native_path, prefixes = _windows_directory_prefixes(path)
        backend = backend or _NativeWindowsStateBackend()
        handles: list[Any] = []
        created = False
        try:
            volume_root: str | None = None
            for index, prefix in enumerate(prefixes):
                final = index + 1 == len(prefixes)
                try:
                    handle = backend.open_node(
                        prefix,
                        # Lifetime pins deliberately retain no mutation rights.
                        write_security=False,
                    )
                except OSError as exc:
                    if not backend.is_missing(exc):
                        raise
                    if not final or not initialize:
                        raise WindowsStateSecurityError(
                            "Windows state parent path is unavailable"
                        ) from exc
                    backend.create_directory(prefix)
                    created = True
                    # The descriptor is supplied atomically by CreateDirectoryW;
                    # the retained name pin therefore needs observation rights
                    # only.  Never keep WRITE_DAC/WRITE_OWNER for guard lifetime.
                    handle = backend.open_node(prefix, write_security=False)
                handles.append(handle)
                attributes = int(backend.attributes(handle))
                if attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
                    raise WindowsStateSecurityError(
                        "Windows state path must not traverse a reparse point"
                    )
                if attributes & WINDOWS_FILE_ATTRIBUTE_DEVICE:
                    raise WindowsStateSecurityError(
                        "Windows state path must not traverse a device object"
                    )
                if not attributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY:
                    raise WindowsStateSecurityError(
                        "Windows state path component is not a directory"
                    )
                final_path = str(backend.final_path(handle))
                volume_match = _VOLUME_GUID_PATH.match(final_path)
                if not volume_match:
                    raise WindowsStateSecurityError(
                        "Windows state path did not resolve to a local volume"
                    )
                observed_volume = volume_match.group(0).casefold()
                if volume_root is None:
                    volume_root = observed_volume
                elif volume_root != observed_volume:
                    raise WindowsStateSecurityError(
                        "Windows state path crossed a volume boundary"
                    )
                expected_tail = prefix[3:].rstrip("\\").casefold()
                observed_tail = final_path[volume_match.end() :].rstrip("\\").casefold()
                if observed_tail != expected_tail:
                    raise WindowsStateSecurityError(
                        "Windows state path resolved through a filesystem alias"
                    )

            guard = cls(
                native_path,
                prefixes,
                handles,
                backend,
                maximum_entries=maximum_entries,
                maximum_depth=maximum_depth,
            )
            # Ownership of every pin has moved to the guard.  Clearing the local
            # list prevents the outer failure path from closing them a second time.
            handles = []
            try:
                root_handle = guard._handles[-1]
                try:
                    root_classification = _classify_security(
                        backend.security_state(root_handle),
                        directory=True,
                        root=False,
                    )
                except WindowsStateSecurityError:
                    # A broadened, malformed, or unowned legacy root is never
                    # normalized around existing content.  Only an observed-empty
                    # pre-existing root is eligible for this recovery path.
                    if not initialize or created:
                        raise
                    if backend.list_children(native_path, 1):
                        raise WindowsStateSecurityError(
                            "refusing to repair a nonempty insecure legacy Windows state tree"
                        )
                    guard._apply_private_to_pin(
                        native_path,
                        root_handle,
                        directory=True,
                        require_safe=False,
                    )
                    guard.refresh(
                        harden_safe_descendants=harden_safe_descendants
                    )
                else:
                    if root_classification == "exact":
                        guard.refresh(
                            harden_safe_descendants=harden_safe_descendants
                        )
                    elif not initialize:
                        raise WindowsStateSecurityError(
                            "Windows state root is private but is not normalized"
                        )
                    else:
                        # This supports an autonomous upgrade from the legacy
                        # Admin/System-only inherited descriptor.  No object is
                        # changed until the complete bounded tree has proven safe.
                        guard._normalize_safe_legacy_root(
                            harden_safe_descendants=harden_safe_descendants
                        )
            except Exception as original:
                try:
                    guard.close()
                except OSError as cleanup_error:
                    original.add_note(
                        f"Windows state pin cleanup also failed: {cleanup_error}"
                    )
                raise
            return guard
        except Exception as original:
            cleanup_error: OSError | None = None
            for handle in reversed(handles):
                try:
                    backend.close(handle)
                except OSError as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
            if cleanup_error is not None:
                original.add_note(
                    f"Windows state prefix cleanup also failed: {cleanup_error}"
                )
            raise

    def _require_open(self) -> None:
        if self.closed or not self._handles:
            raise WindowsStateSecurityError("Windows state guard is closed")

    def _check_open_handle(self, handle) -> bool:
        attributes = int(self._backend.attributes(handle))
        if attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT:
            raise WindowsStateSecurityError(
                "Windows state tree contains a reparse point"
            )
        if attributes & WINDOWS_FILE_ATTRIBUTE_DEVICE:
            raise WindowsStateSecurityError(
                "Windows state tree contains a device object"
            )
        directory = bool(attributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY)
        if not directory and int(self._backend.link_count(handle)) != 1:
            raise WindowsStateSecurityError(
                "Windows state tree contains a hard-linked file"
            )
        return directory

    def _open_checked(self, path: str):
        # Active state files (notably the rotating log) may already have a data
        # writer. Start with write sharing but never delete sharing. Directories
        # are immediately rebound through their pinned path to a restrictive
        # handle before enumeration. ReOpenFile cannot reliably narrow directory
        # share modes on supported Windows builds, so the first handle remains the
        # no-delete name pin until both handles prove the same file identity.
        handle = self._backend.open_node(
            path,
            write_security=False,
            allow_data_writers=True,
        )
        try:
            directory = self._check_open_handle(handle)
        except Exception:
            self._backend.close(handle)
            raise
        if not directory:
            return handle, False
        try:
            restrictive = self._open_pinned_checked(
                path,
                handle,
                directory=True,
                write_security=False,
                allow_data_writers=False,
            )
        except Exception:
            self._backend.close(handle)
            raise
        try:
            self._backend.close(handle)
        except Exception:
            self._backend.close(restrictive)
            raise
        return restrictive, True

    def _open_pinned_checked(
        self,
        path: str,
        pin,
        *,
        directory: bool,
        write_security: bool,
        allow_data_writers: bool,
    ):
        """Open a pinned name and require it to resolve to the audited object."""
        handle = self._backend.open_node(
            path,
            write_security=write_security,
            allow_data_writers=allow_data_writers,
        )
        try:
            if self._check_open_handle(handle) != directory:
                raise WindowsStateSecurityError(
                    "Windows state object type changed during validation"
                )
            if self._backend.identity(handle) != self._backend.identity(pin):
                raise WindowsStateSecurityError(
                    "Windows state object identity changed during validation"
                )
            return handle
        except Exception:
            self._backend.close(handle)
            raise

    def _close_temporary(self, handles: list[Any]) -> None:
        cleanup_error: OSError | None = None
        for handle in reversed(handles):
            try:
                self._backend.close(handle)
            except OSError as exc:
                if cleanup_error is None:
                    cleanup_error = exc
        handles.clear()
        if cleanup_error is not None:
            raise cleanup_error

    def _audit_descendants(
        self,
    ) -> tuple[int, list[tuple[str, Any, bool]], list[Any]]:
        """Audit while retaining every object pin until the caller is done.

        Each recursive directory is enumerated while its own no-delete/no-write
        sharing handle and all of its ancestors remain open.  A checked directory
        therefore cannot be replaced by a junction between validation and descent.
        """
        entries = 0
        harden: list[tuple[str, Any, bool]] = []
        pins: list[Any] = []

        def walk(directory_path: str, depth: int) -> None:
            nonlocal entries
            remaining = self.maximum_entries - entries
            if remaining <= 0:
                if self._backend.list_children(directory_path, 1):
                    raise WindowsStateSecurityError(
                        "Windows state tree exceeds its entry budget"
                    )
                return
            names = self._backend.list_children(directory_path, remaining)
            for name in names:
                entries += 1
                if entries > self.maximum_entries:
                    raise WindowsStateSecurityError(
                        "Windows state tree exceeds its entry budget"
                    )
                child = ntpath.join(directory_path, name)
                handle, directory = self._open_checked(child)
                pins.append(handle)
                classification = _classify_security(
                    self._backend.security_state(handle),
                    directory=directory,
                    root=False,
                )
                if classification != "exact":
                    harden.append((child, handle, directory))
                if directory:
                    if depth + 1 > self.maximum_depth:
                        raise WindowsStateSecurityError(
                            "Windows state tree exceeds its depth budget"
                        )
                    walk(child, depth + 1)

        try:
            walk(self._native_path, 0)
            return entries, harden, pins
        except Exception:
            self._close_temporary(pins)
            raise

    def _apply_private_to_pin(
        self,
        path: str,
        pin,
        *,
        directory: bool,
        require_safe: bool,
    ) -> None:
        handle = self._open_pinned_checked(
            path,
            pin,
            directory=directory,
            write_security=True,
            allow_data_writers=not directory,
        )
        try:
            if require_safe:
                _classify_security(
                    self._backend.security_state(handle),
                    directory=directory,
                    root=False,
                )
            self._backend.apply_private_security(handle, directory)
            _classify_security(
                self._backend.security_state(handle),
                directory=directory,
                root=True,
            )
        finally:
            self._backend.close(handle)

    def _normalize_safe_legacy_root(
        self,
        *,
        harden_safe_descendants: bool,
    ) -> None:
        root_handle = self._handles[-1]
        if (
            _classify_security(
                self._backend.security_state(root_handle),
                directory=True,
                root=False,
            )
            != "safe"
        ):
            raise WindowsStateSecurityError(
                "Windows legacy root is not eligible for normalization"
            )
        entries, candidates, pins = self._audit_descendants()
        final_pins: list[Any] = []
        try:
            # The complete tree is semantically private before the first write.
            # Protecting the root first closes its inheritance boundary; the
            # identity-bound child handles can then be monotonically narrowed.
            self._apply_private_to_pin(
                self._native_path,
                root_handle,
                directory=True,
                require_safe=True,
            )
            if harden_safe_descendants:
                for path, pin, directory in candidates:
                    self._apply_private_to_pin(
                        path,
                        pin,
                        directory=directory,
                        require_safe=True,
                    )
            final_entries, remaining, final_pins = self._audit_descendants()
            if final_entries != entries or (
                harden_safe_descendants and remaining
            ):
                raise WindowsStateSecurityError(
                    "Windows state tree changed during legacy normalization"
                )
        finally:
            try:
                self._close_temporary(final_pins)
            finally:
                self._close_temporary(pins)

    def refresh(
        self, *, harden_safe_descendants: bool = True
    ) -> WindowsStateTreeReport:
        """Revalidate the pinned root and every bounded descendant."""
        self._require_open()
        root_handle = self._handles[-1]
        attributes = int(self._backend.attributes(root_handle))
        if (
            attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT
            or attributes & WINDOWS_FILE_ATTRIBUTE_DEVICE
            or not attributes & WINDOWS_FILE_ATTRIBUTE_DIRECTORY
        ):
            raise WindowsStateSecurityError("Windows state root identity is unsafe")
        _classify_security(
            self._backend.security_state(root_handle), directory=True, root=True
        )
        entries, candidates, pins = self._audit_descendants()
        hardened = 0
        final_pins: list[Any] = []
        try:
            if harden_safe_descendants:
                # The complete walk succeeded before the first mutation. Every
                # path remains protected by its audited no-delete pin, and the
                # write handle must report that pin's volume/file identity.
                for path, pin, directory in candidates:
                    self._apply_private_to_pin(
                        path,
                        pin,
                        directory=directory,
                        require_safe=True,
                    )
                    hardened += 1
                if hardened:
                    final_entries, remaining, final_pins = self._audit_descendants()
                    if final_entries != entries or remaining:
                        raise WindowsStateSecurityError(
                            "Windows state tree changed during descriptor hardening"
                        )
            return WindowsStateTreeReport(
                entries,
                hardened,
                self.maximum_entries,
                self.maximum_depth,
            )
        finally:
            try:
                self._close_temporary(final_pins)
            finally:
                self._close_temporary(pins)

    def close(self) -> None:
        if self.closed and not self._handles:
            return
        # Once close starts the guard is never usable again, even when a native
        # CloseHandle failure leaves a pin to retry on a later close() call.
        self.closed = True
        failed: list[Any] = []
        cleanup_error: OSError | None = None
        for handle in reversed(self._handles):
            try:
                self._backend.close(handle)
            except OSError as exc:
                failed.append(handle)
                if cleanup_error is None:
                    cleanup_error = exc
        self._handles = list(reversed(failed))
        if cleanup_error is not None:
            raise cleanup_error

    def __enter__(self) -> "WindowsStateTreeGuard":
        self._require_open()
        return self

    def __exit__(self, *_args: Any) -> None:
        self.close()


def acquire_windows_state_tree(
    path: str | Path,
    *,
    initialize: bool = False,
    harden_safe_descendants: bool = True,
    maximum_entries: int = DEFAULT_MAXIMUM_ENTRIES,
    maximum_depth: int = DEFAULT_MAXIMUM_DEPTH,
    backend: Any | None = None,
) -> WindowsStateTreeGuard | None:
    """Convenience wrapper used by startup, deployment, and health integration."""
    return WindowsStateTreeGuard.acquire(
        path,
        initialize=initialize,
        harden_safe_descendants=harden_safe_descendants,
        maximum_entries=maximum_entries,
        maximum_depth=maximum_depth,
        backend=backend,
    )
