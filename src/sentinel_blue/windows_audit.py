"""Native, locale-independent Windows logon audit policy checks.

Collection is read-only. The explicit setter is used by approved native setup
and disposable rehearsals; calling it requires Windows security privilege.
"""
from __future__ import annotations

import ctypes
import os
import uuid
from contextlib import contextmanager

LOGON_SUBCATEGORY = '0cce9215-69ae-11d9-bed3-505054503030'


class _Guid(ctypes.Structure):
    _fields_ = [('a',ctypes.c_uint32),('b',ctypes.c_uint16),('c',ctypes.c_uint16),('d',ctypes.c_ubyte*8)]


class _Policy(ctypes.Structure):
    _fields_ = [('subcategory',_Guid),('flags',ctypes.c_uint32),('category',_Guid)]


def _api():
    if os.name != 'nt':
        raise OSError('Windows audit policy requires Windows')
    api = ctypes.WinDLL('advapi32',use_last_error=True)
    api.AuditQuerySystemPolicy.argtypes = [ctypes.POINTER(_Guid),ctypes.c_uint32,ctypes.POINTER(ctypes.POINTER(_Policy))]
    api.AuditQuerySystemPolicy.restype = ctypes.c_ubyte
    api.AuditSetSystemPolicy.argtypes = [ctypes.POINTER(_Policy),ctypes.c_uint32]
    api.AuditSetSystemPolicy.restype = ctypes.c_ubyte
    api.AuditFree.argtypes = [ctypes.c_void_p]
    api.AuditFree.restype = None
    return api


def logon_audit_policy():
    from .restoration import _windows_privileges
    api = _api()
    guid = _Guid.from_buffer_copy(uuid.UUID(LOGON_SUBCATEGORY).bytes_le)
    output = ctypes.POINTER(_Policy)()
    with _windows_privileges('SeSecurityPrivilege'):
        if not api.AuditQuerySystemPolicy(ctypes.byref(guid),1,ctypes.byref(output)):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if bytes(output.contents.subcategory) != bytes(guid):
                raise OSError('Windows returned a different audit subcategory')
            flags = int(output.contents.flags) & 3
            return {'flags':flags,'success':bool(flags & 1),'failure':bool(flags & 2)}
        finally:
            api.AuditFree(output)


def set_logon_audit_policy(flags):
    if type(flags) is not int or flags not in (0,1,2,3):
        raise ValueError('logon audit flags must select success/failure auditing')
    from .restoration import _windows_privileges
    api = _api()
    row = _Policy()
    row.subcategory = _Guid.from_buffer_copy(uuid.UUID(LOGON_SUBCATEGORY).bytes_le)
    # Zero means UNCHANGED to the setter; NONE (4) restores disabled auditing.
    row.flags = flags or 4
    with _windows_privileges('SeSecurityPrivilege'):
        if not api.AuditSetSystemPolicy(ctypes.byref(row),1):
            raise ctypes.WinError(ctypes.get_last_error())
    if logon_audit_policy()['flags'] != flags:
        raise OSError('Windows logon audit policy verification failed')


@contextmanager
def temporary_logon_auditing():
    """Owned rehearsal only: enable logging, then restore its observed policy."""
    before = logon_audit_policy()
    result = {'initial':before,'restored':False}
    try:
        set_logon_audit_policy(3)
        yield result
    finally:
        if logon_audit_policy()['flags'] != 3:
            raise RuntimeError('logon audit policy changed independently; restoration held')
        set_logon_audit_policy(before['flags'])
        result['restored'] = True
