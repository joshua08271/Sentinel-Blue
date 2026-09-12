"""Native operations for reviewed security changes; no arbitrary commands."""

from __future__ import annotations

import base64
import ctypes
import ctypes.util
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from .credential_vault import validate_password
from .setup_transport import powershell_environment


def native_command(argv, *, incoming=b"", timeout=30):
    result = subprocess.run(argv, input=incoming, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=timeout, check=False)
    if result.returncode != 0 or len(result.stdout) > 4 * 1024 * 1024:
        raise RuntimeError("native security operation failed")
    return result.stdout


def powershell_json(script, payload, *, timeout=45):
    executable = shutil.which("powershell.exe")
    if os.name != "nt" or executable is None:
        raise RuntimeError("this operation requires native Windows PowerShell")
    code = ("$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
            "try { $p=[Console]::In.ReadToEnd() | ConvertFrom-Json; " + script +
            " } catch { exit 41 }")
    encoded = base64.b64encode(code.encode("utf-16-le")).decode()
    result = subprocess.run([executable, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
                            input=json.dumps(payload).encode(), stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                            env=powershell_environment(executable))
    if result.returncode or len(result.stdout) > 4 * 1024 * 1024:
        raise RuntimeError("native Windows security operation failed")
    return json.loads(result.stdout.decode("utf-8-sig"))


def _account_name(name):
    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?", name):
        raise ValueError("only explicit local account names are supported")
    return name


class NativeSecurityBackend:
    def account(self, name):
        name = _account_name(name)
        if os.name == "nt":
            return powershell_json(r"""
$u=Get-LocalUser -Name $p.name
if ($u.PrincipalSource -and [string]$u.PrincipalSource -ne 'Local') { throw 'Nonlocal account' }
$groups=@(Get-LocalGroup | ForEach-Object {
  $g=$_; if (@(Get-LocalGroupMember -Group $g.Name | Where-Object SID -eq $u.SID).Count) { $g.SID.Value }
})
$dependencies=@(Get-CimInstance Win32_Service | Where-Object {
  $_.StartName -ieq ('.\'+$u.Name) -or $_.StartName -ieq ($env:COMPUTERNAME+'\'+$u.Name)
} | Select-Object -ExpandProperty Name)
$dependencies+=@(Get-ScheduledTask | Where-Object {
  $_.Principal.UserId -ieq $u.SID.Value -or $_.Principal.UserId -ieq $u.Name -or
  $_.Principal.UserId -ieq ($env:COMPUTERNAME+'\'+$u.Name)
} | ForEach-Object { $_.TaskPath+$_.TaskName })
[PSCustomObject]@{name=$u.Name;account_id=$u.SID.Value;enabled=[bool]$u.Enabled;
  groups=@($groups | Sort-Object);dependencies=@($dependencies | Sort-Object)} | ConvertTo-Json -Compress -Depth 5
""", {"name": name})
        import pwd
        user = pwd.getpwnam(name)
        local = [line.split(':') for line in Path('/etc/passwd').read_text().splitlines()
                 if line.split(':', 1)[0] == name]
        if len(local) != 1 or len(local[0]) != 7 or local[0][2] != str(user.pw_uid):
            raise ValueError('only an exact local passwd identity may be rotated')
        # getent resolves shadow without requiring Python's removed spwd module.
        shadow = native_command(["getent", "shadow", name]).decode().strip().split(":")
        if len(shadow) < 2 or shadow[0] != name:
            raise ValueError("local password state is unavailable")
        groups = sorted(os.getgrouplist(name, user.pw_gid))
        return {"name": user.pw_name, "account_id": str(user.pw_uid), "gid": user.pw_gid,
                "home": user.pw_dir, "shell": user.pw_shell, "groups": groups,
                "enabled": bool(shadow[1] and not shadow[1].startswith(("!", "*"))),
                "dependencies": []}

    def set_password(self, name, account_id, password):
        password = validate_password(password)
        before = self.account(name)
        if before["account_id"] != account_id or not before["enabled"]:
            raise ValueError("account identity changed or login is disabled")
        if before.get("dependencies"):
            raise ValueError("account has service/task dependencies requiring a coordinated rotation adapter")
        if os.name == "nt":
            powershell_json(r"""
$u=Get-LocalUser -SID $p.account_id
if ($u.Name -ine $p.name -or -not $u.Enabled) { throw 'Identity changed' }
$secret=ConvertTo-SecureString $p.password -AsPlainText -Force
Set-LocalUser -SID $u.SID -Password $secret
'true'
""", {"name": name, "account_id": account_id, "password": password})
        else:
            if account_id == "0" and name != "root":
                raise ValueError("duplicate UID-zero aliases require separate identity remediation")
            native_command(["chpasswd"], incoming=(name + ":" + password + "\n").encode())
        after = self.account(name)
        if before != after:
            raise RuntimeError("password operation changed account identity or access state")

    def verify_password(self, name, account_id, password):
        if self.account(name)["account_id"] != account_id:
            return False
        if os.name == "nt":
            advapi = ctypes.WinDLL("advapi32", use_last_error=True)
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            handle = ctypes.c_void_p()
            advapi.LogonUserW.argtypes = [ctypes.c_wchar_p] * 3 + [ctypes.c_uint32, ctypes.c_uint32,
                                                               ctypes.POINTER(ctypes.c_void_p)]
            advapi.LogonUserW.restype = ctypes.c_int
            kernel.CloseHandle.argtypes = [ctypes.c_void_p]
            ok = bool(advapi.LogonUserW(name, ".", password, 3, 0, ctypes.byref(handle)))
            if handle.value:
                kernel.CloseHandle(handle)
            return ok
        return pam_verify(name, password)

    def persistence_snapshot(self, target):
        from .persistence_security import validate_target
        target = validate_target(target)
        kind = target["kind"]
        if kind == "systemd-service":
            if os.name != "posix":
                raise ValueError("systemd requires Linux")
            service = target["service"]
            result = native_command(["systemctl", "show", service, "--property=FragmentPath,ActiveState,UnitFileState"]).decode()
            values = dict(line.split("=", 1) for line in result.splitlines() if "=" in line)
            if values.get("FragmentPath") != target["path"] or values.get("ActiveState") not in {"active", "inactive", "failed"}:
                raise ValueError("systemd unit path or state is unverified")
            if values.get("UnitFileState") not in {"enabled", "disabled", "static"}:
                raise ValueError("unsupported systemd enablement state")
            return values
        if kind == "registry-value":
            import winreg
            hive = winreg.HKEY_LOCAL_MACHINE if target["hive"] == "HKLM" else winreg.HKEY_USERS
            with winreg.OpenKey(hive, target["key"], access=winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                value, value_type = winreg.QueryValueEx(key, target["value_name"])
            if value_type not in {winreg.REG_SZ, winreg.REG_EXPAND_SZ} or not isinstance(value, str):
                raise ValueError("only string startup registry values are supported")
            return {"value": value, "type": value_type}
        if kind == "scheduled-task":
            return powershell_json(r"""
$found=@(Get-ScheduledTask -TaskPath $p.task_path -TaskName $p.task_name)
if ($found.Count -ne 1 -or $found[0].TaskPath -ine $p.task_path -or $found[0].TaskName -ine $p.task_name) { throw 'Task identity is ambiguous' }
$t=$found[0]
if ([string]$t.Principal.LogonType -in @('Password','InteractiveTokenOrPassword')) { throw 'Password-backed task rollback unsupported' }
$xml=Export-ScheduledTask -TaskPath $p.task_path -TaskName $p.task_name
[PSCustomObject]@{xml=[string]$xml} | ConvertTo-Json -Compress
""", target)
        raise ValueError("unsupported native persistence kind")

    def persistence_remove(self, target, expected):
        if self.persistence_snapshot(target) != expected:
            raise ValueError("native persistence changed before removal")
        if target["kind"] == "systemd-service":
            native_command(["systemctl", "stop", target["service"]])
            if expected["UnitFileState"] == "enabled":
                native_command(["systemctl", "disable", target["service"]])
        elif target["kind"] == "registry-value":
            import winreg
            hive = winreg.HKEY_LOCAL_MACHINE if target["hive"] == "HKLM" else winreg.HKEY_USERS
            with winreg.OpenKey(hive, target["key"], access=winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                if winreg.QueryValueEx(key, target['value_name']) != (expected['value'], expected['type']):
                    raise ValueError('registry value changed before deletion')
                winreg.DeleteValue(key, target["value_name"])
        else:
            powershell_json(r"""
$found=@(Get-ScheduledTask -TaskPath $p.target.task_path -TaskName $p.target.task_name)
if ($found.Count -ne 1 -or $found[0].TaskPath -ine $p.target.task_path -or $found[0].TaskName -ine $p.target.task_name) { throw 'Task identity changed' }
$xml=Export-ScheduledTask -TaskPath $p.target.task_path -TaskName $p.target.task_name
if ([string]$xml -cne $p.expected.xml) { throw 'Task changed before mutation' }
Stop-ScheduledTask -InputObject $found[0]
$xml=Export-ScheduledTask -TaskPath $p.target.task_path -TaskName $p.target.task_name
if ([string]$xml -cne $p.expected.xml) { throw 'Task changed while stopping' }
Unregister-ScheduledTask -InputObject $found[0] -Confirm:$false
'true'
""", {'target':target, 'expected':expected})

    def persistence_absent(self, target):
        from .persistence_security import validate_target
        target = validate_target(target)
        if target['kind'] == 'systemd-service':
            output = native_command(['systemctl','show',target['service'],
                '--property=ActiveState,UnitFileState,MainPID,ControlPID']).decode()
            state = dict(line.split('=',1) for line in output.splitlines() if '=' in line)
            return (state.get('ActiveState') == 'inactive' and state.get('MainPID') == '0'
                    and state.get('ControlPID') == '0' and state.get('UnitFileState') in {'', 'disabled', 'static', 'masked'})
        if target["kind"] == "registry-value":
            try:
                self.persistence_snapshot(target)
                return False
            except FileNotFoundError:
                return True
        if target["kind"] == "scheduled-task":
            return powershell_json(r"""
$found=@(Get-ScheduledTask | Where-Object { $_.TaskPath -ieq $p.task_path -and $_.TaskName -ieq $p.task_name })
([bool]($found.Count -eq 0)) | ConvertTo-Json -Compress
""", target) is True
        raise ValueError("native absence check unavailable")

    def persistence_restore(self, target, before):
        from .persistence_security import validate_target
        target = validate_target(target)
        if target["kind"] == "systemd-service":
            self.reload_systemd()
            if before["UnitFileState"] == "enabled":
                native_command(["systemctl", "enable", target["service"]])
            if before["ActiveState"] == "active":
                native_command(["systemctl", "start", target["service"]])
        elif target["kind"] == "registry-value":
            import winreg
            hive = winreg.HKEY_LOCAL_MACHINE if target["hive"] == "HKLM" else winreg.HKEY_USERS
            with winreg.OpenKey(hive, target["key"], access=winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
                try:
                    winreg.QueryValueEx(key, target['value_name'])
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError('registry rollback would overwrite a reappeared value')
                winreg.SetValueEx(key, target["value_name"], 0, before["type"], before["value"])
        else:
            powershell_json(r"""
Register-ScheduledTask -TaskPath $p.target.task_path -TaskName $p.target.task_name -Xml $p.before.xml | Out-Null
'true'
""", {"target": target, "before": before})

    @staticmethod
    def reload_systemd():
        native_command(["systemctl", "daemon-reload"])


def pam_verify(username, password):
    """Use the host PAM authentication/account policy, never compare hashes ourselves."""
    pam_name, libc_name = ctypes.util.find_library("pam"), ctypes.util.find_library("c")
    if not pam_name or not libc_name:
        raise RuntimeError("native password verification requires PAM")
    pam, libc = ctypes.CDLL(pam_name), ctypes.CDLL(libc_name)

    class Message(ctypes.Structure):
        _fields_ = [("style", ctypes.c_int), ("text", ctypes.c_char_p)]

    class Response(ctypes.Structure):
        _fields_ = [("text", ctypes.c_void_p), ("code", ctypes.c_int)]

    callback_type = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.POINTER(Message)),
                                    ctypes.POINTER(ctypes.POINTER(Response)), ctypes.c_void_p)
    libc.calloc.argtypes = [ctypes.c_size_t, ctypes.c_size_t]
    libc.calloc.restype = ctypes.c_void_p
    libc.strdup.argtypes = [ctypes.c_char_p]
    libc.strdup.restype = ctypes.c_void_p
    libc.free.argtypes = [ctypes.c_void_p]

    @callback_type
    def conversation(count, messages, responses, _context):
        if not 1 <= count <= 16:
            return 19
        allocated = libc.calloc(count, ctypes.sizeof(Response))
        if not allocated:
            return 5
        values = ctypes.cast(allocated, ctypes.POINTER(Response))
        try:
            for index in range(count):
                style = messages[index].contents.style
                if style in {1, 2}:
                    values[index].text = libc.strdup((password if style == 1 else username).encode())
                    if not values[index].text:
                        raise ValueError("allocation failed")
                elif style not in {3, 4}:
                    raise ValueError("unsupported PAM prompt")
            responses[0] = values
            return 0
        except Exception:
            for index in range(count):
                if values[index].text:
                    libc.free(values[index].text)
            libc.free(allocated)
            return 19

    class Conversation(ctypes.Structure):
        _fields_ = [("callback", callback_type), ("context", ctypes.c_void_p)]

    conv, handle = Conversation(conversation, None), ctypes.c_void_p()
    pam.pam_start.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.POINTER(Conversation), ctypes.POINTER(ctypes.c_void_p)]
    pam.pam_authenticate.argtypes = pam.pam_acct_mgmt.argtypes = [ctypes.c_void_p, ctypes.c_int]
    pam.pam_end.argtypes = [ctypes.c_void_p, ctypes.c_int]
    status = pam.pam_start(b"login", username.encode(), ctypes.byref(conv), ctypes.byref(handle))
    if status:
        return False
    try:
        status = pam.pam_authenticate(handle, 0)
        if status == 0:
            status = pam.pam_acct_mgmt(handle, 0)
        return status == 0
    finally:
        pam.pam_end(handle, status)
