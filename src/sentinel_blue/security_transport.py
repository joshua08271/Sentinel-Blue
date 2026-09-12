"""Pinned management channels for security operations, with bounded responses."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import stat
import time
from pathlib import Path

from .json_codec import canonical_json_bytes, strict_json_loads
from .security_native import powershell_json


class SecurityTransport:
    def __init__(self, profile, *, range_deployment=False):
        self.profile = profile
        self.range_deployment = range_deployment
        self.management_updates = {}
        self.credential_observer = None

    def set_management_password(self, host, name, password):
        management_name = host.get("username", "").split("\\")[-1]
        if host["transport"] == "winrm" and management_name.casefold() == name.casefold():
            self.management_updates[host["name"]] = password
            if self.credential_observer is not None:
                self.credential_observer(host, name, password)

    def request(self, host, request, seconds):
        if seconds <= 0 or seconds > 45:
            raise ValueError("invalid security transport deadline")
        self.profile.assert_target(host["address"])
        self.profile.assert_route(host["transport"])
        if host["transport"] == "local":
            from .security_workflow import guest_request
            return guest_request(request, self.profile, host)
        payload = {"host": host, "event_profile": self.profile.raw, "request": request}
        if host["transport"] == "ssh":
            return self._ssh(host, payload, seconds)
        if host["transport"] == "winrm":
            if os.name != "nt":
                raise RuntimeError("the WinRM security adapter requires a Windows controller")
            return self._winrm(host, payload, seconds)
        raise ValueError("unsupported security transport")

    def _ssh(self, host, payload, seconds):
        try:
            import paramiko
        except ImportError:
            raise RuntimeError("SSH security operations require the optional paramiko dependency") from None
        for field in ("known_hosts_file", "key_file"):
            path = Path(host[field])
            if not path.is_absolute() or path.is_symlink() or not path.is_file() or path.stat().st_nlink != 1:
                raise ValueError("security SSH requires private pinned management files")
            if os.name == "posix" and path.stat().st_mode & (0o077 if field == "key_file" else 0o022):
                raise ValueError("SSH management file permissions are unsafe")
        client = paramiko.SSHClient()
        client.load_host_keys(host["known_hosts_file"])
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        deadline = time.monotonic() + seconds
        try:
            client.connect(host["address"], port=host.get("port", 22), username=host["username"],
                           key_filename=host["key_file"], allow_agent=False, look_for_keys=False,
                           timeout=seconds, banner_timeout=seconds, auth_timeout=seconds)
            # Execute a private copy of the exact captured bytes so a path change
            # after hashing cannot select a different zipapp.
            wrapper = (
                "import hashlib,os,pathlib,runpy,sys,tempfile; "
                "p=pathlib.Path(sys.argv[1]); d=p.read_bytes(); "
                "assert not p.is_symlink() and hashlib.sha256(d).hexdigest()==sys.argv[2]; "
                "t=tempfile.TemporaryDirectory(prefix='sb-security-'); "
                "q=pathlib.Path(t.name)/'runtime.pyz'; q.write_bytes(d); os.chmod(q,0o600); "
                "sys.argv=[str(q)]+sys.argv[3:]; runpy.run_path(str(q),run_name='__main__')"
            )
            argv = ["sudo", "-n", "--", host.get("python_executable", "python3"), "-c", wrapper,
                    host["runtime_path"], self.profile.release["sha256"], "security-guest"]
            if self.range_deployment:
                argv.append("--range-deployment")
            channel = client.get_transport().open_session(timeout=max(0.1, deadline - time.monotonic()))
            try:
                channel.settimeout(max(0.1, deadline - time.monotonic()))
                channel.exec_command(shlex.join(argv))
                channel.sendall(canonical_json_bytes(payload, max_bytes=2 * 1024 * 1024))
                channel.shutdown_write()
                data, error_bytes = bytearray(), 0
                while True:
                    if time.monotonic() >= deadline:
                        raise TimeoutError("security management request timed out")
                    if channel.recv_ready():
                        data.extend(channel.recv(65536))
                    if channel.recv_stderr_ready():
                        error_bytes += len(channel.recv_stderr(65536))
                    if len(data) + error_bytes > 4 * 1024 * 1024:
                        raise ValueError("security response exceeds its bound")
                    if channel.exit_status_ready() and not channel.recv_ready() and not channel.recv_stderr_ready():
                        break
                    time.sleep(0.01)
                if channel.recv_exit_status() or error_bytes:
                    raise RuntimeError("security guest rejected the operation")
                result = strict_json_loads(bytes(data), max_bytes=4 * 1024 * 1024)
                if not isinstance(result, dict) or "error" in result:
                    raise ValueError("invalid security response")
                return result
            finally:
                channel.close()
        finally:
            client.close()

    def _winrm(self, host, payload, seconds):
        script = r"""
$credential=Import-Clixml -LiteralPath $p.host.credential_file
if ($credential.UserName -ine $p.host.username) { throw 'Management identity mismatch' }
if ($p.replacement_password) {
  $credential=[PSCredential]::new($credential.UserName,(ConvertTo-SecureString $p.replacement_password -AsPlainText -Force))
}
$options=New-PSSessionOption -OpenTimeout $p.milliseconds -OperationTimeout $p.milliseconds
$session=New-PSSession -ComputerName $p.host.address -Port $p.port -UseSSL -Authentication Negotiate -Credential $credential -SessionOption $options
try {
  $result=Invoke-Command -Session $session -ScriptBlock {
    param($python,$runtime,$expected,$request,$range)
    $ErrorActionPreference='Stop'
    if ((Get-Item -LiteralPath $runtime).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse point' }
    if ((Get-FileHash -LiteralPath $runtime -Algorithm SHA256).Hash -ine $expected) { throw 'Runtime mismatch' }
    $args=@('security-guest'); if ($range) { $args+='--range-deployment' }
    $text=$request | & $python $runtime @args
    if ($LASTEXITCODE -ne 0) { throw 'Guest rejected request' }
    return ($text -join "`n")
  } -ArgumentList $p.python,$p.host.runtime_path,$p.expected,$p.request,$p.range
  ($result | ConvertFrom-Json) | ConvertTo-Json -Depth 30 -Compress
} finally { Remove-PSSession -Session $session }
"""
        result = powershell_json(script, {"host": host, "port": host.get("port", 5986),
            "python": host.get("python_executable", "python.exe"), "expected": self.profile.release["sha256"],
            "request": json.dumps(payload), "range": self.range_deployment,
            "replacement_password": self.management_updates.get(host["name"]),
            "milliseconds": max(1000, int(seconds * 1000))}, timeout=seconds)
        if not isinstance(result, dict) or "error" in result:
            raise ValueError("invalid Windows security response")
        return result
