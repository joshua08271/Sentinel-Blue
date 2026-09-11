"""Authenticated, bounded transport for explicitly reviewed setup runbooks.

Scripts travel on stdin, not a process command line. Output is deliberately not
returned: setup scripts and package managers can print credentials. Reports
contain return codes, timings, and output hashes instead.
"""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import math
import os
import signal
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .launcher import DeploymentStep, _powershell_executable, _ssh_base


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    seconds: float
    uncertain: bool = False
    output_sha256: str = ""
    output_log: str | None = None


def _ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def powershell_environment(executable: str) -> dict[str, str] | None:
    # Python launched from pwsh inherits its PS7 module paths. Windows
    # PowerShell cannot load those modules: let it construct its own defaults.
    if Path(executable).name.casefold() == "powershell.exe":
        return {key: value for key, value in os.environ.items() if key.upper() != "PSMODULEPATH"}
    return None


def run_process(argv: list[str], script: str, seconds: float, *, log_dir: Path | None = None,
                env: dict[str, str] | None = None) -> CommandResult:
    """Bound a process group without buffering unbounded or sensitive output."""
    if not math.isfinite(seconds) or seconds <= 0:
        return CommandResult(None, 0, True)
    started = time.monotonic()
    # Anonymous files keep script output out of reports and off persistent logs.
    with tempfile.TemporaryFile() as outgoing, tempfile.TemporaryFile() as incoming:
        incoming.write(script.encode("utf-8"))
        incoming.seek(0)
        proc = subprocess.Popen(
            argv, stdin=incoming, stdout=outgoing, stderr=subprocess.STDOUT, env=env,
            start_new_session=os.name == "posix",
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0,
        )
        uncertain = False
        try:
            proc.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            uncertain = True
            if os.name == "posix":
                try:
                    os.killpg(proc.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
            else:
                # Owned process tree only; never enumerate or kill service PIDs.
                subprocess.run(
                    ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=5, check=False,
                )
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                else:
                    proc.kill()
                proc.wait(timeout=3)
        outgoing.seek(0)
        digest = hashlib.sha256()
        log_name = None
        log = None
        remaining_log_bytes = 16 * 1024 * 1024
        if log_dir is not None:
            if log_dir.is_symlink():
                raise ValueError("private setup log directory cannot be a symlink")
            log_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            log_name = uuid.uuid4().hex + ".log"
            descriptor = os.open(log_dir / log_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                                 getattr(os, "O_NOFOLLOW", 0), 0o600)
            log = os.fdopen(descriptor, "wb")
        try:
            for block in iter(lambda: outgoing.read(65536), b""):
                digest.update(block)
                if log is not None and remaining_log_bytes:
                    captured = block[:remaining_log_bytes]
                    log.write(captured)
                    remaining_log_bytes -= len(captured)
        finally:
            if log is not None:
                log.close()
        return CommandResult(proc.returncode, time.monotonic() - started, uncertain, digest.hexdigest(), log_name)


class SetupTransport:
    """One command per host at a time; the scheduler owns concurrency."""

    def __init__(self, log_dir: Path | None = None):
        self.log_dir = log_dir
        self.management_updates = {}

    def set_management_password(self, host, name, password):
        if host.get("transport") == "winrm" and host.get("username", "").split("\\")[-1].casefold() == name.casefold():
            self.management_updates[host["name"]] = (host["username"], password)

    def execute(self, host: dict[str, Any], script: str, seconds: float) -> CommandResult:
        if seconds <= 0:
            return CommandResult(None, 0, True)
        route = host["transport"]
        platform = host["platform"]
        if route == "local":
            if not ipaddress.ip_address(host["address"]).is_loopback:
                raise ValueError("local setup requires a loopback target on this machine")
            if platform != ("windows" if os.name == "nt" else "linux"):
                raise ValueError("local setup platform does not match this machine")
            if platform == "linux":
                return run_process(["bash", "-se"], script, seconds, log_dir=self.log_dir)
            return self._powershell(script, seconds)
        if route == "ssh":
            if platform != "linux":
                raise ValueError("setup SSH currently supports Linux bash targets")
            step = DeploymentStep(host["name"], host["address"], platform, route, "setup", [], host)
            if host.get("accept_new_host_key"):
                raise ValueError("setup requires an already verified SSH host key")
            options, target = _ssh_base(step)
            # GNU timeout is also installed on the remote host. Losing the SSH
            # client alone does not establish that a remote mutation stopped.
            budget = max(1, math.floor(seconds))
            remote = f"timeout --signal=TERM --kill-after=3s {budget}s bash -se"
            if host.get("sudo", True):
                remote = "sudo -n -- " + remote
            result = run_process(
                ["ssh", *options, "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=5",
                 "-o", "ServerAliveCountMax=2", target, remote], script, seconds, log_dir=self.log_dir,
            )
            if result.returncode in {124, 137, 143, 255}:
                return CommandResult(result.returncode, result.seconds, True, result.output_sha256, result.output_log)
            return result
        if route == "winrm":
            payload = base64.b64encode(script.encode()).decode()
            credential = ""
            credential_argument = ""
            if host.get("credential_file"):
                path = Path(host["credential_file"])
                if not path.is_file() or path.is_symlink():
                    raise ValueError("WinRM credential_file must be a private Export-Clixml file")
                credential = f"$credential = Import-Clixml -LiteralPath {_ps(str(path))}\n"
                if host["name"] in self.management_updates:
                    username, password = self.management_updates[host["name"]]
                    encoded_secret = base64.b64encode(password.encode()).decode()
                    credential += (f"if ($credential.UserName -ine {_ps(username)}) {{ throw 'Management identity changed' }}\n"
                        f"$updated = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded_secret}'))\n"
                        "$credential = [PSCredential]::new($credential.UserName, (ConvertTo-SecureString $updated -AsPlainText -Force))\n")
                credential_argument = " -Credential $credential"
            port = host.get("port", 5986)
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError("invalid WinRM port")
            remote = (
                "$ErrorActionPreference = 'Stop'\ntry {\n" + credential +
                f"$session = New-PSSession -ComputerName {_ps(host['address'])} -Port {port} "
                "-UseSSL -Authentication Negotiate" + credential_argument + "\n"
                "try {\n"
                "  $code = Invoke-Command -Session $session -ScriptBlock { param($payload)\n"
                "    $script = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))\n"
                "    $temp = Join-Path $env:TEMP ([IO.Path]::GetRandomFileName() + '.ps1')\n"
                "    try {\n"
                "      [IO.File]::WriteAllText($temp, $script, [Text.UTF8Encoding]::new($false))\n"
                "      & powershell.exe -NoLogo -NoProfile -NonInteractive -File $temp *> $null\n"
                "      return [int]$LASTEXITCODE\n"
                "    } finally { Remove-Item -LiteralPath $temp -Force -ErrorAction SilentlyContinue }\n"
                f"  }} -ArgumentList '{payload}'\n"
                "  if (@($code).Count -ne 1) { exit 255 }\n"
                "  exit ([int]$code)\n"
                "} finally { Remove-PSSession -Session $session }\n"
                "} catch { exit 255 }\n"
            )
            result = self._powershell(remote, seconds)
            # Transport exceptions may occur after a mutation; a nonzero wrapper
            # exit cannot safely authorize an automatic replay.
            return CommandResult(result.returncode, result.seconds,
                                 result.uncertain or result.returncode == 255,
                                 result.output_sha256, result.output_log)
        raise ValueError(f"setup adapter unavailable: {route}")

    def _powershell(self, script: str, seconds: float) -> CommandResult:
        executable = (shutil.which("powershell.exe") if os.name == "nt" else None) or _powershell_executable()
        # -File gives reliable exit semantics; -Command - with redirected stdin
        # can report success even when an earlier statement failed.
        with tempfile.TemporaryDirectory(prefix="sentinel-setup-") as directory:
            path = Path(directory) / "run.ps1"
            path.write_text(script, encoding="utf-8-sig")
            if os.name == "posix":
                path.chmod(0o600)
            return run_process([executable, "-NoLogo", "-NoProfile", "-NonInteractive",
                                "-File", str(path)], "", seconds, log_dir=self.log_dir,
                               env=powershell_environment(executable))

    def preflight(self, host: dict[str, Any], seconds: float) -> CommandResult:
        if host["platform"] == "linux":
            script = "set -eu\ncommand -v bash >/dev/null\ncommand -v timeout >/dev/null\nid -u >/dev/null\n"
        else:
            script = "$ErrorActionPreference = 'Stop'\n$PSVersionTable.PSVersion | Out-Null\nexit 0\n"
        return self.execute(host, script, seconds)
