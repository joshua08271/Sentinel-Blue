"""Owner-gated Windows-native validation on a disposable GitHub runner.

The campaign creates only inert, run-scoped fixtures.  It exercises real Windows
account, scheduled-task, Registry Run-key, disabled firewall-rule, process,
listener, NTFS ACL, restoration, rollback, and reparse-point behavior, then
fails unless every fixture is removed.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import re
import platform
import secrets
import shutil
import socket
import stat
import subprocess
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping

from . import __version__
from .actions import ActionExecutor
from .collectors import collect
from .detection import detect
from .process_identity import inspect_process_identity
from .risk import RiskModel
from .validation import telemetry_observation_sha256


EXPECTED_REPOSITORY = "joshua08271/Sentinel-Blue"
EXPECTED_ACTOR = "joshua08271"
CONFIRMATION = "github-hosted-ephemeral-windows-runner"
ALLOWED_EVENTS = frozenset({"pull_request", "workflow_dispatch"})
REQUIRED_TOOLS = ("powershell.exe", "icacls.exe")
APPROVED_CONTENT = b"sentinel-blue-windows-native-approved-v1\n"
TAMPERED_CONTENT = b"sentinel-blue-windows-native-inert-tamper-v1\n"
TASK_DESCRIPTION = "Sentinel Blue disposable inert persistence fixture"
# New-LocalUser accepts at most 48 characters in Description.
ACCOUNT_DESCRIPTION = "Sentinel Blue owned privileged fixture"
FIREWALL_DESCRIPTION = "Sentinel Blue disposable disabled loopback-rule fixture"
RUN_KEY_PATH = r"Registry::HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run"
RUN_KEY_LABEL = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run"
REPORT_NAME = "windows-native-live-report.json"


class WindowsNativeRangeError(RuntimeError):
    """A bounded Windows-native assertion failed."""


@dataclass(frozen=True, slots=True)
class WindowsRunnerContext:
    repository: str
    actor: str
    event_name: str
    run_id: str
    suffix: str
    workspace: Path
    runner_temp: Path


def _is_reparse(path: Path) -> bool:
    try:
        details = os.lstat(path)
    except OSError:
        return False
    attributes = int(getattr(details, "st_file_attributes", 0) or 0)
    marker = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))
    return path.is_symlink() or bool(attributes & marker)


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _validated_directory(raw: str, label: str) -> Path:
    path = Path(raw)
    if not raw or not path.is_absolute() or not path.is_dir() or _is_reparse(path):
        raise WindowsNativeRangeError(f"{label} is unavailable or unsafe")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise WindowsNativeRangeError(f"{label} is unavailable or unsafe") from exc
    if not _same_path(path.absolute(), resolved):
        raise WindowsNativeRangeError(f"{label} must not traverse a reparse point")
    return resolved


def _is_windows_admin() -> bool:
    if platform.system().casefold() != "windows":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


def validate_runner_environment(
    environ: Mapping[str, str] | None = None,
    *,
    system_name: str | None = None,
    administrator: bool | None = None,
    tool_finder: Callable[[str], str | None] = shutil.which,
) -> WindowsRunnerContext:
    """Fail closed unless this is the owner's ephemeral Windows Actions job."""

    values = os.environ if environ is None else environ
    if values.get("SENTINEL_BLUE_WINDOWS_DISPOSABLE_LAB") != CONFIRMATION:
        raise WindowsNativeRangeError("the exact Windows disposable-runner confirmation is absent")
    if values.get("GITHUB_ACTIONS", "").casefold() != "true":
        raise WindowsNativeRangeError("Windows native range is restricted to GitHub Actions")
    if values.get("RUNNER_ENVIRONMENT", "").casefold() != "github-hosted":
        raise WindowsNativeRangeError("self-hosted runners are not authorized")
    if values.get("RUNNER_OS", "").casefold() != "windows":
        raise WindowsNativeRangeError("Windows native range requires a disposable Windows runner")
    if (system_name or platform.system()).casefold() != "windows":
        raise WindowsNativeRangeError("Windows native range requires a Windows kernel")
    if values.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
        raise WindowsNativeRangeError("the repository identity is outside the fixed allowlist")
    if values.get("GITHUB_ACTOR") != EXPECTED_ACTOR:
        raise WindowsNativeRangeError("the workflow actor is outside the fixed allowlist")
    event_name = values.get("GITHUB_EVENT_NAME", "")
    if event_name not in ALLOWED_EVENTS:
        raise WindowsNativeRangeError("the workflow event is not authorized for native changes")
    if values.get("SENTINEL_BLUE_HEAD_REPOSITORY") != EXPECTED_REPOSITORY:
        raise WindowsNativeRangeError("forked or unbound workflow code is not authorized")
    run_id = values.get("GITHUB_RUN_ID", "")
    if not run_id.isascii() or not run_id.isdigit() or not 1 <= len(run_id) <= 20:
        raise WindowsNativeRangeError("GITHUB_RUN_ID is not a bounded numeric identifier")
    is_admin = _is_windows_admin() if administrator is None else administrator
    if is_admin is not True:
        raise WindowsNativeRangeError("Windows native range requires the hosted administrator token")
    workspace = _validated_directory(values.get("GITHUB_WORKSPACE", ""), "GITHUB_WORKSPACE")
    runner_temp = _validated_directory(values.get("RUNNER_TEMP", ""), "RUNNER_TEMP")
    missing = [name for name in REQUIRED_TOOLS if tool_finder(name) is None]
    if missing:
        raise WindowsNativeRangeError(
            "required Windows tools are unavailable: " + ", ".join(missing)
        )
    return WindowsRunnerContext(
        repository=EXPECTED_REPOSITORY,
        actor=EXPECTED_ACTOR,
        event_name=event_name,
        run_id=run_id,
        suffix=run_id[-10:],
        workspace=workspace,
        runner_temp=runner_temp,
    )


class _InertHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = b"sentinel-blue inert Windows listener\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class WindowsNativeRunnerLab:
    """Own and clean every Windows resource created by one campaign."""

    def __init__(self, context: WindowsRunnerContext):
        self.context = context
        self.root = context.runner_temp / f"sentinel-blue-windows-native-{context.run_id}"
        self.root_identity: tuple[int, int] | None = None
        self.state_dir = self.root / "agent-state"
        self.config_path = self.root / "protected.conf"
        self.link_path = self.root / "protected-link.conf"
        local_app_data = Path(os.environ.get("LOCALAPPDATA", ""))
        if not local_app_data.is_absolute():
            raise WindowsNativeRangeError("LOCALAPPDATA is unavailable for the inert process fixture")
        self.process_path = (
            local_app_data
            / "Temp"
            / f"sentinel-blue-native-{context.run_id}.exe"
        )
        self.heartbeat_path = self.root / "heartbeat.txt"
        self.heartbeat_script_path = self.root / "heartbeat.vbs"
        self.account_name = f"sblab{context.suffix[-10:]}"
        self.task_name = f"SentinelBlueNative{context.suffix}"
        self.firewall_name = f"SentinelBlueNativeFirewall{context.suffix}"
        self.firewall_description = f"{FIREWALL_DESCRIPTION} [{context.run_id}]"
        self.run_value_name = f"SentinelBlueNative{context.suffix}"
        self.run_value_data = (
            f'"{ntpath.join(os.environ.get("SystemRoot", ""), "System32", "cmd.exe")}" '
            "/d /c exit 0"
        )
        self.account_sid = ""
        self.account_created = False
        self.task_created = False
        self.firewall_created = False
        self.run_value_created = False
        self.process_created = False
        self.process_digest = ""
        self.link_created = False
        self.listener: ThreadingHTTPServer | None = None
        self.listener_thread: threading.Thread | None = None
        self.inert_process: subprocess.Popen[bytes] | None = None
        self.executor: ActionExecutor | None = None
        self.baseline_data: bytes | None = None
        self.baseline_metadata: dict[str, Any] | None = None
        self.baseline_digest = ""
        self.baseline_security_digest = ""
        self.sequence = 0
        self.completed_scenarios: list[dict[str, Any]] = []

    @staticmethod
    def _action_failure(label: str, result: Mapping[str, Any]) -> WindowsNativeRangeError:
        """Report fixed diagnostic categories, never raw action output or ACLs."""
        message = str(result.get('message', ''))
        categories = (
            'no approved restore point exists for this exact path and digest',
            'restore-point security metadata does not match the approved baseline',
            'target changed again after the monitored observation',
            'target security metadata changed again after the monitored observation',
            'post-restoration Windows security descriptor did not match',
            'post-restoration bytes or security metadata did not match the approved restore point',
            'Windows restoration file could not be opened',
            'Windows restoration file could not be read',
            'Windows restoration file information could not be changed',
            'Windows restoration file mode could not be read',
            'Windows restoration target changed before publish',
            'Windows restoration target name changed before publish',
            'Windows restoration temporary file did not verify',
            'Windows file security descriptor could not be restored',
            'Windows file security descriptor restore was incomplete',
            'Windows file security descriptor could not be read',
            'Windows security restore context could not be released',
            'required Windows privilege is unavailable',
            'file restoration failed configuration validation and was rolled back',
            'file restoration failed service validation and was rolled back',
        )
        reasons = [category for category in categories if category in message]
        codes = re.findall(r'\[(?:Errno|WinError) ([0-9]{1,10})\]', message)
        mismatch = re.search(r'\((owner|group|control|revision|resource manager control|(?:DACL|SACL)(?: (?:presence|invalid|revision|ACE count|ACE order|ACE type|ACE flags|ACE data|encoding))?)\)', message)
        details = reasons or ['unclassified action failure']
        if codes:
            details.append('native_error=' + ','.join(codes[:3]))
        if mismatch:
            details.append('descriptor_component=' + mismatch.group(1))
        control = re.search(r'\(control expected=(0x[0-9a-f]{4}) observed=(0x[0-9a-f]{4})\)', message)
        if control:
            details.append('descriptor_control_expected=' + control.group(1))
            details.append('descriptor_control_observed=' + control.group(2))
        return WindowsNativeRangeError(label + ': ' + '; '.join(details))

    @staticmethod
    def _command(
        arguments: list[str],
        *,
        timeout: float = 30.0,
        check: bool = True,
        extra_env: Mapping[str, str] | None = None,
        label: str = "Windows fixture command",
    ) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        if extra_env:
            environment.update(extra_env)
        if arguments and ntpath.basename(arguments[0]).casefold() == 'powershell.exe':
            # pwsh -> Python -> Windows PowerShell retains the PS7 module path.
            # Let Windows PowerShell construct its own default module paths so
            # native fixture cmdlets cannot resolve incompatible PS7 modules.
            environment = {key: value for key, value in environment.items()
                           if key.upper() != 'PSMODULEPATH'}
        result = subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            env=environment,
        )
        if check and result.returncode != 0:
            details = []
            for line in result.stderr.splitlines():
                if not line.startswith('SB_NATIVE_ERROR '):
                    continue
                try:
                    error = json.loads(line.removeprefix('SB_NATIVE_ERROR '))
                except ValueError:
                    continue
                if not isinstance(error, dict):
                    continue
                for name in ('command', 'error_id', 'category', 'exception'):
                    value = error.get(name)
                    if isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9_.,:-]{1,160}', value):
                        details.append(f'{name}={value}')
            raise WindowsNativeRangeError(
                f"{label} failed with status {result.returncode}" +
                (': ' + '; '.join(details) if details else '')
            )
        return result

    @classmethod
    def _powershell(
        cls,
        script: str,
        *,
        extra_env: Mapping[str, str] | None = None,
        timeout: float = 30.0,
        check: bool = True,
        label: str = "PowerShell fixture command",
    ) -> subprocess.CompletedProcess[str]:
        result = cls._command(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "$ErrorActionPreference = 'Stop';\ntry {\n" + script + r"""
} catch {
  $detail = [PSCustomObject]@{
    command = [string]$_.InvocationInfo.MyCommand.Name
    error_id = [string]$_.FullyQualifiedErrorId
    category = [string]$_.CategoryInfo.Category
    exception = $_.Exception.GetType().Name
  }
  [Console]::Error.WriteLine('SB_NATIVE_ERROR ' + ($detail | ConvertTo-Json -Compress))
  exit 1
}
""",
            ],
            timeout=timeout,
            check=check,
            extra_env=extra_env,
            label=label,
        )
        if check and result.stderr.strip():
            raise WindowsNativeRangeError(f'{label} returned error output')
        return result

    @classmethod
    def _powershell_json(
        cls,
        script: str,
        *,
        extra_env: Mapping[str, str] | None = None,
        label: str = "PowerShell inventory command",
    ) -> dict[str, Any]:
        result = cls._powershell(script, extra_env=extra_env, label=label)
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise WindowsNativeRangeError(f"{label} returned invalid JSON") from exc
        if not isinstance(payload, dict):
            raise WindowsNativeRangeError(f"{label} returned an invalid object")
        return payload

    def _account_state(self) -> dict[str, Any]:
        script = r"""
$user = Get-LocalUser -Name $env:SENTINEL_BLUE_FIXTURE_ACCOUNT -ErrorAction SilentlyContinue
if ($null -eq $user) {
  [PSCustomObject]@{Exists=$false} | ConvertTo-Json -Compress
  exit 0
}
$group = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
$memberSids = @(Get-LocalGroupMember -Group $group -ErrorAction Stop | ForEach-Object {$_.SID.Value})
[PSCustomObject]@{
  Exists=$true
  SID=$user.SID.Value
  Enabled=$user.Enabled
  Privileged=($memberSids -contains $user.SID.Value)
  Description=$user.Description
} | ConvertTo-Json -Compress
"""
        return self._powershell_json(
            script,
            extra_env={"SENTINEL_BLUE_FIXTURE_ACCOUNT": self.account_name},
            label="run-scoped account inspection",
        )

    def _task_state(self) -> dict[str, Any]:
        script = r"""
$task = Get-ScheduledTask -TaskName $env:SENTINEL_BLUE_FIXTURE_TASK -TaskPath '\' -ErrorAction SilentlyContinue
if ($null -eq $task) {
  [PSCustomObject]@{Exists=$false} | ConvertTo-Json -Compress
  exit 0
}
$action = @($task.Actions)[0]
[PSCustomObject]@{
  Exists=$true
  Description=$task.Description
  Execute=$action.Execute
  Arguments=$action.Arguments
  ActionCount=@($task.Actions | Where-Object {$null -ne $_}).Count
  TriggerCount=@($task.Triggers | Where-Object {$null -ne $_}).Count
  State=[string]$task.State
} | ConvertTo-Json -Compress
"""
        return self._powershell_json(
            script,
            extra_env={"SENTINEL_BLUE_FIXTURE_TASK": self.task_name},
            label="run-scoped scheduled-task inspection",
        )

    def _firewall_state(self) -> dict[str, Any]:
        script = r"""
$rule = Get-NetFirewallRule -Name $env:SENTINEL_BLUE_FIXTURE_FIREWALL -ErrorAction SilentlyContinue
if ($null -eq $rule) {
  [PSCustomObject]@{Exists=$false} | ConvertTo-Json -Compress
  exit 0
}
$address = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
$application = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
[PSCustomObject]@{
  Exists=$true
  Name=[string]$rule.Name
  DisplayName=[string]$rule.DisplayName
  Description=[string]$rule.Description
  Enabled=[string]$rule.Enabled
  Direction=[string]$rule.Direction
  Action=[string]$rule.Action
  RemoteAddress=@($address.RemoteAddress)
  Program=[string]$application.Program
} | ConvertTo-Json -Depth 3 -Compress
"""
        return self._powershell_json(
            script,
            extra_env={"SENTINEL_BLUE_FIXTURE_FIREWALL": self.firewall_name},
            label="run-scoped firewall-rule inspection",
        )

    def _run_value_state(self) -> dict[str, Any]:
        script = r"""
$key = Get-Item -LiteralPath $env:SENTINEL_BLUE_FIXTURE_RUN_KEY -ErrorAction SilentlyContinue
if ($null -eq $key) {
  [PSCustomObject]@{KeyExists=$false;Exists=$false} | ConvertTo-Json -Compress
  exit 0
}
if (@($key.GetValueNames()) -notcontains $env:SENTINEL_BLUE_FIXTURE_RUN_NAME) {
  [PSCustomObject]@{KeyExists=$true;Exists=$false} | ConvertTo-Json -Compress
  exit 0
}
[PSCustomObject]@{
  KeyExists=$true
  Exists=$true
  Kind=[string]$key.GetValueKind($env:SENTINEL_BLUE_FIXTURE_RUN_NAME)
  Value=[string]$key.GetValue($env:SENTINEL_BLUE_FIXTURE_RUN_NAME, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
} | ConvertTo-Json -Compress
"""
        return self._powershell_json(
            script,
            extra_env={
                "SENTINEL_BLUE_FIXTURE_RUN_KEY": RUN_KEY_PATH,
                "SENTINEL_BLUE_FIXTURE_RUN_NAME": self.run_value_name,
            },
            label="run-scoped Registry Run-value inspection",
        )

    @staticmethod
    def _remote_addresses(state: Mapping[str, Any]) -> list[str]:
        value = state.get("RemoteAddress", [])
        values = value if isinstance(value, list) else [value]
        return sorted(str(item).casefold() for item in values)

    def _firewall_identity_matches(self, state: Mapping[str, Any]) -> bool:
        expected_program = ntpath.normcase(ntpath.normpath(str(self.process_path)))
        observed_program = ntpath.normcase(
            ntpath.normpath(str(state.get("Program", "")))
        )
        remote = self._remote_addresses(state)
        return (
            state.get("Exists") is True
            and str(state.get("Name", "")) == self.firewall_name
            and str(state.get("DisplayName", "")) == self.firewall_name
            and str(state.get("Description", "")) == self.firewall_description
            and str(state.get("Enabled", "")).casefold() == "false"
            and str(state.get("Direction", "")).casefold() == "outbound"
            and str(state.get("Action", "")).casefold() == "block"
            and remote in (["127.0.0.1"], ["127.0.0.1/32"])
            and observed_program == expected_program
        )

    def _disable_account_exact(self) -> None:
        state = self._account_state()
        if (not self.account_created or not self.account_sid or not state.get('Exists')
                or state.get('SID') != self.account_sid or state.get('Description') != ACCOUNT_DESCRIPTION):
            raise WindowsNativeRangeError('refused to disable a changed account identity')
        self._powershell(r"""
$user = Get-LocalUser -Name $env:SENTINEL_BLUE_FIXTURE_ACCOUNT -ErrorAction Stop
if ($user.SID.Value -ne $env:SENTINEL_BLUE_FIXTURE_SID) { throw 'account SID changed' }
if ($user.Description -ne $env:SENTINEL_BLUE_FIXTURE_DESCRIPTION) { throw 'account marker changed' }
Disable-LocalUser -InputObject $user -ErrorAction Stop
""", extra_env={
            'SENTINEL_BLUE_FIXTURE_ACCOUNT': self.account_name,
            'SENTINEL_BLUE_FIXTURE_SID': self.account_sid,
            'SENTINEL_BLUE_FIXTURE_DESCRIPTION': ACCOUNT_DESCRIPTION,
        }, label='disable only the run-owned account fixture')
        state = self._account_state()
        if state.get('SID') != self.account_sid or state.get('Enabled') is not False or state.get('Privileged') is not True:
            raise WindowsNativeRangeError('disabled privileged-account fixture did not retain its exact identity')

    def _delete_account_exact(self) -> None:
        state = self._account_state()
        if not state.get("Exists"):
            self.account_created = False
            return
        observed_sid = str(state.get("SID", ""))
        if (
            str(state.get("Description", "")) != ACCOUNT_DESCRIPTION
            or (self.account_sid and observed_sid != self.account_sid)
        ):
            raise WindowsNativeRangeError("refused to delete a changed account identity")
        script = r"""
$user = Get-LocalUser -Name $env:SENTINEL_BLUE_FIXTURE_ACCOUNT -ErrorAction Stop
if ($user.SID.Value -ne $env:SENTINEL_BLUE_FIXTURE_SID) { throw 'account SID changed' }
if ($user.Description -ne $env:SENTINEL_BLUE_FIXTURE_DESCRIPTION) { throw 'account marker changed' }
Remove-LocalUser -InputObject $user -ErrorAction Stop
"""
        self._powershell(
            script,
            extra_env={
                "SENTINEL_BLUE_FIXTURE_ACCOUNT": self.account_name,
                "SENTINEL_BLUE_FIXTURE_SID": observed_sid,
                "SENTINEL_BLUE_FIXTURE_DESCRIPTION": ACCOUNT_DESCRIPTION,
            },
            label="exact run-scoped account cleanup",
        )
        if self._account_state().get("Exists"):
            raise WindowsNativeRangeError("run-scoped account remained after deletion")
        self.account_sid = ""
        self.account_created = False

    def _delete_task_exact(self) -> None:
        state = self._task_state()
        if not state.get("Exists"):
            self.task_created = False
            return
        expected_executable = ntpath.normcase(
            ntpath.normpath(str(Path(os.environ["SystemRoot"]) / "System32" / "cmd.exe"))
        )
        observed_executable = ntpath.normcase(ntpath.normpath(str(state.get("Execute", ""))))
        if (
            str(state.get("Description", "")) != TASK_DESCRIPTION
            or observed_executable != expected_executable
            or str(state.get("Arguments", "")) != "/d /c exit 0"
            or state.get("ActionCount") != 1
            or state.get("TriggerCount") != 0
        ):
            raise WindowsNativeRangeError("refused to delete a changed scheduled-task identity")
        script = r"""
$task = Get-ScheduledTask -TaskName $env:SENTINEL_BLUE_FIXTURE_TASK -TaskPath '\' -ErrorAction Stop
if ($task.Description -ne $env:SENTINEL_BLUE_FIXTURE_DESCRIPTION) { throw 'task marker changed' }
if (@($task.Actions | Where-Object {$null -ne $_}).Count -ne 1 -or @($task.Triggers | Where-Object {$null -ne $_}).Count -ne 0) { throw 'task structure changed' }
$action = @($task.Actions)[0]
if ($action.Arguments -ne '/d /c exit 0' -or $action.Execute -ne (Join-Path $env:SystemRoot 'System32\cmd.exe')) { throw 'task action changed' }
Unregister-ScheduledTask -InputObject $task -Confirm:$false -ErrorAction Stop
"""
        self._powershell(
            script,
            extra_env={
                "SENTINEL_BLUE_FIXTURE_TASK": self.task_name,
                "SENTINEL_BLUE_FIXTURE_DESCRIPTION": TASK_DESCRIPTION,
            },
            label="exact run-scoped scheduled-task cleanup",
        )
        if self._task_state().get("Exists"):
            raise WindowsNativeRangeError("run-scoped scheduled task remained after deletion")
        self.task_created = False

    def _delete_firewall_rule_exact(self) -> None:
        state = self._firewall_state()
        if not state.get("Exists"):
            self.firewall_created = False
            return
        if not self._firewall_identity_matches(state):
            raise WindowsNativeRangeError("refused to delete a changed firewall-rule identity")
        script = r"""
$rule = Get-NetFirewallRule -Name $env:SENTINEL_BLUE_FIXTURE_FIREWALL -ErrorAction Stop
if ($rule.Name -ne $env:SENTINEL_BLUE_FIXTURE_FIREWALL) { throw 'firewall rule name changed' }
if ($rule.DisplayName -ne $env:SENTINEL_BLUE_FIXTURE_FIREWALL) { throw 'firewall display name changed' }
if ($rule.Description -ne $env:SENTINEL_BLUE_FIXTURE_DESCRIPTION) { throw 'firewall marker changed' }
if ([string]$rule.Enabled -ne 'False') { throw 'firewall rule became enabled' }
if ([string]$rule.Direction -ne 'Outbound') { throw 'firewall direction changed' }
if ([string]$rule.Action -ne 'Block') { throw 'firewall action changed' }
$addressFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction Stop
$address = @($addressFilter.RemoteAddress)
$observedRemote = [string]$address[0]
if ($address.Count -ne 1 -or @('127.0.0.1','127.0.0.1/32') -notcontains $observedRemote) {
  throw 'firewall remote scope changed'
}
$application = $rule | Get-NetFirewallApplicationFilter -ErrorAction Stop
if (-not [string]::Equals([string]$application.Program, $env:SENTINEL_BLUE_FIXTURE_PROGRAM, [StringComparison]::OrdinalIgnoreCase)) {
  throw 'firewall program changed'
}
Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
"""
        self._powershell(
            script,
            extra_env={
                "SENTINEL_BLUE_FIXTURE_FIREWALL": self.firewall_name,
                "SENTINEL_BLUE_FIXTURE_DESCRIPTION": self.firewall_description,
                "SENTINEL_BLUE_FIXTURE_PROGRAM": str(self.process_path),
            },
            label="exact run-scoped firewall-rule cleanup",
        )
        if self._firewall_state().get("Exists"):
            raise WindowsNativeRangeError("run-scoped firewall rule remained after deletion")
        self.firewall_created = False

    def _delete_run_value_exact(self) -> None:
        state = self._run_value_state()
        if not state.get("Exists"):
            self.run_value_created = False
            return
        if (
            str(state.get("Kind", "")) != "String"
            or str(state.get("Value", "")) != self.run_value_data
        ):
            raise WindowsNativeRangeError(
                "refused to delete a changed Registry Run-value identity"
            )
        script = r"""
$key = Get-Item -LiteralPath $env:SENTINEL_BLUE_FIXTURE_RUN_KEY -ErrorAction Stop
if (@($key.GetValueNames()) -notcontains $env:SENTINEL_BLUE_FIXTURE_RUN_NAME) { throw 'Registry Run value disappeared' }
$kind = [string]$key.GetValueKind($env:SENTINEL_BLUE_FIXTURE_RUN_NAME)
$value = [string]$key.GetValue($env:SENTINEL_BLUE_FIXTURE_RUN_NAME, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
if ($kind -ne 'String') { throw 'Registry Run value kind changed' }
if (-not [string]::Equals($value, $env:SENTINEL_BLUE_FIXTURE_RUN_VALUE, [StringComparison]::Ordinal)) { throw 'Registry Run value changed' }
Remove-ItemProperty -LiteralPath $env:SENTINEL_BLUE_FIXTURE_RUN_KEY -Name $env:SENTINEL_BLUE_FIXTURE_RUN_NAME -ErrorAction Stop
"""
        self._powershell(
            script,
            extra_env={
                "SENTINEL_BLUE_FIXTURE_RUN_KEY": RUN_KEY_PATH,
                "SENTINEL_BLUE_FIXTURE_RUN_NAME": self.run_value_name,
                "SENTINEL_BLUE_FIXTURE_RUN_VALUE": self.run_value_data,
            },
            label="exact run-scoped Registry Run-value cleanup",
        )
        if self._run_value_state().get("Exists"):
            raise WindowsNativeRangeError(
                "run-scoped Registry Run value remained after deletion"
            )
        self.run_value_created = False

    def setup(self) -> None:
        if self.root.exists() or _is_reparse(self.root):
            raise WindowsNativeRangeError("run-scoped Windows lab root already exists")
        if self.process_path.exists() or _is_reparse(self.process_path):
            raise WindowsNativeRangeError("run-scoped temporary executable already exists")
        if self._account_state().get("Exists"):
            raise WindowsNativeRangeError("run-scoped Windows account already exists")
        if self._task_state().get("Exists"):
            raise WindowsNativeRangeError("run-scoped Windows scheduled task already exists")
        if self._firewall_state().get("Exists"):
            raise WindowsNativeRangeError("run-scoped Windows firewall rule already exists")
        run_state = self._run_value_state()
        if run_state.get("KeyExists") is not True:
            raise WindowsNativeRangeError("the fixed Windows Registry Run key is unavailable")
        if run_state.get("Exists"):
            raise WindowsNativeRangeError("run-scoped Windows Registry Run value already exists")
        process_parent = self.process_path.parent
        if not process_parent.is_dir() or _is_reparse(process_parent):
            raise WindowsNativeRangeError("the Windows temporary process directory is unsafe")
        self.root.mkdir(mode=0o700)
        root_stat = self.root.stat(follow_symlinks=False)
        self.root_identity = (root_stat.st_dev, root_stat.st_ino)
        self.state_dir.mkdir(mode=0o700)
        self.config_path.write_bytes(APPROVED_CONTENT)
        self.executor = ActionExecutor(
            self.state_dir,
            allow_containment=True,
            quarantine_ttl=30.0,
            allow_restoration=True,
            authorized_networks=["127.0.0.0/8"],
            authorized_hosts=["127.0.0.1"],
            excluded_hosts=[],
        )
        data, metadata = self.executor.restore_points._read_target(self.config_path)
        self.baseline_data = data
        self.baseline_metadata = metadata
        self.baseline_digest = hashlib.sha256(data).hexdigest()
        self.baseline_security_digest = (
            self.executor.restore_points._metadata_security_descriptor_sha256(metadata)
        )
        if data != APPROVED_CONTENT or not self.baseline_security_digest:
            raise WindowsNativeRangeError("the initial Windows file or ACL snapshot is incomplete")
        capture = self.executor.execute(
            "capture_restore_point",
            {
                "files": [
                    {
                        "path": str(self.config_path),
                        "sha256": self.baseline_digest,
                        "security_descriptor_sha256": self.baseline_security_digest,
                    }
                ]
            },
            {},
        )
        if capture.get("success") is not True or capture.get("dry_run") is True:
            raise WindowsNativeRangeError("the Windows restore point was not captured")

    def _security_roundtrip_diagnostics(self) -> list[dict[str, Any]]:
        """Compare documented APIs on empty, owned files after a native failure."""
        validate_runner_environment()
        import base64
        import ctypes
        from . import restoration as security

        current = self.root.stat(follow_symlinks=False)
        if (
            _is_reparse(self.root)
            or (current.st_dev, current.st_ino) != self.root_identity
            or not _same_path(self.root.parent, self.context.runner_temp)
            or self.baseline_metadata is None
        ):
            raise WindowsNativeRangeError("security diagnostic root is not owned")
        encoded = self.baseline_metadata["windows_security_descriptor"]
        parts = security._windows_security_descriptor_semantics(encoded)
        if not parts[2] & security.WINDOWS_SE_DACL_PRESENT or parts[6] is None:
            raise WindowsNativeRangeError("security diagnostic requires a non-NULL DACL")
        raw = base64.b64decode(encoded, validate=True)
        buffer = ctypes.create_string_buffer(raw, len(raw))
        pointers = [
            ctypes.c_void_p(ctypes.addressof(buffer) + offset) if offset else None
            for offset in (
                int.from_bytes(raw[start:start + 4], "little")
                for start in (4, 8, 16, 12)
            )
        ]
        protection = (
            (0x80000000 if parts[2] & security.WINDOWS_SE_DACL_PROTECTED else 0x20000000)
            | (0x40000000 if parts[2] & security.WINDOWS_SE_SACL_PROTECTED else 0x10000000)
        )
        advapi = ctypes.WinDLL("Advapi32.dll", use_last_error=True)
        set_info = advapi.SetSecurityInfo
        set_info.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32] + [ctypes.c_void_p] * 4
        set_info.restype = ctypes.c_uint32
        set_named = advapi.SetNamedSecurityInfoW
        set_named.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32] + [ctypes.c_void_p] * 4
        set_named.restype = ctypes.c_uint32
        set_file = advapi.SetFileSecurityW
        set_file.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_void_p]
        set_file.restype = ctypes.c_int32
        set_kernel = advapi.SetKernelObjectSecurity
        set_kernel.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p]
        set_kernel.restype = ctypes.c_int32
        cases = (
            ("production_restore", "backup", 0),
            ("handle_sacl_protection", "handle", 0x8 | (protection & 0x50000000)),
            ("handle_backup_protection", "handle", security.WINDOWS_SECURITY_INFORMATION | protection),
            ("named_sacl_protection", "named", 0x8 | (protection & 0x50000000)),
            ("named_protection_only", "named", protection),
            ("file_core_protection", "file", security.WINDOWS_CORE_SECURITY_INFORMATION | protection),
            ("file_backup_protection", "file", security.WINDOWS_SECURITY_INFORMATION | protection),
            ("handle_sacl_protection_delete_pending", "handle", 0x8 | (protection & 0x50000000)),
            ("named_sacl_protection_delete_pending", "named", 0x8 | (protection & 0x50000000)),
            ("file_backup_protection_delete_pending", "file", security.WINDOWS_SECURITY_INFORMATION | protection),
            ("kernel_core_protection", "kernel", security.WINDOWS_CORE_SECURITY_INFORMATION | protection),
            ("kernel_backup_protection", "kernel", security.WINDOWS_SECURITY_INFORMATION | protection),
            ("kernel_core_protection_delete_pending", "kernel", security.WINDOWS_CORE_SECURITY_INFORMATION | protection),
            ("kernel_backup_protection_delete_pending", "kernel", security.WINDOWS_SECURITY_INFORMATION | protection),
        )
        results = []
        native = security._WindowsNativeFileOps()
        with security._windows_privileges("SeBackupPrivilege", "SeRestorePrivilege", "SeSecurityPrivilege"):
            for creation, (name, operation, information) in (
                (creation, case) for creation in ("explicit", "inherited", "ordinary") for case in cases
            ):
                path = self.root / ("security-diagnostic-" + creation + "-" + name + ".tmp")
                row: dict[str, Any] = {"case": name, "creation": creation, "expected_control": f"0x{parts[2]:04x}"}
                with security._windows_pinned_parent(path, native) as (_parent, parent_path, leaf):
                    exact_path = security._windows_child_path(parent_path, leaf)
                    handle = native.open_file(
                        exact_path,
                        security.WINDOWS_GENERIC_WRITE | security.WINDOWS_DELETE
                        | security.WINDOWS_READ_CONTROL | security.WINDOWS_WRITE_DAC
                        | security.WINDOWS_WRITE_OWNER | security.WINDOWS_ACCESS_SYSTEM_SECURITY
                        | security.WINDOWS_FILE_READ_ATTRIBUTES | security.WINDOWS_SYNCHRONIZE,
                        0,
                        security.WINDOWS_CREATE_NEW,
                        security.WINDOWS_FILE_ATTRIBUTE_NORMAL
                        | (security.WINDOWS_FILE_FLAG_BACKUP_SEMANTICS if creation != "ordinary" else 0)
                        | security.WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT,
                        **({"security_descriptor": encoded} if creation == "explicit" else {}),
                    )
                    try:
                        if native.final_path(handle).casefold() != exact_path.casefold():
                            raise WindowsNativeRangeError("security diagnostic path changed")
                        before = security._capture_windows_security_descriptor(path, native_handle=handle)
                        row["before_control"] = f"0x{security._windows_security_descriptor_semantics(before)[2]:04x}"
                        row["before_equivalent"] = security._windows_security_descriptors_equivalent(encoded, before)
                        if name.endswith("delete_pending"):
                            native.set_delete_disposition(handle, True)
                        if operation == "backup":
                            security._restore_windows_security_descriptor(path, encoded, native_handle=handle)
                        elif operation in {"file", "kernel"}:
                            if not (set_file if operation == "file" else set_kernel)(
                                exact_path if operation == "file" else handle,
                                information, ctypes.byref(buffer),
                            ):
                                raise OSError(ctypes.get_last_error(), "file security diagnostic failed")
                        else:
                            result = (set_info if operation == "handle" else set_named)(
                                handle if operation == "handle" else exact_path,
                                1, information, *pointers,
                            )
                            if result:
                                raise OSError(int(result), "component security diagnostic failed")
                        after = security._capture_windows_security_descriptor(path, native_handle=handle)
                        row["after_control"] = f"0x{security._windows_security_descriptor_semantics(after)[2]:04x}"
                        row["equivalent"] = security._windows_security_descriptors_equivalent(encoded, after)
                    except OSError as exc:
                        row["error_code"] = int(getattr(exc, "winerror", None) or exc.errno or 0)
                    finally:
                        try:
                            native.set_delete_disposition(handle, True)
                        finally:
                            native.close(handle)
                row["cleanup_verified"] = not path.exists() and not _is_reparse(path)
                results.append(row)
        return results

    def _collect_payload(self) -> dict[str, Any]:
        payload = collect(
            f"windows-native-{self.context.suffix}",
            authorized_networks=["127.0.0.0/8"],
            integrity_paths=[str(self.config_path)],
            authorized_hosts=["127.0.0.1"],
            excluded_hosts=[],
        ).as_dict()
        payload["sequence"] = self.sequence
        self.sequence += 1
        if payload.get("boot_id") in {None, "", "unknown"}:
            raise WindowsNativeRangeError("the Windows boot identity is unavailable")
        matches = [
            item
            for item in payload.get("integrity", [])
            if _same_path(Path(str(item.get("path", ""))), self.config_path)
        ]
        if len(matches) != 1 or not matches[0].get("security_descriptor_sha256"):
            raise WindowsNativeRangeError("the protected Windows file and ACL were not collected")
        return payload

    def _create_account(self) -> None:
        password = "Sb!" + secrets.token_urlsafe(24) + "9z"
        self.account_created = True
        script = r"""
$secure = ConvertTo-SecureString $env:SENTINEL_BLUE_FIXTURE_PASSWORD -AsPlainText -Force
$user = New-LocalUser -Name $env:SENTINEL_BLUE_FIXTURE_ACCOUNT -Password $secure -Description $env:SENTINEL_BLUE_FIXTURE_DESCRIPTION -AccountNeverExpires -PasswordNeverExpires:$false -ErrorAction Stop
$group = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction Stop
Add-LocalGroupMember -Group $group -Member $user -ErrorAction Stop
Enable-LocalUser -InputObject $user -ErrorAction Stop
[PSCustomObject]@{SID=$user.SID.Value} | ConvertTo-Json -Compress
"""
        result = self._powershell_json(
            script,
            extra_env={
                "SENTINEL_BLUE_FIXTURE_ACCOUNT": self.account_name,
                "SENTINEL_BLUE_FIXTURE_PASSWORD": password,
                "SENTINEL_BLUE_FIXTURE_DESCRIPTION": ACCOUNT_DESCRIPTION,
            },
            label="inert privileged-account fixture creation",
        )
        observed_sid = result.get('SID')
        self.account_sid = observed_sid if isinstance(observed_sid, str) else ''
        state = self._account_state()
        checks = {
            'SID returned': bool(self.account_sid),
            'SID matches': state.get('SID') == self.account_sid,
            'enabled': state.get('Enabled') is True,
            'privileged': state.get('Privileged') is True,
            'marker matches': state.get('Description') == ACCOUNT_DESCRIPTION,
        }
        if not all(checks.values()):
            raise WindowsNativeRangeError('the privileged-account fixture is incomplete: ' +
                                          ', '.join(name for name, passed in checks.items() if not passed))

    def _create_task(self) -> None:
        self.task_created = True
        script = r"""
$execute = Join-Path $env:SystemRoot 'System32\cmd.exe'
$action = New-ScheduledTaskAction -Execute $execute -Argument '/d /c exit 0'
$settings = New-ScheduledTaskSettingsSet -Hidden -ExecutionTimeLimit (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$task = Register-ScheduledTask -TaskName $env:SENTINEL_BLUE_FIXTURE_TASK -TaskPath '\' -Action $action -Settings $settings -Description $env:SENTINEL_BLUE_FIXTURE_DESCRIPTION -User 'SYSTEM' -RunLevel Limited -ErrorAction Stop
Disable-ScheduledTask -InputObject $task -ErrorAction Stop | Out-Null
"""
        self._powershell(
            script,
            extra_env={
                "SENTINEL_BLUE_FIXTURE_TASK": self.task_name,
                "SENTINEL_BLUE_FIXTURE_DESCRIPTION": TASK_DESCRIPTION,
            },
            label="inert scheduled-task fixture creation",
        )
        state = self._task_state()
        if (
            state.get("Exists") is not True
            or state.get("Description") != TASK_DESCRIPTION
            or str(state.get("State", "")).casefold() != "disabled"
        ):
            raise WindowsNativeRangeError("the scheduled-task fixture is incomplete")

    def _create_run_value(self) -> None:
        self.run_value_created = True
        script = r"""
New-ItemProperty `
  -LiteralPath $env:SENTINEL_BLUE_FIXTURE_RUN_KEY `
  -Name $env:SENTINEL_BLUE_FIXTURE_RUN_NAME `
  -Value $env:SENTINEL_BLUE_FIXTURE_RUN_VALUE `
  -PropertyType String `
  -ErrorAction Stop | Out-Null
"""
        self._powershell(
            script,
            extra_env={
                "SENTINEL_BLUE_FIXTURE_RUN_KEY": RUN_KEY_PATH,
                "SENTINEL_BLUE_FIXTURE_RUN_NAME": self.run_value_name,
                "SENTINEL_BLUE_FIXTURE_RUN_VALUE": self.run_value_data,
            },
            label="inert Registry Run-value fixture creation",
        )
        state = self._run_value_state()
        if (
            state.get("Exists") is not True
            or str(state.get("Kind", "")) != "String"
            or str(state.get("Value", "")) != self.run_value_data
        ):
            raise WindowsNativeRangeError("the Registry Run-value fixture is incomplete")

    def _create_process(self) -> None:
        source = Path(os.environ["SystemRoot"]) / "System32" / "cscript.exe"
        if not source.is_file():
            raise WindowsNativeRangeError("the trusted Windows script host is unavailable")
        expected_digest = hashlib.sha256(source.read_bytes()).hexdigest()
        shutil.copy2(source, self.process_path)
        if hashlib.sha256(self.process_path.read_bytes()).hexdigest() != expected_digest:
            raise WindowsNativeRangeError("the trusted temporary process copy changed")
        self.process_digest = expected_digest
        self.heartbeat_script_path.write_text(
            "Option Explicit\n"
            "Dim shell, fso, target, i, handle\n"
            'Set shell = CreateObject("WScript.Shell")\n'
            'Set fso = CreateObject("Scripting.FileSystemObject")\n'
            'target = shell.ExpandEnvironmentStrings("%SENTINEL_BLUE_HEARTBEAT%")\n'
            "For i = 1 To 4500\n"
            "  Set handle = fso.CreateTextFile(target, True)\n"
            "  handle.Write CStr(i)\n"
            "  handle.Close\n"
            "  WScript.Sleep 200\n"
            "Next\n",
            encoding="ascii",
        )
        environment = os.environ.copy()
        environment["SENTINEL_BLUE_HEARTBEAT"] = str(self.heartbeat_path)
        self.inert_process = subprocess.Popen(
            [
                str(self.process_path),
                "//B",
                "//NoLogo",
                "//T:900",
                str(self.heartbeat_script_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        self.process_created = True
        self._wait_for_heartbeat_change(None, timeout=12.0)
        if self.inert_process.poll() is not None:
            raise WindowsNativeRangeError("the inert temporary process exited prematurely")

    def _create_firewall_rule(self) -> None:
        self.firewall_created = True
        script = r"""
New-NetFirewallRule `
  -Name $env:SENTINEL_BLUE_FIXTURE_FIREWALL `
  -DisplayName $env:SENTINEL_BLUE_FIXTURE_FIREWALL `
  -Description $env:SENTINEL_BLUE_FIXTURE_DESCRIPTION `
  -Enabled False `
  -Direction Outbound `
  -Action Block `
  -RemoteAddress 127.0.0.1 `
  -Program $env:SENTINEL_BLUE_FIXTURE_PROGRAM `
  -ErrorAction Stop | Out-Null
"""
        self._powershell(
            script,
            extra_env={
                "SENTINEL_BLUE_FIXTURE_FIREWALL": self.firewall_name,
                "SENTINEL_BLUE_FIXTURE_DESCRIPTION": self.firewall_description,
                "SENTINEL_BLUE_FIXTURE_PROGRAM": str(self.process_path),
            },
            label="disabled loopback firewall-rule fixture creation",
        )
        if not self._firewall_identity_matches(self._firewall_state()):
            raise WindowsNativeRangeError("the disabled firewall-rule fixture is incomplete")

    def _create_listener(self) -> None:
        self.listener = ThreadingHTTPServer(("127.0.0.1", 0), _InertHandler)
        self.listener.daemon_threads = True
        self.listener_thread = threading.Thread(
            target=self.listener.serve_forever,
            name="sentinel-blue-windows-inert-loopback-listener",
            daemon=True,
        )
        self.listener_thread.start()

    def _tamper_file(self) -> tuple[bytes, dict[str, Any]]:
        self.config_path.write_bytes(TAMPERED_CONTENT)
        self._command(
            ["icacls.exe", str(self.config_path), "/grant", "*S-1-1-0:(R)"],
            label="run-scoped NTFS ACL tamper",
        )
        assert self.executor is not None
        data, metadata = self.executor.restore_points._read_target(self.config_path)
        security_digest = self.executor.restore_points._metadata_security_descriptor_sha256(
            metadata
        )
        if data != TAMPERED_CONTENT or security_digest == self.baseline_security_digest:
            raise WindowsNativeRangeError("the inert content-and-ACL tamper did not take effect")
        return data, metadata

    def _create_attack_wave(self) -> tuple[bytes, dict[str, Any]]:
        self._create_account()
        self._create_task()
        self._create_run_value()
        self._create_process()
        self._create_firewall_rule()
        self._create_listener()
        return self._tamper_file()

    @staticmethod
    def _candidate(
        candidates: list[Any], kind: str, predicate: Callable[[Any], bool]
    ) -> Any:
        matches = [item for item in candidates if item.kind == kind and predicate(item)]
        if len(matches) != 1:
            raise WindowsNativeRangeError(
                f"expected exactly one run-owned {kind!r} detection, observed {len(matches)}"
            )
        return matches[0]

    @staticmethod
    def _record(
        name: str,
        candidate: Any,
        response_action: str,
        result: dict[str, Any],
        detection_started: float,
        detected_at: float,
        **assertions: bool,
    ) -> dict[str, Any]:
        if result.get("success") is not True or result.get("dry_run") is True:
            raise WindowsNativeRangeError(f"{name} response failed or ran as a dry run")
        if not assertions or not all(assertions.values()):
            failed = sorted(key for key, value in assertions.items() if not value)
            raise WindowsNativeRangeError(
                f"scenario {name!r} failed assertions: {', '.join(failed)}"
            )
        return {
            "name": name,
            "expected_alert": candidate.kind,
            "detected": True,
            "detection_latency_ms": round((detected_at - detection_started) * 1000, 2),
            "response_action": response_action,
            "response_automated": False,
            "response_latency_ms": round((time.perf_counter() - detected_at) * 1000, 2),
            "response_success": True,
            "non_dry_run": True,
            "assertions": dict(sorted(assertions.items())),
        }

    def _account_scenario(
        self, candidate: Any, attacked: dict[str, Any], started: float, detected: float,
        protected_accounts: set[str],
    ) -> dict[str, Any]:
        assert self.executor is not None
        result = self.executor.execute("snapshot", {}, attacked)
        matches_account = lambda item: str(item.evidence.get('account', {}).get('name', '')).casefold() == self.account_name.casefold()
        existing = self._candidate(detect(attacked, attacked, protected_accounts, RiskModel()),
                                   'unverified_privileged_account', matches_account)
        self._disable_account_exact()
        disabled = self._collect_payload()
        disabled_candidate = self._candidate(detect(disabled, attacked, protected_accounts, RiskModel()),
                                             'unverified_privileged_account', matches_account)
        disabled_snapshot = self.executor.execute('snapshot', {}, disabled)
        if disabled_snapshot.get('success') is not True:
            raise WindowsNativeRangeError('disabled privileged-account evidence was not preserved')
        self._delete_account_exact()
        return self._record(
            "enabled_unapproved_local_administrator",
            candidate,
            "snapshot",
            result,
            started,
            detected,
            exact_account_detected=(
                str(candidate.evidence.get("account", {}).get("name", "")).casefold()
                == self.account_name.casefold()
            ),
            evidence_snapshot_created=True,
            present_in_baseline_still_detected=existing.evidence.get('new_since_baseline') is False,
            disabled_baseline_account_still_detected=(
                disabled_candidate.evidence.get('new_since_baseline') is False
                and disabled_candidate.evidence.get('account', {}).get('enabled') is False
                and disabled_candidate.evidence.get('account', {}).get('account_id') == existing.evidence.get('account', {}).get('account_id')
            ),
            account_removed=not self._account_state().get("Exists"),
        )

    def _task_scenario(
        self, candidate: Any, attacked: dict[str, Any], started: float, detected: float
    ) -> dict[str, Any]:
        assert self.executor is not None
        result = self.executor.execute("snapshot", {}, attacked)
        self._delete_task_exact()
        persistence = candidate.evidence.get("persistence", {})
        return self._record(
            "disabled_inert_hidden_scheduled_task",
            candidate,
            "snapshot",
            result,
            started,
            detected,
            exact_task_detected=(
                str(persistence.get("name", "")).casefold()
                == ("\\" + self.task_name).casefold()
            ),
            evidence_snapshot_created=True,
            task_never_executed=True,
            task_removed=not self._task_state().get("Exists"),
        )

    def _run_value_scenario(
        self, candidate: Any, attacked: dict[str, Any], started: float, detected: float
    ) -> dict[str, Any]:
        assert self.executor is not None
        state = self._run_value_state()
        result = self.executor.execute("snapshot", {}, attacked)
        self._delete_run_value_exact()
        persistence = candidate.evidence.get("persistence", {})
        expected_name = f"{RUN_KEY_LABEL}\\{self.run_value_name}"
        return self._record(
            "inert_machine_registry_run_persistence",
            candidate,
            "snapshot_then_exact_value_removal",
            result,
            started,
            detected,
            exact_value_detected=(
                str(persistence.get("kind", "")) == "registry-run"
                and str(persistence.get("name", "")).casefold()
                == expected_name.casefold()
            ),
            content_fingerprint_present=bool(persistence.get("sha256")),
            inert_exit_only=str(state.get("Value", "")) == self.run_value_data,
            value_never_executed=True,
            evidence_snapshot_created=True,
            value_removed=not self._run_value_state().get("Exists"),
        )

    def _listener_scenario(
        self, candidate: Any, attacked: dict[str, Any], started: float, detected: float
    ) -> dict[str, Any]:
        assert self.executor is not None
        result = self.executor.execute("observe", {}, attacked)
        listener = candidate.evidence.get("listener", {})
        assert self.listener is not None
        port = int(self.listener.server_address[1])
        self.listener.shutdown()
        self.listener.server_close()
        self.listener = None
        assert self.listener_thread is not None
        self.listener_thread.join(timeout=5)
        stopped = not self.listener_thread.is_alive()
        self.listener_thread = None
        return self._record(
            "unexpected_loopback_listener",
            candidate,
            "observe",
            result,
            started,
            detected,
            exact_listener_detected=int(listener.get("port", 0)) == port,
            bound_only_to_loopback=str(listener.get("address", "")) in {
                "127.0.0.1",
                "127.0.0.0",
            },
            listener_removed=stopped,
            no_automatic_network_change=True,
        )

    def _firewall_scenario(
        self,
        candidate: Any,
        baseline: dict[str, Any],
        attacked: dict[str, Any],
        started: float,
        detected: float,
    ) -> dict[str, Any]:
        assert self.executor is not None
        state = self._firewall_state()
        result = self.executor.execute("snapshot", {}, attacked)
        baseline_hash = str(baseline.get("firewall", {}).get("rules_sha256", ""))
        attacked_hash = str(attacked.get("firewall", {}).get("rules_sha256", ""))
        evidence = candidate.evidence
        self._delete_firewall_rule_exact()
        restored = self._collect_payload()
        restored_hash = str(restored.get("firewall", {}).get("rules_sha256", ""))
        return self._record(
            "disabled_loopback_firewall_rule_drift",
            candidate,
            "snapshot_then_exact_rule_removal",
            result,
            started,
            detected,
            ruleset_drift_detected=(
                bool(baseline_hash)
                and bool(attacked_hash)
                and baseline_hash != attacked_hash
                and str(evidence.get("baseline", {}).get("rules_sha256", ""))
                == baseline_hash
                and str(evidence.get("current", {}).get("rules_sha256", ""))
                == attacked_hash
            ),
            rule_never_enabled=str(state.get("Enabled", "")).casefold() == "false",
            outbound_block_only=(
                str(state.get("Direction", "")).casefold() == "outbound"
                and str(state.get("Action", "")).casefold() == "block"
            ),
            loopback_remote_scope=self._remote_addresses(state)
            in (["127.0.0.1"], ["127.0.0.1/32"]),
            exact_program_bound=ntpath.normcase(
                ntpath.normpath(str(state.get("Program", "")))
            )
            == ntpath.normcase(ntpath.normpath(str(self.process_path))),
            evidence_snapshot_created=True,
            rule_removed=not self._firewall_state().get("Exists"),
            ruleset_restored=bool(restored_hash) and restored_hash == baseline_hash,
        )

    def _heartbeat(self) -> int | None:
        try:
            raw = self.heartbeat_path.read_text(encoding="ascii").strip()
            return int(raw) if raw.isdigit() else None
        except OSError:
            return None

    def _wait_for_heartbeat_change(
        self, previous: int | None, *, timeout: float = 8.0
    ) -> int:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            current = self._heartbeat()
            if current is not None and current != previous:
                return current
            time.sleep(0.1)
        raise WindowsNativeRangeError("the inert process heartbeat did not advance")

    @staticmethod
    def _session_telemetry(
        process_id: int,
        identity: dict[str, Any],
        *,
        sequence: int,
    ) -> dict[str, Any]:
        now = time.time()
        return {
            "agent_id": "windows-native-process-agent",
            "hostname": socket.gethostname(),
            "platform": "Windows native lab",
            "observed_at": now,
            "queued_at": now,
            "boot_id": identity["boot_id"],
            "sequence": sequence,
            "sessions": [
                {
                    "username": os.environ.get("USERNAME", "runner"),
                    "source": "local",
                    "session_id": identity["kernel_session_id"],
                    "process_id": process_id,
                    "privileged": True,
                    "interactive": True,
                    "process_identity": identity,
                }
            ],
        }

    @staticmethod
    def _session_parameters(telemetry: dict[str, Any]) -> dict[str, Any]:
        return {
            "session": dict(telemetry["sessions"][0]),
            "observation": {
                "boot_id": telemetry["boot_id"],
                "sequence": telemetry["sequence"],
                "payload_sha256": telemetry_observation_sha256(telemetry),
            },
        }

    def _process_scenario(
        self, candidate: Any, attacked: dict[str, Any], started: float, detected: float
    ) -> dict[str, Any]:
        assert self.executor is not None
        assert self.inert_process is not None
        snapshot = self.executor.execute("snapshot", {}, attacked)
        if snapshot.get("success") is not True:
            raise WindowsNativeRangeError("temporary-process evidence snapshot failed")
        process_id = self.inert_process.pid
        identity = inspect_process_identity(process_id, boot_id=str(attacked["boot_id"]))

        before_forgery = self._heartbeat()
        forged = dict(identity)
        forged["start_time"] = str(int(forged["start_time"]) + 1)
        forged_telemetry = self._session_telemetry(
            process_id, forged, sequence=100
        )
        refused = self.executor.execute(
            "quarantine_session",
            self._session_parameters(forged_telemetry),
            forged_telemetry,
        )
        forged_did_not_stop = (
            self._wait_for_heartbeat_change(before_forgery, timeout=5.0) is not None
        )

        exact_telemetry = self._session_telemetry(
            process_id, identity, sequence=101
        )
        quarantine = self.executor.execute(
            "quarantine_session",
            self._session_parameters(exact_telemetry),
            exact_telemetry,
        )
        if quarantine.get("success") is not True or quarantine.get("dry_run") is True:
            raise WindowsNativeRangeError("exact Windows process quarantine failed")
        time.sleep(1.4)
        suspended_first = self._heartbeat()
        time.sleep(1.4)
        suspended_second = self._heartbeat()

        release_telemetry = self._session_telemetry(
            process_id, identity, sequence=102
        )
        release = self.executor.execute(
            "release_quarantine",
            self._session_parameters(release_telemetry),
            release_telemetry,
        )
        resumed = self._wait_for_heartbeat_change(suspended_second, timeout=8.0)
        process = candidate.evidence.get("process", {})
        record = self._record(
            "temporary_privileged_process_identity_containment",
            candidate,
            "quarantine_session_then_release",
            release,
            started,
            detected,
            exact_process_detected=_same_path(
                Path(str(process.get("path", ""))), self.process_path
            ),
            evidence_snapshot_created=True,
            forged_identity_refused=(
                refused.get("success") is False
                and refused.get("review_required") is True
            ),
            forged_identity_did_not_signal=forged_did_not_stop,
            exact_process_suspended=(
                suspended_first is not None and suspended_first == suspended_second
            ),
            exact_process_resumed=resumed != suspended_second,
            release_record_removed=not self.executor._read_quarantine(),
        )
        self.inert_process.kill()
        self.inert_process.wait(timeout=5)
        self.inert_process = None
        self.process_created = False
        self._delete_process_file_exact()
        if self.heartbeat_path.exists():
            self.heartbeat_path.unlink()
        return record

    def _file_scenario(
        self,
        candidate: Any,
        attacked: dict[str, Any],
        tampered_data: bytes,
        tampered_metadata: dict[str, Any],
        started: float,
        detected: float,
    ) -> dict[str, Any]:
        assert self.executor is not None
        assert self.baseline_metadata is not None
        observed_digest = hashlib.sha256(tampered_data).hexdigest()
        observed_security = (
            self.executor.restore_points._metadata_security_descriptor_sha256(
                tampered_metadata
            )
        )
        parameters = {
            "path": str(self.config_path),
            "baseline_sha256": self.baseline_digest,
            "observed_sha256": observed_digest,
            "baseline_security_descriptor_sha256": self.baseline_security_digest,
            "observed_security_descriptor_sha256": observed_security,
            "observed_missing": False,
        }
        restored = self.executor.execute("restore_integrity", parameters, attacked)
        if restored.get("success") is not True or restored.get("dry_run") is True:
            raise self._action_failure("Windows content-and-ACL restoration failed", restored)
        approved_data, approved_meta = self.executor.restore_points._read_target(
            self.config_path
        )
        approved = (
            approved_data == APPROVED_CONTENT
            and self.executor.restore_points._metadata_matches(
                self.baseline_metadata, approved_meta
            )
        )
        rollback = self.executor.execute(
            "rollback_integrity", restored["pre_state"], attacked
        )
        if rollback.get("success") is not True or rollback.get("dry_run") is True:
            raise self._action_failure("Windows restoration rollback failed", rollback)
        rolled_data, rolled_meta = self.executor.restore_points._read_target(
            self.config_path
        )
        rolled_back = (
            rolled_data == tampered_data
            and self.executor.restore_points._metadata_matches(
                tampered_metadata, rolled_meta
            )
        )
        final = self.executor.execute("restore_integrity", parameters, attacked)
        final_data, final_meta = self.executor.restore_points._read_target(
            self.config_path
        )
        return self._record(
            "ntfs_content_acl_restore_rollback_restore",
            candidate,
            "restore_integrity",
            final,
            started,
            detected,
            content_and_acl_drift_detected=set(
                candidate.evidence.get("change_types", [])
            )
            == {"content", "security_metadata"},
            first_restoration_committed=approved,
            evidence_preserved=restored.get("evidence_preserved") is True,
            operator_rollback_exact=rolled_back,
            final_approved_bytes=final_data == APPROVED_CONTENT,
            final_approved_acl=self.executor.restore_points._metadata_matches(
                self.baseline_metadata, final_meta
            ),
        )

    def _reparse_scenario(self) -> dict[str, Any]:
        assert self.executor is not None
        started = time.perf_counter()
        os.symlink(self.config_path, self.link_path, target_is_directory=False)
        self.link_created = True
        result = self.executor.execute(
            "capture_restore_point",
            {
                "files": [
                    {
                        "path": str(self.link_path),
                        "sha256": self.baseline_digest,
                        "security_descriptor_sha256": self.baseline_security_digest,
                    }
                ]
            },
            {},
        )
        rejected = result.get("rejected", [])
        reason = str(rejected[0].get("reason", "")) if len(rejected) == 1 else ""
        if not self.link_path.is_symlink() and not _is_reparse(self.link_path):
            raise WindowsNativeRangeError("the reparse-point fixture was not created")
        self.link_path.unlink()
        self.link_created = False
        assertions = {
            "reparse_capture_refused": result.get("success") is False,
            "reparse_reason_recorded": "reparse" in reason.casefold(),
            "approved_target_unchanged": self.config_path.read_bytes() == APPROVED_CONTENT,
            "link_removed": not self.link_path.exists() and not _is_reparse(self.link_path),
        }
        if not all(assertions.values()):
            failed = sorted(key for key, value in assertions.items() if not value)
            raise WindowsNativeRangeError(
                "reparse substitution scenario failed assertions: " + ", ".join(failed)
            )
        return {
            "name": "ntfs_reparse_point_substitution",
            "expected_alert": "restore_point_reparse_refusal",
            "detected": True,
            "detection_latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "response_action": "refuse_capture",
            "response_automated": True,
            "response_latency_ms": 0.0,
            "response_success": True,
            "non_dry_run": True,
            "assertions": dict(sorted(assertions.items())),
        }

    def campaign(self) -> dict[str, Any]:
        if self.executor is None:
            raise WindowsNativeRangeError("Windows native lab setup did not complete")
        baseline = self._collect_payload()
        baseline_integrity = next(
            item
            for item in baseline["integrity"]
            if _same_path(Path(str(item.get("path", ""))), self.config_path)
        )
        if (
            baseline_integrity.get("sha256") != self.baseline_digest
            or baseline_integrity.get("security_descriptor_sha256")
            != self.baseline_security_digest
        ):
            raise WindowsNativeRangeError("collector baseline differs from the restore point")
        protected_accounts = {
            str(item.get("name", "")).casefold()
            for item in baseline.get("accounts", [])
            if item.get("privileged")
        }
        started = time.perf_counter()
        tampered_data, tampered_metadata = self._create_attack_wave()
        attacked = self._collect_payload()
        candidates = detect(attacked, baseline, protected_accounts, RiskModel())
        detected = time.perf_counter()

        account = self._candidate(
            candidates,
            "unverified_privileged_account",
            lambda item: str(
                item.evidence.get("account", {}).get("name", "")
            ).casefold()
            == self.account_name.casefold(),
        )
        task = self._candidate(
            candidates,
            "new_persistence_item",
            lambda item: str(
                item.evidence.get("persistence", {}).get("name", "")
            ).casefold()
            == ("\\" + self.task_name).casefold(),
        )
        run_value_name = f"{RUN_KEY_LABEL}\\{self.run_value_name}"
        run_value = self._candidate(
            candidates,
            "new_persistence_item",
            lambda item: (
                str(item.evidence.get("persistence", {}).get("kind", ""))
                == "registry-run"
                and str(
                    item.evidence.get("persistence", {}).get("name", "")
                ).casefold()
                == run_value_name.casefold()
            ),
        )
        process = self._candidate(
            candidates,
            "privileged_temporary_process",
            lambda item: _same_path(
                Path(str(item.evidence.get("process", {}).get("path", ""))),
                self.process_path,
            ),
        )
        firewall = self._candidate(
            candidates,
            "host_firewall_rules_changed",
            lambda item: (
                str(item.evidence.get("baseline", {}).get("rules_sha256", ""))
                == str(baseline.get("firewall", {}).get("rules_sha256", ""))
                and str(item.evidence.get("current", {}).get("rules_sha256", ""))
                == str(attacked.get("firewall", {}).get("rules_sha256", ""))
            ),
        )
        assert self.listener is not None
        listener_port = int(self.listener.server_address[1])
        listener = self._candidate(
            candidates,
            "new_network_listener",
            lambda item: int(item.evidence.get("listener", {}).get("port", 0))
            == listener_port,
        )
        file_change = self._candidate(
            candidates,
            "critical_file_changed",
            lambda item: _same_path(
                Path(str(item.evidence.get("path", ""))), self.config_path
            ),
        )

        scenarios = self.completed_scenarios
        for operation in (
            lambda: self._account_scenario(account, attacked, started, detected, protected_accounts),
            lambda: self._task_scenario(task, attacked, started, detected),
            lambda: self._run_value_scenario(run_value, attacked, started, detected),
            lambda: self._listener_scenario(listener, attacked, started, detected),
            lambda: self._firewall_scenario(
                firewall, baseline, attacked, started, detected
            ),
            lambda: self._process_scenario(process, attacked, started, detected),
            lambda: self._file_scenario(
                file_change,
                attacked,
                tampered_data,
                tampered_metadata,
                started,
                detected,
            ),
            self._reparse_scenario,
        ):
            scenarios.append(operation())
        return {
            "schema_version": 1,
            "status": "passed",
            "mode": "native changes on one disposable GitHub-hosted Windows runner",
            "version": __version__,
            "repository": self.context.repository,
            "commit": os.environ.get("GITHUB_SHA", "")[:40],
            "scope": {
                "authorized_networks": ["127.0.0.0/8"],
                "authorized_hosts": ["127.0.0.1"],
                "external_targets_contacted": 0,
                "public_listeners_created": 0,
                "enabled_firewall_rules_created": 0,
            },
            "safety": {
                "destructive_payloads": False,
                "credential_collection": False,
                "input_collection": False,
                "real_malware": False,
                "inert_emulations_only": True,
                "disposable_runner_gate": True,
                "startup_fixture_executed": False,
            },
            "baseline": {
                "boot_identity_available": True,
                "windows_acl_fingerprint_available": True,
                "collector_error_count": len(baseline.get("collector_errors", [])),
                "restore_point_captured": True,
            },
            "attack_observation": {
                "collector_error_count": len(attacked.get("collector_errors", [])),
                "expected_detections": 7,
                "expected_detections_observed": 7,
            },
            "scenarios": scenarios,
            "scenario_count": len(scenarios),
            "scenarios_passed": sum(
                1 for scenario in scenarios if scenario["response_success"]
            ),
            "limitations": [
                "single-host disposable runner; not an unseen competition network",
                "inert account, task, Registry Run value, disabled firewall rule, process, listener, file, ACL, and reparse emulations",
                "event-specific rules and service manifests remain required before deployment",
            ],
        }

    def _stop_process(self) -> None:
        if self.inert_process is None:
            return
        if self.inert_process.poll() is None:
            self.inert_process.kill()
            self.inert_process.wait(timeout=5)
        self.inert_process = None
        self.process_created = False

    def _delete_process_file_exact(self) -> None:
        if not self.process_path.exists() and not _is_reparse(self.process_path):
            self.process_digest = ""
            return
        if _is_reparse(self.process_path):
            raise WindowsNativeRangeError("refused changed temporary executable")
        observed = hashlib.sha256(self.process_path.read_bytes()).hexdigest()
        if not self.process_digest or observed != self.process_digest:
            raise WindowsNativeRangeError("refused changed temporary executable")
        self.process_path.unlink()
        self.process_digest = ""

    def _restore_config_if_needed(self) -> None:
        if (
            self.executor is None
            or self.baseline_metadata is None
            or not self.config_path.exists()
            or _is_reparse(self.config_path)
        ):
            return
        current_data, current_meta = self.executor.restore_points._read_target(
            self.config_path
        )
        if current_data == APPROVED_CONTENT and self.executor.restore_points._metadata_matches(
            self.baseline_metadata, current_meta
        ):
            return
        result = self.executor.execute(
            "restore_integrity",
            {
                "path": str(self.config_path),
                "baseline_sha256": self.baseline_digest,
                "observed_sha256": hashlib.sha256(current_data).hexdigest(),
                "baseline_security_descriptor_sha256": self.baseline_security_digest,
                "observed_security_descriptor_sha256": (
                    self.executor.restore_points._metadata_security_descriptor_sha256(
                        current_meta
                    )
                ),
                "observed_missing": False,
            },
            {},
        )
        if result.get("success") is not True:
            raise self._action_failure("cleanup could not restore the protected file", result)

    def cleanup(self) -> dict[str, Any]:
        errors: list[str] = []

        def attempt(label: str, operation: Callable[[], Any]) -> None:
            try:
                operation()
            except Exception as exc:  # cleanup must continue through every exact resource
                errors.append(f"{label}: {type(exc).__name__}: {str(exc)[:200]}")

        attempt("temporary process", self._stop_process)
        if self.listener is not None:
            attempt("loopback listener shutdown", self.listener.shutdown)
            attempt("loopback listener close", self.listener.server_close)
            self.listener = None
        if self.listener_thread is not None:
            self.listener_thread.join(timeout=5)
            if self.listener_thread.is_alive():
                errors.append("loopback listener thread did not stop")
            self.listener_thread = None
        # Flags are set before each native creation call, so partial creation is
        # still cleaned. Setup refusals must never claim a pre-existing fixture.
        resources = (
            (self.firewall_created, "disabled firewall rule", self._delete_firewall_rule_exact, self._firewall_state),
            (self.run_value_created, "Registry Run value", self._delete_run_value_exact, self._run_value_state),
            (self.account_created, "privileged account", self._delete_account_exact, self._account_state),
            (self.task_created, "scheduled task", self._delete_task_exact, self._task_state),
        )
        resource_absence: list[bool] = []
        for attempted, label, remove, inspect in resources:
            if not attempted:
                continue
            attempt(label, remove)
            try:
                resource_absence.append(not inspect().get("Exists"))
            except Exception as exc:
                errors.append(f"{label} verification: {type(exc).__name__}: {str(exc)[:200]}")
                resource_absence.append(False)

        # The executable remains owned after the child stops, including a
        # failed Popen. The digest is cleared only after file cleanup.
        process_attempted = bool(self.process_digest)
        if process_attempted:
            attempt("temporary executable", self._delete_process_file_exact)
        root_absent = self.root_identity is None
        if self.root_identity is not None:
            try:
                root_stat = self.root.stat(follow_symlinks=False)
                if (
                    not _same_path(self.root.parent, self.context.runner_temp)
                    or _is_reparse(self.root)
                    or (root_stat.st_dev, root_stat.st_ino) != self.root_identity
                ):
                    raise WindowsNativeRangeError("refused replaced Windows cleanup root")
                if self.link_created:
                    if not _is_reparse(self.link_path):
                        raise WindowsNativeRangeError("refused changed reparse fixture")
                    attempt("reparse fixture", self.link_path.unlink)
                    self.link_created = False
                attempt("protected file restoration", self._restore_config_if_needed)
                # Re-check after restoration, before recursive cleanup.
                current = self.root.stat(follow_symlinks=False)
                if _is_reparse(self.root) or (current.st_dev, current.st_ino) != self.root_identity:
                    raise WindowsNativeRangeError("refused replaced Windows cleanup root")
                attempt("Windows lab root", lambda: shutil.rmtree(self.root))
                root_absent = not self.root.exists() and not _is_reparse(self.root)
            except FileNotFoundError:
                root_absent = not self.root.exists() and not _is_reparse(self.root)
            except Exception as exc:
                errors.append(f"Windows lab root: {type(exc).__name__}: {str(exc)[:200]}")
        verified = (
            not errors
            and all(resource_absence)
            and root_absent
            and (not process_attempted or (not self.process_path.exists() and not _is_reparse(self.process_path)))
            and self.inert_process is None
            and self.listener is None
            and self.listener_thread is None
        )
        return {"verified": verified, "errors": errors}


def campaign(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    context = validate_runner_environment(environ)
    lab = WindowsNativeRunnerLab(context)
    try:
        lab.setup()
        report = lab.campaign()
    except Exception as exc:
        report = {
            "schema_version": 1,
            "status": "failed",
            "mode": "native changes on one disposable GitHub-hosted Windows runner",
            "version": __version__,
            "repository": context.repository,
            "commit": os.environ.get("GITHUB_SHA", "")[:40],
            "scenarios": lab.completed_scenarios,
            "scenario_count": 8,
            "scenarios_passed": len(lab.completed_scenarios),
            "error": f"{type(exc).__name__}: {str(exc)[:500]}",
        }
        if "post-restoration Windows security descriptor did not match" in str(exc):
            try:
                report["security_diagnostics"] = lab._security_roundtrip_diagnostics()
            except Exception as diagnostic_error:
                report["security_diagnostics"] = {"error_type": type(diagnostic_error).__name__}
    cleanup = lab.cleanup()
    report["cleanup"] = cleanup
    if not cleanup["verified"]:
        report["status"] = "failed"
    return report


def _report_path(context: WindowsRunnerContext, requested: str | None) -> Path:
    destination = Path(requested) if requested else context.workspace / REPORT_NAME
    if not destination.is_absolute():
        destination = context.workspace / destination
    try:
        resolved_parent = destination.parent.resolve(strict=True)
    except OSError as exc:
        raise WindowsNativeRangeError("Windows native report parent is unavailable") from exc
    if not _same_path(resolved_parent, context.workspace) or destination.name != REPORT_NAME:
        raise WindowsNativeRangeError(
            f"Windows native report must be GITHUB_WORKSPACE/{REPORT_NAME}"
        )
    if destination.exists() or _is_reparse(destination):
        raise WindowsNativeRangeError("Windows native report destination already exists")
    return destination


def run(args: Any) -> int:
    context = validate_runner_environment()
    destination = _report_path(context, getattr(args, "output", None))
    report = campaign()
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    destination.write_text(encoded, encoding="utf-8")
    if getattr(args, "json", False):
        print(encoded, end="")
    else:
        print(
            "Sentinel Blue Windows native disposable range: "
            f"{report['status']} ({report.get('scenarios_passed', 0)}/"
            f"{report.get('scenario_count', 0)} scenarios)"
        )
        print(f"Report: {destination}")
    return 0 if report.get("status") == "passed" else 1


__all__ = [
    "CONFIRMATION",
    "WindowsNativeRangeError",
    "WindowsNativeRunnerLab",
    "WindowsRunnerContext",
    "campaign",
    "run",
    "validate_runner_environment",
]
