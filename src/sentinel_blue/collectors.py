"""Dependency-free host telemetry collectors for Linux and Windows."""

from __future__ import annotations

import json
import hashlib
import os
import platform
import re
import socket
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

try:
    import pwd
except ImportError:  # pragma: no cover - Windows does not provide pwd
    pwd = None  # type: ignore[assignment]

try:
    import grp
except ImportError:  # pragma: no cover - Windows does not provide grp
    grp = None  # type: ignore[assignment]

from .protocol import (
    Account,
    FirewallState,
    IntegrityItem,
    Interface,
    Listener,
    Neighbor,
    PersistenceItem,
    ProcessObservation,
    Route,
    SecurityEvent,
    Service,
    Session,
    Telemetry,
)
from .process_identity import inspect_process_identity

MAX_WINDOWS_INTEGRITY_FILE_BYTES = 32 * 1024 * 1024


def _run(command: list[str], timeout: float = 8.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def _linux_accounts() -> list[Account]:
    if pwd is None:
        return []
    privileged_names: set[str] = set()
    for group in ("sudo", "wheel", "admin"):
        try:
            result = _run(["getent", "group", group])
        except OSError:
            break
        if result.returncode == 0 and result.stdout.strip():
            fields = result.stdout.strip().split(":")
            if len(fields) >= 4:
                privileged_names.update(name for name in fields[3].split(",") if name)
    accounts: list[Account] = []
    try:
        group_entries = grp.getgrall() if grp is not None else []
    except OSError:
        group_entries = []
    for entry in pwd.getpwall():
        disabled_shell = entry.pw_shell.endswith(("/false", "/nologin"))
        groups: list[str] = []
        groups = sorted(
            {
                item.gr_name
                for item in group_entries
                if entry.pw_name in item.gr_mem or item.gr_gid == entry.pw_gid
            }
        )
        accounts.append(
            Account(
                name=entry.pw_name,
                account_id=str(entry.pw_uid),
                privileged=entry.pw_uid == 0 or entry.pw_name in privileged_names,
                enabled=not disabled_shell,
                source="local",
                groups=groups,
            )
        )
    return accounts


def _linux_sessions(privileged: set[str], errors: list[str] | None = None) -> list[Session]:
    result = _run(["who", "-u"])
    if result.returncode != 0:
        return []
    sessions: list[Session] = []
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        username = parts[0]
        source = "local"
        if parts[-1].startswith("(") and parts[-1].endswith(")"):
            source = parts[-1][1:-1]
        process_id = None
        for value in parts[4:]:
            if value.isdigit():
                process_id = int(value)
                break
        process_identity = None
        if process_id is not None:
            try:
                process_identity = inspect_process_identity(
                    process_id, boot_id=_boot_id("linux")
                )
            except (OSError, PermissionError, RuntimeError, ValueError) as exc:
                if errors is not None:
                    errors.append(
                        f"session process identity unavailable for PID {process_id}: {exc}"
                    )
        sessions.append(
            Session(
                username=username,
                source=source,
                session_id=parts[1],
                process_id=process_id,
                privileged=username.casefold() in privileged,
                process_identity=process_identity,
            )
        )
    return sessions


def _linux_services(errors: list[str]) -> list[Service]:
    result = _run(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--no-pager",
            "--plain",
            "--full",
        ],
        timeout=15,
    )
    if result.returncode != 0:
        errors.append("systemctl service inventory unavailable")
        return []
    start_modes: dict[str, str] = {}
    try:
        unit_files = _run(
            [
                "systemctl",
                "list-unit-files",
                "--type=service",
                "--no-legend",
                "--no-pager",
                "--plain",
                "--full",
            ],
            timeout=15,
        )
        if unit_files.returncode == 0:
            for line in unit_files.stdout.splitlines():
                fields = line.split()
                if len(fields) >= 2:
                    start_modes[fields[0]] = fields[1]
    except (OSError, subprocess.TimeoutExpired):
        errors.append("systemctl service startup inventory unavailable")
    parsed: list[tuple[str, str, str]] = []
    for line in result.stdout.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        parsed.append((parts[0], parts[2], parts[3]))
    details: dict[str, dict[str, str]] = {}
    names = [name for name, _active, _substate in parsed[:512]]
    if names:
        try:
            detail_result = _run(
                [
                    "systemctl",
                    "show",
                    "--no-pager",
                    "--property=Id,ActiveState,SubState,UnitFileState,NRestarts,Result,ExecMainStatus",
                    *names,
                ],
                timeout=20,
            )
            if detail_result.returncode == 0:
                record: dict[str, str] = {}
                for line in [*detail_result.stdout.splitlines(), ""]:
                    if not line.strip():
                        if record.get("Id"):
                            details[record["Id"]] = record
                        record = {}
                    elif "=" in line:
                        key, value = line.split("=", 1)
                        record[key] = value
            else:
                errors.append("systemctl service failure metadata unavailable")
        except (OSError, subprocess.TimeoutExpired):
            errors.append("systemctl service failure metadata unavailable")
    services: list[Service] = []
    for name, active, substate in parsed:
        detail = details.get(name, {})
        raw_exit = detail.get("ExecMainStatus", "")
        services.append(
            Service(
                name=name,
                state="running" if substate == "running" else active,
                start_mode=(
                    start_modes.get(name)
                    or detail.get("UnitFileState")
                    or "unknown"
                ),
                substate=detail.get("SubState") or substate or "unknown",
                result=(
                    detail.get("Result")
                    or ("failed" if active == "failed" else "success")
                ),
                restart_count=(
                    int(detail.get("NRestarts", "0"))
                    if detail.get("NRestarts", "0").isdigit()
                    else 0
                ),
                exit_code=int(raw_exit) if raw_exit.isdigit() else None,
            )
        )
    return services[:2000]


def _windows_json(script: str) -> Any:
    result = _run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=20,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell command failed")
    if not result.stdout.strip():
        return []
    value = json.loads(result.stdout)
    return value if isinstance(value, list) else [value]


def _windows_accounts(errors: list[str]) -> list[Account]:
    script = r"""
$admins = @(Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | ForEach-Object {$_.Name.Split('\\')[-1]})
Get-LocalUser | ForEach-Object {
  [PSCustomObject]@{Name=$_.Name; SID=$_.SID.Value; Enabled=$_.Enabled; Privileged=($admins -contains $_.Name)}
} | ConvertTo-Json -Compress
"""
    try:
        return [
            Account(
                name=str(item.get("Name", "unknown")),
                account_id=str(item.get("SID", "")),
                privileged=bool(item.get("Privileged")),
                enabled=bool(item.get("Enabled", True)),
                source="local",
                groups=["Administrators"] if bool(item.get("Privileged")) else [],
            )
            for item in _windows_json(script)
        ]
    except Exception as exc:
        errors.append(f"Windows account inventory failed: {exc}")
        return []


def _windows_services(errors: list[str]) -> list[Service]:
    script = r"""
$restartFailures = @{}
$since = (Get-Date).AddMinutes(-15)
Get-WinEvent -FilterHashtable @{LogName='System';ProviderName='Service Control Manager';Id=7031,7034;StartTime=$since} -MaxEvents 512 -ErrorAction SilentlyContinue | ForEach-Object {
  if ($_.Properties.Count -gt 0) { $key = [string]$_.Properties[0].Value; $restartFailures[$key] = 1 + [int]$restartFailures[$key] }
}
Get-CimInstance Win32_Service | ForEach-Object {
  $count = [int]$restartFailures[$_.Name] + [int]$restartFailures[$_.DisplayName]
  [PSCustomObject]@{Name=$_.Name;State=$_.State;StartMode=$_.StartMode;Status=$_.Status;ExitCode=$_.ExitCode;RestartCount=$count}
} | ConvertTo-Json -Compress
"""
    try:
        return [
            Service(
                name=str(item.get("Name", "unknown")),
                state="running" if str(item.get("State", "")).casefold() == "running" else str(item.get("State", "unknown")).casefold(),
                start_mode=str(item.get("StartMode", "unknown")),
                substate=str(item.get("Status", "unknown")).casefold(),
                result=(
                    "success"
                    if int(item.get("ExitCode", 0) or 0) == 0
                    else "exit-code"
                ),
                restart_count=max(0, int(item.get("RestartCount", 0) or 0)),
                exit_code=max(0, int(item.get("ExitCode", 0) or 0)),
            )
            for item in _windows_json(script)
        ]
    except Exception as exc:
        errors.append(f"Windows service inventory failed: {exc}")
        return []


def _windows_sessions(accounts: list[Account], errors: list[str]) -> list[Session]:
    privileged = {account.name.casefold() for account in accounts if account.privileged}
    script = r"""
$names = @('powershell','pwsh','cmd','WindowsTerminal','ssh','sshd','wsmprovhost')
Get-Process -IncludeUserName -ErrorAction SilentlyContinue |
  Where-Object { $names -contains $_.ProcessName } |
  Select-Object Id,ProcessName,SessionId,UserName |
  ConvertTo-Json -Compress
"""
    try:
        sessions: list[Session] = []
        boot_id = _boot_id("windows")
        for item in _windows_json(script):
            raw_user = str(item.get("UserName", ""))
            username = raw_user.split("\\")[-1] if raw_user else "unknown"
            process_id = int(item["Id"]) if item.get("Id") is not None else None
            process_identity = None
            if process_id is not None:
                try:
                    process_identity = inspect_process_identity(
                        process_id, boot_id=boot_id
                    )
                except (OSError, PermissionError, RuntimeError, ValueError) as exc:
                    errors.append(
                        f"session process identity unavailable for PID {process_id}: {exc}"
                    )
            sessions.append(
                Session(
                    username=username,
                    source="unknown",
                    session_id=str(item.get("SessionId", "")),
                    process_id=process_id,
                    privileged=username.casefold() in privileged,
                    interactive=True,
                    process_identity=process_identity,
                )
            )
        return sessions
    except Exception as exc:
        errors.append(f"Windows interactive-session inventory failed: {exc}")
        return []


def _fallback_interfaces(errors: list[str]) -> list[Interface]:
    interfaces: dict[str, set[str]] = {}
    try:
        for _, name in socket.if_nameindex():
            interfaces.setdefault(name, set())
    except OSError as exc:
        errors.append(f"interface names unavailable: {exc}")
    try:
        for family, _, _, _, address in socket.getaddrinfo(socket.gethostname(), None):
            if family in {socket.AF_INET, socket.AF_INET6}:
                interfaces.setdefault("host", set()).add(str(address[0]))
    except OSError as exc:
        errors.append(f"interface addresses unavailable: {exc}")
    return [Interface(name=name, addresses=sorted(addresses)) for name, addresses in sorted(interfaces.items())]


def _linux_interfaces(errors: list[str]) -> list[Interface]:
    rows = _json_command(["ip", "-j", "address", "show"], [], "interface inventory")
    if not rows:
        return _fallback_interfaces(errors)
    result: list[Interface] = []
    for row in rows[:512]:
        addresses = []
        for item in row.get("addr_info", []):
            if not isinstance(item, dict) or not item.get("local"):
                continue
            address = str(item["local"])
            if item.get("prefixlen") is not None:
                address += f"/{item['prefixlen']}"
            addresses.append(address)
        result.append(Interface(name=str(row.get("ifname", "unknown")), addresses=addresses[:64]))
    return result


def _windows_interfaces(errors: list[str]) -> list[Interface]:
    script = (
        "Get-NetIPAddress | Where-Object {$_.AddressState -ne 'Tentative'} | "
        "Select InterfaceAlias,IPAddress,PrefixLength | ConvertTo-Json -Compress"
    )
    try:
        grouped: dict[str, set[str]] = {}
        for row in _windows_json(script):
            name = str(row.get("InterfaceAlias", "unknown"))
            address = str(row.get("IPAddress", ""))
            if not address:
                continue
            prefix = row.get("PrefixLength")
            grouped.setdefault(name, set()).add(
                f"{address}/{prefix}" if prefix is not None else address
            )
        return [Interface(name=name, addresses=sorted(addresses)) for name, addresses in sorted(grouped.items())]
    except Exception as exc:
        errors.append(f"Windows interface inventory failed: {exc}")
        return _fallback_interfaces(errors)


def _json_command(command: list[str], errors: list[str], label: str) -> list[dict[str, Any]]:
    try:
        result = _run(command, timeout=15)
        if result.returncode != 0 or not result.stdout.strip():
            errors.append(f"{label} unavailable")
            return []
        value = json.loads(result.stdout)
        if isinstance(value, dict):
            return [value]
        return value if isinstance(value, list) else []
    except (OSError, ValueError, subprocess.TimeoutExpired, json.JSONDecodeError) as exc:
        errors.append(f"{label} failed: {exc}")
        return []


def _linux_topology(errors: list[str]) -> tuple[list[Route], list[Neighbor], list[Listener]]:
    route_rows = _json_command(["ip", "-j", "route", "show"], errors, "route inventory")
    neighbor_rows = _json_command(["ip", "-j", "neigh", "show"], errors, "neighbor inventory")
    listener_rows = _json_command(["ss", "-H", "-lntup", "--json"], [], "listener inventory")
    routes = [
        Route(
            destination=str(row.get("dst", "default")),
            gateway=str(row.get("gateway", "")),
            interface=str(row.get("dev", "")),
            metric=int(row["metric"]) if str(row.get("metric", "")).isdigit() else None,
        )
        for row in route_rows
    ]
    neighbors = [
        Neighbor(
            address=str(row.get("dst", "")),
            hardware_address=str(row.get("lladdr", "")),
            interface=str(row.get("dev", "")),
            state=str(row.get("state", "unknown")),
        )
        for row in neighbor_rows
        if row.get("dst")
    ]
    listeners: list[Listener] = []
    if listener_rows:
        for row in listener_rows:
            local = row.get("local", {})
            if isinstance(local, dict) and local.get("port"):
                listeners.append(
                    Listener(
                        protocol=str(row.get("type", row.get("protocol", "tcp"))),
                        address=str(local.get("address", "")),
                        port=int(local["port"]),
                        process=str(row.get("process", "")),
                    )
                )
    else:
        try:
            result = _run(["ss", "-H", "-lnt"])
        except OSError:
            result = None
        if result and result.returncode == 0:
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) < 4:
                    continue
                local = parts[3]
                try:
                    address, port = local.rsplit(":", 1)
                    listeners.append(Listener(protocol="tcp", address=address, port=int(port)))
                except (ValueError, IndexError):
                    continue
        else:
            errors.append("listener inventory unavailable")
    return routes, neighbors, listeners[:2000]


def _windows_topology(errors: list[str]) -> tuple[list[Route], list[Neighbor], list[Listener]]:
    try:
        route_rows = _windows_json(
            "Get-NetRoute | Select DestinationPrefix,NextHop,InterfaceAlias,RouteMetric | ConvertTo-Json -Compress"
        )
        routes = [
            Route(
                destination=str(row.get("DestinationPrefix", "")),
                gateway=str(row.get("NextHop", "")),
                interface=str(row.get("InterfaceAlias", "")),
                metric=int(row["RouteMetric"]) if row.get("RouteMetric") is not None else None,
            )
            for row in route_rows
        ]
    except Exception as exc:
        errors.append(f"Windows route inventory failed: {exc}")
        routes = []
    try:
        neighbor_rows = _windows_json(
            "Get-NetNeighbor | Select IPAddress,LinkLayerAddress,InterfaceAlias,State | ConvertTo-Json -Compress"
        )
        neighbors = [
            Neighbor(
                address=str(row.get("IPAddress", "")),
                hardware_address=str(row.get("LinkLayerAddress", "")),
                interface=str(row.get("InterfaceAlias", "")),
                state=str(row.get("State", "unknown")),
            )
            for row in neighbor_rows
        ]
    except Exception as exc:
        errors.append(f"Windows neighbor inventory failed: {exc}")
        neighbors = []
    try:
        listener_rows = _windows_json(
            "Get-NetTCPConnection -State Listen | Select LocalAddress,LocalPort,OwningProcess | ConvertTo-Json -Compress"
        )
        listeners = [
            Listener(
                protocol="tcp",
                address=str(row.get("LocalAddress", "")),
                port=int(row.get("LocalPort", 0)),
                process=str(row.get("OwningProcess", "")),
            )
            for row in listener_rows
            if row.get("LocalPort")
        ]
    except Exception as exc:
        errors.append(f"Windows listener inventory failed: {exc}")
        listeners = []
    return routes, neighbors, listeners


def _linux_processes(errors: list[str]) -> list[ProcessObservation]:
    observations: list[ProcessObservation] = []
    proc = Path("/proc")
    try:
        entries = sorted((item for item in proc.iterdir() if item.name.isdigit()), key=lambda item: int(item.name))
    except OSError as exc:
        errors.append(f"process inventory unavailable: {exc}")
        return []
    for entry in entries[:4096]:
        try:
            values: dict[str, str] = {}
            for line in (entry / "status").read_text(encoding="utf-8", errors="replace").splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    values[key] = value.strip()
            uid = int(values.get("Uid", "-1").split()[0])
            username = str(uid)
            if pwd is not None:
                try:
                    username = pwd.getpwuid(uid).pw_name
                except KeyError:
                    pass
            try:
                executable = os.readlink(entry / "exe")
            except OSError:
                executable = ""
            observations.append(
                ProcessObservation(
                    name=values.get("Name", entry.name),
                    path=executable,
                    username=username,
                    process_id=int(entry.name),
                    parent_id=int(values.get("PPid", "0")),
                    privileged=uid == 0,
                )
            )
        except (OSError, ValueError, IndexError):
            continue
    return observations


def _windows_processes(errors: list[str]) -> list[ProcessObservation]:
    script = r"""
$admins = @(Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue | Get-LocalGroupMember -ErrorAction SilentlyContinue | ForEach-Object {$_.Name.Split('\')[-1]})
Get-CimInstance Win32_Process | Select-Object -First 4096 | ForEach-Object {
  $owner = Invoke-CimMethod -InputObject $_ -MethodName GetOwner -ErrorAction SilentlyContinue
  $user = if ($owner.User) {$owner.User} else {'unknown'}
  [PSCustomObject]@{ProcessId=$_.ProcessId;ParentProcessId=$_.ParentProcessId;Name=$_.Name;ExecutablePath=$_.ExecutablePath;UserName=$user;Privileged=($user -eq 'SYSTEM' -or $user -eq 'Administrator' -or $admins -contains $user)}
} | ConvertTo-Json -Compress
"""
    try:
        return [
            ProcessObservation(
                name=str(item.get("Name", "unknown")),
                path=str(item.get("ExecutablePath") or ""),
                username=str(item.get("UserName") or "unknown"),
                process_id=int(item.get("ProcessId", 0)),
                parent_id=int(item.get("ParentProcessId", 0)),
                privileged=bool(item.get("Privileged", False)),
            )
            for item in _windows_json(script)
            if int(item.get("ProcessId", 0)) > 0
        ][:4096]
    except Exception as exc:
        errors.append(f"Windows process inventory failed: {exc}")
        return []


def _file_persistence(path: Path, kind: str, owner: str = "unknown") -> PersistenceItem | None:
    try:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if pwd is not None:
            try:
                owner = pwd.getpwuid(path.stat().st_uid).pw_name
            except KeyError:
                pass
        return PersistenceItem(kind=kind, name=str(path), owner=owner, sha256=digest)
    except OSError:
        return None


def _linux_persistence(errors: list[str]) -> list[PersistenceItem]:
    items: list[PersistenceItem] = []
    for fixed in (Path("/etc/crontab"), Path("/etc/rc.local")):
        item = _file_persistence(fixed, "startup-file") if fixed.is_file() else None
        if item:
            items.append(item)
    for directory, kind in (
        (Path("/etc/cron.d"), "cron"),
        (Path("/var/spool/cron"), "user-cron"),
        (Path("/var/spool/cron/crontabs"), "user-cron"),
        (Path("/etc/systemd/system"), "systemd-file"),
        (Path("/usr/lib/systemd/system"), "systemd-file"),
        (Path("/lib/systemd/system"), "systemd-file"),
    ):
        try:
            candidates = directory.rglob("*") if kind == "systemd-file" else directory.iterdir()
            for path in sorted(candidates)[:1024]:
                item = _file_persistence(path, kind) if path.is_file() else None
                if item:
                    items.append(item)
        except OSError:
            continue
    try:
        result = _run(
            [
                "systemctl",
                "list-unit-files",
                "--state=enabled",
                "--type=service",
                "--type=timer",
                "--no-legend",
                "--no-pager",
            ],
            timeout=15,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines()[:2048]:
                fields = line.split()
                if fields:
                    items.append(
                        PersistenceItem(
                            kind="systemd-unit",
                            name=fields[0],
                            owner="root",
                            enabled=True,
                        )
                    )
    except OSError:
        pass
    return items[:4096]


def _windows_persistence(errors: list[str]) -> list[PersistenceItem]:
    script = r"""
Get-ScheduledTask | ForEach-Object {
  $actionText = ($_.Actions | ConvertTo-Json -Depth 4 -Compress)
  $sha = [Security.Cryptography.SHA256]::Create()
  try { $hash = ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($actionText)))).Replace('-','').ToLowerInvariant() } finally { $sha.Dispose() }
  [PSCustomObject]@{Kind='scheduled-task';Name=($_.TaskPath+$_.TaskName);Owner=$_.Author;Enabled=($_.State -ne 'Disabled');SHA256=$hash}
} | ConvertTo-Json -Compress
"""
    try:
        return [
            PersistenceItem(
                kind=str(item.get("Kind", "scheduled-task")),
                name=str(item.get("Name", "unknown")),
                owner=str(item.get("Owner") or "unknown"),
                enabled=bool(item.get("Enabled", True)),
                sha256=str(item.get("SHA256") or ""),
            )
            for item in _windows_json(script)
        ][:4096]
    except Exception as exc:
        errors.append(f"Windows persistence inventory failed: {exc}")
        return []


def _stable_firewall_digest(output: str) -> str:
    normalized = re.sub(
        r"\bcounter\s+packets\s+\d+\s+bytes\s+\d+\b",
        "counter packets * bytes *",
        output,
        flags=re.IGNORECASE,
    )
    return hashlib.sha256(normalized.encode()).hexdigest()


def _linux_firewall(errors: list[str]) -> FirewallState:
    for provider, command in (
        ("nftables", ["nft", "list", "ruleset"]),
        ("iptables", ["iptables-save"]),
        ("ufw", ["ufw", "status"]),
    ):
        try:
            result = _run(command, timeout=15)
        except OSError:
            continue
        if result.returncode != 0:
            continue
        output = result.stdout.strip()
        enabled = bool(output) and "status: inactive" not in output.casefold()
        return FirewallState(
            enabled=enabled,
            provider=provider,
            rules_sha256=_stable_firewall_digest(output),
            detail="rules present" if enabled else "no active rules detected",
        )
    return FirewallState(False, detail="firewall inventory unavailable")


def _windows_firewall(errors: list[str]) -> FirewallState:
    script = r"""
$profiles = @(Get-NetFirewallProfile | Select Name,Enabled)
$rules = @(Get-NetFirewallRule | Sort-Object Name | Select Name,Enabled,Direction,Action,Profile)
[PSCustomObject]@{Profiles=$profiles;Rules=$rules} | ConvertTo-Json -Depth 4 -Compress
"""
    try:
        rows = _windows_json(script)
        state = rows[0] if rows and isinstance(rows[0], dict) else {}
        profiles = state.get("Profiles", [])
        if isinstance(profiles, dict):
            profiles = [profiles]
        encoded = json.dumps(state, separators=(",", ":"), sort_keys=True)
        enabled = bool(profiles) and all(bool(item.get("Enabled")) for item in profiles)
        return FirewallState(
            enabled=enabled,
            provider="Windows Defender Firewall",
            rules_sha256=hashlib.sha256(encoded.encode()).hexdigest(),
            detail=", ".join(f"{item.get('Name')}={item.get('Enabled')}" for item in profiles),
        )
    except Exception as exc:
        errors.append(f"Windows firewall inventory failed: {exc}")
        return FirewallState(False, provider="Windows Defender Firewall", detail="inventory failed")


def _boot_id(system: str) -> str:
    if system != "windows":
        try:
            return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        except OSError:
            return "unknown"
    try:
        rows = _windows_json(
            "Get-CimInstance Win32_OperatingSystem | Select LastBootUpTime | ConvertTo-Json -Compress"
        )
        return str(rows[0].get("LastBootUpTime", "unknown")) if rows else "unknown"
    except Exception:
        return "unknown"


def _clean_event_text(value: Any, limit: int = 512) -> str:
    return " ".join(str(value).split())[:limit]


def _linux_security_events(errors: list[str]) -> list[SecurityEvent]:
    try:
        result = _run(
            [
                "journalctl",
                "--since=-5 minutes",
                "--output=json",
                "--no-pager",
                "--lines=512",
            ],
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if result.returncode != 0:
        return []
    patterns = (
        ("account_created", "success", re.compile(r"(?:new user|useradd).*?name[= :]([A-Za-z0-9_.@-]+)", re.I)),
        ("account_deleted", "success", re.compile(r"(?:delete user|userdel).*?([A-Za-z0-9_.@-]+)", re.I)),
        ("privilege_change", "success", re.compile(r"(?:added|add).*?([A-Za-z0-9_.@-]+).*?(?:sudo|wheel|admin)", re.I)),
        ("privilege_change", "success", re.compile(r"(?:sudoers|visudo|gpasswd|usermod).*?([A-Za-z0-9_.@-]+)", re.I)),
        ("audit_policy_changed", "success", re.compile(r"(?:auditd|audit rules?).*?(?:changed|reloaded|stopped)", re.I)),
        ("auth_failure", "failure", re.compile(r"Failed password for (?:invalid user )?([^ ]+) from ([0-9A-Fa-f:.]+)", re.I)),
        ("auth_success", "success", re.compile(r"Accepted \S+ for ([^ ]+) from ([0-9A-Fa-f:.]+)", re.I)),
        ("audit_cleared", "success", re.compile(r"(?:audit log.*clear|logs? cleared)", re.I)),
    )
    events: list[SecurityEvent] = []
    for line in result.stdout.splitlines()[-512:]:
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            continue
        if not isinstance(row, dict):
            continue
        message = _clean_event_text(row.get("MESSAGE", ""))
        if not message:
            continue
        category = outcome = ""
        match: re.Match[str] | None = None
        for candidate_category, candidate_outcome, pattern in patterns:
            matched = pattern.search(message)
            if matched:
                category, outcome, match = candidate_category, candidate_outcome, matched
                break
        if not category:
            continue
        account = match.group(1) if match and match.lastindex else "unknown"
        remote = match.group(2) if match and (match.lastindex or 0) >= 2 else "unknown"
        raw_time = str(row.get("__REALTIME_TIMESTAMP", "0"))
        occurred = int(raw_time) / 1_000_000 if raw_time.isdigit() else time.time()
        stable = "|".join(
            (
                str(row.get("_BOOT_ID", "")),
                raw_time,
                str(row.get("SYSLOG_IDENTIFIER", "")),
                message,
            )
        )
        raw_uid = str(row.get("_UID", ""))
        actor = raw_uid or "unknown"
        if raw_uid.isdigit() and pwd is not None:
            try:
                actor = pwd.getpwuid(int(raw_uid)).pw_name
            except KeyError:
                pass
        events.append(
            SecurityEvent(
                event_id="linux-" + hashlib.sha256(stable.encode()).hexdigest()[:32],
                category=category,
                outcome=outcome,
                account=_clean_event_text(account, 128),
                actor=_clean_event_text(actor, 128),
                remote_address=_clean_event_text(remote, 256),
                occurred_at=occurred,
                detail=message,
            )
        )
    return events[-256:]


def _windows_security_events(errors: list[str]) -> list[SecurityEvent]:
    script = r"""
$ids = 1102,4624,4625,4697,4698,4700,4701,4702,4719,4720,4722,4725,4726,4728,4729,4732,4733,4735,4738,4756,4757,4946,4947,4948,4950
$start = (Get-Date).AddMinutes(-5)
$events = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=$ids;StartTime=$start} -MaxEvents 512 -ErrorAction SilentlyContinue)
if ($events.Count -eq 0) { exit 0 }
$events | ForEach-Object {
  $xml = [xml]$_.ToXml(); $data = @{}
  foreach ($node in $xml.Event.EventData.Data) { $data[[string]$node.Name] = [string]$node.'#text' }
  $category = switch ($_.Id) {
    1102 {'audit_cleared'}
    4624 {'auth_success'}
    4625 {'auth_failure'}
    4697 {'service_installed'}
    {$_ -in 4698,4700,4701,4702} {'scheduled_task_changed'}
    4719 {'audit_policy_changed'}
    4720 {'account_created'}
    {$_ -in 4725,4726} {'account_disabled_or_deleted'}
    {$_ -in 4722,4738} {'account_changed'}
    {$_ -in 4946,4947,4948,4950} {'firewall_changed'}
    default {'privilege_change'}
  }
  $outcome = if ($_.Id -eq 4625) {'failure'} else {'success'}
  $account = if ($data.MemberName) {$data.MemberName} elseif ($data.MemberSid) {$data.MemberSid} elseif ($data.TargetUserName) {$data.TargetUserName} elseif ($data.TaskName) {$data.TaskName} elseif ($data.ServiceName) {$data.ServiceName} else {'unknown'}
  [PSCustomObject]@{
    EventId=('windows-'+$_.RecordId);Category=$category;Outcome=$outcome
    Account=([string]$account);Actor=([string]$data.SubjectUserName)
    RemoteAddress=([string]$data.IpAddress)
    OccurredAt=([DateTimeOffset]$_.TimeCreated).ToUnixTimeMilliseconds()/1000.0
    Detail=($_.ProviderName+' event '+$_.Id)
  }
} | ConvertTo-Json -Compress
"""
    try:
        return [
            SecurityEvent(
                event_id=_clean_event_text(item.get("EventId", "unknown"), 256),
                category=_clean_event_text(item.get("Category", "unknown"), 64),
                outcome=_clean_event_text(item.get("Outcome", "observed"), 64),
                account=_clean_event_text(item.get("Account") or "unknown", 128),
                actor=_clean_event_text(item.get("Actor") or "unknown", 128),
                remote_address=_clean_event_text(item.get("RemoteAddress") or "unknown", 256),
                occurred_at=max(0.0, float(item.get("OccurredAt", 0) or 0)),
                detail=_clean_event_text(item.get("Detail", ""), 512),
            )
            for item in _windows_json(script)
        ][:256]
    except Exception as exc:
        errors.append(f"Windows security-event inventory failed: {exc}")
        return []


def _windows_inventory(errors: list[str]) -> tuple[
    list[Account],
    list[Session],
    list[Service],
    list[Route],
    list[Neighbor],
    list[Listener],
    list[ProcessObservation],
    list[PersistenceItem],
    FirewallState,
    list[Interface],
    list[SecurityEvent],
]:
    """Collect independent native inventories concurrently and merge errors in order."""
    account_errors: list[str] = []
    accounts = _windows_accounts(account_errors)
    jobs = (
        lambda local: _windows_services(local),
        lambda local: _windows_sessions(accounts, local),
        lambda local: _windows_topology(local),
        lambda local: _windows_processes(local),
        lambda local: _windows_persistence(local),
        lambda local: _windows_firewall(local),
        lambda local: _windows_interfaces(local),
        lambda local: _windows_security_events(local),
    )

    def execute(job: Any) -> tuple[Any, list[str]]:
        local_errors: list[str] = []
        return job(local_errors), local_errors

    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="sb-win-collect") as pool:
        results = list(pool.map(execute, jobs))
    errors.extend(account_errors)
    for _value, local_errors in results:
        errors.extend(local_errors)
    services, sessions, topology, processes, persistence, firewall, interfaces, events = (
        value for value, _local_errors in results
    )
    routes, neighbors, listeners = topology
    return (
        accounts,
        sessions,
        services,
        routes,
        neighbors,
        listeners,
        processes,
        persistence,
        firewall,
        interfaces,
        events,
    )


def _integrity_paths(system: str, extra_paths: list[str] | None = None) -> list[Path]:
    if system == "windows":
        windows = Path(os.environ.get("WINDIR", r"C:\Windows"))
        user_profile = Path(os.environ.get("USERPROFILE", str(Path.home())))
        program_data = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData"))
        candidates = [
            windows / "System32/drivers/etc/hosts",
            windows / "System32/inetsrv/config/applicationHost.config",
            program_data / "ssh/sshd_config",
            program_data / "ssh/administrators_authorized_keys",
            user_profile / "Documents/WindowsPowerShell/profile.ps1",
            user_profile / ".ssh/authorized_keys",
        ]
    else:
        candidates = [
            Path("/etc/passwd"),
            Path("/etc/group"),
            Path("/etc/sudoers"),
            Path("/etc/ssh/sshd_config"),
            Path("/etc/crontab"),
            Path("/etc/hosts"),
            Path("/root/.ssh/authorized_keys"),
            Path("/etc/nginx/nginx.conf"),
            Path("/etc/apache2/apache2.conf"),
            Path("/etc/httpd/conf/httpd.conf"),
            Path("/etc/samba/smb.conf"),
            Path("/etc/named.conf"),
            Path("/etc/my.cnf"),
            Path("/etc/mysql/my.cnf"),
            Path("/etc/chrony.conf"),
        ]
        for root, pattern in (
            (Path("/etc/postgresql"), "*/main/postgresql.conf"),
            (Path("/etc/postgresql"), "*/main/pg_hba.conf"),
            (Path("/etc/systemd/system"), "*.service"),
            (Path("/var/named"), "*.zone"),
        ):
            try:
                candidates.extend(sorted(root.glob(pattern)))
            except OSError:
                pass
    for raw in extra_paths or []:
        path = Path(str(raw))
        if path.is_absolute():
            candidates.append(path)
    unique: list[Path] = []
    seen: set[str] = set()
    for path in candidates:
        normalized = str(path)
        if normalized not in seen:
            seen.add(normalized)
            unique.append(path)
        if len(unique) >= 256:
            break
    return unique


def integrity_watch_paths(extra_paths: list[str] | None = None) -> list[str]:
    """Return the exact default and configured files used by integrity collection."""
    system = platform.system().casefold()
    return [str(path) for path in _integrity_paths(system, extra_paths)]


def _integrity(
    system: str, errors: list[str], extra_paths: list[str] | None = None
) -> list[IntegrityItem]:
    items: list[IntegrityItem] = []
    for path in _integrity_paths(system, extra_paths):
        if system != "windows" and (not path.exists() or not path.is_file()):
            continue
        try:
            digest = hashlib.sha256()
            security_descriptor_sha256 = ""
            if system == "windows":
                from .restoration import _windows_read_file_snapshot_if_present

                result = _windows_read_file_snapshot_if_present(
                    path,
                    MAX_WINDOWS_INTEGRITY_FILE_BYTES,
                    allow_security_failure=True,
                )
                if result is None:
                    continue
                data, snapshot = result
                digest.update(data)
                size = int(snapshot["size"])
                modified_at = float(snapshot["modified_at"])
                security_descriptor = snapshot.get("windows_security_descriptor")
                if isinstance(security_descriptor, str) and security_descriptor:
                    security_descriptor_sha256 = hashlib.sha256(
                        security_descriptor.encode("utf-8")
                    ).hexdigest()
                security_error = str(snapshot.get("security_descriptor_error") or "")
                if security_error:
                    errors.append(
                        f"integrity security metadata read failed for {path}: {security_error}"
                    )
            else:
                with path.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(131072), b""):
                        digest.update(chunk)
                    file_stat = os.fstat(handle.fileno())
                size = int(file_stat.st_size)
                modified_at = float(file_stat.st_mtime)
            items.append(
                IntegrityItem(
                    path=str(path),
                    sha256=digest.hexdigest(),
                    size=size,
                    modified_at=modified_at,
                    security_descriptor_sha256=security_descriptor_sha256,
                )
            )
        except (OSError, ValueError) as exc:
            errors.append(f"integrity read failed for {path}: {exc}")
    return items


def collect(
    agent_id: str,
    probe_specs: list[dict[str, Any]] | None = None,
    authorized_networks: list[str] | None = None,
    integrity_paths: list[str] | None = None,
    authorized_hosts: list[str] | tuple[str, ...] | None = None,
    excluded_hosts: list[str] | tuple[str, ...] | None = None,
) -> Telemetry:
    errors: list[str] = []
    system = platform.system().casefold()
    if system == "windows":
        (
            accounts,
            sessions,
            services,
            routes,
            neighbors,
            listeners,
            processes,
            persistence,
            firewall,
            interfaces,
            security_events,
        ) = _windows_inventory(errors)
    else:
        accounts = _linux_accounts()
        privileged = {item.name.casefold() for item in accounts if item.privileged}
        sessions = _linux_sessions(privileged, errors)
        services = _linux_services(errors)
        routes, neighbors, listeners = _linux_topology(errors)
        processes = _linux_processes(errors)
        persistence = _linux_persistence(errors)
        firewall = _linux_firewall(errors)
        interfaces = _linux_interfaces(errors)
        security_events = _linux_security_events(errors)
    probes = []
    if probe_specs:
        from .probes import run_probes

        probes = run_probes(
            probe_specs,
            authorized_networks or [],
            authorized_hosts=authorized_hosts,
            excluded_hosts=excluded_hosts,
        )
    integrity = _integrity(system, errors, integrity_paths)
    # Collector diagnostics can include attacker-controlled command output and
    # verbose platform exception text.  Normalize them at the collection
    # boundary so a failed sub-collector can never make the complete telemetry
    # record invalid on the wire.
    bounded_errors: list[str] = []
    for error in errors[:256]:
        clean = "".join(
            character
            if ord(character) >= 32 or character in "\t\r\n"
            else "\ufffd"
            for character in str(error)
        ).strip()
        bounded_errors.append((clean or "collector failed without detail")[:256])
    return Telemetry(
        agent_id=agent_id,
        hostname=socket.gethostname(),
        platform=f"{platform.system()} {platform.release()}",
        observed_at=time.time(),
        accounts=accounts,
        sessions=sessions,
        services=services,
        interfaces=interfaces,
        routes=routes,
        neighbors=neighbors,
        listeners=listeners,
        integrity=integrity,
        probes=probes,
        processes=processes,
        persistence=persistence,
        security_events=security_events,
        firewall=firewall,
        collector_errors=bounded_errors,
        boot_id=_boot_id(system),
    )


def machine_identity() -> str:
    candidates = [Path("/etc/machine-id"), Path("/var/lib/dbus/machine-id")]
    for path in candidates:
        try:
            value = path.read_text(encoding="utf-8").strip()
            if value:
                return value
        except OSError:
            continue
    return f"{socket.gethostname()}:{platform.system()}:{os.getenv('COMPUTERNAME', '')}"
