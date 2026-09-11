"""Dependency-free host telemetry collectors for Linux and Windows."""

from __future__ import annotations

import json
import hashlib
import fnmatch
import os
import platform
import re
import socket
import stat
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from contextvars import ContextVar
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
from .windows_queries import WINDOWS_QUERIES
from .windows_query_batch import QueryResult, decode_rows, read_query_batch

MAX_WINDOWS_INTEGRITY_FILE_BYTES = 32 * 1024 * 1024
MAX_WINDOWS_INTEGRITY_TOTAL_BYTES = 128 * 1024 * 1024
WINDOWS_INTEGRITY_BUDGET_SECONDS = 10.0
MAX_INTEGRITY_PATHS = 256
MAX_INTEGRITY_DISCOVERY_ENTRIES = 4096
MAX_POSIX_INTEGRITY_FILE_BYTES = 32 * 1024 * 1024
MAX_POSIX_INTEGRITY_TOTAL_BYTES = 128 * 1024 * 1024
POSIX_INTEGRITY_BUDGET_SECONDS = 10.0
WINDOWS_INVENTORY_BUDGET_SECONDS = 75.0
_windows_deadline: ContextVar[float | None] = ContextVar("windows_inventory_deadline", default=None)
_windows_query_cache: ContextVar[Any] = ContextVar("windows_inventory_queries", default=None)


class _WindowsQueryCache:
    """One lazy native snapshot, discarded at the end of this collection."""
    def __init__(self, deadline: float):
        self.deadline = deadline
        self.results: dict[str, QueryResult] | None = None
        self.lock = threading.Lock()

    def read(self, script: str) -> list[dict[str, Any]]:
        name = next((name for name, body in WINDOWS_QUERIES.items() if body == script), None)
        if name is None:
            raise RuntimeError("query is outside this Windows inventory snapshot")
        with self.lock:
            if self.results is None:
                self.results = read_query_batch(self.deadline)
        record = self.results.get(name)
        if record is None or record.error:
            raise RuntimeError(record.error if record else "Windows inventory section did not complete")
        if time.monotonic() >= self.deadline:
            raise RuntimeError("Windows inventory query completed after its collection budget")
        return record.rows


@contextmanager
def _windows_query_snapshot():
    deadline = _windows_deadline.get()
    if deadline is None:
        raise RuntimeError("Windows snapshot requires the original inventory deadline")
    token = _windows_query_cache.set(_WindowsQueryCache(deadline))
    try:
        yield
    finally:
        _windows_query_cache.reset(token)


@contextmanager
def _windows_inventory_budget():
    """Share one finite query budget without carrying state into the next cycle."""
    current = _windows_deadline.get()
    deadline = current if current is not None else time.monotonic() + WINDOWS_INVENTORY_BUDGET_SECONDS
    token = _windows_deadline.set(deadline)
    try:
        yield deadline
    finally:
        _windows_deadline.reset(token)


def _run(command: list[str], timeout: float = 8.0) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
        # Avoid inheriting a background task's below-normal scheduling class.
        # Normal priority still shares the CPU with the applications we monitor.
        creationflags=(
            getattr(subprocess, "CREATE_NO_WINDOW", 0)
            | getattr(subprocess, "NORMAL_PRIORITY_CLASS", 0)
        ),
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
                privileged=(
                    entry.pw_uid == 0
                    or entry.pw_name in privileged_names
                    or bool(set(groups) & {"sudo", "wheel", "admin"})
                ),
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
    installed_names: list[str] = []
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
                    installed_names.append(fields[0])
        else:
            errors.append("systemctl service startup inventory unavailable")
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
    # systemd may garbage-collect a stopped static unit from list-units even
    # while its unit file remains installed.  Preserve those identities so a
    # baseline service cannot disappear from telemetry at the moment it stops.
    # Do not include unloaded names in the batched `systemctl show`: some valid
    # alias and generated unit-file entries make that command return nonzero.
    loaded_names = {name for name, _active, _substate in parsed}
    for name in installed_names:
        if name not in loaded_names and len(parsed) < 2000:
            parsed.append((name, "inactive", "dead"))
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


def _windows_json(script: str, timeout: float = 60.0) -> Any:
    deadline = _windows_deadline.get()
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Windows inventory query budget exhausted")
        timeout = min(timeout, remaining)
    cache = _windows_query_cache.get()
    if cache is not None:
        return cache.read(script)
    try:
        result = _run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference = 'Stop'\n" + script],
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"PowerShell collector timed out after {timeout:g} seconds") from exc
    if deadline is not None and time.monotonic() > deadline:
        raise RuntimeError("Windows inventory query completed after its collection budget")
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "PowerShell command failed")
    if result.stderr.strip():
        # PowerShell can exit successfully after a non-terminating error and
        # still emit partial JSON. Never turn that into a complete observation.
        raise RuntimeError("PowerShell collector reported errors: " + result.stderr.strip())
    return decode_rows(result.stdout)


def _windows_accounts(errors: list[str]) -> list[Account]:
    script = WINDOWS_QUERIES["ACCOUNTS"]
    try:
        rows = _windows_json(script)
        if not rows:
            raise ValueError("Windows account inventory returned no records")
        return [
            Account(
                name=str(item.get("Name", "unknown")),
                account_id=str(item.get("SID", "")),
                privileged=bool(item.get("Privileged")),
                enabled=bool(item.get("Enabled", True)),
                source="local",
                groups=["Administrators"] if bool(item.get("Privileged")) else [],
            )
            for item in rows
        ]
    except Exception as exc:
        errors.append(f"Windows account inventory failed: {exc}")
        return []


def _windows_services(errors: list[str]) -> list[Service]:
    script = WINDOWS_QUERIES["SERVICES"]
    try:
        rows = _windows_json(script)
        if not rows:
            raise ValueError("Windows service inventory returned no records")
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
            for item in rows
        ]
    except Exception as exc:
        errors.append(f"Windows service inventory failed: {exc}")
        return []


def _windows_sessions(accounts: list[Account], errors: list[str], *, boot_id: str | None = None) -> list[Session]:
    privileged = {account.name.casefold() for account in accounts if account.privileged}
    script = WINDOWS_QUERIES["SESSIONS"]
    try:
        sessions: list[Session] = []
        if boot_id is None:
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
    script = WINDOWS_QUERIES["INTERFACES"]
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
    # Reuse one PowerShell host and its network module for the related queries.
    # Each section retains an explicit error so a partial batch cannot look fresh
    # and complete merely because the enclosing process exited successfully.
    script = WINDOWS_QUERIES["TOPOLOGY"]
    try:
        batch = _windows_json(script)
        if len(batch) != 1 or not isinstance(batch[0], dict):
            raise ValueError("incomplete topology batch")
        state = batch[0]
        sections = {"Routes", "Neighbors", "Listeners"}
        if state.get("Schema") != 1 or not sections.issubset(state):
            raise ValueError("incomplete topology sections")
        failures = state.get("Errors")
        if (
            not isinstance(failures, dict)
            or not set(failures).issubset(sections)
            or any(not isinstance(value, str) or not value for value in failures.values())
        ):
            raise ValueError("invalid topology error records")
    except Exception as exc:
        errors.append(f"Windows topology inventory failed: {exc}")
        return [], [], []

    def rows_for(section: str) -> list[dict[str, Any]]:
        if section in failures:
            raise RuntimeError(failures[section])
        rows = state[section]
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            raise ValueError(f"incomplete topology section: {section}")
        return rows

    try:
        routes = [
            Route(
                destination=str(row.get("DestinationPrefix", "")),
                gateway=str(row.get("NextHop", "")),
                interface=str(row.get("InterfaceAlias", "")),
                metric=int(row["RouteMetric"]) if row.get("RouteMetric") is not None else None,
            )
            for row in rows_for("Routes")
        ]
    except Exception as exc:
        errors.append(f"Windows route inventory failed: {exc}")
        routes = []
    try:
        neighbors = [
            Neighbor(
                address=str(row.get("IPAddress", "")),
                hardware_address=str(row.get("LinkLayerAddress", "")),
                interface=str(row.get("InterfaceAlias", "")),
                state=str(row.get("State", "unknown")),
            )
            for row in rows_for("Neighbors")
        ]
    except Exception as exc:
        errors.append(f"Windows neighbor inventory failed: {exc}")
        neighbors = []
    try:
        listeners = [
            Listener(
                protocol="tcp",
                address=str(row.get("LocalAddress", "")),
                port=int(row.get("LocalPort", 0)),
                process=str(row.get("OwningProcess", "")),
            )
            for row in rows_for("Listeners")
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
    if len(entries) > 4096:
        errors.append("Linux process inventory exceeded its 4096-entry limit; coverage is incomplete")
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
    script = WINDOWS_QUERIES["PROCESSES"]
    try:
        rows = _windows_json(script)
        if len(rows) > 4096:
            errors.append("Windows process inventory exceeded its 4096-entry limit; coverage is incomplete")
        return [
            ProcessObservation(
                name=str(item.get("Name", "unknown")),
                path=str(item.get("ExecutablePath") or ""),
                username=str(item.get("UserName") or "unknown"),
                process_id=int(item.get("ProcessId", 0)),
                parent_id=int(item.get("ParentProcessId", 0)),
                privileged=bool(item.get("Privileged", False)),
            )
            for item in rows[:4096]
            if int(item.get("ProcessId", 0)) > 0
        ]
    except Exception as exc:
        errors.append(f"Windows process inventory failed: {exc}")
        return []


def _file_persistence(path: Path, kind: str, owner: str = "unknown") -> PersistenceItem | None:
    try:
        # Hash links themselves. A startup alias must not redirect a bounded
        # inventory read to an arbitrary file/device controlled by an attacker.
        if path.is_symlink():
            return PersistenceItem(kind=kind + "-link", name=str(path), owner=owner,
                                   sha256=hashlib.sha256(os.readlink(path).encode()).hexdigest())
        from .restoration import RestorePointStore
        from .payload_inventory import _distribution_alias, _alias_unchanged
        native_path, alias = _distribution_alias(path)
        data, metadata = RestorePointStore._read_target(native_path)
        if alias and not _alias_unchanged(alias):
            raise ValueError('startup directory alias changed during inventory')
        digest = hashlib.sha256(data).hexdigest()
        if pwd is not None:
            try:
                owner = pwd.getpwuid(metadata['uid']).pw_name
            except KeyError:
                pass
        return PersistenceItem(kind=kind, name=str(path), owner=owner, sha256=digest)
    except (OSError, ValueError):
        return None


def _linux_persistence(errors: list[str]) -> list[PersistenceItem]:
    items: list[PersistenceItem] = []
    for fixed in (Path("/etc/crontab"), Path("/etc/rc.local"), Path("/etc/profile"),
                  Path("/etc/bash.bashrc"), Path("/etc/ld.so.preload")):
        item = _file_persistence(fixed, "startup-file") if fixed.is_file() else None
        if item:
            items.append(item)
    for directory, kind in (
        (Path("/etc/cron.d"), "cron"),
        (Path("/etc/cron.hourly"), "cron"),
        (Path("/etc/cron.daily"), "cron"),
        (Path("/etc/cron.weekly"), "cron"),
        (Path("/etc/cron.monthly"), "cron"),
        (Path("/etc/profile.d"), "shell-startup"),
        (Path("/etc/pam.d"), "authentication-config"),
        (Path("/etc/ssh/sshd_config.d"), "ssh-config"),
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
                elif path.is_file():
                    errors.append("persistence inventory could not safely read a startup entry")
        except OSError:
            continue
    if pwd is not None:
        # Service-account UIDs are not a trust boundary. An attacker can place
        # authorized keys or shell startup files under those homes too.
        users = list(pwd.getpwall())
        if len(users) > 256:
            errors.append("persistence user inventory exceeded 256 accounts")
        for user in users[:256]:
            home_path = Path(user.pw_dir)
            if not home_path.is_absolute():
                continue
            for suffix, kind in ((".ssh/authorized_keys", "authorized-keys"), (".profile", "shell-startup"),
                                 (".bashrc", "shell-startup"), (".bash_profile", "shell-startup"),
                                 (".zshrc", "shell-startup")):
                path = home_path / suffix
                try:
                    present = path.is_file()
                except OSError:
                    errors.append("persistence inventory could not inspect a user startup path")
                    continue
                if present:
                    item = _file_persistence(path, kind, user.pw_name)
                    if item:
                        items.append(item)
                    else:
                        errors.append("persistence inventory could not safely read a user startup entry")
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
    from .payload_inventory import linux_startup_payloads, linux_process_payloads
    items.extend(linux_startup_payloads(items, errors))
    items.extend(linux_process_payloads(errors))
    if len(items) > 4096:
        errors.append("persistence inventory exceeded its 4096-entry bound")
    return items[:4096]


def _windows_persistence(errors: list[str]) -> list[PersistenceItem]:
    script = WINDOWS_QUERIES["PERSISTENCE"]
    try:
        native = _windows_json(script)
        items = [
            PersistenceItem(
                kind=str(item.get("Kind", "scheduled-task")),
                name=str(item.get("Name", "unknown")),
                owner=str(item.get("Owner") or "unknown"),
                enabled=bool(item.get("Enabled", True)),
                sha256=str(item.get("SHA256") or ""),
            )
            for item in native if item.get('Kind') not in {'process-reference','startup-folder'}
        ]
        from .payload_inventory import fingerprint_references, windows_startup_payload_paths
        folders = [row for row in native if row.get('Kind') == 'startup-folder']
        if folders:
            from .windows_startup import startup_folder_inventory
            items.extend(startup_folder_inventory(folders, errors))
        references = [path for row in native if row.get('Kind') != 'process-reference'
                      for command in row.get('References', [])
                      for path in windows_startup_payload_paths(str(command))]
        items.extend(fingerprint_references(references, errors))
        process_rows = [row for row in native if row.get('Kind') == 'process-reference']
        if len(process_rows) > 4096:
            errors.append('Windows process payload inventory exceeded its process bound')
        running = [path for row in process_rows[:4096]
                   for command in row.get('References', [])
                   for path in windows_startup_payload_paths(str(command))]
        items.extend(fingerprint_references(running, errors, kind='process-payload', max_files=128, seconds=3.0))
        if len(items) > 4096:
            errors.append('Windows persistence inventory exceeded its entry bound')
        return items[:4096]
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
    script = WINDOWS_QUERIES["FIREWALL"]
    try:
        rows = _windows_json(script, timeout=60.0)
        if len(rows) != 1 or not isinstance(rows[0], dict):
            raise ValueError("incomplete firewall inventory")
        state = rows[0]
        filters = state.get("Filters")
        expected_filters = {"Address", "Port", "Application", "Service", "Interface", "InterfaceType", "Security"}
        if state.get("Schema") != 2 or not isinstance(filters, dict) or set(filters) != expected_filters:
            raise ValueError("incomplete firewall filter inventory")
        if not isinstance(state.get("Rules"), list) or any(not isinstance(value, list) for value in filters.values()):
            raise ValueError("malformed firewall inventory")
        profiles = state.get("Profiles", [])
        if not isinstance(profiles, list) or not profiles or any(not isinstance(item, dict) or not isinstance(item.get("Enabled"), bool) for item in profiles):
            raise ValueError("incomplete firewall profile inventory")
        encoded = json.dumps(_canonical_firewall_state(state), separators=(",", ":"), sort_keys=True)
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


def _canonical_firewall_state(value: Any) -> Any:
    """NetSecurity inventories and condition arrays are unordered sets."""
    if isinstance(value, dict):
        return {key: _canonical_firewall_state(item) for key, item in value.items()}
    if isinstance(value, list):
        normalized = [_canonical_firewall_state(item) for item in value]
        return sorted(normalized, key=lambda item: json.dumps(item, separators=(",", ":"), sort_keys=True))
    return value


def _boot_id(system: str) -> str:
    if system != "windows":
        try:
            return Path("/proc/sys/kernel/random/boot_id").read_text(encoding="utf-8").strip()
        except OSError:
            return "unknown"
    try:
        rows = _windows_json(WINDOWS_QUERIES["BOOT"])
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
    from .windows_audit import logon_audit_policy
    try:
        policy = logon_audit_policy()
        if not policy['success'] or not policy['failure']:
            errors.append('Windows successful/failed logon auditing is disabled or incomplete')
    except (OSError,ValueError):
        errors.append('Windows logon audit policy could not be verified')
    script = WINDOWS_QUERIES["SECURITY_EVENTS"]
    try:
        native_events = _windows_json(script)
        # Enforce age against the native event timestamp in Python. Keep the
        # bounded native query independent of PowerShell DateTime conversion.
        now = time.time()
        native_events = [item for item in native_events
                         if now-300 <= float(item.get('OccurredAt',0) or 0) <= now+5]
        if len(native_events) > 256:
            errors.append('Windows security-event inventory exceeded its 256-event telemetry bound')
        return [
            SecurityEvent(
                event_id=_clean_event_text(item.get("EventId", "unknown"), 256),
                category=_clean_event_text(item.get("Category", "unknown"), 64),
                outcome=_clean_event_text(item.get("Outcome", "observed"), 64),
                account=_clean_event_text(item.get("Account") or "unknown", 128),
                account_id=_clean_event_text(item.get("AccountId") or "", 256),
                account_domain=_clean_event_text(item.get("AccountDomain") or "", 256),
                actor=_clean_event_text(item.get("Actor") or "unknown", 128),
                remote_address=_clean_event_text(item.get("RemoteAddress") or "unknown", 256),
                occurred_at=max(0.0, float(item.get("OccurredAt", 0) or 0)),
                detail=_clean_event_text(item.get("Detail", ""), 512),
            )
            for item in native_events
        ][:256]
    except Exception as exc:
        errors.append(f"Windows security-event inventory failed: {exc}")
        return []


def _windows_inventory(errors: list[str], *, boot_id: str | None = None) -> tuple[
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
    """Bound native helper contention and merge complete inventory errors in order."""
    deadline = _windows_deadline.get()
    if deadline is None:
        deadline = time.monotonic() + WINDOWS_INVENTORY_BUDGET_SECONDS
    jobs = (
        lambda local: _windows_services(local),
        lambda local: _windows_topology(local),
        lambda local: _windows_processes(local),
        lambda local: _windows_persistence(local),
        lambda local: _windows_firewall(local),
        lambda local: _windows_interfaces(local),
        lambda local: _windows_security_events(local),
    )
    query_cache = _windows_query_cache.get()

    def execute(job: Any) -> tuple[Any, list[str]]:
        local_errors: list[str] = []
        token = _windows_deadline.set(deadline)
        cache_token = _windows_query_cache.set(query_cache)
        try:
            return job(local_errors), local_errors
        finally:
            _windows_query_cache.reset(cache_token)
            _windows_deadline.reset(token)

    accounts, account_errors = execute(_windows_accounts)

    # On a single CPU, overlapping PowerShell/CIM helpers made otherwise valid
    # inventories time out and held recovery. Keep each query bounded without
    # dropping a collector or trusting its prior result as a fresh observation.
    workers = min(2, max(1, os.cpu_count() or 1))
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="sb-win-collect") as pool:
        results = list(pool.map(execute, jobs))
    # A session scan must not observe our short-lived inventory PowerShell
    # helpers after they exit. Its own PowerShell process is excluded by $PID;
    # every remaining session still needs the normal exact process identity.
    results.insert(1, execute(lambda local: _windows_sessions(accounts, local) if boot_id is None
                             else _windows_sessions(accounts, local, boot_id=boot_id)))
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


def _discover_integrity_paths(root: Path, pattern: str) -> list[Path]:
    """Expand fixed watch patterns without hiding directory access failures."""
    remaining = MAX_INTEGRITY_DISCOVERY_ENTRIES

    def walk(directory: Path, parts: list[str]):
        nonlocal remaining
        part, *tail = parts
        if not any(mark in part for mark in "*?["):
            target = directory / part
            if tail:
                yield from walk(target, tail)
            else:
                try:
                    target.lstat()
                except (FileNotFoundError, NotADirectoryError):
                    return
                yield target
            return
        try:
            entries = os.scandir(directory)
        except (FileNotFoundError, NotADirectoryError):
            return  # Optional application directories need not be installed.
        with entries:
            for entry in entries:
                remaining -= 1
                if remaining < 0:
                    raise ValueError("integrity discovery entry limit exceeded; coverage is incomplete")
                if fnmatch.fnmatchcase(entry.name, part):
                    target = directory / entry.name
                    if tail:
                        yield from walk(target, tail)
                    else:
                        yield target

    return sorted(walk(root, pattern.split("/")))


def _integrity_paths(
    system: str, extra_paths: list[str] | None = None, *, errors: list[str] | None = None
) -> list[Path]:
    # Watcher hints may use a bounded subset, but collection must explicitly
    # report every loss of coverage so it cannot authorize automatic repair.
    diagnostics = errors if errors is not None else []
    protected: list[Path] = []
    for raw in extra_paths or []:
        if not isinstance(raw, str) or "\x00" in raw or not Path(raw).is_absolute():
            diagnostics.append("integrity protected path must be an absolute path without NUL")
            continue
        protected.append(Path(raw))
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
                for discovered in _discover_integrity_paths(root, pattern):
                    # Installed service aliases are not writable restore targets.
                    # Monitor/capture the canonical file; the alias remains in
                    # persistence telemetry. A new destination is a new path
                    # requiring manifest and baseline review. Explicit protected
                    # paths are never silently redirected by this discovery step.
                    if root == Path("/etc/systemd/system") and discovered.is_symlink():
                        try:
                            discovered = discovered.resolve(strict=True)
                        except (OSError, RuntimeError):
                            pass
                    candidates.append(discovered)
            except (OSError, ValueError) as exc:
                diagnostics.append(f"integrity path discovery failed for {root}: {exc}")
    unique: list[Path] = []
    seen: set[str] = set()
    for path in [*protected, *candidates]:
        # Windows directories can opt into case-sensitive names. Without
        # filesystem identity evidence, case variants remain distinct targets.
        normalized = str(path)
        if normalized not in seen:
            if len(unique) >= MAX_INTEGRITY_PATHS:
                diagnostics.append(
                    f"integrity path limit of {MAX_INTEGRITY_PATHS} exceeded; coverage is incomplete"
                )
                break
            seen.add(normalized)
            unique.append(path)
    return unique


def integrity_watch_paths(extra_paths: list[str] | None = None) -> list[str]:
    """Return bounded watcher hints; collection reports any missing coverage."""
    system = platform.system().casefold()
    return [str(path) for path in _integrity_paths(system, extra_paths)]


class _IntegrityBudget:
    """One cycle's read allowance, including bytes from rejected snapshots."""

    def __init__(self, system: str = "linux") -> None:
        windows = system == "windows"
        self.label = "Windows" if windows else "POSIX"
        self.deadline = time.monotonic() + (
            WINDOWS_INTEGRITY_BUDGET_SECONDS if windows else POSIX_INTEGRITY_BUDGET_SECONDS
        )
        self.remaining_bytes = (
            MAX_WINDOWS_INTEGRITY_TOTAL_BYTES if windows else MAX_POSIX_INTEGRITY_TOTAL_BYTES
        )

    def check(self) -> None:
        if time.monotonic() >= self.deadline:
            raise TimeoutError(f"{self.label} integrity collection time budget exhausted")

    def consume(self, count: int) -> None:
        self.remaining_bytes -= count
        if self.remaining_bytes < 0:
            raise ValueError(f"{self.label} integrity collection byte budget exhausted")
        self.check()


def _file_snapshot_identity(value: os.stat_result) -> tuple[int, ...]:
    # Access time changes on normal reads and is deliberately excluded.
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _posix_integrity_item(path: Path, budget: _IntegrityBudget) -> IntegrityItem | None:
    """Hash a bounded regular-file snapshot; reject concurrent changes.

    Deadlines are checked between operations. A blocked filesystem call still
    depends on the OS. Existing monitored symlink paths remain supported, with
    the final pathname required to identify the same snapshot as the open file.
    """
    budget.check()
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        return None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("integrity target is not a regular file")
        if before.st_size > MAX_POSIX_INTEGRITY_FILE_BYTES:
            raise ValueError("integrity file exceeds the per-file byte limit")
        # Leave room for one bounded EOF check. This also rejects pseudo-files
        # whose reported size does not describe their readable contents.
        if before.st_size >= budget.remaining_bytes:
            raise ValueError("POSIX integrity collection byte budget exhausted")
        digest = hashlib.sha256()
        received = 0
        while received <= before.st_size:
            budget.check()
            chunk = os.read(descriptor, min(131072, before.st_size + 1 - received))
            budget.consume(len(chunk))
            if not chunk:
                break
            received += len(chunk)
            if received > before.st_size:
                raise ValueError("integrity file changed while being read or reports an unsupported size")
            digest.update(chunk)
        if received != before.st_size:
            raise ValueError("integrity file changed while being read")
        after = os.fstat(descriptor)
        named = path.stat()
        budget.check()
        identity = _file_snapshot_identity(before)
        if identity != _file_snapshot_identity(after) or identity != _file_snapshot_identity(named):
            raise ValueError("integrity file changed while being read")
        return IntegrityItem(path=str(path), sha256=digest.hexdigest(),
                             size=received, modified_at=float(after.st_mtime))
    finally:
        os.close(descriptor)


def _integrity(
    system: str, errors: list[str], extra_paths: list[str] | None = None
) -> list[IntegrityItem]:
    items: list[IntegrityItem] = []
    budget = _IntegrityBudget(system)
    for path in _integrity_paths(system, extra_paths, errors=errors):
        try:
            budget.check()
            if system != "windows":
                item = _posix_integrity_item(path, budget)
                if item is not None:
                    items.append(item)
                continue
            digest = hashlib.sha256()
            security_descriptor_sha256 = ""
            if system == "windows":
                from .restoration import _windows_read_file_snapshot_if_present

                if budget.remaining_bytes <= 0:
                    raise ValueError("Windows integrity collection byte budget exhausted")
                result = _windows_read_file_snapshot_if_present(
                    path,
                    min(MAX_WINDOWS_INTEGRITY_FILE_BYTES, budget.remaining_bytes - 1),
                    allow_security_failure=True,
                    read_budget=budget,
                )
                budget.check()
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
            budget.check()
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
            if time.monotonic() >= budget.deadline or budget.remaining_bytes <= 0:
                break
    return items


def collect(
    agent_id: str,
    probe_specs: list[dict[str, Any]] | None = None,
    authorized_networks: list[str] | None = None,
    integrity_paths: list[str] | None = None,
    authorized_hosts: list[str] | tuple[str, ...] | None = None,
    excluded_hosts: list[str] | tuple[str, ...] | None = None,
) -> Telemetry:
    # Date the oldest part of this observation. Dating completion instead would
    # let a slow inventory refresh the apparent age of already-stale evidence.
    observed_at = time.time()
    errors: list[str] = []
    system = platform.system().casefold()
    if system == "windows":
        with _windows_inventory_budget(), _windows_query_snapshot():
            boot_id = _boot_id(system)
            if boot_id == "unknown":
                errors.append("Windows boot identity is unavailable")
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
            ) = _windows_inventory(errors, boot_id=boot_id)
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
        observed_at=observed_at,
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
        boot_id=boot_id if system == "windows" else _boot_id(system),
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
