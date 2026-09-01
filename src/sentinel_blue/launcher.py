"""Scope-checked deployment planning for authorized competition systems."""

from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shlex
import shutil
import subprocess
import tempfile
import uuid
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .auth import derive_enrollment_ticket
from .config_validation import validate_bound_transport
from .event_profile import EventProfile, load_event_profile
from .net_safety import validate_http_origin
from .state import read_private_json, read_private_text


ALLOWED_TRANSPORTS = {"ssh", "winrm", "web-console", "agentless", "local", "auto"}
SAFE_USERNAME = re.compile(r"^[A-Za-z0-9_.@-]{1,128}$")
SAFE_POSIX_PATH = re.compile(r"^/[A-Za-z0-9_./-]{1,512}$")
SHA256_TEXT = re.compile(r"^[0-9a-fA-F]{64}$")
SAFE_AGENT_ID = re.compile(r"^[A-Za-z0-9_.:@-]{1,128}$")
RESERVED_AGENT_IDS = frozenset({"sentinel-relay-probes"})
REQUIRED_RUNTIME_ENTRIES = {
    "__main__.py",
    "sentinel_blue/__main__.py",
    "sentinel_blue/agent.py",
    "sentinel_blue/controller.py",
    "sentinel_blue/web/index.html",
}
MAX_RUNTIME_BYTES = 128 * 1024 * 1024
MAX_RUNTIME_ENTRIES = 4096


@dataclass(slots=True)
class DeploymentStep:
    host: str
    address: str
    platform: str
    transport: str
    operation: str
    requires: list[str]
    options: dict[str, Any]
    status: str = "planned"


def load_inventory(path: str | Path) -> dict[str, Any]:
    inventory_path = Path(path)
    data = read_private_json(inventory_path, 2 * 1024 * 1024)
    if not isinstance(data, dict) or not isinstance(data.get("hosts"), list):
        raise ValueError("inventory must contain a hosts array")
    if not isinstance(data.get("authorized_networks"), list) or not data["authorized_networks"]:
        raise ValueError("inventory must contain at least one authorized_networks entry")
    if len(data["authorized_networks"]) > 64:
        raise ValueError("inventory contains more than 64 authorized networks")
    for value in data["authorized_networks"]:
        ipaddress.ip_network(str(value), strict=False)
    shared_probe_config = "probes" in data or "protected_paths" in data
    for host in data["hosts"]:
        if not isinstance(host, dict):
            continue
        if shared_probe_config and not host.get("probe_config"):
            host["probe_config"] = str(inventory_path.resolve())
        elif host.get("probe_config"):
            probe_path = Path(str(host["probe_config"])).expanduser()
            if not probe_path.is_absolute():
                host["probe_config"] = str((inventory_path.parent / probe_path).resolve())
    if not data["hosts"] and data.get("auto_discover", False):
        from .discovery import discover_hosts

        data["hosts"] = discover_hosts([str(value) for value in data["authorized_networks"]])
    return data


def deployment_plan(
    inventory: dict[str, Any],
    package_url: str | None = None,
    event_profile: EventProfile | None = None,
) -> list[DeploymentStep]:
    if not isinstance(inventory, dict) or not isinstance(inventory.get("hosts"), list):
        raise ValueError("inventory must contain a hosts array")
    if len(inventory["hosts"]) > 1024:
        raise ValueError("inventory contains more than 1,024 hosts")
    if not isinstance(inventory.get("authorized_networks"), list) or not inventory["authorized_networks"]:
        raise ValueError("inventory must contain authorized_networks")
    networks = [ipaddress.ip_network(value, strict=False) for value in inventory["authorized_networks"]]
    if event_profile:
        event_profile.assert_inventory_networks(list(inventory["authorized_networks"]))
    if package_url:
        parsed = urlparse(package_url)
        if parsed.scheme != "https" or parsed.username or parsed.password or not parsed.hostname:
            raise ValueError("package URL must use HTTPS without embedded credentials")
    steps: list[DeploymentStep] = []
    seen: set[str] = set()
    seen_agent_ids: set[str] = set()
    for host in inventory["hosts"]:
        if not isinstance(host, dict):
            raise ValueError("each inventory host must be an object")
        if any(key in host for key in ("password", "secret", "private_key")):
            raise ValueError("inventories must not contain passwords or inline private keys")
        address = str(host["address"])
        ip = ipaddress.ip_address(address)
        if not any(ip in network for network in networks):
            raise ValueError(f"host {address} is outside the declared authorized networks")
        if event_profile:
            agent_id = host.get("agent_id")
            if not isinstance(agent_id, str) or not SAFE_AGENT_ID.fullmatch(agent_id):
                raise ValueError(
                    f"bound deployment requires an explicit valid agent_id for {address}"
                )
            if agent_id in RESERVED_AGENT_IDS:
                raise ValueError(f"bound deployment agent_id is reserved: {agent_id}")
            if agent_id in seen_agent_ids:
                raise ValueError(f"duplicate bound deployment agent_id: {agent_id}")
            seen_agent_ids.add(agent_id)
            event_profile.assert_target(address)
        if address in seen:
            raise ValueError(f"duplicate inventory address: {address}")
        seen.add(address)
        platform = str(host.get("platform", "unknown")).casefold()
        transport = str(host.get("transport", "auto")).casefold()
        if transport not in ALLOWED_TRANSPORTS:
            raise ValueError(f"unsupported transport {transport!r} for {address}")
        if transport == "auto":
            transport = "winrm" if platform == "windows" else "ssh" if platform == "linux" else "agentless"
        if transport == "winrm" and host.get(
            "install_directory", "C:\\ProgramData\\SentinelBlue"
        ) != "C:\\ProgramData\\SentinelBlue":
            raise ValueError("WinRM deployment currently requires C:\\ProgramData\\SentinelBlue")
        if event_profile:
            event_profile.assert_route(transport)
            default_path = (
                "C:\\ProgramData\\SentinelBlue"
                if platform == "windows"
                else "/opt/sentinel-blue"
            )
            event_profile.assert_deployment_path(
                str(host.get("install_directory", default_path))
            )
            if host.get("allow_containment") and not event_profile.allows("session_containment"):
                raise ValueError(f"session containment is not approved for {address}")
            if host.get("allow_restoration") and not event_profile.allows("file_restoration"):
                raise ValueError(f"file restoration is not approved for {address}")
        operation = "install-agent"
        requires = ["approved credentials", "reachable management service"]
        if transport == "web-console":
            operation = "inject-bootstrap"
            requires = ["authenticated portal session", "console clipboard or virtual keyboard"]
        if transport == "agentless":
            operation = "register-connector"
            requires = ["approved read-only API, SSH, SNMP, or log access"]
        if package_url:
            requires.append("VM internet access to the approved public release")
        else:
            requires.append("approved offline package transfer")
        steps.append(
            DeploymentStep(
                host=str(host.get("name", address)),
                address=address,
                platform=platform,
                transport=transport,
                operation=operation,
                requires=requires,
                options={
                    key: host[key]
                    for key in (
                        "username",
                        "key_file",
                        "python",
                        "allow_containment",
                        "allow_restoration",
                        "probe_config",
                        "install_directory",
                        "quarantine_ttl",
                        "known_hosts_file",
                        "accept_new_host_key",
                        "event_profile",
                        "controller_ca_file",
                        "range_deployment",
                        "agent_id",
                    )
                    if key in host
                }
                | (
                    {
                        "_enrollment_bound": True,
                        "_profile_fingerprint": event_profile.fingerprint,
                    }
                    if event_profile
                    else {}
                ),
            )
        )
    return steps


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_runtime_package(path: str | Path) -> dict[str, Any]:
    """Reject malformed, ambiguous, or unexpectedly large release archives."""
    package = Path(path)
    if package.is_symlink() or not package.is_file():
        raise ValueError(f"runtime package is unavailable or is a symlink: {package}")
    size = package.stat().st_size
    if size <= 0 or size > MAX_RUNTIME_BYTES:
        raise ValueError("runtime package size is outside the safe limit")
    if not zipfile.is_zipfile(package):
        raise ValueError("runtime package is not a valid zipapp archive")
    with zipfile.ZipFile(package) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_RUNTIME_ENTRIES:
            raise ValueError("runtime package contains too many entries")
        names: set[str] = set()
        total = 0
        for info in entries:
            raw = info.filename
            normalized = raw.replace("\\", "/")
            parts = Path(normalized).parts
            if (
                not normalized
                or normalized.startswith("/")
                or ".." in parts
                or any(":" in part for part in parts)
                or raw != normalized
                or normalized in names
            ):
                raise ValueError("runtime package contains an unsafe or duplicate path")
            names.add(normalized)
            total += int(info.file_size)
            if total > MAX_RUNTIME_BYTES:
                raise ValueError("runtime package expands beyond the safe limit")
            mode = (info.external_attr >> 16) & 0o170000
            if mode == 0o120000:
                raise ValueError("runtime package contains a symbolic link")
            if mode not in {0, 0o040000, 0o100000}:
                raise ValueError("runtime package contains a non-regular special file")
        missing = sorted(REQUIRED_RUNTIME_ENTRIES - names)
        if missing:
            raise ValueError(f"runtime package is incomplete: missing {', '.join(missing)}")
        for required in REQUIRED_RUNTIME_ENTRIES:
            if archive.getinfo(required).is_dir():
                raise ValueError(f"runtime package entry is not a file: {required}")
        bad = archive.testzip()
        if bad:
            raise ValueError(f"runtime package failed CRC validation at {bad}")
    return {
        "path": str(package.resolve()),
        "size_bytes": size,
        "entries": len(names),
        "expanded_bytes": total,
        "sha256": _sha256(package),
    }


def _run(command: list[str], timeout: float = 120.0) -> str:
    result = subprocess.run(command, text=True, capture_output=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "deployment command failed")
    return result.stdout.strip()


def _ssh_base(step: DeploymentStep) -> tuple[list[str], str]:
    username = str(step.options.get("username", "")).strip()
    if username and not SAFE_USERNAME.fullmatch(username):
        raise ValueError(f"invalid SSH username for {step.host}")
    target = f"{username}@{step.address}" if username else step.address
    strict_host_key = "accept-new" if step.options.get("accept_new_host_key") else "yes"
    base = [
        "-o", "BatchMode=yes",
        "-o", "ForwardAgent=no",
        "-o", "ClearAllForwardings=yes",
        "-o", f"StrictHostKeyChecking={strict_host_key}",
    ]
    known_hosts_file = step.options.get("known_hosts_file")
    if known_hosts_file:
        known_hosts_path = Path(str(known_hosts_file)).expanduser()
        if not known_hosts_path.is_file():
            raise ValueError(f"known-hosts file not found for {step.host}: {known_hosts_path}")
        base.extend(["-o", f"UserKnownHostsFile={known_hosts_path}"])
    key_file = step.options.get("key_file")
    if key_file:
        key_path = Path(str(key_file)).expanduser()
        if not key_path.is_file():
            raise ValueError(f"SSH key not found for {step.host}: {key_path}")
        base.extend(["-i", str(key_path)])
    return base, target


def _linux_unit(
    controller: str,
    package_path: str,
    state_dir: str,
    networks: list[str],
    containment: bool,
    restoration: bool,
    quarantine_ttl: float,
    probe_config: str | None = None,
    expected_package_sha256: str | None = None,
    event_profile: str | None = None,
    range_deployment: bool = False,
    agent_id: str | None = None,
    ca_file: str | None = None,
) -> str:
    args = [
        "/usr/bin/python3",
        package_path,
        "agent",
        "--controller",
        controller,
        "--state-dir",
        state_dir,
        "--quarantine-ttl",
        str(quarantine_ttl),
    ]
    for network in networks:
        args.extend(["--authorized-network", network])
    if expected_package_sha256:
        args.extend(["--expected-package-sha256", expected_package_sha256])
    if probe_config:
        args.extend(["--probe-config", probe_config])
    if event_profile:
        args.extend(["--event-profile", event_profile])
    if ca_file:
        args.extend(["--ca-file", ca_file])
    if range_deployment:
        args.append("--range-deployment")
    if agent_id:
        if not SAFE_AGENT_ID.fullmatch(agent_id):
            raise ValueError("Linux service agent_id contains unsupported characters")
        args.extend(["--agent-id", agent_id])
    if containment:
        args.append("--allow-containment")
    if restoration:
        args.append("--allow-restoration")
    command = " ".join(shlex.quote(value) for value in args)
    return "\n".join(
        (
            "[Unit]",
            "Description=Sentinel Blue defensive agent",
            "After=network-online.target",
            "Wants=network-online.target",
            "StartLimitIntervalSec=300",
            "StartLimitBurst=20",
            "",
            "[Service]",
            f"ExecStart={command}",
            "Restart=always",
            "RestartSec=5",
            "WatchdogSec=300",
            "NotifyAccess=main",
            "NoNewPrivileges=true",
            "PrivateTmp=true",
            *(("ProtectSystem=strict", "ProtectHome=true") if not restoration else ()),
            "ProtectKernelTunables=true",
            "ProtectKernelModules=true",
            "ProtectControlGroups=true",
            "LockPersonality=true",
            "RestrictSUIDSGID=true",
            "RestrictRealtime=true",
            "SystemCallArchitectures=native",
            f"ReadWritePaths={shlex.quote(state_dir)}",
            f"ReadOnlyPaths={shlex.quote(package_path)}",
            "",
            "[Install]",
            "WantedBy=multi-user.target",
            "",
        )
    )


def _validated_probe_config(step: DeploymentStep) -> Path | None:
    raw = step.options.get("probe_config")
    if not raw:
        return None
    path = Path(str(raw)).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"probe config not found or is a symlink for {step.host}: {path}")
    if path.stat().st_size > 1024 * 1024:
        raise ValueError(f"probe config exceeds 1 MiB for {step.host}")
    payload = read_private_json(path, 1024 * 1024)
    if not isinstance(payload, dict):
        raise ValueError(f"probe config must be an object for {step.host}")
    if not isinstance(payload.get("probes", []), list):
        raise ValueError(f"probe config probes must be an array for {step.host}")
    if not isinstance(payload.get("protected_paths", []), list):
        raise ValueError(f"probe config protected_paths must be an array for {step.host}")
    probes = payload.get("probes", [])
    protected_paths = payload.get("protected_paths", [])
    if len(probes) > 256 or len(protected_paths) > 256:
        raise ValueError(f"probe config exceeds 256 probes or paths for {step.host}")
    if any(not isinstance(item, str) or not item or len(item) > 1024 for item in protected_paths):
        raise ValueError(f"probe config contains an invalid protected path for {step.host}")
    for probe in probes:
        if not isinstance(probe, dict):
            raise ValueError(f"probe config entries must be objects for {step.host}")
        patterns = probe.get("restore_paths")
        if patterns is not None and (
            not isinstance(patterns, list)
            or not patterns
            or len(patterns) > 64
            or any(not isinstance(item, str) or not item or len(item) > 1024 for item in patterns)
        ):
            raise ValueError(f"probe restore_paths are invalid for {step.host}")
    return path


def _validated_event_profile(step: DeploymentStep) -> Path:
    raw = step.options.get("event_profile")
    if not raw:
        raise ValueError(f"event profile is required for {step.host}")
    path = Path(str(raw)).expanduser()
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        raise ValueError(f"event profile is unavailable, unsafe, or oversized for {step.host}")
    profile = load_event_profile(path)
    profile.require_runtime_ready(
        range_deployment=bool(step.options.get("range_deployment", False))
    )
    profile.assert_target(step.address)
    profile.assert_route(step.transport)
    return path


def _validated_controller_ca(step: DeploymentStep, profile_path: Path) -> Path:
    raw = step.options.get("controller_ca_file")
    if not raw:
        raise ValueError(f"controller CA certificate is required for {step.host}")
    path = Path(str(raw)).expanduser()
    profile = load_event_profile(profile_path)
    profile.verify_controller_ca_file(path)
    return path


def _deploy_ssh(
    step: DeploymentStep,
    package: Path,
    checksum: str,
    controller: str,
    token: str,
    networks: list[str],
) -> dict[str, Any]:
    ssh_options, target = _ssh_base(step)
    deployment_nonce = uuid.uuid4().hex[:16]
    remote_stage = f"/tmp/sentinel-blue-{checksum[:12]}-{deployment_nonce}.pyz"
    remote_token_stage = f"/tmp/sentinel-blue-enroll-{deployment_nonce}.json"
    remote_unit_stage = f"/tmp/sentinel-blue-{deployment_nonce}.service"
    install_dir = str(step.options.get("install_directory", "/opt/sentinel-blue"))
    if not SAFE_POSIX_PATH.fullmatch(install_dir) or ".." in Path(install_dir).parts:
        raise ValueError("Linux install_directory must be a safe absolute path")
    remote_package = f"{install_dir}/sentinel-blue.pyz"
    state_dir = "/var/lib/sentinel-blue"
    remote_token = f"{state_dir}/enrollment.json"
    local_probe_config = _validated_probe_config(step)
    local_event_profile = _validated_event_profile(step)
    local_controller_ca = _validated_controller_ca(step, local_event_profile)
    remote_probe_stage = f"/tmp/sentinel-blue-probes-{deployment_nonce}.json"
    remote_probe = f"{state_dir}/probes.json" if local_probe_config else None
    remote_profile_stage = f"/tmp/sentinel-blue-profile-{deployment_nonce}.json"
    remote_profile = f"{state_dir}/event-profile.json"
    remote_ca_stage = f"/tmp/sentinel-blue-controller-ca-{deployment_nonce}.crt"
    remote_ca = f"{state_dir}/controller-ca.crt"
    containment = bool(step.options.get("allow_containment", False))
    restoration = bool(step.options.get("allow_restoration", False))
    quarantine_ttl = max(30.0, min(float(step.options.get("quarantine_ttl", 300.0)), 3600.0))
    with tempfile.TemporaryDirectory(prefix="sentinel-blue-deploy-") as directory:
        token_file = Path(directory) / "enrollment.json"
        token_file.write_text(json.dumps({"token": token}), encoding="utf-8")
        if os.name == "posix":
            token_file.chmod(0o600)
        unit_file = Path(directory) / "sentinel-blue.service"
        unit_file.write_text(
            _linux_unit(
                controller,
                remote_package,
                state_dir,
                networks,
                containment,
                restoration,
                quarantine_ttl,
                remote_probe,
                checksum,
                remote_profile,
                bool(step.options.get("range_deployment", False)),
                str(step.options.get("agent_id", "")) or None,
                remote_ca,
            ),
            encoding="utf-8",
        )
        _run(["scp", *ssh_options, str(package), f"{target}:{remote_stage}"])
        _run(["scp", *ssh_options, str(unit_file), f"{target}:{remote_unit_stage}"])
        _run(["scp", *ssh_options, str(token_file), f"{target}:{remote_token_stage}"])
        _run(["scp", *ssh_options, str(local_event_profile), f"{target}:{remote_profile_stage}"])
        _run(["scp", *ssh_options, str(local_controller_ca), f"{target}:{remote_ca_stage}"])
        if local_probe_config:
            _run(["scp", *ssh_options, str(local_probe_config), f"{target}:{remote_probe_stage}"])
        python_command = str(step.options.get("python", "python3"))
        if not SAFE_USERNAME.fullmatch(python_command):
            raise ValueError("invalid remote Python command")
        bootstrap_args = [
            python_command,
            remote_package,
            "agent",
            "--controller",
            controller,
            "--token-file",
            remote_token,
            "--state-dir",
            state_dir,
            "--once",
            "--expected-package-sha256",
            checksum,
            "--event-profile",
            remote_profile,
            "--ca-file",
            remote_ca,
        ]
        agent_id = str(step.options.get("agent_id", ""))
        if agent_id:
            if not SAFE_AGENT_ID.fullmatch(agent_id):
                raise ValueError("SSH deployment agent_id contains unsupported characters")
            bootstrap_args.extend(["--agent-id", agent_id])
        if step.options.get("range_deployment", False):
            bootstrap_args.append("--range-deployment")
        for network in networks:
            bootstrap_args.extend(["--authorized-network", network])
        if remote_probe:
            bootstrap_args.extend(["--probe-config", remote_probe])
        bootstrap = " ".join(shlex.quote(value) for value in bootstrap_args)
        cleanup = (
            f"rm -f {shlex.quote(remote_stage)} {shlex.quote(remote_token_stage)} "
            f"{shlex.quote(remote_probe_stage)} {shlex.quote(remote_profile_stage)} "
            f"{shlex.quote(remote_ca_stage)} {shlex.quote(remote_unit_stage)}; "
            f"sudo -n rm -f {shlex.quote(remote_token)}"
        )
        rollback_dir = f"/tmp/sentinel-blue-rollback-{deployment_nonce}"
        backup_package = f"{rollback_dir}/sentinel-blue.pyz"
        backup_probe = f"{rollback_dir}/probes.json"
        backup_profile = f"{rollback_dir}/event-profile.json"
        backup_ca = f"{rollback_dir}/controller-ca.crt"
        backup_unit = f"{rollback_dir}/sentinel-blue.service"
        rollback = " ".join(
            (
                "status=$?; set +e; rollback_failed=0;",
                cleanup + " || rollback_failed=1;",
                "if [ $status -ne 0 ]; then",
                f"if sudo -n test -f {shlex.quote(backup_package)}; then sudo -n install -m 0755 {shlex.quote(backup_package)} {shlex.quote(remote_package)} || rollback_failed=1; else sudo -n rm -f {shlex.quote(remote_package)} || rollback_failed=1; fi;",
                *(
                    (
                        f"if sudo -n test -f {shlex.quote(backup_probe)}; then sudo -n install -m 0600 {shlex.quote(backup_probe)} {shlex.quote(remote_probe)} || rollback_failed=1; else sudo -n rm -f {shlex.quote(remote_probe)} || rollback_failed=1; fi;",
                    )
                    if remote_probe
                    else ()
                ),
                f"if sudo -n test -f {shlex.quote(backup_ca)}; then sudo -n install -m 0644 {shlex.quote(backup_ca)} {shlex.quote(remote_ca)} || rollback_failed=1; else sudo -n rm -f {shlex.quote(remote_ca)} || rollback_failed=1; fi;",
                f"if sudo -n test -f {shlex.quote(backup_profile)}; then sudo -n install -m 0600 {shlex.quote(backup_profile)} {shlex.quote(remote_profile)} || rollback_failed=1; else sudo -n rm -f {shlex.quote(remote_profile)} || rollback_failed=1; fi;",
                f"if sudo -n test -f {shlex.quote(backup_unit)}; then sudo -n install -m 0644 {shlex.quote(backup_unit)} /etc/systemd/system/sentinel-blue.service || rollback_failed=1; else sudo -n rm -f /etc/systemd/system/sentinel-blue.service || rollback_failed=1; fi;",
                "sudo -n systemctl daemon-reload || rollback_failed=1;",
                f"if sudo -n test -f {shlex.quote(backup_unit)}; then sudo -n systemctl try-restart sentinel-blue.service || rollback_failed=1; fi;",
                "fi;",
                f"if [ $rollback_failed -eq 0 ]; then sudo -n rm -rf {shlex.quote(rollback_dir)}; else echo 'Sentinel Blue rollback evidence preserved at {rollback_dir}' >&2; fi;",
                "exit $status",
            )
        )
        commands = [
            "set -eu",
            f"sudo -n mkdir -p {shlex.quote(install_dir)} {shlex.quote(state_dir)}",
            f"sudo -n rm -rf {shlex.quote(rollback_dir)}",
            f"sudo -n mkdir -p {shlex.quote(rollback_dir)}",
            f"sudo -n test ! -f {shlex.quote(remote_package)} || sudo -n cp -p {shlex.quote(remote_package)} {shlex.quote(backup_package)}",
            *(
                [f"sudo -n test ! -f {shlex.quote(remote_probe)} || sudo -n cp -p {shlex.quote(remote_probe)} {shlex.quote(backup_probe)}"]
                if remote_probe
                else []
            ),
            f"sudo -n test ! -f {shlex.quote(remote_ca)} || sudo -n cp -p {shlex.quote(remote_ca)} {shlex.quote(backup_ca)}",
            f"sudo -n test ! -f {shlex.quote(remote_profile)} || sudo -n cp -p {shlex.quote(remote_profile)} {shlex.quote(backup_profile)}",
            f"sudo -n test ! -f /etc/systemd/system/sentinel-blue.service || sudo -n cp -p /etc/systemd/system/sentinel-blue.service {shlex.quote(backup_unit)}",
            f"trap {shlex.quote(rollback)} EXIT",
            f"test \"$(sha256sum {shlex.quote(remote_stage)} | cut -d' ' -f1)\" = {shlex.quote(checksum)}",
            f"sudo -n install -m 0755 {shlex.quote(remote_stage)} {shlex.quote(remote_package)}",
            f"sudo -n install -m 0600 {shlex.quote(remote_token_stage)} {shlex.quote(remote_token)}",
            *(
                [f"sudo -n install -m 0600 {shlex.quote(remote_probe_stage)} {shlex.quote(remote_probe)}"]
                if remote_probe
                else []
            ),
            f"sudo -n install -m 0644 {shlex.quote(remote_ca_stage)} {shlex.quote(remote_ca)}",
            f"sudo -n install -m 0600 {shlex.quote(remote_profile_stage)} {shlex.quote(remote_profile)}",
            f"sudo -n {bootstrap}",
            f"sudo -n install -m 0644 {shlex.quote(remote_unit_stage)} /etc/systemd/system/sentinel-blue.service",
            "sudo -n systemctl daemon-reload",
            "sudo -n systemctl enable --now sentinel-blue.service",
            f"test \"$(sudo -n sha256sum {shlex.quote(remote_package)} | cut -d' ' -f1)\" = {shlex.quote(checksum)}",
            "sudo -n systemctl is-active --quiet sentinel-blue.service",
            f"sudo -n /usr/bin/python3 {shlex.quote(remote_package)} --version",
            "trap - EXIT",
            f"rm -f {shlex.quote(remote_stage)} {shlex.quote(remote_token_stage)} {shlex.quote(remote_probe_stage)} {shlex.quote(remote_profile_stage)} {shlex.quote(remote_ca_stage)} {shlex.quote(remote_unit_stage)}",
            f"sudo -n rm -rf {shlex.quote(rollback_dir)}",
        ]
        output = _run(["ssh", *ssh_options, target, " && ".join(commands)], timeout=180)
    return {
        "status": "deployed",
        "verified": True,
        "transport": "ssh",
        "host": step.host,
        "package_sha256": checksum,
        "output": output[-1000:],
    }


def _powershell_executable() -> str:
    for candidate in ("pwsh", "powershell.exe", "powershell"):
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError("PowerShell is required for WinRM deployment")


def _deploy_winrm(
    step: DeploymentStep,
    package: Path,
    checksum: str,
    controller: str,
    token: str,
    networks: list[str],
) -> dict[str, Any]:
    powershell = _powershell_executable()
    local_probe_config = _validated_probe_config(step)
    local_event_profile = _validated_event_profile(step)
    local_controller_ca = _validated_controller_ca(step, local_event_profile)
    with tempfile.TemporaryDirectory(prefix="sentinel-blue-winrm-") as directory:
        token_file = Path(directory) / "enrollment.json"
        token_file.write_text(json.dumps({"token": token}), encoding="utf-8")
        escaped_networks = [value.replace("'", "''") for value in networks]
        network_args = " ".join(
            "--authorized-network '" + value + "'" for value in escaped_networks
        )
        containment = " --allow-containment" if step.options.get("allow_containment") else ""
        restoration = " --allow-restoration" if step.options.get("allow_restoration") else ""
        range_argument = (
            " --range-deployment" if step.options.get("range_deployment", False) else ""
        )
        agent_id = str(step.options.get("agent_id", ""))
        if agent_id and not SAFE_AGENT_ID.fullmatch(agent_id):
            raise ValueError("WinRM deployment agent_id contains unsupported characters")
        agent_argument = " --agent-id '" + agent_id + "'" if agent_id else ""
        integrity_argument = f" --expected-package-sha256 {checksum}"
        ca_argument = " --ca-file C:\\ProgramData\\SentinelBlue\\controller-ca.crt"
        probe_argument = (
            " --probe-config C:\\ProgramData\\SentinelBlue\\probes.json"
            if local_probe_config
            else ""
        )
        incoming_nonce = secrets.token_hex(8)
        incoming_package = f"sentinel-blue.{incoming_nonce}.incoming.pyz"
        incoming_token = f"enrollment.{incoming_nonce}.incoming.json"
        incoming_probe = f"probes.{incoming_nonce}.incoming.json"
        incoming_profile = f"event-profile.{incoming_nonce}.incoming.json"
        incoming_ca = f"controller-ca.{incoming_nonce}.incoming.crt"
        probe_copy = (
            "  Copy-Item -ToSession $session -Path '"
            + str(local_probe_config).replace("'", "''")
            + f"' -Destination 'C:\\ProgramData\\SentinelBlue\\{incoming_probe}'\n"
            if local_probe_config
            else ""
        )
        profile_copy = (
            "  Copy-Item -ToSession $session -Path '"
            + str(local_event_profile).replace("'", "''")
            + f"' -Destination 'C:\\ProgramData\\SentinelBlue\\{incoming_profile}'\n"
        )
        ca_copy = (
            "  Copy-Item -ToSession $session -Path '"
            + str(local_controller_ca).replace("'", "''")
            + f"' -Destination 'C:\\ProgramData\\SentinelBlue\\{incoming_ca}'\n"
        )
        quarantine_ttl = max(30.0, min(float(step.options.get("quarantine_ttl", 300.0)), 3600.0))
        script = f"""
$ErrorActionPreference = 'Stop'
$session = New-PSSession -ComputerName '{step.address}'
try {{
  Invoke-Command -Session $session -ScriptBlock {{ New-Item -ItemType Directory -Force -Path 'C:\\ProgramData\\SentinelBlue' | Out-Null }}
  Invoke-Command -Session $session -ScriptBlock {{ icacls 'C:\\ProgramData\\SentinelBlue' /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null; if ($LASTEXITCODE -ne 0) {{ throw 'Sentinel Blue ACL setup failed' }} }}
  Copy-Item -ToSession $session -Path '{str(package).replace("'", "''")}' -Destination 'C:\\ProgramData\\SentinelBlue\\{incoming_package}'
  Copy-Item -ToSession $session -Path '{str(token_file).replace("'", "''")}' -Destination 'C:\\ProgramData\\SentinelBlue\\{incoming_token}'
{probe_copy}{profile_copy}{ca_copy}  Invoke-Command -Session $session -ScriptBlock {{
    $root = 'C:\\ProgramData\\SentinelBlue'
    $package = Join-Path $root 'sentinel-blue.pyz'
    $probe = Join-Path $root 'probes.json'
    $profile = Join-Path $root 'event-profile.json'
    $controllerCa = Join-Path $root 'controller-ca.crt'
    $rollback = Join-Path $env:TEMP ('sentinel-blue-rollback-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $rollback | Out-Null
    $retainRollback = $false
    $hadPackage = Test-Path -LiteralPath $package -PathType Leaf
    $hadProbe = Test-Path -LiteralPath $probe -PathType Leaf
    $hadProfile = Test-Path -LiteralPath $profile -PathType Leaf
    $hadControllerCa = Test-Path -LiteralPath $controllerCa -PathType Leaf
    if ($hadPackage) {{ Copy-Item -LiteralPath $package -Destination (Join-Path $rollback 'sentinel-blue.pyz') }}
    if ($hadProbe) {{ Copy-Item -LiteralPath $probe -Destination (Join-Path $rollback 'probes.json') }}
    if ($hadProfile) {{ Copy-Item -LiteralPath $profile -Destination (Join-Path $rollback 'event-profile.json') }}
    if ($hadControllerCa) {{ Copy-Item -LiteralPath $controllerCa -Destination (Join-Path $rollback 'controller-ca.crt') }}
    $oldTask = Get-ScheduledTask -TaskName 'SentinelBlueAgent' -ErrorAction SilentlyContinue
    $oldTaskXml = if ($oldTask) {{ Export-ScheduledTask -TaskName 'SentinelBlueAgent' }} else {{ $null }}
    if ($oldTask) {{ Stop-ScheduledTask -TaskName 'SentinelBlueAgent' -ErrorAction Stop }}
    try {{
      Move-Item -Force (Join-Path $root '{incoming_package}') $package
      Move-Item -Force (Join-Path $root '{incoming_token}') (Join-Path $root 'enrollment.json')
      if (Test-Path -LiteralPath (Join-Path $root '{incoming_probe}')) {{ Move-Item -Force (Join-Path $root '{incoming_probe}') $probe }}
      Move-Item -Force (Join-Path $root '{incoming_profile}') $profile
      Move-Item -Force (Join-Path $root '{incoming_ca}') $controllerCa
      if ((Get-FileHash -Algorithm SHA256 $package).Hash.ToLowerInvariant() -ne '{checksum}') {{ throw 'Sentinel Blue package checksum mismatch' }}
      py -3 $package agent --controller '{controller}' --token-file C:\\ProgramData\\SentinelBlue\\enrollment.json --state-dir C:\\ProgramData\\SentinelBlue\\state --event-profile C:\\ProgramData\\SentinelBlue\\event-profile.json --once {network_args}{probe_argument}{integrity_argument}{ca_argument}{range_argument}{agent_argument}
      if ($LASTEXITCODE -ne 0) {{ throw ('Sentinel Blue enrollment failed with exit code ' + $LASTEXITCODE) }}
      $action = New-ScheduledTaskAction -Execute 'py.exe' -Argument '-3 C:\\ProgramData\\SentinelBlue\\sentinel-blue.pyz agent --controller {controller} --state-dir C:\\ProgramData\\SentinelBlue\\state --event-profile C:\\ProgramData\\SentinelBlue\\event-profile.json --log-file C:\\ProgramData\\SentinelBlue\\state\\agent.log --log-max-bytes 5242880 --log-backups 3 --quarantine-ttl {quarantine_ttl} {network_args}{containment}{restoration}{probe_argument}{integrity_argument}{ca_argument}{range_argument}{agent_argument}'
      $trigger = New-ScheduledTaskTrigger -AtStartup
      $settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew
      Register-ScheduledTask -TaskName 'SentinelBlueAgent' -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
      Start-ScheduledTask -TaskName 'SentinelBlueAgent'
      Get-ScheduledTask -TaskName 'SentinelBlueAgent' -ErrorAction Stop | Out-Null
      Start-Sleep -Seconds 2
      $taskInfo = Get-ScheduledTaskInfo -TaskName 'SentinelBlueAgent' -ErrorAction Stop
      if ($taskInfo.LastTaskResult -notin @(0,267009)) {{ throw ('Sentinel Blue task failed with result ' + $taskInfo.LastTaskResult) }}
      if ((Get-FileHash -Algorithm SHA256 $package).Hash.ToLowerInvariant() -ne '{checksum}') {{ throw 'Sentinel Blue post-install checksum mismatch' }}
      py -3 $package --version | Out-Null
      if ($LASTEXITCODE -ne 0) {{ throw ('Sentinel Blue runtime check failed with exit code ' + $LASTEXITCODE) }}
    }} catch {{
      try {{
        Unregister-ScheduledTask -TaskName 'SentinelBlueAgent' -Confirm:$false -ErrorAction SilentlyContinue
        if ($hadPackage) {{ Copy-Item -Force (Join-Path $rollback 'sentinel-blue.pyz') $package }} else {{ Remove-Item -Force -ErrorAction SilentlyContinue $package }}
        if ($hadProbe) {{ Copy-Item -Force (Join-Path $rollback 'probes.json') $probe }} else {{ Remove-Item -Force -ErrorAction SilentlyContinue $probe }}
        if ($hadProfile) {{ Copy-Item -Force (Join-Path $rollback 'event-profile.json') $profile }} else {{ Remove-Item -Force -ErrorAction SilentlyContinue $profile }}
        if ($hadControllerCa) {{ Copy-Item -Force (Join-Path $rollback 'controller-ca.crt') $controllerCa }} else {{ Remove-Item -Force -ErrorAction SilentlyContinue $controllerCa }}
        if ($oldTaskXml) {{
          Register-ScheduledTask -TaskName 'SentinelBlueAgent' -Xml $oldTaskXml -Force | Out-Null
          Start-ScheduledTask -TaskName 'SentinelBlueAgent'
        }}
      }} catch {{
        $retainRollback = $true
        throw
      }}
      throw
    }} finally {{
      if (-not $retainRollback) {{ Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $rollback }}
    }}
  }}
}} finally {{
  if ($session) {{
    Invoke-Command -Session $session -ScriptBlock {{ Remove-Item -Force -ErrorAction SilentlyContinue 'C:\\ProgramData\\SentinelBlue\\enrollment.json','C:\\ProgramData\\SentinelBlue\\{incoming_token}','C:\\ProgramData\\SentinelBlue\\{incoming_package}','C:\\ProgramData\\SentinelBlue\\{incoming_probe}','C:\\ProgramData\\SentinelBlue\\{incoming_profile}','C:\\ProgramData\\SentinelBlue\\{incoming_ca}' }}
    Remove-PSSession $session
  }}
}}
"""
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        output = _run([powershell, "-NoLogo", "-NoProfile", "-EncodedCommand", encoded], timeout=240)
    return {
        "status": "deployed",
        "verified": True,
        "transport": "winrm",
        "host": step.host,
        "package_sha256": checksum,
        "output": output[-1000:],
    }


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_file(path: Path) -> None:
    if os.name != "posix":
        return
    with path.open("rb") as handle:
        os.fsync(handle.fileno())


def _publish_local_transaction(
    destination: Path,
    staged: dict[str, tuple[Path, int]],
) -> None:
    """Publish staged deployment files and restore the prior set on any failure."""
    rollback = destination / f".sentinel-rollback-{uuid.uuid4().hex}"
    rollback.mkdir(mode=0o700)
    replaced: list[str] = []
    backups: list[str] = []
    cleanup_rollback = True
    try:
        for name in staged:
            target = destination / name
            if target.is_symlink():
                raise ValueError(f"refusing to replace symbolic-link deployment target: {target}")
            if target.exists():
                os.replace(target, rollback / name)
                backups.append(name)
        for name, (source, mode) in staged.items():
            os.chmod(source, mode)
            os.replace(source, destination / name)
            replaced.append(name)
        _fsync_directory(destination)
    except Exception:
        try:
            for name in reversed(replaced):
                (destination / name).unlink(missing_ok=True)
            for name in reversed(backups):
                backup = rollback / name
                if backup.exists() or backup.is_symlink():
                    os.replace(backup, destination / name)
            _fsync_directory(destination)
        except Exception as rollback_error:
            cleanup_rollback = False
            raise RuntimeError(
                f"deployment rollback was incomplete; preserved recovery files at {rollback}: {rollback_error}"
            ) from rollback_error
        raise
    finally:
        if cleanup_rollback:
            shutil.rmtree(rollback, ignore_errors=True)


def _deploy_local(
    step: DeploymentStep,
    package: Path,
    checksum: str,
    controller: str,
    token: str,
    networks: list[str],
) -> dict[str, Any]:
    default_destination = (
        "C:\\ProgramData\\SentinelBlue"
        if step.platform == "windows"
        else "/opt/sentinel-blue"
    )
    destination = Path(str(step.options.get("install_directory", default_destination)))
    if destination.is_symlink():
        raise ValueError("local install_directory must not be a symbolic link")
    local_probe_config = _validated_probe_config(step)
    local_event_profile = _validated_event_profile(step)
    local_controller_ca = _validated_controller_ca(step, local_event_profile)
    destination.mkdir(parents=True, exist_ok=True)
    lock_path = destination / ".sentinel-deploy.lock"
    if lock_path.is_symlink():
        raise ValueError("local deployment lock must not be a symbolic link")
    try:
        lock_descriptor = os.open(
            lock_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
    except FileExistsError as exc:
        raise RuntimeError(
            f"another or interrupted deployment owns {lock_path}; review it before retrying"
        ) from exc
    transaction = destination / f".sentinel-stage-{uuid.uuid4().hex}"
    try:
        os.write(lock_descriptor, f"pid={os.getpid()}\n".encode())
        os.fsync(lock_descriptor)
    finally:
        os.close(lock_descriptor)
    transaction.mkdir(mode=0o700)
    installed = destination / "sentinel-blue.pyz"
    token_file = destination / "enrollment.json"
    staged_probe_config = None
    staged: dict[str, tuple[Path, int]] = {}
    try:
        staged_package = transaction / "sentinel-blue.pyz"
        shutil.copyfile(package, staged_package)
        if _sha256(staged_package) != checksum:
            raise RuntimeError("local staged package checksum mismatch")
        _fsync_file(staged_package)
        staged["sentinel-blue.pyz"] = (staged_package, 0o755)
        staged_token = transaction / "enrollment.json"
        staged_token.write_text(json.dumps({"token": token}), encoding="utf-8")
        _fsync_file(staged_token)
        staged["enrollment.json"] = (staged_token, 0o600)
        if local_probe_config:
            staged_probe = transaction / "probes.json"
            shutil.copyfile(local_probe_config, staged_probe)
            _fsync_file(staged_probe)
            staged["probes.json"] = (staged_probe, 0o600)
            staged_probe_config = destination / "probes.json"
        staged_profile = transaction / "event-profile.json"
        shutil.copyfile(local_event_profile, staged_profile)
        _fsync_file(staged_profile)
        staged["event-profile.json"] = (staged_profile, 0o600)
        staged_ca = transaction / "controller-ca.crt"
        shutil.copyfile(local_controller_ca, staged_ca)
        _fsync_file(staged_ca)
        staged["controller-ca.crt"] = (staged_ca, 0o644)
        _fsync_directory(transaction)
        _publish_local_transaction(destination, staged)
    finally:
        shutil.rmtree(transaction, ignore_errors=True)
        lock_path.unlink(missing_ok=True)
        _fsync_directory(destination)
    return {
        "status": "staged",
        "verified": True,
        "transport": "local",
        "host": step.host,
        "package": str(installed),
        "token_file": str(token_file),
        "controller": controller,
        "authorized_networks": networks,
        "package_sha256": checksum,
        "probe_config": str(staged_probe_config) if staged_probe_config else None,
        "event_profile": str(destination / "event-profile.json"),
        "ca_file": str(destination / "controller-ca.crt"),
        "agent_id": str(step.options.get("agent_id", "")) or None,
    }


def _validate_controller_origin(controller: str) -> None:
    validate_http_origin(controller)


def deployment_preflight(
    plan: list[DeploymentStep],
    package: Path | None,
    expected_checksum: str | None = None,
    controller: str | None = None,
) -> dict[str, Any]:
    """Perform non-mutating local checks before deployment is attempted."""
    global_blockers: list[str] = []
    package_checksum = None
    if package is None or not package.is_file():
        global_blockers.append("a readable local release package is required")
    else:
        try:
            package_report = validate_runtime_package(package)
            package_checksum = str(package_report["sha256"])
        except (OSError, ValueError, zipfile.BadZipFile) as exc:
            global_blockers.append(str(exc))
            package_checksum = _sha256(package)
        if expected_checksum:
            if not SHA256_TEXT.fullmatch(expected_checksum):
                global_blockers.append("expected package checksum is not a SHA-256 digest")
            elif package_checksum.casefold() != expected_checksum.casefold():
                global_blockers.append("package checksum does not match the expected value")
    if controller:
        try:
            _validate_controller_origin(controller)
        except ValueError as exc:
            global_blockers.append(str(exc))

    hosts: list[dict[str, Any]] = []
    for step in plan:
        blockers: list[str] = []
        warnings: list[str] = []
        try:
            _validated_probe_config(step)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            blockers.append(str(exc))
        try:
            _validated_event_profile(step)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            blockers.append(str(exc))
        if step.platform not in {"linux", "windows"} and step.transport not in {"local", "agentless"}:
            blockers.append(f"unsupported or unknown platform: {step.platform}")
        if step.transport == "ssh":
            for command in ("ssh", "scp"):
                if not shutil.which(command):
                    blockers.append(f"required local command is unavailable: {command}")
            try:
                _ssh_base(step)
            except ValueError as exc:
                blockers.append(str(exc))
        elif step.transport == "winrm":
            if not any(shutil.which(item) for item in ("pwsh", "powershell.exe", "powershell")):
                blockers.append("PowerShell is unavailable for WinRM deployment")
        elif step.transport in {"web-console", "agentless"}:
            warnings.append(
                "this transport requires an event- and portal-specific approved adapter"
            )
        if step.options.get("allow_restoration") and not step.options.get("probe_config"):
            warnings.append(
                "restoration is enabled without a host probe/protected-path configuration"
            )
        hosts.append(
            {
                "host": step.host,
                "address": step.address,
                "platform": step.platform,
                "transport": step.transport,
                "ready": not blockers,
                "blockers": blockers,
                "warnings": warnings,
            }
        )
    ready = not global_blockers and all(item["ready"] for item in hosts)
    return {
        "mode": "non-mutating deployment preflight",
        "ready": ready,
        "package_sha256": package_checksum,
        "global_blockers": global_blockers,
        "hosts": hosts,
        "network_reachability_tested": False,
        "note": "Run this on the actual competition laptop; portal and target reachability remain environment-specific.",
    }


def execute_plan(
    plan: list[DeploymentStep],
    inventory: dict[str, Any],
    package: Path,
    expected_checksum: str | None,
    controller: str,
    token: str,
) -> list[dict[str, Any]]:
    package_report = validate_runtime_package(package)
    checksum = str(package_report["sha256"])
    if expected_checksum and checksum.casefold() != expected_checksum.casefold():
        raise ValueError("package checksum does not match --checksum")
    _validate_controller_origin(controller)
    if len(token) < 16:
        raise ValueError("deployment token must be at least 16 characters")
    networks = [str(value) for value in inventory["authorized_networks"]]
    results: list[dict[str, Any]] = []
    for step in plan:
        try:
            deployment_token = token
            if step.options.get("_enrollment_bound"):
                agent_id = step.options.get("agent_id")
                profile_fingerprint = step.options.get("_profile_fingerprint")
                if not isinstance(agent_id, str) or not SAFE_AGENT_ID.fullmatch(agent_id):
                    raise ValueError(
                        f"bound deployment requires an explicit valid agent_id for {step.host}"
                    )
                if not isinstance(profile_fingerprint, str):
                    raise ValueError("bound deployment is missing its profile fingerprint")
                deployment_token = derive_enrollment_ticket(
                    token, profile_fingerprint, agent_id
                )
            if step.transport == "ssh":
                result = _deploy_ssh(
                    step, package, checksum, controller, deployment_token, networks
                )
            elif step.transport == "winrm":
                result = _deploy_winrm(
                    step, package, checksum, controller, deployment_token, networks
                )
            elif step.transport == "local":
                result = _deploy_local(
                    step, package, checksum, controller, deployment_token, networks
                )
            else:
                result = {
                    "status": "adapter-required",
                    "transport": step.transport,
                    "host": step.host,
                    "reason": "portal-console and agentless devices use their approved adapter",
                }
        except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
            result = {"status": "failed", "transport": step.transport, "host": step.host, "error": str(exc)}
        results.append(result)
    return results


def run(args: argparse.Namespace) -> None:
    inventory = load_inventory(args.inventory)
    profile_path = Path(args.event_profile or args.inventory).resolve()
    event_profile = load_event_profile(profile_path)
    range_deployment = bool(getattr(args, "range_deployment", False))
    event_profile.require_runtime_ready(range_deployment=range_deployment)
    if args.preflight or args.execute:
        validate_bound_transport(
            event_profile,
            role="launcher",
            controller=args.controller,
            ca_file=args.ca_file,
        )
    if args.package_url and args.package_url != event_profile.release.get("public_url"):
        raise ValueError("--package-url does not match the approved public release URL")
    event_profile.assert_inventory_networks(list(inventory["authorized_networks"]))
    for host in inventory["hosts"]:
        if isinstance(host, dict):
            host["event_profile"] = str(profile_path)
            if args.ca_file:
                host["controller_ca_file"] = str(Path(args.ca_file).resolve())
            host["range_deployment"] = range_deployment
    approved_checksum = str(event_profile.release.get("sha256", "")).casefold()
    if approved_checksum and not SHA256_TEXT.fullmatch(approved_checksum):
        raise ValueError("event profile release.sha256 is not a SHA-256 digest")
    if args.checksum and approved_checksum and args.checksum.casefold() != approved_checksum:
        raise ValueError("--checksum does not match the event-profile approved release")
    expected_checksum = args.checksum or approved_checksum or None
    plan = deployment_plan(inventory, args.package_url, event_profile)
    if args.preflight:
        report = deployment_preflight(
            plan,
            Path(args.package) if args.package else None,
            expected_checksum,
            args.controller,
        )
        print(json.dumps(report, indent=2))
        if not report["ready"]:
            raise SystemExit(2)
        return
    if args.execute:
        if not args.yes:
            raise SystemExit("--execute requires --yes to confirm the exact authorized inventory")
        if not args.package or not args.controller or not (args.token or args.token_file):
            raise SystemExit("--execute requires --package, --controller, and --token or --token-file")
        token = args.token or read_private_text(args.token_file, 64 * 1024).strip()
        try:
            token_payload = json.loads(token)
            token = str(token_payload.get("token", ""))
        except json.JSONDecodeError:
            pass
        results = execute_plan(
            plan,
            inventory,
            Path(args.package),
            expected_checksum,
            args.controller,
            token,
        )
        print(
            json.dumps(
                {
                    "checksum": _sha256(Path(args.package)),
                    "profile_id": event_profile.profile_id,
                    "profile_fingerprint": event_profile.fingerprint,
                    "results": results,
                },
                indent=2,
            )
        )
        if any(result.get("status") == "failed" for result in results):
            raise SystemExit(2)
        return
    print(
        json.dumps(
            {
                "profile_id": event_profile.profile_id,
                "profile_fingerprint": event_profile.fingerprint,
                "authorized_networks": inventory["authorized_networks"],
                "steps": [asdict(step) for step in plan],
            },
            indent=2,
        )
    )
