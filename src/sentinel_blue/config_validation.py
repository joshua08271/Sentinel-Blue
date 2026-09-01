"""Bounded, allowlisted validators for restored service configuration files."""

from __future__ import annotations

import os
import shutil
import ssl
import stat
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlparse

from .net_safety import validate_http_origin

if TYPE_CHECKING:
    from .event_profile import EventProfile


VALIDATION_TIMEOUT = 12.0
MAX_TLS_MATERIAL_BYTES = 1024 * 1024


def require_https_controller_origin(value: str) -> str:
    """Validate a simple controller origin and require authenticated TLS."""
    normalized = validate_http_origin(value)
    if urlparse(normalized).scheme != "https":
        raise ValueError("checksum-bound deployments require an HTTPS controller")
    return normalized


def _tls_material_path(value: str | Path, label: str) -> Path:
    path = Path(value).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is unavailable or is a symbolic link")
    try:
        details = path.stat()
    except OSError as exc:
        raise ValueError(f"{label} metadata is unavailable") from exc
    if not stat.S_ISREG(details.st_mode) or not 0 < details.st_size <= MAX_TLS_MATERIAL_BYTES:
        raise ValueError(f"{label} must be a non-empty regular file of at most 1 MiB")
    return path


def validate_controller_ca_binding(
    profile: "EventProfile", ca_file: str | Path | None
) -> Path:
    """Verify and parse the exact controller trust anchor pinned by a profile."""
    if not ca_file:
        raise ValueError("checksum-bound deployments require --ca-file")
    path = _tls_material_path(ca_file, "controller CA certificate")
    profile.verify_controller_ca_file(path)
    try:
        ssl.create_default_context(cafile=str(path))
    except (OSError, ssl.SSLError) as exc:
        raise ValueError("controller CA certificate is not a valid PEM trust anchor") from exc
    return path


def validate_tls_server_material(
    certificate: str | Path | None,
    private_key: str | Path | None,
) -> tuple[Path, Path]:
    """Fail closed on missing, unsafe, mismatched, or malformed server TLS files."""
    if not certificate or not private_key:
        raise ValueError(
            "checksum-bound controllers require --tls-cert and --tls-key"
        )
    certificate_path = _tls_material_path(certificate, "controller TLS certificate")
    key_path = _tls_material_path(private_key, "controller TLS private key")
    if os.name == "posix" and key_path.stat().st_mode & 0o077:
        raise ValueError("controller TLS private key must not be group- or world-accessible")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    try:
        context.load_cert_chain(str(certificate_path), str(key_path))
    except (OSError, ssl.SSLError) as exc:
        raise ValueError("controller TLS certificate/key are invalid or do not match") from exc
    return certificate_path, key_path


def validate_bound_transport(
    profile: "EventProfile",
    *,
    role: str,
    controller: str | None = None,
    ca_file: str | Path | None = None,
    tls_cert: str | Path | None = None,
    tls_key: str | Path | None = None,
    syslog_bind: str | None = None,
) -> None:
    """Apply transport gates only to live or checksum-bound range deployments."""
    if not profile.requires_strict_transport:
        return
    if role in {"agent", "launcher"}:
        if not controller:
            raise ValueError("checksum-bound deployments require a controller origin")
        require_https_controller_origin(controller)
        validate_controller_ca_binding(profile, ca_file)
        return
    if role == "controller":
        if syslog_bind:
            raise ValueError(
                "checksum-bound controllers refuse unauthenticated UDP syslog"
            )
        validate_tls_server_material(tls_cert, tls_key)
        validate_controller_ca_binding(profile, ca_file)
        return
    raise ValueError(f"unsupported transport validation role: {role}")


def _first_available(*commands: str) -> str | None:
    for command in commands:
        resolved = shutil.which(command)
        if resolved:
            return resolved
    return None


def validation_command(path: str | Path) -> tuple[str, list[str]] | None:
    """Return an exact argv validator for a recognized live configuration path."""
    target = Path(path)
    normalized = target.as_posix().casefold()
    name = target.name.casefold()
    executable: str | None = None
    arguments: list[str] = []

    windows_text = str(target).replace("/", "\\").casefold()

    if normalized == "/etc/ssh/sshd_config" or normalized.startswith("/etc/ssh/sshd_config.d/"):
        executable = _first_available("sshd")
        arguments = ["-t", "-f", str(target)]
    elif windows_text.endswith("\\programdata\\ssh\\sshd_config"):
        candidate = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "OpenSSH" / "sshd.exe"
        executable = str(candidate) if candidate.is_file() else _first_available("sshd.exe", "sshd")
        arguments = ["-t", "-f", str(target)]
    elif normalized == "/etc/sudoers" or normalized.startswith("/etc/sudoers.d/"):
        executable = _first_available("visudo")
        arguments = ["-c", "-f", str(target)]
    elif normalized.startswith("/etc/nginx/"):
        executable = _first_available("nginx")
        arguments = ["-t"]
    elif normalized.startswith("/etc/apache2/"):
        executable = _first_available("apache2ctl", "apachectl")
        arguments = ["configtest"]
    elif normalized.startswith("/etc/httpd/"):
        executable = _first_available("httpd", "apachectl")
        arguments = ["-t"]
    elif normalized == "/etc/named.conf" or normalized.startswith("/etc/named/"):
        executable = _first_available("named-checkconf")
        arguments = [str(target)] if name.endswith(".conf") else []
    elif normalized.startswith("/etc/samba/"):
        executable = _first_available("testparm")
        arguments = ["-s", str(target)] if name == "smb.conf" else ["-s"]
    elif normalized.startswith("/etc/systemd/system/") and name.endswith((".service", ".socket", ".timer")):
        executable = _first_available("systemd-analyze")
        arguments = ["verify", str(target)]
    elif "\\windows\\system32\\inetsrv\\config\\" in windows_text:
        candidate = Path(os.environ.get("SystemRoot", "C:\\Windows")) / "System32" / "inetsrv" / "appcmd.exe"
        executable = str(candidate) if candidate.is_file() else None
        arguments = ["list", "config"]
    else:
        return None

    if executable is None:
        return "", arguments
    return executable, arguments


def validate_restored_configuration(path: str | Path) -> dict[str, Any]:
    """Validate a recognized live config without a shell or user-controlled command."""
    selected = validation_command(path)
    if selected is None:
        return {
            "applicable": False,
            "available": False,
            "healthy": None,
            "validator": None,
            "detail": "no allowlisted validator applies to this path",
        }
    executable, arguments = selected
    if not executable:
        return {
            "applicable": True,
            "available": False,
            "healthy": None,
            "validator": None,
            "detail": "the service validator is not installed; scorer probes remain required",
        }
    try:
        result = subprocess.run(
            [executable, *arguments],
            stdin=subprocess.DEVNULL,
            text=True,
            capture_output=True,
            timeout=VALIDATION_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "applicable": True,
            "available": True,
            "healthy": False,
            "validator": Path(executable).name,
            "detail": f"validator could not complete: {exc}"[:500],
        }
    detail = (result.stderr.strip() or result.stdout.strip() or "configuration accepted")[:500]
    return {
        "applicable": True,
        "available": True,
        "healthy": result.returncode == 0,
        "validator": Path(executable).name,
        "detail": detail,
    }
