"""Deterministic setup scripts. No guessed accounts, ports, data, or passwords.

Recipes install ordinary distro packages/features and apply the exact reviewed
configuration. Event-specific database, directory, and appliance configuration
can be supplied as hash-pinned check/apply/rollback runbooks.
"""

from __future__ import annotations

import base64
import hashlib
import os
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any

from .state import read_private_text


NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}$")
DIGEST = re.compile(r"^[a-f0-9]{64}$")
RECIPES = {
    "linux-packages", "linux-service", "windows-features", "windows-service", "runbook",
}


def _name(value: Any, label: str) -> str:
    if not isinstance(value, str) or not NAME.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def _boolean(options: dict, name: str, default: bool = False) -> bool:
    value = options.get(name, default)
    if type(value) is not bool:
        raise ValueError(f"{name} must be a boolean")
    return value


def _argv(value: Any) -> str:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise ValueError("validate_argv requires 1 to 64 literal arguments")
    if any(not isinstance(x, str) or not x or "\x00" in x or len(x) > 1024 for x in value):
        raise ValueError("invalid validate_argv argument")
    if not value[0].startswith("/"):
        raise ValueError("validate_argv executable must be an absolute path")
    return shlex.join(value)


def _source(root: Path, value: Any) -> str:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError("runbook/configuration source requires path and sha256")
    path = Path(str(value["path"]))
    if not path.is_absolute():
        path = root / path
    text = read_private_text(path, 1024 * 1024)
    actual = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if value["sha256"] != actual:
        raise ValueError(f"setup source checksum mismatch: {path.name}")
    if "\x00" in text:
        raise ValueError("setup sources must be UTF-8 text without NUL")
    return text


def _ps(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _linux_packages(options: dict) -> tuple[str, str, str | None]:
    packages = options.get("packages")
    if not isinstance(packages, list) or not packages or len(packages) > 64:
        raise ValueError("linux-packages requires 1 to 64 package names")
    names = sorted({_name(x, "package name") for x in packages})
    manager = options.get("manager", "apt")
    cache = _boolean(options, "cache_only")
    if manager == "apt":
        check = "set -eu\n"
        for name in names:
            check += f"test \"$(dpkg-query -W -f='${{Status}}' {shlex.quote(name)} 2>/dev/null)\" = 'install ok installed'\n"
        args = shlex.join(names)
        apply = "set -eu\ntest \"$(id -u)\" = 0\nexport DEBIAN_FRONTEND=noninteractive\n"
        if not cache:
            apply += "apt-get -o Acquire::Retries=1 -o Acquire::http::Timeout=20 -o DPkg::Lock::Timeout=60 update\n"
        apply += (
            "apt-get -y --no-install-recommends --no-remove "
            "-o DPkg::Lock::Timeout=60 -o Dpkg::Options::=--force-confold "
            + ("--no-download " if cache else "") + "install " + args + "\n"
        )
        return check, apply, None
    if manager == "dnf":
        check = "set -eu\nrpm -q " + shlex.join(names) + " >/dev/null\n"
        apply = "set -eu\ntest \"$(id -u)\" = 0\ndnf -y "
        apply += "--cacheonly " if cache else "--setopt=timeout=20 --setopt=retries=1 "
        return check, apply + "install " + shlex.join(names) + "\n", None
    raise ValueError("package manager must be apt or dnf")


def _linux_service(options: dict, root: Path) -> tuple[str, str, str | None]:
    service = _name(options.get("service"), "service name")
    enable = _boolean(options, "enable")
    unmask = _boolean(options, "unmask")
    files = options.get("files", [])
    if not isinstance(files, list) or len(files) > 64:
        raise ValueError("linux-service files must be an array of at most 64 files")
    normalized = []
    seen = set()
    for row in files:
        if not isinstance(row, dict) or set(row) - {"path", "source", "mode", "previous_sha256"}:
            raise ValueError("invalid setup file fields")
        target = row.get("path")
        if (not isinstance(target, str) or not target.startswith("/") or
                any(x in {"..", "."} for x in target.split("/")) or "\n" in target or
                "\r" in target or "\x00" in target or len(target) > 512):
            raise ValueError("setup file target requires a canonical absolute path")
        if target in seen:
            raise ValueError("duplicate setup file target")
        seen.add(target)
        mode = row.get("mode", "0644")
        if mode not in {"0600", "0640", "0644"}:
            raise ValueError("setup file mode must be 0600, 0640, or 0644")
        previous = row.get("previous_sha256")
        if previous != "absent" and (not isinstance(previous, str) or not DIGEST.fullmatch(previous)):
            raise ValueError("setup file requires exact previous_sha256 or 'absent'")
        content = _source(root, row.get("source"))
        normalized.append((target, content, mode, previous))
    check = "set -eu\n"
    for target, content, mode, _ in normalized:
        path = shlex.quote(target)
        digest = hashlib.sha256(content.encode()).hexdigest()
        check += f"test -f {path} && test ! -L {path}\n"
        check += f"test \"$(sha256sum -- {path} | cut -d' ' -f1)\" = {digest}\n"
        check += f"test \"$(stat -c %a -- {path})\" = {mode[1:]}\n"
    quoted = shlex.quote(service)
    check += f"systemctl is-active --quiet -- {quoted}\n"
    if enable:
        check += f"systemctl is-enabled --quiet -- {quoted}\n"
    if options.get("validate_argv"):
        check += _argv(options["validate_argv"]) + " >/dev/null\n"

    # All file preconditions run before the first write. Backups remain on the
    # host and preserve metadata; no credential-bearing file enters the report.
    apply = """set -eu
test "$(id -u)" = 0
sb_secure_parent() {
  sb_parent=$(dirname -- "$1")
  while [ "$sb_parent" != / ]; do
    test ! -L "$sb_parent" || return 1
    test -d "$sb_parent" || return 1
    test "$(stat -c %u -- "$sb_parent")" = 0 || return 1
    sb_mode=$(stat -c %a -- "$sb_parent")
    test "$((0$sb_mode & 0022))" = 0 || return 1
    sb_parent=$(dirname -- "$sb_parent")
  done
}
"""
    for target, content, mode, previous in normalized:
        path = shlex.quote(target)
        desired = hashlib.sha256(content.encode()).hexdigest()
        apply += f"sb_secure_parent {path}\ntest ! -L {path}\n"
        apply += f"if [ -e {path} ]; then\n  test -f {path}\n  test \"$(stat -c %h -- {path})\" = 1\n"
        apply += f"  sb_hash=$(sha256sum -- {path} | cut -d' ' -f1)\n"
        allowed = f'  test "$sb_hash" = {desired}'
        if previous != "absent":
            allowed += f' || test "$sb_hash" = {previous}'
        apply += allowed + "\n"
        apply += "else\n" + ("  :\n" if previous == "absent" else "  exit 42\n") + "fi\n"
    apply += f"sb_active=0; systemctl is-active --quiet -- {quoted} && sb_active=1\n"
    apply += f"sb_enabled=$(systemctl is-enabled -- {quoted} 2>/dev/null || true)\n"
    if not unmask:
        apply += 'case "$sb_enabled" in masked*) exit 42;; esac\n'
    # root's persistent backups are intentionally retained after either outcome.
    apply += "umask 077\nsb_backup=$(mktemp -d /var/lib/sentinel-setup-backup.XXXXXXXX)\n"
    apply += "sb_changed=0\n"
    rollback = "sb_restore() {\n  set +e\n  sb_restore_failed=0\n"
    for index, (target, content, mode, _) in enumerate(normalized):
        path = shlex.quote(target)
        apply += f"if [ -e {path} ]; then cp -a -- {path} \"$sb_backup/{index}\"; else touch \"$sb_backup/{index}.absent\"; fi\n"
        rollback += f"  if [ -f \"$sb_backup/{index}.written\" ]; then\n"
        rollback += f"    if [ -f \"$sb_backup/{index}.absent\" ]; then rm -f -- {path} || sb_restore_failed=1; else cp -a -- \"$sb_backup/{index}\" {path} || sb_restore_failed=1; fi\n  fi\n"
    rollback += f"  if [ \"$sb_active\" = 1 ]; then systemctl restart -- {quoted} || sb_restore_failed=1; else systemctl stop -- {quoted} || sb_restore_failed=1; fi\n"
    if enable:
        rollback += f"  case \"$sb_enabled\" in disabled) systemctl disable -- {quoted} || sb_restore_failed=1;; esac\n"
    if unmask:
        rollback += f"  case \"$sb_enabled\" in masked) systemctl mask -- {quoted} || sb_restore_failed=1;; masked-runtime) systemctl mask --runtime -- {quoted} || sb_restore_failed=1;; esac\n"
    rollback += "  return $sb_restore_failed\n}\n"
    apply += rollback
    apply += "trap 'sb_status=$?; if [ \"$sb_status\" -ne 0 ]; then sb_restore || exit 43; fi' EXIT\n"
    for index, (target, content, mode, _) in enumerate(normalized):
        path = shlex.quote(target)
        digest = hashlib.sha256(content.encode()).hexdigest()
        encoded = base64.b64encode(content.encode()).decode()
        apply += f"if [ ! -f {path} ] || [ \"$(sha256sum -- {path} | cut -d' ' -f1)\" != {digest} ] || [ \"$(stat -c %a -- {path})\" != {mode[1:]} ]; then\n"
        apply += f"  sb_temp=$(mktemp -- {shlex.quote(str(PurePosixPath(target).parent) + '/.sentinel-setup.XXXXXXXX')})\n"
        apply += f"  printf '%s' '{encoded}' | base64 -d > \"$sb_temp\"\n"
        apply += f"  test \"$(sha256sum -- \"$sb_temp\" | cut -d' ' -f1)\" = {digest}\n"
        # Preserve an existing file's owner, ACLs, and xattrs by cloning before
        # replacing its content. New files receive the explicit reviewed mode.
        apply += f"  if [ -f {path} ]; then cp --attributes-only --preserve=all -- {path} \"$sb_temp\"; fi\n"
        apply += f"  chmod {mode} \"$sb_temp\"\n  touch \"$sb_backup/{index}.written\"\n"
        apply += f"  mv -f -- \"$sb_temp\" {path}\n  sb_changed=1\nfi\n"
    if options.get("validate_argv"):
        apply += _argv(options["validate_argv"]) + "\n"
    if unmask:
        apply += f"systemctl unmask -- {quoted}\n"
    if enable:
        apply += f"systemctl enable -- {quoted}\n"
    if any(target.startswith("/etc/systemd/system/") for target, *_ in normalized):
        apply += "systemctl daemon-reload\n"
    apply += f"if [ \"$sb_changed\" = 1 ] && [ \"$sb_active\" = 1 ]; then systemctl restart -- {quoted}; else systemctl start -- {quoted}; fi\n"
    apply += f"systemctl is-active --quiet -- {quoted}\ntrap - EXIT\n"
    return check, apply, None


def _windows_features(options: dict) -> tuple[str, str, str | None]:
    values = options.get("features")
    if not isinstance(values, list) or not values or len(values) > 32:
        raise ValueError("windows-features requires 1 to 32 feature names")
    names = ",".join(_ps(_name(x, "Windows feature")) for x in values)
    header = "$ErrorActionPreference = 'Stop'\nImport-Module ServerManager\n"
    check = header + f"$features = @(Get-WindowsFeature -Name {names})\n"
    check += f"if ($features.Count -ne {len(set(values))}) {{ exit 20 }}\n"
    check += "$missing = @($features | Where-Object { -not $_.Installed })\n"
    check += "if ($missing.Count -gt 0) { exit 10 }; exit 0\n"
    apply = header + f"$result = Install-WindowsFeature -Name {names} -IncludeManagementTools\n"
    apply += "if (-not $result.Success) { exit 20 }\nif ([string]$result.RestartNeeded -eq 'Yes') { exit 30 }\nexit 0\n"
    return check, apply, None


def _windows_service(options: dict) -> tuple[str, str, str | None]:
    name = _ps(_name(options.get("service"), "Windows service"))
    enable = _boolean(options, "enable")
    check = "$ErrorActionPreference = 'Stop'\n"
    check += f"$svc = Get-Service -Name {name}\nif ($svc.Status -ne 'Running') {{ exit 10 }}\n"
    if enable:
        check += "if ($svc.StartType -ne 'Automatic') { exit 10 }\n"
    check += "exit 0\n"
    apply = "$ErrorActionPreference = 'Stop'\n"
    apply += f"$svc = Get-Service -Name {name}\n"
    if enable:
        apply += f"Set-Service -Name {name} -StartupType Automatic\n"
    else:
        apply += "if ($svc.StartType -eq 'Disabled') { exit 42 }\n"
    apply += f"Start-Service -Name {name}\n(Get-Service -Name {name}).WaitForStatus('Running', [TimeSpan]::FromSeconds(45))\nexit 0\n"
    return check, apply, None


def compile_recipe(recipe: str, options: dict, root: Path, platform: str) -> tuple[str, str, str | None]:
    if recipe not in RECIPES or not isinstance(options, dict):
        raise ValueError("unknown setup recipe or invalid options")
    allowed = {
        "linux-packages": {"packages", "manager", "cache_only"},
        "linux-service": {"service", "enable", "unmask", "files", "validate_argv"},
        "windows-features": {"features"},
        "windows-service": {"service", "enable"},
        "runbook": {"check", "apply", "rollback"},
    }
    if set(options) - allowed[recipe]:
        raise ValueError("unknown setup recipe option")
    if recipe.startswith("linux-") and platform != "linux":
        raise ValueError("Linux setup recipe assigned to a non-Linux host")
    if recipe.startswith("windows-") and platform != "windows":
        raise ValueError("Windows setup recipe assigned to a non-Windows host")
    if recipe == "linux-packages":
        return _linux_packages(options)
    if recipe == "linux-service":
        return _linux_service(options, root)
    if recipe == "windows-features":
        return _windows_features(options)
    if recipe == "windows-service":
        return _windows_service(options)
    if set(options) - {"check", "apply", "rollback"}:
        raise ValueError("unknown runbook option")
    check = _source(root, options.get("check"))
    apply = _source(root, options.get("apply"))
    rollback = _source(root, options["rollback"]) if options.get("rollback") else None
    return check, apply, rollback
