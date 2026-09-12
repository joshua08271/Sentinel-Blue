"""Bounded fingerprints of files referenced by native startup and processes.

Only paths and hashes leave this collector; command arguments are never emitted.
This is inventory, not a verdict on the intent of an unfamiliar program.
"""

from __future__ import annotations

import re
import os
import stat
import time
from pathlib import Path, PureWindowsPath

from .protocol import PersistenceItem
from .restoration import RestorePointStore


SCRIPT_SUFFIXES = {'.sh', '.bash', '.ksh', '.zsh', '.py', '.pyw', '.pyz', '.pyzw',
                   '.ps1', '.psm1', '.bat', '.cmd', '.vbs', '.js', '.wsf', '.hta',
                   '.php', '.phtml', '.pl', '.rb', '.lua'}


def _distribution_alias(path):
    """Recognize only the standard, root-owned merged-/usr directory links."""
    if os.name != 'posix' or len(path.parts)<3:
        return path, None
    name=path.parts[1]
    if name not in {'lib','lib64','bin','sbin'}:
        return path, None
    alias=Path('/')/name
    before=alias.lstat()
    if not stat.S_ISLNK(before.st_mode):
        return path, None
    target=os.readlink(alias)
    if before.st_uid != 0 or target not in {'usr/'+name,'/usr/'+name}:
        raise ValueError('distribution directory link does not match its expected native layout')
    signature=(before.st_dev,before.st_ino,before.st_uid,before.st_ctime_ns,target)
    return Path('/usr')/name/Path(*path.parts[2:]), (alias,signature)


def _alias_unchanged(alias):
    path, signature = alias
    info=path.lstat()
    return (info.st_dev,info.st_ino,info.st_uid,info.st_ctime_ns,os.readlink(path))==signature


def referenced_paths(text: str, *, windows: bool = False, scripts_only: bool = False) -> list[str]:
    """Extract literal absolute file references; never expand or execute syntax."""
    matches = re.findall(r'''"([^"\r\n]+)"|'([^'\r\n]+)'|([^\s;|<>"']+)''', text[:262144])
    paths = []
    for match in matches:
        token = next(part for part in match if part)
        if windows:
            token = re.split(r'(?i)(?<=\.dll),',token,maxsplit=1)[0]
        if not windows and '=' in token:
            token = token.split('=', 1)[1]
        token = token.lstrip('-+!:@') if not windows else token
        path = PureWindowsPath(token) if windows else Path(token)
        if (path.is_absolute() and len(token) <= 512 and not any(c in token for c in ('$','%','*','?','\x00'))
                and (not scripts_only or path.suffix.lower() in SCRIPT_SUFFIXES)):
            if token not in paths:
                paths.append(token)
    return paths


def windows_startup_payload_paths(command):
    paths=referenced_paths(command,windows=True)
    windows=os.environ.get('WINDIR',r'C:\Windows').casefold()+'\\'
    executable_suffixes=SCRIPT_SUFFIXES|{'.exe','.com','.dll','.pyd','.scr','.msi'}
    return [path for index,path in enumerate(paths)
            if PureWindowsPath(path).suffix.lower() in executable_suffixes
            and (PureWindowsPath(path).suffix.lower() in SCRIPT_SUFFIXES or not path.casefold().startswith(windows))
            or index==0 and not PureWindowsPath(path).suffix and not path.casefold().startswith(windows)]


def fingerprint_references(references, errors, *, kind='startup-payload', max_files=256, seconds=5.0):
    """Read bounded regular files with the same race/alias checks as quarantine."""
    import hashlib
    deadline = time.monotonic() + seconds
    items, seen, aliases = [], set(), set()
    for name in references:
        if name in seen:
            continue
        if len(seen) >= max_files or time.monotonic() >= deadline:
            errors.append(f'{kind} inventory reached its file/time bound')
            break
        seen.add(name)
        path = Path(name)
        try:
            # Windows must enter the pinned no-reparse reader before any path
            # probe: is_file() can follow a malicious junction/UNC reference.
            if os.name != 'nt' and not path.is_file():
                continue
            native_path, alias = _distribution_alias(path)
            if os.name == 'nt':
                from .restoration import _windows_read_file_snapshot
                # Multiple hard links are normal for installed Windows programs.
                # Read only, under a pinned handle; quarantine stays single-link.
                data, _ = _windows_read_file_snapshot(native_path,32*1024*1024,
                    capture_security=False,allow_hard_links=True)
                metadata = {}
            else:
                data, metadata = RestorePointStore._read_target(native_path, maximum=32*1024*1024)
            if alias:
                if not _alias_unchanged(alias):
                    raise ValueError('distribution directory alias changed during inventory')
                if str(alias[0]) not in aliases:
                    aliases.add(str(alias[0]))
                    items.append(PersistenceItem(kind+'-path-link',str(alias[0]),'0',True,
                        hashlib.sha256(alias[1][-1].encode()).hexdigest()))
            items.append(PersistenceItem(kind, str(path), str(metadata.get('uid', 'unknown')),
                                         True, hashlib.sha256(data).hexdigest()))
        except FileNotFoundError as exc:
            if os.name != 'nt':
                errors.append(f'{kind} could not safely fingerprint {str(path)[:160]} ({type(exc).__name__})')
        except (OSError, ValueError) as exc:
            # A failed read is visible and cannot silently establish coverage.
            errors.append(f'{kind} could not safely fingerprint {str(path)[:160]} ({type(exc).__name__})')
    return items


def linux_startup_payloads(entries, errors):
    references = []
    deadline = time.monotonic() + 3.0
    for item in entries:
        if time.monotonic() >= deadline:
            errors.append('startup reference parsing reached its time bound')
            break
        if item.kind not in {'startup-file', 'cron', 'user-cron', 'shell-startup', 'systemd-file'}:
            continue
        try:
            data, _ = RestorePointStore._read_target(Path(item.name))
            text = data[:262144].decode('utf-8', 'strict')
        except (OSError, ValueError, UnicodeError):
            continue
        references.extend(path for path in referenced_paths(text)
                          if Path(path).suffix.lower() in SCRIPT_SUFFIXES or
                          path.startswith(('/opt/', '/srv/', '/home/', '/root/', '/tmp/', '/var/tmp/', '/usr/local/')))
    return fingerprint_references(references, errors)


def linux_process_payloads(errors, *, proc_root=Path('/proc')):
    """Inventory script arguments and non-distribution running executables.

    Relative script arguments are anchored to the process's observed cwd. Native
    process links locate candidates only; fingerprinting still refuses arbitrary
    symlinks, and this inventory never authorizes killing a PID or removing a file.
    """
    references = []
    deadline = time.monotonic() + 1.0
    try:
        for index, entry in enumerate(p for p in proc_root.iterdir() if p.name.isdigit()):
            if index >= 4096 or time.monotonic() >= deadline:
                errors.append('process payload enumeration reached its process/time bound')
                break
            if len(references) >= 512:
                errors.append('process payload reference inventory reached its bound')
                break
            try:
                executable = os.readlink(entry / 'exe')
                if executable.endswith(' (deleted)'):
                    errors.append('running executable was unlinked; on-disk payload coverage is incomplete')
                elif executable.startswith(('/opt/', '/srv/', '/home/', '/root/', '/tmp/', '/var/tmp/', '/usr/local/')):
                    references.append(executable)
            except FileNotFoundError:
                pass  # Kernel threads and processes that already exited.
            except OSError:
                errors.append('a running executable reference could not be inspected')
            try:
                with (entry / 'cmdline').open('rb') as stream:
                    raw = stream.read(32769)
                if len(raw) > 32768:
                    errors.append('process command reference exceeded its byte bound')
                    continue
                # NUL-separated arguments remain separate, including quoted paths.
                for arg in raw.split(b'\0'):
                    text = arg.decode('utf-8', 'strict')
                    path = Path(text)
                    if path.suffix.lower() not in SCRIPT_SUFFIXES or len(text) > 512 or text.startswith('-'):
                        continue
                    if not path.is_absolute():
                        cwd = Path(os.readlink(entry / 'cwd'))
                        if not cwd.is_absolute() or str(cwd).endswith(' (deleted)'):
                            errors.append('relative process payload has no stable working directory')
                            continue
                        path = cwd / path
                    references.append(str(path))
                    if len(references) >= 512:
                        break
            except FileNotFoundError:
                continue
            except (OSError, UnicodeError, ValueError):
                errors.append('a process payload command reference could not be inspected')
    except OSError:
        errors.append('process payload references unavailable')
    return fingerprint_references(references, errors, kind='process-payload', max_files=128, seconds=3.0)
