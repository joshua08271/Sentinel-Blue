"""Read default Startup folders while pinning every local, non-reparse parent."""
from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path

from .protocol import PersistenceItem


def startup_folder_inventory(folders, errors, *, maximum=256, seconds=3.0):
    from .restoration import _WindowsNativeFileOps, _windows_pinned_parent, _windows_read_file_snapshot
    items, seen = [], set()
    deadline = time.monotonic() + seconds
    native = _WindowsNativeFileOps()
    for row in folders:
        folder = Path(row['Name'])
        entered = False
        try:
            if time.monotonic() >= deadline:
                raise TimeoutError('Startup folder inventory reached its file/time bound')
            # No is_dir/is_file probe may follow a junction before these handles
            # establish a local directory chain and prevent parent replacement.
            with _windows_pinned_parent(folder/'sentinel-inventory-leaf', native):
                entered = True
                with os.scandir(folder) as entries:
                    for entry in entries:
                        if time.monotonic() >= deadline or len(seen) >= maximum:
                            raise TimeoutError('Startup folder inventory reached its file/time bound')
                        if not entry.is_file(follow_symlinks=False):
                            if entry.is_symlink() or entry.stat(follow_symlinks=False).st_file_attributes & 0x400:
                                errors.append('Windows Startup folder contains a reparse entry; target was not followed')
                            continue
                        path = Path(entry.path)
                        if str(path).casefold() in seen:
                            continue
                        seen.add(str(path).casefold())
                        data, _ = _windows_read_file_snapshot(path, 32*1024*1024,
                            capture_security=False, allow_hard_links=True)
                        items.append(PersistenceItem('startup-folder-file', str(path), str(row.get('Owner','unknown')),
                                                     True, hashlib.sha256(data).hexdigest()))
        except FileNotFoundError:
            if entered:
                errors.append('Windows Startup entry disappeared during inventory')
            # A missing default Startup folder is ordinary native state.
        except TimeoutError as exc:
            errors.append(str(exc)); break
        except (OSError, ValueError) as exc:
            errors.append('Windows Startup folder inventory incomplete: '+type(exc).__name__)
    return items
