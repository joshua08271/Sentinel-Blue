"""Reuse native modules, never observations, in one owned Windows helper.

Only the fixed inventory is accepted. Each request has a fresh nonce and an
explicit completion record. A failed request destroys the helper before the
next collection. The original caller deadline covers startup, IO and queries.
"""
from __future__ import annotations

import atexit
import base64
import ctypes
import json
import math
import queue
import secrets
import subprocess
import threading
import time

from .setup_transport import powershell_environment
from .windows_queries import WINDOWS_QUERIES

MAX_OUTPUT = 16 * 1024 * 1024


class _OwnedJob:
    """The noninherited parent handle kills the helper tree on parent death."""

    def __init__(self):
        from ctypes import wintypes as w

        class Basic(ctypes.Structure):
            _fields_ = [('ProcessTime', ctypes.c_int64), ('JobTime', ctypes.c_int64),
                        ('Flags', w.DWORD), ('MinWorkingSet', ctypes.c_size_t),
                        ('MaxWorkingSet', ctypes.c_size_t), ('ActiveProcesses', w.DWORD),
                        ('Affinity', ctypes.c_size_t), ('Priority', w.DWORD), ('Scheduling', w.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in
                        ('ReadOps', 'WriteOps', 'OtherOps', 'ReadBytes', 'WriteBytes', 'OtherBytes')]

        class Extended(ctypes.Structure):
            _fields_ = [('Basic', Basic), ('IO', IO), ('ProcessMemory', ctypes.c_size_t),
                        ('JobMemory', ctypes.c_size_t), ('PeakProcess', ctypes.c_size_t),
                        ('PeakJob', ctypes.c_size_t)]

        self.api = ctypes.WinDLL('kernel32', use_last_error=True)
        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        self.api.CreateJobObjectW.restype = w.HANDLE
        self.api.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        self.api.SetInformationJobObject.restype = w.BOOL
        self.api.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.api.AssignProcessToJobObject.restype = w.BOOL
        self.api.CloseHandle.argtypes = [w.HANDLE]
        self.api.CloseHandle.restype = w.BOOL
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise ctypes.WinError(ctypes.get_last_error())
        limits = Extended()
        limits.Basic.Flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE; no breakaway.
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
            error = ctypes.WinError(ctypes.get_last_error())
            self.close()
            raise error

    def assign(self, process):
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise ctypes.WinError(ctypes.get_last_error())

    def close(self):
        if self.handle:
            if not self.api.CloseHandle(self.handle):
                raise ctypes.WinError(ctypes.get_last_error())
            self.handle = None


def host_script():
    # Blocks are fixed at process creation; requests contain no executable code.
    entries = '\n'.join("[PSCustomObject]@{Name='" + name + "';Code={\n" + body + '\n}}'
                        for name, body in WINDOWS_QUERIES.items())
    return "$ErrorActionPreference='Stop'\n$ProgressPreference='SilentlyContinue'\n$queries=@(\n" + entries + r"""
)
while ($null -ne ($request = [Console]::In.ReadLine())) {
  if ($request -cnotmatch '^[0-9a-f]{32}$') { throw 'Invalid inventory request' }
  # Keep loaded modules and compiled native code only. No SCM observation may
  # survive a request, including an empty or previously unsuccessful inventory.
  $script:sentinelNativeServices = $null
  foreach ($query in $queries) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $ok = $false; $payload = ''; $problem = ''
    try {
      $native = @(& $query.Code 2>&1)
      if (@($native | Where-Object { $_ -is [Management.Automation.ErrorRecord] }).Count) {
        throw 'Inventory emitted a nonterminating error'
      }
      if (@($native | Where-Object { $_ -isnot [string] }).Count) {
        throw 'Inventory emitted non-JSON output'
      }
      $payload = [string]::Join("`n", [string[]]$native)
      $ok = $true
    } catch {
      $line = [int]$_.InvocationInfo.ScriptLineNumber - [int]$query.Code.Ast.Extent.StartLineNumber
      $problem = 'Native section failed: ' + $_.Exception.GetType().Name + ' (section line ' + $line + ')'
    }
    $watch.Stop()
    $record = [PSCustomObject]@{Request=$request;Schema=1;Section=$query.Name;OK=$ok;Payload=$payload;Error=$problem;Seconds=$watch.Elapsed.TotalSeconds}
    [Console]::Out.WriteLine(($record | ConvertTo-Json -Depth 3 -Compress))
    [Console]::Out.Flush()
  }
  $script:sentinelNativeServices = $null
  [Console]::Out.WriteLine(([PSCustomObject]@{Request=$request;Done=$true} | ConvertTo-Json -Compress))
  [Console]::Out.Flush()
}
"""


class InventoryHost:
    def __init__(self, *, command=None, initial_script=None, job_factory=_OwnedJob):
        self.process = None
        self.job = None
        self.reader = None
        self.writer = None
        self.output = queue.Queue(maxsize=32)
        self.output_bytes = 0
        self.output_lock = threading.Lock()
        self.broken = threading.Event()
        self.completed = 0
        self.created = time.monotonic()
        self.initial_script = host_script() if initial_script is None else initial_script
        command = command or ['powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-Command',
            "$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'; "
            "[Console]::InputEncoding=[Text.UTF8Encoding]::new($false); "
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false); "
            "& ([ScriptBlock]::Create([Text.Encoding]::UTF8.GetString("
            "[Convert]::FromBase64String([Console]::In.ReadLine()))))"]
        try:
            self.job = job_factory()
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                # Buffered reads avoid a pipe syscall for every output byte.
                # The reader still rejects a line or request over MAX_OUTPUT.
                stderr=subprocess.STDOUT, bufsize=65536, close_fds=True,
                env=powershell_environment('powershell.exe'),
                creationflags=(getattr(subprocess, 'CREATE_NO_WINDOW', 0) |
                               getattr(subprocess, 'ABOVE_NORMAL_PRIORITY_CLASS', 0)))
            # The child cannot receive executable script until its ownership
            # is established. Failure to create/assign the job never falls back.
            self.job.assign(self.process)
            self.reader = threading.Thread(target=self._read, name='sentinel-inventory-output', daemon=True)
            self.reader.start()
        except BaseException:
            self.close()
            raise

    def _read(self):
        try:
            while not self.broken.is_set():
                line = self.process.stdout.readline(MAX_OUTPUT + 1)
                with self.output_lock:
                    self.output_bytes += len(line)
                    overflow = self.output_bytes > MAX_OUTPUT
                if not line or not line.endswith(b'\n') or overflow:
                    self.broken.set()
                    return
                self.output.put_nowait(line)
        except (OSError, ValueError, queue.Full):
            self.broken.set()

    def _send(self, data, deadline):
        finished = threading.Event()
        failed = []

        def send():
            try:
                remaining = memoryview(data)
                while remaining:
                    written = self.process.stdin.write(remaining)
                    if not written:
                        raise OSError('Inventory request pipe closed')
                    remaining = remaining[written:]
                self.process.stdin.flush()
            except (OSError, ValueError):
                failed.append(True)
            finally:
                finished.set()

        self.writer = threading.Thread(target=send, name='sentinel-inventory-input', daemon=True)
        self.writer.start()
        if not finished.wait(max(0, deadline-time.monotonic())):
            raise TimeoutError('Windows inventory request exceeded its deadline')
        if failed:
            raise RuntimeError('Windows inventory helper rejected its request')

    def query(self, deadline):
        from .windows_query_batch import decode_batch
        if not math.isfinite(deadline) or deadline <= time.monotonic():
            raise TimeoutError('Windows inventory query budget exhausted')
        if self.broken.is_set() or self.process.poll() is not None or not self.output.empty():
            raise RuntimeError('Windows inventory helper has unsolicited or incomplete output')
        with self.output_lock:
            self.output_bytes = 0
        nonce = secrets.token_hex(16)
        prefix = b'' if self.completed else base64.b64encode(self.initial_script.encode('utf-8')) + b'\n'
        self._send(prefix + nonce.encode('ascii') + b'\n', deadline)
        frames = []
        names = set()
        while True:
            if self.broken.is_set() or time.monotonic() >= deadline:
                raise TimeoutError('Windows inventory helper did not complete within its deadline')
            try:
                line = self.output.get(timeout=min(0.1, max(0, deadline-time.monotonic())))
            except queue.Empty:
                continue
            row = json.loads(line)
            if not isinstance(row, dict) or row.pop('Request', None) != nonce:
                raise ValueError('Windows inventory reply belongs to a different request')
            if row == {'Done': True} and type(row.get('Done')) is bool:
                if names != set(WINDOWS_QUERIES):
                    raise ValueError('Windows inventory completed without every required section')
                result = decode_batch(b''.join(frames), WINDOWS_QUERIES)
                if time.monotonic() >= deadline or self.broken.is_set() or self.process.poll() is not None:
                    raise TimeoutError('Windows inventory completed after its deadline or helper failure')
                self.completed += 1
                return result
            name = row.get('Section')
            if not isinstance(name, str) or name not in WINDOWS_QUERIES or name in names:
                raise ValueError('Windows inventory returned an unknown or duplicate section')
            names.add(name)
            frames.append(json.dumps(row, separators=(',', ':')).encode('utf-8') + b'\n')

    def close(self):
        self.broken.set()
        error = None
        if self.job is not None:
            try:
                self.job.close()
            except OSError as exc:
                error = exc
        if self.process is not None:
            if self.process.poll() is None:
                self.process.kill()
            self.process.wait(timeout=2)
            for thread in (self.reader, self.writer):
                if thread is not None:
                    thread.join(timeout=1)
                    if thread.is_alive():
                        raise RuntimeError('Owned Windows inventory IO worker did not stop')
            for stream in (self.process.stdin, self.process.stdout):
                stream.close()
        if error is not None:
            raise error


_lock = threading.Lock()
_host = None


def close_inventory_host():
    global _host
    with _lock:
        if _host is not None:
            _host.close()
            _host = None


def read_owned_inventory(deadline):
    """At most one helper; failure never permits stale data or helper overlap."""
    global _host
    from .windows_query_batch import QueryResult
    remaining = deadline - time.monotonic()
    if not math.isfinite(remaining) or remaining <= 0 or not _lock.acquire(timeout=remaining):
        return {name: QueryResult(error='Windows inventory query budget exhausted') for name in WINDOWS_QUERIES}
    try:
        try:
            if _host is not None and (_host.broken.is_set() or _host.completed >= 256 or
                                      time.monotonic() - _host.created > 3600):
                _host.close()
                _host = None
            if _host is None:
                _host = InventoryHost()
            return _host.query(deadline)
        except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
            if _host is not None:
                # Retain the failed instance if close fails: another request
                # must retry cleanup instead of creating an overlapping child.
                try:
                    _host.close()
                except (OSError, RuntimeError, subprocess.SubprocessError):
                    return {name: QueryResult(error='Owned Windows inventory helper cleanup is unverified')
                            for name in WINDOWS_QUERIES}
                _host = None
            return {name: QueryResult(error='Windows inventory helper failed: ' + type(exc).__name__)
                    for name in WINDOWS_QUERIES}
    finally:
        _lock.release()


atexit.register(close_inventory_host)
