"""Measure real host collection under bounded, owned CPU load.

Only counts, timings, and error categories leave the host in the report. This
does not simulate a service outage or establish a full competition result.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from pathlib import Path

@contextmanager
def limit_cpus(count: int | None):
    """Constrain this measurement and its children, then restore our affinity."""
    if count is None:
        yield None
        return
    if os.name == 'nt':
        import ctypes
        from ctypes import wintypes
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.GetCurrentProcess.restype = wintypes.HANDLE
        api.GetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_size_t)]
        api.GetProcessAffinityMask.restype = wintypes.BOOL
        api.SetProcessAffinityMask.argtypes = [wintypes.HANDLE, ctypes.c_size_t]
        api.SetProcessAffinityMask.restype = wintypes.BOOL
        handle = api.GetCurrentProcess()

        def read_mask():
            process_mask, system_mask = ctypes.c_size_t(), ctypes.c_size_t()
            if not api.GetProcessAffinityMask(handle, ctypes.byref(process_mask), ctypes.byref(system_mask)):
                raise ctypes.WinError(ctypes.get_last_error())
            return process_mask.value

        previous = read_mask()
        available = [1 << index for index in range(ctypes.sizeof(ctypes.c_size_t) * 8) if previous & (1 << index)]
        if len(available) < count:
            raise RuntimeError('requested CPU affinity is unavailable')
        selected = sum(available[:count])
        if not api.SetProcessAffinityMask(handle, selected):
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            if read_mask() != selected:
                raise RuntimeError('CPU affinity did not take effect')
            yield count
        finally:
            if not api.SetProcessAffinityMask(handle, previous) or read_mask() != previous:
                raise RuntimeError('measurement could not restore its original CPU affinity')
    elif hasattr(os, 'sched_getaffinity'):
        previous = os.sched_getaffinity(0)
        if len(previous) < count:
            raise RuntimeError('requested CPU affinity is unavailable')
        selected = set(sorted(previous)[:count])
        os.sched_setaffinity(0, selected)
        try:
            if os.sched_getaffinity(0) != selected:
                raise RuntimeError('CPU affinity did not take effect')
            yield count
        finally:
            os.sched_setaffinity(0, previous)
    else:
        raise RuntimeError('CPU affinity is unavailable on this measurement host')


def busy_worker(seconds: float) -> None:
    deadline = time.monotonic() + seconds
    block = b"owned sentinel-blue collection pressure fixture" * 128
    while time.monotonic() < deadline:
        for _ in range(250):
            block = hashlib.sha256(block).digest()


def measure(*, workers: int, load_seconds: float, samples: int) -> dict:
    # Expiring load workers need only the standard library, including when
    # the caller loaded Sentinel from a zipapp in an embedded interpreter.
    from sentinel_blue import __version__, collectors
    from sentinel_blue.service_recovery import RECOVERY_FRESHNESS_SECONDS

    children = []
    rows = []
    timings = []
    originals = {}
    lock = threading.Lock()
    started = time.monotonic()
    load_elapsed = 0.0
    cleanup_verified = False

    def timed(name, original):
        def call(*args, **kwargs):
            before = time.monotonic()
            try:
                return original(*args, **kwargs)
            finally:
                with lock:
                    timings.append({'section': name, 'seconds': round(time.monotonic() - before, 3)})
        return call

    # Observe native helpers without changing their output, timeout, or errors.
    for name in ('_boot_id', '_windows_accounts', '_windows_services', '_windows_sessions',
                 '_windows_topology', '_windows_processes', '_windows_persistence',
                 '_windows_firewall', '_windows_interfaces', '_windows_security_events', '_integrity'):
        originals[name] = getattr(collectors, name)
        setattr(collectors, name, timed(name, originals[name]))

    try:
        with tempfile.TemporaryDirectory(prefix='sentinel-blue-collection-pressure-') as directory:
            target = Path(directory).resolve() / 'owned.conf'
            target.write_bytes(b'approved bounded pressure fixture\n')

            def sample(phase):
                timings.clear()
                before = time.monotonic()
                telemetry = collectors.collect(
                    'collection-pressure-fixture', authorized_networks=['127.0.0.0/8'],
                    authorized_hosts=['127.0.0.1'], excluded_hosts=[], integrity_paths=[str(target)],
                ).as_dict()
                elapsed = time.monotonic() - before
                age = time.time() - telemetry['observed_at']
                errors = telemetry.get('collector_errors', [])
                # Do not export native account names, addresses, paths, or raw provider errors.
                categories = sorted({
                    'timeout' if 'timed out' in str(error).lower() else
                    'query_budget' if 'budget' in str(error).lower() else
                    'identity' if 'identity' in str(error).lower() else 'other_collection_error'
                    for error in errors
                })
                row = {
                    'phase': phase, 'elapsed_seconds': round(elapsed, 3),
                    'observation_age_seconds': round(age, 3),
                    'collector_error_count': len(errors), 'error_categories': categories,
                    'boot_identity_available': telemetry.get('boot_id') not in (None, '', 'unknown'),
                    'inventory_counts': {name: len(telemetry.get(name, [])) for name in
                                         ('accounts', 'sessions', 'services', 'processes', 'integrity')},
                    'sections': list(timings),
                }
                fixture_rows = [item for item in telemetry.get('integrity', [])
                                if Path(item.get('path', '')).resolve() == target]
                row['protected_fixture_unchanged'] = (
                    len(fixture_rows) == 1
                    and fixture_rows[0].get('sha256') == hashlib.sha256(target.read_bytes()).hexdigest()
                    and (platform.system() != 'Windows' or bool(fixture_rows[0].get('security_descriptor_sha256')))
                )
                row['usable_for_recovery'] = (
                    0 <= age <= RECOVERY_FRESHNESS_SECONDS and not errors
                    and row['boot_identity_available'] and row['inventory_counts']['accounts'] > 0
                    and row['inventory_counts']['services'] > 0 and row['protected_fixture_unchanged']
                )
                rows.append(row)

            sample('idle')
            load_started = time.monotonic()
            # Workers have their own expiry even if the parent fails. Only the
            # exact child handles created here are stopped in finally.
            for _ in range(workers):
                children.append(subprocess.Popen(
                    [sys.executable, str(Path(__file__).resolve()), '--worker-seconds', str(load_seconds + 120)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                ))
            for index in range(samples):
                target_time = load_started + 3 + index * load_seconds / samples
                while time.monotonic() < target_time:
                    time.sleep(max(0, min(.25, target_time - time.monotonic())))
                if any(child.poll() is not None for child in children):
                    raise RuntimeError('an owned CPU worker exited before the loaded sample')
                sample('cpu_load')
                if any(child.poll() is not None for child in children):
                    raise RuntimeError('an owned CPU worker exited during the loaded sample')
            while time.monotonic() - load_started < load_seconds:
                time.sleep(.25)
            load_elapsed = time.monotonic() - load_started
            for child in children:
                if child.poll() is None:
                    child.terminate()
                child.wait(timeout=10)
            sample('after_load')
    finally:
        for child in children:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=10)
        cleanup_verified = all(child.poll() is not None for child in children)
        for name, original in originals.items():
            setattr(collectors, name, original)

    return {
        'schema_version': 1, 'version': __version__, 'platform': platform.system(),
        'commit': os.environ.get('GITHUB_SHA', '')[:40],
        'status': 'passed' if rows and all(row['usable_for_recovery'] for row in rows) and cleanup_verified else 'failed',
        'logical_cpu_count': os.cpu_count(), 'owned_cpu_workers': workers,
        'load_seconds': round(load_elapsed, 3), 'duration_seconds': round(time.monotonic() - started, 3),
        'freshness_limit_seconds': RECOVERY_FRESHNESS_SECONDS,
        'samples': rows, 'cleanup_verified': cleanup_verified,
        'limitations': ['one runner image and bounded CPU workload',
                        'read-only native collection; no service recovery or full-event uptime claim'],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--workers', type=int, default=min(os.cpu_count() or 1, 8))
    parser.add_argument('--load-seconds', type=float, default=180)
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--cpu-limit', type=int, help='limit this measurement and its children to this many CPUs')
    parser.add_argument('--worker-seconds', type=float, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker_seconds is not None:
        if not 0 < args.worker_seconds <= 1020:
            parser.error('worker lifetime must be between 0 and 1020 seconds')
        busy_worker(args.worker_seconds)
        return
    if not 1 <= args.workers <= 8 or not 3 <= args.load_seconds <= 900 or not 1 <= args.samples <= 10:
        parser.error('workers: 1..8; load-seconds: 3..900; samples: 1..10')
    if args.cpu_limit is not None and not 1 <= args.cpu_limit <= 8:
        parser.error('cpu-limit must be 1..8')
    with limit_cpus(args.cpu_limit) as applied_limit:
        report = measure(workers=args.workers, load_seconds=args.load_seconds, samples=args.samples)
        report['applied_cpu_limit'] = applied_limit
    report['affinity_restored'] = True
    encoded = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.output:
        args.output.write_text(encoded, encoding='utf-8')
    print(encoded, end='')
    raise SystemExit(0 if report['status'] == 'passed' else 1)


if __name__ == '__main__':
    main()
