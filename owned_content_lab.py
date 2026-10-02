"""Bounded native rehearsal using one newly owned, loopback-only service.

Requires explicit disposable-fixture approval. Refuses existing Sentinel
processes or a host ledger; it never adopts a service or resets a saved Pause.
Only new fixture content is faulted. Production release bytes stay unchanged.
No SQL, network recovery, account, authentication, or hypervisor changes.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import fcntl
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import zipfile

APP_SHA = '9e3a7d254d4866be393eac5649211e656446ae1c16651ee0d4f64933a33d3ab5'
CODE_SHA = '416f1239f35f8028fa2f882f16dfe12d0cfe269e7daa25ad91f3a32cbf653aba'
FAULT_BYTES = b'# Sentinel disposable coverage fault\n'
CODE_NAMES = {'campaign.py', 'kernel_immutable.py', 'measurement.py', 'nft_syntax.py',
              'observer.py', 'preflight.py', 'scored_scenarios.py'}
LOGIN_ROWS = None
TRANSACTIONS = Path('/var/lib/sentinel-blue-setup-transactions')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=20)


def private_root(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022):
        raise ValueError('fixture ancestry must be plain root-owned directories without shared write access')


def occupancy():
    rows = command('who').stdout.splitlines()
    if len(rows) != 1 or LOGIN_ROWS is not None and rows != LOGIN_ROWS:
        raise ValueError('one operator login is required; another login or unknown occupancy holds the lab')


def admission(args):
    global LOGIN_ROWS
    if (not args.ack_disposable_vm or not args.approve_owned_fixture or os.geteuid() != 0
            or Path('/proc/1/comm').read_text().strip() != 'systemd'
            or Path('/etc/pve').exists() or Path('/usr/bin/pveversion').exists()):
        raise ValueError('requires explicit approval for an idle disposable guest with native systemd; hypervisors refused')
    if os.environ.get('SENTINEL_LEDGER_DIR') or os.path.lexists('/var/lib/sentinel-blue-ledger'):
        raise ValueError('existing host ledger or ledger override requires separate review; no fixture created')
    if os.path.lexists(TRANSACTIONS):
        raise ValueError('existing native setup transactions require separate ownership review; no fixture created')
    for entry in Path('/proc').iterdir():
        if not entry.name.isdecimal() or int(entry.name) == os.getpid():
            continue
        try:
            argv = (entry / 'cmdline').read_bytes().split(b'\0')
        except (FileNotFoundError, ProcessLookupError):
            continue
        if any(b'sentinel-blue' in arg.lower() or b'sentinel_blue' in arg.lower() for arg in argv):
            raise ValueError('another Sentinel process exists; no fixture created')
    occupancy()
    LOGIN_ROWS = command('who').stdout.splitlines()
    for path in (Path('/'), Path('/srv'), Path('/etc'), Path('/etc/systemd'), Path('/etc/systemd/system')):
        private_root(path)
    app = Path(args.runtime).absolute().read_bytes()
    code = Path(args.validation_code).absolute().read_bytes()
    if digest(app) != APP_SHA or digest(code) != CODE_SHA:
        raise ValueError('application or seven-script validation archive differs from the reviewed release')
    return app, code


def wait_for(description, seconds, probe):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        occupancy()
        value = probe()
        if value:
            return value
        time.sleep(1)
    raise TimeoutError(description + ' was not confirmed before its deadline')


def review_profile(config, body, unit):
    """Review only this newly created fixture, before any runtime starts."""
    from sentinel_blue.auth import derive_enrollment_ticket
    from sentinel_blue.event_profile import EventProfile
    from sentinel_blue.scored_state import coverage_candidate
    from sentinel_blue.setup import compile_plan
    from sentinel_blue.state import read_private_json, write_private_json
    directory = Path(config['directory'])
    raw = read_private_json(config['event_profile'])
    manifest = raw['services'][0]
    owned = sorted([str(body), str(unit)])
    if len(raw['services']) != 1 or manifest['required_accounts'] or manifest['required_data']:
        raise ValueError('fixture review refuses accounts, data stores or additional services')
    if sorted(manifest['repair_policy']['restore_files']) != owned:
        raise ValueError('generated repair scope differs from the two owned fixture files')
    # Omit normal host-wide integrity observations from this narrow rehearsal.
    manifest['required_files'] = owned
    manifest['repair_policy']['host_files'] = []
    raw = coverage_candidate(raw, 'local-linux', unit.name,
                             [{'path': str(body), 'kind': 'content'}], repeated_disruption=True)
    pending = EventProfile.from_dict(raw)
    if raw['approval']['status'] != 'pending' or raw['release']['approved']:
        raise ValueError('new coverage must start unapproved')
    if (pending.raw['scope']['authorized_networks'] != ['127.0.0.1/32']
            or pending.raw['scope']['authorized_hosts'] != ['127.0.0.1']
            or pending.services[0]['repair_policy']['scored_targets'] != [{'path': str(body), 'kind': 'content'}]):
        raise ValueError('fixture review rejects expanded endpoint or fault scope')
    # --approve-owned-fixture grants this new range-only contract, never a
    # production release approval or an approval of an existing session.
    raw['approval'] = {'status': 'range-only', 'approved_by': 'owned-disposable-fixture-operator'}
    profile = EventProfile.from_dict(raw)
    profile.require_range_ready()
    profile.verify_release_file(config['runtime'])
    write_private_json(config['event_profile'], raw)
    master = read_private_json(directory / 'master.json')['token']
    write_private_json(directory / 'enrollment.json',
                       {'token': derive_enrollment_ticket(master, profile.fingerprint, 'local-linux')})
    probes = manifest['expected_transactions']
    write_private_json(directory / 'probes.json', {'probes': probes, 'protected_paths': owned})
    config['baseline_capture_paths'] = owned
    config['repair_coverage'][unit.name]['alert_only'] = []
    write_private_json(directory / 'session.json', config)
    inventory = read_private_json(config['inventory'])
    plan = compile_plan(inventory, profile, directory)
    tasks = plan['tasks']
    if (len(tasks) != 1 or tasks[0]['recipe'] != 'linux-service'
            or tasks[0]['service_key'] != ['local-linux', unit.name]
            or tasks[0]['configuration'].get('service') != unit.name):
        raise ValueError('reviewed setup must contain only the new fixture service')
    return plan, profile


def approve_clean_baseline(config, client):
    from sentinel_blue.desktop_control import verification_rows
    def ready():
        snap = client.dashboard()
        host = next((h for h in snap.get('agents', []) if h.get('agent_id') == 'local-linux'), {})
        rows = [r for r in verification_rows(snap) if r['kind'] == 'baseline' and r['id'] == 'local-linux']
        return rows[0] if rows and host.get('baseline_readiness', {}).get('ready') is True else None
    row = wait_for('healthy owned fixture baseline', 120, ready)
    client.decide(row, 'approve')  # Normal authenticated operator control.
    def captured():
        snap = client.dashboard()
        hosts = [h for h in snap.get('agents', []) if h.get('agent_id') == 'local-linux']
        actions = [a for a in snap.get('actions', []) if a.get('action_type') == 'capture_restore_point']
        return (len(hosts) == 1 and hosts[0].get('baseline_status') == 'approved'
                and actions and all(a.get('status') == 'completed' for a in actions))
    wait_for('authenticated clean restore capture', 90, captured)


def safe_remove_tree(root):
    """Remove only a fresh private generated tree, never shared files/symlinks."""
    private_root(root)
    entries = list(root.rglob('*'))
    if len(entries) > 20000:
        raise ValueError('owned fixture cleanup exceeds its reviewed bound')
    for path in entries:
        info = path.lstat()
        if info.st_uid != 0 or (not stat.S_ISDIR(info.st_mode) and not stat.S_ISREG(info.st_mode)):
            raise ValueError('changed ownership or unexpected entry requires manual fixture cleanup')
        if stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError('shared fixture directory requires manual cleanup')
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise ValueError('shared fixture file requires manual cleanup')
    shutil.rmtree(root)


def require_owned_file(path, allowed, expected_metadata):
    from sentinel_blue.restoration import RestorePointStore
    data, metadata = RestorePointStore._read_target(path)
    if data not in allowed or not RestorePointStore._metadata_matches(expected_metadata, metadata):
        raise ValueError('fixture bytes or security metadata changed outside the known test; preserve it for review')


def setup_evidence(report):
    """Keep bounded worker diagnostics, excluding private command output/inputs."""
    fields = {'status', 'error_type', 'reason', 'pause_reason', 'elapsed_seconds',
              'task_count', 'tasks_ready', 'all_declared_services_ready', 'changed',
              'healthy', 'returncode', 'uncertain', 'attempts', 'kind', 'seconds',
              'failure_reason', 'rollback_error_type', 'rollback_confirmed',
              'already_ready', 'latency_ms', 'output_sha256', 'output_bytes'}
    def project(value, depth=0):
        if depth > 8:
            return {'diagnostic_limit': True}
        if isinstance(value, list):
            return [project(item, depth + 1) for item in value[:64]]
        if not isinstance(value, dict):
            return value if value is None or type(value) in {bool, int, float} else str(value)[:500]
        result = {key: project(item, depth + 1) for key, item in value.items() if key in fields}
        for key in ('checks', 'final_checks', 'admission', 'apply', 'rollback', 'commit'):
            if key in value:
                result[key] = project(value[key], depth + 1)
        if 'tasks' in value:
            result['tasks'] = {name: project(row, depth + 1) for name, row in list(value['tasks'].items())[:8]}
        return result
    return project(report)


def remove_owned_transactions(unit, evidence=None, *, fixture_absent=False, expected_root=None, review_only=False):
    """Delete only completed records for this disposable unit under its lock.

    Refuse another transaction, pending resource claim, unknown file, or a
    live Sentinel process. Failed/uncertain transactions keep their ledger.
    """
    if not os.path.lexists(TRANSACTIONS):
        return []
    from sentinel_blue.state import read_private_json, write_private_json
    private_root(TRANSACTIONS)
    lock = TRANSACTIONS / 'lock'
    info = lock.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1 or info.st_mode & 0o022:
        raise ValueError('native transaction lock changed; preserve records')
    fd = os.open(lock, os.O_RDWR | os.O_NOFOLLOW)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if os.fstat(fd).st_ino != info.st_ino:
            raise ValueError('native transaction lock was replaced')
        entries = list(TRANSACTIONS.iterdir())
        records = []
        for entry in entries:
            if entry == lock:
                continue
            if not re.fullmatch('[0-9a-f]{32}', entry.name):
                raise ValueError('another native resource or unknown entry requires review')
            private_root(entry)
            if {p.name for p in entry.iterdir()} != {'state.json'}:
                raise ValueError('native transaction has additional files; preserve it')
            row = read_private_json(entry / 'state.json')
            spec = row.get('spec', {})
            if (row.get('status') not in {'committed', 'rolled-back'}
                    or spec.get('service') != unit or spec.get('recipe') != 'linux-service'
                    or spec.get('files') != []):
                raise ValueError('uncompleted or different native transaction requires its retained ledger')
            records.append({'transaction': entry.name, 'state': row})
        if review_only:
            if evidence is not None:
                write_private_json(evidence / 'completed-native-transactions.json', records)
            return records
        if fixture_absent:
            nonce = unit.removeprefix('sb-content-').removesuffix('.service')
            root = Path('/srv/sb-content-' + nonce)
            if (not re.fullmatch('[0-9a-f]{16}', nonce)
                    or os.path.lexists(root) and expected_root != root
                    or os.path.lexists('/etc/systemd/system/' + unit)
                    or command('systemctl', 'show', unit, '--property=LoadState', '--value').stdout.strip() != 'not-found'):
                raise ValueError('disposable fixture is not proved absent')
        else:
            raise ValueError('stop and remove the disposable fixture before deleting its completed native records')
        for entry in Path('/proc').iterdir():
            if not entry.name.isdecimal() or int(entry.name) == os.getpid():
                continue
            try:
                argv = (entry / 'cmdline').read_bytes().split(b'\0')
            except (FileNotFoundError, ProcessLookupError):
                continue
            if any(b'sentinel-blue' in arg.lower() or b'sentinel_blue' in arg.lower() for arg in argv):
                raise ValueError('a Sentinel process remains; preserve native transaction records')
        if evidence is not None:
            write_private_json(evidence / 'completed-native-transactions.json', records)
        for record in records:
            entry = TRANSACTIONS / record['transaction']
            if read_private_json(entry / 'state.json') != record['state']:
                raise ValueError('native transaction changed before cleanup')
            safe_remove_tree(entry)
        if set(TRANSACTIONS.iterdir()) != {lock}:
            raise ValueError('native transaction directory changed during cleanup')
        lock.unlink()
        TRANSACTIONS.rmdir()
        return records
    finally:
        os.close(fd)


def run(args):
    app, code = admission(args)
    nonce = secrets.token_hex(8)
    root = Path('/srv') / ('sb-content-' + nonce)
    evidence = Path('/srv') / ('sb-content-evidence-' + nonce)
    unit = Path('/etc/systemd/system') / ('sb-content-' + nonce + '.service')
    if (os.path.lexists(root) or os.path.lexists(evidence) or os.path.lexists(unit)
            or command('systemctl', 'show', unit.name, '--property=LoadState', '--value').stdout.strip() != 'not-found'):
        raise ValueError('fixture name is not unused')
    root.mkdir(mode=0o700)
    evidence.mkdir(mode=0o700)
    runtime = root / 'sentinel-blue.pyz'
    runtime.write_bytes(app); runtime.chmod(0o600)
    code_path = root / 'validation.zip'
    code_path.write_bytes(code); code_path.chmod(0o600)
    code_dir = root / 'validation'
    code_dir.mkdir(mode=0o700)
    with zipfile.ZipFile(code_path) as archive:
        if set(archive.namelist()) != CODE_NAMES or archive.testzip() is not None:
            raise ValueError('unexpected validation archive members')
        for name in sorted(CODE_NAMES):
            path = code_dir / name
            path.write_bytes(archive.read(name)); path.chmod(0o600)
    os.environ['SB_PYZ'] = str(runtime)
    os.environ['SENTINEL_LEDGER_DIR'] = str(root / 'ledger')
    sys.argv[0] = str(runtime)
    sys.path[:0] = [str(code_dir), str(runtime)]
    from sentinel_blue.linux_workspace import (prepare_workspace, local_observation, require_available_local_ports,
        activate_reviewed_session, client_for, request_running_session_stop, session_runner_alive)
    from sentinel_blue.desktop_jobs import detach, launch_job
    from sentinel_blue.setup import plan_digest
    from sentinel_blue.state import read_private_json, write_private_json
    from sentinel_blue.restoration import RestorePointStore
    from sentinel_blue import setup_redo
    from scored_scenarios import run as fault, check_running
    from campaign import execute
    from observer import observe
    body = root / 'body.txt'
    good = ('owned-content-' + nonce + '\n').encode()
    body.write_bytes(good); body.chmod(0o600)
    server = root / 'server.py'
    server_bytes = ("import http.server, pathlib, sys\n"
                    "path = pathlib.Path(sys.argv[1])\n"
                    "class H(http.server.BaseHTTPRequestHandler):\n"
                    " def do_GET(self):\n"
                    "  body = path.read_bytes()\n"
                    "  self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)\n"
                    " def log_message(self, *args): pass\n"
                    "http.server.HTTPServer(('127.0.0.1', int(sys.argv[2])), H).serve_forever()\n").encode()
    server.write_bytes(server_bytes); server.chmod(0o600)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
    unit_bytes = (f'[Unit]\nDescription=Disposable Sentinel content fixture {nonce}\n'
                  f'[Service]\nExecStart={sys.executable} {server} {body} {port}\n'
                  '[Install]\nWantedBy=multi-user.target\n').encode()
    owned_metadata = {str(path): RestorePointStore._read_target(path)[1] for path in (body, server)}
    config = runner = worker = observation = guard = None
    guard_stop = threading.Event()
    occupied = threading.Event()
    collected = {}
    result = {'schema': 1, 'release': '2.0.28', 'program_sha256': APP_SHA,
              'native_systemd': True, 'status': 'preparing', 'faults_requested': 3,
              'observer_seconds': 180, 'observer_interval_seconds': 5,
              'same_host_observer': True, 'external_scoring_measured': False,
              'continuous_uptime_measured': False, 'private_evidence': str(evidence)}
    try:
        occupancy()
        with unit.open('xb') as handle: handle.write(unit_bytes)
        unit.chmod(0o644)
        owned_metadata[str(unit)] = RestorePointStore._read_target(unit)[1]
        command('systemctl', 'daemon-reload'); command('systemctl', 'start', '--', unit.name)
        custom = [{'unit': unit.name, 'label': 'Owned disposable content fixture', 'files': [str(body)],
                   'check': {'kind': 'http', 'target': f'http://127.0.0.1:{port}/', 'timeout': 5,
                             'expected_status': [200], 'expected_body': good.decode().strip()}}]
        observed = local_observation()
        if observed['observation'].get('complete') is not True:
            raise ValueError('complete native listener observation is required')
        desktop = root / 'desktop'
        desktop.mkdir(mode=0o700)
        config, _ = prepare_workspace(desktop / 'sessions', runtime, [], {}, observed['presence'],
            autonomy='guarded-autonomous', port_observation=observed['observation'],
            custom_services=custom, local_addresses=[], repeated_disruption=True)
        plan, profile = review_profile(config, body, unit)
        result['profile_fingerprint'] = profile.fingerprint
        result['phase'] = 'session_startup'
        require_available_local_ports(config)
        session = str(Path(config['directory']) / 'session.json')
        runner = detach(['linux-desktop-session', '--session', session])
        def running():
            path = Path(config['directory']) / 'session-status.json'
            if not path.exists(): return False
            status = read_private_json(path, 4096)
            if status.get('state') == 'failed': raise RuntimeError('owned fixture runtime failed')
            return status.get('state') == 'running'
        wait_for('owned session startup', 60, running)
        client = client_for(config)
        def monitor_occupancy():
            while not guard_stop.wait(1):
                try:
                    occupancy()
                except Exception:
                    occupied.set()
                    # Stop only this newly owned session if occupancy changes.
                    try: client.request('/api/v1/governance/emergency-stop', {})
                    except Exception: pass
                    try:
                        from sentinel_blue.job_control import JobControl
                        if JobControl(desktop).path.exists(): JobControl(desktop).set_paused(True)
                    except Exception: pass
                    try: request_running_session_stop(config)
                    except Exception: pass
                    return
        guard = threading.Thread(target=monitor_occupancy, daemon=False)
        guard.start()
        activate_reviewed_session(config, client, occupancy)
        result['phase'] = 'owned_setup'
        job = {'inventory': config['inventory'], 'event_profile': config['event_profile'], 'runtime': str(runtime),
               'kind': 'setup', 'range_deployment': True, 'approved_digest': plan_digest(plan)}
        worker, job_path = launch_job(job, desktop / ('job-' + secrets.token_hex(8)))
        setup_redo.record_approved_setup(Path(config['directory']), job, job_root=desktop, job_path=job_path)
        report_path = job_path.parent / 'result.json'
        wait_for('owned setup completion', 120, lambda: report_path.exists())
        setup_report = read_private_json(report_path)
        collected['setup'] = setup_evidence(setup_report)
        write_private_json(evidence / 'setup-diagnostics.json', collected['setup'])
        result['setup'] = collected['setup']
        worker_code = worker.wait(timeout=20)
        result['setup_worker_exit_code'] = worker_code
        if setup_report.get('status') not in {'passed', 'ready'} or worker_code != 0:
            raise RuntimeError('owned setup did not pass; no fault injected')
        approve_clean_baseline(config, client)
        result['phase'] = 'recovery_budget'
        manifest = profile.services[0]
        occupancy(); check_running(config, profile, manifest, client)
        options = SimpleNamespace(event_profile=config['event_profile'], host='local-linux', service=unit.name,
                                  output=str(evidence), seconds=180, interval=5, vantage='same-host')
        def observe_window():
            try: collected['observer'] = observe(options)
            except Exception as exc: collected['observer_error'] = type(exc).__name__
        observation = threading.Thread(target=observe_window, daemon=False)
        observation.start()
        # Wait for a persisted pre-fault observation; don't miss the first fault.
        wait_for('first independent observer sample', 15,
                 lambda: any(p.stat().st_size for p in evidence.glob('probe-observer-*/probe-timeline.jsonl')))
        result['status'] = 'running'
        result['phase'] = 'content_faults_and_whole_window_observation'
        write_private_json(evidence / 'summary.json', result)
        with (evidence / 'scenario-output.txt').open('w') as output, contextlib.redirect_stdout(output):
            occupancy(); check_running(config, profile, manifest, client)
            first = fault(SimpleNamespace(session=session, ack_disposable_vm=True, service=unit.name,
                                          target=str(body), timeout=60))
            collected['first'] = first
            # No retries or mutation after a failed/held/unobserved scenario.
            time.sleep(15); occupancy()
            plan_path = evidence / 'campaign-plan.json'
            write_private_json(plan_path, {'schema': 1, 'rounds': 2, 'gap_seconds': 15,
                'scenarios': [{'service': unit.name, 'target': str(body), 'timeout': 60}]})
            collected['campaign'] = execute(SimpleNamespace(session=session, plan=str(plan_path), ack_disposable_vm=True),
                runner=lambda opt: (occupancy(), fault(opt))[1])
        result['status'] = ('passed' if collected['campaign'].get('status') == 'completed' else 'held')
    except (Exception, KeyboardInterrupt) as exc:
        result.update(status='held', error_type=type(exc).__name__, reason=str(exc)[:500])
    finally:
        # Keep the entire observer window even when a fault held.
        if observation:
            observation.join(timeout=185)
            if observation.is_alive(): result.update(status='held', observer_error='ObserverDidNotStop')
        guard_stop.set()
        if guard: guard.join(timeout=25)
        if occupied.is_set(): result.update(status='held', error_type='OccupancyChanged')
        if 'observer' in collected:
            observed_result = collected['observer']
            result['observer'] = {k: observed_result[k] for k in ('status', 'elapsed_seconds', 'probe_measurement')}
            result['observer']['probe_contract_sha256'] = observed_result['probe_contract_sha256']
            if observed_result['status'] != 'completed': result['status'] = 'held'
        if 'observer_error' in collected:
            result.update(status='held', observer_error=collected['observer_error'])
        first = collected.get('first')
        campaign = collected.get('campaign')
        if first:
            result['first_fault'] = {k: first.get(k) for k in ('status', 'fault_observed', 'recovered', 'elapsed_seconds')}
        if campaign:
            result['campaign'] = {k: campaign.get(k) for k in ('status', 'completed_faults', 'prevented_faults', 'maximum_recovery_seconds')}
        # Export full sanitized timelines before deleting runtime credentials.
        records = [r for r in [first, *(campaign or {}).get('scenarios', [])] if r]
        if config:
            # Also retain a failed scenario's persisted evidence, without retry.
            for path in sorted(Path(config['directory']).glob('scored-fault-*/result.json')):
                record = read_private_json(path)
                if record.get('private_evidence') not in {r.get('private_evidence') for r in records}:
                    records.append(record)
        collected['fault_records'] = records
        for record in records:
            timeline = record.get('probe_timeline')
            if timeline:
                record['retained_samples'] = [json.loads(line) for line in Path(timeline).read_text().splitlines()]
        if config:
            from sentinel_blue.job_control import JobControl
            try:
                request_running_session_stop(config)
                control = JobControl(Path(config['directory']).parents[1])
                if control.path.exists(): control.set_paused(True)
                if runner: runner.wait(timeout=55)
                if worker and worker.poll() is None: worker.wait(timeout=30)
                if session_runner_alive(config): raise RuntimeError('owned session lock remains held')
                from sentinel_blue.linux_workspace import read_previous_session_processes, _current_identity
                if any(_current_identity(identity) for _, identity in read_previous_session_processes(Path(config['directory']), config)):
                    raise RuntimeError('owned session child remains live')
                for entry in Path('/proc').iterdir():
                    if not entry.name.isdecimal() or int(entry.name) == os.getpid(): continue
                    try: argv = (entry / 'cmdline').read_bytes().split(b'\0')
                    except (FileNotFoundError, ProcessLookupError): continue
                    if str(runtime).encode() in argv:
                        raise RuntimeError('owned runtime child remains live')
                result['session_stopped'] = True
            except Exception as exc:
                result.update(status='held', cleanup_error=type(exc).__name__)
        try:
            remove_owned_transactions(unit.name, evidence, review_only=True)
            for path, allowed in ((server, {server_bytes}), (body, {good, FAULT_BYTES})):
                require_owned_file(path, allowed, owned_metadata[str(path)])
            if str(unit) in owned_metadata and not os.path.lexists(unit):
                raise ValueError('owned unit disappeared outside cleanup; preserve its fixture for review')
            if os.path.lexists(unit):
                if str(unit) not in owned_metadata:
                    raise ValueError('unit creation was incomplete; preserve the fixture for review')
                require_owned_file(unit, {unit_bytes}, owned_metadata[str(unit)])
                command('systemctl', 'stop', '--', unit.name)
                command('systemctl', 'disable', '--', unit.name)
                if command('systemctl', 'is-active', unit.name, check=False).returncode == 0:
                    raise RuntimeError('owned fixture service is still active')
                unit.unlink(); command('systemctl', 'daemon-reload')
            if (runner and runner.poll() is None) or (worker and worker.poll() is None):
                raise RuntimeError('owned runtime still active; preserve its files')
            # Keep the private job and ledger if transaction ownership needs
            # review. Never erase the only authenticated recovery evidence.
            completed = remove_owned_transactions(unit.name, evidence, fixture_absent=True, expected_root=root)
            result['completed_native_transactions_removed'] = len(completed)
            safe_remove_tree(root)
            result['fixture_removed'] = True
        except Exception as exc:
            result.update(status='held', cleanup_error=type(exc).__name__)
        write_private_json(evidence / 'summary.json', result)
        write_private_json(evidence / 'fault-records.json', records)
    print(json.dumps(result, indent=2), flush=True)
    if args.console_evidence:
        observer = collected.get('observer')
        timeline = ([json.loads(line) for line in Path(observer['probe_timeline']).read_text().splitlines()] if observer else [])
        payload = json.dumps({'summary': result, 'fault_records': collected.get('fault_records', []),
                              'observer_timeline': timeline}, sort_keys=True, separators=(',', ':')).encode()
        packed = gzip.compress(payload, mtime=0)
        encoded = base64.b64encode(packed).decode()
        print('PRIVATE_EVIDENCE_GZIP_SHA256=' + digest(packed))
        print('BEGIN_PRIVATE_EVIDENCE_BASE64')
        for offset in range(0, len(encoded), 96): print(encoded[offset:offset+96])
        print('END_PRIVATE_EVIDENCE_BASE64', flush=True)
    return 0 if result['status'] == 'passed' else 2


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', default='sentinel-blue.pyz')
    parser.add_argument('--validation-code', default='validation-2.0.28.zip')
    parser.add_argument('--ack-disposable-vm', action='store_true')
    parser.add_argument('--approve-owned-fixture', action='store_true')
    parser.add_argument('--console-evidence', action='store_true', help='print compressed private sanitized timelines for retention')
    parser.add_argument('--cleanup-completed-fixture', help='review and remove completed native records for an already absent disposable sb-content unit; no test starts')
    args = parser.parse_args()
    if args.cleanup_completed_fixture:
        if (not args.ack_disposable_vm or not args.approve_owned_fixture or os.geteuid() != 0
                or Path('/proc/1/comm').read_text().strip() != 'systemd'
                or Path('/etc/pve').exists() or Path('/usr/bin/pveversion').exists()
                or not re.fullmatch(r'sb-content-[0-9a-f]{16}\.service', args.cleanup_completed_fixture)
                or os.environ.get('SENTINEL_LEDGER_DIR') or os.path.lexists('/var/lib/sentinel-blue-ledger')):
            raise ValueError('completed-fixture cleanup requires explicit owned disposable guest approval and no existing host ledger')
        occupancy()
        runtime = Path(args.runtime).absolute()
        if digest(runtime.read_bytes()) != APP_SHA:
            raise ValueError('cleanup requires the frozen reviewed application')
        sys.path.insert(0, str(runtime))
        records = remove_owned_transactions(args.cleanup_completed_fixture, fixture_absent=True)
        print(json.dumps({'schema': 1, 'status': 'completed', 'unit': args.cleanup_completed_fixture,
                          'completed_native_transactions_removed': len(records), 'retained_states': records}, indent=2))
        raise SystemExit(0)
    raise SystemExit(run(args))
