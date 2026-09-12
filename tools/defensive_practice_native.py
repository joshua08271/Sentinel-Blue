"""Defensive Azure acceptance: setup, ordinary faults, continuity and read-only load.

This entry point never imports the account/persistence or red-team campaigns.
Native fixtures own their service instances and verify cleanup before proceeding.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import urllib.request


def native_repair():
    from tools import service_repair_native as repair
    from sentinel_blue.controller import assess_baseline_readiness
    checks, samples = {}, []
    errors, seconds = {}, None
    def observe(sample):
        samples.append({'collection_seconds': round(time.time()-sample['observed_at'], 3),
                        'collector_errors': sample.get('collector_errors', []),
                        'readiness': assess_baseline_readiness(sample)})
    with tempfile.TemporaryDirectory(prefix='defensive-repair-', dir=Path(__file__).resolve().parent) as directory:
        root = Path(directory)
        executable = root / ('owned-service.exe' if os.name == 'nt' else 'owned-service.py')
        if os.name == 'nt':
            repair.powershell_json("Add-Type -TypeDefinition $p.source -OutputAssembly $p.output -OutputType WindowsApplication -ReferencedAssemblies System.ServiceProcess,System; 'true'",
                                   {'source': repair.CSHARP_WORKER, 'output': str(executable)})
        else:
            executable.write_text(repair.PYTHON_WORKER)
            executable.chmod(0o700)
        try:
            seconds = repair.scenario(root/'native', executable, 'missing_file', checks,
                                      native_collection=True, observation_interval=15,
                                      sample_observer=observe)
        except Exception as exc:
            errors['native_recovery'] = type(exc).__name__+': '+str(exc)[:450]
    return {'passed': not errors and bool(checks) and all(checks.values()), 'checks': checks,
            'repair_seconds': seconds, 'samples': samples, 'errors': errors,
            'observation_interval_seconds': 15, 'telemetry_source': 'full native collector',
            'cleanup_verified': checks.get('missing_file_fixture_removed') is True}


def rehearse():
    from sentinel_blue import __version__
    from tools import agent_transport_rehearsal, probe_timing_rehearsal, service_repair_native, smoke_release
    from tools.measure_collection_pressure import measure
    root = Path(__file__).resolve().parent
    options = json.loads((root/'run-options.json').read_text())
    mode = options['mode']
    if mode not in ('full', 'recovery'):
        raise ValueError('Unsupported defensive test mode')
    setup_budget = options.get('setup_budget_seconds', 180)
    if type(setup_budget) is not int or not 180 <= setup_budget <= 600:
        raise ValueError('Unsupported setup diagnostic stop limit')
    runtime = root/'runtime.pyz'
    started = time.monotonic()
    phases = {}
    report = {'version': __version__, 'runtime_sha256': hashlib.sha256(runtime.read_bytes()).hexdigest(),
              'platform': 'Windows' if os.name == 'nt' else 'Linux', 'phases': phases,
              'live_red_team_executed': False, 'full_network_test_executed': False,
              'full_competition_readiness_proven': False,
              'scope': 'guest-local defensive acceptance on actual Azure VMs', 'mode': mode,
              'opening_goal_seconds': 180, 'setup_stop_limit_seconds': setup_budget}

    def phase(name, operation):
        before = time.monotonic()
        try:
            result = operation()
        except Exception as exc:
            import traceback
            (root/(name+'-private-error.txt')).write_text(traceback.format_exc())
            result = {'passed': False, 'error_type': type(exc).__name__}
        (root/('defensive-'+name+'.json')).write_text(json.dumps(result, indent=2))
        phases[name] = {'passed': result.get('passed', result.get('status') == 'passed'),
                        'seconds': round(time.monotonic()-before, 3)}
        for key in ('error_type', 'checks', 'errors', 'cleanup_verified', 'repair_seconds'):
            if key in result:
                phases[name][key] = result[key]
        (root/'defensive-progress.json').write_text(json.dumps(report, indent=2))
        return result

    if mode == 'recovery':
        native = phase('native_recovery', native_repair)
        report['cleanup'] = {'verified': native.get('cleanup_verified') is True}
        if report['cleanup']['verified']:
            pressure = phase('collection_pressure', lambda: measure(workers=1, load_seconds=90, samples=2))
            phases['collection_pressure']['samples'] = [{key: row[key] for key in
                ('phase', 'elapsed_seconds', 'observation_age_seconds', 'collector_error_count', 'usable_for_recovery')}
                for row in pressure.get('samples', [])]
            phase('probe_deadlines', lambda: probe_timing_rehearsal.rehearse(repeats=5))
        report.update(passed=len(phases)==3 and all(row['passed'] for row in phases.values()),
                      seconds=round(time.monotonic()-started, 3))
        return report

    def setup():
        request = urllib.request.Request('http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                                         headers={'Metadata': 'true'})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=5) as response:
            identity = json.load(response)['compute']['resourceId']
        output = root/'setup-defensive-result.json'
        with (root/'setup-private.log').open('w') as stream:
            completed = subprocess.run([sys.executable, str(root/'tools/azure_setup_guest.py'),
                '--runtime', str(runtime), '--expected-resource-id', identity, '--output', str(output),
                '--with-defender', '--budget-seconds', str(setup_budget)], stdout=stream, stderr=subprocess.STDOUT, timeout=900)
        result = json.loads(output.read_text()) if output.is_file() else {
            'status': 'failed', 'error_type': 'SetupResultMissing'}
        if completed.returncode:
            result['status'] = 'failed'
        return result

    opening = phase('setup', setup)
    report['cleanup'] = opening.get('cleanup', {})
    for key in ('complete_opening_seconds', 'complete_opening_within_budget',
                'complete_opening_under_180_seconds', 'opening_clock_scope'):
        if key in opening:
            phases['setup'][key] = opening[key]
    phases['setup']['cleanup_verified'] = report['cleanup'].get('verified') is True
    if (not phases['setup']['cleanup_verified'] or
            opening.get('defender_cleanup', {}).get('verified') is not True):
        report.update(passed=False, stopped_for_unverified_cleanup=True,
                      seconds=round(time.monotonic()-started, 3))
        return report
    phase('transport', lambda: agent_transport_rehearsal.rehearse(repeats=5))
    phase('probe_deadlines', lambda: probe_timing_rehearsal.rehearse(repeats=3))
    phase('controller_continuity', lambda: smoke_release.smoke(runtime, exercise_crash_resume=os.name=='posix'))
    repaired = phase('service_repair', service_repair_native.rehearse)
    required = [kind+'_fixture_removed' for kind in ('damaged_files', 'missing_file', 'running_unhealthy', 'failed_validation')]
    phases['service_repair']['cleanup_verified'] = all(repaired.get('checks', {}).get(key) is True for key in required)
    if phases['service_repair']['cleanup_verified']:
        native = phase('native_recovery', native_repair)
        if native.get('cleanup_verified') is True:
            pressure = phase('collection_pressure', lambda: measure(workers=1, load_seconds=90, samples=2))
            keys = ('phase', 'elapsed_seconds', 'observation_age_seconds', 'collector_error_count', 'usable_for_recovery')
            phases['collection_pressure']['samples'] = [{key: row[key] for key in keys} for row in pressure.get('samples', [])]
    report.update(passed=len(phases)==7 and all(row['passed'] for row in phases.values()),
                  seconds=round(time.monotonic()-started, 3))
    return report


def summary(report):
    result = {key: value for key, value in report.items() if key != 'phases'}
    result['phases'] = {}
    for name, row in report.get('phases', {}).items():
        result['phases'][name] = {key: value for key, value in row.items() if key not in ('checks', 'errors')}
        checks = row.get('checks', {})
        result['phases'][name]['failed_checks'] = [key for key, value in checks.items() if value is False]
        result['phases'][name]['errors'] = row.get('errors', {})
    return result
