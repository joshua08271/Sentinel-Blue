"""Boot/readiness rehearsal for the exact private Sentinel Azure lab.

Run in an already authenticated Azure Cloud Shell. With --start-and-check,
start only initially deallocated, validated VMs, collect read-only guest facts,
and deallocate every attempted start in finally. This is not service setup or
an acceptance pass. It never changes Azure identity, network, VM size or disks.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import uuid


GROUP = "sentinel-blue-range-wus2"
HOSTS = {"sb-controller": "Linux", "sb-linux-target": "Linux",
         "sb-redsim": "Linux", "sb-windows-target": "Windows"}
MARKER = "SENTINEL_AZURE_PREFLIGHT_V1="

LINUX_CHECK = r'''set -eu
if ! command -v python3 >/dev/null 2>&1; then
  printf '%s\n' 'SENTINEL_AZURE_PREFLIGHT_V1={"schema":1,"platform":"Linux","python":null}'
  exit 0
fi
python3 - <<'SB_PY'
import json, os, platform, shutil, socket, subprocess, sys
def listener(port):
    try:
        with socket.create_connection(('127.0.0.1', port), timeout=2):
            return True
    except OSError:
        return False
def service(name):
    if not shutil.which('systemctl'):
        return 'unavailable'
    try:
        p = subprocess.run(['systemctl', 'is-active', name], stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, universal_newlines=True, timeout=10)
        return p.stdout.strip() if p.stdout.strip() in ['active', 'inactive', 'failed', 'unknown', 'activating'] else 'unknown'
    except (OSError, subprocess.TimeoutExpired):
        return 'unknown'
release = {}
try:
    with open('/etc/os-release') as f:
        for line in f:
            key, sep, value = line.strip().partition('=')
            if sep and key in ['ID', 'VERSION_ID']:
                release[key] = value.strip('"')[:80]
except OSError:
    pass
facts = {'schema': 1, 'platform': 'Linux', 'os_id': release.get('ID'),
         'os_version': release.get('VERSION_ID'), 'python': platform.python_version(),
         'cpu_count': os.cpu_count(),
         'memory_mb': round(os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES') / 1048576),
         'disk_free_mb': shutil.disk_usage('/').free // 1048576,
         'tools': {k: bool(shutil.which(k)) for k in ['bash', 'timeout', 'ssh', 'sudo', 'curl', 'systemctl', 'pwsh']},
         'services': {k: service(k) for k in ['ssh', 'sshd']},
         'ssh_listener': listener(22), 'winrm_https_listener': listener(5986)}
print('SENTINEL_AZURE_PREFLIGHT_V1=' + json.dumps(facts, separators=(',', ':')))
SB_PY
'''

WINDOWS_CHECK = r'''$ErrorActionPreference = 'Stop'
$osInfo = Get-CimInstance Win32_OperatingSystem
$machine = Get-CimInstance Win32_ComputerSystem
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
$pythonVersion = $null
$python = Get-Command python.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
if ($python) {
    $versionText = (& $python.Source --version 2>&1 | Out-String).Trim()
    if ($versionText -match '^Python (\d+\.\d+\.\d+)') { $pythonVersion = $Matches[1] }
}
$services = @{}
foreach ($name in @('W3SVC', 'DNS', 'WinRM', 'sshd')) {
    $service = Get-Service -Name $name -ErrorAction SilentlyContinue
    $services[$name] = if ($service) { [string]$service.Status } else { 'absent' }
}
$ports = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty LocalPort)
$facts = [ordered]@{
    schema = 1; platform = 'Windows'; os_id = [string]$osInfo.Caption
    os_version = [string]$osInfo.Version; python = $pythonVersion
    cpu_count = [int]$machine.NumberOfLogicalProcessors
    memory_mb = [int][math]::Round($machine.TotalPhysicalMemory / 1MB)
    disk_free_mb = [int][math]::Floor($disk.FreeSpace / 1MB)
    powershell = [string]$PSVersionTable.PSVersion; services = $services
    ssh_listener = ($ports -contains 22); winrm_https_listener = ($ports -contains 5986)
}
Write-Output ('SENTINEL_AZURE_PREFLIGHT_V1=' + ($facts | ConvertTo-Json -Depth 5 -Compress))
'''


class PreflightError(RuntimeError):
    pass


class Azure:
    def __init__(self, work: Path):
        self.work = work
        self.subscription = None

    def call(self, *args, timeout=60):
        command = ['az', *args, '--only-show-errors', '--output', 'json']
        if self.subscription:
            command.extend(['--subscription', self.subscription])
        log = self.work / (uuid.uuid4().hex + '.log')
        with log.open('xb') as output:
            try:
                result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                        stderr=output, timeout=max(1, timeout), check=False)
            except subprocess.TimeoutExpired as exc:
                raise PreflightError('Azure call timed out: ' + ' '.join(args[:2])) from exc
        if result.returncode:
            raise PreflightError('Azure call failed: ' + ' '.join(args[:2]) + '; see private diagnostics')
        try:
            return json.loads(result.stdout) if result.stdout.strip() else None
        except (UnicodeDecodeError, ValueError) as exc:
            raise PreflightError('Azure returned invalid JSON') from exc


def instance_view(response):
    """Azure CLI wraps VM statuses/agent facts inside instanceView.

    Also accept a direct instance-view object, but reject ambiguous mixtures.
    Malformed or absent nested data must never become a ready/off state.
    """
    if not isinstance(response, dict):
        return {}
    if 'instanceView' not in response:
        return response
    nested = response['instanceView']
    if not isinstance(nested, dict) or any(key in response for key in ['statuses', 'vmAgent']):
        return {}
    return nested


def power(response):
    view = instance_view(response)
    codes = [x.get('code') for x in (view.get('statuses') or [])
             if isinstance(x, dict) and str(x.get('code', '')).startswith('PowerState/')]
    return codes[0] if len(codes) == 1 else 'unknown'


def agent_ready(response):
    view = instance_view(response)
    agent = view.get('vmAgent') or {}
    return isinstance(agent, dict) and any(isinstance(x, dict) and
               str(x.get('code', '')).lower() == 'provisioningstate/succeeded'
               for x in (agent.get('statuses') or []))


def parallel(names, action):
    """Finish every submitted operation before reporting errors to the caller."""
    values, failures = {}, {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = {pool.submit(action, name): name for name in names}
        for future in concurrent.futures.as_completed(futures):
            name = futures[future]
            try:
                values[name] = future.result()
            except Exception as exc:
                failures[name] = type(exc).__name__ + ': ' + str(exc)
    return values, failures


def guard(azure):
    account = azure.call('account', 'show')
    try:
        azure.subscription = str(uuid.UUID(account['id']))
    except (KeyError, TypeError, ValueError) as exc:
        raise PreflightError('No valid selected Azure subscription') from exc
    group_id = '/subscriptions/' + azure.subscription + '/resourceGroups/' + GROUP
    group = azure.call('group', 'show', '--name', GROUP)
    if group.get('id', '').lower() != group_id.lower():
        raise PreflightError('Unexpected resource-group scope')
    records = azure.call('vm', 'list', '--resource-group', GROUP)
    if not isinstance(records, list) or len(records) != 4 or sorted(x.get('name', '') for x in records) != sorted(HOSTS):
        raise PreflightError('Expected exactly the four Sentinel lab VMs')
    vms = {}
    for record in records:
        name = record['name']
        vm_id = group_id + '/providers/Microsoft.Compute/virtualMachines/' + name
        if record.get('id', '').lower() != vm_id.lower():
            raise PreflightError('Unexpected VM resource identity')
        if record.get('storageProfile', {}).get('osDisk', {}).get('osType') != HOSTS[name]:
            raise PreflightError('Unexpected OS for ' + name)
        if record.get('provisioningState') != 'Succeeded':
            raise PreflightError('VM provisioning is not settled for ' + name)
        nics = record.get('networkProfile', {}).get('networkInterfaces', [])
        if not nics:
            raise PreflightError('Missing network interface for ' + name)
        for nic in nics:
            nic_id = nic.get('id', '')
            prefix = group_id + '/providers/Microsoft.Network/networkInterfaces/'
            if not nic_id.lower().startswith(prefix.lower()) or '/' in nic_id[len(prefix):] or not nic_id[len(prefix):]:
                raise PreflightError('NIC is outside the fixed lab resource group')
            info = azure.call('network', 'nic', 'show', '--ids', nic_id)
            if info.get('id', '').lower() != nic_id.lower():
                raise PreflightError('Unexpected NIC resource identity')
            configurations = info.get('ipConfigurations', [])
            if not configurations or any(x.get('publicIPAddress') is not None for x in configurations):
                raise PreflightError('NIC has a public-IP attachment or no readable IP configuration')
        vms[name] = {'id': vm_id, 'os': HOSTS[name], 'size': record.get('hardwareProfile', {}).get('vmSize')}
    views, errors = parallel(vms, lambda name: azure.call('vm', 'get-instance-view', '--ids', vms[name]['id']))
    if errors:
        raise PreflightError('Could not read all initial VM power states')
    for name, view in views.items():
        vms[name]['initial_power'] = power(view)
    return vms


def guest_facts(result, expected_os):
    rows = result.get('value', []) if isinstance(result, dict) else []
    if not rows or any(not isinstance(x, dict) or str(x.get('level', '')).lower() == 'error' or
                       not str(x.get('code', '')).lower().endswith('/succeeded') for x in rows):
        raise PreflightError('Guest readiness command did not complete successfully')
    matches = []
    for row in rows:
        for line in str(row.get('message', '')).splitlines():
            if line.startswith(MARKER):
                try:
                    matches.append(json.loads(line[len(MARKER):]))
                except ValueError as exc:
                    raise PreflightError('Guest result was truncated or invalid') from exc
    if len(matches) != 1 or not isinstance(matches[0], dict):
        raise PreflightError('Expected one complete guest readiness result')
    facts = matches[0]
    if facts.get('schema') != 1 or facts.get('platform') != expected_os:
        raise PreflightError('Guest result does not match expected OS/schema')
    # Only these facts may enter the shareable report. No raw Run Command logs,
    # usernames, resource IDs, private addresses, keys or environment variables.
    text_fields = ['os_id', 'os_version', 'python', 'powershell']
    clean = {'schema': 1, 'platform': expected_os}
    for key in text_fields:
        value = facts.get(key)
        clean[key] = value[:100] if isinstance(value, str) else None
    for key in ['cpu_count', 'memory_mb', 'disk_free_mb']:
        value = facts.get(key)
        clean[key] = value if type(value) is int and value >= 0 else None
    for key in ['ssh_listener', 'winrm_https_listener']:
        clean[key] = facts.get(key) if type(facts.get(key)) is bool else None
    for field, keys in [('tools', ['bash', 'timeout', 'ssh', 'sudo', 'curl', 'systemctl', 'pwsh']),
                        ('services', ['ssh', 'sshd', 'W3SVC', 'DNS', 'WinRM'])]:
        source = facts.get(field, {})
        if not isinstance(source, dict):
            raise PreflightError('Invalid guest field: ' + field)
        clean[field] = {key: source[key] for key in keys if key in source and
                        (type(source[key]) is bool or source[key] in
                         ['Running', 'Stopped', 'absent', 'active', 'inactive', 'failed', 'unknown', 'activating', 'unavailable'])}
    return clean


def inspect_guest(azure, name, vm):
    script = LINUX_CHECK if vm['os'] == 'Linux' else WINDOWS_CHECK
    path = azure.work / (name + ('.sh' if vm['os'] == 'Linux' else '.ps1'))
    path.write_bytes(script.encode('utf-8'))
    result = azure.call('vm', 'run-command', 'invoke', '--ids', vm['id'], '--command-id',
                        'RunShellScript' if vm['os'] == 'Linux' else 'RunPowerShellScript',
                        '--scripts', '@' + str(path), timeout=300)
    return guest_facts(result, vm['os'])


def wait_for(azure, vms, names, seconds, *, running, clock=time.monotonic, sleep=time.sleep):
    deadline = clock() + seconds
    pending = set(names)
    while pending and clock() < deadline:
        print('Waiting for ' + ('boot/guest agent: ' if running else 'deallocation: ') + ', '.join(sorted(pending)), flush=True)
        views, _errors = parallel(sorted(pending), lambda name: azure.call(
            'vm', 'get-instance-view', '--ids', vms[name]['id'], timeout=min(60, max(1, deadline - clock()))))
        for name, view in views.items():
            if ((power(view) == 'PowerState/running' and agent_ready(view)) if running
                    else power(view) == 'PowerState/deallocated'):
                pending.remove(name)
        if pending and clock() < deadline:
            sleep(min(15, max(0, deadline - clock())))
    if pending:
        raise PreflightError('Timed out waiting for ' + ', '.join(sorted(pending)))


def readiness(facts):
    blockers = ['1.9.26 WinRM setup requires a Windows controller; sb-controller is Linux']
    for name, row in facts.items():
        match = re.fullmatch(r'(\d+)\.(\d+)\.\d+', row.get('python') or '')
        if not match or tuple(map(int, match.groups())) < (3, 11):
            blockers.append(name + ': Python 3.11+ was not found in the guest agent environment')
    return blockers


def cleanup(azure, vms, names, seconds=600, *, clock=time.monotonic, sleep=time.sleep):
    """Retry deallocation when an uncertain start still has an Azure operation pending."""
    deadline = clock() + seconds
    pending = set(names)
    while pending and clock() < deadline:
        print('Verifying deallocation: ' + ', '.join(sorted(pending)), flush=True)
        views, _ = parallel(sorted(pending), lambda name: azure.call(
            'vm', 'get-instance-view', '--ids', vms[name]['id'], timeout=min(60, max(1, deadline - clock()))))
        pending.difference_update(name for name, view in views.items() if power(view) == 'PowerState/deallocated')
        request = [name for name in pending if power(views.get(name, {})) != 'PowerState/deallocating']
        if request and clock() < deadline:
            parallel(request, lambda name: azure.call('vm', 'deallocate', '--ids', vms[name]['id'],
                     '--no-wait', timeout=min(90, max(1, deadline - clock()))))
        if pending and clock() < deadline:
            sleep(min(15, max(0, deadline - clock())))
    if pending:
        raise PreflightError('Deallocation was not verified for all attempted starts')


def run(azure, *, start_and_check=False):
    vms = guard(azure)
    report = {'kind': 'azure-boot-and-guest-preflight', 'status': 'inventory_verified',
              'no_public_ip_attachments': True, 'resource_group': GROUP,
              'vms': {name: {k: v for k, v in row.items() if k != 'id'} for name, row in vms.items()},
              'full_setup_test_executed': False, 'full_competition_readiness_proven': False}
    if not start_and_check:
        return report
    if any(x['initial_power'] != 'PowerState/deallocated' for x in vms.values()):
        raise PreflightError('Boot rehearsal requires all four VMs initially deallocated; no starts attempted')
    attempted = list(vms)
    clock = time.monotonic()
    # Persist the exact resource IDs and initial states before requesting any
    # starts. A killed Cloud Shell cannot run finally; this record supports
    # manual recovery through the already authorized Azure account.
    (azure.work / 'power-intent.json').write_text(json.dumps(
        {'subscription': azure.subscription, 'vms': vms, 'attempted_starts': attempted}), encoding='utf-8')
    try:
        print('Starting the four validated lab VMs. Cleanup will deallocate them after these read-only checks.', flush=True)
        _, errors = parallel(attempted, lambda name: azure.call('vm', 'start', '--ids', vms[name]['id'], '--no-wait', timeout=90))
        if errors:
            raise PreflightError('One or more VM start requests failed; restoring the initial power state')
        wait_for(azure, vms, attempted, 600, running=True)
        report['boot_and_agent_ready_seconds'] = round(time.monotonic() - clock, 3)
        print('VM agents are ready. Collecting OS, Python, capacity and management listener facts.', flush=True)
        facts, errors = parallel(attempted, lambda name: inspect_guest(azure, name, vms[name]))
        report['guests'] = facts
        report['guest_errors'] = errors
        report['setup_blockers'] = readiness(facts)
        report['status'] = 'boot_and_guest_checks_passed' if not errors and len(facts) == 4 else 'guest_checks_failed'
    except (Exception, KeyboardInterrupt) as exc:
        report['status'] = 'interrupted' if isinstance(exc, KeyboardInterrupt) else 'failed'
        report['error'] = str(exc) if isinstance(exc, PreflightError) else type(exc).__name__
    finally:
        report['preflight_seconds_before_cleanup'] = round(time.monotonic() - clock, 3)
        print('Deallocating every VM whose start was attempted.', flush=True)
        try:
            cleanup(azure, vms, attempted)
            report['all_vms_deallocated'] = True
        except (Exception, KeyboardInterrupt):
            report['all_vms_deallocated'] = False
            report['status'] = 'cleanup_not_verified'
        report['total_seconds_including_cleanup'] = round(time.monotonic() - clock, 3)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--start-and-check', action='store_true', help='Boot the fixed lab, run read-only guest checks, then deallocate it')
    args = parser.parse_args()
    if os.name != 'posix':
        parser.error('Run this tool in Azure Cloud Shell using Bash')
    os.umask(0o077)
    import fcntl
    # This lock prevents overlapping copies in the same Cloud Shell home.
    # It is not a distributed Azure lease; do not run another lab controller.
    lock_path = Path.home() / '.sentinel-azure-preflight.lock'
    fd = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error('Another preflight is already running in this Cloud Shell')
        work = Path(tempfile.mkdtemp(prefix='sentinel-azure-preflight-'))
        print('Private diagnostics: ' + str(work), flush=True)
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, interrupted)
        try:
            report = run(Azure(work), start_and_check=args.start_and_check)
        except Exception as exc:
            report = {'kind': 'azure-boot-and-guest-preflight', 'status': 'blocked_before_start',
                      'error': str(exc) if isinstance(exc, PreflightError) else type(exc).__name__,
                      'full_setup_test_executed': False, 'full_competition_readiness_proven': False}
        report['preflight_script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['diagnostics_directory'] = str(work)
        path = work / 'result.json'
        path.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2), flush=True)
        print('Result saved to ' + str(path), flush=True)
        if report.get('all_vms_deallocated') is False:
            print('Cleanup is NOT verified. Use Azure portal to stop/deallocate the four lab VMs.', file=sys.stderr)
        return 0 if report['status'] in ['inventory_verified', 'boot_and_guest_checks_passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
