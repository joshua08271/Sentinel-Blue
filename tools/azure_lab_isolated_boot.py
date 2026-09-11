"""Temporarily detach the lab's three reserved IPs for a private boot rehearsal.

Default mode only reviews the current network. The explicit rehearsal mode
requires the reviewed network digest, keeps the static public IP resources,
uses the unchanged private-NIC preflight, deallocates the VMs, and restores the
original associations. Run only in authenticated Azure Cloud Shell Bash, with
no other lab controller active. No service setup is performed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import uuid

try:
    from . import azure_lab_preflight as lab
except ImportError:
    import azure_lab_preflight as lab


PUBLIC_HOSTS = {'sb-controller', 'sb-linux-target', 'sb-windows-target'}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def stable_network(value):
    """Ignore Azure operation metadata and only the association we will change."""
    def clean(item):
        if isinstance(item, dict):
            return {k: clean(v) for k, v in item.items() if k not in ['etag', 'provisioningState']}
        if isinstance(item, list):
            return [clean(v) for v in item]
        return item
    result = clean(value)
    # Azure may omit this generated suffix after boot/deallocation. It is
    # derived metadata, not the operator's DNS server or DNS-label settings.
    # Preserve checks on every configured DNS value and all NIC addressing.
    dns = result.get('dnsSettings')
    if isinstance(dns, dict):
        dns.pop('internalDomainNameSuffix', None)
    for config in result.get('ipConfigurations', []):
        config.pop('publicIPAddress', None)
    return result


def attached(config):
    value = config.get('publicIPAddress')
    if value is None:
        return None
    if not isinstance(value, dict) or not isinstance(value.get('id'), str):
        raise lab.PreflightError('Unreadable public IP association')
    return value['id'].lower()


def require_off(azure, vms):
    views, errors = lab.parallel(vms, lambda name: azure.call('vm', 'get-instance-view', '--ids', vms[name]['id']))
    if errors or any(lab.power(views.get(name, {})) != 'PowerState/deallocated' for name in vms):
        raise lab.PreflightError('All four VMs must be verified deallocated before changing IP associations')


def snapshot(azure, *, allow_detached=False):
    account = azure.call('account', 'show')
    try:
        azure.subscription = str(uuid.UUID(account['id']))
    except (KeyError, TypeError, ValueError) as exc:
        raise lab.PreflightError('Invalid selected Azure subscription') from exc
    prefix = '/subscriptions/' + azure.subscription + '/resourceGroups/' + lab.GROUP
    group = azure.call('group', 'show', '--name', lab.GROUP)
    if group.get('id', '').lower() != prefix.lower():
        raise lab.PreflightError('Unexpected resource group')
    records = azure.call('vm', 'list', '--resource-group', lab.GROUP)
    if not isinstance(records, list) or len(records) != 4 or sorted(x.get('name', '') for x in records) != sorted(lab.HOSTS):
        raise lab.PreflightError('Expected exactly the four Sentinel lab VMs')
    vms, network = {}, {}
    for record in records:
        name = record['name']
        vm_id = prefix + '/providers/Microsoft.Compute/virtualMachines/' + name
        nic_id = prefix + '/providers/Microsoft.Network/networkInterfaces/' + name + '-nic'
        refs = record.get('networkProfile', {}).get('networkInterfaces', [])
        if (record.get('id', '').lower() != vm_id.lower() or
                record.get('provisioningState') != 'Succeeded' or
                record.get('storageProfile', {}).get('osDisk', {}).get('osType') != lab.HOSTS[name] or
                len(refs) != 1 or refs[0].get('id', '').lower() != nic_id.lower()):
            raise lab.PreflightError('Unexpected VM or NIC identity for ' + name)
        nic = azure.call('network', 'nic', 'show', '--ids', nic_id)
        configs = nic.get('ipConfigurations', [])
        if (nic.get('id', '').lower() != nic_id.lower() or
                nic.get('virtualMachine', {}).get('id', '').lower() != vm_id.lower() or
                nic.get('provisioningState') != 'Succeeded' or len(configs) != 1):
            raise lab.PreflightError('Unexpected NIC state for ' + name)
        config = configs[0]
        config_name = config.get('name', '')
        config_id = nic_id + '/ipConfigurations/' + config_name
        if not config_name or '/' in config_name or config.get('id', '').lower() != config_id.lower():
            raise lab.PreflightError('Unexpected IP configuration identity')
        pip = None
        if name in PUBLIC_HOSTS:
            pip_id = prefix + '/providers/Microsoft.Network/publicIPAddresses/' + name + '-pip'
            if attached(config) != pip_id.lower() and not (allow_detached and attached(config) is None):
                raise lab.PreflightError('Unexpected public IP association for ' + name)
            pip = azure.call('network', 'public-ip', 'show', '--ids', pip_id)
            if (pip.get('id', '').lower() != pip_id.lower() or
                    pip.get('publicIPAllocationMethod') != 'Static' or
                    pip.get('sku', {}).get('name') != 'Standard' or not pip.get('ipAddress') or
                    pip.get('provisioningState') != 'Succeeded' or
                    ((pip.get('ipConfiguration') or {}).get('id', '').lower() != config_id.lower()
                     and not (allow_detached and attached(config) is None and not pip.get('ipConfiguration')))):
                raise lab.PreflightError('Expected an existing, reserved static IP for ' + name)
        elif attached(config) is not None:
            raise lab.PreflightError('The red simulator must already have no public IP')
        vms[name] = {'id': vm_id}
        network[name] = {'nic': nic, 'public_ip': pip}
    require_off(azure, vms)
    return {'subscription': azure.subscription, 'vms': vms, 'network': network}


def network_digest(state):
    return digest({'subscription': state['subscription'], 'vms': state['vms'], 'network': {
        name: {'nic': stable_network(row['nic']), 'public_ip': {
            key: row['public_ip'].get(key) for key in ['id', 'ipAddress', 'publicIPAllocationMethod', 'sku']
        } if row['public_ip'] else None} for name, row in state['network'].items()}})


def change_association(azure, name, row, *, restore):
    original = row['nic']
    current = azure.call('network', 'nic', 'show', '--ids', original['id'])
    if current.get('provisioningState') != 'Succeeded' or stable_network(current) != stable_network(original):
        raise lab.PreflightError('NIC changed outside this rehearsal for ' + name)
    config = current['ipConfigurations'][0]
    pip = row['public_ip']
    expected = pip['id'].lower()
    actual = attached(config)
    desired = expected if restore else None
    if actual == desired:
        return
    if actual != (None if restore else expected):
        raise lab.PreflightError('Unexpected current IP association for ' + name)
    live_pip = azure.call('network', 'public-ip', 'show', '--ids', pip['id'])
    binding = (live_pip.get('ipConfiguration') or {}).get('id')
    if (any(live_pip.get(k) != pip.get(k) for k in ['id', 'ipAddress', 'publicIPAllocationMethod', 'sku']) or
            (binding is not None and binding.lower() != config['id'].lower())):
        raise lab.PreflightError('Reserved IP changed or is associated elsewhere for ' + name)
    request_error = None
    try:
        azure.call('network', 'nic', 'ip-config', 'update', '--resource-group', lab.GROUP,
                   '--nic-name', original['name'], '--name', config['name'],
                   '--public-ip-address', pip['id'] if restore else 'null', timeout=180)
    except lab.PreflightError as exc:
        # An uncertain response must be reconciled by reading, never replayed.
        request_error = exc
    updated = azure.call('network', 'nic', 'show', '--ids', original['id'])
    if (updated.get('provisioningState') != 'Succeeded' or
            stable_network(updated) != stable_network(original) or
            attached(updated['ipConfigurations'][0]) != desired):
        raise lab.PreflightError('IP association update was not verified for ' + name) from request_error


def run(azure, expected_digest=None):
    state = snapshot(azure)
    network_sha = network_digest(state)
    report = {'kind': 'azure-temporary-isolation-boot', 'status': 'network_reviewed',
              'network_sha256': network_sha, 'temporary_detachment': sorted(PUBLIC_HOSTS),
              'full_setup_test_executed': False, 'full_competition_readiness_proven': False}
    (azure.work / 'initial-network.json').write_text(json.dumps(state, indent=2) + '\n', encoding='utf-8')
    if expected_digest is None:
        return report
    if expected_digest != network_sha:
        raise lab.PreflightError('Network changed since review; no changes attempted')
    begun = time.monotonic()
    try:
        for name in sorted(PUBLIC_HOSTS):
            require_off(azure, state['vms'])
            print('Temporarily detaching reserved IP: ' + name, flush=True)
            change_association(azure, name, state['network'][name], restore=False)
        report['network_prepare_seconds'] = round(time.monotonic() - begun, 3)
        # The original private-NIC guard runs unchanged, before any VM starts.
        report['preflight'] = lab.run(azure, start_and_check=True)
        report['status'] = report['preflight']['status']
    except (Exception, KeyboardInterrupt) as exc:
        report['status'] = 'failed'
        report['error'] = str(exc) if isinstance(exc, lab.PreflightError) else type(exc).__name__
    finally:
        restored_at = time.monotonic()
        try:
            # A public association is never restored to a running/unknown VM.
            lab.cleanup(azure, state['vms'], list(state['vms']))
            require_off(azure, state['vms'])
            report['all_vms_deallocated'] = True
        except (Exception, KeyboardInterrupt):
            report['all_vms_deallocated'] = False
        errors = {}
        if report['all_vms_deallocated']:
            for name in sorted(PUBLIC_HOSTS):
                try:
                    require_off(azure, state['vms'])
                    print('Restoring original reserved IP association: ' + name, flush=True)
                    change_association(azure, name, state['network'][name], restore=True)
                except (Exception, KeyboardInterrupt) as exc:
                    errors[name] = str(exc) if isinstance(exc, lab.PreflightError) else type(exc).__name__
        else:
            errors['power_state'] = 'Power cleanup is unverified; public IP restoration was not attempted'
        report['network_restored'] = not errors
        report['network_restore_errors'] = errors
        report['network_restore_seconds'] = round(time.monotonic() - restored_at, 3)
        if errors:
            report['status'] = 'cleanup_not_verified'
        report['total_seconds'] = round(time.monotonic() - begun, 3)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--temporary-private-boot', action='store_true')
    parser.add_argument('--expected-network-sha256')
    args = parser.parse_args()
    if args.temporary_private_boot != bool(args.expected_network_sha256):
        parser.error('Rehearsal requires both --temporary-private-boot and --expected-network-sha256')
    if os.name != 'posix':
        parser.error('Use authenticated Azure Cloud Shell Bash')
    os.umask(0o077)
    import fcntl
    fd = os.open(Path.home() / '.sentinel-azure-preflight.lock', os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            parser.error('Another lab preflight is running in this Cloud Shell')
        work = Path(tempfile.mkdtemp(prefix='sentinel-azure-isolated-'))
        print('Private diagnostics and original network: ' + str(work), flush=True)
        def interrupted(_signum, _frame):
            raise KeyboardInterrupt()
        signal.signal(signal.SIGTERM, interrupted)
        try:
            report = run(lab.Azure(work), expected_digest=args.expected_network_sha256)
        except Exception as exc:
            report = {'kind': 'azure-temporary-isolation-boot', 'status': 'blocked_before_changes',
                      'error': str(exc) if isinstance(exc, lab.PreflightError) else type(exc).__name__,
                      'full_setup_test_executed': False, 'full_competition_readiness_proven': False}
        report['script_sha256'] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
        report['preflight_script_sha256'] = hashlib.sha256(Path(lab.__file__).read_bytes()).hexdigest()
        report['diagnostics_directory'] = str(work)
        (work / 'result.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, indent=2), flush=True)
        return 0 if report['status'] in ['network_reviewed', 'boot_and_guest_checks_passed'] else 2


if __name__ == '__main__':
    raise SystemExit(main())
