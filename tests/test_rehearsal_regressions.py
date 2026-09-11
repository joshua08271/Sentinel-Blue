"""Integration boundaries discovered while deploying the complete private range."""
import copy
import subprocess
import tempfile
import threading
import time
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.actions import ActionExecutor
from sentinel_blue.collectors import _linux_services, _integrity_paths
from sentinel_blue.collectors import _windows_inventory
from sentinel_blue.store import Store
from sentinel_blue.service_recovery import ServiceRecoveryPlanner, recovery_parameters
from test_autonomous_service_recovery import fixtures, stopped
from test_service_manifest_policy import profile_for, service_manifest


class RehearsalRegressionTests(unittest.TestCase):
    def test_internal_probe_record_never_becomes_remote_agent_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            store = Store(Path(directory) / 'controller.db')
            try:
                store.register_agent('sentinel-relay-probes', 'controller-probes', 'Sentinel Blue relay')
                self.assertIsNone(store.agent_binding('sentinel-relay-probes', require_fresh=True))
                self.assertTrue(store.stored_json_readiness()['ready'])
                store.register_agent('ordinary-agent', 'host', 'Linux')
                self.assertIsNone(store.agent_binding('ordinary-agent', require_fresh=True))
                self.assertFalse(store.stored_json_readiness()['ready'])
            finally:
                store.close()

    def test_windows_sessions_wait_until_other_collector_helpers_exit(self):
        finished = threading.Event()
        def services(errors):
            time.sleep(0.05)
            finished.set()
            return []
        def sessions(accounts, errors):
            self.assertTrue(finished.is_set(), 'session scan raced a live collector helper')
            return []
        with (
            patch('sentinel_blue.collectors._windows_accounts', return_value=[]),
            patch('sentinel_blue.collectors._windows_services', side_effect=services),
            patch('sentinel_blue.collectors._windows_sessions', side_effect=sessions),
            patch('sentinel_blue.collectors._windows_topology', return_value=([], [], [])),
            patch('sentinel_blue.collectors._windows_processes', return_value=[]),
            patch('sentinel_blue.collectors._windows_persistence', return_value=[]),
            patch('sentinel_blue.collectors._windows_firewall', return_value=None),
            patch('sentinel_blue.collectors._windows_interfaces', return_value=[]),
            patch('sentinel_blue.collectors._windows_security_events', return_value=[]),
        ):
            _windows_inventory([])

    def test_actual_linux_collector_states_can_reach_recovery_planner(self):
        profile, baseline = fixtures()
        for native, substate in [('inactive', 'dead'), ('failed', 'failed')]:
            with self.subTest(native=native):
                outputs = [
                    subprocess.CompletedProcess([], 0, f'web.service loaded {native} {substate} Web\n', ''),
                    subprocess.CompletedProcess([], 0, 'web.service enabled enabled\n', ''),
                    subprocess.CompletedProcess([], 0, f'Id=web.service\nActiveState={native}\nSubState={substate}\nNRestarts=0\nResult=success\nExecMainStatus=0\n\n', ''),
                ]
                errors = []
                with patch('sentinel_blue.collectors._run', side_effect=outputs):
                    service = asdict(_linux_services(errors)[0])
                self.assertFalse(errors)
                planner = ServiceRecoveryPlanner(profile)
                for seq in [2, 3]:
                    observation = stopped(baseline, seq)
                    observation['services'] = [service]
                    result = planner.observe('agent-one', baseline, True, observation)
                self.assertIn('web.service', result)

    def test_windows_disabled_start_mode_cannot_authorize_start(self):
        profile, baseline = fixtures()
        baseline['platform'] = 'Windows Server'
        for item in baseline['integrity']:
            item['security_descriptor_sha256'] = 'a' * 64
        observation = stopped(baseline)
        observation['services'][0]['start_mode'] = 'Disabled'
        with self.assertRaisesRegex(ValueError, 'disabled'):
            recovery_parameters(profile, 'agent-one', 'web.service', baseline, observation)

    def test_dependency_config_tamper_holds_recovery_even_with_healthy_probe(self):
        profile, baseline = fixtures()
        web = copy.deepcopy(profile.services[0]); web['dependencies'] = ['backend.service']
        dependency = service_manifest('backend.service', required_files=['/etc/backend.conf'])
        profile = profile_for([web, dependency])
        baseline['services'].append({'name': 'backend.service', 'state': 'running'})
        baseline['integrity'].append({**baseline['integrity'][0], 'path': '/etc/backend.conf'})
        observation = stopped(baseline)
        observation['integrity'][1]['sha256'] = 'f' * 64
        observation['probes'] = [{'name': dependency['expected_transactions'][0]['name'], 'target': dependency['expected_transactions'][0]['target'], 'healthy': True}]
        with self.assertRaisesRegex(ValueError, 'required file'):
            recovery_parameters(profile, 'agent-one', 'web.service', baseline, observation)

    def test_recovery_can_be_enabled_without_session_containment(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=False, allow_service_recovery=True)
            with patch.object(executor, '_service_state', return_value='running'):
                result = executor.execute('restart_service', {'service': 'web.service'}, {})
            self.assertFalse(result.get('dry_run', False))
            result = executor.execute('quarantine_session', {'process_id': 12345}, {})
            self.assertTrue(result.get('dry_run'))

    def test_discovered_service_alias_is_pinned_to_regular_inventory_target(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / 'canonical.service'; target.write_text('trusted unit')
            alias = root / 'alias.service'; alias.symlink_to(target)
            original = Path.glob
            def entries(path, pattern):
                if path.as_posix() == '/etc/systemd/system':
                    return iter([alias])
                return original(path, pattern)
            with patch.object(Path, 'glob', entries):
                paths = _integrity_paths('linux')
            self.assertIn(target, paths)
            self.assertNotIn(alias, paths)
