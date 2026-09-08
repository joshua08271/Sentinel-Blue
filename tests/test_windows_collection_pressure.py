"""Windows collector pressure must not create avoidable incomplete observations."""
import subprocess
import platform
import threading
import time
import unittest
from unittest.mock import patch

from sentinel_blue.collectors import _run, _windows_accounts, _windows_inventory, _windows_json, _windows_services, collect
from sentinel_blue.collectors import _windows_deadline, _windows_inventory_budget
from sentinel_blue.service_recovery import recovery_parameters
from test_autonomous_service_recovery import fixtures, stopped


class WindowsCollectionPressureTests(unittest.TestCase):
    def test_queries_share_remaining_budget_and_next_cycle_gets_a_fresh_budget(self):
        clock = [100.0]
        timeouts = []

        def query(command, timeout):
            timeouts.append(timeout)
            clock[0] += 40
            return subprocess.CompletedProcess(command, 0, '[]', '')

        with patch('sentinel_blue.collectors.time.monotonic', side_effect=lambda: clock[0]), patch(
            'sentinel_blue.collectors._run', side_effect=query
        ) as invoke:
            with _windows_inventory_budget():
                _windows_json('first')
                with self.assertRaisesRegex(RuntimeError, 'after its collection budget'):
                    _windows_json('late second')
                with self.assertRaisesRegex(RuntimeError, 'budget exhausted'):
                    _windows_json('must not start')
                self.assertEqual(invoke.call_count, 2)
            self.assertIsNone(_windows_deadline.get())
            with _windows_inventory_budget():
                _windows_json('new collection')
        self.assertEqual(timeouts, [60, 35, 60])

    def test_parallel_workers_inherit_the_same_deadline_and_reset_after_failure(self):
        deadlines = []
        lock = threading.Lock()

        def section(value):
            def run(*_args, **_kwargs):
                with lock:
                    deadlines.append(_windows_deadline.get())
                return value
            return run

        with (
            patch('sentinel_blue.collectors.os.cpu_count', return_value=4),
            patch('sentinel_blue.collectors._windows_accounts', section([])),
            patch('sentinel_blue.collectors._windows_services', section([])),
            patch('sentinel_blue.collectors._windows_sessions', section([])),
            patch('sentinel_blue.collectors._windows_topology', section(([], [], []))),
            patch('sentinel_blue.collectors._windows_processes', section([])),
            patch('sentinel_blue.collectors._windows_persistence', section([])),
            patch('sentinel_blue.collectors._windows_firewall', section(None)),
            patch('sentinel_blue.collectors._windows_interfaces', section([])),
            patch('sentinel_blue.collectors._windows_security_events', section([])),
        ):
            with _windows_inventory_budget() as deadline:
                _windows_inventory([], boot_id='one-boot')
            self.assertEqual(deadlines, [deadline] * 9)
        with self.assertRaisesRegex(RuntimeError, 'fixture failure'):
            with _windows_inventory_budget():
                raise RuntimeError('fixture failure')
        self.assertIsNone(_windows_deadline.get())

    def test_collection_reuses_one_boot_identity_for_sessions_and_telemetry(self):
        with (
            patch('sentinel_blue.collectors.platform.system', return_value='Windows'),
            patch('sentinel_blue.collectors._windows_inventory', return_value=([], [], [], [], [], [], [], [], None, [], [])) as inventory,
            patch('sentinel_blue.collectors._integrity', return_value=[]),
            patch('sentinel_blue.collectors._boot_id', return_value='one-boot') as boot,
        ):
            sample = collect('agent-one')
        boot.assert_called_once_with('windows')
        self.assertEqual(inventory.call_args.kwargs, {'boot_id': 'one-boot'})
        self.assertEqual(sample.boot_id, 'one-boot')

    def test_single_cpu_inventory_does_not_overlap_native_helpers(self):
        active = 0
        peak = 0
        lock = threading.Lock()

        def inventory(value):
            def run(*args):
                nonlocal active, peak
                with lock:
                    active += 1
                    peak = max(peak, active)
                try:
                    time.sleep(0.015)
                    return value
                finally:
                    with lock:
                        active -= 1
            return run

        with (
            patch('sentinel_blue.collectors.os.cpu_count', return_value=1),
            patch('sentinel_blue.collectors._windows_accounts', inventory([])),
            patch('sentinel_blue.collectors._windows_services', inventory([])),
            patch('sentinel_blue.collectors._windows_sessions', inventory([])),
            patch('sentinel_blue.collectors._windows_topology', inventory(([], [], []))),
            patch('sentinel_blue.collectors._windows_processes', inventory([])),
            patch('sentinel_blue.collectors._windows_persistence', inventory([])),
            patch('sentinel_blue.collectors._windows_firewall', inventory(None)),
            patch('sentinel_blue.collectors._windows_interfaces', inventory([])),
            patch('sentinel_blue.collectors._windows_security_events', inventory([])),
        ):
            errors = []
            _windows_inventory(errors)
        self.assertFalse(errors)
        self.assertEqual(peak, 1, 'native helpers contend for the only CPU')

    def test_slow_successful_inventory_is_accepted_within_finite_budget(self):
        def slow(command, timeout):
            if timeout < 35:
                raise subprocess.TimeoutExpired(command, timeout)
            self.assertLessEqual(timeout, 60)
            return subprocess.CompletedProcess(command, 0, '[{"Name":"fixture"}]', '')

        with patch('sentinel_blue.collectors._run', side_effect=slow):
            self.assertEqual(_windows_json('owned read-only inventory'), [{'Name':'fixture'}])

    def test_exhausted_inventory_budget_still_reports_failure(self):
        with patch('sentinel_blue.collectors._run', side_effect=subprocess.TimeoutExpired('powershell', 60)):
            with self.assertRaisesRegex(RuntimeError, 'timed out after 60 seconds'):
                _windows_json('owned read-only inventory')

    def test_explicit_shorter_inventory_deadline_is_preserved(self):
        with patch('sentinel_blue.collectors._run', side_effect=subprocess.TimeoutExpired('powershell', 3)) as invoke:
            with self.assertRaisesRegex(RuntimeError, 'timed out after 3 seconds'):
                _windows_json('owned read-only inventory', timeout=3)
        self.assertEqual(invoke.call_args.kwargs['timeout'], 3)

    def test_zero_exit_with_partial_output_and_error_is_not_complete_inventory(self):
        result = subprocess.CompletedProcess('powershell', 0, '[{"Name":"partial"}]',
                                             'The inventory provider failed')
        with patch('sentinel_blue.collectors._run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, 'inventory provider failed'):
                _windows_json('read-only inventory')

    def test_empty_service_inventory_reports_incomplete_collection(self):
        errors = []
        with patch('sentinel_blue.collectors._windows_json', return_value=[]):
            services = _windows_services(errors)
        self.assertEqual(services, [])
        self.assertTrue(errors, 'a native Windows host must have service records')

    def test_empty_account_inventory_reports_incomplete_collection(self):
        errors = []
        with patch('sentinel_blue.collectors._windows_json', return_value=[]):
            self.assertEqual(_windows_accounts(errors), [])
        self.assertTrue(errors, 'a native Windows host must have local account records')

    def test_clean_empty_query_remains_valid_for_optional_inventories(self):
        for output in ('', '[]'):
            with self.subTest(output=output):
                result = subprocess.CompletedProcess('powershell', 0, output, '')
                with patch('sentinel_blue.collectors._run', return_value=result):
                    self.assertEqual(_windows_json('optional inventory'), [])

    def test_collector_json_rejects_scalar_and_mixed_rows(self):
        for output in ('null', 'true', '17', '[{}, null]', '[{}, "partial"]'):
            with self.subTest(output=output):
                result = subprocess.CompletedProcess('powershell', 0, output, '')
                with patch('sentinel_blue.collectors._run', return_value=result):
                    with self.assertRaisesRegex(ValueError, 'inventory JSON'):
                        _windows_json('read-only inventory')

    def test_slow_collection_keeps_its_age_and_cannot_authorize_recovery(self):
        clock = [1000.0]

        def delayed_inventory(errors, **_kwargs):
            clock[0] += 120.0
            return ([], [], [], [], [], [], [], [], None, [], [])

        with (
            patch('sentinel_blue.collectors.platform.system', return_value='Windows'),
            patch('sentinel_blue.collectors._windows_inventory', side_effect=delayed_inventory),
            patch('sentinel_blue.collectors._integrity', return_value=[]),
            patch('sentinel_blue.collectors._boot_id', return_value='fixture-boot'),
            patch('sentinel_blue.collectors.time.time', side_effect=lambda: clock[0]),
        ):
            sample = collect('agent-one')
            self.assertEqual(sample.observed_at, 1000.0)
            profile, baseline = fixtures()
            outage = stopped(baseline)
            outage['observed_at'] = sample.observed_at
            with self.assertRaisesRegex(ValueError, 'fresh sequenced telemetry'):
                recovery_parameters(profile, 'agent-one', 'web.service', baseline, outage)

    def test_windows_helper_gets_normal_priority_and_keeps_deadline(self):
        with (
            patch('sentinel_blue.collectors.subprocess.CREATE_NO_WINDOW', 0x08000000, create=True),
            patch('sentinel_blue.collectors.subprocess.NORMAL_PRIORITY_CLASS', 0x20, create=True),
            patch('sentinel_blue.collectors.subprocess.run') as invoke,
        ):
            _run(['powershell.exe', '-NoProfile'], timeout=3)
        self.assertEqual(invoke.call_args.kwargs['creationflags'], 0x08000020)
        self.assertEqual(invoke.call_args.kwargs['timeout'], 3)

    @unittest.skipUnless(platform.system() == 'Windows', 'requires native Windows PowerShell')
    def test_native_nonterminating_query_error_cannot_return_partial_success(self):
        with self.assertRaisesRegex(RuntimeError, 'sentinel inventory failure fixture'):
            _windows_json("Write-Error 'sentinel inventory failure fixture'; "
                          "[PSCustomObject]@{Name='partial'} | ConvertTo-Json -Compress")


if __name__ == '__main__':
    unittest.main()
