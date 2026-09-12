"""A shared native host must not hide missing, stale or unsuccessful sections."""
import json
import subprocess
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from sentinel_blue.collectors import (
    _WindowsQueryCache, _boot_id, _windows_deadline, _windows_inventory_budget,
    _windows_json, _windows_query_cache, _windows_query_snapshot,
)
from sentinel_blue.windows_queries import WINDOWS_QUERIES
from sentinel_blue.windows_query_batch import QueryResult, decode_batch, read_query_batch


def record(name, payload='[]', **overrides):
    row = dict(Schema=1, Section=name, OK=True, Payload=payload, Error='', Seconds=0.25)
    row.update(overrides)
    return (json.dumps(row, ensure_ascii=False) + '\n').encode('utf-8')


class WindowsQueryBatchTests(unittest.TestCase):
    def test_empty_and_unicode_sections_are_independent(self):
        rows = decode_batch(record('A', '') + record('B', '{"Name":"蓝 Ω"}'), {'A':'', 'B':''})
        self.assertEqual(rows['A'].rows, [])
        self.assertFalse(rows['A'].error)
        self.assertEqual(rows['B'].rows, [{'Name':'蓝 Ω'}])

    def test_section_failure_does_not_hide_a_later_success(self):
        rows = decode_batch(record('A', OK=False, Error='provider failed') + record('B'), {'A':'', 'B':''})
        self.assertTrue(rows['A'].error)
        self.assertFalse(rows['B'].error)

    def test_missing_or_malformed_section_cannot_establish_completeness(self):
        for payload in ('null', 'true', '12', '[{}, null]', '[{}, "partial"]', '{'):
            with self.subTest(payload=payload):
                rows = decode_batch(record('A', payload), {'A':'', 'B':''})
                self.assertTrue(rows['A'].error)
                self.assertTrue(rows['B'].error)

    def test_untrusted_record_envelopes_are_rejected(self):
        for output in (record('A') * 2, record('UNKNOWN'), record('A', Schema=True),
                       record('A', Seconds=float('nan')), record('A', Seconds=-1),
                       record('A', Seconds=True), record('A', OK='true'),
                       record('A', Error='contradictory'), record('A', OK=False),
                       record('A', Extra='unexpected'), b'[]\n'):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    decode_batch(output, {'A':''})

    def test_interruption_keeps_only_complete_records_and_marks_missing(self):
        rows = decode_batch(record('A') + record('B')[:-5], {'A':'', 'B':''}, interrupted=True)
        self.assertFalse(rows['A'].error)
        self.assertTrue(rows['B'].error)

    def test_process_timeout_cannot_pass_even_after_all_records_were_flushed(self):
        expired = subprocess.TimeoutExpired('powershell', 5, output=record('A') + record('B'))
        with patch('sentinel_blue.windows_query_batch.subprocess.run', side_effect=expired):
            rows = read_query_batch(time.monotonic()+5, {'A':'', 'B':''})
        self.assertFalse(rows['A'].error)
        self.assertTrue(rows['B'].error)

    def test_process_errors_and_missing_executable_fail_every_section(self):
        for outcome in (subprocess.CompletedProcess([], 1, record('A'), b''),
                        subprocess.CompletedProcess([], 0, record('A'), b'provider failed'),
                        FileNotFoundError('powershell is unavailable')):
            kwargs = {'side_effect':outcome} if isinstance(outcome, Exception) else {'return_value':outcome}
            with patch('sentinel_blue.windows_query_batch.subprocess.run', **kwargs):
                rows = read_query_batch(time.monotonic()+5, {'A':'', 'B':''})
            self.assertTrue(all(row.error for row in rows.values()))

    def test_only_finite_inventory_child_uses_above_normal_priority(self):
        with (
            patch('sentinel_blue.windows_query_batch.subprocess.CREATE_NO_WINDOW', 0x08000000, create=True),
            patch('sentinel_blue.windows_query_batch.subprocess.ABOVE_NORMAL_PRIORITY_CLASS', 0x8000, create=True),
            patch('sentinel_blue.windows_query_batch.subprocess.run',
                  return_value=subprocess.CompletedProcess([], 0, record('A'), b'')) as invoke,
        ):
            result = read_query_batch(time.monotonic()+5, {'A':''})
        self.assertFalse(result['A'].error)
        self.assertEqual(invoke.call_args.kwargs['creationflags'], 0x08008000)
        self.assertLessEqual(invoke.call_args.kwargs['timeout'], 5)

    def test_combined_script_uses_stdin_and_original_deadline(self):
        deadline = time.monotonic()+5
        script = '# Ω\n' * 10000 + "'[]'"
        with patch('sentinel_blue.windows_query_batch.subprocess.run',
                   return_value=subprocess.CompletedProcess([], 0, record('A'), b'')) as invoke:
            rows = read_query_batch(deadline, {'A':script})
        self.assertFalse(rows['A'].error)
        self.assertLess(len(' '.join(invoke.call_args.args[0])), 1000)
        self.assertIn(script.encode('utf-8'), invoke.call_args.kwargs['input'])
        self.assertLessEqual(invoke.call_args.kwargs['timeout'], 5)
        with patch('sentinel_blue.windows_query_batch.subprocess.run') as invoke:
            self.assertTrue(read_query_batch(time.monotonic()-1, {'A':''})['A'].error)
        invoke.assert_not_called()

    def test_workers_share_one_snapshot_but_next_cycle_never_reuses_it(self):
        generations = []
        def collect(deadline):
            generations.append(deadline)
            return {key:QueryResult([{'generation':len(generations)}]) for key in WINDOWS_QUERIES}
        with patch('sentinel_blue.collectors.read_query_batch', side_effect=collect) as invoke:
            first = _WindowsQueryCache(time.monotonic()+10)
            with ThreadPoolExecutor(max_workers=4) as pool:
                results = list(pool.map(first.read, WINDOWS_QUERIES.values()))
            self.assertEqual(invoke.call_count, 1)
            self.assertTrue(all(result == [{'generation':1}] for result in results))
            with _windows_inventory_budget(), _windows_query_snapshot():
                self.assertEqual(_windows_json(WINDOWS_QUERIES['ACCOUNTS']), [{'generation':2}])
        self.assertIsNone(_windows_query_cache.get())
        self.assertIsNone(_windows_deadline.get())

    def test_boot_and_inventory_share_one_current_snapshot_and_boot_failure_is_visible(self):
        good = {key:QueryResult([]) for key in WINDOWS_QUERIES}
        good['BOOT'] = QueryResult([{'LastBootUpTime':'native-boot'}])
        failed = {**good, 'BOOT':QueryResult(error='native boot unavailable')}
        with patch('sentinel_blue.collectors.read_query_batch', side_effect=[good, failed]) as invoke:
            with _windows_inventory_budget(), _windows_query_snapshot():
                self.assertEqual(_boot_id('windows'), 'native-boot')
                self.assertEqual(_windows_json(WINDOWS_QUERIES['ACCOUNTS']), [])
                self.assertEqual(invoke.call_count, 1)
            with _windows_inventory_budget(), _windows_query_snapshot():
                self.assertEqual(_boot_id('windows'), 'unknown')
                self.assertEqual(_windows_json(WINDOWS_QUERIES['ACCOUNTS']), [])
                self.assertEqual(invoke.call_count, 2)

    def test_failed_new_snapshot_does_not_borrow_previous_rows_and_resets_context(self):
        good = {key:QueryResult([{'Name':'previous'}]) for key in WINDOWS_QUERIES}
        with patch('sentinel_blue.collectors.read_query_batch', side_effect=[good, {}]):
            with _windows_inventory_budget(), _windows_query_snapshot():
                self.assertEqual(_windows_json(WINDOWS_QUERIES['ACCOUNTS']), [{'Name':'previous'}])
            with self.assertRaisesRegex(RuntimeError, 'did not complete'):
                with _windows_inventory_budget(), _windows_query_snapshot():
                    _windows_json(WINDOWS_QUERIES['ACCOUNTS'])
        self.assertIsNone(_windows_query_cache.get())
        self.assertIsNone(_windows_deadline.get())


if __name__ == '__main__':
    unittest.main()
