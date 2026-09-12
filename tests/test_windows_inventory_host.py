"""Exercise framing and lifetime failures using actual bounded child processes."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from sentinel_blue import windows_inventory_host as host
from sentinel_blue.windows_queries import WINDOWS_QUERIES


class OwnedChild:
    def __init__(self):
        self.child = None
    def assign(self, child):
        self.child = child
    def close(self):
        if self.child is not None and self.child.poll() is None:
            self.child.kill()


def simulated_worker(mode='good'):
    # Protocol stand-in only: these tests do not claim native Windows coverage.
    return '''import sys,json,time
names=''' + repr(list(WINDOWS_QUERIES)) + '''
mode=''' + repr(mode) + '''
sys.stdin.readline()
generation=0
for request in sys.stdin:
 request=request.strip(); generation+=1
 if mode=='late': time.sleep(2)
 if mode=='oversize': print('x'*(16*1024*1024+1),flush=True); continue
 for name in names:
  if mode=='missing' and name==names[-1]: continue
  payload=json.dumps([{'generation':generation,'section':name}])
  if mode=='large' and name==names[0]: payload=json.dumps([{'generation':generation,'value':'x'*(1024*1024)}])
  if mode=='bad_rows': payload='[null]'
  row={'Request':request if mode!='replay' else 'f'*32,'Schema':1,'Section':name,'OK':True,'Payload':payload,'Error':'','Seconds':0.01}
  if mode=='bad_status': row['OK']='true'
  print(json.dumps(row),flush=True)
  if mode=='duplicate': print(json.dumps(row),flush=True)
 if mode=='unterminated': sys.stdout.write('{'); sys.stdout.flush(); time.sleep(2); continue
 if mode=='no_done': time.sleep(2); continue
 if mode=='false_done': print(json.dumps({'Request':request,'Done':1}),flush=True)
 else: print(json.dumps({'Request':request,'Done':True}),flush=True)
'''


class InventoryHostTests(unittest.TestCase):
    def helper(self, mode='good'):
        child = host.InventoryHost(command=[sys.executable, '-u', '-c', simulated_worker(mode)],
                                   initial_script='fixed read only code', job_factory=OwnedChild)
        self.addCleanup(child.close)
        return child

    def test_same_process_produces_fresh_independent_cycles(self):
        child = self.helper()
        pid = child.process.pid
        for generation in (1, 2, 3):
            result = child.query(time.monotonic()+3)
            self.assertEqual(child.process.pid, pid)
            self.assertEqual(set(result), set(WINDOWS_QUERIES))
            self.assertTrue(all(not row.error and row.rows[0]['generation']==generation for row in result.values()))
        self.assertEqual(child.completed, 3)
        child.close()
        self.assertIsNotNone(child.process.poll())
        self.assertFalse(child.reader.is_alive())
        self.assertFalse(child.writer.is_alive())

    def test_malformed_or_replayed_envelopes_never_complete(self):
        for mode in ('replay', 'duplicate', 'missing', 'bad_status', 'false_done'):
            with self.subTest(mode=mode):
                child=self.helper(mode)
                with self.assertRaises((ValueError, RuntimeError)):
                    child.query(time.monotonic()+2)
                self.assertEqual(child.completed, 0)
                child.close()

    def test_invalid_section_rows_remain_errors(self):
        child=self.helper('bad_rows')
        result=child.query(time.monotonic()+2)
        self.assertTrue(all(row.error and not row.rows for row in result.values()))

    def test_large_flushed_frames_complete_and_next_cycle_is_fresh(self):
        child=self.helper('large')
        for generation in (1,2):
            result=child.query(time.monotonic()+3)
            first=result[next(iter(WINDOWS_QUERIES))]
            self.assertFalse(first.error)
            self.assertEqual(len(first.rows[0]['value']),1024*1024)
            self.assertEqual(first.rows[0]['generation'],generation)
        self.assertEqual(child.completed,2)

    def test_timeout_truncation_and_output_overflow_are_bounded(self):
        for mode in ('late', 'unterminated', 'no_done', 'oversize'):
            with self.subTest(mode=mode):
                child=self.helper(mode)
                began=time.monotonic()
                with self.assertRaises((TimeoutError, ValueError, RuntimeError)):
                    child.query(began+0.2)
                child.close()
                self.assertLess(time.monotonic()-began, 1.5)
                self.assertIsNotNone(child.process.poll())
                self.assertFalse(child.reader.is_alive())
                self.assertFalse(child.writer.is_alive())

    def test_blocked_input_uses_same_deadline_and_writer_is_removed(self):
        child=host.InventoryHost(command=[sys.executable,'-c','import time; time.sleep(10)'],
            initial_script='x'*(1024*1024), job_factory=OwnedChild)
        self.addCleanup(child.close)
        began=time.monotonic()
        with self.assertRaises(TimeoutError):
            child.query(began+0.1)
        child.close()
        self.assertLess(time.monotonic()-began, 1.5)
        self.assertFalse(child.writer.is_alive())

    def test_job_assignment_failure_cannot_deliver_executable_input(self):
        children=[]
        class FailedJob(OwnedChild):
            def assign(self, child):
                children.append(child)
                raise OSError('Job assignment rejected')
        with self.assertRaises(OSError):
            host.InventoryHost(command=[sys.executable,'-c','import sys; sys.stdin.read()'],
                               initial_script='must never execute', job_factory=FailedJob)
        self.assertEqual(len(children),1)
        self.assertIsNotNone(children[0].poll())

    def test_failed_cycle_destroys_host_and_cannot_supply_previous_rows(self):
        first=self.helper(); second=self.helper('replay'); third=self.helper()
        with patch.object(host,'_host',None), patch.object(host,'InventoryHost',side_effect=[first,second,third]) as create:
            one=host.read_owned_inventory(time.monotonic()+2)
            self.assertTrue(all(not r.error for r in one.values()))
            first.close()  # Real child death between cycles.
            two=host.read_owned_inventory(time.monotonic()+2)
            self.assertTrue(all(r.error and not r.rows for r in two.values()))
            self.assertIsNotNone(second.process.poll())
            three=host.read_owned_inventory(time.monotonic()+2)
            self.assertTrue(all(not r.error and r.rows[0]['generation']==1 for r in three.values()))
            self.assertEqual(create.call_count,3)
            host.close_inventory_host()

    def test_unverified_cleanup_holds_existing_host_without_replacement(self):
        child=self.helper()
        child.broken.set()
        with patch.object(host,'_host',child), patch.object(child,'close',side_effect=OSError('held')), patch.object(host,'InventoryHost') as create:
            for _ in range(2):
                result=host.read_owned_inventory(time.monotonic()+1)
                self.assertTrue(all('cleanup is unverified' in r.error for r in result.values()))
                self.assertIs(host._host,child)
            create.assert_not_called()

    def test_waiting_for_another_inventory_does_not_reset_deadline(self):
        with patch.object(host,'_host',None), patch.object(host,'InventoryHost') as create:
            host._lock.acquire()
            try:
                began=time.monotonic()
                result=host.read_owned_inventory(began+0.08)
                self.assertLess(time.monotonic()-began,0.5)
                self.assertTrue(all(r.error for r in result.values()))
                create.assert_not_called()
            finally:
                host._lock.release()


if __name__=='__main__':
    unittest.main()
