"""Bounded integrity reads with a native API stand-in; Windows has a real-file check."""
from contextlib import nullcontext
import ctypes
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinel_blue import collectors, restoration


class MemoryFile(restoration._WindowsNativeFileOps):
    """Exercise the production chunk loop without a Windows DLL on POSIX."""
    def __init__(self, data, *, after_read=lambda: None, changed=False):
        self.data = data
        self.offset = 0
        self.reads = 0
        self.snapshots = 0
        self.closed = []
        self.after_read = after_read
        self.changed = changed

    def _read_file(self, handle, buffer, count, result, overlapped):
        chunk = self.data[self.offset:self.offset + count]
        ctypes.memmove(buffer, chunk, len(chunk))
        ctypes.cast(result, ctypes.POINTER(ctypes.c_uint32)).contents.value = len(chunk)
        self.offset += len(chunk)
        self.reads += 1
        self.after_read()
        return 1

    def file_snapshot(self, handle):
        self.snapshots += 1
        return {"attributes": 0, "links": 1, "size": len(self.data),
                "creation_ticks": 1, "modified_ticks": 2 + int(self.changed and self.snapshots > 1),
                "identity": "fixture", "modified_at": 1.0}

    def open_file(self, *args):
        return 7

    def close(self, handle):
        self.closed.append(handle)


def snapshot(native, budget, maximum):
    with patch.object(restoration, "_windows_pinned_parent", return_value=nullcontext((1, "parent", "file"))):
        return restoration._windows_read_file_snapshot(
            Path("fixture"), maximum, capture_security=False, native=native, read_budget=budget
        )


class WindowsIntegrityBudgetTests(unittest.TestCase):
    def test_regular_snapshot_charges_actual_bytes_and_closes_handle(self):
        native = MemoryFile(b"service configuration")
        budget = collectors._IntegrityBudget("windows")
        before = budget.remaining_bytes
        data, metadata = snapshot(native, budget, 100)
        self.assertEqual(data, native.data)
        self.assertEqual(metadata["size"], len(data))
        self.assertEqual(budget.remaining_bytes, before - len(data))
        self.assertEqual(native.closed, [7])

    def test_timeout_after_read_rejects_snapshot_and_closes_handle(self):
        now = [100.0]
        native = MemoryFile(b"configuration", after_read=lambda: now.__setitem__(0, 111.0))
        with patch.object(collectors.time, "monotonic", side_effect=lambda: now[0]):
            budget = collectors._IntegrityBudget("windows")
            before = budget.remaining_bytes
            with self.assertRaisesRegex(TimeoutError, "time budget"):
                snapshot(native, budget, 100)
        self.assertEqual(native.reads, 1)
        self.assertEqual(native.closed, [7])
        self.assertEqual(budget.remaining_bytes, before - len(native.data))

    def test_changed_snapshot_consumes_budget_even_when_rejected(self):
        native = MemoryFile(b"ordinary file", changed=True)
        budget = collectors._IntegrityBudget("windows")
        before = budget.remaining_bytes
        with self.assertRaisesRegex(OSError, "changed during"):
            snapshot(native, budget, 100)
        self.assertEqual(budget.remaining_bytes, before - len(native.data))
        self.assertEqual(native.closed, [7])

    def test_expired_budget_does_not_open_or_read(self):
        native = MemoryFile(b"configuration")
        budget = collectors._IntegrityBudget("windows")
        budget.deadline = 0
        with self.assertRaises(TimeoutError), patch.object(native, "open_file") as opened:
            snapshot(native, budget, 100)
        opened.assert_not_called()
        self.assertEqual(native.reads, 0)

    def test_chunk_loop_rechecks_deadline_between_reads(self):
        now = [100.0]
        native = MemoryFile(b"x" * (2 * 1024 * 1024), after_read=lambda: now.__setitem__(0, now[0] + 6))
        with patch.object(collectors.time, "monotonic", side_effect=lambda: now[0]):
            budget = collectors._IntegrityBudget("windows")
            with self.assertRaises(TimeoutError):
                snapshot(native, budget, len(native.data))
        self.assertEqual(native.reads, 2)
        self.assertEqual(native.closed, [7])

    def test_metadata_delay_cannot_publish_late_snapshot(self):
        now = [100.0]
        native = MemoryFile(b"configuration")
        original = native.file_snapshot

        def metadata(handle):
            result = original(handle)
            if native.snapshots > 1:
                now[0] = 111.0
            return result

        with patch.object(collectors.time, "monotonic", side_effect=lambda: now[0]), patch.object(
            native, "file_snapshot", side_effect=metadata
        ):
            budget = collectors._IntegrityBudget("windows")
            with self.assertRaises(TimeoutError):
                snapshot(native, budget, 100)
        self.assertEqual(native.closed, [7])

    def test_collection_shares_byte_allowance_and_next_cycle_resets(self):
        targets = [Path("one"), Path("two")]
        limits = []
        budgets = []

        def read(path, maximum, *, read_budget, **kwargs):
            limits.append(maximum)
            budgets.append(read_budget)
            return snapshot(MemoryFile(b"12345678"), read_budget, maximum)

        with patch.object(collectors, "_integrity_paths", return_value=targets), patch.object(
            collectors, "MAX_WINDOWS_INTEGRITY_TOTAL_BYTES", 10
        ), patch.object(restoration, "_windows_read_file_snapshot_if_present", side_effect=read):
            for _ in range(2):
                errors = []
                items = collectors._integrity("windows", errors)
                self.assertEqual([item.path for item in items], ["one"])
                self.assertEqual(items[0].sha256, hashlib.sha256(b"12345678").hexdigest())
                self.assertTrue(errors)
        self.assertEqual(limits, [9, 1, 9, 1])
        self.assertIs(budgets[0], budgets[1])
        self.assertIsNot(budgets[0], budgets[2])

    def test_collection_stops_after_deadline_and_rejects_late_data(self):
        now = [100.0]

        def slow_read(path, maximum, *, read_budget, **kwargs):
            return snapshot(MemoryFile(b"x", after_read=lambda: now.__setitem__(0, 111.0)), read_budget, maximum)

        with patch.object(collectors.time, "monotonic", side_effect=lambda: now[0]), patch.object(
            collectors, "_integrity_paths", return_value=[Path("one"), Path("two")]
        ), patch.object(restoration, "_windows_read_file_snapshot_if_present", side_effect=slow_read) as read:
            errors = []
            items = collectors._integrity("windows", errors)
        self.assertEqual(items, [])
        self.assertEqual(read.call_count, 1)
        self.assertTrue(any("time budget" in error for error in errors))

    def test_late_absence_is_not_treated_as_complete_coverage(self):
        now = [100.0]

        def absent(*args, **kwargs):
            now[0] = 111.0
            return None

        with patch.object(collectors.time, "monotonic", side_effect=lambda: now[0]), patch.object(
            collectors, "_integrity_paths", return_value=[Path("one")]
        ), patch.object(restoration, "_windows_read_file_snapshot_if_present", side_effect=absent):
            errors = []
            self.assertEqual(collectors._integrity("windows", errors), [])
        self.assertTrue(errors)

    @unittest.skipUnless(os.name == "nt", "requires native Windows file handles")
    def test_native_windows_file_supports_budget_and_releases_handle(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory).resolve() / "service.conf"
            path.write_bytes(b"native Windows integrity fixture")
            budget = collectors._IntegrityBudget("windows")
            native = restoration._WindowsNativeFileOps()
            data, _ = restoration._windows_read_file_snapshot(
                path, 1024, native=native, capture_security=False, read_budget=budget
            )
            self.assertEqual(data, path.read_bytes())
            path.unlink()  # A leaked snapshot handle would block deletion.


if __name__ == "__main__":
    unittest.main()
