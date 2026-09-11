"""Local file collection checks; no host services, accounts, or network calls."""

import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from sentinel_blue import collectors


@unittest.skipUnless(os.name == "posix", "requires POSIX file semantics")
class PosixIntegrityBudgetTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / "service.conf"
        self.target.write_bytes(b"ordinary configuration\n")

    def collect_files(self, paths=None):
        errors = []
        with patch.object(collectors, "_integrity_paths", return_value=paths or [self.target]):
            items = collectors._integrity("linux", errors)
        return items, errors

    def test_regular_and_empty_files_keep_exact_hashes(self):
        empty = self.root / "empty.conf"
        empty.touch()
        items, errors = self.collect_files([self.target, empty])
        self.assertFalse(errors)
        self.assertEqual(len(items), 2)
        for item in items:
            contents = Path(item.path).read_bytes()
            self.assertEqual(item.sha256, hashlib.sha256(contents).hexdigest())
            self.assertEqual(item.size, len(contents))

    def test_oversized_file_is_rejected_before_content_read(self):
        with patch.object(collectors, "MAX_POSIX_INTEGRITY_FILE_BYTES", 8), patch.object(
            collectors.os, "read"
        ) as read:
            items, errors = self.collect_files()
        self.assertFalse(items)
        self.assertIn("per-file byte limit", errors[0])
        read.assert_not_called()

    def test_total_byte_budget_is_shared_and_resets_each_cycle(self):
        second = self.root / "second.conf"
        second.write_bytes(self.target.read_bytes())
        size = self.target.stat().st_size
        with patch.object(collectors, "MAX_POSIX_INTEGRITY_TOTAL_BYTES", size + 1):
            for _ in range(2):
                items, errors = self.collect_files([self.target, second])
                self.assertEqual([row.path for row in items], [str(self.target)])
                self.assertIn("byte budget exhausted", errors[0])

    def test_concurrent_configuration_edit_is_not_published(self):
        read = os.read

        def edit(descriptor, size):
            data = read(descriptor, size)
            if data:
                self.target.write_bytes(b"new configuration\n")
            return data

        with patch.object(collectors.os, "read", side_effect=edit):
            items, errors = self.collect_files()
        self.assertFalse(items)
        self.assertIn("changed while being read", errors[0])
        fresh, errors = self.collect_files()
        self.assertFalse(errors)
        self.assertEqual(fresh[0].sha256, hashlib.sha256(self.target.read_bytes()).hexdigest())

    def test_atomic_file_replacement_requires_a_new_snapshot(self):
        replacement = self.root / "replacement.conf"
        replacement.write_bytes(self.target.read_bytes())
        read = os.read

        def replace(descriptor, size):
            data = read(descriptor, size)
            if data:
                replacement.replace(self.target)
            return data

        with patch.object(collectors.os, "read", side_effect=replace):
            items, errors = self.collect_files()
        self.assertFalse(items)
        self.assertIn("changed while being read", errors[0])

    def test_permission_change_during_read_requires_a_new_snapshot(self):
        self.target.chmod(0o600)
        read = os.read

        def change_mode(descriptor, size):
            data = read(descriptor, size)
            if data:
                self.target.chmod(0o640)
            return data

        with patch.object(collectors.os, "read", side_effect=change_mode):
            items, errors = self.collect_files()
        self.assertFalse(items)
        self.assertIn("changed while being read", errors[0])

    def test_rejected_snapshots_still_consume_the_byte_budget(self):
        budget = collectors._IntegrityBudget()
        read = os.read
        size = self.target.stat().st_size
        initial = budget.remaining_bytes

        def edit(descriptor, count):
            data = read(descriptor, count)
            if data:
                self.target.write_bytes(b"different")
            return data

        with patch.object(collectors.os, "read", side_effect=edit):
            with self.assertRaisesRegex(ValueError, "changed while"):
                collectors._posix_integrity_item(self.target, budget)
        self.assertEqual(budget.remaining_bytes, initial - size)

    def test_missing_optional_file_is_distinct_from_access_error(self):
        items, errors = self.collect_files([self.root / "absent.conf"])
        self.assertEqual((items, errors), ([], []))
        with patch.object(collectors.os, "open", side_effect=PermissionError("cannot read configuration")):
            items, errors = self.collect_files()
        self.assertFalse(items)
        self.assertIn("cannot read configuration", errors[0])

    def test_disappearance_after_open_is_a_collection_error(self):
        read = os.read

        def remove(descriptor, count):
            data = read(descriptor, count)
            if data:
                self.target.unlink()
            return data

        with patch.object(collectors.os, "read", side_effect=remove):
            items, errors = self.collect_files()
        self.assertFalse(items)
        self.assertTrue(errors)

    def test_nonregular_target_reports_an_error(self):
        items, errors = self.collect_files([self.root])
        self.assertFalse(items)
        self.assertIn("not a regular file", errors[0])

    def test_expired_deadline_does_not_open_a_file(self):
        budget = collectors._IntegrityBudget()
        budget.deadline = time.monotonic() - 1
        with patch.object(collectors.os, "open") as opened:
            with self.assertRaises(TimeoutError):
                collectors._posix_integrity_item(self.target, budget)
        opened.assert_not_called()

    def test_deadline_stops_remaining_files_and_closes_current_descriptor(self):
        second = self.root / "second.conf"
        second.write_bytes(b"configuration")
        read, opened, close = os.read, os.open, os.close
        clock = [100.0]

        def delayed_read(descriptor, count):
            data = read(descriptor, count)
            clock[0] += collectors.POSIX_INTEGRITY_BUDGET_SECONDS + 1
            return data

        with patch.object(collectors.time, "monotonic", side_effect=lambda: clock[0]), patch.object(
            collectors.os, "read", side_effect=delayed_read
        ), patch.object(collectors.os, "open", wraps=opened) as opens, patch.object(
            collectors.os, "close", wraps=close
        ) as closes:
            items, errors = self.collect_files([self.target, second])
        self.assertFalse(items)
        self.assertEqual(len(errors), 1)
        self.assertIn("time budget exhausted", errors[0])
        self.assertEqual(opens.call_count, 1)
        self.assertEqual(closes.call_count, 1)

    def test_existing_monitored_symlink_keeps_its_original_path(self):
        alias = self.root / "alias.conf"
        alias.symlink_to(self.target)
        items, errors = self.collect_files([alias])
        self.assertFalse(errors)
        self.assertEqual(items[0].path, str(alias))
        self.assertEqual(items[0].sha256, hashlib.sha256(self.target.read_bytes()).hexdigest())

    def test_extra_bytes_on_a_reported_empty_file_are_not_hashed_as_empty(self):
        self.target.write_bytes(b"")
        with patch.object(collectors.os, "read", return_value=b"x") as read:
            items, errors = self.collect_files()
        self.assertFalse(items)
        self.assertIn("unsupported size", errors[0])
        self.assertEqual(read.call_count, 1)

    def test_file_at_the_per_file_limit_is_still_supported(self):
        with patch.object(collectors, "MAX_POSIX_INTEGRITY_FILE_BYTES", self.target.stat().st_size):
            items, errors = self.collect_files()
        self.assertFalse(errors)
        self.assertEqual(len(items), 1)


if __name__ == "__main__":
    unittest.main()
