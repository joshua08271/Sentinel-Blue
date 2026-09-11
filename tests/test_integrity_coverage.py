"""Coverage limits must be visible in telemetry, including optional discovery."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sentinel_blue import collectors


class IntegrityCoverageTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def test_explicit_files_are_prioritized_and_overflow_is_reported(self):
        required = self.root / "scored.conf"
        required.write_bytes(b"reviewed configuration")
        discovered = [self.root / f"unit-{index}.service" for index in range(260)]
        errors = []
        with patch.object(collectors, "_discover_integrity_paths", return_value=iter(discovered)):
            paths = collectors._integrity_paths("linux", [str(required)], errors=errors)
        self.assertEqual(len(paths), 256)
        self.assertEqual(paths[0], required)
        self.assertTrue(any("path limit" in error for error in errors))

    def test_collection_reports_overflow_without_opening_unselected_paths(self):
        required = [str(self.root / f"file-{index}") for index in range(257)]
        errors = []
        with patch.object(collectors, "_discover_integrity_paths", return_value=iter(())), patch.object(
            collectors, "_posix_integrity_item", return_value=None
        ) as read:
            self.assertEqual(collectors._integrity("linux", errors, required), [])
        self.assertEqual(read.call_count, 256)
        self.assertTrue(any("path limit" in error for error in errors))

    def test_invalid_explicit_path_cannot_disappear_without_diagnostic(self):
        for path in ("relative.conf", "bad\x00path"):
            with self.subTest(path=path), patch.object(collectors, "_discover_integrity_paths", return_value=iter(())):
                errors = []
                collectors._integrity_paths("linux", [path], errors=errors)
                self.assertTrue(any("protected path" in error for error in errors))

    def test_unreadable_discovery_reports_incomplete_coverage(self):
        errors = []
        with patch.object(collectors, "_discover_integrity_paths", side_effect=PermissionError("inventory unavailable")):
            collectors._integrity_paths("linux", errors=errors)
        self.assertTrue(any("discovery" in error for error in errors))

    def test_duplicates_do_not_consume_path_capacity(self):
        required = str(self.root / "one.conf")
        errors = []
        with patch.object(collectors, "_discover_integrity_paths", return_value=iter(())):
            paths = collectors._integrity_paths("linux", [required] * 256, errors=errors)
        self.assertFalse(errors)
        self.assertEqual(paths.count(Path(required)), 1)

    def test_case_distinct_paths_are_retained_without_identity_evidence(self):
        required = [str(self.root / "service.conf"), str(self.root / "SERVICE.conf")]
        paths = collectors._integrity_paths("windows", required, errors=[])
        self.assertEqual([str(path) for path in paths[:2]], required)

    def test_watcher_remains_available_when_collection_will_report_overflow(self):
        required = [str(self.root / f"file-{index}") for index in range(257)]
        with patch.object(collectors, "_discover_integrity_paths", return_value=iter(())):
            paths = collectors.integrity_watch_paths(required)
        self.assertEqual(len(paths), 256)
        self.assertEqual(paths[0], required[0])

    def test_discovery_reads_nested_application_paths_and_missing_roots(self):
        config = self.root / "16" / "main" / "postgresql.conf"
        config.parent.mkdir(parents=True)
        config.write_bytes(b"configuration")
        (self.root / "unrelated").write_bytes(b"file")
        self.assertEqual(collectors._discover_integrity_paths(self.root, "*/main/postgresql.conf"), [config])
        self.assertEqual(collectors._discover_integrity_paths(self.root / "absent", "*.conf"), [])

    def test_native_directory_access_failure_is_not_treated_as_empty(self):
        with patch.object(collectors.os, "scandir", side_effect=PermissionError("directory unavailable")):
            with self.assertRaises(PermissionError):
                collectors._discover_integrity_paths(self.root, "*.conf")

    def test_directory_entry_work_is_bounded_even_without_matches(self):
        for index in range(4):
            (self.root / f"unrelated-{index}").touch()
        with patch.object(collectors, "MAX_INTEGRITY_DISCOVERY_ENTRIES", 2):
            with self.assertRaisesRegex(ValueError, "entry limit"):
                collectors._discover_integrity_paths(self.root, "*.conf")


if __name__ == "__main__":
    unittest.main()
