"""Service inventory limits must remain visible to recovery decisions."""
import subprocess
import unittest
from unittest.mock import patch

from sentinel_blue import collectors


class ServiceCoverageTests(unittest.TestCase):
    def collect(self, loaded, installed):
        def run(argv, **kwargs):
            if argv[1] == "list-units":
                output = "".join(f"{name} loaded active running Owned fixture\n" for name in loaded)
            elif argv[1] == "list-unit-files":
                output = "".join(f"{name} enabled enabled\n" for name in installed)
            else:
                output = "".join(f"Id={name}\nActiveState=active\nSubState=running\nExecMainStatus=0\n\n"
                                 for name in argv[4:])
            return subprocess.CompletedProcess(argv, 0, output, "")
        errors = []
        with patch.object(collectors, "_run", side_effect=run):
            rows = collectors._linux_services(errors)
        return rows, errors

    def test_complete_inventory_at_limit_deduplicates_loaded_and_installed(self):
        names = [f"owned-{i}.service" for i in range(2000)]
        rows, errors = self.collect(names, names)
        self.assertEqual(len(rows), 2000)
        self.assertEqual(len({row.name for row in rows}), 2000)
        self.assertFalse(errors)

    def test_loaded_or_unloaded_overflow_cannot_be_reported_as_complete(self):
        names = [f"owned-{i}.service" for i in range(2001)]
        for loaded, installed in ((names, names), (names[:1], names)):
            with self.subTest(loaded=len(loaded)):
                rows, errors = self.collect(loaded, installed)
                self.assertEqual(len(rows), 2000)
                self.assertTrue(any("service inventory" in error and "limit" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
