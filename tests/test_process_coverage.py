"""A bounded process inventory must report when it omits observations."""
from types import SimpleNamespace
import os
import unittest
from unittest.mock import patch

from sentinel_blue import collectors


class ProcEntry:
    def __init__(self, pid):
        self.name = str(pid)

    def __truediv__(self, name):
        return SimpleNamespace(read_text=lambda **_: "Name:\towned-fixture\nUid:\t0\nPPid:\t1\n")


class ProcessCoverageTests(unittest.TestCase):
    def linux(self, count):
        errors = []
        with patch.object(collectors.Path, "iterdir", return_value=iter(ProcEntry(i + 1) for i in range(count))), patch.object(
            collectors.os, "readlink", return_value="/owned/fixture"
        ):
            rows = collectors._linux_processes(errors)
        return rows, errors

    def windows(self, count):
        native = [{"Name": "owned-fixture", "ProcessId": i + 1, "ParentProcessId": 1,
                   "ExecutablePath": "C:\\owned\\fixture.exe", "UserName": "fixture",
                   "Privileged": False} for i in range(count)]
        errors = []
        with patch.object(collectors, "_windows_json", return_value=native):
            rows = collectors._windows_processes(errors)
        return rows, errors

    def test_exact_limit_retains_every_process_without_overflow(self):
        for collect in (self.linux, self.windows):
            with self.subTest(platform=collect.__name__):
                rows, errors = collect(4096)
                self.assertEqual(len(rows), 4096)
                self.assertEqual(rows[-1].process_id, 4096)
                self.assertFalse(errors)

    def test_overflow_is_visible_while_keeping_bounded_observations(self):
        for collect in (self.linux, self.windows):
            with self.subTest(platform=collect.__name__):
                rows, errors = collect(4097)
                self.assertEqual(len(rows), 4096)
                self.assertTrue(any("process inventory" in error and "limit" in error for error in errors), errors)

    @unittest.skipUnless(os.name == "nt", "requires native PowerShell")
    def test_native_query_retains_overflow_signal_from_inert_provider(self):
        # Stub only provider input. Run the actual compiled query and decoder;
        # no processes, accounts or native services are created by this test.
        provider = r"""
function Get-LocalGroup { [CmdletBinding()] param([string]$SID) }
function Get-LocalGroupMember { [CmdletBinding()] param() }
function Get-Process { [CmdletBinding()] param([switch]$IncludeUserName) }
function Get-CimInstance {
  [CmdletBinding()] param([string]$ClassName, [string[]]$Property)
  for ($i=1; $i -le 4097; $i++) {
    [PSCustomObject]@{ProcessId=$i;ParentProcessId=1;Name='owned-fixture';ExecutablePath='';CreationDate=$null}
  }
}
"""
        query = provider + collectors.WINDOWS_QUERIES["PROCESSES"]
        errors = []
        with patch.object(collectors, "WINDOWS_QUERIES", {"PROCESSES": query}):
            rows = collectors._windows_processes(errors)
        self.assertEqual(len(rows), 4096, errors)
        self.assertTrue(any("process inventory" in error and "limit" in error for error in errors), errors)


if __name__ == "__main__":
    unittest.main()
