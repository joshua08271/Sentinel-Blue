"""The delivered defender must exclude campaign entry points and remain runnable."""
import contextlib
import hashlib
import io
import subprocess
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

from sentinel_blue.__main__ import parser
from tools.build_defensive_release import EXCLUDED, ROOT, build


class DefensiveDistributionTests(unittest.TestCase):
    def test_source_entry_point_has_the_same_defender_defaults_as_the_archive(self):
        result = subprocess.run(
            [sys.executable, '-m', 'sentinel_blue', '--help'],
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('controller', result.stdout)
        self.assertIn('opening', result.stdout)
        self.assertNotIn('native-lab', result.stdout)
        self.assertNotIn('restoration-lab', result.stdout)
        self.assertNotIn('self-test', parser().format_help())

    def test_build_cannot_include_its_own_output(self):
        with self.assertRaisesRegex(ValueError, 'outside runtime source'):
            build(ROOT/'src'/'not-a-release-directory')

    def test_campaign_commands_are_absent_and_rejected(self):
        cli = parser(include_labs=False)
        help_text = cli.format_help()
        for command in ('native-lab', 'windows-native-lab', 'range', 'restoration-lab', 'policy-lab', 'self-test', 'simulate'):
            with self.subTest(command=command), contextlib.redirect_stderr(io.StringIO()):
                self.assertNotIn(command+',', help_text)
                with self.assertRaises(SystemExit) as raised:
                    cli.parse_args([command])
                self.assertEqual(raised.exception.code, 2)
        self.assertEqual(cli.parse_args(['doctor', '--json']).command, 'doctor')

    def test_reproducible_package_excludes_campaign_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first, second = build(root/'one'), build(root/'two')
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                self.assertFalse(EXCLUDED & {Path(name).name for name in archive.namelist()})
                self.assertIn('sentinel_blue/controller.py', archive.namelist())
                self.assertIn('sentinel_blue/service_repair_executor.py', archive.namelist())
            result = subprocess.run([sys.executable, str(first), 'native-lab'], capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2)
            self.assertIn(b'invalid choice', result.stderr)
