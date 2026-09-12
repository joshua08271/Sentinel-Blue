"""Validate the exact defensive execution boundary before cloud changes."""
import ast
import base64
import hashlib
import io
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

# Azure control-plane tools also run as standalone scripts in Cloud Shell.
with patch.object(sys, 'path', [str(Path(__file__).resolve().parents[1]/'tools'), *sys.path]):
    import azure_defensive_rehearsal as azure


class DefensiveAzurePayloadTests(unittest.TestCase):
    def test_payload_contains_only_defensive_fixture_entry(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)/'runtime.pyz'
            runtime.write_bytes(b'pinned fixture runtime')
            packed, digest = azure.pack(runtime, hashlib.sha256(runtime.read_bytes()).hexdigest())
            data = base64.b64decode(packed, validate=True)
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest)
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                names = archive.namelist()
                self.assertEqual(len(names), len(set(names)))
                self.assertIn('defensive_practice_native.py', names)
                self.assertFalse(any('security_native' in name or 'windows_load_native' in name for name in names))
                tree = ast.parse(archive.read('defensive_practice_native.py'))
                imports = [alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names]
                self.assertFalse(any('security_native' in name or 'windows_load_native' in name for name in imports))
                self.assertNotIn(b'--security-fixture', archive.read('defensive_practice_native.py'))
            for target in azure.lifecycle.TARGETS:
                script = azure.captured_script(target, '/reviewed-resource', packed, digest, 'fixture',
                    'https://example.blob.core.windows.net/input?fixture',
                    'https://example.blob.core.windows.net/output?fixture')
                self.assertNotIn('--security-fixture', script)
                self.assertIn('/reviewed-resource', script)
                if target == 'sb-linux-target':
                    compile(script.split("<<'SB_STAGE'\n", 1)[1].rsplit('\nSB_STAGE', 1)[0], '<linux-fixture>', 'exec')

    def test_changed_runtime_is_rejected_before_cloud_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)/'runtime.pyz'
            runtime.write_bytes(b'changed')
            with self.assertRaisesRegex(ValueError, 'checksum'):
                azure.pack(runtime, '0'*64)

    def test_security_fixture_cannot_be_selected(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory)/'runtime.pyz'
            runtime.write_bytes(b'pinned')
            with self.assertRaisesRegex(ValueError, 'Only defensive'):
                azure.pack(runtime, hashlib.sha256(runtime.read_bytes()).hexdigest(), 'security')
