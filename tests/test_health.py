import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sentinel_blue.health import assess_agent_health


class AgentHealthTests(unittest.TestCase):
    def test_unsafe_state_file_permissions_gate_actions(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions test")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            (root / "sequence.json").write_text('{"sequence":1}', encoding="utf-8")
            (root / "sequence.json").chmod(0o644)
            result = assess_agent_health(root)
            self.assertFalse(result["action_safe"])
            self.assertTrue(any("sequence.json" in error for error in result["critical_errors"]))
    def test_matching_runtime_is_action_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "agent.pyz"
            runtime.write_bytes(b"runtime")
            expected = hashlib.sha256(runtime.read_bytes()).hexdigest()
            result = assess_agent_health(root, expected, runtime)
            self.assertTrue(result["action_safe"])
            self.assertEqual(result["runtime_sha256"], expected)

    def test_runtime_tamper_and_low_disk_gate_actions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            runtime = root / "agent.pyz"
            runtime.write_bytes(b"tampered")
            with patch("sentinel_blue.health.shutil.disk_usage", return_value=Mock(free=1)):
                result = assess_agent_health(root, "a" * 64, runtime)
            self.assertFalse(result["action_safe"])
            self.assertTrue(any("digest mismatch" in item for item in result["errors"]))
            self.assertTrue(any("free bytes" in item for item in result["errors"]))


if __name__ == "__main__":
    unittest.main()
