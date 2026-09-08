import subprocess
import tempfile
import unittest
from unittest.mock import patch

from sentinel_blue.actions import ActionExecutor
from sentinel_blue.protocol import ProbeResult


class ServiceRecoveryRegressionTests(unittest.TestCase):
    def test_unknown_native_state_is_not_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            with patch("sentinel_blue.actions.platform.system", return_value="Linux"), patch(
                "sentinel_blue.actions.subprocess.run",
                return_value=subprocess.CompletedProcess([], 4, "unknown\n", ""),
            ):
                self.assertEqual(executor._service_state("missing.service"), "unknown")

    def test_unknown_prior_state_never_changes_service(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            with patch.object(executor, "_service_state", return_value="unknown"), patch.object(
                executor, "_set_service_state"
            ) as change:
                result = executor.execute("restart_service", {"service": "web.service"}, {})
            self.assertFalse(result["success"])
            change.assert_not_called()

    def test_already_running_service_is_not_mutated(self):
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            with patch.object(executor, "_service_state", return_value="running"), patch.object(
                executor, "_set_service_state"
            ) as change:
                result = executor.execute("restart_service", {"service": "web.service"}, {})
            self.assertTrue(result["success"])
            change.assert_not_called()

    def test_one_transient_healthy_probe_does_not_commit_recovery(self):
        healthy = ProbeResult("web", "http://127.0.0.1", True)
        failed = ProbeResult("web", "http://127.0.0.1", False)
        with tempfile.TemporaryDirectory() as directory:
            executor = ActionExecutor(directory, allow_containment=True)
            with patch.object(executor, "_service_state", side_effect=["stopped", "running"]), patch.object(
                executor, "_set_service_state"
            ), patch("sentinel_blue.actions.run_probes", side_effect=[[healthy], [failed], [failed]]), patch(
                "sentinel_blue.actions.SERVICE_RECOVERY_MAX_PROBE_ATTEMPTS", 3
            ), patch("sentinel_blue.actions.time.sleep"):
                result = executor.execute(
                    "restart_service", {"service": "web.service", "probes": [{"name": "web"}]}, {}
                )
            self.assertFalse(result["success"])
            self.assertTrue(result["rolled_back"])
