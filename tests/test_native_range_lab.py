import os
import tempfile
import unittest
from pathlib import Path

from sentinel_blue.native_range_lab import (
    CONFIRMATION,
    NativeRangeError,
    RunnerContext,
    _report_path,
    build_native_profile,
    validate_runner_environment,
)


class NativeRangeGateTests(unittest.TestCase):
    def _environment(self, workspace: str) -> dict[str, str]:
        return {
            "SENTINEL_BLUE_DISPOSABLE_LAB": CONFIRMATION,
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Linux",
            "GITHUB_REPOSITORY": "joshua08271/Sentinel-Blue",
            "GITHUB_ACTOR": "joshua08271",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_RUN_ID": "123456789012",
            "GITHUB_WORKSPACE": workspace,
        }

    def test_exact_owner_disposable_runner_context_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            context = validate_runner_environment(
                self._environment(directory),
                effective_uid=0,
                system_name="Linux",
                tool_finder=lambda name: f"/usr/bin/{name}",
            )
        self.assertEqual(context.repository, "joshua08271/Sentinel-Blue")
        self.assertEqual(context.actor, "joshua08271")
        self.assertEqual(context.suffix, "3456789012")

    def test_gate_rejects_each_scope_or_authority_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = self._environment(directory)
            cases = {
                "confirmation": ("SENTINEL_BLUE_DISPOSABLE_LAB", "yes"),
                "actions": ("GITHUB_ACTIONS", "false"),
                "runner": ("RUNNER_ENVIRONMENT", "self-hosted"),
                "os": ("RUNNER_OS", "Windows"),
                "repository": ("GITHUB_REPOSITORY", "someone/fork"),
                "actor": ("GITHUB_ACTOR", "someone-else"),
                "event": ("GITHUB_EVENT_NAME", "push"),
                "run-id": ("GITHUB_RUN_ID", "../../etc"),
            }
            for label, (key, value) in cases.items():
                with self.subTest(label=label):
                    changed = dict(base)
                    changed[key] = value
                    with self.assertRaises(NativeRangeError):
                        validate_runner_environment(
                            changed,
                            effective_uid=0,
                            system_name="Linux",
                            tool_finder=lambda name: f"/usr/bin/{name}",
                        )
            with self.assertRaisesRegex(NativeRangeError, "sudo"):
                validate_runner_environment(
                    base,
                    effective_uid=1000,
                    system_name="Linux",
                    tool_finder=lambda name: f"/usr/bin/{name}",
                )
            with self.assertRaisesRegex(NativeRangeError, "unavailable"):
                validate_runner_environment(
                    base,
                    effective_uid=0,
                    system_name="Linux",
                    tool_finder=lambda name: None if name == "systemctl" else f"/usr/bin/{name}",
                )

    def test_profile_and_probe_are_strictly_loopback_and_not_deployable(self):
        root = (
            Path("C:/SentinelBlueNative/sentinel-blue-native-123")
            if os.name == "nt"
            else Path("/tmp/sentinel-blue-native-123")
        )
        profile, probe, restoration_probe = build_native_profile(
            root,
            agent_id="native-runner-123",
            service_id="sentinel-blue-native-123.service",
            port=43123,
        )
        self.assertEqual(profile.authorized_networks, ("127.0.0.0/8",))
        self.assertEqual(profile.authorized_hosts, ("127.0.0.1",))
        self.assertEqual(profile.controller_ingress_hosts, ("127.0.0.1",))
        self.assertEqual(probe["target"], "http://127.0.0.1:43123/health")
        self.assertEqual(restoration_probe["restore_paths"], [str(root / "protected.conf")])
        self.assertFalse(profile.capabilities["external_telemetry_export"])
        self.assertFalse(profile.capabilities["external_cloud_processing"])
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            profile.require_range_ready()

    def test_report_path_cannot_escape_or_change_name(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            context = RunnerContext(
                repository="joshua08271/Sentinel-Blue",
                actor="joshua08271",
                event_name="pull_request",
                run_id="123",
                suffix="123",
                workspace=workspace,
            )
            expected = workspace / "native-live-report.json"
            self.assertEqual(_report_path(context, None), expected)
            for path in (workspace / "other.json", workspace.parent / "native-live-report.json"):
                with self.subTest(path=path):
                    with self.assertRaises(NativeRangeError):
                        _report_path(context, str(path))


if __name__ == "__main__":
    unittest.main()
