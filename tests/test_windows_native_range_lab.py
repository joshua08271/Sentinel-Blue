import os
import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.windows_native_range_lab import (
    ACCOUNT_DESCRIPTION,
    CONFIRMATION,
    REPORT_NAME,
    WindowsNativeRangeError,
    WindowsNativeRunnerLab,
    WindowsRunnerContext,
    _is_reparse,
    _report_path,
    validate_runner_environment,
)


ROOT = Path(__file__).resolve().parents[1]


class WindowsNativeRangeGateTests(unittest.TestCase):
    def _environment(self, workspace: str) -> dict[str, str]:
        # The runner's TEMP may use an 8.3 alias. Supply the actual fixture
        # directory to the unchanged production no-alias/no-reparse gate.
        workspace = str(Path(workspace).resolve(strict=True))
        return {
            "SENTINEL_BLUE_WINDOWS_DISPOSABLE_LAB": CONFIRMATION,
            "SENTINEL_BLUE_HEAD_REPOSITORY": "joshua08271/Sentinel-Blue",
            "GITHUB_ACTIONS": "true",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "RUNNER_OS": "Windows",
            "GITHUB_REPOSITORY": "joshua08271/Sentinel-Blue",
            "GITHUB_ACTOR": "joshua08271",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_RUN_ID": "123456789012",
            "GITHUB_WORKSPACE": workspace,
            "RUNNER_TEMP": workspace,
        }

    def test_exact_owner_windows_hosted_context_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            context = validate_runner_environment(
                self._environment(directory),
                system_name="Windows",
                administrator=True,
                tool_finder=lambda name: f"C:/Windows/System32/{name}",
            )
        self.assertEqual(context.repository, "joshua08271/Sentinel-Blue")
        self.assertEqual(context.suffix, "3456789012")

    def test_gate_rejects_each_scope_or_authority_substitution(self):
        with tempfile.TemporaryDirectory() as directory:
            base = self._environment(directory)
            cases = {
                "confirmation": (
                    "SENTINEL_BLUE_WINDOWS_DISPOSABLE_LAB",
                    "yes",
                ),
                "actions": ("GITHUB_ACTIONS", "false"),
                "runner": ("RUNNER_ENVIRONMENT", "self-hosted"),
                "os": ("RUNNER_OS", "Linux"),
                "repository": ("GITHUB_REPOSITORY", "someone/fork"),
                "head-repository": (
                    "SENTINEL_BLUE_HEAD_REPOSITORY",
                    "someone/fork",
                ),
                "actor": ("GITHUB_ACTOR", "someone-else"),
                "event": ("GITHUB_EVENT_NAME", "push"),
                "run-id": ("GITHUB_RUN_ID", "../../windows"),
            }
            for label, (key, value) in cases.items():
                with self.subTest(label=label):
                    changed = dict(base)
                    changed[key] = value
                    with self.assertRaises(WindowsNativeRangeError):
                        validate_runner_environment(
                            changed,
                            system_name="Windows",
                            administrator=True,
                            tool_finder=lambda name: f"C:/Windows/System32/{name}",
                        )
            with self.assertRaisesRegex(WindowsNativeRangeError, "administrator"):
                validate_runner_environment(
                    base,
                    system_name="Windows",
                    administrator=False,
                    tool_finder=lambda name: f"C:/Windows/System32/{name}",
                )
            with self.assertRaisesRegex(WindowsNativeRangeError, "unavailable"):
                validate_runner_environment(
                    base,
                    system_name="Windows",
                    administrator=True,
                    tool_finder=lambda name: None if name == "icacls.exe" else name,
                )

    def test_report_path_cannot_escape_or_change_name(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory).resolve()
            context = WindowsRunnerContext(
                repository="joshua08271/Sentinel-Blue",
                actor="joshua08271",
                event_name="pull_request",
                run_id="123",
                suffix="123",
                workspace=workspace,
                runner_temp=workspace,
            )
            expected = workspace / REPORT_NAME
            self.assertEqual(_report_path(context, None), expected)
            for path in (workspace / "other.json", workspace.parent / REPORT_NAME):
                with self.subTest(path=path):
                    with self.assertRaises(WindowsNativeRangeError):
                        _report_path(context, str(path))

    @unittest.skipUnless(hasattr(os, "symlink"), "symbolic links unavailable")
    def test_reparse_helper_recognizes_a_symbolic_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            target.write_text("fixture", encoding="utf-8")
            link = root / "link"
            link.symlink_to(target)
            self.assertTrue(_is_reparse(link))

    def test_workflow_uses_only_owner_gated_github_hosted_windows(self):
        workflow = (
            ROOT / ".github" / "workflows" / "native-red-blue-lab.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("runs-on: windows-latest", workflow)
        self.assertIn("github.actor == 'joshua08271'", workflow)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", workflow)
        self.assertIn(
            "SENTINEL_BLUE_WINDOWS_DISPOSABLE_LAB: "
            "github-hosted-ephemeral-windows-runner",
            workflow,
        )
        self.assertIn("SENTINEL_BLUE_HEAD_REPOSITORY:", workflow)
        self.assertIn("windows-native-lab", workflow)
        self.assertNotIn("runs-on: self-hosted", workflow)
        self.assertNotIn("secrets.", workflow)


class WindowsNativeOwnershipTests(unittest.TestCase):
    def test_disable_fixture_refuses_a_replaced_sid_or_unowned_account(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            lab.account_sid = 'S-1-5-21-1-2-3-1001'
            for owned, observed in ((False, lab.account_sid), (True, 'S-1-5-21-1-2-3-1002')):
                lab.account_created = owned
                with (
                    patch.object(lab, '_account_state', return_value={'Exists': True, 'SID': observed,
                                                                      'Description': ACCOUNT_DESCRIPTION}),
                    patch.object(lab, '_powershell') as command,
                    self.assertRaisesRegex(WindowsNativeRangeError, 'changed account'),
                ):
                    lab._disable_account_exact()
                command.assert_not_called()

    def test_setup_refusal_never_deletes_a_preexisting_root_or_queries_native_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            lab.root.mkdir()
            preserved = lab.root / "previous-owner.txt"
            preserved.write_text("preserve me", encoding="utf-8")
            with self.assertRaisesRegex(WindowsNativeRangeError, "root already exists"):
                lab.setup()
            with patch.object(lab, "_powershell", side_effect=AssertionError("no resource was created")) as invoke:
                lab.cleanup()
            self.assertTrue(preserved.exists())
            self.assertEqual(preserved.read_text(encoding="utf-8"), "preserve me")
            invoke.assert_not_called()

    def _lab(self, directory: str) -> WindowsNativeRunnerLab:
        root = Path(directory).resolve()
        context = WindowsRunnerContext(
            repository="joshua08271/Sentinel-Blue",
            actor="joshua08271",
            event_name="pull_request",
            run_id="123456789012",
            suffix="3456789012",
            workspace=root,
            runner_temp=root,
        )
        with patch.dict(os.environ, {"LOCALAPPDATA": directory}):
            return WindowsNativeRunnerLab(context)

    def test_cleanup_refuses_a_changed_account_marker(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            lab.account_created = True
            lab.account_sid = "S-1-5-21-1-2-3-1001"
            with (
                patch.object(
                    lab,
                    "_account_state",
                    return_value={
                        "Exists": True,
                        "SID": lab.account_sid,
                        "Description": "changed",
                    },
                ),
                patch.object(lab, "_powershell") as powershell,
                self.assertRaisesRegex(WindowsNativeRangeError, "changed account"),
            ):
                lab._delete_account_exact()
            powershell.assert_not_called()

    def test_cleanup_refuses_a_replaced_account_sid(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            lab.account_created = True
            lab.account_sid = "S-1-5-21-1-2-3-1001"
            with (
                patch.object(
                    lab,
                    "_account_state",
                    return_value={
                        "Exists": True,
                        "SID": "S-1-5-21-1-2-3-1002",
                        "Description": ACCOUNT_DESCRIPTION,
                    },
                ),
                patch.object(lab, "_powershell") as powershell,
                self.assertRaisesRegex(WindowsNativeRangeError, "changed account"),
            ):
                lab._delete_account_exact()
            powershell.assert_not_called()

    def test_cleanup_refuses_a_changed_temporary_executable(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            lab.process_path.parent.mkdir(parents=True, exist_ok=True)
            lab.process_path.write_bytes(b"changed")
            lab.process_digest = "0" * 64
            with self.assertRaisesRegex(
                WindowsNativeRangeError, "changed temporary executable"
            ):
                lab._delete_process_file_exact()
            self.assertTrue(lab.process_path.exists())

    def test_cleanup_refuses_a_changed_firewall_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            state = {
                "Exists": True,
                "Name": lab.firewall_name,
                "DisplayName": lab.firewall_name,
                "Description": "changed",
                "Enabled": "False",
                "Direction": "Outbound",
                "Action": "Block",
                "RemoteAddress": "127.0.0.1",
                "Program": str(lab.process_path),
            }
            with (
                patch.object(lab, "_firewall_state", return_value=state),
                patch.object(lab, "_powershell") as powershell,
                self.assertRaisesRegex(WindowsNativeRangeError, "changed firewall"),
            ):
                lab._delete_firewall_rule_exact()
            powershell.assert_not_called()

    def test_cleanup_refuses_an_enabled_or_expanded_firewall_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            baseline = {
                "Exists": True,
                "Name": lab.firewall_name,
                "DisplayName": lab.firewall_name,
                "Description": lab.firewall_description,
                "Enabled": "False",
                "Direction": "Outbound",
                "Action": "Block",
                "RemoteAddress": "127.0.0.1",
                "Program": str(lab.process_path),
            }
            for field, value in (("Enabled", "True"), ("RemoteAddress", "Any")):
                with self.subTest(field=field):
                    changed = dict(baseline)
                    changed[field] = value
                    with (
                        patch.object(lab, "_firewall_state", return_value=changed),
                        patch.object(lab, "_powershell") as powershell,
                        self.assertRaisesRegex(
                            WindowsNativeRangeError, "changed firewall"
                        ),
                    ):
                        lab._delete_firewall_rule_exact()
                    powershell.assert_not_called()

    def test_cleanup_continues_after_firewall_ownership_refusal(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            lab.firewall_created = lab.run_value_created = lab.account_created = lab.task_created = True
            lab.process_created = True
            lab.process_digest = "a" * 64
            lab.root.mkdir()
            root_stat = lab.root.stat(follow_symlinks=False)
            lab.root_identity = (root_stat.st_dev, root_stat.st_ino)
            with (
                patch.object(
                    lab,
                    "_delete_firewall_rule_exact",
                    side_effect=WindowsNativeRangeError("ownership refused"),
                ) as firewall,
                patch.object(lab, "_delete_run_value_exact") as run_value,
                patch.object(lab, "_delete_account_exact") as account,
                patch.object(lab, "_delete_task_exact") as task,
                patch.object(lab, "_delete_process_file_exact") as process_file,
                patch.object(lab, "_restore_config_if_needed") as protected_file,
                patch.object(lab, "_account_state", return_value={"Exists": False}),
                patch.object(lab, "_task_state", return_value={"Exists": False}),
                patch.object(lab, "_firewall_state", return_value={"Exists": False}),
                patch.object(lab, "_run_value_state", return_value={"Exists": False}),
            ):
                result = lab.cleanup()
            self.assertFalse(result["verified"])
            self.assertTrue(any("ownership refused" in item for item in result["errors"]))
            firewall.assert_called_once_with()
            run_value.assert_called_once_with()
            account.assert_called_once_with()
            task.assert_called_once_with()
            process_file.assert_called_once_with()
            protected_file.assert_called_once_with()

    def test_cleanup_preserves_a_replacement_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            lab.root.mkdir()
            owned = lab.root.stat(follow_symlinks=False)
            lab.root_identity = (owned.st_dev, owned.st_ino)
            lab.root.rename(lab.root.with_name("moved-owned-root"))
            lab.root.mkdir()
            replacement = lab.root / "replacement.txt"
            replacement.write_text("preserve", encoding="utf-8")
            with patch.object(lab, "_restore_config_if_needed") as restore:
                result = lab.cleanup()
            self.assertFalse(result["verified"])
            self.assertTrue(any("replaced Windows cleanup root" in x for x in result["errors"]))
            self.assertEqual(replacement.read_text(encoding="utf-8"), "preserve")
            restore.assert_not_called()

    def test_cleanup_removes_owned_executable_even_when_process_is_already_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            lab.process_path.parent.mkdir(parents=True, exist_ok=True)
            lab.process_path.write_bytes(b"owned inert file")
            lab.process_digest = hashlib.sha256(b"owned inert file").hexdigest()
            lab.process_created = False
            result = lab.cleanup()
            self.assertTrue(result["verified"])
            self.assertFalse(lab.process_path.exists())

    def test_firewall_creation_is_recoverable_after_partial_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            with (
                patch.object(
                    lab,
                    "_powershell",
                    side_effect=WindowsNativeRangeError("creation interrupted"),
                ),
                self.assertRaisesRegex(WindowsNativeRangeError, "creation interrupted"),
            ):
                lab._create_firewall_rule()
            self.assertTrue(lab.firewall_created)

    def test_firewall_fixture_is_disabled_loopback_block_only(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            state = {
                "Exists": True,
                "Name": lab.firewall_name,
                "DisplayName": lab.firewall_name,
                "Description": lab.firewall_description,
                "Enabled": "False",
                "Direction": "Outbound",
                "Action": "Block",
                "RemoteAddress": "127.0.0.1",
                "Program": str(lab.process_path),
            }
            with (
                patch.object(lab, "_powershell") as powershell,
                patch.object(lab, "_firewall_state", return_value=state),
            ):
                lab._create_firewall_rule()
            script = powershell.call_args.args[0]
            self.assertIn("-Enabled False", script)
            self.assertIn("-Direction Outbound", script)
            self.assertIn("-Action Block", script)
            self.assertIn("-RemoteAddress 127.0.0.1", script)
            self.assertNotIn("-Action Allow", script)

    def test_cleanup_refuses_a_changed_registry_run_value(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            for field, value in (
                ("Kind", "ExpandString"),
                ("Value", lab.run_value_data + " changed"),
            ):
                with self.subTest(field=field):
                    state = {
                        "KeyExists": True,
                        "Exists": True,
                        "Kind": "String",
                        "Value": lab.run_value_data,
                    }
                    state[field] = value
                    with (
                        patch.object(lab, "_run_value_state", return_value=state),
                        patch.object(lab, "_powershell") as powershell,
                        self.assertRaisesRegex(
                            WindowsNativeRangeError, "changed Registry Run"
                        ),
                    ):
                        lab._delete_run_value_exact()
                    powershell.assert_not_called()

    def test_registry_run_fixture_is_inert_and_not_force_replaced(self):
        with tempfile.TemporaryDirectory() as directory:
            lab = self._lab(directory)
            state = {
                "KeyExists": True,
                "Exists": True,
                "Kind": "String",
                "Value": lab.run_value_data,
            }
            with (
                patch.object(lab, "_powershell") as powershell,
                patch.object(lab, "_run_value_state", return_value=state),
            ):
                lab._create_run_value()
            script = powershell.call_args.args[0]
            environment = powershell.call_args.kwargs["extra_env"]
            self.assertIn("New-ItemProperty", script)
            self.assertNotIn("-Force", script)
            self.assertTrue(environment["SENTINEL_BLUE_FIXTURE_RUN_VALUE"].endswith("/d /c exit 0"))

    def test_session_parameters_bind_the_entire_observation(self):
        identity = {
            "schema": "sentinel-process-v1",
            "platform": "windows",
            "process_id": 4242,
            "boot_id": "20260904010101.000000+000",
            "start_time": "133999999999999999",
            "executable_path": r"C:\Windows\Temp\fixture.exe",
            "executable_file_id": "vol:1:file:2",
            "user_id": "S-1-5-21-1-2-3-1001",
            "kernel_session_id": "1",
        }
        telemetry = WindowsNativeRunnerLab._session_telemetry(
            4242, identity, sequence=7
        )
        parameters = WindowsNativeRunnerLab._session_parameters(telemetry)
        self.assertEqual(parameters["session"]["process_identity"], identity)
        self.assertEqual(parameters["observation"]["boot_id"], identity["boot_id"])
        self.assertEqual(parameters["observation"]["sequence"], 7)
        self.assertRegex(parameters["observation"]["payload_sha256"], r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
