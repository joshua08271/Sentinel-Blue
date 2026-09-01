import base64
import hashlib
import json
import os
import tempfile
import unittest
import zipfile
from unittest.mock import patch
from pathlib import Path

from sentinel_blue.__main__ import parser as cli_parser
from sentinel_blue.auth import derive_enrollment_ticket
from sentinel_blue.launcher import (
    _deploy_winrm,
    _deploy_local,
    _deploy_ssh,
    _linux_unit,
    _ssh_base,
    deployment_plan,
    deployment_preflight,
    execute_plan,
    load_inventory,
    run as run_launcher,
    validate_runtime_package,
)
from sentinel_blue import __version__
from sentinel_blue.event_profile import CAPABILITIES, EventProfile, load_event_profile


def write_runtime_package(path: Path) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in (
            "__main__.py",
            "sentinel_blue/__main__.py",
            "sentinel_blue/agent.py",
            "sentinel_blue/controller.py",
            "sentinel_blue/web/index.html",
        ):
            archive.writestr(name, "# test runtime\n")


def attach_live_test_profile(inventory: dict, root: Path) -> dict:
    paths = []
    routes = []
    hosts = []
    for host in inventory["hosts"]:
        hosts.append(host["address"])
        transport = host.get("transport", "auto")
        if transport == "auto":
            transport = "winrm" if host.get("platform") == "windows" else "ssh"
        routes.append(transport)
        paths.append(
            host.get(
                "install_directory",
                "C:\\ProgramData\\SentinelBlue"
                if host.get("platform") == "windows"
                else "/opt/sentinel-blue",
            )
        )
    capabilities = {name: False for name in CAPABILITIES}
    capabilities["external_controller"] = True
    capabilities["file_restoration"] = any(
        host.get("allow_restoration", False) for host in inventory["hosts"]
    )
    capabilities["session_containment"] = any(
        host.get("allow_containment", False) for host in inventory["hosts"]
    )
    controller_ca = root / "controller-ca.crt"
    controller_ca.write_bytes(b"launcher fixture public controller trust anchor")
    profile_path = root / "event-profile.json"
    profile_path.write_text(
        json.dumps(
            {
                "profile_version": 1,
                "profile_id": "launcher-live-test",
                "competition": "custom",
                "environment": "live-competition",
                "autonomy_mode": "approval-based",
                "architecture": {
                    "single_live_scored_network": True,
                    "blue_staging_non_authoritative": True,
                },
                "scope": {
                    "authorized_networks": inventory["authorized_networks"],
                    "authorized_hosts": hosts,
                    "controller_ingress_hosts": hosts,
                    "excluded_hosts": [],
                    "approved_deployment_paths": paths,
                },
                "deployment": {"approved_routes": sorted(set(routes))},
                "capabilities": capabilities,
                "organizer_exceptions": [],
                "allowed_automatic_actions": [],
                "official_identities": [{"agent_id": "*", "name": "official-example", "class": "organizer", "source": "unit-test"}],
                "services": [{
                    "service_id": "fixture", "host": hosts[0], "protocol": "tcp", "port": 1,
                    "implementation": "fixture", "dependencies": [], "required_accounts": [],
                    "required_files": [], "required_data": [], "credential_source": "",
                    "expected_transactions": [{"kind": "fixture"}], "local_checks": [],
                    "allowed_automatic_actions": [], "approval_actions": [],
                    "backup_method": "fixture", "recovery_method": "fixture", "rollback_method": "fixture"
                }],
                "services_confirmed": True,
                "recovery": {"baseline_promotion_delay_seconds": 60},
                "approval": {"status": "approved", "approved_by": "unit-test"},
                "release": {
                    "version": __version__, "approved": True, "sha256": "a" * 64,
                    "controller_ca_sha256": hashlib.sha256(
                        controller_ca.read_bytes()
                    ).hexdigest(),
                    "public_url": "https://example.invalid/sentinel-blue.pyz", "frozen": True,
                    "submitted_to_officials": True, "submission_approved": True,
                    "public_and_equal_access": True, "cloud_processing": False,
                    "external_telemetry_export": False, "public_days_before_event": 0,
                    "submitted_days_before_event": 0
                },
            }
        ),
        encoding="utf-8",
    )
    for host in inventory["hosts"]:
        host["event_profile"] = str(profile_path)
        host["controller_ca_file"] = str(controller_ca)
    return inventory


def write_range_test_profile(
    inventory: dict, root: Path, package_checksum: str
) -> Path:
    payload = json.loads(json.dumps(EventProfile.testing().raw))
    hosts = [host["address"] for host in inventory["hosts"]]
    payload["profile_id"] = "launcher-range-test"
    payload["scope"] = {
        "authorized_networks": inventory["authorized_networks"],
        "authorized_hosts": hosts,
        "controller_ingress_hosts": hosts,
        "excluded_hosts": [],
        "approved_deployment_paths": [
            "/opt/sentinel-blue",
            "C:\\ProgramData\\SentinelBlue",
        ],
    }
    payload["deployment"] = {"approved_routes": ["ssh", "winrm"]}
    payload["services"] = [
        {
            "service_id": "fixture",
            "host": hosts[0],
            "protocol": "tcp",
            "port": 1,
            "implementation": "fixture",
            "dependencies": [],
            "required_accounts": [],
            "required_files": [],
            "required_data": [],
            "credential_source": "",
            "expected_transactions": [{"kind": "fixture"}],
            "local_checks": [],
            "allowed_automatic_actions": [],
            "approval_actions": [],
            "backup_method": "fixture",
            "recovery_method": "fixture",
            "rollback_method": "fixture",
        }
    ]
    payload["services_confirmed"] = True
    controller_ca = root / "controller-ca.crt"
    controller_ca.write_bytes(b"range fixture public controller trust anchor")
    payload["release"] = {
        "version": __version__,
        "sha256": package_checksum,
        "controller_ca_sha256": hashlib.sha256(controller_ca.read_bytes()).hexdigest(),
        "cloud_processing": False,
        "external_telemetry_export": False,
    }
    profile_path = root / "range-profile.json"
    profile_path.write_text(json.dumps(payload), encoding="utf-8")
    for host in inventory["hosts"]:
        host["controller_ca_file"] = str(controller_ca)
    return profile_path


class LauncherTests(unittest.TestCase):
    def test_bound_plan_requires_an_explicit_agent_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = {
                "authorized_networks": ["127.0.0.0/8"],
                "hosts": [
                    {
                        "name": "host-name-is-not-an-identity",
                        "address": "127.0.0.1",
                        "platform": "linux",
                        "transport": "local",
                    }
                ],
            }
            attach_live_test_profile(inventory, Path(directory))
            profile = load_event_profile(Path(directory) / "event-profile.json")
            with self.assertRaisesRegex(ValueError, "explicit valid agent_id"):
                deployment_plan(inventory, event_profile=profile)

    def test_bound_plan_rejects_duplicate_or_reserved_agent_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory = {
                "authorized_networks": ["127.0.0.0/8"],
                "hosts": [
                    {
                        "agent_id": "same-agent",
                        "address": "127.0.0.1",
                        "platform": "linux",
                        "transport": "local",
                    },
                    {
                        "agent_id": "same-agent",
                        "address": "127.0.0.2",
                        "platform": "linux",
                        "transport": "local",
                    },
                ],
            }
            attach_live_test_profile(inventory, root)
            profile = load_event_profile(root / "event-profile.json")
            with self.assertRaisesRegex(ValueError, "duplicate.*agent_id"):
                deployment_plan(inventory, event_profile=profile)
            inventory["hosts"] = [
                {
                    "agent_id": "sentinel-relay-probes",
                    "address": "127.0.0.1",
                    "platform": "linux",
                    "transport": "local",
                    "event_profile": str(root / "event-profile.json"),
                }
            ]
            with self.assertRaisesRegex(ValueError, "reserved"):
                deployment_plan(inventory, event_profile=profile)

    def test_bound_local_deployment_stages_only_the_per_host_ticket(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "sentinel-blue.pyz"
            write_runtime_package(package)
            destination = root / "installed"
            master = "m" * 48
            inventory = {
                "authorized_networks": ["127.0.0.0/8"],
                "hosts": [
                    {
                        "name": "local-test",
                        "agent_id": "local-agent-one",
                        "address": "127.0.0.1",
                        "platform": "linux",
                        "transport": "local",
                        "install_directory": str(destination),
                    }
                ],
            }
            attach_live_test_profile(inventory, root)
            profile = load_event_profile(root / "event-profile.json")
            step = deployment_plan(inventory, event_profile=profile)[0]
            result = execute_plan(
                [step], inventory, package, None, "http://127.0.0.1:8765", master
            )[0]
            staged = json.loads((destination / "enrollment.json").read_text())
            expected = derive_enrollment_ticket(
                master, profile.fingerprint, "local-agent-one"
            )
            self.assertEqual(staged, {"token": expected})
            self.assertNotIn(master, (destination / "enrollment.json").read_text())
            self.assertEqual(result["agent_id"], "local-agent-one")

    def test_rejects_host_outside_scope(self):
        inventory = {
            "authorized_networks": ["198.51.100.0/24"],
            "hosts": [{"address": "203.0.113.5", "platform": "linux"}],
        }
        with self.assertRaises(ValueError):
            deployment_plan(inventory)

    def test_preflight_rejects_controller_command_injection_characters(self):
        inventory = {
            "authorized_networks": ["198.51.100.0/24"],
            "hosts": [{"address": "198.51.100.5", "platform": "windows"}],
        }
        report = deployment_preflight(
            deployment_plan(inventory), None, controller="https://bad'host:8765"
        )
        self.assertFalse(report["ready"])
        self.assertTrue(report["global_blockers"])

    def test_selects_platform_transport(self):
        inventory = {
            "authorized_networks": ["198.51.100.0/24"],
            "hosts": [{"address": "198.51.100.5", "platform": "windows", "transport": "auto"}],
        }
        self.assertEqual(deployment_plan(inventory)[0].transport, "winrm")

    def test_shared_inventory_probe_config_is_forwarded_to_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory_path = Path(directory) / "inventory.json"
            inventory_path.write_text(
                '{"authorized_networks":["198.51.100.0/24"],"probes":[],"hosts":[{"address":"198.51.100.5","platform":"linux"}]}',
                encoding="utf-8",
            )
            inventory = load_inventory(inventory_path)
            self.assertEqual(inventory["hosts"][0]["probe_config"], str(inventory_path.resolve()))

    def test_ssh_requires_a_known_host_by_default(self):
        inventory = {
            "authorized_networks": ["198.51.100.0/24"],
            "hosts": [{"address": "198.51.100.5", "platform": "linux", "transport": "ssh"}],
        }
        options, _ = _ssh_base(deployment_plan(inventory)[0])
        self.assertIn("StrictHostKeyChecking=yes", options)

    def test_ssh_deployment_is_rollback_guarded_and_post_verified(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "sentinel-blue.pyz"
            package.write_bytes(b"runtime")
            inventory = {
                "authorized_networks": ["198.51.100.0/24"],
                "hosts": [{"address": "198.51.100.5", "platform": "linux", "transport": "ssh"}],
            }
            attach_live_test_profile(inventory, Path(directory))
            with patch("sentinel_blue.launcher._run", return_value="") as run_command:
                result = _deploy_ssh(
                    deployment_plan(inventory)[0], package, "a" * 64,
                    "https://198.51.100.2:8765", "b" * 48,
                    inventory["authorized_networks"],
                )
            remote = run_command.call_args_list[-1].args[0][-1]
            self.assertIn("sentinel-blue-rollback", remote)
            self.assertIn("trap", remote)
            self.assertIn("systemctl is-active --quiet", remote)
            self.assertIn("try-restart sentinel-blue.service", remote)
            self.assertIn("--ca-file /var/lib/sentinel-blue/controller-ca.crt", remote)
            self.assertTrue(
                any(
                    command[0] == "scp" and "controller-ca.crt" in command[-2]
                    for command in (call.args[0] for call in run_command.call_args_list)
                )
            )
            self.assertTrue(result["verified"])

    def test_local_execution_stages_verified_package(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "sentinel-blue.pyz"
            write_runtime_package(package)
            destination = Path(directory) / "installed"
            inventory = {
                "authorized_networks": ["127.0.0.0/8"],
                "hosts": [
                    {
                        "name": "local-test",
                        "address": "127.0.0.1",
                        "platform": "linux",
                        "transport": "local",
                        "install_directory": str(destination),
                    }
                ],
            }
            attach_live_test_profile(inventory, Path(directory))
            plan = deployment_plan(inventory)
            result = execute_plan(
                plan, inventory, package, None, "http://127.0.0.1:8765", "a" * 32
            )
            self.assertEqual(result[0]["status"], "staged")
            self.assertTrue((destination / "sentinel-blue.pyz").exists())
            self.assertEqual(
                (destination / "controller-ca.crt").read_bytes(),
                b"launcher fixture public controller trust anchor",
            )

    def test_local_execution_transfers_verified_probe_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "sentinel-blue.pyz"
            write_runtime_package(package)
            probes = root / "probes.json"
            probes.write_text('{"protected_paths":["/etc/test.conf"],"probes":[]}', encoding="utf-8")
            destination = root / "installed"
            inventory = {
                "authorized_networks": ["127.0.0.0/8"],
                "hosts": [
                    {
                        "name": "local-test",
                        "address": "127.0.0.1",
                        "platform": "linux",
                        "transport": "local",
                        "install_directory": str(destination),
                        "probe_config": str(probes),
                    }
                ],
            }
            attach_live_test_profile(inventory, root)
            result = execute_plan(
                deployment_plan(inventory), inventory, package, None,
                "http://127.0.0.1:8765", "a" * 32,
            )[0]
            self.assertEqual(Path(result["probe_config"]).read_text(encoding="utf-8"), probes.read_text(encoding="utf-8"))

    def test_non_mutating_preflight_finds_configuration_blockers(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "sentinel-blue.pyz"
            write_runtime_package(package)
            inventory = {
                "authorized_networks": ["127.0.0.0/8"],
                "hosts": [
                    {
                        "address": "127.0.0.1",
                        "platform": "linux",
                        "transport": "local",
                        "probe_config": str(root / "missing.json"),
                    }
                ],
            }
            report = deployment_preflight(
                deployment_plan(inventory), package, "0" * 64,
                "http://127.0.0.1:8765",
            )
            self.assertFalse(report["ready"])
            self.assertTrue(report["global_blockers"])
            self.assertTrue(report["hosts"][0]["blockers"])

    def test_runtime_validation_rejects_traversal_and_incomplete_archives(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            traversal = root / "traversal.pyz"
            with zipfile.ZipFile(traversal, "w") as archive:
                archive.writestr("../escape", "bad")
            with self.assertRaisesRegex(ValueError, "unsafe"):
                validate_runtime_package(traversal)
            incomplete = root / "incomplete.pyz"
            with zipfile.ZipFile(incomplete, "w") as archive:
                archive.writestr("__main__.py", "pass")
            with self.assertRaisesRegex(ValueError, "incomplete"):
                validate_runtime_package(incomplete)

    def test_local_transaction_restores_prior_files_on_publish_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "sentinel-blue.pyz"
            write_runtime_package(package)
            destination = root / "installed"
            destination.mkdir()
            (destination / "sentinel-blue.pyz").write_bytes(b"prior-package")
            (destination / "enrollment.json").write_text("prior-token", encoding="utf-8")
            inventory = {
                "authorized_networks": ["127.0.0.0/8"],
                "hosts": [{
                    "address": "127.0.0.1", "platform": "linux", "transport": "local",
                    "install_directory": str(destination),
                }],
            }
            attach_live_test_profile(inventory, root)
            real_replace = os.replace
            calls = 0

            def fail_once(source, target):
                nonlocal calls
                calls += 1
                if calls == 4:
                    raise OSError("synthetic interrupted publish")
                return real_replace(source, target)

            checksum = hashlib.sha256(package.read_bytes()).hexdigest()
            with patch("sentinel_blue.launcher.os.replace", side_effect=fail_once):
                with self.assertRaisesRegex(OSError, "interrupted"):
                    _deploy_local(
                        deployment_plan(inventory)[0], package, checksum,
                        "http://127.0.0.1:8765", "a" * 32, inventory["authorized_networks"],
                    )
            self.assertEqual((destination / "sentinel-blue.pyz").read_bytes(), b"prior-package")
            self.assertEqual((destination / "enrollment.json").read_text(), "prior-token")

    def test_local_deployment_refuses_concurrent_or_interrupted_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "sentinel-blue.pyz"
            write_runtime_package(package)
            destination = root / "installed"
            destination.mkdir()
            (destination / ".sentinel-deploy.lock").write_text("prior deployment", encoding="utf-8")
            inventory = {
                "authorized_networks": ["127.0.0.0/8"],
                "hosts": [{
                    "address": "127.0.0.1", "platform": "linux", "transport": "local",
                    "install_directory": str(destination),
                }],
            }
            attach_live_test_profile(inventory, root)
            checksum = hashlib.sha256(package.read_bytes()).hexdigest()
            with self.assertRaisesRegex(RuntimeError, "review it before retrying"):
                _deploy_local(
                    deployment_plan(inventory)[0], package, checksum,
                    "http://127.0.0.1:8765", "a" * 32, inventory["authorized_networks"],
                )

    def test_winrm_fixture_contains_checksum_acl_cleanup_and_scheduled_agent(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / "sentinel-blue.pyz"
            package.write_bytes(b"runtime")
            inventory = {
                "authorized_networks": ["198.51.100.0/24"],
                "hosts": [
                    {"address": "198.51.100.5", "platform": "windows", "transport": "winrm"}
                ],
            }
            attach_live_test_profile(inventory, Path(directory))
            step = deployment_plan(inventory)[0]
            with (
                patch("sentinel_blue.launcher._powershell_executable", return_value="pwsh"),
                patch("sentinel_blue.launcher._run", return_value="") as run_command,
            ):
                _deploy_winrm(
                    step,
                    package,
                    "a" * 64,
                    "https://198.51.100.2:8765",
                    "b" * 48,
                    inventory["authorized_networks"],
                )
            encoded = run_command.call_args.args[0][-1]
            script = base64.b64decode(encoded).decode("utf-16le")
            self.assertIn("Get-FileHash -Algorithm SHA256", script)
            self.assertIn("icacls", script)
            self.assertIn("Remove-Item -Force", script)
            self.assertIn("Register-ScheduledTask", script)
            self.assertIn("New-ScheduledTaskSettingsSet -RestartCount 999", script)
            self.assertIn("Get-ScheduledTaskInfo", script)
            self.assertIn("--expected-package-sha256", script)
            self.assertIn("post-install checksum mismatch", script)
            self.assertIn("Export-ScheduledTask", script)
            self.assertRegex(script, r"sentinel-blue\.[0-9a-f]{16}\.incoming\.pyz")
            self.assertNotIn("sentinel-blue.incoming.pyz", script)
            self.assertIn("Sentinel Blue enrollment failed with exit code", script)
            self.assertIn("Sentinel Blue runtime check failed with exit code", script)
            self.assertIn("$retainRollback", script)
            self.assertIn(
                r"--log-file C:\ProgramData\SentinelBlue\state\agent.log",
                script,
            )
            self.assertIn("--log-max-bytes 5242880", script)
            self.assertIn("--log-backups 3", script)
            self.assertIn(
                r"--ca-file C:\ProgramData\SentinelBlue\controller-ca.crt",
                script,
            )

    def test_restoration_flags_are_emitted_only_when_inventory_enables_them(self):
        unit = _linux_unit(
            "https://198.51.100.2:8765",
            "/opt/sentinel-blue/sentinel-blue.pyz",
            "/var/lib/sentinel-blue",
            ["198.51.100.0/24"],
            False,
            True,
            300.0,
        )
        self.assertIn("--allow-restoration", unit)
        self.assertIn("WatchdogSec=300", unit)
        self.assertIn("ReadWritePaths=/var/lib/sentinel-blue", unit)
        self.assertNotIn("ProtectSystem=strict", unit)
        monitor_only = _linux_unit(
            "https://198.51.100.2:8765",
            "/opt/sentinel-blue/sentinel-blue.pyz",
            "/var/lib/sentinel-blue",
            ["198.51.100.0/24"],
            False,
            False,
            300.0,
        )
        self.assertIn("ProtectSystem=strict", monitor_only)
        inventory = {
            "authorized_networks": ["198.51.100.0/24"],
            "hosts": [
                {
                    "address": "198.51.100.5",
                    "platform": "windows",
                    "transport": "winrm",
                    "allow_restoration": True,
                }
            ],
        }
        step = deployment_plan(inventory)[0]
        with tempfile.TemporaryDirectory() as directory:
            attach_live_test_profile(inventory, Path(directory))
            step = deployment_plan(inventory)[0]
            package = Path(directory) / "sentinel-blue.pyz"
            package.write_bytes(b"runtime")
            with (
                patch("sentinel_blue.launcher._powershell_executable", return_value="pwsh"),
                patch("sentinel_blue.launcher._run", return_value="") as run_command,
            ):
                _deploy_winrm(
                    step,
                    package,
                    "a" * 64,
                    "https://198.51.100.2:8765",
                    "b" * 48,
                    inventory["authorized_networks"],
                )
            script = base64.b64decode(run_command.call_args.args[0][-1]).decode("utf-16le")
            self.assertIn("--allow-restoration", script)

    def test_winrm_fixture_transfers_probe_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "sentinel-blue.pyz"
            package.write_bytes(b"runtime")
            probes = root / "probes.json"
            probes.write_text('{"protected_paths":[],"probes":[]}', encoding="utf-8")
            inventory = {
                "authorized_networks": ["198.51.100.0/24"],
                "hosts": [
                    {
                        "address": "198.51.100.5",
                        "platform": "windows",
                        "transport": "winrm",
                        "probe_config": str(probes),
                    }
                ],
            }
            attach_live_test_profile(inventory, root)
            with (
                patch("sentinel_blue.launcher._powershell_executable", return_value="pwsh"),
                patch("sentinel_blue.launcher._run", return_value="") as run_command,
            ):
                _deploy_winrm(
                    deployment_plan(inventory)[0], package, "a" * 64,
                    "https://198.51.100.2:8765", "b" * 48,
                    inventory["authorized_networks"],
                )
            script = base64.b64decode(run_command.call_args.args[0][-1]).decode("utf-16le")
            self.assertIn("probes.json", script)
            self.assertIn("--probe-config", script)

    def test_linux_range_unit_propagates_the_explicit_range_gate(self):
        unit = _linux_unit(
            "https://198.51.100.2:8765",
            "/opt/sentinel-blue/sentinel-blue.pyz",
            "/var/lib/sentinel-blue",
            ["198.51.100.0/24"],
            False,
            False,
            300.0,
            event_profile="/var/lib/sentinel-blue/event-profile.json",
            range_deployment=True,
        )
        self.assertIn("--range-deployment", unit)

    def test_linux_unit_uses_the_staged_controller_ca(self):
        unit = _linux_unit(
            "https://198.51.100.2:8765",
            "/opt/sentinel-blue/sentinel-blue.pyz",
            "/var/lib/sentinel-blue",
            ["198.51.100.0/24"],
            False,
            False,
            300.0,
            ca_file="/var/lib/sentinel-blue/controller-ca.crt",
        )
        self.assertIn("--ca-file /var/lib/sentinel-blue/controller-ca.crt", unit)

    def test_range_launcher_cli_propagates_gate_to_linux_and_windows_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            package = root / "sentinel-blue.pyz"
            write_runtime_package(package)
            checksum = hashlib.sha256(package.read_bytes()).hexdigest()
            inventory = {
                "authorized_networks": ["198.51.100.0/24"],
                "hosts": [
                    {
                        "agent_id": "linux-range-agent",
                        "address": "198.51.100.5",
                        "platform": "linux",
                        "transport": "ssh",
                    },
                    {
                        "agent_id": "windows-range-agent",
                        "address": "198.51.100.6",
                        "platform": "windows",
                        "transport": "winrm",
                    },
                ],
            }
            inventory_path = root / "inventory.json"
            inventory_path.write_text(json.dumps(inventory), encoding="utf-8")
            profile_path = write_range_test_profile(inventory, root, checksum)
            base_arguments = [
                "launcher",
                "--inventory",
                str(inventory_path),
                "--event-profile",
                str(profile_path),
                "--package",
                str(package),
                "--controller",
                "https://198.51.100.2:8765",
                "--ca-file",
                str(root / "controller-ca.crt"),
                "--token",
                "b" * 48,
                "--execute",
                "--yes",
            ]
            with self.assertRaisesRegex(ValueError, "disposable range"):
                run_launcher(cli_parser().parse_args(base_arguments))

            commands = []
            linux_units = []

            def capture_command(command, timeout=120.0):
                commands.append(command)
                if command and command[0] == "scp":
                    for argument in command:
                        candidate = Path(argument)
                        if candidate.name == "sentinel-blue.service" and candidate.is_file():
                            linux_units.append(candidate.read_text(encoding="utf-8"))
                return ""

            with (
                patch("sentinel_blue.launcher._powershell_executable", return_value="pwsh"),
                patch("sentinel_blue.launcher._run", side_effect=capture_command),
                patch("sentinel_blue.config_validation.ssl.create_default_context"),
                patch("builtins.print"),
            ):
                run_launcher(
                    cli_parser().parse_args(base_arguments + ["--range-deployment"])
                )

            self.assertTrue(linux_units)
            self.assertTrue(
                any("--range-deployment" in unit for unit in linux_units)
            )
            self.assertTrue(
                any("--agent-id linux-range-agent" in unit for unit in linux_units)
            )
            ssh_commands = [
                command for command in commands if command and command[0] == "ssh"
            ]
            self.assertEqual(len(ssh_commands), 1)
            self.assertIn("--range-deployment", ssh_commands[0][-1])
            self.assertIn("--agent-id linux-range-agent", ssh_commands[0][-1])
            powershell_commands = [
                command for command in commands if command and command[0] == "pwsh"
            ]
            self.assertEqual(len(powershell_commands), 1)
            script = base64.b64decode(powershell_commands[0][-1]).decode("utf-16le")
            self.assertGreaterEqual(script.count("--range-deployment"), 2)
            self.assertGreaterEqual(script.count("--agent-id 'windows-range-agent'"), 2)


if __name__ == "__main__":
    unittest.main()
