import hashlib
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from subprocess import CompletedProcess

from sentinel_blue.collectors import (
    _linux_interfaces,
    _linux_security_events,
    _linux_services,
    _integrity,
    _stable_firewall_digest,
    _windows_security_events,
    _windows_inventory,
    collect,
)
from sentinel_blue.validation import validate_telemetry
from sentinel_blue.protocol import FirewallState


class CollectorTests(unittest.TestCase):
    def test_windows_integrity_hashes_only_the_descriptor_from_the_open_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            errors = []
            with (
                patch("sentinel_blue.collectors._integrity_paths", return_value=[target]),
                patch(
                    "sentinel_blue.restoration._windows_read_file_snapshot_if_present",
                    return_value=(
                        b"approved",
                        {
                            "size": 8,
                            "modified_at": 1234.5,
                            "windows_security_descriptor": "binary-descriptor-base64",
                            "security_descriptor_error": "",
                        },
                    ),
                ) as snapshot,
            ):
                items = _integrity("windows", errors)
        self.assertEqual(errors, [])
        self.assertEqual(len(items), 1)
        self.assertEqual(
            items[0].security_descriptor_sha256,
            hashlib.sha256(b"binary-descriptor-base64").hexdigest(),
        )
        snapshot.assert_called_once()
        self.assertEqual(snapshot.call_args.args[0], target)
        self.assertGreater(snapshot.call_args.args[1], 0)
        self.assertTrue(snapshot.call_args.kwargs["allow_security_failure"])
        self.assertEqual(items[0].size, 8)
        self.assertEqual(items[0].modified_at, 1234.5)
        self.assertNotIn("binary-descriptor-base64", repr(items[0]))

    def test_windows_descriptor_failure_preserves_content_observation_and_blocks_readiness(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "protected.conf"
            target.write_text("approved", encoding="utf-8")
            errors = []
            with (
                patch("sentinel_blue.collectors._integrity_paths", return_value=[target]),
                patch(
                    "sentinel_blue.restoration._windows_read_file_snapshot_if_present",
                    return_value=(
                        b"approved",
                        {
                            "size": 8,
                            "modified_at": 1234.5,
                            "windows_security_descriptor": None,
                            "security_descriptor_error": "descriptor denied",
                        },
                    ),
                ),
            ):
                items = _integrity("windows", errors)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].security_descriptor_sha256, "")
        self.assertEqual(items[0].sha256, hashlib.sha256(b"approved").hexdigest())
        self.assertIn("security metadata read failed", errors[0])

    def test_windows_integrity_never_uses_path_gates_and_missing_is_not_an_error(self):
        target = Path(r"C:\safe\missing.conf")
        errors = []
        with (
            patch("sentinel_blue.collectors._integrity_paths", return_value=[target]),
            patch.object(Path, "exists", side_effect=AssertionError),
            patch.object(Path, "is_file", side_effect=AssertionError),
            patch(
                "sentinel_blue.restoration._windows_read_file_snapshot_if_present",
                return_value=None,
            ) as snapshot,
        ):
            items = _integrity("windows", errors)
        self.assertEqual(items, [])
        self.assertEqual(errors, [])
        snapshot.assert_called_once()

    def test_windows_integrity_does_not_treat_access_denied_as_absence(self):
        target = Path(r"C:\safe\denied.conf")
        errors = []
        with (
            patch("sentinel_blue.collectors._integrity_paths", return_value=[target]),
            patch.object(Path, "exists", side_effect=AssertionError),
            patch.object(Path, "is_file", side_effect=AssertionError),
            patch(
                "sentinel_blue.restoration._windows_read_file_snapshot_if_present",
                side_effect=PermissionError(5, "access denied"),
            ),
        ):
            items = _integrity("windows", errors)
        self.assertEqual(items, [])
        self.assertEqual(len(errors), 1)
        self.assertIn("integrity read failed", errors[0])
        self.assertIn("access denied", errors[0])

    def test_collector_errors_are_wire_safe_even_when_platform_output_is_hostile(self):
        hostile = "PowerShell failed: " + ("x" * 400) + "\x00"
        with (
            patch("sentinel_blue.collectors.platform.system", return_value="Windows"),
            patch(
                "sentinel_blue.collectors._windows_inventory",
                side_effect=lambda errors: (
                    errors.append(hostile)
                    or ([], [], [], [], [], [], [], [], FirewallState(False), [], [])
                ),
            ),
            patch("sentinel_blue.collectors._integrity", return_value=[]),
            patch("sentinel_blue.collectors._boot_id", return_value="boot"),
        ):
            telemetry = collect("windows-target").as_dict()
        self.assertEqual(len(telemetry["collector_errors"]), 1)
        self.assertEqual(len(telemetry["collector_errors"][0]), 256)
        self.assertNotIn("\x00", telemetry["collector_errors"][0])
        validate_telemetry(telemetry, "windows-target")

    def test_integrity_errors_are_included_before_wire_normalization(self):
        def failed_integrity(_system, errors, _paths):
            errors.append("integrity read failed: " + ("z" * 400) + "\x00")
            return []

        with (
            patch("sentinel_blue.collectors.platform.system", return_value="Windows"),
            patch(
                "sentinel_blue.collectors._windows_inventory",
                return_value=([], [], [], [], [], [], [], [], FirewallState(False), [], []),
            ),
            patch("sentinel_blue.collectors._integrity", side_effect=failed_integrity),
            patch("sentinel_blue.collectors._boot_id", return_value="boot"),
        ):
            telemetry = collect("windows-target").as_dict()
        self.assertEqual(len(telemetry["collector_errors"]), 1)
        self.assertTrue(telemetry["collector_errors"][0].startswith("integrity read failed"))
        self.assertEqual(len(telemetry["collector_errors"][0]), 256)
        validate_telemetry(telemetry, "windows-target")

    def test_service_probes_receive_the_complete_event_scope(self):
        probe_specs = [{"name": "web", "kind": "tcp", "target": "203.0.113.7"}]
        with (
            patch("sentinel_blue.collectors.platform.system", return_value="Windows"),
            patch(
                "sentinel_blue.collectors._windows_inventory",
                return_value=([], [], [], [], [], [], [], [], FirewallState(False), [], []),
            ),
            patch("sentinel_blue.collectors._integrity", return_value=[]),
            patch("sentinel_blue.collectors._boot_id", return_value="boot"),
            patch("sentinel_blue.probes.run_probes", return_value=[]) as runner,
        ):
            collect(
                "windows-target",
                probe_specs,
                ["203.0.113.0/24"],
                [],
                authorized_hosts=["203.0.113.7"],
                excluded_hosts=["203.0.113.99"],
            )
        runner.assert_called_once_with(
            probe_specs,
            ["203.0.113.0/24"],
            authorized_hosts=["203.0.113.7"],
            excluded_hosts=["203.0.113.99"],
        )

    def test_linux_interface_addresses_preserve_prefixes(self):
        rows = [
            {
                "ifname": "eth0",
                "addr_info": [
                    {"local": "192.0.2.10", "prefixlen": 24},
                    {"local": "2001:db8::10", "prefixlen": 64},
                ],
            }
        ]
        with patch("sentinel_blue.collectors._json_command", return_value=rows):
            interfaces = _linux_interfaces([])
        self.assertEqual(interfaces[0].name, "eth0")
        self.assertEqual(interfaces[0].addresses, ["192.0.2.10/24", "2001:db8::10/64"])

    def test_linux_service_start_mode_is_collected(self):
        units = CompletedProcess(
            [], 0, "web.service loaded active running Web service\n", ""
        )
        files = CompletedProcess([], 0, "web.service enabled enabled\n", "")
        details = CompletedProcess(
            [],
            0,
            "Id=web.service\nActiveState=active\nSubState=running\nUnitFileState=enabled\nNRestarts=2\nResult=success\nExecMainStatus=0\n\n",
            "",
        )
        with patch(
            "sentinel_blue.collectors._run", side_effect=[units, files, details]
        ) as runner:
            services = _linux_services([])
        self.assertIn("--full", runner.call_args_list[0].args[0])
        self.assertIn("--full", runner.call_args_list[1].args[0])
        self.assertEqual(services[0].state, "running")
        self.assertEqual(services[0].start_mode, "enabled")
        self.assertEqual(services[0].restart_count, 2)
        self.assertEqual(services[0].result, "success")

    def test_linux_empty_systemd_metadata_is_normalized_for_wire_validation(self):
        units = CompletedProcess(
            [], 0, "generated.service loaded inactive dead Generated service\n", ""
        )
        files = CompletedProcess([], 0, "", "")
        details = CompletedProcess(
            [],
            0,
            "Id=generated.service\nActiveState=inactive\nSubState=dead\n"
            "UnitFileState=\nNRestarts=0\nResult=\nExecMainStatus=0\n\n",
            "",
        )
        with patch("sentinel_blue.collectors._run", side_effect=[units, files, details]):
            service = _linux_services([])[0]
        self.assertEqual(service.start_mode, "unknown")
        self.assertEqual(service.substate, "dead")
        self.assertEqual(service.result, "success")

    def test_linux_stopped_unloaded_unit_file_remains_in_inventory(self):
        units = CompletedProcess([], 0, "", "")
        files = CompletedProcess(
            [], 0, "sentinel-example.service static -\n", ""
        )
        with patch(
            "sentinel_blue.collectors._run", side_effect=[units, files]
        ) as runner:
            services = _linux_services([])
        self.assertEqual(runner.call_count, 2)
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0].name, "sentinel-example.service")
        self.assertEqual(services[0].state, "inactive")
        self.assertEqual(services[0].substate, "dead")
        self.assertEqual(services[0].start_mode, "static")

    def test_firewall_packet_counters_do_not_change_rules_fingerprint(self):
        first = "ip saddr 198.51.100.1 counter packets 2 bytes 100 accept"
        second = "ip saddr 198.51.100.1 counter packets 900 bytes 99999 accept"
        self.assertEqual(_stable_firewall_digest(first), _stable_firewall_digest(second))

    def test_linux_security_events_extract_account_and_remote_source(self):
        row = (
            '{"MESSAGE":"Failed password for invalid user redadmin from 192.0.2.50 port 22 ssh2",'
            '"__REALTIME_TIMESTAMP":"1760000000000000","_BOOT_ID":"boot","_UID":"0",'
            '"SYSLOG_IDENTIFIER":"sshd"}\n'
        )
        completed = CompletedProcess([], 0, row, "")
        with patch("sentinel_blue.collectors._run", return_value=completed):
            events = _linux_security_events([])
        self.assertEqual(events[0].category, "auth_failure")
        self.assertEqual(events[0].account, "redadmin")
        self.assertEqual(events[0].remote_address, "192.0.2.50")

    def test_windows_security_collection_covers_control_plane_changes(self):
        with patch("sentinel_blue.collectors._windows_json", return_value=[]) as invoke:
            self.assertEqual(_windows_security_events([]), [])
        script = invoke.call_args.args[0]
        for event_id in (4698, 4702, 4719, 4726, 4735, 4946, 4950):
            self.assertIn(str(event_id), script)
        self.assertIn("scheduled_task_changed", script)
        self.assertIn("audit_policy_changed", script)
        self.assertIn("firewall_changed", script)

    def test_windows_security_collection_treats_no_matching_events_as_success(self):
        with patch("sentinel_blue.collectors._windows_json", return_value=[]) as invoke:
            self.assertEqual(_windows_security_events([]), [])
        script = invoke.call_args.args[0]
        self.assertIn("$events = @(Get-WinEvent", script)
        self.assertIn("if ($events.Count -eq 0) { exit 0 }", script)

    def test_windows_inventory_parallel_merge_is_deterministic(self):
        def collector(name, value):
            def run(errors):
                errors.append(name)
                return value

            return run

        errors = []
        with (
            patch("sentinel_blue.collectors._windows_accounts", collector("accounts", ["accounts"])),
            patch("sentinel_blue.collectors._windows_services", collector("services", ["services"])),
            patch(
                "sentinel_blue.collectors._windows_sessions",
                side_effect=lambda accounts, local: (
                    local.append("sessions") or [f"sessions:{accounts[0]}"]
                ),
            ),
            patch(
                "sentinel_blue.collectors._windows_topology",
                collector("topology", (["routes"], ["neighbors"], ["listeners"])),
            ),
            patch("sentinel_blue.collectors._windows_processes", collector("processes", ["processes"])),
            patch("sentinel_blue.collectors._windows_persistence", collector("persistence", ["persistence"])),
            patch("sentinel_blue.collectors._windows_firewall", collector("firewall", "firewall")),
            patch("sentinel_blue.collectors._windows_interfaces", collector("interfaces", ["interfaces"])),
            patch("sentinel_blue.collectors._windows_security_events", collector("events", ["events"])),
        ):
            result = _windows_inventory(errors)
        self.assertEqual(result[0], ["accounts"])
        self.assertEqual(result[1], ["sessions:accounts"])
        self.assertEqual(result[3:6], (["routes"], ["neighbors"], ["listeners"]))
        self.assertEqual(
            errors,
            [
                "accounts",
                "services",
                "sessions",
                "topology",
                "processes",
                "persistence",
                "firewall",
                "interfaces",
                "events",
            ],
        )


if __name__ == "__main__":
    unittest.main()
