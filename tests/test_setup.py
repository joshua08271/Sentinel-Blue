import copy
import hashlib
import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.event_profile import EventProfile
from sentinel_blue.protocol import ProbeResult
from sentinel_blue.setup import SetupRunner, compile_plan, plan_digest, summarize_plan
from sentinel_blue.setup_recipes import compile_recipe
from sentinel_blue.setup_transport import CommandResult, SetupTransport, powershell_environment, run_process
from sentinel_blue.state import read_private_json, write_private_json


def fixture(root, *, hosts=2, services=True, budget=10):
    raw = copy.deepcopy(EventProfile.testing().raw)
    addresses = [f"127.0.0.{x + 1}" for x in range(hosts)]
    raw["scope"]["authorized_hosts"] = addresses
    raw["scope"]["controller_ingress_hosts"] = addresses
    raw["services"] = []
    raw["services_confirmed"] = True
    inventory = {"authorized_networks": raw["scope"]["authorized_networks"], "hosts": [],
                 "setup": {"budget_seconds": budget, "max_parallel_hosts": hosts, "tasks": []}}
    for i, address in enumerate(addresses):
        name = f"host-{i}"
        inventory["hosts"].append({"name": name, "address": address, "agent_id": name,
                                   "platform": "linux", "transport": "local"})
        if services:
            raw["services"].append({
                "host": name, "service_id": "web", "protocol": "http", "port": 8080,
                "implementation": "owned fixture", "dependencies": [], "required_accounts": [],
                "required_files": [], "required_data": [], "credential_source": "",
                "expected_transactions": [{"kind": "http", "target": f"http://{address}:8080/",
                                           "expected_body": "healthy"}],
                "local_checks": [], "allowed_automatic_actions": [], "approval_actions": [],
                "backup_method": "fixture", "recovery_method": "fixture", "rollback_method": "fixture",
            })
        options = {}
        for phase in ["check", "apply"]:
            path = root / f"{name}-{phase}.sh"
            content = f"# {phase} {name}\nexit 0\n"
            # Hash and write the same bytes on Windows and Linux. Text mode
            # would insert CRLF on Windows after the LF-only hash was computed.
            path.write_bytes(content.encode("utf-8"))
            options[phase] = {"path": path.name, "sha256": hashlib.sha256(content.encode()).hexdigest()}
        task = {"id": name, "host": name, "recipe": "runbook", "options": options,
                "timeout_seconds": 5, "health_wait_seconds": 2, "estimate_seconds": 1}
        if services:
            task["service_id"] = "web"
        inventory["setup"]["tasks"].append(task)
    return inventory, EventProfile.from_dict(raw)


class FixtureTransport:
    def __init__(self):
        self.ready = set()
        self.applies = []
        self.events = []
        self.failed = set()
        self.uncertain = set()
        self.unreachable = set()
        self.delay = 0
        self.active = set()
        self.maximum_active = 0
        self.lock = threading.Lock()

    def preflight(self, host, seconds):
        return CommandResult(1 if host["name"] in self.unreachable else 0, 0)

    def execute(self, host, script, seconds):
        name = host["name"]
        if seconds <= 0:
            return CommandResult(None, 0, True)
        if script.startswith("# check"):
            self.events.append((name, "check"))
            return CommandResult(0 if name in self.ready else 10, 0)
        with self.lock:
            if name in self.active:
                raise AssertionError("concurrent mutation on the same host")
            self.active.add(name)
            self.maximum_active = max(self.maximum_active, len(self.active))
            self.applies.append(name)
            self.events.append((name, "apply"))
        time.sleep(min(self.delay, seconds))
        with self.lock:
            self.active.remove(name)
        if name in self.uncertain or self.delay > seconds:
            return CommandResult(None, min(self.delay, seconds), True)
        if name in self.failed:
            return CommandResult(20, 0)
        self.ready.add(name)
        return CommandResult(0, self.delay)


def healthy_probe(*args, **kwargs):
    return ProbeResult("fixture", "loopback", True, 1)


class SetupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inventory, self.profile = fixture(self.root)

    def tearDown(self):
        self.temp.cleanup()

    def plan(self):
        return compile_plan(self.inventory, self.profile, self.root)

    def execute(self, transport, *, resume=False, probe=healthy_probe, plan=None):
        plan = plan or self.plan()
        return SetupRunner(plan, self.profile, transport=transport, probe=probe).execute(
            self.root / "state", plan_digest(plan), resume=resume)

    def test_independent_hosts_recover_in_parallel_and_final_checks_pass(self):
        transport = FixtureTransport()
        transport.delay = 0.1
        report = self.execute(transport)
        self.assertEqual(report["status"], "ready")
        self.assertTrue(report["under_30_minutes"])
        self.assertEqual(transport.maximum_active, 2)
        self.assertEqual(len(transport.applies), 2)
        self.assertTrue(all(t["final_checks"][0]["healthy"] for t in report["tasks"].values()))

    def test_cross_host_dependency_waits_for_verified_health(self):
        self.inventory["setup"]["tasks"][1]["requires"] = ["host-0"]
        transport = FixtureTransport()
        self.execute(transport)
        self.assertEqual(transport.maximum_active, 1)
        self.assertEqual(transport.applies, ["host-0", "host-1"])
        apply_second = transport.events.index(("host-1", "apply"))
        self.assertGreaterEqual(transport.events[:apply_second].count(("host-0", "check")), 3)

    def test_failed_dependency_blocks_consumer(self):
        self.inventory["setup"]["tasks"][1]["requires"] = ["host-0"]
        transport = FixtureTransport()
        transport.failed.add("host-0")
        report = self.execute(transport)
        self.assertEqual(report["tasks"]["host-0"]["status"], "failed")
        self.assertEqual(report["tasks"]["host-1"]["status"], "blocked")
        self.assertEqual(transport.applies, ["host-0"])

    def test_unreachable_host_does_not_prevent_other_host_setup(self):
        transport = FixtureTransport()
        transport.unreachable.add("host-0")
        report = self.execute(transport)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["tasks"]["host-1"]["status"], "ready")
        self.assertEqual(transport.applies, ["host-1"])

    def test_resume_rechecks_completed_work_without_reapplying(self):
        transport = FixtureTransport()
        first = self.execute(transport)
        second = self.execute(transport, resume=True)
        self.assertEqual(second["status"], "ready")
        self.assertEqual(len(transport.applies), 2)
        self.assertGreaterEqual(second["elapsed_seconds"], first["elapsed_seconds"])

    def test_resumed_uncertain_mutation_never_replays(self):
        transport = FixtureTransport()
        transport.uncertain.add("host-0")
        first = self.execute(transport)
        transport.uncertain.clear()
        transport.ready.add("host-0")
        second = self.execute(transport, resume=True)
        self.assertEqual(first["tasks"]["host-0"]["status"], "uncertain")
        self.assertEqual(second["tasks"]["host-0"]["status"], "uncertain")
        self.assertEqual(len(transport.applies), 2)

    def test_crashed_running_stage_becomes_uncertain(self):
        transport = FixtureTransport()
        self.execute(transport)
        path = self.root / "state/setup-state.json"
        state = read_private_json(path)
        state["tasks"]["host-0"] = {"status": "running"}
        write_private_json(path, state)
        result = self.execute(transport, resume=True)
        self.assertEqual(result["tasks"]["host-0"]["status"], "uncertain")
        self.assertEqual(len(transport.applies), 2)

    def test_deadline_does_not_reset_on_resume(self):
        self.inventory["setup"]["budget_seconds"] = 0.15
        transport = FixtureTransport()
        transport.delay = 0.3
        report = self.execute(transport)
        self.assertFalse(report["under_30_minutes"])
        path = self.root / "state/setup-state.json"
        deadline = read_private_json(path)["deadline_at"]
        self.execute(transport, resume=True)
        self.assertEqual(read_private_json(path)["deadline_at"], deadline)

    def test_event_clock_includes_time_before_command_and_exhaustion_prevents_mutation(self):
        transport = FixtureTransport()
        plan = self.plan()
        started_at = time.time() - 30
        report = SetupRunner(plan, self.profile, transport=transport).execute(
            self.root / "state", plan_digest(plan), started_at=started_at)
        self.assertEqual(transport.applies, [])
        self.assertGreaterEqual(report["elapsed_seconds"], 30)
        self.assertFalse(report["under_30_minutes"])

    def test_future_or_changed_event_start_is_rejected(self):
        transport = FixtureTransport()
        plan = self.plan()
        runner = SetupRunner(plan, self.profile, transport=transport, probe=healthy_probe)
        with self.assertRaisesRegex(ValueError, "timestamp"):
            runner.execute(self.root / "state", plan_digest(plan), started_at=time.time() + 30)
        started_at = time.time() - 1
        runner.execute(self.root / "state", plan_digest(plan), started_at=started_at)
        with self.assertRaisesRegex(ValueError, "original start"):
            runner.execute(self.root / "state", plan_digest(plan), resume=True, started_at=started_at + 0.1)

    def test_uncertain_mutation_holds_even_independent_tasks_on_same_host(self):
        later = copy.deepcopy(self.inventory["setup"]["tasks"][0])
        later["id"] = "later"
        later.pop("service_id")
        self.inventory["setup"]["tasks"].append(later)
        transport = FixtureTransport()
        transport.uncertain.add("host-0")
        report = self.execute(transport)
        self.assertEqual(report["tasks"]["later"]["status"], "blocked")
        self.assertEqual(transport.applies.count("host-0"), 1)
        self.assertEqual(report["tasks"]["host-1"]["status"], "ready")

    def test_current_service_drift_prevents_resumed_success(self):
        transport = FixtureTransport()
        self.execute(transport)
        transport.ready.remove("host-0")
        report = self.execute(transport, resume=True)
        self.assertEqual(report["tasks"]["host-0"]["status"], "changed")
        self.assertEqual(len(transport.applies), 2)

    def test_final_validation_catches_later_service_loss(self):
        calls = {"count": 0}
        def probe(*args, **kwargs):
            calls["count"] += 1
            return ProbeResult("fixture", "loopback", calls["count"] <= 4, 1)
        report = self.execute(FixtureTransport(), probe=probe)
        self.assertEqual(report["status"], "incomplete")
        self.assertTrue(any(r["status"] == "changed" for r in report["tasks"].values()))

    def test_uncovered_service_prevents_completion(self):
        self.inventory["setup"]["tasks"][1].pop("service_id")
        report = self.execute(FixtureTransport())
        self.assertEqual(report["tasks_ready"], 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(report["uncovered_services"], [["host-1", "web"]])

    def test_wrong_digest_or_profile_denies_all_mutations(self):
        transport = FixtureTransport()
        plan = self.plan()
        runner = SetupRunner(plan, self.profile, transport=transport, probe=healthy_probe)
        with self.assertRaisesRegex(ValueError, "changed"):
            runner.execute(self.root / "state", "a" * 64)
        changed = copy.deepcopy(self.profile.raw)
        changed["capabilities"]["initial_provisioning"] = False
        self.profile = EventProfile.from_dict(changed)
        with self.assertRaisesRegex(ValueError, "initial_provisioning"):
            self.execute(transport)
        self.assertEqual(transport.applies, [])

    def test_cycle_missing_and_duplicate_dependencies_rejected(self):
        tasks = self.inventory["setup"]["tasks"]
        for requires in [["absent"], ["host-1"], ["host-0", "host-0"]]:
            tasks[1]["requires"] = requires
            with self.assertRaises(ValueError):
                self.plan()

    def test_scope_exclusion_and_duplicate_host_rejected(self):
        self.inventory["hosts"][0]["address"] = "192.0.2.1"
        with self.assertRaises(ValueError):
            self.plan()
        self.inventory["hosts"][0]["address"] = "127.0.0.2"
        with self.assertRaisesRegex(ValueError, "unique"):
            self.plan()

    def test_source_change_or_option_typo_cannot_silently_change_plan(self):
        self.inventory["setup"]["tasks"][0]["options"]["enablee"] = True
        with self.assertRaises(ValueError):
            self.plan()
        del self.inventory["setup"]["tasks"][0]["options"]["enablee"]
        (self.root / "host-0-apply.sh").write_text("changed", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "checksum"):
            self.plan()

    def test_summary_never_exposes_script_contents(self):
        output = json.dumps(summarize_plan(self.plan()))
        self.assertNotIn("exit 0", output)
        self.assertIn("apply_sha256", output)

    def test_deadline_cannot_be_extended_in_state(self):
        transport = FixtureTransport()
        self.execute(transport)
        path = self.root / "state/setup-state.json"
        state = read_private_json(path)
        state["deadline_at"] += 300
        write_private_json(path, state)
        with self.assertRaisesRegex(ValueError, "deadline"):
            self.execute(transport, resume=True)

    def test_ip_literal_required_for_setup_probe(self):
        raw = copy.deepcopy(self.profile.raw)
        raw["services"][0]["expected_transactions"][0]["target"] = "http://example.invalid/"
        self.profile = EventProfile.from_dict(raw)
        with self.assertRaisesRegex(ValueError, "literal"):
            self.plan()


class RecipeTests(unittest.TestCase):
    def test_windows_powershell_uses_compatible_module_environment_only_in_child(self):
        with patch.dict(os.environ, {"PSModulePath": "PS7-incompatible", "SENTINEL_TEST_ENV": "preserved"}):
            env = powershell_environment("powershell.exe")
            self.assertFalse(any(key.upper() == "PSMODULEPATH" for key in env))
            self.assertEqual(env["SENTINEL_TEST_ENV"], "preserved")
            self.assertEqual(os.environ["PSModulePath"], "PS7-incompatible")
            self.assertIsNone(powershell_environment("pwsh"))

    @unittest.skipUnless(os.name == "posix", "POSIX private command diagnostics")
    def test_command_output_is_private_and_only_hash_and_name_enter_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "logs"
            result = run_process(["bash", "-se"], "printf fixture-secret", 2, log_dir=root)
            output = root / result.output_log
            self.assertEqual(output.read_text(), "fixture-secret")
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertNotIn("fixture-secret", repr(result))
            self.assertEqual(result.output_sha256, hashlib.sha256(output.read_bytes()).hexdigest())

    def test_package_names_cannot_inject_options_or_shell_syntax(self):
        for name in ["--allow-unauthenticated", "nginx;id", "nginx\nwhoami"]:
            with self.assertRaises(ValueError):
                compile_recipe("linux-packages", {"packages": [name]}, Path("."), "linux")

    def test_cache_only_does_not_update_repositories(self):
        _, apply, _ = compile_recipe("linux-packages", {"packages": ["nginx"], "cache_only": True}, Path("."), "linux")
        self.assertIn("--no-download", apply)
        self.assertNotIn(" update", apply)
        self.assertIn("--no-remove", apply)

    def test_service_file_requires_exact_precondition(self):
        with self.assertRaisesRegex(ValueError, "previous_sha256"):
            compile_recipe("linux-service", {"service": "nginx", "files": [{"path": "/etc/nginx/nginx.conf"}]}, Path("."), "linux")

    def test_linux_scripts_parse_without_touching_native_services(self):
        if os.name != "posix":
            self.skipTest("bash syntax check")
        for recipe, options in [
            ("linux-packages", {"packages": ["nginx", "bind9"]}),
            ("linux-service", {"service": "nginx", "enable": True, "unmask": True}),
        ]:
            for script in compile_recipe(recipe, options, Path("."), "linux")[:2]:
                self.assertEqual(run_process(["bash", "-n"], script, 2).returncode, 0)

    def test_local_transport_refuses_wrong_host_or_platform(self):
        transport = SetupTransport()
        with self.assertRaisesRegex(ValueError, "loopback"):
            transport.execute({"transport": "local", "platform": "linux", "address": "192.0.2.1"}, "exit 0", 1)

    @unittest.skipUnless(os.name == "posix", "POSIX owned-process deadline")
    def test_process_deadline_kills_owned_sleep_and_redacts_output(self):
        result = run_process(["bash", "-se"], "printf secret-value\nsleep 10\n", 0.1)
        self.assertTrue(result.uncertain)
        self.assertLess(result.seconds, 3)
        self.assertEqual(result.output_sha256, hashlib.sha256(b"secret-value").hexdigest())


if __name__ == "__main__":
    unittest.main()
