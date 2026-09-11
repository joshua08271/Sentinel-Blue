import contextlib
import io
import json
import tempfile
import time
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from sentinel_blue.protocol import ProbeResult
from sentinel_blue.setup_transport import CommandResult
from sentinel_blue.state import write_private_json
from tools import measure_setup_acceptance as acceptance


class SetupAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plan = {"budget_seconds": 10, "uncovered_services": [],
                     "tasks": [{"service_key": ["host", "web"],
                                "probes": [{"kind": "http", "target": "http://127.0.0.1/"}]}]}
        self.profile = Mock(authorized_networks=["127.0.0.0/8"], authorized_hosts=["127.0.0.1"],
                            excluded_hosts=[], release={"sha256": "b" * 64})

    def measure(self, health, *, child_digest=None, uncertain=False, started_at=None):
        output = self.root / "report.json"
        argv = ["measure_setup_acceptance.py", "--inventory", str(self.root / "inventory.json"),
                "--runtime", str(self.root / "runtime.pyz"), "--approve-plan", "a" * 64,
                "--state-dir", str(self.root / "state"), "--output", str(output)]
        if started_at is not None:
            argv.extend(['--started-at',str(started_at)])
        def execute(command, script, seconds):
            self.assertIn("--started-at", command)
            self.assertLessEqual(float(command[command.index("--started-at") + 1]), time.time())
            self.assertLessEqual(seconds, 10)
            write_private_json(Path(command[command.index("--output") + 1]),
                               {"status": "ready", "plan_sha256": child_digest or "a" * 64})
            return CommandResult(0, 0, uncertain)
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch("sys.argv", argv))
            stack.enter_context(patch.object(acceptance, "load_inventory", return_value={}))
            stack.enter_context(patch.object(acceptance, "load_event_profile", return_value=self.profile))
            stack.enter_context(patch.object(acceptance, "compile_plan", return_value=self.plan))
            stack.enter_context(patch.object(acceptance, "plan_digest", return_value="a" * 64))
            stack.enter_context(patch.object(acceptance, "run_probe", side_effect=[
                ProbeResult("http", "loopback", healthy, 1) for healthy in health]))
            process = stack.enter_context(patch.object(acceptance, "run_process", side_effect=execute))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = acceptance.main()
        return code, json.loads(output.read_text()), process.call_count

    def test_initially_healthy_service_prevents_execution(self):
        code, report, calls = self.measure([True])
        self.assertEqual(code, 2)
        self.assertEqual(calls, 0)
        self.assertFalse(report["under_30_minutes"])

    def test_cold_to_healthy_requires_matching_plan_and_final_transaction(self):
        code, report, calls = self.measure([False, True])
        self.assertEqual(code, 0)
        self.assertEqual(calls, 1)
        self.assertTrue(report["under_30_minutes"])
        self.assertFalse(report["full_competition_readiness_proven"])

    def test_wrong_child_plan_or_unknown_completion_cannot_pass(self):
        for options in [{"child_digest": "c" * 64}, {"uncertain": True}]:
            with self.subTest(options=options):
                code, report, _ = self.measure([False, True], **options)
                self.assertEqual(code, 2)
                self.assertFalse(report["under_30_minutes"])

    def test_final_service_failure_prevents_pass(self):
        code, report, _ = self.measure([False, False])
        self.assertEqual(code, 2)
        self.assertFalse(report["under_30_minutes"])

    def test_expired_probe_budget_is_unchecked_not_proof_of_cold_state(self):
        with patch.object(acceptance, "run_probe") as probe:
            results = acceptance.service_checks(self.plan, self.profile, time.monotonic() - 1)
        self.assertFalse(results[0]["checked"])
        probe.assert_not_called()

    def test_declared_probe_budget_is_preserved_within_original_deadline(self):
        self.plan['tasks'][0]['probes'][0]['timeout'] = 5
        for remaining, maximum in ((10, 5), (2, 2)):
            with self.subTest(remaining=remaining), patch.object(acceptance, 'run_probe',
                    return_value=ProbeResult('fixture', 'loopback', True, 1)) as probe:
                result = acceptance.service_checks(self.plan, self.profile, time.monotonic()+remaining)
                applied = probe.call_args.args[0]['timeout']
                self.assertLessEqual(applied, maximum)
                self.assertGreater(applied, maximum-0.25)
                self.assertTrue(result[0]['healthy'])

    def test_missing_observer_is_not_proof_of_a_down_service(self):
        with patch.object(acceptance,'dependency_readiness',return_value={'ready':False,'missing':['Python module smbprotocol']}), \
                patch.object(acceptance,'run_probe') as probe:
            results = acceptance.service_checks(self.plan,self.profile,time.monotonic()+10)
        self.assertFalse(results[0]['checked'])
        self.assertEqual(results[0]['error'],'observer_dependencies_missing')
        probe.assert_not_called()

    def test_prior_upload_exhaustion_cannot_reset_the_opening_clock(self):
        code, report, calls = self.measure([],started_at=time.time()-11)
        self.assertEqual(code,2)
        self.assertEqual(calls,0)
        self.assertGreaterEqual(report['elapsed_seconds'],11)
        self.assertFalse(report['under_3_minutes'])

    def test_probe_exceptions_are_unchecked_and_do_not_establish_cold_state(self):
        with patch.object(acceptance, "run_probe", side_effect=RuntimeError("private diagnostic")):
            results = acceptance.service_checks(self.plan, self.profile, time.monotonic() + 10)
        self.assertFalse(results[0]["checked"])
        self.assertFalse(results[0]["healthy"])
        self.assertEqual(results[0]["error"], "RuntimeError")
        self.assertNotIn("private diagnostic", str(results))

    def test_checks_overlap_different_hosts_and_retain_inventory_order(self):
        second = {"service_key": ["second", "web"],
                  "probes": [{"kind": "http", "target": "http://127.0.0.2/"}]}
        self.plan["tasks"].append(second)
        barrier = threading.Barrier(2)

        def probe(spec, *args, **kwargs):
            barrier.wait(timeout=2)
            return ProbeResult("http", spec["target"], True, 1)

        with patch.object(acceptance, "run_probe", side_effect=probe):
            results = acceptance.service_checks(self.plan, self.profile, time.monotonic() + 10)
        self.assertEqual([row["service"] for row in results], [["host", "web"], ["second", "web"]])
        self.assertTrue(all(row["healthy"] for row in results))


if __name__ == "__main__":
    unittest.main()
