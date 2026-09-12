import copy
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from sentinel_blue.competition_catalog import bind_catalog, catalog_rows, matches_requirement
from sentinel_blue.opening import OpeningRunner, assess_defender, compile_opening
from sentinel_blue import __version__
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.protocol import ProbeResult
from sentinel_blue.setup import compile_plan, plan_digest
from sentinel_blue.state import write_private_json
from tests.test_setup import fixture, FixtureTransport


class CompetitionCatalogTests(unittest.TestCase):
    def test_complete_catalog_compiles_with_real_file_bindings_and_detects_runtime_change(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory, profile = fixture(root, hosts=1)
            runtime = root / "package.pyz"
            runtime.write_bytes(b"plan compilation only; never executed")
            ca = root / "ca.pem"
            ca.write_text('-----BEGIN CERTIFICATE-----\nMIIDmjCCAoKgAwIBAgIUaK3ztqKeEWNijT5wiW+c+Fi7ILMwDQYJKoZIhvcNAQEL\nBQAwZTELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM\nDVNhbiBGcmFuY2lzY28xFDASBgNVBAoMC09wZW5BSSwgTExDMRMwEQYDVQQDDApv\ncGVuYWkuY29tMB4XDTI0MTIwMzIxNDYyM1oXDTM0MTIwMTIxNDYyM1owZTELMAkG\nA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFu\nY2lzY28xFDASBgNVBAoMC09wZW5BSSwgTExDMRMwEQYDVQQDDApvcGVuYWkuY29t\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvgkSpVwR/F09gwBIz7XE\ncoOAoFhNFVK1byj1fkmhnrIY7TyWZDDllCCJyJjFzMtgnH2U83ZHnbnrZBfQpsJ7\n3gxS+k7J9A8aoNAiur9UT2+AX7Z2MNss6tmWjYtZW5R7y74vkoP5lcN5roscvNRU\n15tjoMcejDp2S8oE8/AfirtlSPz1/nmixoGDuRFZh41nboennrr+l4jom6QZEKo9\nZhghDpun51XS1ddbs2H6sDyP+K1MTWW20cVchJZUdOGHgiLlf2zKXR8J2hRDZ0DA\nNcmViO+yoliXUEazKZJGEdkO+E7YY4pL3ERA1O3p5TMmwMSceuON5xunktIxbkDV\nhQIDAQABo0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNV\nHQ4EFgQUMSKHNgbzazg8+Y6I+s+tmTvqUkYwDQYJKoZIhvcNAQELBQADggEBADr6\n+X8qvvGMDPbfIaa9hHcRWv7IUQWdbu/0hihYesk1aiKCUAT7rJyXe3qHjqwz77XT\niWuawsr6kfMtAv97jXHWWQxJL6v58Ell3Ec9vsCvEI7Sgpi3HSLfOC7rfAJMjbit\nOo8f4COgVwp+6vHpifpyIu45mfoeVgbIL/4IjT7+CgxxIsbKcvUl6BDIOcqA+MDo\nruluqr2yksYlW1mZbrrg4u1o0dyMe60AGmQsTFlb1bXna4U0mjErAJ/X+SeIHpf4\nq26sVqpTT8H4sGANN+04f812FH5cbuiheLa31qFrBzQC7ULHhleE/dAi9EoPtGxz\nihzqGdsPyRa+Q4LcTxc=\n-----END CERTIFICATE-----\n')
            raw = copy.deepcopy(profile.raw)
            raw["release"] = {"version": __version__, "sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
                "controller_ca_sha256": hashlib.sha256(ca.read_bytes()).hexdigest(), "cloud_processing": False,
                "external_telemetry_export": False}
            probes = {
                "icmp": {"kind": "icmp"},
                "ssh-login": {"kind": "ssh-login", "username": "scorer", "known_hosts_file": "/private/known_hosts", "password_file": "/private/password"},
                "smb-login": {"kind": "smb", "operation": "login", "username": "scorer", "share": "score", "password_file": "/private/password"},
                "smb-read": {"kind": "smb", "operation": "read", "username": "scorer", "share": "score", "password_file": "/private/password", "path": "read.txt", "expected_sha256": "b" * 64},
                "smb-write": {"kind": "smb", "operation": "write", "username": "scorer", "share": "score", "password_file": "/private/password", "directory": "probes", "allow_write": True},
                "http-content": {"kind": "http", "target": "http://127.0.0.1/", "expected_body": "score", "expected_status": [200]},
                "https": {"kind": "https", "target": "https://127.0.0.1/", "verify": True},
                "sql": {"kind": "postgres", "username": "scorer", "database": "score", "password_file": "/private/password"},
                "dns-forward": {"kind": "dns", "query": "www.score.test", "record_type": "A", "expected_answers": ["127.0.0.1"]},
                "dns-update": {"kind": "dns-update", "allow_write": True, "zone": "score.test", "prefix": "sb", "key_file": "/private/update.key", "value": "127.0.0.1"},
            }
            raw["services"][0]["expected_transactions"] = [dict({"target": "127.0.0.1"}, **probes[row["transaction"]], name=row["label"]) for row in catalog_rows("ncae")]
            profile = EventProfile.from_dict(raw)
            profile_path = root / "profile.json"
            write_private_json(profile_path, raw)
            inventory["hosts"][0].update(event_profile=str(profile_path), install_directory="/tmp/sentinel-blue-range")
            inventory["opening"] = {"catalog": "ncae", "budget_seconds": 180,
                "deployment_hosts": ["host-0"], "scoring": {row["id"]: {"task": inventory["setup"]["tasks"][0]["id"], "probe": row["label"]} for row in catalog_rows("ncae")},
                "controller": {"host": "host-0", "origin": "https://127.0.0.1:8765", "ca_file": str(ca),
                    "operator_token_file": "/private/operator", "operator_principal": "operator", "operator_epoch": 1,
                    "enrollment_token_file": "/private/enroll", "expected_mode": "range-autonomous"}}
            plan = compile_opening(inventory, profile, root, runtime, range_deployment=True)
            self.assertEqual(len(plan["scoring"]), 13)
            self.assertEqual(plan["setup"]["budget_seconds"], 180)
            self.assertEqual(plan["expected_agents"], ["host-0"])
            runtime.write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "digest"):
                compile_opening(inventory, profile, root, runtime, range_deployment=True)

    def test_both_screenshots_have_thirteen_distinct_exact_columns(self):
        ncae = catalog_rows("ncae")
        gddc = catalog_rows("gddc-ualbany")
        for rows in (ncae, gddc):
            self.assertEqual(len(rows), 13)
            self.assertEqual(len({row["id"] for row in rows}), 13)
        self.assertIn("Dynamic DNS", [row["label"] for row in ncae])
        self.assertIn("Postgres Access", [row["label"] for row in gddc])
        self.assertEqual(sum(row["transaction"] == "dns-reverse" for row in gddc), 2)

    def test_weaker_or_wrong_protocols_cannot_claim_score_coverage(self):
        for requirement in ("smb-login", "smb-write", "ssh-login", "postgres", "dns-reverse", "dns-update", "https"):
            self.assertFalse(matches_requirement(requirement, {"kind": "tcp", "port": 443}))
        self.assertFalse(matches_requirement("postgres", {"kind": "mysql", "username": "user", "database": "db", "password_file": "pass"}))
        self.assertFalse(matches_requirement("https", {"kind": "https", "target": "https://127.0.0.1", "verify": False}))
        self.assertFalse(matches_requirement("dns-reverse", {"kind": "dns", "query": "www.test", "expected_answers": ["127.0.0.1"]}))
        with self.assertRaisesRegex(ValueError, "every score column"):
            bind_catalog("gddc-ualbany", {}, {"tasks": []})


class OpeningDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inventory, self.profile = fixture(self.root, hosts=1, budget=4)
        self.inventory["hosts"][0]["event_profile"] = str(self.root / "profile.json")
        self.inventory["hosts"][0]["controller_ca_file"] = str(self.root / "ca.crt")
        self.inventory["hosts"][0]["install_directory"] = "/tmp/sentinel-blue-range"
        self.runtime = self.root / "runtime.pyz"
        self.runtime.write_bytes(b"non-executed opening control-flow fixture")
        self.token = self.root / "token"
        self.token.write_text("a" * 48)
        self.token.chmod(0o600)
        setup = compile_plan(self.inventory, self.profile, self.root)
        self.plan = {"release_version": "fixture", "runtime_sha256": "a" * 64,
                     "profile_fingerprint": self.profile.fingerprint, "catalog": "fixture",
                     "budget_seconds": 4, "setup": setup, "inventory": self.inventory,
                     "expected_agents": ["host-0"], "scoring": [{"id": "content", "label": "Content", "host": "host-0", "probe": setup["tasks"][0]["probes"][0]}],
                     "controller": {"host": "host-0", "origin": "http://127.0.0.1:8765", "expected_mode": "range-autonomous",
                                    "enrollment_token_file": str(self.token)}}
        self.transport = FixtureTransport()

    def tearDown(self):
        self.temp.cleanup()

    def snapshot(self):
        return {"controller": {"version": "fixture", "stored_json_ready": True, "database_integrity": "ok",
                "credential_migration_blockers": [], "automatic_service_recovery": True, "restoration_blockers": {},
                "governance": {"profile_fingerprint": self.profile.fingerprint, "autonomy_mode": "range-autonomous", "emergency_stopped": False, "services_confirmed": True}},
                "agents": [{"agent_id": "host-0", "enabled": True, "health": "online", "last_seen": time.time(),
                            "baseline_status": "approved", "baseline_readiness": {"ready": True}}]}

    def runner(self, *, deploy=None, dashboard=None):
        return OpeningRunner(self.plan, self.profile, self.runtime, transport=self.transport,
            probe=lambda *_a, **_kw: ProbeResult("fixture", "loopback", bool(self.transport.ready), 1),
            deploy=deploy or (lambda *_a, **_kw: [{"status": "deployed"}]),
            dashboard=dashboard or (lambda *_a: self.snapshot()))

    def test_complete_opening_includes_prior_upload_time_and_refuses_replay(self):
        started = time.time() - 0.3
        # The package bytes are deliberately not a release; only the state
        # machine is being tested here, with real journal and setup scheduling.
        with patch.object(type(self.profile), "verify_release_file"):
            result = self.runner().execute(self.root / "state", plan_digest(self.plan), started_at=started)
            self.assertEqual(result["status"], "passed", result)
            self.assertGreaterEqual(result["elapsed_seconds"], 0.3)
            self.assertTrue(result["cold_start_under_3_minutes"])
            with self.assertRaisesRegex(ValueError, "already exists"):
                self.runner().execute(self.root / "state", plan_digest(self.plan))

    def test_security_requires_unlocked_vault_before_any_deployment(self):
        self.plan['security']={'fixture':'approved security plan'}
        with self.assertRaisesRegex(ValueError,'unlocked'):
            self.runner().execute(self.root/'state',plan_digest(self.plan))
        self.assertFalse((self.root/'state').exists())

    def test_incomplete_security_blocks_activation_and_keeps_original_timer(self):
        from unittest.mock import Mock
        self.plan['security']={'fixture':'approved security plan'}
        security=Mock();security.execute.return_value={'status':'incomplete'}
        runner=self.runner();runner.security=security
        started=time.time()-0.2
        with patch.object(type(self.profile),'verify_release_file'):
            result=runner.execute(self.root/'state',plan_digest(self.plan),started_at=started)
        self.assertEqual(result['status'],'incomplete')
        security.execute.assert_called_once_with(approved_digest=plan_digest(self.plan['security']),started_at=started)
        self.assertNotIn('defense_activation',result['stages'])

    def test_late_deployment_never_resets_or_passes_deadline(self):
        self.plan["budget_seconds"] = self.plan["setup"]["budget_seconds"] = 1.0
        self.transport.ready.add("host-0")
        def late(*_args, **kwargs):
            self.assertLessEqual(kwargs["budget_seconds"], 1.0)
            time.sleep(1.05)
            return [{"status": "deployed"}]
        with patch.object(type(self.profile), "verify_release_file"):
            result = self.runner(deploy=late).execute(self.root / "state", plan_digest(self.plan))
        self.assertFalse(result["under_3_minutes"])
        self.assertEqual(result["status"], "uncertain")

    def test_agent_enrollment_after_activation_is_observed_without_redeploying(self):
        calls, deployments = [], []
        def dashboard(*_args):
            calls.append(time.monotonic())
            result = self.snapshot()
            if len(calls) == 1:
                result['agents'] = []
            return result
        def deploy(*_args, **_kwargs):
            deployments.append(True)
            return [{'status':'deployed'}]
        with patch.object(type(self.profile), 'verify_release_file'):
            result = self.runner(deploy=deploy, dashboard=dashboard).execute(
                self.root/'state', plan_digest(self.plan))
        self.assertEqual(result['status'], 'passed', result)
        self.assertEqual(result['defender']['readiness_checks'], 2)
        self.assertEqual(len(deployments), 1)

    def test_pending_defender_exhausts_same_deadline_and_retains_blockers(self):
        self.plan['budget_seconds'] = self.plan['setup']['budget_seconds'] = 0.6
        self.transport.ready.add('host-0')
        def dashboard(*_args):
            result = self.snapshot(); result['agents'] = []; return result
        with patch.object(type(self.profile), 'verify_release_file'):
            result = self.runner(dashboard=dashboard).execute(self.root/'state', plan_digest(self.plan))
        self.assertEqual(result['status'], 'uncertain')
        self.assertFalse(result['under_3_minutes'])
        self.assertTrue(result['defender']['blockers'])
        self.assertLess(result['elapsed_seconds'], 1.0)

    def test_healthy_services_with_pending_baseline_are_incomplete(self):
        def pending(*_args):
            data = self.snapshot()
            data["agents"][0]["baseline_status"] = "pending"
            return data
        with patch.object(type(self.profile), "verify_release_file"):
            result = self.runner(dashboard=pending).execute(self.root / "state", plan_digest(self.plan))
        self.assertEqual(result["status"], "uncertain")
        self.assertFalse(result["under_3_minutes"])

    def test_missing_observer_client_cannot_claim_cold_state_or_mutate(self):
        with patch.object(type(self.profile), "verify_release_file"), patch(
                "sentinel_blue.opening.dependency_readiness", return_value={"ready": False, "missing": ["psql"]}):
            result = self.runner().execute(self.root / "state", plan_digest(self.plan))
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(result.get("initial_all_scored_checks_unhealthy", False))
        self.assertEqual(self.transport.applies, [])
        self.assertEqual(result["stages"]["observer_preflight"]["result"]["missing"], ["psql"])

    def test_stale_wrong_profile_or_stopped_defender_cannot_pass(self):
        for mutation in ("stale", "profile", "stop", "missing", "partial"):
            data = self.snapshot()
            if mutation == "stale":
                data["agents"][0]["last_seen"] -= 100
            elif mutation == "profile":
                data["controller"]["governance"]["profile_fingerprint"] = "wrong"
            elif mutation == "stop":
                data["controller"]["governance"]["emergency_stopped"] = True
            elif mutation == "missing":
                data["agents"] = []
            else:
                data["agents"][0]["baseline_readiness"]["ready"] = False
            self.assertFalse(assess_defender(data, self.plan, time.time(), time.time() - 10)["ready"], mutation)
