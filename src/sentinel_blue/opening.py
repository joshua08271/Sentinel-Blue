"""One reviewed competition opening: provisioning, deployment, and live readiness."""

from __future__ import annotations

import copy
import ipaddress
import json
import math
import secrets
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .competition_catalog import bind_catalog, catalog_rows
from .config_validation import validate_bound_transport
from .event_profile import load_event_profile
from .launcher import deployment_plan, execute_plan, load_inventory
from .native_probes import dependency_readiness
from .operator_auth import operator_signature
from .probes import _PinnedHTTPConnection, _PinnedHTTPSConnection, run_probe
from .request_deadline import BoundedRequestPool
from .setup import SetupRunner, _locked_state, compile_plan, plan_digest
from .setup_recipes import compile_recipe
from .setup_transport import SetupTransport
from .state import read_private_json, read_private_text, write_private_json

_READINESS_REQUESTS = BoundedRequestPool(4, label="opening readiness request",
                                       thread_name="sentinel-opening-request")


def compile_opening(inventory, profile, root, runtime, *, range_deployment=False):
    profile.require_runtime_ready(range_deployment=range_deployment)
    if not profile.allows("initial_provisioning"):
        raise ValueError("opening requires approved initial_provisioning")
    profile.verify_release_file(runtime)
    source = inventory.get("opening")
    if not isinstance(source, dict) or set(source) - {"catalog", "budget_seconds", "scoring", "controller", "deployment_hosts", "pipeline_deployment"}:
        raise ValueError("inventory requires a valid opening section")
    pipeline = source.get("pipeline_deployment", True)
    if type(pipeline) is not bool:
        raise ValueError("pipeline_deployment must be a boolean")
    budget = source.get("budget_seconds", 180)
    if type(budget) not in {int, float} or not math.isfinite(budget) or not 0 < budget <= 1800:
        raise ValueError("opening budget must be positive and at most 1800 seconds")
    setup = compile_plan(inventory, profile, root)
    if setup["uncovered_services"]:
        raise ValueError("opening requires setup coverage for every event service")
    # The setup substage consumes the same original time window.
    setup["budget_seconds"] = float(budget)
    scoring = bind_catalog(source.get("catalog"), source.get("scoring"), setup)
    controller = copy.deepcopy(source.get("controller"))
    if not isinstance(controller, dict) or set(controller) - {
        "host", "origin", "ca_file", "operator_token_file", "operator_principal", "operator_epoch",
        "enrollment_token_file", "expected_mode", "bootstrap", "activate",
    }:
        raise ValueError("opening requires a controller definition")
    if controller.get("host") not in setup["hosts"]:
        raise ValueError("opening controller host must be in the setup inventory")
    if controller.get("expected_mode") not in {"guarded-autonomous", "range-autonomous"}:
        raise ValueError("opening completion requires an explicitly approved autonomous mode")
    if controller["expected_mode"] == "range-autonomous" and not range_deployment:
        raise ValueError("range-autonomous completion requires range deployment")
    if not isinstance(controller.get("operator_principal"), str) or type(controller.get("operator_epoch")) is not int:
        raise ValueError("opening requires an operator principal and credential epoch")
    for field in ("ca_file", "operator_token_file", "enrollment_token_file"):
        raw = controller.get(field)
        if not isinstance(raw, str) or not raw:
            raise ValueError(f"opening controller requires {field}")
        path = Path(raw).expanduser()
        controller[field] = str(path if path.is_absolute() else (root / path).absolute())
    validate_bound_transport(profile, role="launcher", controller=controller.get("origin"), ca_file=controller["ca_file"])
    parsed = urlparse(controller["origin"])
    address = str(ipaddress.ip_address(parsed.hostname))
    profile.assert_target(address)
    if address != setup["hosts"][controller["host"]]["address"]:
        raise ValueError("controller origin must match its inventoried host")
    for stage in ("bootstrap", "activate"):
        if controller.get(stage) is not None:
            check, apply, _rollback = compile_recipe("runbook", controller[stage], root,
                                                   setup["hosts"][controller["host"]]["platform"])
            controller[stage] = {"check": check, "apply": apply}
    selected = source.get("deployment_hosts")
    if not isinstance(selected, list) or not selected or len(selected) != len(set(selected)):
        raise ValueError("opening requires explicit unique deployment_hosts")
    # Every Linux/Windows setup host is a required defender. An appliance adapter
    # must supply its own future readiness contract rather than being omitted.
    if set(selected) != set(setup["hosts"]):
        raise ValueError("opening must deploy Sentinel Blue to every inventoried setup host")
    deployment_inventory = copy.deepcopy(inventory)
    for host in deployment_inventory["hosts"]:
        host["event_profile"] = str(profile.source_path) if getattr(profile, "source_path", None) else host.get("event_profile")
        host["controller_ca_file"] = controller["ca_file"]
        host["range_deployment"] = range_deployment
        for field in ("key_file", "known_hosts_file", "credential_file", "probe_config", "event_profile"):
            if host.get(field):
                path = Path(host[field]).expanduser()
                host[field] = str(path if path.is_absolute() else (root / path).absolute())
    deployments = deployment_plan(deployment_inventory, event_profile=profile)
    if any(step.transport not in {"ssh", "winrm", "local"} for step in deployments):
        raise ValueError("opening requires implemented deployment transports")
    expected_agents = [step.options["agent_id"] for step in deployments]
    result = {"version": 1, "release_version": __version__, "runtime_sha256": profile.release["sha256"],
            "profile_fingerprint": profile.fingerprint, "catalog": source["catalog"], "budget_seconds": float(budget),
            "setup": setup, "scoring": scoring, "controller": controller,
            "inventory": deployment_inventory, "expected_agents": expected_agents,
            "pipeline_deployment": pipeline}
    if "security" in inventory:
        from .security_workflow import compile_security_plan
        security_inventory = copy.deepcopy(deployment_inventory)
        security_inventory["security"]["budget_seconds"] = float(budget)
        result["security"] = compile_security_plan(security_inventory, profile)
    return result


def scoring_checks(plan, profile, deadline, probe=run_probe):
    groups = {}
    for index, row in enumerate(plan["scoring"]):
        groups.setdefault(row["host"], []).append((index, row))
    def host_checks(rows):
        output = []
        for index, row in rows:
            result = {"id": row["id"], "label": row["label"], "healthy": False, "checked": False}
            remaining = deadline - time.monotonic()
            if remaining >= 0.25:
                spec = dict(row["probe"], timeout=min(float(row["probe"].get("timeout", 5)), remaining))
                try:
                    observed = probe(spec, list(profile.authorized_networks), authorized_hosts=profile.authorized_hosts,
                                     excluded_hosts=profile.excluded_hosts)
                    result.update(healthy=observed.healthy, latency_ms=observed.latency_ms,
                                  checked=time.monotonic() < deadline)
                except Exception as exc:
                    result["error"] = type(exc).__name__
            output.append((index, result))
        return output
    output = []
    with ThreadPoolExecutor(max_workers=plan["setup"]["max_parallel_hosts"]) as pool:
        for group in pool.map(host_checks, groups.values()):
            output.extend(group)
    return [row for _, row in sorted(output)]


def assess_defender(snapshot, plan, now, started_at):
    blockers = []
    controller = snapshot.get("controller", {})
    governance = controller.get("governance", {})
    if controller.get("version") != plan["release_version"]:
        blockers.append("controller release does not match")
    if governance.get("profile_fingerprint") != plan["profile_fingerprint"]:
        blockers.append("controller event binding does not match")
    if governance.get("autonomy_mode") != plan["controller"]["expected_mode"] or governance.get("emergency_stopped") is not False:
        blockers.append("approved autonomous mode is not active")
    if controller.get("stored_json_ready") is not True or controller.get("credential_migration_blockers"):
        blockers.append("controller state or credentials require review")
    if controller.get("database_integrity") != "ok" or governance.get("services_confirmed") is not True:
        blockers.append("controller database integrity or service confirmation is incomplete")
    if controller.get("automatic_service_recovery") is not True:
        blockers.append("automatic service recovery is not enabled")
    agents = {row.get("agent_id"): row for row in snapshot.get("agents", []) if isinstance(row, dict)}
    for agent_id in plan["expected_agents"]:
        row = agents.get(agent_id, {})
        seen = row.get("last_seen")
        fresh = type(seen) in {int, float} and math.isfinite(seen) and started_at <= seen <= now and now - seen < 90
        if (row.get("enabled") is not True or row.get("health") != "online" or not fresh or
                row.get("baseline_status") != "approved" or row.get("baseline_readiness", {}).get("ready") is not True or
                agent_id in controller.get("restoration_blockers", {})):
            blockers.append(f"agent {agent_id} is not freshly enrolled, complete, and baseline-approved")
    return {"ready": not blockers, "blockers": blockers, "expected_agents": plan["expected_agents"]}


def read_dashboard(plan, seconds):
    config = copy.deepcopy(plan['controller'])
    return _READINESS_REQUESTS.run(lambda budget: _read_dashboard(config, budget), seconds)


def _read_dashboard(config, budget):
    seconds = budget.remaining()
    token = read_private_text(config["operator_token_file"], 65536).strip()
    target = "/api/v1/dashboard"
    timestamp, request_id = str(int(time.time())), secrets.token_hex(16)
    signature = operator_signature(token, config["operator_principal"], config["operator_epoch"],
                                   timestamp, request_id, "GET", target, b"")
    headers = {"X-SB-Operator-Version": "1", "X-SB-Operator-Principal": config["operator_principal"],
               "X-SB-Operator-Epoch": str(config["operator_epoch"]), "X-SB-Operator-Timestamp": timestamp,
               "X-SB-Operator-Request-ID": request_id, "X-SB-Operator-Signature": signature}
    parsed = urlparse(config["origin"])
    address = str(ipaddress.ip_address(parsed.hostname))
    if parsed.scheme == "https":
        context = ssl.create_default_context(cafile=config["ca_file"])
        client = _PinnedHTTPSConnection(address, address, parsed.port or 443, seconds, context)
    else:
        if not ipaddress.ip_address(address).is_loopback:
            raise ValueError("plaintext controller checks require loopback")
        client = _PinnedHTTPConnection(address, address, parsed.port or 80, seconds)
    client._budget = budget
    response = None
    try:
        client.request("GET", target, headers=headers)
        response = client.getresponse()
        if response.status != 200:
            raise RuntimeError("authenticated controller readiness query failed")
        payload = response.read(4 * 1024 * 1024 + 1)
        if len(payload) > 4 * 1024 * 1024:
            raise ValueError("controller dashboard exceeds its response bound")
        return json.loads(payload)
    finally:
        if response is not None:
            response.close()
        client.close()


class OpeningRunner:
    def __init__(self, plan, profile, runtime, *, transport=None, probe=None, dashboard=None, deploy=None, security=None):
        self.plan, self.profile, self.runtime = plan, profile, runtime
        self.transport = transport or SetupTransport()
        self.probe = probe or run_probe
        self.dashboard = dashboard or read_dashboard
        self.deploy = deploy or execute_plan
        self.security = security

    def wait_for_defender(self, deadline, started_at):
        """Wait for fresh authenticated telemetry without replaying activation."""
        attempts = 0
        result = {"ready": False, "blockers": ["defender readiness has not been observed"],
                  "expected_agents": self.plan["expected_agents"]}
        while deadline - time.monotonic() >= 0.25:
            snapshot = self.dashboard(self.plan, min(10, deadline - time.monotonic()))
            attempts += 1
            result = assess_defender(snapshot, self.plan, time.time(), started_at)
            if result["ready"]:
                break
            # Installation/activation may finish before the first complete agent
            # report. Poll reads only; the original opening deadline still wins.
            time.sleep(min(0.25, max(0, deadline - time.monotonic())))
        return {**result, "readiness_checks": attempts}

    def execute(self, state_dir, approved, *, started_at=None):
        if self.plan.get("security") is not None and self.security is None:
            raise ValueError("the opening security stage requires an unlocked operator-side credential vault")
        clock = time.monotonic()
        now = time.time()
        start = now if started_at is None else started_at
        if type(start) not in {int, float} or not math.isfinite(start) or start <= 0 or start > now:
            raise ValueError("opening started_at must be a valid past Unix timestamp")
        deadline = clock + self.plan["budget_seconds"] - (now - start)
        if approved != plan_digest(self.plan):
            raise ValueError("opening requires the exact reviewed complete plan digest")
        if self.profile.fingerprint != self.plan["profile_fingerprint"]:
            raise ValueError("opening plan does not match this event profile")
        self.profile.verify_release_file(self.runtime)
        with _locked_state(state_dir):
            path = state_dir / "opening-state.json"
            if path.exists():
                raise ValueError("opening state already exists; inspect it before planning another run; automatic replay is refused")
            report = {"status": "running", "plan_sha256": approved, "runtime_sha256": self.plan["runtime_sha256"],
                      "catalog": self.plan["catalog"], "started_at": start, "budget_seconds": self.plan["budget_seconds"],
                      "stages": {}, "full_competition_readiness_proven": False}
            def persist():
                report["elapsed_seconds"] = round(now - start + time.monotonic() - clock, 3)
                write_private_json(path, report)
            def stage(name, operation):
                if time.monotonic() >= deadline:
                    raise TimeoutError("opening deadline exhausted")
                report["active_stage"] = name
                report["stages"][name] = {"status": "in-flight"}
                persist()  # A crash leaves durable evidence; it never permits replay.
                then = time.monotonic()
                value = operation()
                report["stages"][name] = {"seconds": round(time.monotonic() - then, 3), "result": value}
                persist()
                return value
            def controller_runbook(name):
                scripts = self.plan["controller"].get(name)
                if scripts is None:
                    return {"status": "not-configured"}
                host = self.plan["setup"]["hosts"][self.plan["controller"]["host"]]
                check = self.transport.execute(host, scripts["check"], deadline - time.monotonic())
                if check.uncertain:
                    raise TimeoutError("controller stage check was uncertain")
                if check.returncode != 0:
                    applied = self.transport.execute(host, scripts["apply"], deadline - time.monotonic())
                    if applied.uncertain:
                        raise TimeoutError("controller stage mutation was uncertain")
                    if applied.returncode != 0:
                        raise RuntimeError("controller stage failed or needs a reboot")
                    check = self.transport.execute(host, scripts["check"], deadline - time.monotonic())
                    if check.uncertain or check.returncode != 0:
                        raise RuntimeError("controller stage verification failed")
                return {"status": "verified"}
            persist()
            try:
                dependencies = stage("observer_preflight", lambda: dependency_readiness(
                    [row["probe"] for row in self.plan["scoring"]]))
                if not dependencies["ready"]:
                    raise RuntimeError("observer clients must be available before measuring service state")
                initial = stage("initial_scoring", lambda: scoring_checks(self.plan, self.profile, deadline, self.probe))
                report["initial_all_scored_checks_unhealthy"] = bool(initial) and all(x["checked"] and not x["healthy"] for x in initial)
                stage("controller_bootstrap", lambda: controller_runbook("bootstrap"))
                def deploy_agents(selected_host=None):
                    token = read_private_text(self.plan["controller"]["enrollment_token_file"], 65536).strip()
                    try:
                        token = json.loads(token)["token"]
                    except json.JSONDecodeError:
                        pass
                    steps = deployment_plan(self.plan["inventory"], event_profile=self.profile)
                    if selected_host is not None:
                        steps = [step for step in steps if step.host == selected_host]
                    if not steps:
                        raise ValueError("host has no approved deployment")
                    return self.deploy(steps,
                        self.plan["inventory"], self.runtime, self.plan["runtime_sha256"], self.plan["controller"]["origin"], token,
                        max_parallel_hosts=self.plan["setup"]["max_parallel_hosts"], budget_seconds=deadline - time.monotonic())
                local_deployment_lock = threading.Lock()
                def finish_host(name, remaining):
                    # Different loopback aliases still install onto this same OS.
                    if self.plan["setup"]["hosts"][name].get("transport") == "local":
                        with local_deployment_lock:
                            rows = deploy_agents(name)
                    else:
                        rows = deploy_agents(name)
                    completed = bool(rows) and all(row.get("status") in {"deployed", "staged"} for row in rows)
                    return {"status": "completed" if completed else "uncertain", "deployments": rows}
                pipeline = self.plan.get("pipeline_deployment", True)
                setup = stage("service_setup", lambda: SetupRunner(self.plan["setup"], self.profile,
                    transport=self.transport, probe=self.probe,
                    on_host_ready=finish_host if pipeline else None).execute(
                        state_dir / "services", plan_digest(self.plan["setup"]), started_at=start))
                if setup.get("status") != "ready":
                    if time.monotonic() >= deadline:
                        raise TimeoutError("setup or deployment exceeded the original opening deadline")
                    raise RuntimeError("service setup or host deployment did not complete")
                if pipeline:
                    deployed = [row for host in self.plan["setup"]["hosts"]
                                for row in setup["host_completions"][host].get("deployments", [])]
                    report["stages"]["upload_install_enroll"] = {
                        "overlapped_with": "service_setup", "result": deployed}
                    persist()
                else:
                    deployed = stage("upload_install_enroll", deploy_agents)
                if not deployed or any(row.get("status") not in {"deployed", "staged"} for row in deployed):
                    raise RuntimeError("not every defender deployment completed")
                if self.plan.get("security") is not None:
                    security_result = stage("security_changes", lambda: self.security.execute(
                        approved_digest=plan_digest(self.plan["security"]), started_at=start))
                    if security_result.get("status") != "completed":
                        raise RuntimeError("password rotation or persistence remediation remains incomplete")
                # Activation is an exact reviewed runbook, never an automatic
                # approval of whatever baseline a compromised host reports.
                stage("defense_activation", lambda: controller_runbook("activate"))
                defender = stage("defender_readiness", lambda: self.wait_for_defender(deadline, start))
                report["defender"] = defender
                if not defender["ready"]:
                    if deadline - time.monotonic() < 0.25:
                        raise TimeoutError("defender was not ready inside the original opening deadline")
                    raise RuntimeError("defender readiness is incomplete")
                # Waiting for enrollment must not leave us using score results
                # from before the wait. Recheck both sides of the completion gate.
                final = stage("final_scoring", lambda: scoring_checks(self.plan, self.profile, deadline, self.probe))
                if not final or not all(row["checked"] and row["healthy"] for row in final):
                    raise RuntimeError("not every scored transaction passed")
                final_defender = stage("final_defender_verification", lambda: assess_defender(
                    self.dashboard(self.plan, min(10, deadline - time.monotonic())), self.plan, time.time(), start))
                if not final_defender["ready"]:
                    report["defender"] = final_defender
                    raise RuntimeError("defender readiness changed during final scoring")
                if time.monotonic() >= deadline:
                    raise TimeoutError("completion exceeded the opening deadline")
                report["status"] = "passed"
            except Exception as exc:
                report["status"] = "uncertain" if isinstance(exc, TimeoutError) else "incomplete"
                report["error"] = type(exc).__name__
            persist()
            report["under_3_minutes"] = report["status"] == "passed" and report["elapsed_seconds"] < 180
            report["under_30_minutes"] = report["status"] == "passed" and report["elapsed_seconds"] < 1800
            report["cold_start_under_3_minutes"] = report["under_3_minutes"] and report.get("initial_all_scored_checks_unhealthy") is True
            report["clock_scope"] = "original upload/start through provisioning, controller bootstrap, agent upload/install/enrollment, approved activation, and final checks; VM creation/boot excluded"
            write_private_json(path, report)
            return report


def run(args):
    # Capture the start before reading inventories or validating the package.
    started_at = args.started_at if args.started_at is not None else time.time()
    if args.catalog:
        print(json.dumps(catalog_rows(args.catalog), indent=2))
        return 0
    if not args.inventory or not args.runtime:
        raise ValueError("opening requires --inventory and --runtime")
    inventory_path = Path(args.inventory).absolute()
    inventory = load_inventory(inventory_path)
    profile_path = Path(args.event_profile or inventory_path).absolute()
    profile = load_event_profile(profile_path)
    for host in inventory["hosts"]:
        host["event_profile"] = str(profile_path)
    runtime = Path(args.runtime).absolute()
    plan = compile_opening(inventory, profile, inventory_path.parent, runtime, range_deployment=args.range_deployment)
    if args.plan_out:
        write_private_json(args.plan_out, plan)
    if not args.execute:
        print(json.dumps({"plan_sha256": plan_digest(plan), "catalog": plan["catalog"],
                          "score_columns": len(plan["scoring"]), "budget_seconds": plan["budget_seconds"],
                          "expected_agents": plan["expected_agents"], "performance_proven": False}, indent=2))
        return 0
    if not args.state_dir:
        raise ValueError("opening execution requires a private --state-dir")
    if plan.get("security") is not None:
        import getpass
        from .credential_vault import CredentialVault
        from .security_transport import SecurityTransport
        from .security_workflow import SecurityCoordinator
        if not getattr(args, "security_vault_dir", None):
            raise ValueError("opening security changes require --security-vault-dir on the trusted operator machine")
        passphrase = getpass.getpass("Security vault passphrase: ")
        creating = not (Path(args.security_vault_dir) / "vault.json").exists()
        if creating and getpass.getpass("Confirm security vault passphrase: ") != passphrase:
            raise ValueError("vault passphrases do not match")
        with CredentialVault(args.security_vault_dir, passphrase, create=creating) as vault:
            setup_transport = SetupTransport()
            security_transport = SecurityTransport(profile, range_deployment=args.range_deployment)
            security_transport.credential_observer = setup_transport.set_management_password
            security = SecurityCoordinator(plan["security"], profile, vault, security_transport)
            report = OpeningRunner(plan, profile, runtime, transport=setup_transport, security=security).execute(
                Path(args.state_dir).absolute(), args.approve_plan, started_at=started_at)
    else:
        report = OpeningRunner(plan, profile, runtime).execute(Path(args.state_dir).absolute(), args.approve_plan, started_at=started_at)
    if args.output:
        write_private_json(args.output, report)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 2
