"""Measure isolated application setup on either authorized Azure target VM.

This is guest-local service acceptance. It does not exercise a Linux controller
managing Windows, change existing Sentinel deployments, or prove an event-wide
setup. The caller starts the exact lab privately and restores its power/network.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import gzip
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


def setup_state_diagnostic(root: Path) -> dict:
    """Retain bounded task timing evidence even when the setup child times out."""
    from sentinel_blue.state import read_private_json
    path = root/'state/setup-state.json'
    if not path.exists():
        return {'available':False}
    try:
        state=read_private_json(path,maximum=2*1024*1024)
        tasks=state.get('tasks',{})
        if not isinstance(tasks,dict) or len(tasks)>32:
            raise ValueError('Unexpected owned setup task inventory')
        records={}
        for name,row in tasks.items():
            if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}',name) or not isinstance(row,dict):
                raise ValueError('Invalid owned setup task identity')
            status=row.get('status')
            if status not in {'pending','running','ready','failed','uncertain','deadline','blocked','changed','reboot-required'}:
                raise ValueError('Invalid persisted setup status')
            entry={'persisted_status':status}
            for key in ('seconds','initial_check_seconds','health_check_seconds'):
                if key in row:
                    value=row[key]
                    if type(value) not in (int,float) or not math.isfinite(value) or value<0:
                        raise ValueError('Invalid setup timing')
                    entry[key]=value
            records[name]=entry
        return {'available':True,'source':'persisted task state after setup returned',
                'not_a_completion_proof':True,'tasks':records}
    except (OSError,TypeError,ValueError,AttributeError) as exc:
        return {'available':False,'error_type':type(exc).__name__}


def validate_guest(expected: str) -> dict:
    pattern = (r"/subscriptions/[0-9a-fA-F-]{36}/resourceGroups/sentinel-blue-range-wus2"
               r"/providers/Microsoft.Compute/virtualMachines/(sb-linux-target|sb-windows-target)")
    if not re.fullmatch(pattern, expected, re.IGNORECASE):
        raise ValueError("Only the two existing Azure lab target VMs are permitted")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        "http://169.254.169.254/metadata/instance?api-version=2021-02-01", headers={"Metadata": "true"})
    with opener.open(request, timeout=5) as response:
        metadata = json.loads(response.read(256 * 1024))
    compute = metadata["compute"]
    if compute.get("resourceId", "").casefold() != expected.casefold():
        raise ValueError("Azure guest resource identity does not match the reviewed target")
    windows = expected.casefold().endswith("/sb-windows-target")
    if (os.name == "nt") != windows or compute.get("osType") != ("Windows" if windows else "Linux"):
        raise ValueError("Azure guest OS mismatch")
    if sys.version_info < (3, 11):
        raise ValueError("Python 3.11+ is required")
    if os.name == "posix":
        if os.geteuid() != 0 or Path("/run/systemd/system").is_dir() is False:
            raise ValueError("Native Azure Linux service setup requires root and systemd")
        release = Path("/etc/os-release").read_text()
        if 'VERSION_ID="24.04"' not in release or not re.search(r'^ID=ubuntu$', release, re.MULTILINE):
            raise ValueError("This fixture requires the reviewed Ubuntu 24.04 target")
    else:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
            raise ValueError("Native Azure Windows setup requires administrator access")
    return {"platform": compute["osType"], "size": compute.get("vmSize"),
            "scope_verified": True}


def overlap_defender_preparation():
    """Avoid competing with ServerManager on a single-core Windows guest."""
    return os.name == 'nt' and (os.cpu_count() or 1) > 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--expected-resource-id", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--with-defender", action='store_true')
    parser.add_argument('--security-fixture',action='store_true')
    parser.add_argument('--budget-seconds',type=int,default=180)
    args = parser.parse_args()
    if not 30 <= args.budget_seconds <= 1800:
        parser.error('--budget-seconds must be 30..1800')
    opening_started = float(os.environ.get('SENTINEL_OPENING_STARTED_AT',time.time()))
    phase_seconds = {'guest_entered':round(time.time()-opening_started,3)}
    defender = None
    preparation_pool = None
    preparation = None
    guest = validate_guest(args.expected_resource_id)
    runtime = args.runtime.resolve(strict=True)
    prefix = "SentinelAzureSetup-" if os.name == "nt" else "sentinel-azure-setup-"
    for prior in runtime.parent.parent.glob(prefix + "*"):
        if prior == runtime.parent or not any(prior.glob("inputs-*")):
            continue
        previous = prior / "result.json"
        if not previous.is_file() or not json.loads(previous.read_text()).get("cleanup", {}).get("verified"):
            raise RuntimeError("A previous owned setup fixture has unverified cleanup; inspect it before another run")
    sys.path.insert(0, str(runtime))
    # The existing Windows embeddable interpreter omits the working directory
    # from its module path. Add only this verified, private staging package.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from sentinel_blue import __version__
    from sentinel_blue.event_profile import EventProfile
    from sentinel_blue.setup import compile_plan, plan_digest
    from sentinel_blue.state import read_private_json, write_private_json
    from tools import measure_setup_acceptance
    from tools.setup_native_inputs import profile_inventory
    from tools.competition_native_inputs import linux_competition_inputs, windows_competition_inputs

    root = args.output.absolute().parent / ("inputs-" + uuid.uuid4().hex[:10])
    root.mkdir(mode=0o700)
    builder = windows_competition_inputs if os.name == "nt" else linux_competition_inputs
    services, secrets, cleanup = [], [], None
    report = {"status": "failed", "version": __version__, "guest": guest,
              "runtime_sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
              "scope": "owned native service instances on one actual Azure target; guest-local checks",
              "initial_packages_or_features": [],
              "initial_scored_service_state": "owned service instances, website, or DNS zone absent",
              "existing_windows_base_services_stopped_for_fixture": False,
              "full_network_setup_test_executed": False, "full_competition_readiness_proven": False}
    report['opening_clock_scope'] = (
        'provider dispatch plus private staging; VM boot and browser upload excluded'
        if 'SENTINEL_OPENING_STARTED_AT' in os.environ else
        'guest entry to readiness; payload transfer and prior bootstrap dependencies excluded')
    report['setup_phase_seconds_from_original_start'] = phase_seconds
    try:
        tasks, services, initial, identities, cleanup, secrets = builder(root, root.name.removeprefix("inputs-"))
        report['initial_packages_or_features'] = initial
        phase_seconds['fixture_inputs_ready'] = round(time.time()-opening_started,3)
        from tools.competition_native_inputs import prepare_opening_observer
        if not args.with_defender:
            opening_started = time.time()
        budget = args.budget_seconds if args.with_defender else 1800
        report['measurement_budget_seconds'] = budget
        prepare_opening_observer(root,time.monotonic()+budget-(time.time()-opening_started))
        phase_seconds['prerequisites_ready'] = round(time.time()-opening_started,3)
        inventory = profile_inventory(runtime, tasks, services)
        if args.with_defender:
            inventory['setup']['budget_seconds'] = budget
        inventory_path = root / "inventory.json"
        write_private_json(inventory_path, inventory)
        profile = EventProfile.from_dict(inventory["event_profile"])
        plan = compile_plan(inventory, profile, root)
        acceptance_path = root / "acceptance.json"
        argv = ["measure_setup_acceptance", "--inventory", str(inventory_path), "--runtime", str(runtime),
                "--approve-plan", plan_digest(plan), "--state-dir", str(root / "state"),
                "--output", str(acceptance_path)]
        argv.extend(['--started-at',str(opening_started)])
        if args.with_defender and overlap_defender_preparation():
            from tools.native_defender_startup import NativeDefender
            defender = NativeDefender(root/'defender',runtime,inventory,started_at=opening_started,budget=budget)
            # Controller/package paths are private and disjoint from the owned
            # service fixtures. Agent collection and baseline approval still wait
            # for successful service setup, using the same original deadline.
            preparation_pool = ThreadPoolExecutor(max_workers=1)
            preparation = preparation_pool.submit(defender.prepare)
        saved = sys.argv
        try:
            sys.argv = argv
            with (root / "acceptance-console.txt").open("w") as stream, contextlib.redirect_stdout(stream):
                code = measure_setup_acceptance.main()
        finally:
            sys.argv = saved
        report["acceptance"] = read_private_json(acceptance_path)
        if isinstance(initial, list):
            features = report['acceptance'].get('setup', {}).get('tasks', {}).get('features', {})
            # Only a successful initial feature check proves this was a warm
            # prerequisite. An absent/failed check stays unknown, not cold.
            for item in initial:
                if item.get('inventory_source') == 'setup-task-initial-check':
                    item['Installed'] = True if features.get('already_ready') is True else None
        phase_seconds['service_setup_and_checks_complete'] = round(time.time()-opening_started,3)
        if code != 0:
            raise RuntimeError("measured setup did not pass")
        if args.with_defender:
            if defender is None:
                # Linux discovers new service-unit paths after provisioning.
                from tools.native_defender_startup import NativeDefender
                defender = NativeDefender(root/'defender',runtime,inventory,started_at=opening_started,budget=budget)
            if preparation is not None:
                preparation.result(timeout=defender.remaining())
            report['defender'] = defender.start()
            report['defender']['preparation_overlapped_service_setup'] = preparation is not None
            # Recheck scored transactions after defender installation and activation.
            final = measure_setup_acceptance.service_checks(plan,profile,
                time.monotonic()+budget-(time.time()-opening_started))
            report['final_service_checks'] = final
            if not final or not all(x['checked'] and x['healthy'] for x in final):
                raise RuntimeError('scored services were not healthy after defender activation')
            from sentinel_blue.opening import assess_defender
            snapshot = defender.request('/api/v1/dashboard')
            defender.last_snapshot = snapshot
            readiness = assess_defender(snapshot,defender.plan,time.time(),opening_started)
            if not readiness['ready']:
                raise RuntimeError('defender readiness changed during final service checks')
            report['defender']['final_authenticated_readiness'] = readiness
            report['complete_opening_seconds'] = round(time.time()-opening_started,3)
            report['complete_opening_under_180_seconds'] = report['complete_opening_seconds'] < 180
            report['complete_opening_within_budget'] = report['complete_opening_seconds'] < budget
            if not report['complete_opening_within_budget']:
                raise TimeoutError('complete opening exceeded the selected measurement budget')
        if args.with_defender:
            report['status'] = 'passed'
            report['resume_scope'] = 'not repeated inside the complete-opening benchmark'
        else:
            before = identities()
            resume = measure_setup_acceptance.runtime_command(runtime, ["setup", "--inventory", str(inventory_path),
                      "--execute", "--range-deployment", "--approve-plan", plan_digest(plan),
                      "--state-dir", str(root / "state"), "--resume"])
            with (root / "resume-output.txt").open("w") as stream:
                result = subprocess.run(resume, stdout=stream, stderr=subprocess.STDOUT, timeout=180)
            after = identities()
            resumed = read_private_json(root / "state/setup-state.json").get("last_report", {})
            report["resume"] = {"returncode": result.returncode,
                                "identities_unchanged": bool(before) and before == after,
                                "failed_tasks": {name: {key: row.get(key) for key in ("status", "checks", "reason")}
                                                 for name, row in resumed.get("tasks", {}).items()
                                                 if row.get("status") != "ready"}}
            report["resume_without_service_restart"] = result.returncode == 0 and report["resume"]["identities_unchanged"]
            report["status"] = "passed" if report["resume_without_service_restart"] else "failed"
    except Exception as exc:
        report['error_type'] = type(exc).__name__
        # A builder can fail before returning its secret list or cleanup
        # contract. Preserve the failure without copying an unknown argv or
        # claiming that partial native fixture creation was rolled back.
        if cleanup is None:
            report['failure_stage'] = 'fixture_inputs'
            report['error'] = type(exc).__name__
        else:
            report["error"] = type(exc).__name__ + ": " + str(exc)
        for secret in secrets:
            report["error"] = report["error"].replace(secret, "[redacted]")
        if os.name == "nt":
            # Diagnose native SMB before removing the owned share/account. The
            # bounded worker returns only fixed messages or exception types.
            # These post-failure checks never turn a failed measurement into a pass.
            from sentinel_blue.probes import run_probe
            report["smb_probe_diagnostics"] = []
            for service in services:
                for spec in service["expected_transactions"]:
                    if spec.get("kind") != "smb":
                        continue
                    observed = run_probe(dict(spec, timeout=5), ["127.0.0.0/8"],
                                         authorized_hosts=["127.0.0.1"], excluded_hosts=[])
                    report["smb_probe_diagnostics"].append({"operation": spec["operation"],
                        "healthy": observed.healthy, "latency_ms": observed.latency_ms,
                        "detail": observed.detail[:200], "timeout_seconds": 5})
                    if spec["operation"] == "write" and not observed.healthy:
                        from tools.competition_native_inputs import diagnose_owned_windows_smb_write
                        report["smb_write_diagnostics"] = diagnose_owned_windows_smb_write(spec)
    finally:
        report['setup_task_diagnostic'] = setup_state_diagnostic(root)
        if preparation_pool is not None:
            # Never race cleanup against an in-flight private installation.
            preparation_pool.shutdown(wait=True)
        if defender is not None:
            report['windows_inventory_section_seconds'] = defender.inventory_section_seconds() if os.name == 'nt' else {}
            if report['status'] != 'passed':
                report['defender_diagnostics'] = defender.diagnostics()
            report['defender_cleanup'] = defender.close()
            if not report['defender_cleanup']['verified']:
                report['status'] = 'failed'
        else:
            report['defender_cleanup'] = {'verified': True, 'children_started': False,
                                          'scope': 'defender was not constructed'}
        try:
            report["cleanup"] = cleanup() if cleanup is not None else {
                'verified': False, 'reason': 'fixture preparation did not return a cleanup contract'}
            # Existing lab machines are retained; these are explicit package/
            # feature additions, not a promise that the VM will be destroyed.
            for key in ["distro_packages_retained_until_runner_disposal", "server_features_retained_until_runner_disposal"]:
                if key in report["cleanup"]:
                    report["cleanup"].pop(key)
                    report["cleanup"]["installed_packages_or_features_retained"] = True
        except Exception as exc:
            report["cleanup"] = {"verified": False, "error": type(exc).__name__}
        if not report["cleanup"].get("verified"):
            report["status"] = "failed"
        write_private_json(args.output, report)
    if args.with_defender and os.name == 'nt' and report.get('cleanup',{}).get('verified'):
        # Read-only native error/scope checks occur after the unchanged opening
        # timer. A failed check invalidates this run; it never grants readiness.
        try:
            from tools.windows_query_contract import verify
            report['windows_query_contract'] = verify()
            if not report['windows_query_contract']['passed']:
                report['status'] = 'failed'
        except Exception as exc:
            report['windows_query_contract'] = {'passed':False,'error_type':type(exc).__name__}
            report['status'] = 'failed'
        write_private_json(args.output, report)
    if args.security_fixture and report.get('cleanup',{}).get('verified'):
        # Attack fixtures run only after the opening timer and service/defender
        # cleanup. They cannot turn an unsuccessful opening into a pass.
        try:
            from tools.security_native_rehearsal import rehearse
            report['native_security'] = rehearse()
            if not report['native_security']['passed']:
                report['status'] = 'failed'
        except Exception as exc:
            report['native_security'] = {'passed':False,'error_type':type(exc).__name__}
            report['status'] = 'failed'
        write_private_json(args.output,report)
    measured = report.get("acceptance", {})
    setup = measured.get("setup", {})
    summary = {key: report[key] for key in ["status", "version", "guest", "runtime_sha256", "scope",
                                           "initial_packages_or_features", "cleanup"]}
    summary.update({key: measured.get(key) for key in ["elapsed_seconds", "under_30_minutes", "under_3_minutes",
                                                      "initial_all_services_unhealthy",'seconds_before_acceptance',
                                                      'initial_check_seconds','setup_execute_seconds','final_check_seconds']})
    summary["tasks"] = {name: {key: row.get(key) for key in ["status", "seconds", "already_ready"]}
                        for name, row in setup.get("tasks", {}).items()}
    summary["resume_without_service_restart"] = report.get("resume_without_service_restart", False)
    if "resume" in report:
        summary["resume"] = report["resume"]
    summary["full_network_setup_test_executed"] = False
    for key in ('defender','defender_diagnostics','defender_cleanup','complete_opening_seconds','complete_opening_under_180_seconds',
                'measurement_budget_seconds','complete_opening_within_budget','setup_phase_seconds_from_original_start',
                'final_service_checks','windows_inventory_section_seconds','windows_query_contract','error_type','failure_stage',
                'opening_clock_scope','setup_task_diagnostic'):
        if key in report:
            summary[key] = report[key]
    if report.get("error"):
        summary["error"] = report["error"]
    if "smb_probe_diagnostics" in report:
        summary["smb_probe_diagnostics"] = report["smb_probe_diagnostics"]
    if "smb_write_diagnostics" in report:
        summary["smb_write_diagnostics"] = report["smb_write_diagnostics"]
    if 'native_security' in report:
        security = report['native_security']
        summary['native_security'] = {k:security.get(k) for k in ('passed','seconds','error_type','error_sites','native_event_diagnostic','audit_policy')}
        summary['native_security']['checks'] = len(security.get('checks',{}))
        summary['native_security']['failed_checks'] = [k for k,v in security.get('checks',{}).items() if not v]
        summary['native_security']['hardening_checks'] = {k:v for k,v in security.get('checks',{}).items()
                                                       if k.startswith(('scorer_','startup_','wmi_'))}
    encoded = base64.b64encode(gzip.compress(json.dumps(summary, separators=(",", ":")).encode(), mtime=0)).decode()
    if len(encoded) > 3500:
        print('SB_SETUP_RESULT={"status":"failed","error":"guest summary exceeds transport bound; full private result retained"}', flush=True)
        return 2
    print("SB_SETUP_RESULT_GZIP=" + encoded, flush=True)
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
