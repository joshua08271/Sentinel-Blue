"""Measure an approved cold setup from a real network controller, including Azure.

This tool does not fabricate a down state or reset VMs. It verifies that every
declared service's transactions fail before starting the exact packaged setup
command. Use a disposable range and its reviewed inventory. A successful report
is a result for those hosts/services only, not for an arbitrary competition.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sentinel_blue.event_profile import load_event_profile
from sentinel_blue.launcher import load_inventory
from sentinel_blue.native_probes import dependency_readiness
from sentinel_blue.probes import run_probe
from sentinel_blue.setup import compile_plan, plan_digest
from sentinel_blue.setup_transport import run_process
from sentinel_blue.state import read_private_json, write_private_json


def runtime_command(runtime, arguments):
    if os.name != "nt":
        return [sys.executable, str(runtime), *arguments]
    # The already-installed Windows embeddable Python ignores PYTHONPATH.
    # Carry this verified caller's explicit observer dependency directories to
    # the packaged child without changing its interpreter or global packages.
    paths = [str(runtime), *[str(Path(path).absolute()) for path in sys.path if path]]
    code = "import json,runpy,sys; sys.path[:0]=json.loads(sys.argv[1]); sys.argv=sys.argv[2:]; runpy.run_path(sys.argv[0],run_name='__main__')"
    return [sys.executable, "-c", code, json.dumps(paths), str(runtime), *arguments]


def service_checks(plan, profile, deadline):
    groups = {}
    for index, task in enumerate(plan["tasks"]):
        if task["service_key"]:
            groups.setdefault(task.get("host", task["service_key"][0]), []).append((index, task))

    def check_host(tasks):
        results = []
        for index, task in tasks:
            dependencies = dependency_readiness(task['probes'])
            if not dependencies['ready']:
                results.append((index, {'service': task['service_key'], 'checked': False,
                    'healthy': False, 'checks': [], 'error': 'observer_dependencies_missing',
                    'missing': dependencies['missing']}))
                continue
            probes = []
            error = None
            for source in task["probes"]:
                remaining = deadline - time.monotonic()
                if remaining < 0.25:
                    break
                spec = dict(source)
                spec["timeout"] = min(float(spec.get("timeout", 3)), remaining)
                try:
                    probes.append(run_probe(spec, list(profile.authorized_networks),
                                            authorized_hosts=profile.authorized_hosts,
                                            excluded_hosts=profile.excluded_hosts))
                except Exception as exc:
                    error = type(exc).__name__
                    break
            checked = bool(probes) and len(probes) == len(task["probes"]) and time.monotonic() < deadline
            record = {"service": task["service_key"], "checked": checked,
                      "healthy": checked and all(row.healthy for row in probes),
                      "checks": [{"kind": task["probes"][position]["kind"],
                                  "operation": task['probes'][position].get('operation'),
                                  "failure_category": (None if row.healthy else
                                      'timeout' if any(word in row.detail.casefold() for word in ('deadline', 'timed out')) else 'probe_failed'),
                                  "healthy": row.healthy, "latency_ms": row.latency_ms}
                                 for position, row in enumerate(probes)]}
            if error:
                record["error"] = error
            results.append((index, record))
        return results

    results = []
    with ThreadPoolExecutor(max_workers=plan.get("max_parallel_hosts", 4)) as pool:
        futures = [pool.submit(check_host, tasks) for tasks in groups.values()]
        for future in futures:
            results.extend(future.result())
    return [record for _, record in sorted(results)]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--event-profile", type=Path)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--approve-plan", required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--started-at", type=float)
    args = parser.parse_args()
    inventory = load_inventory(args.inventory)
    profile_path = args.event_profile or args.inventory
    profile = load_event_profile(profile_path)
    profile.require_range_ready()
    profile.verify_release_file(args.runtime)
    plan = compile_plan(inventory, profile, args.inventory.absolute().parent)
    if plan_digest(plan) != args.approve_plan:
        raise ValueError("acceptance measurement requires the exact reviewed setup plan")
    if plan["uncovered_services"]:
        raise ValueError("acceptance measurement requires setup coverage for every service")
    now = time.time()
    started_at = now if args.started_at is None else args.started_at
    if not math.isfinite(started_at) or not 0 < started_at <= now:
        raise ValueError('acceptance start must be a finite past timestamp')
    prior_seconds = now-started_at
    clock = time.monotonic()
    deadline = clock + plan["budget_seconds"] - prior_seconds
    initial = service_checks(plan, profile, deadline)
    initial_check_seconds = round(time.monotonic()-clock,3)
    report = {"status": "incomplete", "runtime_sha256": profile.release["sha256"],
              "plan_sha256": args.approve_plan, "initial_checks": initial,
              "initial_all_services_unhealthy": bool(initial) and all(x["checked"] and not x["healthy"] for x in initial),
              "full_competition_readiness_proven": False,
              "scope": "actual inventoried hosts reached from this controller; no VM power operations"}
    report['initial_check_seconds'] = initial_check_seconds
    if not report["initial_all_services_unhealthy"]:
        report["reason"] = "cold-start condition was not established; no setup actions were executed"
    else:
        result_path = args.output.with_name(args.output.stem + ".setup.json")
        command = runtime_command(args.runtime.absolute(), ["setup", "--inventory", str(args.inventory.absolute()),
                   "--event-profile", str(profile_path.absolute()), "--execute", "--range-deployment",
                   "--approve-plan", args.approve_plan, "--state-dir", str(args.state_dir.absolute()),
                   "--started-at", str(started_at), "--output", str(result_path.absolute())])
        setup_started = time.monotonic()
        completed = run_process(command, "", max(0, deadline - time.monotonic()))
        report['setup_execute_seconds'] = round(time.monotonic()-setup_started,3)
        if result_path.exists():
            report["setup"] = read_private_json(result_path)
        final_checks_started = time.monotonic()
        report["final_checks"] = service_checks(plan, profile, deadline)
        report['final_check_seconds'] = round(time.monotonic()-final_checks_started,3)
        elapsed = prior_seconds + time.monotonic() - clock
        child = report.get("setup", {})
        if (not completed.uncertain and completed.returncode == 0 and child.get("status") == "ready" and
                child.get("plan_sha256") == args.approve_plan and
                len(report["final_checks"]) == len(initial) and bool(report["final_checks"]) and
                all(x["checked"] and x["healthy"] for x in report["final_checks"]) and elapsed < plan["budget_seconds"]):
            report["status"] = "passed"
        if completed.uncertain:
            report["reason"] = "execution did not finish inside the measured budget; review in-flight remote work"
    report["elapsed_seconds"] = round(prior_seconds + time.monotonic() - clock, 3)
    report["budget_seconds"] = plan["budget_seconds"]
    report["under_30_minutes"] = report["status"] == "passed" and report["elapsed_seconds"] < 1800
    report["under_3_minutes"] = report["status"] == "passed" and report["elapsed_seconds"] < 180
    report['seconds_before_acceptance'] = round(prior_seconds, 3)
    report["clock_scope"] = ("all elapsed time since the supplied start, initial service checks, management preflight, "
                             "provisioning, and final service checks; VM creation/boot excluded")
    write_private_json(args.output, report)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
