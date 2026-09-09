"""Measure an approved cold setup from a real network controller, including Azure.

This tool does not fabricate a down state or reset VMs. It verifies that every
declared service's transactions fail before starting the exact packaged setup
command. Use a disposable range and its reviewed inventory. A successful report
is a result for those hosts/services only, not for an arbitrary competition.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from sentinel_blue.event_profile import load_event_profile
from sentinel_blue.launcher import load_inventory
from sentinel_blue.probes import run_probe
from sentinel_blue.setup import compile_plan, plan_digest
from sentinel_blue.setup_transport import run_process
from sentinel_blue.state import read_private_json, write_private_json


def service_checks(plan, profile, deadline):
    results = []
    for task in plan["tasks"]:
        if task["service_key"]:
            probes = []
            for source in task["probes"]:
                remaining = deadline - time.monotonic()
                if remaining < 0.25:
                    break
                spec = dict(source)
                spec["timeout"] = min(float(spec.get("timeout", 3)), 3, remaining)
                probes.append(run_probe(spec, list(profile.authorized_networks),
                                        authorized_hosts=profile.authorized_hosts,
                                        excluded_hosts=profile.excluded_hosts))
            results.append({"service": task["service_key"],
                            "checked": len(probes) == len(task["probes"]) and bool(probes),
                            "healthy": bool(probes) and len(probes) == len(task["probes"]) and all(row.healthy for row in probes),
                            "checks": [{"healthy": row.healthy, "latency_ms": row.latency_ms} for row in probes]})
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--event-profile", type=Path)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--approve-plan", required=True)
    parser.add_argument("--state-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
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
    started_at = time.time()
    clock = time.monotonic()
    deadline = clock + plan["budget_seconds"]
    initial = service_checks(plan, profile, deadline)
    report = {"status": "incomplete", "runtime_sha256": profile.release["sha256"],
              "plan_sha256": args.approve_plan, "initial_checks": initial,
              "initial_all_services_unhealthy": bool(initial) and all(x["checked"] and not x["healthy"] for x in initial),
              "full_competition_readiness_proven": False,
              "scope": "actual inventoried hosts reached from this controller; no VM power operations"}
    if not report["initial_all_services_unhealthy"]:
        report["reason"] = "cold-start condition was not established; no setup actions were executed"
    else:
        result_path = args.output.with_name(args.output.stem + ".setup.json")
        command = [sys.executable, str(args.runtime.absolute()), "setup", "--inventory", str(args.inventory.absolute()),
                   "--event-profile", str(profile_path.absolute()), "--execute", "--range-deployment",
                   "--approve-plan", args.approve_plan, "--state-dir", str(args.state_dir.absolute()),
                   "--started-at", str(started_at), "--output", str(result_path.absolute())]
        completed = run_process(command, "", max(0, deadline - time.monotonic()))
        if result_path.exists():
            report["setup"] = read_private_json(result_path)
        report["final_checks"] = service_checks(plan, profile, deadline)
        elapsed = time.monotonic() - clock
        child = report.get("setup", {})
        if (not completed.uncertain and completed.returncode == 0 and child.get("status") == "ready" and
                child.get("plan_sha256") == args.approve_plan and
                all(x["healthy"] for x in report["final_checks"]) and elapsed < plan["budget_seconds"]):
            report["status"] = "passed"
        if completed.uncertain:
            report["reason"] = "execution did not finish inside the measured budget; review in-flight remote work"
    report["elapsed_seconds"] = round(time.monotonic() - clock, 3)
    report["budget_seconds"] = plan["budget_seconds"]
    report["under_30_minutes"] = report["status"] == "passed" and report["elapsed_seconds"] < 1800
    write_private_json(args.output, report)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
