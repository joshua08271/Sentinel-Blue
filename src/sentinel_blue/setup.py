"""Deadline-aware initial provisioning of an explicitly inventoried network."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import math
import os
import re
import stat
import sys
import time
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from . import __version__
from .event_profile import EventProfile, load_event_profile
from .json_codec import canonical_json_bytes
from .launcher import load_inventory
from .probes import run_probe
from .setup_recipes import compile_recipe
from .setup_transport import CommandResult, SetupTransport
from .state import read_private_json, write_private_json


PLAN_VERSION = 1
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$")
TERMINAL = {"ready", "failed", "uncertain", "blocked", "deadline", "reboot-required", "changed"}


def _identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError(f"{label} requires a simple identifier")
    return value


def _seconds(value: Any, label: str, maximum: int = 1800) -> float:
    if type(value) not in {int, float} or not math.isfinite(value) or not 0 < value <= maximum:
        raise ValueError(f"{label} must be positive and at most {maximum} seconds")
    return float(value)


def plan_digest(plan: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(plan, max_bytes=4 * 1024 * 1024)).hexdigest()


def compile_plan(inventory: dict, profile: EventProfile, root: Path) -> dict:
    """Compile literal scripts and bind every task/probe to the reviewed profile."""
    profile.assert_inventory_networks(inventory.get("authorized_networks", []))
    setup = inventory.get("setup")
    if not isinstance(setup, dict) or set(setup) - {"budget_seconds", "max_parallel_hosts", "tasks"}:
        raise ValueError("inventory requires a setup object with tasks")
    budget = _seconds(setup.get("budget_seconds", 1800), "setup budget")
    workers = setup.get("max_parallel_hosts", 4)
    if type(workers) is not int or not 1 <= workers <= 16:
        raise ValueError("max_parallel_hosts must be from 1 to 16")
    hosts = {}
    addresses = set()
    for source in inventory.get("hosts", []):
        if not isinstance(source, dict):
            raise ValueError("invalid setup host")
        name = _identifier(source.get("name"), "host name")
        address = str(ipaddress.ip_address(source.get("address")))
        if name in hosts or address in addresses:
            raise ValueError("setup host names and addresses must be unique")
        addresses.add(address)
        profile.assert_target(address)
        platform = source.get("platform")
        route = source.get("transport")
        if platform not in {"linux", "windows"}:
            raise ValueError(f"setup adapter required for host {name}: {platform}")
        if route not in {"local", "ssh", "winrm"}:
            raise ValueError(f"setup adapter required for host {name}: {route}")
        profile.assert_route(route)
        if route == "local" and not ipaddress.ip_address(address).is_loopback:
            raise ValueError("local setup requires a loopback target")
        if route == "ssh" and platform != "linux" or route == "winrm" and platform != "windows":
            raise ValueError("setup transport/platform mismatch")
        host = {key: source[key] for key in (
            "name", "address", "platform", "transport", "agent_id", "username", "key_file",
            "known_hosts_file", "accept_new_host_key", "credential_file", "port", "sudo",
        ) if key in source}
        for boolean in ("sudo", "accept_new_host_key"):
            if boolean in host and type(host[boolean]) is not bool:
                raise ValueError(f"host {boolean} must be a boolean")
        if host.get("accept_new_host_key"):
            raise ValueError("setup requires an already verified SSH host key")
        for field in ("key_file", "known_hosts_file", "credential_file"):
            if host.get(field):
                path = Path(host[field]).expanduser()
                host[field] = str(path if path.is_absolute() else (root / path).absolute())
        host["address"] = address
        hosts[name] = host
    if not hosts or len(hosts) > 64:
        raise ValueError("setup requires 1 to 64 explicitly inventoried hosts")
    raw_tasks = setup.get("tasks")
    if not isinstance(raw_tasks, list) or not raw_tasks or len(raw_tasks) > 256:
        raise ValueError("setup requires 1 to 256 tasks")
    tasks = {}
    covered = set()
    manifest_keys = {(m["host"], m["service_id"]) for m in profile.services}
    for row in raw_tasks:
        if not isinstance(row, dict) or set(row) - {
            "id", "host", "requires", "recipe", "options", "service_id", "estimate_seconds",
            "timeout_seconds", "health_wait_seconds",
        }:
            raise ValueError("invalid setup task fields")
        task_id = _identifier(row.get("id"), "task id")
        if task_id in tasks:
            raise ValueError("duplicate setup task id")
        if row.get("host") not in hosts:
            raise ValueError(f"unknown setup host for {task_id}")
        host = hosts[row["host"]]
        requires = row.get("requires", [])
        if not isinstance(requires, list) or len(requires) > 256 or len(set(requires)) != len(requires):
            raise ValueError("requires must contain unique task ids")
        requires = [_identifier(x, "dependency") for x in requires]
        recipe = row.get("recipe")
        options = row.get("options", {})
        check, apply, rollback = compile_recipe(recipe, options, root, host["platform"])
        probes = []
        service_key = None
        if row.get("service_id"):
            if recipe in {"linux-packages", "windows-features"}:
                raise ValueError("package/feature installation cannot establish service readiness")
            matches = [m for m in profile.services if m["service_id"] == row["service_id"]
                       and m["host"] in {host["address"], host.get("agent_id")}]
            if len(matches) != 1:
                raise ValueError(f"task {task_id} requires an unambiguous approved service manifest")
            manifest = matches[0]
            service_key = [manifest["host"], manifest["service_id"]]
            key = tuple(service_key)
            if key in covered:
                raise ValueError("a service can have only one final setup task")
            covered.add(key)
            if recipe in {"linux-service", "windows-service"} and options.get("service") != manifest["service_id"]:
                raise ValueError("native setup service must match its approved manifest")
            probes = json.loads(json.dumps(manifest["expected_transactions"]))
            for probe in probes:
                if probe.get("kind") not in {"http", "https", "tcp", "tls", "dns", "transaction", "ftp", "banner", "smtp"}:
                    raise ValueError("setup requires a real supported application/transport probe")
                target = probe.get("host", probe.get("target", ""))
                if probe.get("kind") in {"http", "https"}:
                    target = urlparse(probe.get("target", "")).hostname
                # Literal endpoints remain reachable before event DNS is built,
                # avoid unbounded name resolution, and cannot redirect by DNS.
                try:
                    address = str(ipaddress.ip_address(target))
                except ValueError as exc:
                    raise ValueError("setup probe endpoints must be literal scoped IP addresses") from exc
                profile.assert_target(address)
        tasks[task_id] = {
            "id": task_id, "host": row["host"], "requires": requires, "recipe": recipe,
            "check": check, "apply": apply, "rollback": rollback, "probes": probes,
            "service_key": service_key,
            "estimate_seconds": _seconds(row.get("estimate_seconds", 120), "task estimate"),
            "timeout_seconds": _seconds(row.get("timeout_seconds", 600), "task timeout"),
            "health_wait_seconds": _seconds(row.get("health_wait_seconds", 60), "health wait", 300),
        }
    order = []
    visiting = set()
    visited = set()

    def visit(name: str) -> None:
        if name not in tasks:
            raise ValueError(f"missing setup dependency: {name}")
        if name in visiting:
            raise ValueError("setup dependency cycle")
        if name in visited:
            return
        visiting.add(name)
        for dependency in tasks[name]["requires"]:
            visit(dependency)
        visiting.remove(name)
        visited.add(name)
        order.append(name)

    for task_id in tasks:
        visit(task_id)
    cost = {}
    host_cost = {name: 0.0 for name in hosts}
    for name in order:
        task = tasks[name]
        cost[name] = max((cost[x] for x in task["requires"]), default=0) + task["estimate_seconds"]
        host_cost[task["host"]] += task["estimate_seconds"]
    lower_bound = max(max(cost.values()), max(host_cost.values()), sum(host_cost.values()) / workers)
    return {
        "plan_version": PLAN_VERSION, "release_version": __version__,
        "profile_fingerprint": profile.fingerprint, "profile_id": profile.profile_id,
        "budget_seconds": budget, "max_parallel_hosts": workers,
        "estimated_lower_bound_seconds": round(lower_bound, 3),
        "estimate_within_budget": lower_bound <= budget,
        "hosts": hosts, "tasks": [tasks[x] for x in order],
        "uncovered_services": [list(x) for x in sorted(manifest_keys - covered)],
    }


def summarize_plan(plan: dict) -> dict:
    return {
        key: plan[key] for key in (
            "profile_id", "budget_seconds", "max_parallel_hosts", "estimated_lower_bound_seconds",
            "estimate_within_budget", "uncovered_services",
        )
    } | {
        "plan_sha256": plan_digest(plan),
        "tasks": [{"id": t["id"], "host": t["host"], "recipe": t["recipe"],
                   "requires": t["requires"], "service_key": t["service_key"],
                   "timeout_seconds": t["timeout_seconds"],
                   "check_sha256": hashlib.sha256(t["check"].encode()).hexdigest(),
                   "apply_sha256": hashlib.sha256(t["apply"].encode()).hexdigest(),
                   "rollback_available": t["rollback"] is not None} for t in plan["tasks"]],
        "estimate_note": "Planning lower bound only; downloads, reboots, and observed host speed determine actual time.",
    }


@contextmanager
def _locked_state(directory: Path):
    directory = directory.absolute()
    for path in [directory, *directory.parents]:
        if path.is_symlink():
            raise ValueError("setup state cannot use symlink directories")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        details = directory.stat()
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise ValueError("setup state directory must be owned by this user and private (0700)")
    path = directory / "setup.lock"
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("invalid setup state lock")
        if os.name == "posix":
            import fcntl
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        else:
            import msvcrt
            os.write(descriptor, b"0")
            os.lseek(descriptor, 0, os.SEEK_SET)
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        yield directory / "setup-state.json"
    except BlockingIOError as exc:
        raise ValueError("another setup process owns this state directory") from exc
    finally:
        os.close(descriptor)


class SetupRunner:
    def __init__(self, plan: dict, profile: EventProfile, *, transport=None, probe=None, progress=None):
        self.plan = plan
        self.profile = profile
        self.transport = transport or SetupTransport()
        self.probe = probe or run_probe
        self.progress = progress or (lambda _: None)
        self.started_monotonic = 0.0
        self.remaining_at_start = 0.0

    def remaining(self) -> float:
        return max(0.0, self.remaining_at_start - (time.monotonic() - self.started_monotonic))

    def _command(self, host: dict, script: str, seconds: float) -> CommandResult:
        return self.transport.execute(host, script, min(seconds, self.remaining()))

    def _healthy(self, task: dict, host: dict, seconds: float) -> tuple[bool, list[dict]]:
        result = self._command(host, task["check"], min(30, seconds))
        if result.uncertain or result.returncode != 0:
            return False, [{"kind": "native-check", "healthy": False, "returncode": result.returncode,
                            "uncertain": result.uncertain}]
        checks = []
        for source in task["probes"]:
            if self.remaining() < 0.25:
                return False, checks + [{"kind": "deadline", "healthy": False}]
            spec = dict(source)
            spec["timeout"] = min(float(spec.get("timeout", 3)), 3, self.remaining())
            probe = self.probe(spec, list(self.profile.authorized_networks),
                               authorized_hosts=self.profile.authorized_hosts,
                               excluded_hosts=self.profile.excluded_hosts)
            checks.append({"kind": spec["kind"], "healthy": probe.healthy,
                           "latency_ms": probe.latency_ms})
        return all(x["healthy"] for x in checks), checks

    def _task(self, task: dict) -> dict:
        started = time.monotonic()
        host = self.plan["hosts"][task["host"]]
        limit = min(task["timeout_seconds"], self.remaining())
        if limit <= 0:
            return {"status": "deadline", "changed": False, "seconds": 0}
        healthy, checks = self._healthy(task, host, limit)
        if healthy:
            return {"status": "ready", "changed": False, "seconds": time.monotonic() - started,
                    "checks": checks, "already_ready": True}
        available = min(limit - (time.monotonic() - started), self.remaining())
        if available <= 0:
            return {"status": "deadline", "changed": False, "seconds": time.monotonic() - started}
        applied = self._command(host, task["apply"], available)
        record = {"changed": True, "apply": asdict(applied)}
        if applied.uncertain:
            return record | {"status": "uncertain", "seconds": time.monotonic() - started,
                             "reason": "mutation completion is unknown; do not replay automatically"}
        if applied.returncode == 30:
            return record | {"status": "reboot-required", "seconds": time.monotonic() - started}
        if applied.returncode != 0:
            if task["rollback"] and self.remaining() > 0:
                record["rollback"] = asdict(self._command(host, task["rollback"], min(60, self.remaining())))
            return record | {"status": "failed", "seconds": time.monotonic() - started,
                             "reason": "setup command failed; inspect the reviewed runbook on the host"}
        grace_end = min(started + limit, time.monotonic() + task["health_wait_seconds"])
        consecutive = 0
        while time.monotonic() < grace_end and self.remaining() > 0:
            healthy, checks = self._healthy(task, host, grace_end - time.monotonic())
            consecutive = consecutive + 1 if healthy else 0
            if consecutive >= 2:
                return record | {"status": "ready", "seconds": time.monotonic() - started, "checks": checks}
            time.sleep(min(0.5, max(0, grace_end - time.monotonic()), self.remaining()))
        # An external check failure does not authorize rolling back packages or
        # other hosts. Report the exact stage and retain successful independent work.
        return record | {"status": "deadline" if self.remaining() <= 0 else "failed",
                         "seconds": time.monotonic() - started, "checks": checks,
                         "reason": "required health checks did not stabilize"}

    def execute(self, state_dir: Path, approved_digest: str, *, resume: bool = False) -> dict:
        digest = plan_digest(self.plan)
        if digest != approved_digest or self.plan["profile_fingerprint"] != self.profile.fingerprint:
            raise ValueError("setup plan changed or does not match the approved profile/digest")
        if not self.profile.allows("initial_provisioning"):
            raise ValueError("event profile must explicitly permit initial_provisioning")
        with _locked_state(state_dir) as state_path:
            now = time.time()
            if state_path.exists():
                if not resume:
                    raise ValueError("setup state already exists; use --resume to retain its original deadline")
                state = read_private_json(state_path)
                if state.get("plan_sha256") != digest:
                    raise ValueError("existing setup state belongs to another plan")
                if set(state.get("tasks", {})) != {t["id"] for t in self.plan["tasks"]}:
                    raise ValueError("setup state task inventory is inconsistent")
                if type(state.get("last_wall_time")) not in {int, float} or now < state["last_wall_time"] - 0.5:
                    raise ValueError("clock moved backwards; review the setup deadline")
                if not math.isfinite(state.get("started_at", float("nan"))) or state["started_at"] > now:
                    raise ValueError("invalid setup start time")
                expected_deadline = state["started_at"] + self.plan["budget_seconds"]
                if state.get("deadline_at") != expected_deadline:
                    raise ValueError("persisted setup deadline was changed")
                for row in state["tasks"].values():
                    if row.get("status") == "running":
                        row.update(status="uncertain", reason="previous process ended during this task")
                    elif row.get("status") == "blocked" and row.get("changed") is False:
                        row.update(status="pending")
                    elif row.get("status") not in TERMINAL | {"pending"}:
                        raise ValueError("invalid persisted setup task status")
            else:
                if resume:
                    raise ValueError("no setup state exists to resume")
                state = {"plan_sha256": digest, "started_at": now,
                         "deadline_at": now + self.plan["budget_seconds"], "last_wall_time": now,
                         "tasks": {t["id"]: {"status": "pending"} for t in self.plan["tasks"]}}
            self.remaining_at_start = max(0, state["deadline_at"] - now)
            self.started_monotonic = time.monotonic()

            def persist():
                state["last_wall_time"] = time.time()
                write_private_json(state_path, state)

            persist()
            host_results = {}
            def preflight_host(host):
                return self.transport.preflight(host, min(20, self.remaining()))
            with ThreadPoolExecutor(max_workers=self.plan["max_parallel_hosts"]) as pool:
                futures = {pool.submit(preflight_host, host): name
                           for name, host in self.plan["hosts"].items() if self.remaining() > 0}
                for future in futures:
                    name = futures[future]
                    try:
                        result = future.result()
                        host_results[name] = result.returncode == 0 and not result.uncertain
                    except Exception:
                        host_results[name] = False
            state["host_preflight"] = host_results
            # Completed stages are rechecked on resume; drift never silently
            # grants permission to repeat an earlier mutation.
            if resume:
                for task in self.plan["tasks"]:
                    if state["tasks"][task["id"]]["status"] == "ready":
                        healthy, checks = self._healthy(task, self.plan["hosts"][task["host"]], self.remaining())
                        if not healthy:
                            state["tasks"][task["id"]].update(status="changed", checks=checks)
            persist()
            tasks = {t["id"]: t for t in self.plan["tasks"]}
            unsafe_hosts = {tasks[name]["host"] for name, row in state["tasks"].items()
                            if row["status"] in {"uncertain", "reboot-required"}}
            pending = {name for name, row in state["tasks"].items() if row["status"] == "pending"}
            active = {}
            busy = set()
            with ThreadPoolExecutor(max_workers=self.plan["max_parallel_hosts"]) as pool:
                while pending or active:
                    for name in list(tasks):
                        if name not in pending:
                            continue
                        task = tasks[name]
                        host = task["host"]
                        dependency_status = [state["tasks"][x]["status"] for x in task["requires"]]
                        reason = None
                        status = "blocked"
                        if self.remaining() <= 0:
                            status, reason = "deadline", "original setup deadline exhausted"
                        elif not host_results.get(host):
                            reason = "management access is unavailable; host was not changed"
                        elif host in unsafe_hosts:
                            reason = "another task on this host has an uncertain outcome or requires reboot"
                        elif any(x in TERMINAL - {"ready"} for x in dependency_status):
                            reason = "a required setup dependency did not become ready"
                        if reason:
                            state["tasks"][name] = {"status": status, "reason": reason, "changed": False}
                            pending.remove(name)
                            persist()
                            continue
                        if host in busy or len(active) >= self.plan["max_parallel_hosts"] or any(x != "ready" for x in dependency_status):
                            continue
                        pending.remove(name)
                        busy.add(host)
                        state["tasks"][name] = {"status": "running", "started_at": time.time()}
                        persist()  # durable BEFORE a worker may mutate the host
                        self.progress({"task": name, "status": "running", "remaining_seconds": round(self.remaining(), 1)})
                        active[pool.submit(self._task, task)] = name
                    if active:
                        finished, _ = wait(active, timeout=0.25, return_when=FIRST_COMPLETED)
                        for future in finished:
                            name = active.pop(future)
                            busy.remove(tasks[name]["host"])
                            try:
                                result = future.result()
                            except Exception as exc:
                                result = {"status": "uncertain", "reason": "task raised " + type(exc).__name__}
                            state["tasks"][name] = result
                            if result["status"] in {"uncertain", "reboot-required"}:
                                unsafe_hosts.add(tasks[name]["host"])
                            persist()
                            self.progress({"task": name, "status": result["status"], "remaining_seconds": round(self.remaining(), 1)})
                    elif pending:
                        raise RuntimeError("setup scheduler could not advance a validated dependency graph")
            # Revalidate all scored endpoints after the last mutation. Early
            # success cannot hide a service broken by a later setup stage.
            for task in self.plan["tasks"]:
                row = state["tasks"][task["id"]]
                if task["service_key"] and row["status"] == "ready":
                    healthy, checks = self._healthy(task, self.plan["hosts"][task["host"]], self.remaining())
                    row["final_checks"] = checks
                    if not healthy:
                        row["status"] = "deadline" if self.remaining() <= 0 else "changed"
            elapsed = self.plan["budget_seconds"] - self.remaining_at_start + (time.monotonic() - self.started_monotonic)
            all_ready = all(row["status"] == "ready" for row in state["tasks"].values())
            complete = all_ready and not self.plan["uncovered_services"] and elapsed < self.plan["budget_seconds"]
            report = {
                "version": __version__, "status": "ready" if complete else "incomplete",
                "plan_sha256": digest, "profile_id": self.profile.profile_id,
                "elapsed_seconds": round(elapsed, 3), "budget_seconds": self.plan["budget_seconds"],
                "under_30_minutes": complete and elapsed < 1800,
                "all_declared_services_ready": all_ready and not self.plan["uncovered_services"],
                "uncovered_services": self.plan["uncovered_services"],
                "tasks_ready": sum(row["status"] == "ready" for row in state["tasks"].values()),
                "task_count": len(state["tasks"]), "tasks": state["tasks"],
                "host_preflight": host_results,
                "full_competition_readiness_proven": False,
                "clock_scope": "management preflight, provisioning, health checks, and time between resumptions; inventory preparation excluded",
            }
            state["last_report"] = report
            persist()
            return report


def run(args: argparse.Namespace) -> int:
    root = Path(args.inventory).absolute().parent
    inventory = load_inventory(args.inventory)
    profile = load_event_profile(args.event_profile or args.inventory)
    plan = compile_plan(inventory, profile, root)
    if args.plan_out:
        write_private_json(args.plan_out, plan)
    if not args.execute:
        print(json.dumps(summarize_plan(plan), indent=2))
        return 0
    profile.require_runtime_ready(range_deployment=args.range_deployment)
    profile.verify_release_file(sys.argv[0])
    if not args.approve_plan or not args.state_dir:
        raise ValueError("--execute requires --approve-plan SHA256 and --state-dir")
    runner = SetupRunner(plan, profile, progress=lambda row: print(json.dumps(row), file=sys.stderr, flush=True))
    report = runner.execute(Path(args.state_dir), args.approve_plan, resume=args.resume)
    if args.output:
        write_private_json(args.output, report)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "ready" else 2
