"""Reviewed fleet security workflow, with encrypted write-ahead credentials."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .credential_vault import CredentialVault, new_password, validate_password
from .event_profile import EventProfile, load_event_profile
from .identity_guard import _source_allowed
from .json_codec import canonical_json_bytes, strict_json_loads
from .persistence_security import PersistenceRemediator, fingerprint, validate_target
from .security_native import NativeSecurityBackend
from .state import read_private_json, write_private_json


ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\Z")


def _blue_identity(profile, agent_id, name):
    rows = [row for row in profile.identities if row["agent_id"] in {"*", agent_id}
            and row["name"].casefold() == name.casefold()]
    if not rows or any(row["class"] != "blue-admin" for row in rows):
        raise ValueError("password rotation requires an exclusively blue-admin official identity")


def compile_security_plan(inventory, profile):
    source = inventory.get("security")
    if (not isinstance(source, dict) or not {"batch_id", "budget_seconds", "blue_accounts", "removals"} <= set(source)
            or set(source) - {"batch_id", "budget_seconds", "blue_accounts", "removals", "ssh_guard_hosts"}):
        raise ValueError("security requires batch_id, budget_seconds, blue_accounts and removals")
    if not isinstance(source["batch_id"], str) or not ID.fullmatch(source["batch_id"]):
        raise ValueError("security batch requires an explicit unique identifier")
    budget = source["budget_seconds"]
    if type(budget) not in {int, float} or not 1 <= budget <= 1800:
        raise ValueError("security budget must be between 1 and 1800 seconds")
    profile.assert_inventory_networks(inventory.get("authorized_networks", []))
    hosts = {}
    addresses, agents = set(), set()
    for raw in inventory.get("hosts", []):
        if not isinstance(raw, dict) or not isinstance(raw.get("name"), str) or not ID.fullmatch(raw["name"]):
            raise ValueError("invalid security host")
        address = str(ipaddress.ip_address(raw["address"]))
        profile.assert_target(address)
        profile.assert_route(raw["transport"])
        if raw["transport"] not in {"local", "ssh", "winrm"} or raw["platform"] not in {"linux", "windows"}:
            raise ValueError("unsupported security management route")
        if raw["transport"] == "local" and (not ipaddress.ip_address(address).is_loopback or
                raw["platform"] != ("windows" if os.name == "nt" else "linux")):
            raise ValueError("local security operation must name this operating system and loopback")
        if raw["transport"] == "winrm" and raw["platform"] != "windows":
            raise ValueError("WinRM security operation requires a Windows host")
        if raw["transport"] == "ssh" and raw["platform"] != "linux":
            raise ValueError("the security SSH adapter currently requires a Linux host")
        agent = raw.get("agent_id", raw["name"])
        if not isinstance(agent, str) or not ID.fullmatch(agent):
            raise ValueError("security host requires an exact agent identifier")
        if raw["name"] in hosts or address in addresses or agent in agents:
            raise ValueError("duplicate security host or agent")
        if raw.get("accept_new_host_key"):
            raise ValueError("security changes require a previously verified SSH host key")
        host = {key: raw[key] for key in ("name", "address", "platform", "transport", "username", "key_file",
                 "known_hosts_file", "port", "credential_file", "runtime_path", "python_executable", "security_state_dir") if key in raw}
        host["agent_id"] = agent
        for field in ("runtime_path", "security_state_dir"):
            value = raw.get(field)
            if not isinstance(value, str) or not value or any(c in value for c in "\r\n\0\""):
                raise ValueError("security host needs explicit runtime_path and security_state_dir")
            from pathlib import PurePosixPath, PureWindowsPath
            path_type = PureWindowsPath if raw["platform"] == "windows" else PurePosixPath
            path = path_type(value)
            if not path.is_absolute() or ".." in path.parts or not any(
                    path.is_relative_to(path_type(root)) for root in profile.deployment_paths
                    if path_type(root).is_absolute()):
                raise ValueError("security runtime/state path is outside approved deployment paths")
        if raw["transport"] == "ssh" and not all(raw.get(k) for k in ("username", "known_hosts_file", "key_file")):
            raise ValueError("SSH rotation requires a pinned host key and independent management key")
        if raw["transport"] == "winrm" and not all(raw.get(k) for k in ("username", "credential_file")):
            raise ValueError("WinRM rotation requires an explicit management username and private credential file")
        hosts[raw["name"]] = host
        addresses.add(address)
        agents.add(agent)
    if not hosts or len(hosts) > 256:
        raise ValueError("security requires 1–256 inventoried hosts")
    accounts, seen = [], set()
    if not isinstance(source["blue_accounts"], list) or len(source["blue_accounts"]) > 2048:
        raise ValueError("invalid blue-team roster")
    for row in source["blue_accounts"]:
        if not isinstance(row, dict) or set(row) != {"host", "name", "account_id"} or row["host"] not in hosts:
            raise ValueError("blue-team account requires exact host, name and native account_id")
        host = hosts[row["host"]]
        from .security_native import _account_name
        _account_name(row["name"])
        if not isinstance(row["account_id"], str) or not re.fullmatch(r"\d+|S-1-(?:\d+-)+\d+", row["account_id"]):
            raise ValueError("blue account requires a native UID or SID")
        if host["platform"] == "linux" and (not row["account_id"].isdigit() or row["account_id"] == "0" and row["name"] != "root"):
            raise ValueError("Linux rotation cannot target a duplicate root alias or a SID")
        if host["platform"] == "windows" and not row["account_id"].startswith("S-1-5-21-"):
            raise ValueError("Windows rotation requires an exact local account SID")
        _blue_identity(profile, host["agent_id"], row["name"])
        key = (row["host"], row["name"].casefold())
        if key in seen:
            raise ValueError("duplicate blue-team account")
        seen.add(key)
        for service in profile.services:
            if service["host"] in {host["agent_id"], host["name"]} and row["name"].casefold() in {
                    str(name).casefold() for name in service["required_accounts"]}:
                raise ValueError("blue login also serves a scored application; a dependency-aware rotation adapter is required")
        accounts.append(dict(row))
    # A plan cannot silently omit an official blue-team account on an included host.
    for host in hosts.values():
        for identity in profile.identities:
            if identity["class"] == "blue-admin" and identity["agent_id"] in {"*", host["agent_id"]}:
                if (host["name"], identity["name"].casefold()) not in seen:
                    raise ValueError("blue-team rotation plan omits an official blue-admin identity")
    removals = source["removals"]
    if not isinstance(removals, list) or len(removals) > 256:
        raise ValueError("invalid persistence-removal list")
    removal_seen = set()
    for row in removals:
        if (not isinstance(row, dict) or set(row) != {"host", "target", "snapshot_sha256", "reason"}
                or row["host"] not in hosts or not re.fullmatch(r"[0-9a-f]{64}", str(row["snapshot_sha256"]))
                or not isinstance(row["reason"], str) or not 5 <= len(row["reason"]) <= 512):
            raise ValueError("removal requires a reviewed exact native snapshot and reason")
        validate_target(row["target"])
        key = (row["host"], fingerprint(row["target"]))
        if key in removal_seen:
            raise ValueError("duplicate persistence-removal target")
        removal_seen.add(key)
        # Do not delete required configuration/service definitions in this workflow.
        for service in profile.services:
            if service["host"] in {hosts[row["host"]]["agent_id"], row["host"]} and (
                    row["target"].get("path") in service["required_files"] or
                    row["target"].get("service") == service["service_id"]):
                raise ValueError("required service/configuration needs in-place repair, not whole-object removal")
    if accounts and not profile.capabilities["password_rotation"]:
        raise ValueError("event profile does not permit password rotation")
    if removals and not profile.capabilities["persistence_removal"]:
        raise ValueError("event profile does not permit persistence removal")
    guard_hosts = source.get("ssh_guard_hosts", [])
    if not isinstance(guard_hosts, list) or len(set(guard_hosts)) != len(guard_hosts):
        raise ValueError("SSH guard hosts must be a unique array")
    for name in guard_hosts:
        if name not in hosts or hosts[name]["platform"] != "linux":
            raise ValueError("SSH scorer enforcement requires an inventoried Linux host")
        if not profile.capabilities["scoring_access_control"]:
            raise ValueError("event profile does not authorize scoring access restrictions")
        selected = [g for g in profile.raw.get("identity_guards", []) if g["agent_id"] == hosts[name]["agent_id"]]
        if not selected:
            raise ValueError("SSH scorer enforcement requires native identities and official source networks")
        for guard in selected:
            roles = [r["class"] for r in profile.identities if r["agent_id"] in {"*", hosts[name]["agent_id"]}
                     and r["name"] == guard["name"]]
            if not roles or set(roles) != {"scoring"}:
                raise ValueError("SSH source enforcement is limited to exclusively scoring identities")
    return {"schema": 1, "version": __version__, "profile_fingerprint": profile.fingerprint,
            "batch_id": source["batch_id"], "budget_seconds": float(budget), "hosts": hosts,
            "blue_accounts": accounts, "removals": removals, "ssh_guard_hosts": guard_hosts}


def guest_request(request, profile, host):
    """Called only through an authenticated management route or explicit local CLI."""
    operation = request.get("operation")
    backend = NativeSecurityBackend()
    if operation == "guard_ssh":
        if not profile.capabilities["scoring_access_control"] or profile.autonomy_mode == "observe":
            raise ValueError("scoring access control is not enabled")
        from .scorer_ssh_guard import enforce_ssh_guard
        guards = [g for g in profile.raw.get("identity_guards", []) if g["agent_id"] == host["agent_id"]]
        return enforce_ssh_guard(guards, Path(host["security_state_dir"]) / "ssh-guard")
    if operation in {"account", "set_password", "verify_password"}:
        _blue_identity(profile, host["agent_id"], request["name"])
        if operation == "account":
            return backend.account(request["name"])
        if not profile.capabilities["password_rotation"] or profile.autonomy_mode == "observe":
            raise ValueError("password rotation is not enabled by this profile")
        if operation == "set_password":
            backend.set_password(request["name"], request["account_id"], request["password"])
            return {"applied": True}
        return {"verified": backend.verify_password(request["name"], request["account_id"], request["password"]),
                "verification": "native_password_policy", "network_login_verified": False}
    if operation == "scan":
        from .collectors import _linux_persistence, _windows_persistence
        errors = []
        items = _windows_persistence(errors) if os.name == "nt" else _linux_persistence(errors)
        return {"items": [asdict(i) for i in items], "collector_errors": errors,
                "coverage": "bounded native startup inventory", "host_clean": False}
    remediator = PersistenceRemediator(host["security_state_dir"])
    try:
        if operation == "inspect":
            return remediator.inspect(request["target"])
        if operation in {"remove", "restore"}:
            if not profile.capabilities["persistence_removal"] or profile.autonomy_mode == "observe":
                raise ValueError("persistence removal is not enabled by this profile")
            if operation == "remove":
                return remediator.remove(request["target"], request["snapshot_sha256"], operation_id=request["operation_id"])
            return remediator.restore(request["operation_id"])
        raise ValueError("unknown security operation")
    finally:
        remediator.close()


class SecurityCoordinator:
    def __init__(self, plan, profile, vault, transport, *, clock=time.time, password_factory=new_password):
        self.plan, self.profile, self.vault, self.transport = plan, profile, vault, transport
        self.clock, self.password_factory = clock, password_factory
        self.digest = fingerprint(plan)

    def execute(self, *, approved_digest, started_at=None):
        if approved_digest != self.digest or self.profile.fingerprint != self.plan["profile_fingerprint"]:
            raise ValueError("security plan approval or profile binding does not match")
        if self.profile.autonomy_mode == "observe":
            raise ValueError("security changes are disabled in observe mode")
        entries = self.vault.data["entries"]
        batch_key = "batch:" + self.digest
        batch = entries.get(batch_key)
        now = self.clock()
        if batch is None:
            start = now if started_at is None else started_at
            if type(start) not in {int, float} or not 0 < start <= now:
                raise ValueError("invalid original security start time")
            batch = {"started_at": start, "last_observed": now, "status": "running", "operations": {}}
            entries[batch_key] = batch
            self.vault.save()
        if now < batch["last_observed"]:
            raise ValueError("clock moved backwards; review the original security deadline")
        deadline = batch["started_at"] + self.plan["budget_seconds"]
        results = []

        def request(host, body):
            remaining = deadline - self.clock()
            if remaining <= 0:
                raise TimeoutError("original security deadline expired")
            response = self.transport.request(host, body, min(45, remaining))
            if self.clock() > deadline:
                raise TimeoutError("security operation exceeded original deadline")
            return response

        # Stage ALL passwords durably before changing any account.
        for account in self.plan["blue_accounts"]:
            key = self.digest + ":" + account["host"] + ":" + account["name"]
            if key not in entries:
                entries[key] = {**account, "password": validate_password(self.password_factory()),
                                "status": "prepared", "created_at": self.clock(), "batch": self.digest}
        self.vault.save()
        # Remove approved persistence before exposing fresh passwords to these hosts.
        failed_hosts = set()
        for name in self.plan.get("ssh_guard_hosts", []):
            try:
                guarded = request(self.plan["hosts"][name], {"operation": "guard_ssh"})
                if guarded.get("status") != "verified":
                    raise ValueError("SSH scorer restriction was not verified")
            except Exception:
                guarded = {"status": "uncertain"}
                failed_hosts.add(name)
            results.append({"host": name, "operation": "scoring_ssh_guard", **guarded})
        for index, removal in enumerate(self.plan["removals"]):
            host = self.plan["hosts"][removal["host"]]
            operation_id = "remove_" + self.digest[:24] + "_" + str(index)
            prior = batch["operations"].get(operation_id)
            if prior is not None and prior.get("status") != "quarantined":
                result = prior
            else:
                batch["operations"][operation_id] = {"status": "uncertain"}
                self.vault.save()
                try:
                    result = request(host, {"operation": "remove", "operation_id": operation_id,
                                           "target": removal["target"], "snapshot_sha256": removal["snapshot_sha256"]})
                    if result.get("status") != "quarantined":
                        result = {"status": "uncertain"}
                except Exception:
                    result = {"status": "uncertain"}
                batch["operations"][operation_id] = result
                self.vault.save()
            results.append({"host": host["name"], "operation": "persistence_removal", **result})
            if result.get("status") != "quarantined":
                failed_hosts.add(host["name"])
        for account in self.plan["blue_accounts"]:
            host = self.plan["hosts"][account["host"]]
            key = self.digest + ":" + account["host"] + ":" + account["name"]
            entry = entries[key]
            try:
                if host["name"] in failed_hosts:
                    raise ValueError("host has unresolved security operations")
                if entry["status"] != "prepared" and hasattr(self.transport, "set_management_password"):
                    self.transport.set_management_password(host, account["name"], entry["password"])
                observed = request(host, {"operation": "account", "name": account["name"]})
                if (observed.get("account_id") != account["account_id"] or observed.get("enabled") is not True
                        or observed.get("dependencies") or observed.get("name", "").casefold() != account["name"].casefold()
                        or host["platform"] == "linux" and observed.get("name") != account["name"]):
                    raise ValueError("native identity, enabled state or service dependencies do not match")
                if "before" in entry and observed != entry["before"]:
                    raise ValueError("account access metadata changed since the rotation began")
                entry.setdefault("before", observed)
                if entry["status"] == "prepared":
                    entry["status"] = "applying"
                    self.vault.save()
                    changed = request(host, {"operation": "set_password", **account, "password": entry["password"]})
                    if changed.get("applied") is not True:
                        raise ValueError("password change result is unconfirmed")
                    if hasattr(self.transport, "set_management_password"):
                        self.transport.set_management_password(host, account["name"], entry["password"])
                    entry["status"] = "applied_unverified"
                    self.vault.save()
                # An interrupted write is reconciled by verifying the SAME stored
                # secret. It is never repeated or replaced with another password.
                verified = request(host, {"operation": "verify_password", **account, "password": entry["password"]})
                if verified.get("verified") is not True:
                    raise ValueError("new password authentication did not pass")
                entry["status"] = "verified"
                entry["verification"] = verified.get("verification", "native_password_policy")
                entry["network_login_verified"] = verified.get("network_login_verified") is True
                entry["verified_at"] = self.clock()
            except Exception:
                if entry["status"] != "prepared":
                    entry["status"] = "uncertain"
                failed_hosts.add(host["name"])
            self.vault.data["audit"].append({"at": self.clock(), "host": host["name"], "account": account["name"],
                                            "operation": "password_rotation", "status": entry["status"]})
            self.vault.save()
            results.append({"host": host["name"], "account": account["name"], "operation": "password_rotation",
                            "status": entry["status"], "identity_preserved": entry["status"] == "verified"})
        batch["last_observed"] = self.clock()
        batch["status"] = "completed" if not failed_hosts and self.clock() <= deadline else "incomplete"
        self.vault.save()
        return {"version": __version__, "plan_sha256": self.digest, "status": batch["status"],
                "elapsed_seconds": round(self.clock() - batch["started_at"], 3), "results": results,
                "all_backdoors_found": False, "scorer_cryptographically_authenticated": False,
                "passwords_in_report": False}


def add_cli(subcommands):
    security = subcommands.add_parser("security", help="inspect persistence, quarantine reviewed objects and rotate blue credentials")
    security.add_argument("action", choices=["plan", "scan", "inspect", "execute", "restore", "vault-list", "vault-show"])
    security.add_argument("--inventory")
    security.add_argument("--event-profile")
    security.add_argument("--host")
    security.add_argument("--target", help="private JSON describing one exact persistence object")
    security.add_argument("--approve-plan")
    security.add_argument("--vault-dir")
    security.add_argument("--entry", help="vault entry identifier; password display requires an interactive terminal")
    security.add_argument("--operation-id")
    security.add_argument("--choose-passwords", action="store_true")
    security.add_argument("--started-at", type=float)
    security.add_argument("--range-deployment", action="store_true")
    security.add_argument("--output")
    guest = subcommands.add_parser("security-guest", help=argparse.SUPPRESS)
    guest.add_argument("--range-deployment", action="store_true")


def run(args):
    if args.command == "security-guest":
        try:
            payload = strict_json_loads(sys.stdin.buffer.read(2 * 1024 * 1024 + 1), max_bytes=2 * 1024 * 1024)
            profile = EventProfile.from_dict(payload["event_profile"])
            profile.require_runtime_ready(range_deployment=args.range_deployment)
            host = payload["host"]
            profile.assert_target(host["address"])
            response = guest_request(payload["request"], profile, host)
            print(json.dumps(response))
            return 0
        except Exception:
            print(json.dumps({"error": "native security operation failed; inspect private host evidence"}))
            return 1
    started = time.time()
    try:
        if args.action in {"vault-list", "vault-show"}:
            if not args.vault_dir:
                raise ValueError("--vault-dir is required")
            with CredentialVault(args.vault_dir, getpass.getpass("Vault passphrase: ")) as vault:
                if args.action == "vault-show":
                    if not sys.stdout.isatty() or not args.entry or args.output:
                        raise ValueError("secret display requires an interactive terminal and an exact --entry; redirection is disabled")
                    row = vault.data["entries"][args.entry]
                    print(json.dumps({k: row[k] for k in ("host", "name", "account_id", "password", "status")}, indent=2))
                else:
                    print(json.dumps({key: {k: row[k] for k in ("host", "name", "account_id", "status")}
                                      for key, row in vault.data["entries"].items() if "password" in row}, indent=2))
            return 0
        if not args.inventory:
            raise ValueError("--inventory is required")
        inventory = read_private_json(args.inventory)
        profile = load_event_profile(args.event_profile or args.inventory)
        plan = compile_security_plan(inventory, profile)
        if args.action == "plan":
            result = {"plan": plan, "approve_plan": fingerprint(plan)}
        else:
            profile.require_runtime_ready(range_deployment=args.range_deployment)
            from .security_transport import SecurityTransport
            transport = SecurityTransport(profile, range_deployment=args.range_deployment)
            if args.action == "execute":
                if args.approve_plan != fingerprint(plan) or not args.vault_dir:
                    raise ValueError("execution requires the exact --approve-plan and an operator-side --vault-dir")
                passphrase = getpass.getpass("Vault passphrase (at least 16 characters): ")
                creating = not (Path(args.vault_dir) / "vault.json").exists()
                if creating and getpass.getpass("Confirm vault passphrase: ") != passphrase:
                    raise ValueError("vault passphrases do not match")
                def chosen():
                    account = next(pending_accounts)
                    password = getpass.getpass(f"New password for {account['host']} / {account['name']} (blank generates one): ")
                    if password and getpass.getpass("Confirm new account password: ") != password:
                        raise ValueError("account passwords do not match")
                    return validate_password(password) if password else new_password()
                with CredentialVault(args.vault_dir, passphrase, create=creating) as vault:
                    pending_accounts = iter(account for account in plan['blue_accounts']
                        if fingerprint(plan) + ':' + account['host'] + ':' + account['name'] not in vault.data['entries'])
                    coordinator = SecurityCoordinator(plan, profile, vault, transport,
                        password_factory=chosen if args.choose_passwords else new_password)
                    result = coordinator.execute(approved_digest=args.approve_plan,
                                                 started_at=args.started_at or started)
            else:
                if args.host not in plan["hosts"]:
                    raise ValueError("select an inventoried --host")
                request = {"operation": args.action}
                if args.action == "inspect":
                    request["target"] = validate_target(read_private_json(args.target))
                if args.action == "restore":
                    if args.approve_plan != fingerprint(plan):
                        raise ValueError("restoration requires exact plan approval")
                    request["operation_id"] = args.operation_id
                result = transport.request(plan["hosts"][args.host], request, 45)
        if args.output:
            write_private_json(args.output, result)
        print(json.dumps(result, indent=2))
        return 0 if result.get("status") not in {"incomplete", "uncertain"} else 1
    except Exception as exc:
        # Never stringify a provider exception: it can contain request secrets.
        print(json.dumps({"status": "failed", "error_type": type(exc).__name__,
                          "detail": "security operation failed; verify the approved inventory, native readiness and private journal"}))
        return 1
