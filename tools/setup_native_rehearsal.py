"""Provision owned native services on the owner's disposable hosted runners.

This is a single-host rehearsal per OS, not a claim about a multi-VM event.
The packaged setup CLI performs every installation/configuration/start. The
harness prepares input files, measures it, checks a resume, and removes its
owned service instances. It never runs on an ordinary or self-hosted machine.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from sentinel_blue import __version__
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.setup import compile_plan, plan_digest
from sentinel_blue.state import read_private_json, write_private_json


def source(root: Path, name: str, content: str) -> dict:
    path = root / name
    path.write_bytes(content.encode())
    if os.name == "posix":
        path.chmod(0o600)
    return {"path": str(path), "sha256": hashlib.sha256(content.encode()).hexdigest()}


def runbook(root: Path, task_id: str, check: str, apply: str, *, requires=(), service=None) -> dict:
    suffix = ".ps1" if os.name == "nt" else ".sh"
    task = {"id": task_id, "host": "target", "recipe": "runbook", "requires": list(requires),
            "estimate_seconds": 60, "timeout_seconds": 360, "health_wait_seconds": 30,
            "options": {"check": source(root, task_id + "-check" + suffix, check),
                        "apply": source(root, task_id + "-apply" + suffix, apply)}}
    if service:
        task["service_id"] = service
    return task


def manifest(service: str, protocol: str, port: int, checks: list) -> dict:
    return {"host": "target", "service_id": service, "protocol": protocol, "port": port,
            "implementation": "owned native setup rehearsal", "dependencies": [],
            "required_accounts": [], "required_files": [], "required_data": [],
            "credential_source": "disposable generated fixture only", "expected_transactions": checks,
            "local_checks": [], "allowed_automatic_actions": [], "approval_actions": [],
            "backup_method": "owned disposable instance", "recovery_method": "setup runbook",
            "rollback_method": "stop and remove only the owned fixture"}


def free_port() -> int:
    with socket.socket() as stream:
        stream.bind(("127.0.0.1", 0))
        return stream.getsockname()[1]


def profile_inventory(runtime: Path, tasks: list, services: list) -> dict:
    raw = copy.deepcopy(EventProfile.testing().raw)
    raw["profile_id"] = "native-setup-rehearsal"
    raw["scope"]["authorized_networks"] = ["127.0.0.0/8"]
    raw["scope"]["authorized_hosts"] = ["127.0.0.1"]
    raw["scope"]["controller_ingress_hosts"] = ["127.0.0.1"]
    raw["services"] = services
    raw["services_confirmed"] = True
    raw["release"] = {"version": __version__, "sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
                      "controller_ca_sha256": "a" * 64, "cloud_processing": False,
                      "external_telemetry_export": False}
    return {"authorized_networks": ["127.0.0.0/8"], "event_profile": raw,
            "hosts": [{"name": "target", "agent_id": "target", "address": "127.0.0.1",
                       "platform": "windows" if os.name == "nt" else "linux", "transport": "local"}],
            "setup": {"budget_seconds": 1800, "max_parallel_hosts": 4, "tasks": tasks}}


def linux_inputs(root: Path, suffix: str):
    base = Path("/var/lib") / ("sentinel-setup-" + suffix)
    if base.exists():
        raise RuntimeError("native setup fixture path already exists")
    units = {name: f"sentinel-setup-{suffix}-{name}" for name in ["web", "dns", "db", "ftp"]}
    ports = {name: free_port() for name in units}
    if len(set(ports.values())) != len(ports):
        raise RuntimeError("fixture port collision")
    packages = ["nginx", "bind9", "bind9-utils", "postgresql-16", "vsftpd"]
    dns_config = Path("/etc/bind") / ("sentinel-" + suffix + ".conf")
    dns_zone = Path("/etc/bind") / ("sentinel-" + suffix + ".zone")
    dns_cache = Path("/var/cache/bind") / ("sentinel-" + suffix)
    initial = {name: subprocess.run(["dpkg-query", "-W", "-f=${Status}", name], capture_output=True,
                                   text=True).stdout == "install ok installed" for name in packages}
    tasks = [{"id": "packages", "host": "target", "recipe": "linux-packages", "requires": [],
              "estimate_seconds": 480, "timeout_seconds": 900,
              "options": {"manager": "apt", "packages": packages}}]
    layout = f"""set -eu
test ! -e {base}
install -d -m 0755 {base} {base}/web {base}/dns {base}/ftp
install -d -o bind -g bind -m 0750 {dns_cache}
install -d -o postgres -g postgres -m 0700 {base}/pgdata
install -d -o postgres -g postgres -m 0750 {base}/pgsocket
runuser -u postgres -- /usr/lib/postgresql/16/bin/initdb -D {base}/pgdata --auth-local=peer --auth-host=scram-sha-256
"""
    tasks.append(runbook(root, "layout", f"test -f {base}/pgdata/PG_VERSION\n", layout, requires=["packages"]))

    def file_row(name, path, content):
        return {"path": str(path), "source": source(root, name, content), "mode": "0644", "previous_sha256": "absent"}

    def service_task(role, files, validate=None, requires=("layout",), covers=True):
        unit = units[role]
        options = {"service": unit, "enable": True, "files": files}
        if validate:
            options["validate_argv"] = validate
        task = {"id": role, "host": "target", "recipe": "linux-service", "requires": list(requires),
                "estimate_seconds": 60, "timeout_seconds": 180, "options": options}
        if covers:
            task["service_id"] = unit
        tasks.append(task)

    marker = "sentinel-native-setup-content-v1\n"
    unit_header = "[Unit]\nDescription=Owned Sentinel setup rehearsal\n[Service]\nType=simple\n"
    unit_footer = "\nRestart=no\n[Install]\nWantedBy=multi-user.target\n"
    web_conf = f"""worker_processes 1;
pid {base}/web/nginx.pid;
error_log {base}/web/error.log;
events {{ worker_connections 64; }}
http {{ access_log off; server {{ listen 127.0.0.1:{ports['web']}; root {base}/web; location / {{ try_files $uri =404; }} }} }}
"""
    service_task("web", [
        file_row("web.conf", base / "web/nginx.conf", web_conf),
        file_row("index.txt", base / "web/index.txt", marker),
        file_row("web.service", Path("/etc/systemd/system") / (units["web"] + ".service"),
                 unit_header + f"ExecStart=/usr/sbin/nginx -c {base}/web/nginx.conf -g 'daemon off;'" + unit_footer),
    ], ["/usr/sbin/nginx", "-t", "-c", str(base / "web/nginx.conf")], requires=["database", "dns"])

    dns_conf = f"""options {{ directory \"{dns_cache}\"; listen-on port {ports['dns']} {{ 127.0.0.1; }}; listen-on-v6 {{ none; }}; recursion no; pid-file \"/run/named/sentinel-{suffix}/named.pid\"; }};
zone \"setup.test\" {{ type primary; file \"{dns_zone}\"; }};
"""
    zone = "$TTL 60\n@ IN SOA ns.setup.test. hostmaster.setup.test. (1 60 60 60 60)\n@ IN NS ns.setup.test.\nns IN A 127.0.0.1\nwww IN A 127.0.0.1\n"
    service_task("dns", [
        file_row("named.conf", dns_config, dns_conf),
        file_row("setup.zone", dns_zone, zone),
        file_row("dns.service", Path("/etc/systemd/system") / (units["dns"] + ".service"),
                 unit_header + f"User=bind\nRuntimeDirectory=named/sentinel-{suffix}\nExecStart=/usr/sbin/named -g -c {dns_config}" + unit_footer),
    ], ["/usr/bin/env", "named-checkconf", "-z", str(dns_config)])
    pg_command = f"/usr/lib/postgresql/16/bin/postgres -D {base}/pgdata -h 127.0.0.1 -p {ports['db']} -k {base}/pgsocket"
    service_task("db", [file_row("db.service", Path("/etc/systemd/system") / (units["db"] + ".service"),
                                unit_header + "User=postgres\nExecStart=" + pg_command + unit_footer)], covers=False)
    password = uuid.uuid4().hex
    query = f"PGPASSWORD={password} /usr/bin/psql -h 127.0.0.1 -p {ports['db']} -U sb_setup_test -d sb_setup_test -Atqc 'SELECT 1'"
    db_check = f"set -eu\ntest \"$({query})\" = 1\n"
    db_apply = f"""set -eu
runuser -u postgres -- /usr/bin/psql -h {base}/pgsocket -p {ports['db']} -d postgres -v ON_ERROR_STOP=1 <<'SQL'
CREATE ROLE sb_setup_test LOGIN PASSWORD '{password}';
CREATE DATABASE sb_setup_test OWNER sb_setup_test;
SQL
"""
    tasks.append(runbook(root, "database", db_check, db_apply, requires=["db"], service=units["db"]))
    ftp_conf = f"""listen=YES
listen_ipv6=NO
background=NO
listen_address=127.0.0.1
listen_port={ports['ftp']}
anonymous_enable=YES
no_anon_password=YES
anon_root={base}/ftp
local_enable=NO
write_enable=NO
secure_chroot_dir=/var/run/vsftpd/empty
pasv_enable=YES
pasv_address=127.0.0.1
"""
    service_task("ftp", [
        file_row("vsftpd.conf", base / "ftp/vsftpd.conf", ftp_conf),
        file_row("download.txt", base / "ftp/download.txt", marker),
        file_row("ftp.service", Path("/etc/systemd/system") / (units["ftp"] + ".service"),
                 unit_header + f"ExecStart=/usr/sbin/vsftpd {base}/ftp/vsftpd.conf" + unit_footer),
    ])
    services = [
        manifest(units["web"], "http", ports["web"], [{"kind": "http", "target": f"http://127.0.0.1:{ports['web']}/index.txt", "expected_body": marker, "expected_status": [200]}]),
        manifest(units["dns"], "dns", ports["dns"], [{"kind": "dns", "target": "127.0.0.1", "port": ports["dns"], "query": "www.setup.test", "record_type": "A", "expected_answers": ["127.0.0.1"]}]),
        manifest(units["db"], "postgresql", ports["db"], [{"kind": "tcp", "target": "127.0.0.1", "port": ports["db"]}]),
        manifest(units["ftp"], "ftp", ports["ftp"], [{"kind": "ftp", "target": "127.0.0.1", "port": ports["ftp"], "path": "download.txt", "expected_sha256": hashlib.sha256(marker.encode()).hexdigest()}]),
    ]

    def identities():
        return {role: subprocess.run(["systemctl", "show", "-p", "MainPID", "--value", unit],
                                      capture_output=True, text=True).stdout.strip() for role, unit in units.items()}

    def cleanup():
        stopped = True
        for unit in units.values():
            subprocess.run(["systemctl", "stop", unit], capture_output=True, timeout=45)
            subprocess.run(["systemctl", "disable", unit], capture_output=True, timeout=20)
            state = subprocess.run(["systemctl", "is-active", "--quiet", unit], capture_output=True)
            stopped = stopped and state.returncode != 0
            (Path("/etc/systemd/system") / (unit + ".service")).unlink(missing_ok=True)
        subprocess.run(["systemctl", "daemon-reload"], capture_output=True, timeout=20)
        if stopped:
            shutil.rmtree(base, ignore_errors=True)
            dns_config.unlink(missing_ok=True)
            dns_zone.unlink(missing_ok=True)
            shutil.rmtree(dns_cache, ignore_errors=True)
        return {"verified": stopped and not base.exists() and not dns_config.exists() and not dns_zone.exists() and not dns_cache.exists(), "owned_service_instances_removed": stopped,
                "distro_packages_retained_until_runner_disposal": True}

    return tasks, services, initial, identities, cleanup, [password]


def windows_inputs(root: Path, suffix: str):
    base = root / "site"
    site = "SentinelSetup" + suffix
    port = free_port()
    zone = "sentinel-setup-" + suffix + ".test"
    ps = shutil.which("powershell.exe") or shutil.which("pwsh")
    from sentinel_blue.setup_transport import powershell_environment

    def command(code):
        return subprocess.run([ps, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", code],
                              capture_output=True, text=True, timeout=120, env=powershell_environment(ps))

    initial_result = command("Import-Module ServerManager; Get-WindowsFeature Web-Server,DNS | Select-Object Name,Installed | ConvertTo-Json -Compress")
    initial = json.loads(initial_result.stdout) if initial_result.returncode == 0 else []
    services_before = command("Get-Service W3SVC,DNS -ErrorAction SilentlyContinue | Select-Object Name,@{n='Status';e={[string]$_.Status}},@{n='StartType';e={[string]$_.StartType}} | ConvertTo-Json -Compress")
    before = json.loads(services_before.stdout) if services_before.stdout.strip() else []
    if isinstance(before, dict):
        before = [before]
    tasks = [{"id": "features", "host": "target", "recipe": "windows-features", "requires": [],
              "estimate_seconds": 600, "timeout_seconds": 900,
              "options": {"features": ["Web-Server", "DNS"]}}]
    tasks.append({"id": "web-service", "host": "target", "recipe": "windows-service", "requires": ["features"],
                  "options": {"service": "W3SVC", "enable": True}})
    tasks.append({"id": "dns-service", "host": "target", "recipe": "windows-service", "requires": ["features"],
                  "options": {"service": "DNS", "enable": True}})
    marker = "sentinel-native-windows-setup-v1"
    header = "$ErrorActionPreference = 'Stop'\n"
    site_check = header + f"Import-Module WebAdministration\nif ((Get-Website -Name '{site}').State -ne 'Started') {{ exit 10 }}\nif ((Get-Content -Raw -LiteralPath '{base}\\index.txt').Trim() -ne '{marker}') {{ exit 10 }}\nexit 0\n"
    site_apply = header + f"""Import-Module WebAdministration
if (Test-Path -LiteralPath '{base}') {{ throw 'Fixture site path already exists' }}
New-Item -ItemType Directory -Path '{base}' | Out-Null
Set-Content -LiteralPath '{base}\\index.txt' -Value '{marker}' -Encoding Ascii
$acl = Get-Acl -LiteralPath '{base}'
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule('IIS_IUSRS','ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($rule)
$anonymousRule = New-Object System.Security.AccessControl.FileSystemAccessRule('IUSR','ReadAndExecute','ContainerInherit,ObjectInherit','None','Allow')
$acl.AddAccessRule($anonymousRule)
Set-Acl -LiteralPath '{base}' -AclObject $acl
New-WebAppPool -Name '{site}' | Out-Null
New-Website -Name '{site}' -Port {port} -IPAddress '127.0.0.1' -PhysicalPath '{base}' -ApplicationPool '{site}' | Out-Null
Start-Website -Name '{site}'
exit 0
"""
    tasks.append(runbook(root, "website", site_check, site_apply, requires=["web-service", "zone"], service="W3SVC"))
    dns_check = header + f"""Import-Module DnsServer
$records = @(Get-DnsServerResourceRecord -ZoneName '{zone}' -Name www -RRType A)
if ($records.Count -ne 1 -or $records[0].RecordData.IPv4Address.IPAddressToString -ne '127.0.0.1') {{ exit 10 }}
exit 0
"""
    dns_apply = header + f"""Import-Module DnsServer
if (Get-DnsServerZone -Name '{zone}' -ErrorAction SilentlyContinue) {{ throw 'Fixture zone already exists' }}
Add-DnsServerPrimaryZone -Name '{zone}' -ZoneFile '{zone}.dns' -DynamicUpdate None
Add-DnsServerResourceRecordA -Name www -ZoneName '{zone}' -IPv4Address '127.0.0.1'
exit 0
"""
    tasks.append(runbook(root, "zone", dns_check, dns_apply, requires=["dns-service"], service="DNS"))
    services = [
        manifest("W3SVC", "http", port, [{"kind": "http", "target": f"http://127.0.0.1:{port}/index.txt", "expected_body": marker, "expected_status": [200]}]),
        manifest("DNS", "dns", 53, [{"kind": "dns", "target": "127.0.0.1", "query": "www." + zone, "record_type": "A", "expected_answers": ["127.0.0.1"]}]),
    ]

    def identities():
        result = command("Get-CimInstance Win32_Service -Filter \"Name='W3SVC' OR Name='DNS'\" | Select-Object Name,ProcessId | ConvertTo-Json -Compress")
        return json.loads(result.stdout) if result.stdout.strip() else []

    def cleanup():
        code = header + f"""Import-Module WebAdministration -ErrorAction SilentlyContinue
if (Get-Website -Name '{site}' -ErrorAction SilentlyContinue) {{ Remove-Website -Name '{site}' }}
if (Test-Path 'IIS:\\AppPools\\{site}') {{ Remove-WebAppPool -Name '{site}' }}
Import-Module DnsServer -ErrorAction SilentlyContinue
if (Get-DnsServerZone -Name '{zone}' -ErrorAction SilentlyContinue) {{ Remove-DnsServerZone -Name '{zone}' -Force }}
if (Test-Path -LiteralPath '{base}') {{ Remove-Item -LiteralPath '{base}' -Recurse -Force }}
"""
        original = {x["Name"]: x for x in before}
        for name in ["W3SVC", "DNS"]:
            previous = original.get(name)
            if not previous or previous["Status"] != "Running":
                code += f"Stop-Service -Name '{name}' -Force -ErrorAction SilentlyContinue\n"
            if previous:
                code += f"Set-Service -Name '{name}' -StartupType {previous['StartType']}\n"
        result = command(code + "exit 0\n")
        return {"verified": result.returncode == 0 and not base.exists(),
                "server_features_retained_until_runner_disposal": True}

    # Stop existing services only on this explicitly gated ephemeral runner;
    # record the original state and restore it in cleanup.
    stopped = command("Stop-Service W3SVC,DNS -Force -ErrorAction SilentlyContinue; exit 0")
    if stopped.returncode:
        raise RuntimeError("could not establish native Windows starting condition")
    return tasks, services, initial, identities, cleanup, []


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.name == "nt":
        from sentinel_blue.windows_native_range_lab import validate_runner_environment
    else:
        from sentinel_blue.native_range_lab import validate_runner_environment
    validate_runner_environment()
    report = {"status": "failed", "version": __version__, "runtime_sha256": hashlib.sha256(args.runtime.read_bytes()).hexdigest(),
              "scope": "one disposable native host per OS; loopback service checks",
              "full_competition_readiness_proven": False}
    with tempfile.TemporaryDirectory(prefix="sentinel-setup-input-") as directory:
        root = Path(directory)
        suffix = uuid.uuid4().hex[:10]
        builder = windows_inputs if os.name == "nt" else linux_inputs
        tasks, services, initial, identities, cleanup, secrets = builder(root, suffix)
        report["initial_packages_or_features"] = initial
        report["initial_scored_service_state"] = "owned instances absent; Windows base services stopped if present"
        try:
            inventory = profile_inventory(args.runtime, tasks, services)
            inventory_path = root / "inventory.json"
            write_private_json(inventory_path, inventory)
            profile = EventProfile.from_dict(inventory["event_profile"])
            plan = compile_plan(inventory, profile, root)
            command = [sys.executable, str(args.runtime.absolute()), "setup", "--inventory", str(inventory_path),
                       "--execute", "--approve-plan", plan_digest(plan), "--state-dir", str(root / "state"),
                       "--range-deployment", "--output", str(root / "result.json")]
            started = time.monotonic()
            result = subprocess.run(command, capture_output=True, text=True, timeout=1845)
            report["timed_command_seconds"] = round(time.monotonic() - started, 3)
            if (root / "result.json").exists():
                report["setup"] = read_private_json(root / "result.json")
            else:
                error = result.stderr[-3000:]
                for secret in secrets:
                    error = error.replace(secret, "[redacted]")
                report["error"] = error
            if result.returncode != 0:
                # Only the owned fixture checks are rerun. Their outputs are
                # sanitized and bounded to diagnose native configuration errors.
                diagnostics = {}
                for task in plan["tasks"]:
                    if report.get("setup", {}).get("tasks", {}).get(task["id"], {}).get("status") in {"failed", "uncertain", "changed"}:
                        record = report["setup"]["tasks"][task["id"]]
                        log_name = record.get("apply", {}).get("output_log")
                        if log_name:
                            private_log = root / "state/private-command-output" / log_name
                            if private_log.is_file():
                                text = private_log.read_text(errors="replace")[-4000:]
                                for secret in secrets:
                                    text = text.replace(secret, "[redacted]")
                                diagnostics[task["id"]] = {"apply_output": text}
                        if os.name == "posix":
                            check = subprocess.run(["bash", "-se"], input=task["check"], capture_output=True, text=True, timeout=30)
                            text = (check.stdout + check.stderr)[-2000:]
                            for secret in secrets:
                                text = text.replace(secret, "[redacted]")
                            diagnostics.setdefault(task["id"], {}).update(code=check.returncode, output=text)
                report["diagnostics"] = diagnostics
                raise RuntimeError("packaged native setup did not complete")
            before = identities()
            resumed = subprocess.run(command + ["--resume"], capture_output=True, text=True, timeout=180)
            after = identities()
            report["resume_without_service_restart"] = resumed.returncode == 0 and before == after
            report["status"] = "passed" if report["resume_without_service_restart"] and report["timed_command_seconds"] < 1800 else "failed"
        except Exception as exc:
            report.setdefault("error", type(exc).__name__ + ": " + str(exc))
        finally:
            try:
                report["cleanup"] = cleanup()
            except Exception as exc:
                report["cleanup"] = {"verified": False, "error": type(exc).__name__}
            if not report["cleanup"].get("verified"):
                report["status"] = "failed"
            write_private_json(args.output, report)
            if os.name == "posix":
                # This one sanitized report is read by the unprivileged artifact
                # uploader. Inventories, scripts, and raw logs remain private.
                args.output.chmod(0o644)
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
