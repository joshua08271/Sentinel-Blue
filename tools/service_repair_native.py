"""Owned native service faults exercising the real planner, journal and repairs.

Creates only uniquely named loopback fixtures. No existing service, credential,
firewall rule, or application data is changed. Run as administrator/root in the
authorized disposable range. This is not a competition uptime benchmark.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager, nullcontext
from dataclasses import asdict

from sentinel_blue.actions import ActionExecutor
from sentinel_blue.agent import execute_queued_action
from sentinel_blue.controller import ControllerApp
from sentinel_blue.event_profile import EventProfile
from sentinel_blue.probes import run_probes
from sentinel_blue.security_native import powershell_json
from sentinel_blue.state import ActionJournal
from sentinel_blue.store import Store


PYTHON_WORKER = r'''
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import sys
root=Path(sys.argv[1]); port=int(sys.argv[2]); poisoned=False
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        global poisoned
        poisoned = poisoned or (root/'fault.flag').exists()
        healthy = not poisoned and all((root/name).is_file() and (root/name).read_bytes()==b'trusted' for name in ('web.conf','second.conf'))
        body=b'fixture-ok' if healthy else b'fixture-unhealthy'
        self.send_response(200 if healthy else 503)
        self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass
HTTPServer(('127.0.0.1',port),Handler).serve_forever()
'''

CSHARP_WORKER = r'''
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.ServiceProcess;
using System.Text;
using System.Threading;
public class SentinelRepairFixture : ServiceBase {
    string root; int port; TcpListener listener; Thread worker; volatile bool stopping; bool poisoned;
    public SentinelRepairFixture(string[] args) { ServiceName=args[0]; root=args[1]; port=int.Parse(args[2]); }
    protected override void OnStart(string[] args) {
        stopping=false; poisoned=false; listener=new TcpListener(IPAddress.Loopback,port); listener.Start();
        worker=new Thread(Serve); worker.IsBackground=true; worker.Start();
    }
    void Serve() {
        while(!stopping) {
            try { using(TcpClient client=listener.AcceptTcpClient()) {
                client.ReceiveTimeout=3000; client.SendTimeout=3000;
                using(NetworkStream stream=client.GetStream()) {
                    byte[] request=new byte[4096]; int length=stream.Read(request,0,request.Length);
                    if(Encoding.ASCII.GetString(request,0,length).StartsWith("GET /owned-crash HTTP/")) { Environment.Exit(71); }
                    poisoned=poisoned || File.Exists(Path.Combine(root,"fault.flag"));
                    bool healthy=!poisoned;
                    foreach(string name in new string[]{"web.conf","second.conf"}) {
                        string path=Path.Combine(root,name);
                        healthy=healthy && File.Exists(path) && File.ReadAllText(path)=="trusted";
                    }
                    string body=healthy?"fixture-ok":"fixture-unhealthy";
                    string response="HTTP/1.1 "+(healthy?"200 OK":"503 Unavailable")+"\r\nContent-Length: "+body.Length+"\r\nConnection: close\r\n\r\n"+body;
                    byte[] bytes=Encoding.ASCII.GetBytes(response); stream.Write(bytes,0,bytes.Length);
                }
            }} catch(Exception) { if(!stopping) Thread.Sleep(25); }
        }
    }
    protected override void OnStop() { stopping=true; listener.Stop(); if(worker!=null) worker.Join(5000); }
    public static void Main(string[] args) { ServiceBase.Run(new SentinelRepairFixture(args)); }
}
'''


def command(args, *, expected=0):
    result = subprocess.run(args, capture_output=True, text=True, timeout=45)
    if result.returncode != expected:
        raise RuntimeError(f"native fixture command {args[0]} failed ({result.returncode}): {(result.stderr or result.stdout)[-500:]}")
    return result


def wait_state(executor, name, desired):
    until = time.monotonic() + 20
    while executor._service_state(name) != desired:
        if time.monotonic() >= until:
            raise TimeoutError("owned native fixture state transition failed")
        time.sleep(0.2)


@contextmanager
def healthy_service_watch(spec):
    """Measure scheduled HTTP responsiveness while the full collector runs."""
    from urllib.request import urlopen
    stop, ready = threading.Event(), threading.Event()
    measurements = []
    result = {}

    def watch():
        due = time.monotonic()
        while not stop.is_set():
            healthy = False
            try:
                with urlopen(spec['target'], timeout=1) as response:
                    healthy = response.status == 200 and response.read(128) == b'fixture-ok'
            except Exception:
                pass
            measurements.append((healthy, time.monotonic()-due))
            ready.set()
            due = time.monotonic()+.25
            stop.wait(.25)

    thread = threading.Thread(target=watch, daemon=True, name='owned-http-responsiveness')
    thread.start()
    try:
        if not ready.wait(3):
            raise TimeoutError('owned HTTP monitor could not begin')
        yield result
    finally:
        stop.set(); thread.join(timeout=3)
        result.update(requests=len(measurements),
                      failed=sum(not row[0] for row in measurements),
                      maximum_scheduled_response_seconds=round(max((row[1] for row in measurements), default=0),3),
                      monitor_removed=not thread.is_alive())


def scenario(root, executable, kind, checks, *, native_collection=False,
             observation_interval=0, sample_observer=None, verify_restart_event=False):
    root.mkdir(mode=0o700)
    name = "sbrepair" + secrets.token_hex(5)
    service = name if os.name == "nt" else name + ".service"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    files = [root / "web.conf", root / "second.conf"]
    for path in files:
        path.write_bytes(b"trusted")
    unit = None
    owned = False
    store = Store(":memory:")
    executor = ActionExecutor(root / "agent", allow_service_recovery=True, allow_restoration=True,
                              authorized_networks=["127.0.0.0/8"])
    specs = [{"name": "native-health", "kind": "http", "target": f"http://127.0.0.1:{port}/health",
              "expected_status": [200], "expected_body": "fixture-ok", "timeout": 1}]
    manifest = {"service_id": service, "host": "repair-native", "protocol": "http", "port": port,
                "implementation": "owned loopback acceptance fixture", "dependencies": [], "required_accounts": [],
                "required_files": [str(path) for path in files], "required_data": [], "credential_source": "",
                "expected_transactions": specs, "local_checks": [],
                "allowed_automatic_actions": ["repair_service", "capture_restore_point"],
                "approval_actions": ["rollback_service_repair"], "backup_method": "approved local files",
                "recovery_method": "coordinated repair", "rollback_method": "journal",
                "repair_policy": {"restore_files": [str(path) for path in files], "restart_unhealthy": True,
                                  "validation_timeout_seconds": 5 if kind == "failed_validation" else 30}}
    raw = copy.deepcopy(EventProfile.testing().raw)
    raw.update(profile_id="repair-native", services=[manifest], services_confirmed=True)
    if native_collection:
        from sentinel_blue.collectors import integrity_watch_paths
        # Full collection includes the standard host watch list. Declare its
        # capture-only contract in advance; repair authority remains limited to
        # the two owned service files above.
        extra = []
        if os.name != 'nt':
            extra.append(str(Path('/etc/systemd/system')/service))
        host_baseline = copy.deepcopy(manifest)
        host_baseline.update(service_id='native-host-baseline',
                             required_files=[path for path in integrity_watch_paths(extra)
                                             if path not in manifest['required_files']],
                             allowed_automatic_actions=['capture_restore_point'], approval_actions=[])
        host_baseline.pop('repair_policy')
        raw['services'].append(host_baseline)
    profile = EventProfile.from_dict(raw)
    app = ControllerApp(store, "t" * 32, operator_token="o" * 32, event_profile=profile, auto_recover_services=True,
                        authorized_networks=["127.0.0.0/8"])
    journal = ActionJournal(root / "journal")
    sequence = 0

    def collect(*, healthy_during_collection=False):
        nonlocal sequence
        sequence += 1
        if native_collection:
            from sentinel_blue.collectors import collect as host_collect
            with healthy_service_watch(specs[0]) if healthy_during_collection else nullcontext({}) as responsiveness:
                sample = host_collect('repair-native', probe_specs=specs,
                                      authorized_networks=['127.0.0.0/8'],
                                      integrity_paths=[str(path) for path in files]).as_dict()
            if responsiveness:
                checks.setdefault('healthy_collection_responsiveness', []).append(responsiveness)
                checks['healthy_service_responsive_during_collection'] = all(
                    row['requests']>=2 and not row['failed'] and row['monitor_removed']
                    and row['maximum_scheduled_response_seconds']<=2
                    for row in checks['healthy_collection_responsiveness'])
            sample['sequence'] = sequence
            if sample_observer is not None:
                sample_observer(sample)
            return sample
        observed_at = time.time()
        integrity = []
        for path in files:
            data = executor.restore_points._read_target_if_present(path)
            if data is not None:
                content, metadata = data
                integrity.append({"path": str(path), "sha256": hashlib.sha256(content).hexdigest(),
                                  "security_descriptor_sha256": executor.restore_points._metadata_security_descriptor_sha256(metadata),
                                  "readable": True, "size": len(content), "modified_at": path.stat().st_mtime})
        return {"agent_id": "repair-native", "hostname": socket.gethostname(), "platform": "Windows" if os.name == "nt" else "Linux",
                "observed_at": observed_at, "boot_id": "owned-fixture-" + name, "sequence": sequence,
                "collector_errors": [], "accounts": [], "sessions": [], "interfaces": [], "integrity": integrity,
                "services": [{"name": service, "state": executor._service_state(service), "start_mode": "manual"}],
                "probes": [asdict(item) for item in run_probes(specs, ["127.0.0.0/8"])]}

    def execute(action, telemetry):
        result = execute_queued_action(journal, executor, asdict(action), telemetry,
                                       {"action_safe": not telemetry.get('collector_errors')}, profile)
        app.complete_action({**result, "action_id": action.action_id}, "repair-native")
        return result

    try:
        if os.name == "nt":
            command(["sc.exe", "query", service], expected=1060)
            command(["sc.exe", "create", service, "binPath=", subprocess.list2cmdline([str(executable), service, str(root), str(port)]), "start=", "demand"])
            owned = True
        else:
            unit = Path("/etc/systemd/system") / service
            code = f'[Unit]\nDescription=Sentinel owned repair fixture\n[Service]\nExecStart={sys.executable} {executable} {root} {port}\nRestart=no\n'
            with unit.open("x") as stream:
                stream.write(code)
            owned = True
            unit.chmod(0o600)
            command(["systemctl", "daemon-reload"])
        executor._set_service_state(service, "running")
        wait_state(executor, service, "running")
        if verify_restart_event:
            if os.name != "nt":
                raise ValueError('restart event fixture requires native Windows SCM')
            from urllib.error import URLError
            from urllib.request import urlopen
            from http.client import RemoteDisconnected
            try:
                with urlopen(f'http://127.0.0.1:{port}/owned-crash', timeout=5):
                    raise ValueError('owned crash request did not stop its service')
            except (URLError, RemoteDisconnected, ConnectionResetError):
                pass
            wait_state(executor, service, 'stopped')
            executor._set_service_state(service, 'running')
            wait_state(executor, service, 'running')
        until = time.monotonic() + 15
        # Native "running" can precede an application's listening socket. Start
        # the responsiveness measurement only after a successful transaction.
        while not all(row.healthy for row in run_probes(specs, ['127.0.0.0/8'])):
            if time.monotonic() >= until:
                raise TimeoutError('owned service did not initially pass HTTP validation')
            time.sleep(0.2)
        baseline = collect(healthy_during_collection=native_collection)
        while not all(row["healthy"] for row in baseline["probes"]):
            if time.monotonic() >= until:
                raise TimeoutError("owned service did not initially pass HTTP validation")
            time.sleep(0.2)
            baseline = collect(healthy_during_collection=native_collection)
        if verify_restart_event:
            matches = [row for row in baseline['services'] if row['name'] == service]
            checks[kind + '_native_restart_event_detected'] = len(matches)==1 and matches[0]['restart_count']==1
            if not checks[kind + '_native_restart_event_detected']:
                raise ValueError('owned service crash was absent from native restart evidence')
        checks[kind + "_initially_healthy"] = True
        app.ingest(baseline)
        approval = app.approve_baseline("repair-native")
        action = next(row for row in store.pending_actions("repair-native") if row.action_id == approval["restore_point_action_id"])
        receipt = execute(action, baseline)
        checks[kind + "_approved_backup_captured"] = receipt["success"] and store.baseline_status("repair-native") == "approved"
        if not checks[kind + "_approved_backup_captured"]:
            raise ValueError("native baseline promotion failed")
        if kind == "running_unhealthy":
            (root / "fault.flag").write_text("owned memory fault")
            unhealthy = collect()  # Service retains a failed state until restarted.
            (root / "fault.flag").unlink()
            if all(row["healthy"] for row in unhealthy["probes"]):
                raise ValueError("native running-service fault was not active")
        else:
            executor._set_service_state(service, "stopped")
            wait_state(executor, service, "stopped")
            if kind == "missing_file":
                files[0].unlink()
            else:
                for path in files:
                    path.write_bytes(b"damaged")
            if kind == "failed_validation":
                (root / "fault.flag").write_text("owned persistent validation failure")
        started = time.monotonic()
        first = collect()
        app.ingest(first)
        checks[kind + "_first_observation_did_not_mutate"] = not any(row.action_type == "repair_service" for row in store.pending_actions("repair-native"))
        if observation_interval:
            time.sleep(observation_interval)
        second = collect()
        app.ingest(second)
        action = next((row for row in store.pending_actions("repair-native") if row.action_type == "repair_service"), None)
        if action is None:
            raise ValueError('native repair was held: '+str(app.service_recovery_planner.status())[:600])
        result = execute(action, second)
        elapsed = round(time.monotonic() - started, 3)
        if kind == "failed_validation":
            checks[kind + "_exact_rollback"] = (result["success"] is False and result.get("rolled_back") is True
                                                and executor._service_state(service) == "stopped"
                                                and all(path.read_bytes() == b"damaged" for path in files))
        else:
            checks[kind + "_autonomous_repair_passed"] = (result["success"] is True and result.get("stable_health") is True
                                                           and all(path.read_bytes() == b"trusted" for path in files)
                                                           and all(row["healthy"] for row in collect(healthy_during_collection=native_collection)["probes"]))
        if not result["success"] and kind != "failed_validation":
            raise ValueError(result["message"])
        return elapsed
    finally:
        store.close()
        if owned:
            # Cleanup is independent of Sentinel's result and verified natively.
            state = executor._service_state(service)
            if state != "stopped":
                executor._set_service_state(service, "stopped")
                wait_state(executor, service, "stopped")
            if os.name == "nt":
                command(["sc.exe", "delete", service])
                command(["sc.exe", "query", service], expected=1060)
            else:
                if unit.read_text() != code:
                    raise ValueError("owned fixture unit changed before cleanup")
                unit.unlink()
                command(["systemctl", "daemon-reload"])
            checks[kind + "_fixture_removed"] = True


def rehearse():
    checks, timings, errors = {}, {}, {}
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="service-repair-", dir=Path(__file__).resolve().parent) as directory:
        root = Path(directory)
        executable = root / ("owned-service.exe" if os.name == "nt" else "owned-service.py")
        if os.name == "nt":
            powershell_json("Add-Type -TypeDefinition $p.source -OutputAssembly $p.output -OutputType WindowsApplication -ReferencedAssemblies System.ServiceProcess,System; 'true'",
                            {"source": CSHARP_WORKER, "output": str(executable)})
        else:
            executable.write_text(PYTHON_WORKER)
            executable.chmod(0o700)
        for kind in ("damaged_files", "missing_file", "running_unhealthy", "failed_validation"):
            try:
                timings[kind] = scenario(root / kind, executable, kind, checks)
            except Exception as exc:
                checks[kind + "_completed"] = False
                errors[kind] = f"{type(exc).__name__}: {str(exc)[:450]}"
    return {"passed": bool(checks) and all(checks.values()) and not errors,
            "checks": checks, "repair_seconds": timings, "errors": errors,
            "seconds": round(time.monotonic() - started, 3), "full_competition_readiness_proven": False}


if __name__ == "__main__":
    print(json.dumps(rehearse(), indent=2))
