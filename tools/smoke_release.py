"""Start the built zipapp controller and agent and verify the local dashboard."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.request import Request, urlopen


def _port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _stop_process(process: subprocess.Popen[str]) -> None:
    """Stop a smoke-test child without relying on unsupported Windows SIGINT."""
    if process.poll() is not None:
        return
    if os.name == "nt":
        process.terminate()
    else:
        process.send_signal(signal.SIGINT)
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=3)


def _operator_headers(
    token: str,
    *,
    principal_id: str,
    credential_epoch: int,
    method: str,
    target: str,
    body: bytes = b"",
    request_timestamp: int | None = None,
) -> dict[str, str]:
    """Sign one exact operator request without importing the source tree."""
    timestamp = str(
        int(time.time()) if request_timestamp is None else request_timestamp
    )
    request_id = secrets.token_hex(16)
    canonical = b"\x00".join(
        (
            b"sentinel-blue-operator-request-v1",
            principal_id.encode("ascii"),
            str(credential_epoch).encode("ascii"),
            timestamp.encode("ascii"),
            request_id.encode("ascii"),
            method.encode("ascii"),
            target.encode("ascii"),
            hashlib.sha256(body).hexdigest().encode("ascii"),
        )
    )
    signature = hmac.new(
        token.encode("ascii"), canonical, hashlib.sha256
    ).hexdigest()
    return {
        "X-SB-Operator-Version": "1",
        "X-SB-Operator-Principal": principal_id,
        "X-SB-Operator-Epoch": str(credential_epoch),
        "X-SB-Operator-Timestamp": timestamp,
        "X-SB-Operator-Request-ID": request_id,
        "X-SB-Operator-Signature": signature,
    }


def _diagnose_enrollment_rejection(
    runtime: Path,
    origin: str,
    event_profile: Path,
    token_file: Path,
    agent_id: str,
    ca_file: Path,
) -> str:
    """Return only the controller-authenticated bounded rejection reason."""
    program = """
import json
import platform
import socket
import sys
from pathlib import Path
from urllib.error import HTTPError

sys.path.insert(0, sys.argv[1])
from sentinel_blue.agent import AgentClient
from sentinel_blue.event_profile import load_event_profile

profile = load_event_profile(sys.argv[3])
ticket = json.loads(Path(sys.argv[4]).read_text(encoding='utf-8'))['token']
client = AgentClient(
    sys.argv[2], ticket, sys.argv[5], ca_file=sys.argv[6],
    profile_id=profile.profile_id, profile_fingerprint=profile.fingerprint,
)
try:
    client.request_enrollment(
        socket.gethostname() or sys.argv[5],
        f'{platform.system()} {platform.release()}'.strip() or sys.platform,
    )
except HTTPError as error:
    print(getattr(error, 'sentinel_blue_error', 'unverified controller rejection'))
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            program,
            str(runtime),
            origin,
            str(event_profile),
            str(token_file),
            agent_id,
            str(ca_file),
        ],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    reason = result.stdout.strip()
    return reason[:256] if reason else "no authenticated rejection reason available"


class _SlowProbeFixture:
    """Hold one owned loopback request across a real controller SIGTERM."""

    def __init__(self) -> None:
        self.delay_next = threading.Event()
        self.entered = threading.Event()
        self.release = threading.Event()
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass

            def do_GET(self):  # noqa: N802
                if fixture.delay_next.is_set():
                    fixture.delay_next.clear()
                    fixture.entered.set()
                    fixture.release.wait(4.5)
                body = b"lifecycle healthy"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)


def smoke(runtime: Path, *, exercise_lifecycle: bool = False,
          exercise_crash_resume: bool = False) -> dict[str, object]:
    exercise_lifecycle = exercise_lifecycle or exercise_crash_resume
    if exercise_lifecycle and os.name != "posix":
        raise ValueError("the SIGTERM/SIGKILL lifecycle smoke requires POSIX")
    if not runtime.is_file():
        raise ValueError(f"runtime not found: {runtime}")
    version_result = subprocess.run(
        [sys.executable, str(runtime), "--version"],
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    prefix = "sentinel-blue "
    if version_result.returncode != 0 or not version_result.stdout.strip().startswith(prefix):
        raise ValueError("runtime did not report a valid Sentinel Blue version")
    runtime_version = version_result.stdout.strip().removeprefix(prefix)
    expected_runtime = hashlib.sha256(runtime.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="sentinel-blue-release-smoke-") as directory, ExitStack() as cleanup:
        # GitHub's Windows runner exposes TEMP through an 8.3 alias. Resolve the
        # already-created private fixture root before exercising the runtime's
        # intentional anti-alias state-tree gate.
        root = Path(directory).resolve(strict=True)
        token = secrets.token_urlsafe(48)
        controller_token = root / "controller-token.json"
        controller_token.write_text(json.dumps({"token": token}), encoding="utf-8")
        agent_token = root / "agent-token.json"
        agent_token.write_text(json.dumps({"token": token}), encoding="utf-8")
        operator_secret = secrets.token_urlsafe(48)
        operator_token = root / "operator-token.txt"
        operator_token.write_text(operator_secret, encoding="utf-8")
        operator_principal = "release-smoke"
        # recovery-init creates the database before controller startup, so the
        # first signing authority deliberately starts above the bearer-era floor.
        operator_epoch = 2
        recovery_key = root / "recovery.key"
        recovery_key.write_bytes(secrets.token_bytes(48))
        recovery_anchor = root / "recovery.anchor"
        controller_database = root / "controller.db"
        backup_directory = root / "backups"
        backup_directory.mkdir(mode=0o700)
        controller_cert = root / "controller.crt"
        controller_key = root / "controller.key"
        if shutil.which('openssl'):
            certificate = subprocess.run(
                [
                    "openssl",
                    "req",
                    "-x509",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-days",
                    "1",
                    "-subj",
                    "/CN=127.0.0.1",
                    "-addext",
                    "subjectAltName=IP:127.0.0.1",
                    "-keyout",
                    str(controller_key),
                    "-out",
                    str(controller_cert),
                ],
                stdin=subprocess.DEVNULL,
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if certificate.returncode != 0:
                raise RuntimeError(
                    certificate.stderr.strip() or "OpenSSL could not create the smoke trust anchor"
                )
        else:
            # The Windows embeddable interpreter need not have OpenSSL on PATH.
            # Use the same declared test dependency as native opening setup.
            import datetime
            import ipaddress
            from cryptography import x509
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import rsa
            from cryptography.x509.oid import NameOID
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])
            now = datetime.datetime.now(datetime.timezone.utc)
            cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                    .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
                    .not_valid_after(now+datetime.timedelta(days=1))
                    .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), critical=False)
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                    .sign(key, hashes.SHA256()))
            controller_cert.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
            controller_key.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
        for private_file in (
            controller_token,
            agent_token,
            operator_token,
            recovery_key,
            controller_key,
        ):
            private_file.chmod(0o600)
        controller_ca_sha256 = hashlib.sha256(controller_cert.read_bytes()).hexdigest()
        event_profile = root / "event-profile.json"
        event_profile.write_text(
            json.dumps(
                {
                    "profile_version": 1,
                    "profile_id": "release-smoke",
                    "competition": "custom",
                    "environment": "live-competition",
                    "autonomy_mode": "guarded-autonomous" if exercise_crash_resume else "approval-based",
                    "architecture": {
                        "single_live_scored_network": True,
                        "blue_staging_non_authoritative": True,
                    },
                    "scope": {
                        "authorized_networks": ["127.0.0.0/8"],
                        "authorized_hosts": ["127.0.0.1"],
                        "controller_ingress_hosts": ["127.0.0.1"],
                        "excluded_hosts": [],
                        "approved_deployment_paths": [str(root)],
                    },
                    "deployment": {"approved_routes": ["local"]},
                    "capabilities": {
                        "external_controller": True,
                        "in_place_repair": True,
                        "structured_rollback": True,
                        "configuration_backups": True,
                        "network_monitoring": True,
                        "guarded_autonomy": bool(exercise_crash_resume),
                    },
                    "organizer_exceptions": [],
                    "allowed_automatic_actions": [],
                    "official_identities": [
                        {
                            "agent_id": "release-smoke-agent",
                            "name": "smoke-official",
                            "class": "organizer",
                            "source": "smoke",
                        }
                    ],
                    "services": [
                        {
                            "service_id": "controller-smoke", "host": "127.0.0.1",
                            "protocol": "https", "port": 8765, "implementation": "release smoke",
                            "dependencies": [], "required_accounts": [], "required_files": [],
                            "required_data": [], "credential_source": "", "expected_transactions": [{"kind": "http"}],
                            "local_checks": ["controller health"], "allowed_automatic_actions": [],
                            "approval_actions": [], "backup_method": "temporary fixture",
                            "recovery_method": "restart disposable fixture", "rollback_method": "delete disposable fixture"
                        }
                    ],
                    "services_confirmed": True,
                    "recovery": {"baseline_promotion_delay_seconds": 0,
                                 "resume_after_controller_crash": bool(exercise_crash_resume)},
                    "approval": {"status": "approved", "approved_by": "release-smoke"},
                    "release": {
                        "version": runtime_version, "approved": True, "sha256": expected_runtime,
                        "controller_ca_sha256": controller_ca_sha256,
                        "public_url": f"https://example.invalid/sentinel-blue-{runtime_version}.pyz",
                        "frozen": True, "submitted_to_officials": True,
                        "submission_approved": True, "public_and_equal_access": True,
                        "cloud_processing": False, "external_telemetry_export": False,
                        "public_days_before_event": 0, "submitted_days_before_event": 0
                    },
                }
            ),
            encoding="utf-8",
        )
        event_profile.chmod(0o600)
        recovery_init = subprocess.run(
            [
                sys.executable,
                str(runtime),
                "recovery-init",
                "--database",
                str(controller_database),
                "--recovery-key-file",
                str(recovery_key),
                "--recovery-anchor",
                str(recovery_anchor),
            ],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if recovery_init.returncode != 0:
            raise RuntimeError(
                recovery_init.stderr.strip()
                or "built runtime could not initialize authenticated recovery"
            )
        normalized_profile = json.loads(event_profile.read_text(encoding="utf-8"))
        profile_fingerprint = hashlib.sha256(
            json.dumps(
                normalized_profile, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        smoke_agent_id = "release-smoke-agent"
        enrollment_message = (
            b"sentinel-blue-enrollment-ticket-v1\x00"
            + profile_fingerprint.encode("ascii")
            + b"\x00"
            + smoke_agent_id.encode("ascii")
        )
        enrollment_ticket = hmac.new(
            token.encode("ascii"), enrollment_message, hashlib.sha256
        ).hexdigest()
        agent_token.write_text(
            json.dumps({"token": enrollment_ticket}), encoding="utf-8"
        )
        agent_token.chmod(0o600)
        port = _port()
        origin = f"https://127.0.0.1:{port}"
        client_tls = ssl.create_default_context(cafile=str(controller_cert))
        extra_controller_args = []
        lifecycle_fixture = None
        if exercise_lifecycle:
            lifecycle_fixture = _SlowProbeFixture()
            cleanup.callback(lifecycle_fixture.close)
            probe_config = root / "lifecycle-probes.json"
            probe_config.write_text(json.dumps({"probes": [{
                "name": "lifecycle-probe", "kind": "http",
                "target": f"http://127.0.0.1:{lifecycle_fixture.server.server_port}/health",
                "timeout": 10.0, "expected_body": "lifecycle healthy",
            }]}), encoding="utf-8")
            probe_config.chmod(0o600)
            extra_controller_args = ["--probe-config", str(probe_config), "--probe-interval", "5"]
        controller = subprocess.Popen(
            [
                sys.executable,
                str(runtime),
                "controller",
                "--bind",
                "127.0.0.1",
                "--port",
                str(port),
                "--event-profile",
                str(event_profile),
                "--token-file",
                str(controller_token),
                "--database",
                str(controller_database),
                "--operator-token-file",
                str(operator_token),
                "--operator-principal-id",
                operator_principal,
                "--operator-credential-epoch",
                str(operator_epoch),
                "--recovery-key-file",
                str(recovery_key),
                "--recovery-anchor",
                str(recovery_anchor),
                "--tls-cert",
                str(controller_cert),
                "--tls-key",
                str(controller_key),
                "--tls-ca-file",
                str(controller_cert),
                "--maintenance-interval",
                "5",
                "--log-level",
                "WARNING",
                *extra_controller_args,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

        def operator_request(target: str, payload=None):
            with urlopen(origin + "/api/v1/operator/auth-info", timeout=3, context=client_tls) as response:
                metadata = json.loads(response.read())
            body = b"" if payload is None else json.dumps(payload).encode("utf-8")
            method = "GET" if payload is None else "POST"
            headers = _operator_headers(
                operator_secret, principal_id=operator_principal,
                credential_epoch=operator_epoch, method=method, target=target,
                body=body, request_timestamp=max(int(time.time()), int(metadata["request_not_before"])),
            )
            headers["Content-Type"] = "application/json"
            request = Request(origin + target, data=None if payload is None else body,
                              headers=headers, method=method)
            with urlopen(request, timeout=5, context=client_tls) as response:
                return json.loads(response.read())

        def restart_controller():
            nonlocal controller
            command = controller.args
            for stream in (controller.stdout, controller.stderr):
                if stream:
                    stream.close()
            controller = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if controller.poll() is not None:
                    raise RuntimeError("controller exited during lifecycle restart")
                try:
                    return operator_request("/api/v1/dashboard")["controller"]["governance"]
                except OSError:
                    time.sleep(0.05)
            raise RuntimeError("controller did not become healthy after lifecycle restart")

        try:
            for _ in range(100):
                try:
                    with urlopen(
                        f"{origin}/api/v1/health", timeout=1, context=client_tls
                    ) as response:
                        if response.status == 200:
                            break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("built controller did not become healthy")
            agent_command = [
                    sys.executable,
                    str(runtime),
                    "agent",
                    "--controller",
                    origin,
                    "--event-profile",
                    str(event_profile),
                    "--token-file",
                    str(agent_token),
                    "--agent-id",
                    smoke_agent_id,
                    "--ca-file",
                    str(controller_cert),
                    "--state-dir",
                    str(root / "agent-state"),
                    "--expected-package-sha256",
                    expected_runtime,
                    "--once",
                    "--log-level",
                    "WARNING",
                ]
            agent = subprocess.run(
                agent_command,
                text=True,
                capture_output=True,
                timeout=60,
                check=False,
            )
            with urlopen(
                f"{origin}/api/v1/operator/auth-info",
                timeout=2,
                context=client_tls,
            ) as response:
                operator_metadata = json.loads(response.read())
            if (
                operator_metadata.get("principal_id") != operator_principal
                or operator_metadata.get("credential_epoch") != operator_epoch
            ):
                raise RuntimeError("built controller reported the wrong operator authority")
            dashboard_target = "/api/v1/dashboard"
            request = Request(
                origin + dashboard_target,
                headers=_operator_headers(
                    operator_secret,
                    principal_id=operator_principal,
                    credential_epoch=operator_epoch,
                    method="GET",
                    target=dashboard_target,
                    request_timestamp=max(
                        int(time.time()),
                        int(operator_metadata["request_not_before"]),
                    ),
                ),
            )
            with urlopen(request, timeout=3, context=client_tls) as response:
                dashboard = json.loads(response.read())
            enrolled_agents = [item for item in dashboard.get("agents", [])
                               if item["agent_id"] != "sentinel-relay-probes"]
            if agent.returncode != 0 or len(enrolled_agents) != 1:
                rejection = _diagnose_enrollment_rejection(
                    runtime,
                    origin,
                    event_profile,
                    agent_token,
                    smoke_agent_id,
                    controller_cert,
                )
                raise RuntimeError(
                    f"agent smoke failed: exit={agent.returncode}, "
                    f"controller_reason={rejection}, stderr={agent.stderr[-4000:]}"
                )
            telemetry = enrolled_agents[0]
            lifecycle_result = {}
            if lifecycle_fixture:
                fixture_mode = "guarded-autonomous" if exercise_crash_resume else "approval-based"
                operator_request("/api/v1/governance/mode", {"mode": fixture_mode})
                before = operator_request("/api/v1/governance/resume", {})
                if before["autonomy_mode"] != fixture_mode or before["emergency_stopped"]:
                    raise RuntimeError("lifecycle fixture did not activate its authorized governance")
                lifecycle_fixture.delay_next.set()
                if not lifecycle_fixture.entered.wait(10):
                    raise RuntimeError("controller did not start the delayed lifecycle probe")
            if os.name == "posix":
                # systemd uses SIGTERM for ordinary stops and restarts. This must
                # complete a clean session rather than masquerading as a crash.
                controller.terminate()
                controller.wait(timeout=30)
                with sqlite3.connect(controller_database) as connection:
                    dirty = connection.execute(
                        "SELECT 1 FROM controller_state WHERE state_key='controller_unclean_session'"
                    ).fetchone()
                if controller.returncode != 0 or dirty:
                    raise RuntimeError("normal SIGTERM did not close the controller session cleanly")
                if lifecycle_fixture:
                    after = restart_controller()
                    if after != before:
                        raise RuntimeError("clean restart changed approved controller governance")
                    controller.kill()
                    controller.wait(timeout=5)
                    offline_result = {}
                    if exercise_crash_resume:
                        offline_started = time.monotonic()
                        offline_agent = subprocess.run(
                            agent_command, text=True, capture_output=True, timeout=60,
                        )
                        queued = sorted((root / "agent-state" / "telemetry-spool").glob("*.json"))
                        if offline_agent.returncode != 0 or not queued:
                            raise RuntimeError("enrolled agent did not retain native telemetry while controller was down")
                        offline_result = {
                            "offline_native_sample_spooled": True,
                            "offline_agent_cycle_seconds": round(time.monotonic() - offline_started, 3),
                        }
                    recovery_started = time.monotonic()
                    crashed = restart_controller()
                    recovery_seconds = time.monotonic() - recovery_started
                    if exercise_crash_resume:
                        if crashed != before:
                            raise RuntimeError("authorized crash resume changed committed governance")
                        reconnect_started = time.monotonic()
                        reconnected = subprocess.run(
                            agent_command, text=True, capture_output=True, timeout=60,
                        )
                        if reconnected.returncode != 0 or list((root / "agent-state" / "telemetry-spool").glob("*.json")):
                            raise RuntimeError("agent did not drain its offline spool after controller restart")
                        with sqlite3.connect(controller_database) as connection:
                            sequence = connection.execute(
                                "SELECT last_sequence FROM agents WHERE agent_id=?", (smoke_agent_id,),
                            ).fetchone()[0]
                        if sequence < 3:
                            raise RuntimeError("post-recovery telemetry did not advance the authenticated sequence")
                        offline_result.update(
                            offline_spool_drained=True,
                            post_recovery_native_sequence=sequence,
                            reconnect_agent_cycle_seconds=round(time.monotonic() - reconnect_started, 3),
                        )
                        stopped = operator_request("/api/v1/governance/emergency-stop", {})
                        controller.kill()
                        controller.wait(timeout=5)
                        if restart_controller() != stopped:
                            raise RuntimeError("crash resume cleared a committed emergency stop")
                    elif (crashed["autonomy_mode"] != "observe" or not crashed["emergency_stopped"]
                          or crashed["governance_revision"] <= before["governance_revision"]):
                        raise RuntimeError("forced crash did not reset controller governance safely")
                    controller.terminate()
                    controller.wait(timeout=30)
                    if controller.returncode != 0:
                        raise RuntimeError("post-crash controller cleanup failed")
                    lifecycle_result = {
                        "delayed_probe_seconds": 4.5,
                        "clean_restart_governance_preserved": True,
                        "forced_crash_safe_governance": not exercise_crash_resume,
                        "authorized_crash_resume": exercise_crash_resume,
                        "crash_resume_preserved_emergency_stop": exercise_crash_resume,
                        "controller_restart_seconds": round(recovery_seconds, 3),
                        **offline_result,
                    }
            else:
                _stop_process(controller)
            backup = subprocess.run(
                [
                    sys.executable,
                    str(runtime),
                    "recovery-backup",
                    "--database",
                    str(controller_database),
                    "--output-directory",
                    str(backup_directory),
                    "--recovery-key-file",
                    str(recovery_key),
                    "--recovery-anchor",
                    str(recovery_anchor),
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if backup.returncode != 0:
                raise RuntimeError(
                    backup.stderr.strip()
                    or "built runtime could not create an authenticated backup"
                )
            backup_result = json.loads(backup.stdout)
            verify = subprocess.run(
                [
                    sys.executable,
                    str(runtime),
                    "recovery-verify",
                    "--bundle",
                    str(backup_result["bundle"]),
                    "--recovery-key-file",
                    str(recovery_key),
                    "--recovery-anchor",
                    str(recovery_anchor),
                ],
                text=True,
                capture_output=True,
                timeout=30,
                check=False,
            )
            if verify.returncode != 0 or not json.loads(verify.stdout).get("verified"):
                raise RuntimeError(
                    verify.stderr.strip()
                    or "built runtime could not verify its authenticated backup"
                )
            return {
                "passed": True,
                "runtime": str(runtime.resolve()),
                "controller_version": dashboard["controller"]["version"],
                "agents": len(enrolled_agents),
                "agent_health": telemetry["health"],
                "database_integrity": dashboard["controller"]["database_integrity"],
                "agent_token_file_deleted": not agent_token.exists(),
                "runtime_integrity_pinned": True,
                "operator_requests_signed": True,
                "authenticated_recovery_verified": True,
                "sigterm_clean_shutdown": os.name == "posix",
                **lifecycle_result,
            }
        finally:
            _stop_process(controller)
            for stream in (controller.stdout, controller.stderr):
                if stream:
                    stream.close()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("runtime", type=Path)
    parser.add_argument("--exercise-lifecycle", action="store_true",
                        help="test a delayed loopback probe, clean restart, and forced crash")
    parser.add_argument("--exercise-crash-resume", action="store_true",
                        help="test profile-authorized crash resume and preservation of emergency stop")
    args = parser.parse_args()
    print(json.dumps(smoke(args.runtime, exercise_lifecycle=args.exercise_lifecycle,
                           exercise_crash_resume=args.exercise_crash_resume), indent=2))


if __name__ == "__main__":
    main()
