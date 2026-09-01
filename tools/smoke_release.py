"""Start the built zipapp controller and agent and verify the local dashboard."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.request import Request, urlopen


def _port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


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


def smoke(runtime: Path) -> dict[str, object]:
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
    with tempfile.TemporaryDirectory(prefix="sentinel-blue-release-smoke-") as directory:
        root = Path(directory)
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
                    "autonomy_mode": "approval-based",
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
                    "recovery": {"baseline_promotion_delay_seconds": 0},
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
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
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
            agent = subprocess.run(
                [
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
                ],
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
            if agent.returncode != 0 or len(dashboard.get("agents", [])) != 1:
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
            telemetry = dashboard["agents"][0]
            controller.send_signal(signal.SIGINT)
            controller.wait(timeout=5)
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
                "agents": len(dashboard["agents"]),
                "agent_health": telemetry["health"],
                "database_integrity": dashboard["controller"]["database_integrity"],
                "agent_token_file_deleted": not agent_token.exists(),
                "runtime_integrity_pinned": True,
                "operator_requests_signed": True,
                "authenticated_recovery_verified": True,
            }
        finally:
            if controller.poll() is None:
                controller.send_signal(signal.SIGINT)
                try:
                    controller.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    controller.kill()
                    controller.wait(timeout=3)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("runtime", type=Path)
    args = parser.parse_args()
    print(json.dumps(smoke(args.runtime), indent=2))


if __name__ == "__main__":
    main()
