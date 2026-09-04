"""Packaged defensive range, recovery, and throughput certification."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import socket
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any
from unittest.mock import patch
from http.client import HTTPConnection

from . import __version__
from .actions import ActionExecutor
from .adversarial_lab import authentication_boundary_campaign, protocol_fuzz, valid_payload
from .analyzers import analyze_security_events
from .controller import ControllerApp, ControllerServer, LOG
from .probes import scoped_addresses
from .policy_lab import competition_policy_campaign
from .range_lab import (
    _complete_disposable_baseline_promotion,
    _materialize_disposable_integrity,
    _windows_integrity_security_digest,
    campaign,
)
from .restoration_lab import restoration_policy_campaign
from .recovery_ops import (
    controller_recovery_status,
    create_controller_backup,
    initialize_controller_recovery,
    verify_controller_backup,
)
from .risk import RiskModel
from .state import ActionJournal, TelemetrySpool
from .store import Store


MAX_SCENARIOS = 5_000
MAX_FUZZ_ITERATIONS = 50_000
MAX_LOAD_EVENTS = 50_000


def _check(name: str, passed: bool, detail: Any) -> dict[str, Any]:
    return {"name": name, "passed": bool(passed), "detail": detail}


def _p95(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, max(0, math.ceil(len(ordered) * 0.95) - 1))]


class _CertificationHealthHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802
        body = b"ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class _CertificationTlsSocket:
    def __init__(self, handshake_error: BaseException | None = None):
        self.handshake_error = handshake_error
        self.handshakes = 0
        self.timeouts: list[float] = []

    def do_handshake(self) -> None:
        self.handshakes += 1
        if self.handshake_error is not None:
            raise self.handshake_error

    def settimeout(self, value: float) -> None:
        self.timeouts.append(value)

    def shutdown(self, _how: int) -> None:
        return

    def close(self) -> None:
        return


def _tls_worker_lifecycle_campaign() -> dict[str, Any]:
    """Exercise bounded deferred-handshake logic without claiming a native TLS range pass."""
    server = ControllerServer(
        ("127.0.0.1", 0),
        _CertificationHealthHandler,
        max_workers=1,
        max_workers_per_client=1,
        request_timeout=4.0,
    )
    server._tls_context = object()  # Only the worker lifecycle is exercised here.
    address = ("192.0.2.20", 1000)
    successful = _CertificationTlsSocket()
    failed = _CertificationTlsSocket(ssl.SSLError("certification handshake failure"))
    try:
        first_admitted = server._acquire_worker(address)
        with (
            patch.object(server, "finish_request") as finish,
            patch.object(server, "shutdown_request") as shutdown,
        ):
            server.process_request_thread(successful, address)
        first_released = server.active_connections() == {}
        second_admitted = server._acquire_worker(address)
        with patch.object(server, "shutdown_request") as failed_shutdown:
            server.process_request_thread(failed, address)
        second_released = server.active_connections() == {}
        capacity_reacquired = server._acquire_worker(address)
        if capacity_reacquired:
            server._release_worker(address)
        passed = bool(
            first_admitted
            and successful.handshakes == 1
            and successful.timeouts == [4.0]
            and finish.call_count == 1
            and shutdown.call_count == 1
            and first_released
            and second_admitted
            and failed.handshakes == 1
            and failed_shutdown.call_count == 1
            and server.connection_pressure_snapshot().get("SSLError") == 1
            and second_released
            and capacity_reacquired
        )
        return {
            "mode": "in-process deferred TLS worker lifecycle",
            "passed": passed,
            "successful_handshake": successful.handshakes == 1,
            "request_timeout_applied": successful.timeouts == [4.0],
            "failed_handshake_counted": (
                server.connection_pressure_snapshot().get("SSLError") == 1
            ),
            "workers_recovered": first_released and second_released and capacity_reacquired,
        }
    finally:
        server.server_close()


def _absolute_request_deadline_campaign() -> dict[str, Any]:
    """Prove that active byte drips cannot turn the idle timeout into infinity."""
    server = ControllerServer(
        ("127.0.0.1", 0),
        _CertificationHealthHandler,
        max_workers=2,
        max_workers_per_client=1,
        request_timeout=0.15,
    )
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    connection = socket.socket()
    connection.settimeout(1.0)
    connection.bind(("127.0.0.2", 0))
    connection.connect(("127.0.0.1", server.server_port))
    stop = threading.Event()

    def drip() -> None:
        while not stop.is_set():
            try:
                connection.sendall(b"G")
            except OSError:
                return
            time.sleep(0.03)

    drip_thread = threading.Thread(target=drip, daemon=True)
    deadline_count = 0
    recovered = False
    capacity_reacquired = False
    no_tracebacks = False
    try:
        with patch.object(LOG, "error") as error_log:
            drip_thread.start()
            deadline = time.monotonic() + 1.5
            while (
                server.connection_pressure_snapshot().get("request_deadline", 0) < 1
                and time.monotonic() < deadline
            ):
                time.sleep(0.01)
            deadline_count = server.connection_pressure_snapshot().get(
                "request_deadline", 0
            )
            deadline = time.monotonic() + 1.0
            while server.active_connections() and time.monotonic() < deadline:
                time.sleep(0.01)
            recovered = server.active_connections() == {}
            capacity_reacquired = server._acquire_worker(("192.0.2.20", 2000))
            if capacity_reacquired:
                server._release_worker(("192.0.2.20", 2000))
            no_tracebacks = error_log.call_count == 0
    finally:
        stop.set()
        connection.close()
        drip_thread.join(timeout=1)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)
    return {
        "mode": "loopback active-byte-drip deadline",
        "passed": bool(
            deadline_count == 1
            and recovered
            and capacity_reacquired
            and no_tracebacks
        ),
        "request_deadline_count": deadline_count,
        "workers_recovered": recovered and capacity_reacquired,
        "tracebacks_suppressed": no_tracebacks,
    }


def controller_availability_campaign() -> dict[str, Any]:
    """Exercise alternate-source fairness and error hygiene on loopback sockets.

    The health request deliberately originates from a different loopback address
    than the pressure clients.  This campaign therefore demonstrates blast-radius
    containment between sources; it does not claim that a legitimate request from
    the same source remains available after that source consumes its own quota.
    """
    server = ControllerServer(
        ("127.0.0.1", 0),
        _CertificationHealthHandler,
        max_workers=8,
        max_workers_per_client=2,
        request_timeout=3.0,
    )
    admission_source = ("192.0.2.10", 1000)
    alternate_source = ("192.0.2.11", 1001)
    first = server._acquire_worker(admission_source)
    second = server._acquire_worker(admission_source)
    source_limited = not server._acquire_worker(admission_source)
    alternate_admitted = server._acquire_worker(alternate_source)
    if first:
        server._release_worker(admission_source)
    if second:
        server._release_worker(admission_source)
    if alternate_admitted:
        server._release_worker(alternate_source)
    admission_recovered = server.active_connections() == {}
    pressure_before_network = server.connection_pressure_snapshot().get(
        "source_quota_rejected", 0
    )

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    held: list[socket.socket] = []
    network_pressure_exercised = False
    health_ok = False
    health_latency_ms = 0.0
    source_peak = 0
    expected_errors_suppressed = False
    network_rejection_delta = 0
    capacity_recovered = False
    try:
        with patch.object(LOG, "error") as error_log:
            connection: socket.socket | None = None
            try:
                for _ in range(6):
                    connection = socket.socket()
                    connection.settimeout(1.0)
                    connection.bind(("127.0.0.2", 0))
                    connection.connect(("127.0.0.1", server.server_port))
                    connection.sendall(b"G")
                    held.append(connection)
                    connection = None
                network_pressure_exercised = True
            except OSError:
                if connection is not None:
                    connection.close()
                for connection in held:
                    connection.close()
                held.clear()
            deadline = time.monotonic() + 1.0
            while time.monotonic() < deadline:
                source_peak = max(
                    source_peak,
                    server.active_connections().get("127.0.0.2", 0),
                )
                if not network_pressure_exercised or source_peak >= 2:
                    break
                time.sleep(0.01)
            health_started = time.perf_counter()
            health_connection = HTTPConnection(
                "127.0.0.1",
                server.server_port,
                timeout=1.0,
                source_address=("127.0.0.1", 0),
            )
            try:
                health_connection.request("GET", "/health")
                response = health_connection.getresponse()
                health_ok = response.status == 200 and response.read() == b"ok"
            finally:
                health_connection.close()
            health_latency_ms = round((time.perf_counter() - health_started) * 1000, 3)
            network_rejection_delta = (
                server.connection_pressure_snapshot().get(
                    "source_quota_rejected", 0
                )
                - pressure_before_network
            )
            for connection in held:
                connection.close()
            held.clear()
            deadline = time.monotonic() + 4.0
            while server.active_connections() and time.monotonic() < deadline:
                time.sleep(0.01)
            try:
                raise ConnectionResetError("expected certification disconnect")
            except ConnectionResetError:
                with socket.socket() as diagnostic_socket:
                    server.handle_error(diagnostic_socket, ("127.0.0.2", 1))
            expected_errors_suppressed = error_log.call_count == 0
    finally:
        for connection in held:
            connection.close()
        deadline = time.monotonic() + 4.0
        while server.active_connections() and time.monotonic() < deadline:
            time.sleep(0.01)
        leases: list[tuple[str, int]] = []
        for index in range(8):
            address = (f"198.51.100.{index + 1}", 2000 + index)
            if not server._acquire_worker(address):
                break
            leases.append(address)
        capacity_recovered = len(leases) == 8
        for address in leases:
            server._release_worker(address)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    recovered = server.active_connections() == {}
    pressure_counts = server.connection_pressure_snapshot()
    tls_lifecycle = _tls_worker_lifecycle_campaign()
    request_deadline = _absolute_request_deadline_campaign()
    passed = bool(
        first
        and second
        and source_limited
        and alternate_admitted
        and admission_recovered
        and network_pressure_exercised
        and health_ok
        and source_peak == 2
        and expected_errors_suppressed
        and network_rejection_delta >= 4
        and tls_lifecycle["passed"]
        and request_deadline["passed"]
        and recovered
        and capacity_recovered
    )
    return {
        "mode": "disposable loopback controller alternate-source fairness",
        "passed": passed,
        "same_source_availability_claimed": False,
        "source_quota_enforced": bool(source_limited),
        "alternate_source_admitted": bool(alternate_admitted),
        "admission_recovered": admission_recovered,
        "network_pressure_exercised": network_pressure_exercised,
        "source_peak": source_peak,
        "network_source_quota_rejections": network_rejection_delta,
        "health_ok": health_ok,
        "health_latency_ms": health_latency_ms,
        "expected_errors_suppressed": expected_errors_suppressed,
        "connection_pressure_counts": pressure_counts,
        "tls_worker_lifecycle": tls_lifecycle,
        "absolute_request_deadline": request_deadline,
        "workers_recovered": recovered and capacity_recovered,
    }


def self_test(
    scenarios: int = 300,
    fuzz_iterations: int = 1500,
    load_events: int = 750,
) -> dict[str, Any]:
    """Exercise only disposable local state; no real host service is changed."""
    started = time.perf_counter()
    checks: list[dict[str, Any]] = []
    fuzz_report = protocol_fuzz(max(100, min(fuzz_iterations, MAX_FUZZ_ITERATIONS)))
    checks.append(_check("hostile-telemetry-schema-inputs", fuzz_report["passed"], fuzz_report))

    authentication_report = authentication_boundary_campaign()
    checks.append(
        _check(
            "authentication-freshness-boundary",
            bool(authentication_report["passed"]),
            authentication_report,
        )
    )

    availability_report = controller_availability_campaign()
    checks.append(
        _check(
            "controller-alternate-source-fairness-and-error-hygiene",
            bool(availability_report["passed"]),
            availability_report,
        )
    )

    range_report = campaign(max(10, min(scenarios, MAX_SCENARIOS)))
    range_ok = (
        range_report["false_negative"] == 0
        and range_report["false_positive"] == 0
        and range_report["actions_queued"] == range_report["actions_completed"]
        and range_report["protocol_fuzz"]["passed"]
    )
    checks.append(_check("end-to-end-range", range_ok, range_report))

    policy_report = competition_policy_campaign(max(100, min(scenarios, MAX_SCENARIOS)))
    checks.append(
        _check(
            "competition-legality-policy-campaign",
            bool(policy_report["passed"]),
            policy_report,
        )
    )

    with tempfile.TemporaryDirectory(prefix="sentinel-blue-selftest-") as directory:
        root = Path(directory)
        spool = TelemetrySpool(root / "agent", max_items=8, max_bytes=64 * 1024)
        for sequence in range(20):
            payload = valid_payload()
            payload["sequence"] = sequence
            spool.enqueue(payload)
        corrupt = spool.directory / "99999999999999999999-corrupt.json"
        corrupt.write_text("{not-json", encoding="utf-8")
        pending = spool.pending(limit=32)
        spool_ok = len(pending) == 8 and corrupt.with_suffix(".corrupt").exists()
        checks.append(
            _check(
                "offline-spool-bounds-and-corruption",
                spool_ok,
                {"retained": len(pending), "maximum": 8, "corrupt_quarantined": True},
            )
        )

        restoration_range = restoration_policy_campaign(max(60, scenarios // 5))
        checks.append(
            _check(
                "restoration-policy-attack-campaign",
                bool(restoration_range["passed"]),
                restoration_range,
            )
        )

        journal = ActionJournal(root / "agent")
        journal.remember("stable-action", {"success": True, "message": "once"})
        journal_ok = ActionJournal(root / "agent").get("stable-action") == {
            "success": True,
            "message": "once",
        }
        checks.append(_check("action-idempotency-restart", journal_ok, "journal reloaded"))

        interrupted = ActionJournal(root / "interrupted")
        claimed = interrupted.begin("interrupted-action", "restart_service")
        restarted_record = ActionJournal(root / "interrupted").record("interrupted-action")
        crash_safe = claimed and restarted_record is not None and restarted_record.get("status") == "in_progress"
        checks.append(
            _check(
                "pre-side-effect-action-claim",
                crash_safe,
                "an interrupted changing action remains in-progress and cannot be replayed",
            )
        )

        dns_answers = [(2, 1, 6, "", ("192.0.2.7", 0))]
        mixed_answers = [*dns_answers, (2, 1, 6, "", ("203.0.113.9", 0))]
        unlisted_answers = [*dns_answers, (2, 1, 6, "", ("192.0.2.8", 0))]
        with patch("sentinel_blue.probes.socket.getaddrinfo", return_value=dns_answers):
            pinned = scoped_addresses(
                "service.test",
                ["192.0.2.0/24"],
                authorized_hosts=["192.0.2.7"],
                excluded_hosts=["192.0.2.99"],
            )
        mixed_rejected = False
        try:
            with patch("sentinel_blue.probes.socket.getaddrinfo", return_value=mixed_answers):
                scoped_addresses(
                    "service.test",
                    ["192.0.2.0/24"],
                    authorized_hosts=["192.0.2.7"],
                    excluded_hosts=["192.0.2.99"],
                )
        except ValueError:
            mixed_rejected = True
        unlisted_rejected = False
        try:
            with patch("sentinel_blue.probes.socket.getaddrinfo", return_value=unlisted_answers):
                scoped_addresses(
                    "service.test",
                    ["192.0.2.0/24"],
                    authorized_hosts=["192.0.2.7"],
                    excluded_hosts=["192.0.2.99"],
                )
        except ValueError:
            unlisted_rejected = True
        excluded_rejected = False
        try:
            scoped_addresses(
                "192.0.2.99",
                ["192.0.2.0/24"],
                authorized_hosts=[],
                excluded_hosts=["192.0.2.99"],
            )
        except ValueError:
            excluded_rejected = True
        checks.append(
            _check(
                "dns-full-scope-pinning",
                pinned == ["192.0.2.7"]
                and mixed_rejected
                and unlisted_rejected
                and excluded_rejected,
                {
                    "pinned": pinned,
                    "mixed_answer_rejected": mixed_rejected,
                    "unlisted_answer_rejected": unlisted_rejected,
                    "excluded_address_rejected": excluded_rejected,
                },
            )
        )

        security_alerts = analyze_security_events(
            {
                "accounts": [],
                "security_events": [
                    {
                        "event_id": "policy-change",
                        "category": "audit_policy_changed",
                        "account": "unknown",
                        "actor": "unexpected-admin",
                        "occurred_at": 101.0,
                    },
                    {
                        "event_id": "protected-change",
                        "category": "privilege_change",
                        "account": "service-monitor-example",
                        "actor": "unexpected-admin",
                        "occurred_at": 102.0,
                    },
                ],
            },
            {"observed_at": 100.0, "accounts": []},
            {"service-monitor-example"},
            RiskModel(),
        )
        alert_kinds = {item.kind for item in security_alerts}
        checks.append(
            _check(
                "protected-control-plane-detection",
                alert_kinds
                == {"security_event_audit_policy_changed", "security_event_privilege_change"},
                sorted(alert_kinds),
            )
        )

        executor = ActionExecutor(root / "agent-actions", allow_containment=False)
        telemetry = valid_payload()
        action_results = {
            "snapshot": executor.execute("snapshot", {}, telemetry),
            "quarantine": executor.execute(
                "quarantine_session", {"session": {"process_id": 4242}}, telemetry
            ),
            "restart": executor.execute("restart_service", {"service": "web.service"}, telemetry),
            "rollback": executor.execute(
                "rollback_service",
                {"service": "web.service", "desired_state": "stopped"},
                telemetry,
            ),
        }
        dry_run_ok = all(item.get("success") for item in action_results.values()) and all(
            action_results[name].get("dry_run") for name in ("quarantine", "restart", "rollback")
        )
        checks.append(_check("safe-action-defaults", dry_run_ok, action_results))

        protected_file = root / "disposable-protected.conf"
        protected_file.write_text("approved-state\n", encoding="utf-8")
        approved_digest = hashlib.sha256(protected_file.read_bytes()).hexdigest()
        restore_executor = ActionExecutor(root / "restoration", allow_restoration=True)
        capture_item = {"path": str(protected_file), "sha256": approved_digest}
        baseline_security = _windows_integrity_security_digest(protected_file)
        if baseline_security:
            capture_item["security_descriptor_sha256"] = baseline_security
        captured = restore_executor.execute(
            "capture_restore_point",
            {"files": [capture_item]},
            telemetry,
        )
        protected_file.write_text("simulated-tamper\n", encoding="utf-8")
        observed_digest = hashlib.sha256(protected_file.read_bytes()).hexdigest()
        restore_parameters = {
            "path": str(protected_file),
            "baseline_sha256": approved_digest,
            "observed_sha256": observed_digest,
        }
        if baseline_security:
            restore_parameters["baseline_security_descriptor_sha256"] = (
                baseline_security
            )
            restore_parameters["observed_security_descriptor_sha256"] = (
                _windows_integrity_security_digest(protected_file)
            )
        restored = restore_executor.execute(
            "restore_integrity",
            restore_parameters,
            telemetry,
        )
        undone = restore_executor.execute(
            "rollback_integrity", dict(restored.get("pre_state", {})), telemetry
        )
        restoration_ok = (
            captured.get("success")
            and restored.get("success")
            and undone.get("success")
            and protected_file.read_text(encoding="utf-8") == "simulated-tamper\n"
        )
        checks.append(
            _check(
                "monitored-restoration-and-undo",
                bool(restoration_ok),
                {
                    "capture": captured.get("message"),
                    "restore": restored.get("message"),
                    "undo": undone.get("message"),
                    "evidence_preserved": restored.get("evidence_preserved", False),
                },
            )
        )

        database = root / "controller.db"
        store = Store(database)
        app = ControllerApp(
            store,
            "s" * 32,
            authorized_networks=["192.0.2.0/24"],
            operator_token="o" * 32,
        )
        agent_count = 16
        load_executor = ActionExecutor(root / "load-baseline-actions")
        load_integrity: dict[str, list[dict[str, Any]]] = {}
        baseline_capture_actions = baseline_capture_receipts = 0
        for index in range(agent_count):
            payload = valid_payload()
            agent_id = f"load-agent-{index}"
            payload.update(
                agent_id=agent_id,
                hostname=f"load-host-{index}",
                boot_id=f"load-boot-{index}",
                sequence=0,
            )
            _materialize_disposable_integrity(
                root / "load-baseline-fixtures" / agent_id,
                payload,
            )
            app.ingest(payload)
            capture = _complete_disposable_baseline_promotion(
                app,
                store,
                load_executor,
                agent_id,
                payload,
            )
            baseline_capture_actions += capture["actions"]
            baseline_capture_receipts += capture["receipts"]
            load_integrity[agent_id] = json.loads(json.dumps(payload["integrity"]))

        latencies: list[float] = []
        load_started = time.perf_counter()
        for index in range(max(1, min(load_events, MAX_LOAD_EVENTS))):
            agent_index = index % agent_count
            payload = valid_payload()
            payload.update(
                agent_id=f"load-agent-{agent_index}",
                hostname=f"load-host-{agent_index}",
                boot_id=f"load-boot-{agent_index}",
                observed_at=time.time(),
                sequence=index + 1,
                integrity=json.loads(
                    json.dumps(load_integrity[f"load-agent-{agent_index}"])
                ),
            )
            event_started = time.perf_counter()
            app.ingest(payload)
            latencies.append((time.perf_counter() - event_started) * 1000)
        load_duration = max(0.000001, time.perf_counter() - load_started)
        throughput = {
            "events": len(latencies),
            "agents": agent_count,
            "events_per_second": round(len(latencies) / load_duration, 2),
            "p95_ingest_ms": round(_p95(latencies), 3),
            "duration_seconds": round(load_duration, 3),
            "baseline_capture_actions": baseline_capture_actions,
            "baseline_capture_receipts": baseline_capture_receipts,
            "baseline_capture_mode": "non-dry-run disposable files",
        }
        checks.append(
            _check(
                "bounded-telemetry-load",
                len(store.latest_telemetry()) == agent_count
                and baseline_capture_actions == agent_count
                and baseline_capture_receipts == agent_count
                and store.integrity_check() == "ok",
                throughput,
            )
        )

        store.close()

        recovery_database = root / "recovery-controller.db"
        recovery_anchor = root / "recovery.anchor"
        recovery_backups = root / "authenticated-backups"
        recovery_backups.mkdir(mode=0o700)
        recovery_key = hashlib.sha256(
            b"sentinel-blue-disposable-selftest-recovery-key"
        ).digest()
        initialized = initialize_controller_recovery(
            recovery_database,
            recovery_anchor,
            recovery_key,
            enrollment_window=60.0,
        )
        recovery_store = Store(recovery_database)
        try:
            recovery_store.activate_release_binding(
                profile_id="selftest-recovery",
                profile_fingerprint="b" * 64,
                agent_version=__version__,
                release_sha256="a" * 64,
                strict=True,
            )
            recovery_store.load_governance(
                profile_fingerprint="b" * 64,
                default_mode="observe",
                strict=False,
                allowed_modes={"observe"},
            )
            rollback_copy = root / "pre-backup-rollback-copy.db"
            recovery_store.backup(rollback_copy)
            created = create_controller_backup(
                recovery_store,
                recovery_backups,
                recovery_anchor,
                recovery_key,
            )
        finally:
            recovery_store.close()
        verified = verify_controller_backup(
            created["bundle"],
            recovery_anchor,
            recovery_key,
        )
        live_status = controller_recovery_status(
            recovery_database,
            recovery_anchor,
            recovery_key,
        )
        rollback_status = controller_recovery_status(
            rollback_copy,
            recovery_anchor,
            recovery_key,
        )
        recovery = {
            "initialized_ready": initialized["ready"],
            "backup_sequence": created["backup_sequence"],
            "manifest_verified": verified["verified"],
            "anchor_binding": verified["anchor_binding"],
            "live_ready": live_status["ready"],
            "rollback_copy_action": rollback_status["action"],
            "rollback_copy_reason": rollback_status["reason"],
        }
        recovery_ok = bool(
            recovery["initialized_ready"]
            and recovery["backup_sequence"] == 1
            and recovery["manifest_verified"]
            and recovery["anchor_binding"] == "latest"
            and recovery["live_ready"]
            and recovery["rollback_copy_action"] == "block"
            and "below the protected floor" in recovery["rollback_copy_reason"]
        )
        checks.append(
            _check(
                "authenticated-controller-recovery-and-rollback-floor",
                recovery_ok,
                recovery,
            )
        )

    failures = [item for item in checks if not item["passed"]]
    return {
        "product": "Sentinel Blue",
        "version": __version__,
        "mode": "disposable local defensive certification",
        "passed": not failures,
        "checks": checks,
        "duration_seconds": round(time.perf_counter() - started, 3),
        "containment": (
            "containment dry-run only; restore-point capture and file restoration "
            "touched disposable files only"
        ),
        "validation_boundary": [
            "No real CCDC scoring engine or competition portal was available.",
            "Windows collection and WinRM deployment were syntax- and fixture-tested, not run on Windows.",
            "Live service changes and real remote hosts were intentionally not touched.",
            "Policy-lab outcomes are synthetic and do not establish competition readiness.",
        ],
    }


def run(args: argparse.Namespace) -> int:
    if args.full:
        scenarios, fuzz_iterations, load_events = (
            MAX_SCENARIOS,
            MAX_FUZZ_ITERATIONS,
            MAX_LOAD_EVENTS,
        )
    else:
        scenarios = args.scenarios
        fuzz_iterations = args.fuzz_iterations
        load_events = args.load_events
    report = self_test(scenarios, fuzz_iterations, load_events)
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"Sentinel Blue self-test: {'PASS' if report['passed'] else 'FAIL'}")
        for item in report["checks"]:
            print(f"[{'PASS' if item['passed'] else 'FAIL'}] {item['name']}")
        print(f"duration_seconds: {report['duration_seconds']}")
    return 0 if report["passed"] else 1
