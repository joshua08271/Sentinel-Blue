"""Gated native red-on-blue validation for disposable GitHub-hosted runners.

This module intentionally refuses ordinary hosts, self-hosted runners, forks,
and untrusted actors.  The campaign changes only fixed, run-scoped resources on
an ephemeral Ubuntu runner and never contacts a non-loopback address.
"""

from __future__ import annotations

import copy
import json
import os
import platform
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Mapping

try:
    import pwd
except ImportError:  # pragma: no cover - the native lab itself is Linux-only
    pwd = None  # type: ignore[assignment]

from . import __version__
from .actions import ActionExecutor
from .collectors import collect
from .controller import ControllerApp, assess_baseline_readiness
from .event_profile import CAPABILITIES, EventProfile
from .native_loopback_fixture import HEALTH_MARKER
from .probes import run_probe
from .range_lab import _complete_disposable_baseline_promotion
from .risk import RiskModel
from .store import Store


EXPECTED_REPOSITORY = "joshua08271/Sentinel-Blue"
EXPECTED_ACTOR = "joshua08271"
CONFIRMATION = "github-hosted-ephemeral-runner"
ALLOWED_EVENTS = frozenset({"pull_request", "workflow_dispatch"})
REQUIRED_TOOLS = ("getent", "passwd", "ss", "systemctl", "useradd", "userdel")
APPROVED_CONTENT = b"sentinel-blue-native-approved-v1\n"
TAMPERED_CONTENT = b"sentinel-blue-native-inert-tamper-v1\n"


class NativeRangeError(RuntimeError):
    """A bounded native-range assertion failed."""


@dataclass(frozen=True, slots=True)
class RunnerContext:
    repository: str
    actor: str
    event_name: str
    run_id: str
    suffix: str
    workspace: Path


def validate_runner_environment(
    environ: Mapping[str, str] | None = None,
    *,
    effective_uid: int | None = None,
    system_name: str | None = None,
    tool_finder: Callable[[str], str | None] = shutil.which,
) -> RunnerContext:
    """Fail closed unless this is the owner's disposable GitHub runner job."""

    values = os.environ if environ is None else environ
    if values.get("SENTINEL_BLUE_DISPOSABLE_LAB") != CONFIRMATION:
        raise NativeRangeError("the exact disposable-runner confirmation is absent")
    if values.get("GITHUB_ACTIONS", "").casefold() != "true":
        raise NativeRangeError("native range is restricted to GitHub Actions")
    if values.get("RUNNER_ENVIRONMENT", "").casefold() != "github-hosted":
        raise NativeRangeError("self-hosted runners are not authorized")
    if values.get("RUNNER_OS", "").casefold() != "linux":
        raise NativeRangeError("native range requires a disposable Linux runner")
    if (system_name or platform.system()).casefold() != "linux":
        raise NativeRangeError("native range requires a Linux kernel")
    if values.get("GITHUB_REPOSITORY") != EXPECTED_REPOSITORY:
        raise NativeRangeError("the repository identity is outside the fixed allowlist")
    if values.get("GITHUB_ACTOR") != EXPECTED_ACTOR:
        raise NativeRangeError("the workflow actor is outside the fixed allowlist")
    event_name = values.get("GITHUB_EVENT_NAME", "")
    if event_name not in ALLOWED_EVENTS:
        raise NativeRangeError("the workflow event is not authorized for native changes")
    run_id = values.get("GITHUB_RUN_ID", "")
    if not run_id.isascii() or not run_id.isdigit() or not 1 <= len(run_id) <= 20:
        raise NativeRangeError("GITHUB_RUN_ID is not a bounded numeric identifier")
    uid = (
        getattr(os, "geteuid", lambda: -1)()
        if effective_uid is None
        else effective_uid
    )
    if uid != 0:
        raise NativeRangeError("native range must run through the workflow's sudo gate")
    workspace_text = values.get("GITHUB_WORKSPACE", "")
    workspace = Path(workspace_text)
    if (
        not workspace_text
        or not workspace.is_absolute()
        or workspace.is_symlink()
        or not workspace.is_dir()
    ):
        raise NativeRangeError("GITHUB_WORKSPACE is unavailable or unsafe")
    missing = [name for name in REQUIRED_TOOLS if tool_finder(name) is None]
    if missing:
        raise NativeRangeError("required native tools are unavailable: " + ", ".join(missing))
    return RunnerContext(
        repository=EXPECTED_REPOSITORY,
        actor=EXPECTED_ACTOR,
        event_name=event_name,
        run_id=run_id,
        suffix=run_id[-10:],
        workspace=workspace.resolve(),
    )


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def build_native_profile(
    root: Path,
    *,
    agent_id: str,
    service_id: str,
    port: int,
) -> tuple[EventProfile, dict[str, Any], dict[str, Any]]:
    """Build a minimal in-process range profile bound only to loopback."""

    config_path = root / "protected.conf"
    probe = {
        "name": "native-loopback-health",
        "kind": "http",
        "target": f"http://127.0.0.1:{port}/health",
        "expected_status": [200],
        "expected_body": HEALTH_MARKER,
        "timeout": 2.0,
    }
    restoration_probe = {**probe, "restore_paths": [str(config_path)]}
    capabilities = {name: False for name in CAPABILITIES}
    for name in (
        "configuration_backups",
        "external_controller",
        "file_restoration",
        "guarded_autonomy",
        "in_place_repair",
        "network_monitoring",
        "structured_rollback",
    ):
        capabilities[name] = True
    payload = copy.deepcopy(EventProfile.testing().raw)
    payload.update(
        {
            "profile_id": f"native-github-runner-{root.name.rsplit('-', 1)[-1]}",
            "capabilities": capabilities,
            "organizer_exceptions": [],
            "allowed_automatic_actions": [
                "capture_restore_point",
                "restore_integrity",
                "snapshot",
                "validate_service",
            ],
            "official_identities": [],
            "services_confirmed": True,
            "services": [
                {
                    "service_id": service_id,
                    "host": agent_id,
                    "protocol": "http",
                    "port": port,
                    "implementation": "Sentinel Blue inert loopback health fixture",
                    "dependencies": [],
                    "required_accounts": [],
                    "required_files": [str(config_path)],
                    "required_data": [],
                    "credential_source": "",
                    "expected_transactions": [probe],
                    "local_checks": [
                        "systemd active state",
                        "loopback HTTP health transaction",
                    ],
                    "allowed_automatic_actions": [
                        "capture_restore_point",
                        "restore_integrity",
                        "validate_service",
                    ],
                    "approval_actions": [
                        "restart_service",
                        "restore_integrity",
                        "rollback_integrity",
                        "rollback_service",
                    ],
                    "backup_method": "authenticated agent-local restore point",
                    "recovery_method": "in-place service start and exact file restoration",
                    "rollback_method": "restore captured immediate pre-state",
                }
            ],
            "approval": {
                "status": "range-only",
                "approved_by": "repository-owner GitHub Actions workflow",
            },
            "recovery": {"baseline_promotion_delay_seconds": 0},
        }
    )
    payload["scope"] = {
        "authorized_networks": ["127.0.0.0/8"],
        "authorized_hosts": ["127.0.0.1"],
        "controller_ingress_hosts": ["127.0.0.1"],
        "excluded_hosts": [],
        "approved_deployment_paths": [str(root)],
    }
    payload["deployment"] = {"approved_routes": ["local"]}
    # Deliberately omit a release digest. This profile can drive only this
    # in-process range and cannot pass the deployed range/runtime gate.
    payload["release"] = {"version": __version__, "approved": False}
    return EventProfile.from_dict(payload), probe, restoration_probe


class _InertHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        body = b"sentinel-blue inert listener\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class NativeRunnerLab:
    """Own and clean every native resource used by one disposable campaign."""

    def __init__(self, context: RunnerContext):
        self.context = context
        self.root = Path("/tmp") / f"sentinel-blue-native-{context.run_id}"
        self.agent_id = f"native-runner-{context.suffix}"
        self.service_id = f"sentinel-blue-native-{context.suffix}.service"
        self.unit_path = Path("/etc/systemd/system") / self.service_id
        self.cron_path = Path("/etc/cron.d") / f"sentinel-blue-native-{context.suffix}"
        self.account_name = f"sblab{context.suffix[-8:]}"
        self.config_path = self.root / "protected.conf"
        self.state_dir = self.root / "agent-state"
        self.port = _free_loopback_port()
        self.profile, self.probe, self.restoration_probe = build_native_profile(
            self.root,
            agent_id=self.agent_id,
            service_id=self.service_id,
            port=self.port,
        )
        self.sequence = 0
        self.inert_process: subprocess.Popen[bytes] | None = None
        self.listener: ThreadingHTTPServer | None = None
        self.listener_thread: threading.Thread | None = None
        self.unit_created = False
        self.account_created = False
        self.cron_created = False

    @staticmethod
    def _command(
        arguments: list[str], *, timeout: float = 30.0, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            arguments,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if check and result.returncode != 0:
            raise NativeRangeError(
                f"native command {arguments[0]!r} failed with status {result.returncode}"
            )
        return result

    @staticmethod
    def _write_exclusive(path: Path, data: bytes, mode: int) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, mode)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            os.close(descriptor)

    @staticmethod
    def _account_exists(name: str) -> bool:
        if pwd is None:
            return False
        try:
            pwd.getpwnam(name)
            return True
        except KeyError:
            return False

    def _delete_duplicate_uid_zero_account(self) -> None:
        """Delete only the exact run-scoped duplicate-UID fixture account."""

        if pwd is None:
            raise NativeRangeError("POSIX account inventory is unavailable")
        try:
            entry = pwd.getpwnam(self.account_name)
        except KeyError:
            self.account_created = False
            return
        if entry.pw_name != self.account_name or entry.pw_uid != 0:
            raise NativeRangeError(
                "refused to delete a changed emulation-account identity"
            )
        # A duplicate UID zero appears to userdel as a logged-in identity
        # whenever any root process exists. --force bypasses only that check;
        # omitting --remove ensures no home or UID-owned files are traversed.
        self._command(["userdel", "--force", self.account_name])
        if self._account_exists(self.account_name):
            raise NativeRangeError("duplicate-UID emulation account remained after deletion")
        self.account_created = False

    def _probe_result(self) -> Any:
        return run_probe(
            self.probe,
            list(self.profile.authorized_networks),
            authorized_hosts=list(self.profile.authorized_hosts),
            excluded_hosts=list(self.profile.excluded_hosts),
        )

    def _probe_healthy(self) -> bool:
        return bool(self._probe_result().healthy)

    def _wait_for_probe(self, expected: bool, timeout: float = 12.0) -> None:
        deadline = time.monotonic() + timeout
        last_detail = "probe did not run"
        while time.monotonic() < deadline:
            result = self._probe_result()
            last_detail = str(result.detail)[:240].replace("\n", " ")
            if result.healthy is expected:
                return
            time.sleep(0.2)
        service_state = self._command(
            [
                "systemctl",
                "show",
                self.service_id,
                "--property=ActiveState,SubState,Result,ExecMainStatus",
                "--no-pager",
            ],
            check=False,
        ).stdout.strip().replace("\n", ";")[:240]
        raise NativeRangeError(
            "loopback health transaction did not reach the expected state: "
            f"expected={expected}; probe={last_detail}; service={service_state or 'unknown'}"
        )

    def setup(self) -> None:
        if self.root.exists() or self.root.is_symlink():
            raise NativeRangeError("run-scoped lab root already exists")
        if self.unit_path.exists() or self.unit_path.is_symlink():
            raise NativeRangeError("run-scoped systemd unit already exists")
        if self.cron_path.exists() or self.cron_path.is_symlink():
            raise NativeRangeError("run-scoped cron marker already exists")
        if self._account_exists(self.account_name):
            raise NativeRangeError("run-scoped account already exists")
        executable = Path(sys.executable)
        if not executable.is_absolute() or any(character.isspace() for character in str(executable)):
            raise NativeRangeError("Python executable path is unsafe for the systemd fixture")
        self.root.mkdir(mode=0o755)
        self.state_dir.mkdir(mode=0o700)
        self._write_exclusive(self.config_path, APPROVED_CONTENT, 0o640)
        unit = (
            "[Unit]\n"
            "Description=Sentinel Blue disposable native range fixture\n"
            "After=network.target\n\n"
            "[Service]\n"
            "Type=simple\n"
            f"ExecStart={executable} -m sentinel_blue.native_loopback_fixture "
            f"--port {self.port}\n"
            "DynamicUser=yes\n"
            "NoNewPrivileges=yes\n"
            "PrivateDevices=yes\n"
            "PrivateTmp=yes\n"
            "ProtectHome=yes\n"
            "ProtectSystem=strict\n"
            "RestrictAddressFamilies=AF_UNIX AF_INET\n"
            "Restart=no\n"
        ).encode("utf-8")
        self._write_exclusive(self.unit_path, unit, 0o644)
        self.unit_created = True
        self._command(["systemctl", "daemon-reload"])
        self._command(["systemctl", "start", self.service_id])
        self._wait_for_probe(True)

    def _collect_payload(self) -> dict[str, Any]:
        payload = collect(
            self.agent_id,
            probe_specs=[self.probe],
            authorized_networks=list(self.profile.authorized_networks),
            integrity_paths=[str(self.config_path)],
            authorized_hosts=list(self.profile.authorized_hosts),
            excluded_hosts=list(self.profile.excluded_hosts),
        ).as_dict()
        payload["services"] = [
            row for row in payload["services"] if row.get("name") == self.service_id
        ]
        payload["integrity"] = [
            row
            for row in payload["integrity"]
            if row.get("path") == str(self.config_path)
        ]
        payload["sequence"] = self.sequence
        payload["profile_id"] = self.profile.profile_id
        payload["profile_fingerprint"] = self.profile.fingerprint
        self.sequence += 1
        if payload.get("collector_errors"):
            raise NativeRangeError(
                f"native collection reported {len(payload['collector_errors'])} error(s)"
            )
        if len(payload["services"]) != 1:
            unit_state = self._command(
                [
                    "systemctl",
                    "show",
                    self.service_id,
                    "--property=Id,LoadState,ActiveState,SubState",
                    "--no-pager",
                ],
                check=False,
            ).stdout.strip().replace("\n", ";")[:240]
            raise NativeRangeError(
                "the exact lab service was not collected: "
                f"targeted_state={unit_state or 'unknown'}"
            )
        if len(payload["integrity"]) != 1:
            raise NativeRangeError("the exact protected lab file was not collected")
        if len(payload.get("probes", [])) != 1:
            raise NativeRangeError("the exact loopback service probe was not collected")
        if payload.get("boot_id") in {None, "", "unknown"}:
            raise NativeRangeError("the runner boot identity is unavailable")
        return payload

    @staticmethod
    def _alert_for(
        store: Store, alert_ids: list[str], expected_kind: str
    ) -> dict[str, Any]:
        matches: list[dict[str, Any]] = []
        for identifier in dict.fromkeys(alert_ids):
            row = store.get_alert(identifier)
            if row is None:
                continue
            record = dict(row)
            if record.get("kind") == expected_kind:
                matches.append(record)
        if len(matches) != 1:
            raise NativeRangeError(
                f"expected exactly one {expected_kind!r} alert, observed {len(matches)}"
            )
        return matches[0]

    @staticmethod
    def _observe_other_alerts(
        app: ControllerApp, store: Store, alert_ids: list[str], keep_id: str
    ) -> None:
        for identifier in dict.fromkeys(alert_ids):
            if identifier == keep_id:
                continue
            row = store.get_alert(identifier)
            if row is not None and dict(row).get("status") == "open":
                app.decision(identifier, "observe")

    def _execute_decision(
        self,
        app: ControllerApp,
        store: Store,
        executor: ActionExecutor,
        alert: dict[str, Any],
        expected_action: str,
        telemetry: dict[str, Any],
    ) -> tuple[dict[str, Any], Any]:
        decision = app.decision(str(alert["alert_id"]), "approve")
        if not decision or not decision.get("action_id"):
            raise NativeRangeError("approved alert did not bind to an action")
        expected_id = str(decision["action_id"])
        selected_result: dict[str, Any] | None = None
        selected_action: Any = None
        actions = app.pending_actions_for_agent(self.agent_id)
        for action in actions:
            result = executor.execute(action.action_type, action.parameters, telemetry)
            completion = app.complete_action(
                {**result, "action_id": action.action_id}, self.agent_id
            )
            if completion != "new":
                raise NativeRangeError("action result was not accepted exactly once")
            if action.action_id == expected_id:
                selected_result = result
                selected_action = action
        if selected_result is None or selected_action is None:
            raise NativeRangeError("the approved action was not dispatched")
        if selected_action.action_type != expected_action:
            raise NativeRangeError(
                f"expected {expected_action!r}, received {selected_action.action_type!r}"
            )
        if selected_result.get("success") is not True:
            message = str(selected_result.get("message", "no diagnostic"))
            probe_summary = [
                {
                    "healthy": item.get("healthy"),
                    "detail": str(item.get("detail", ""))[:120],
                }
                for item in selected_result.get("probes", [])[:8]
                if isinstance(item, dict)
            ]
            raise NativeRangeError(
                f"{expected_action} did not complete successfully: "
                f"{message[:240]}; probes={probe_summary}"
            )
        if selected_result.get("dry_run") is True:
            raise NativeRangeError(f"{expected_action} unexpectedly ran in dry-run mode")
        return selected_result, selected_action

    def _clean_observation(self, app: ControllerApp) -> None:
        payload = self._collect_payload()
        if payload["probes"][0].get("healthy") is not True:
            raise NativeRangeError("clean-state service transaction is unhealthy")
        app.ingest(payload)

    @staticmethod
    def _scenario_record(
        name: str,
        expected_alert: str,
        detection_started: float,
        response_started: float,
        action: Any,
        result: dict[str, Any],
        **assertions: bool,
    ) -> dict[str, Any]:
        if not assertions or not all(assertions.values()):
            failed = sorted(name for name, passed in assertions.items() if not passed)
            raise NativeRangeError(
                f"scenario {name!r} failed assertions: {', '.join(failed)}"
            )
        probes = result.get("probes", [])
        return {
            "name": name,
            "expected_alert": expected_alert,
            "detected": True,
            "detection_latency_ms": round((response_started - detection_started) * 1000, 2),
            "response_action": action.action_type,
            "response_automated": bool(action.automated),
            "response_latency_ms": round((time.perf_counter() - response_started) * 1000, 2),
            "response_success": True,
            "non_dry_run": result.get("dry_run") is not True,
            "response_probes_healthy": (
                None
                if not probes
                else all(item.get("healthy") is True for item in probes)
            ),
            "assertions": dict(sorted(assertions.items())),
        }

    def _service_stop_scenario(
        self, app: ControllerApp, store: Store, executor: ActionExecutor
    ) -> dict[str, Any]:
        started = time.perf_counter()
        self._command(["systemctl", "stop", self.service_id])
        self._wait_for_probe(False)
        telemetry = self._collect_payload()
        alert_ids = app.ingest(telemetry)
        alert = self._alert_for(store, alert_ids, "baseline_service_stopped")
        detected_at = time.perf_counter()
        self._observe_other_alerts(app, store, alert_ids, str(alert["alert_id"]))
        result, action = self._execute_decision(
            app, store, executor, alert, "restart_service", telemetry
        )
        self._wait_for_probe(True)
        expected_probes = [self.probe]
        record = self._scenario_record(
            "systemd_service_stop",
            "baseline_service_stopped",
            started,
            detected_at,
            action,
            result,
            application_transaction_restored=self._probe_healthy(),
            manifest_probe_bound=action.parameters.get("probes") == expected_probes,
            systemd_state_restored=self._command(
                ["systemctl", "is-active", self.service_id], check=False
            ).stdout.strip()
            == "active",
        )
        self._clean_observation(app)
        return record

    def _file_tamper_scenario(
        self, app: ControllerApp, store: Store, executor: ActionExecutor
    ) -> dict[str, Any]:
        started = time.perf_counter()
        self.config_path.write_bytes(TAMPERED_CONTENT)
        self.config_path.chmod(0o666)
        first = self._collect_payload()
        first_ids = app.ingest(first)
        first_alert = self._alert_for(store, first_ids, "critical_file_changed")
        prematurely_queued = (
            store.action_for_alert(
                str(first_alert["alert_id"]), "restore_integrity"
            )
            is not None
        )
        second = self._collect_payload()
        second_ids = app.ingest(second)
        alert = self._alert_for(
            store, [*first_ids, *second_ids], "critical_file_changed"
        )
        detected_at = time.perf_counter()
        self._observe_other_alerts(
            app, store, [*first_ids, *second_ids], str(first_alert["alert_id"])
        )
        result, action = self._execute_decision(
            app, store, executor, alert, "restore_integrity", second
        )
        restored_mode = stat.S_IMODE(self.config_path.stat().st_mode)
        record = self._scenario_record(
            "protected_file_content_and_mode_tamper",
            "critical_file_changed",
            started,
            detected_at,
            action,
            result,
            approved_bytes_restored=self.config_path.read_bytes() == APPROVED_CONTENT,
            approved_mode_restored=restored_mode == 0o640,
            evidence_preserved=result.get("evidence_preserved") is True,
            matching_observations_required=not prematurely_queued,
            restoration_was_automatic=bool(action.automated),
        )
        self._clean_observation(app)
        return record

    def _persistence_scenario(
        self, app: ControllerApp, store: Store, executor: ActionExecutor
    ) -> dict[str, Any]:
        started = time.perf_counter()
        self._write_exclusive(
            self.cron_path,
            b"# Sentinel Blue inert persistence-emulation marker; no command\n",
            0o644,
        )
        self.cron_created = True
        telemetry = self._collect_payload()
        alert_ids = app.ingest(telemetry)
        alert = self._alert_for(store, alert_ids, "new_persistence_item")
        detected_at = time.perf_counter()
        self._observe_other_alerts(app, store, alert_ids, str(alert["alert_id"]))
        result, action = self._execute_decision(
            app, store, executor, alert, "snapshot", telemetry
        )
        self.cron_path.unlink()
        self.cron_created = False
        record = self._scenario_record(
            "inert_root_cron_persistence_marker",
            "new_persistence_item",
            started,
            detected_at,
            action,
            result,
            marker_was_inert=True,
            marker_removed=not self.cron_path.exists(),
            evidence_snapshot_created=True,
        )
        self._clean_observation(app)
        return record

    def _uid_zero_account_scenario(
        self, app: ControllerApp, store: Store, executor: ActionExecutor
    ) -> dict[str, Any]:
        started = time.perf_counter()
        self._command(
            [
                "useradd",
                "-M",
                "-o",
                "-u",
                "0",
                "-g",
                "0",
                "-s",
                "/bin/bash",
                self.account_name,
            ]
        )
        self.account_created = True
        if not self._account_exists(self.account_name):
            raise NativeRangeError("locked UID-zero emulation account was not created")
        password_state = self._command(
            ["passwd", "-S", self.account_name]
        ).stdout.split()
        credential_locked = len(password_state) >= 2 and password_state[1] in {
            "L",
            "LK",
        }
        if not credential_locked:
            raise NativeRangeError("UID-zero emulation account was not credential-locked")
        telemetry = self._collect_payload()
        alert_ids = app.ingest(telemetry)
        alert = self._alert_for(store, alert_ids, "unverified_privileged_account")
        detected_at = time.perf_counter()
        self._observe_other_alerts(app, store, alert_ids, str(alert["alert_id"]))
        result, action = self._execute_decision(
            app, store, executor, alert, "snapshot", telemetry
        )
        self._delete_duplicate_uid_zero_account()
        record = self._scenario_record(
            "locked_duplicate_uid_zero_account",
            "unverified_privileged_account",
            started,
            detected_at,
            action,
            result,
            account_had_no_configured_credential=credential_locked,
            account_removed=not self._account_exists(self.account_name),
            evidence_snapshot_created=True,
        )
        self._clean_observation(app)
        return record

    def _temporary_process_scenario(
        self, app: ControllerApp, store: Store, executor: ActionExecutor
    ) -> dict[str, Any]:
        started = time.perf_counter()
        source = Path(shutil.which("sleep") or "")
        if not source.is_file():
            raise NativeRangeError("trusted sleep fixture is unavailable")
        executable = self.root / "inert-input-capture-emulator"
        self._write_exclusive(executable, source.read_bytes(), 0o700)
        self.inert_process = subprocess.Popen(
            [str(executable), "60"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(0.1)
        if self.inert_process.poll() is not None:
            raise NativeRangeError("inert temporary process exited before collection")
        telemetry = self._collect_payload()
        alert_ids = app.ingest(telemetry)
        alert = self._alert_for(store, alert_ids, "privileged_temporary_process")
        detected_at = time.perf_counter()
        self._observe_other_alerts(app, store, alert_ids, str(alert["alert_id"]))
        result, action = self._execute_decision(
            app, store, executor, alert, "snapshot", telemetry
        )
        self.inert_process.terminate()
        self.inert_process.wait(timeout=5)
        self.inert_process = None
        executable.unlink()
        record = self._scenario_record(
            "inert_privileged_temporary_process",
            "privileged_temporary_process",
            started,
            detected_at,
            action,
            result,
            binary_was_trusted_sleep_copy=True,
            captured_no_input=True,
            process_removed=not executable.exists(),
        )
        self._clean_observation(app)
        return record

    def _listener_scenario(
        self, app: ControllerApp, store: Store, executor: ActionExecutor
    ) -> dict[str, Any]:
        started = time.perf_counter()
        self.listener = ThreadingHTTPServer(("127.0.0.1", 0), _InertHandler)
        self.listener.daemon_threads = True
        self.listener_thread = threading.Thread(
            target=self.listener.serve_forever,
            name="sentinel-blue-inert-loopback-listener",
            daemon=True,
        )
        self.listener_thread.start()
        telemetry = self._collect_payload()
        alert_ids = app.ingest(telemetry)
        alert = self._alert_for(store, alert_ids, "new_network_listener")
        detected_at = time.perf_counter()
        self._observe_other_alerts(app, store, alert_ids, str(alert["alert_id"]))
        result, action = self._execute_decision(
            app, store, executor, alert, "observe", telemetry
        )
        self.listener.shutdown()
        self.listener.server_close()
        self.listener = None
        self.listener_thread.join(timeout=5)
        thread_stopped = not self.listener_thread.is_alive()
        self.listener_thread = None
        record = self._scenario_record(
            "unexpected_loopback_listener",
            "new_network_listener",
            started,
            detected_at,
            action,
            result,
            bound_only_to_loopback=True,
            listener_removed=thread_stopped,
            no_automatic_network_change=not action.automated,
        )
        self._clean_observation(app)
        return record

    def campaign(self) -> dict[str, Any]:
        store = Store(self.root / "controller.db")
        app = ControllerApp(
            store,
            "n" * 32,
            RiskModel(),
            list(self.profile.authorized_networks),
            operator_token="o" * 32,
            auto_restore=True,
            restoration_probes=[self.restoration_probe],
            restore_confirmations=2,
            event_profile=self.profile,
        )
        executor = ActionExecutor(
            self.state_dir,
            allow_containment=True,
            authorized_networks=list(self.profile.authorized_networks),
            allow_restoration=True,
            default_probes=[self.probe],
            authorized_hosts=list(self.profile.authorized_hosts),
            excluded_hosts=list(self.profile.excluded_hosts),
        )
        try:
            baseline = self._collect_payload()
            readiness = assess_baseline_readiness(baseline)
            if not readiness["ready"]:
                raise NativeRangeError("native baseline was not healthy enough to approve")
            for account in baseline.get("accounts", []):
                if account.get("privileged"):
                    store.protect_account(
                        self.agent_id,
                        str(account.get("name", "")),
                        "github-runner-baseline",
                        "disposable-runner-image",
                    )
            app.ingest(baseline)
            capture = _complete_disposable_baseline_promotion(
                app, store, executor, self.agent_id, baseline
            )
            scenarios = [
                self._service_stop_scenario(app, store, executor),
                self._file_tamper_scenario(app, store, executor),
                self._persistence_scenario(app, store, executor),
                self._uid_zero_account_scenario(app, store, executor),
                self._temporary_process_scenario(app, store, executor),
                self._listener_scenario(app, store, executor),
            ]
            return {
                "schema_version": 1,
                "status": "passed",
                "mode": "native changes on one disposable GitHub-hosted Linux runner",
                "version": __version__,
                "repository": self.context.repository,
                "commit": os.environ.get("GITHUB_SHA", "")[:40],
                "scope": {
                    "authorized_networks": list(self.profile.authorized_networks),
                    "authorized_hosts": list(self.profile.authorized_hosts),
                    "external_targets_contacted": 0,
                    "public_listeners_created": 0,
                },
                "safety": {
                    "destructive_payloads": False,
                    "credential_collection": False,
                    "input_collection": False,
                    "real_malware": False,
                    "inert_emulations_only": True,
                    "disposable_runner_gate": True,
                },
                "baseline": {
                    "readiness_score": readiness["score"],
                    "collector_errors": 0,
                    "restore_point_actions": capture["actions"],
                    "restore_point_receipts": capture["receipts"],
                },
                "scenarios": scenarios,
                "scenario_count": len(scenarios),
                "scenarios_passed": sum(
                    1 for scenario in scenarios if scenario["response_success"]
                ),
                "feedback_records": len(store.feedback_samples()),
                "limitations": [
                    "single-host disposable runner; not an unseen competition network",
                    "inert root-access, persistence, process, file, service, and listener emulations",
                    "event-specific rules and service manifests remain required before deployment",
                ],
            }
        finally:
            store.close()

    def cleanup(self) -> dict[str, Any]:
        errors: list[str] = []

        def attempt(label: str, operation: Callable[[], Any]) -> None:
            try:
                operation()
            except Exception as exc:  # cleanup must continue through every exact resource
                errors.append(f"{label}: {type(exc).__name__}: {str(exc)[:200]}")

        if self.inert_process is not None:
            def stop_process() -> None:
                assert self.inert_process is not None
                if self.inert_process.poll() is None:
                    self.inert_process.terminate()
                    try:
                        self.inert_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        self.inert_process.kill()
                        self.inert_process.wait(timeout=3)
                self.inert_process = None

            attempt("temporary process", stop_process)
        if self.listener is not None:
            attempt("loopback listener shutdown", self.listener.shutdown)
            attempt("loopback listener close", self.listener.server_close)
            self.listener = None
        if self.listener_thread is not None:
            self.listener_thread.join(timeout=5)
            if self.listener_thread.is_alive():
                errors.append("loopback listener thread did not stop")
            self.listener_thread = None
        if self.cron_created or self.cron_path.exists() or self.cron_path.is_symlink():
            attempt("cron marker", self.cron_path.unlink)
            self.cron_created = False
        if self.account_created or self._account_exists(self.account_name):
            attempt("UID-zero account", self._delete_duplicate_uid_zero_account)
        if self.unit_created or self.unit_path.exists() or self.unit_path.is_symlink():
            attempt(
                "systemd service stop",
                lambda: self._command(
                    ["systemctl", "stop", self.service_id], check=False
                ),
            )
            attempt("systemd unit", self.unit_path.unlink)
            attempt("systemd reload", lambda: self._command(["systemctl", "daemon-reload"]))
            attempt(
                "systemd failed-state reset",
                lambda: self._command(
                    ["systemctl", "reset-failed", self.service_id], check=False
                ),
            )
            self.unit_created = False
        if self.root.exists() or self.root.is_symlink():
            if self.root.parent != Path("/tmp") or not self.root.name.startswith(
                "sentinel-blue-native-"
            ):
                errors.append("refused unexpected cleanup root")
            elif self.root.is_symlink():
                errors.append("refused symbolic-link cleanup root")
            else:
                attempt("lab root", lambda: shutil.rmtree(self.root))
        verified = (
            not errors
            and not self.root.exists()
            and not self.root.is_symlink()
            and not self.unit_path.exists()
            and not self.unit_path.is_symlink()
            and not self.cron_path.exists()
            and not self.cron_path.is_symlink()
            and not self._account_exists(self.account_name)
        )
        return {"verified": verified, "errors": errors}


def campaign(environ: Mapping[str, str] | None = None) -> dict[str, Any]:
    context = validate_runner_environment(environ)
    lab = NativeRunnerLab(context)
    report: dict[str, Any]
    try:
        lab.setup()
        report = lab.campaign()
    except Exception as exc:
        report = {
            "schema_version": 1,
            "status": "failed",
            "mode": "native changes on one disposable GitHub-hosted Linux runner",
            "version": __version__,
            "repository": context.repository,
            "error": f"{type(exc).__name__}: {str(exc)[:500]}",
        }
    cleanup = lab.cleanup()
    report["cleanup"] = cleanup
    if not cleanup["verified"]:
        report["status"] = "failed"
    return report


def _report_path(context: RunnerContext, requested: str | None) -> Path:
    destination = Path(requested) if requested else context.workspace / "native-live-report.json"
    if not destination.is_absolute():
        destination = context.workspace / destination
    resolved_parent = destination.parent.resolve()
    if resolved_parent != context.workspace or destination.name != "native-live-report.json":
        raise NativeRangeError(
            "native report must be GITHUB_WORKSPACE/native-live-report.json"
        )
    if destination.exists() or destination.is_symlink():
        raise NativeRangeError("native report destination already exists")
    return destination


def run(args: Any) -> int:
    context = validate_runner_environment()
    destination = _report_path(context, getattr(args, "output", None))
    report = campaign()
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    destination.write_text(encoded, encoding="utf-8")
    if getattr(args, "json", False):
        print(encoded, end="")
    else:
        print(
            "Sentinel Blue native disposable range: "
            f"{report['status']} ({report.get('scenarios_passed', 0)}/"
            f"{report.get('scenario_count', 0)} scenarios)"
        )
        print(f"Report: {destination}")
    return 0 if report.get("status") == "passed" else 1


__all__ = [
    "CONFIRMATION",
    "NativeRangeError",
    "RunnerContext",
    "build_native_profile",
    "campaign",
    "run",
    "validate_runner_environment",
]
