"""Default-deny competition rules, scope, service, and autonomy profiles."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any
from urllib.parse import urlparse

from . import __version__
from .policy import ALLOWED_ACTIONS, AUTOMATIC_ACTIONS
from .risk import RiskModel
from .state import read_private_json


PROFILE_VERSION = 1
PROFILE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
AUTONOMY_MODES = frozenset(
    {"observe", "interactive", "approval-based", "guarded-autonomous", "range-autonomous"}
)
COMPETITIONS = frozenset({"ccdc-strict", "ncae-standard", "hivestorm", "cyberforce", "custom", "range"})
IDENTITY_CLASSES = frozenset(
    {
        "operations",
        "white-team",
        "scoring",
        "service",
        "blue-admin",
        "black-team",
        "red-team-required",
        "organizer",
    }
)
DEPLOYMENT_ROUTES = frozenset(
    {"ssh", "ssh-jump", "vpn", "winrm", "portal-upload", "signed-bootstrap", "preinstalled", "local", "agentless"}
)
CAPABILITIES = frozenset(
    {
        "in_place_repair",
        "structured_rollback",
        "configuration_backups",
        "network_monitoring",
        "external_controller",
        "second_vm_staging",
        "password_rotation",
        "account_disabling",
        "file_restoration",
        "host_snapshots",
        "full_vm_duplication",
        "scored_service_migration",
        "automatic_vm_replacement",
        "external_cloud_processing",
        "external_telemetry_export",
        "guarded_autonomy",
        "honeypots",
        "sandbox_analysis",
        "cyber_physical_changes",
        "broad_firewall_changes",
        "domain_credential_rotation",
        "database_restoration",
        "network_forks",
        "session_containment",
    }
)
COMMON_LIVE_PROHIBITIONS = frozenset(
    {"scored_service_migration", "automatic_vm_replacement", "network_forks"}
)
HIVESTORM_PROHIBITIONS = COMMON_LIVE_PROHIBITIONS | {
    "full_vm_duplication",
    "host_snapshots",
}
ACTION_CAPABILITIES = {
    "observe": None,
    "snapshot": "configuration_backups",
    "validate_service": "network_monitoring",
    "capture_restore_point": "configuration_backups",
    "restore_integrity": "file_restoration",
    "rollback_integrity": "structured_rollback",
    "quarantine_session": "session_containment",
    "release_quarantine": "session_containment",
    "restart_service": "in_place_repair",
    "rollback_service": "structured_rollback",
}
HOST_CHANGING_ACTIONS = frozenset(
    {
        "restore_integrity",
        "rollback_integrity",
        "quarantine_session",
        "release_quarantine",
        "restart_service",
        "rollback_service",
    }
)
EMERGENCY_ALLOWED_ACTIONS = frozenset(
    {"rollback_integrity", "rollback_service", "release_quarantine"}
)
GUARDED_ACTIONS = frozenset(
    {
        "snapshot",
        "validate_service",
        "capture_restore_point",
        "restore_integrity",
        "quarantine_session",
        "restart_service",
        "rollback_integrity",
        "rollback_service",
        "release_quarantine",
    }
)


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise ValueError(f"{label} must be an object with string keys")
    return value


def _text(value: Any, label: str, limit: int = 512, *, empty: bool = False) -> str:
    if not isinstance(value, str) or (not empty and not value) or len(value) > limit:
        raise ValueError(f"{label} must be a bounded string")
    if "\x00" in value or any(ord(character) < 32 for character in value):
        raise ValueError(f"{label} contains unsafe characters")
    return value


def _strings(value: Any, label: str, maximum: int, limit: int = 512) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum:
        raise ValueError(f"{label} must be an array of at most {maximum} strings")
    return [_text(item, f"{label}[{index}]", limit) for index, item in enumerate(value)]


def _boolean_map(value: Any, label: str, allowed: frozenset[str]) -> dict[str, bool]:
    row = _object(value, label)
    unknown = set(row) - set(allowed)
    if unknown:
        raise ValueError(f"{label} contains unknown keys: {', '.join(sorted(unknown))}")
    result = {name: False for name in allowed}
    for name, enabled in row.items():
        if type(enabled) is not bool:
            raise ValueError(f"{label}.{name} must be a boolean")
        result[name] = enabled
    return result


def _service_manifest(value: Any, index: int) -> dict[str, Any]:
    service = _object(value, f"services[{index}]")
    required = {
        "service_id",
        "host",
        "protocol",
        "port",
        "implementation",
        "dependencies",
        "required_accounts",
        "required_files",
        "required_data",
        "credential_source",
        "expected_transactions",
        "local_checks",
        "allowed_automatic_actions",
        "approval_actions",
        "backup_method",
        "recovery_method",
        "rollback_method",
    }
    missing = required - set(service)
    if missing:
        raise ValueError(
            f"services[{index}] is missing required fields: {', '.join(sorted(missing))}"
        )
    port = service["port"]
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError(f"services[{index}].port must be an integer from 1 to 65535")
    transactions = service["expected_transactions"]
    if not isinstance(transactions, list) or not transactions or len(transactions) > 32:
        raise ValueError(f"services[{index}].expected_transactions must contain 1 to 32 probes")
    if any(not isinstance(item, dict) for item in transactions):
        raise ValueError(f"services[{index}].expected_transactions must contain objects")
    automatic = _strings(
        service["allowed_automatic_actions"],
        f"services[{index}].allowed_automatic_actions",
        16,
        128,
    )
    approval = _strings(
        service["approval_actions"], f"services[{index}].approval_actions", 16, 128
    )
    unknown_actions = (set(automatic) | set(approval)) - set(ALLOWED_ACTIONS)
    if unknown_actions:
        raise ValueError(
            f"services[{index}] contains unsupported actions: {', '.join(sorted(unknown_actions))}"
        )
    return {
        "service_id": _text(service["service_id"], f"services[{index}].service_id", 128),
        "host": _text(service["host"], f"services[{index}].host", 128),
        "protocol": _text(service["protocol"], f"services[{index}].protocol", 32),
        "port": port,
        "implementation": _text(
            service["implementation"], f"services[{index}].implementation", 256
        ),
        "dependencies": _strings(
            service["dependencies"], f"services[{index}].dependencies", 64, 128
        ),
        "required_accounts": _strings(
            service["required_accounts"], f"services[{index}].required_accounts", 64, 128
        ),
        "required_files": _strings(
            service["required_files"], f"services[{index}].required_files", 256, 1024
        ),
        "required_data": _strings(
            service["required_data"], f"services[{index}].required_data", 256, 1024
        ),
        "credential_source": _text(
            service["credential_source"],
            f"services[{index}].credential_source",
            256,
            empty=True,
        ),
        "expected_transactions": [dict(item) for item in transactions],
        "local_checks": _strings(
            service["local_checks"], f"services[{index}].local_checks", 32, 512
        ),
        "allowed_automatic_actions": automatic,
        "approval_actions": approval,
        "backup_method": _text(
            service["backup_method"], f"services[{index}].backup_method", 512
        ),
        "recovery_method": _text(
            service["recovery_method"], f"services[{index}].recovery_method", 512
        ),
        "rollback_method": _text(
            service["rollback_method"], f"services[{index}].rollback_method", 512
        ),
    }


@dataclass(frozen=True, slots=True)
class EventProfile:
    profile_id: str
    competition: str
    environment: str
    autonomy_mode: str
    authorized_networks: tuple[str, ...]
    authorized_hosts: tuple[str, ...]
    controller_ingress_hosts: tuple[str, ...]
    excluded_hosts: tuple[str, ...]
    deployment_paths: tuple[str, ...]
    deployment_routes: frozenset[str]
    capabilities: dict[str, bool]
    allowed_automatic_actions: frozenset[str]
    identities: tuple[dict[str, str], ...]
    services: tuple[dict[str, Any], ...]
    services_confirmed: bool
    recovery_promotion_delay_seconds: float
    approval: dict[str, Any]
    release: dict[str, Any]
    organizer_exceptions: frozenset[str]
    raw: dict[str, Any]
    fingerprint: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "EventProfile":
        root = _object(payload.get("event_profile", payload), "event profile")
        if root.get("profile_version") != PROFILE_VERSION:
            raise ValueError(f"event profile_version must be {PROFILE_VERSION}")
        profile_id = _text(root.get("profile_id"), "profile_id", 128)
        if not PROFILE_ID.fullmatch(profile_id):
            raise ValueError("profile_id contains unsupported characters")
        competition = _text(root.get("competition"), "competition", 64).casefold()
        if competition not in COMPETITIONS:
            raise ValueError(f"unsupported competition profile: {competition}")
        environment = _text(root.get("environment"), "environment", 32).casefold()
        if environment not in {"live-competition", "range-autonomous"}:
            raise ValueError("environment must be live-competition or range-autonomous")
        autonomy_mode = _text(root.get("autonomy_mode"), "autonomy_mode", 32).casefold()
        if autonomy_mode not in AUTONOMY_MODES:
            raise ValueError("event profile contains an unsupported autonomy mode")
        if environment == "live-competition" and autonomy_mode == "range-autonomous":
            raise ValueError("range-autonomous mode cannot be used in a live competition profile")
        if environment == "range-autonomous" and competition != "range":
            raise ValueError("range-autonomous environment requires the range competition profile")

        architecture = _object(root.get("architecture"), "architecture")
        if architecture.get("single_live_scored_network") is not True:
            raise ValueError("single_live_scored_network must be explicitly true")
        if architecture.get("blue_staging_non_authoritative") is not True:
            raise ValueError("blue_staging_non_authoritative must be explicitly true")

        scope = _object(root.get("scope"), "scope")
        networks = _strings(scope.get("authorized_networks"), "scope.authorized_networks", 64, 128)
        if not networks:
            raise ValueError("scope.authorized_networks must not be empty")
        normalized_networks = tuple(
            str(ipaddress.ip_network(value, strict=False)) for value in networks
        )
        hosts = tuple(
            str(ipaddress.ip_address(value))
            for value in _strings(scope.get("authorized_hosts"), "scope.authorized_hosts", 1024, 128)
        )
        controller_ingress = tuple(
            str(ipaddress.ip_address(value))
            for value in _strings(
                scope.get("controller_ingress_hosts", []),
                "scope.controller_ingress_hosts",
                1024,
                128,
            )
        )
        excluded = tuple(
            str(ipaddress.ip_address(value))
            for value in _strings(scope.get("excluded_hosts"), "scope.excluded_hosts", 1024, 128)
        )
        if len(set(hosts)) != len(hosts):
            raise ValueError("scope.authorized_hosts must not contain duplicates")
        if len(set(controller_ingress)) != len(controller_ingress):
            raise ValueError("scope.controller_ingress_hosts must not contain duplicates")
        if set(hosts) & set(excluded):
            raise ValueError("a host cannot be both authorized and excluded")
        for address in hosts:
            parsed = ipaddress.ip_address(address)
            if not any(parsed in ipaddress.ip_network(network) for network in normalized_networks):
                raise ValueError(f"authorized host {address} is outside authorized networks")
        for address in controller_ingress:
            if address in excluded:
                raise ValueError(
                    f"controller ingress host {address} is explicitly excluded"
                )
            if address not in hosts:
                raise ValueError(
                    f"controller ingress host {address} is not in the authorized host inventory"
                )
        paths = tuple(
            _strings(scope.get("approved_deployment_paths"), "scope.approved_deployment_paths", 64, 1024)
        )
        if not paths or any(
            not (PurePosixPath(path).is_absolute() or PureWindowsPath(path).is_absolute())
            for path in paths
        ):
            raise ValueError("approved deployment paths must contain absolute paths")

        deployment = _object(root.get("deployment"), "deployment")
        routes = frozenset(
            value.casefold()
            for value in _strings(deployment.get("approved_routes"), "deployment.approved_routes", 16, 64)
        )
        if not routes or not routes <= DEPLOYMENT_ROUTES:
            raise ValueError("deployment.approved_routes contains an unsupported route")

        capabilities = _boolean_map(root.get("capabilities"), "capabilities", CAPABILITIES)
        exceptions = frozenset(
            _strings(root.get("organizer_exceptions", []), "organizer_exceptions", 32, 128)
        )
        if not exceptions <= CAPABILITIES:
            raise ValueError("organizer_exceptions contains an unknown capability")
        if environment == "live-competition":
            prohibited = set(COMMON_LIVE_PROHIBITIONS)
            if competition == "hivestorm":
                prohibited |= set(HIVESTORM_PROHIBITIONS)
            if competition == "ccdc-strict":
                prohibited.add("external_cloud_processing")
            for capability in prohibited:
                if capabilities[capability]:
                    raise ValueError(
                        f"{capability} is prohibited by the selected live competition profile"
                    )
            if capabilities["full_vm_duplication"] and "full_vm_duplication" not in exceptions:
                raise ValueError("full_vm_duplication requires an explicit organizer exception")
        if competition == "hivestorm" and exceptions & HIVESTORM_PROHIBITIONS:
            raise ValueError("Hivestorm does not permit VM copies, snapshots, or replacement")

        automatic_actions = frozenset(
            _strings(root.get("allowed_automatic_actions", []), "allowed_automatic_actions", 32, 128)
        )
        if not automatic_actions <= ALLOWED_ACTIONS:
            raise ValueError("allowed_automatic_actions contains an unsupported action")
        if automatic_actions and autonomy_mode not in {"guarded-autonomous", "range-autonomous"}:
            raise ValueError("automatic changing actions require guarded or range autonomy")
        if autonomy_mode == "guarded-autonomous" and not capabilities["guarded_autonomy"]:
            raise ValueError("guarded-autonomous mode requires guarded_autonomy capability")

        identity_rows = root.get("official_identities")
        if not isinstance(identity_rows, list) or len(identity_rows) > 2048:
            raise ValueError("official_identities must be a bounded array")
        identities: list[dict[str, str]] = []
        for index, item in enumerate(identity_rows):
            row = _object(item, f"official_identities[{index}]")
            identity_class = _text(
                row.get("class"), f"official_identities[{index}].class", 64
            ).casefold()
            if identity_class not in IDENTITY_CLASSES:
                raise ValueError(f"official_identities[{index}] has an unsupported class")
            identities.append(
                {
                    "agent_id": _text(
                        row.get("agent_id", "*"), f"official_identities[{index}].agent_id", 128
                    ),
                    "name": _text(row.get("name"), f"official_identities[{index}].name", 128),
                    "class": identity_class,
                    "source": _text(
                        row.get("source", "event-profile"),
                        f"official_identities[{index}].source",
                        128,
                    ),
                }
            )

        raw_services = root.get("services")
        if not isinstance(raw_services, list) or len(raw_services) > 256:
            raise ValueError("services must be an array of at most 256 manifests")
        services = tuple(_service_manifest(item, index) for index, item in enumerate(raw_services))
        services_confirmed = root.get("services_confirmed")
        if type(services_confirmed) is not bool:
            raise ValueError("services_confirmed must be a boolean")
        if services_confirmed and not services:
            raise ValueError("services_confirmed requires at least one service manifest")

        recovery = _object(root.get("recovery"), "recovery")
        delay = recovery.get("baseline_promotion_delay_seconds", 60)
        if isinstance(delay, bool) or not isinstance(delay, (int, float)) or not 0 <= float(delay) <= 3600:
            raise ValueError("recovery baseline promotion delay must be from 0 to 3600 seconds")

        approval = _object(root.get("approval"), "approval")
        release = _object(root.get("release"), "release")
        controller_ca_digest = release.get("controller_ca_sha256")
        if controller_ca_digest is not None and not SHA256.fullmatch(
            str(controller_ca_digest).casefold()
        ):
            raise ValueError("release.controller_ca_sha256 must be an exact SHA-256")
        normalized = json.loads(json.dumps(root, sort_keys=True, separators=(",", ":")))
        fingerprint = hashlib.sha256(
            json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        return cls(
            profile_id=profile_id,
            competition=competition,
            environment=environment,
            autonomy_mode=autonomy_mode,
            authorized_networks=normalized_networks,
            authorized_hosts=hosts,
            controller_ingress_hosts=controller_ingress,
            excluded_hosts=excluded,
            deployment_paths=paths,
            deployment_routes=routes,
            capabilities=capabilities,
            allowed_automatic_actions=automatic_actions,
            identities=tuple(identities),
            services=services,
            services_confirmed=services_confirmed,
            recovery_promotion_delay_seconds=float(delay),
            approval=dict(approval),
            release=dict(release),
            organizer_exceptions=exceptions,
            raw=normalized,
            fingerprint=fingerprint,
        )

    @classmethod
    def testing(cls) -> "EventProfile":
        """Explicit disposable-range profile used only by local tests and labs."""
        return cls.from_dict(
            {
                "profile_version": 1,
                "profile_id": "sentinel-blue-disposable-test",
                "competition": "range",
                "environment": "range-autonomous",
                "autonomy_mode": "range-autonomous",
                "architecture": {
                    "single_live_scored_network": True,
                    "blue_staging_non_authoritative": True,
                },
                "scope": {
                    "authorized_networks": ["0.0.0.0/0", "::/0"],
                    "authorized_hosts": [],
                    "controller_ingress_hosts": [],
                    "excluded_hosts": [],
                    "approved_deployment_paths": ["/tmp/sentinel-blue-range", "C:\\SentinelBlueRange"],
                },
                "deployment": {"approved_routes": ["local"]},
                "capabilities": {name: True for name in CAPABILITIES},
                "organizer_exceptions": list(CAPABILITIES),
                "allowed_automatic_actions": list(ALLOWED_ACTIONS),
                "official_identities": [],
                "services": [],
                "services_confirmed": False,
                "recovery": {"baseline_promotion_delay_seconds": 0},
                "approval": {"status": "range-only", "approved_by": "local-test"},
                "release": {"version": __version__, "approved": False},
            }
        )

    def require_live_ready(self, release_version: str = __version__) -> None:
        if self.environment != "live-competition":
            raise ValueError("a disposable range profile cannot authorize live deployment")
        if self.approval.get("status") != "approved" or not self.approval.get("approved_by"):
            raise ValueError("event profile requires explicit organizer or event approval")
        if self.release.get("approved") is not True:
            raise ValueError("the Sentinel Blue release is not marked approved in the event profile")
        if self.release.get("version") != release_version:
            raise ValueError(
                f"event profile approves release {self.release.get('version')!r}, not {release_version!r}"
            )
        digest = str(self.release.get("sha256", "")).casefold()
        if not SHA256.fullmatch(digest):
            raise ValueError("event profile release requires an exact SHA-256")
        self._require_controller_transport_contract("event profile")
        public_url = urlparse(str(self.release.get("public_url", "")))
        if (
            public_url.scheme != "https"
            or not public_url.hostname
            or public_url.username
            or public_url.password
        ):
            raise ValueError("event profile release requires a public credential-free HTTPS URL")
        for field in (
            "frozen",
            "submitted_to_officials",
            "submission_approved",
            "public_and_equal_access",
        ):
            if self.release.get(field) is not True:
                raise ValueError(f"event profile release requires {field}=true")
        if self.release.get("cloud_processing") is not False:
            raise ValueError("event profile must explicitly disable release cloud processing")
        if self.release.get("external_telemetry_export") is not False:
            raise ValueError("event profile must explicitly disable external telemetry export")
        public_days = self.release.get("public_days_before_event", 0)
        submitted_days = self.release.get("submitted_days_before_event", 0)
        if type(public_days) is not int or type(submitted_days) is not int:
            raise ValueError("release publication/submission lead times must be integer days")
        if self.competition == "ccdc-strict" and (public_days < 90 or submitted_days < 30):
            raise ValueError("CCDC Strict requires 90 public days and 30 submitted days")
        if self.competition == "ncae-standard" and (public_days < 7 or submitted_days < 7):
            raise ValueError("NCAE Standard requires public disclosure and approval at least 7 days before the event")
        if not self.authorized_hosts:
            raise ValueError("live deployment requires an explicit authorized_hosts inventory")
        if not self.services_confirmed or not self.services:
            raise ValueError("live deployment requires confirmed service manifests")
        if not self.identities:
            raise ValueError("live deployment requires an explicit official identity manifest")
        if not self.capabilities["external_controller"]:
            raise ValueError("live Sentinel deployment requires external_controller approval")

    def require_range_ready(self, release_version: str = __version__) -> None:
        """Require an explicit, bounded profile for a real disposable test range."""
        if self.environment != "range-autonomous" or self.competition != "range":
            raise ValueError("range deployment requires a range-autonomous range profile")
        if self.approval.get("status") != "range-only" or not self.approval.get("approved_by"):
            raise ValueError("range deployment requires explicit range-only authorization")
        if self.release.get("version") != release_version:
            raise ValueError(
                f"range profile approves release {self.release.get('version')!r}, not {release_version!r}"
            )
        digest = str(self.release.get("sha256", "")).casefold()
        if not SHA256.fullmatch(digest):
            raise ValueError("range profile release requires an exact SHA-256")
        self._require_controller_transport_contract("range profile")
        if self.release.get("external_telemetry_export") is not False:
            raise ValueError("range profile must explicitly disable external telemetry export")
        if self.release.get("cloud_processing") is not False:
            raise ValueError("range profile must explicitly disable release cloud processing")
        if not self.authorized_hosts:
            raise ValueError("range deployment requires an explicit authorized_hosts inventory")
        if not self.services_confirmed or not self.services:
            raise ValueError("range deployment requires confirmed service manifests")
        if not self.capabilities["external_controller"]:
            raise ValueError("range deployment requires external_controller approval")

    def require_runtime_ready(
        self,
        release_version: str = __version__,
        *,
        range_deployment: bool = False,
    ) -> None:
        """Select the live or disposable-range gate without weakening either one."""
        if range_deployment:
            self.require_range_ready(release_version)
            return
        self.require_live_ready(release_version)

    @property
    def requires_strict_transport(self) -> bool:
        """Whether this profile represents a checksum-bound deployed runtime."""
        return self.environment == "live-competition" or (
            self.environment == "range-autonomous"
            and SHA256.fullmatch(str(self.release.get("sha256", "")).casefold()) is not None
        )

    @property
    def controller_ca_sha256(self) -> str:
        return str(self.release.get("controller_ca_sha256", "")).casefold()

    def _require_controller_transport_contract(self, label: str) -> None:
        if not SHA256.fullmatch(self.controller_ca_sha256):
            raise ValueError(
                f"{label} release requires controller_ca_sha256 as an exact SHA-256"
            )
        if not self.controller_ingress_hosts:
            raise ValueError(
                f"{label} requires an explicit scope.controller_ingress_hosts inventory"
            )

    @staticmethod
    def _file_digest(path: str | Path, label: str, maximum: int | None = None) -> str:
        target = Path(path)
        if target.is_symlink() or not target.is_file():
            raise ValueError(f"{label} is unavailable or is a symbolic link")
        descriptor = os.open(target, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        digest = hashlib.sha256()
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise ValueError(f"{label} is not a regular file")
            if maximum is not None and details.st_size > maximum:
                raise ValueError(f"{label} exceeds its size limit")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
        finally:
            os.close(descriptor)
        return digest.hexdigest()

    def verify_release_file(self, path: str | Path) -> str:
        observed = self._file_digest(path, "frozen runtime")
        if observed != str(self.release.get("sha256", "")).casefold():
            raise ValueError("frozen runtime digest does not match the event profile")
        return observed

    def verify_controller_ca_file(self, path: str | Path) -> str:
        """Authenticate the exact public trust anchor approved by the profile."""
        expected = self.controller_ca_sha256
        if not SHA256.fullmatch(expected):
            raise ValueError(
                "controller CA verification requires release.controller_ca_sha256"
            )
        observed = self._file_digest(path, "controller CA certificate", 1024 * 1024)
        if observed != expected:
            raise ValueError(
                "controller CA certificate digest does not match the event profile"
            )
        return observed

    def verify_model_file(self, path: str | Path) -> str:
        """Bind an optional external risk model to the approved event profile."""
        self.load_model_file(path)
        return str(self.release.get("model_sha256", "")).casefold()

    def load_model_file(self, path: str | Path) -> RiskModel:
        """Authenticate and parse an external model from one byte snapshot."""
        expected = str(self.release.get("model_sha256", "")).casefold()
        if not SHA256.fullmatch(expected):
            raise ValueError("external model requires release.model_sha256 in the event profile")
        return RiskModel.load_verified(path, expected)

    def allows(self, capability: str) -> bool:
        if capability not in CAPABILITIES:
            raise ValueError(f"unknown capability: {capability}")
        return bool(self.capabilities[capability])

    def assert_target(self, address: str) -> None:
        parsed = ipaddress.ip_address(address)
        if str(parsed) in self.excluded_hosts:
            raise ValueError(f"target {parsed} is explicitly excluded by the event profile")
        if not any(parsed in ipaddress.ip_network(network) for network in self.authorized_networks):
            raise ValueError(f"target {parsed} is outside the event profile networks")
        if self.authorized_hosts and str(parsed) not in self.authorized_hosts:
            raise ValueError(f"target {parsed} is not in the event profile host inventory")

    def assert_route(self, route: str) -> None:
        normalized = route.casefold()
        mapped = {"web-console": "portal-upload", "auto": "ssh"}.get(normalized, normalized)
        if mapped not in self.deployment_routes:
            raise ValueError(f"deployment route {route!r} is not approved by the event profile")

    def assert_deployment_path(self, path: str) -> None:
        normalized = path.rstrip("/\\").casefold()
        allowed = [item.rstrip("/\\").casefold() for item in self.deployment_paths]
        if not any(normalized == root or normalized.startswith(root + "/") or normalized.startswith(root + "\\") for root in allowed):
            raise ValueError(f"deployment path {path!r} is not approved by the event profile")

    def assert_inventory_networks(self, networks: list[str]) -> None:
        normalized = {str(ipaddress.ip_network(value, strict=False)) for value in networks}
        if normalized != set(self.authorized_networks):
            raise ValueError("inventory networks must match the event profile exactly")

    def action_allowed(
        self,
        action_type: str,
        *,
        automated: bool,
        autonomy_mode: str | None = None,
        emergency_stopped: bool = False,
    ) -> bool:
        if action_type not in ALLOWED_ACTIONS:
            return False
        mode = (autonomy_mode or self.autonomy_mode).casefold()
        if mode not in AUTONOMY_MODES:
            return False
        capability = ACTION_CAPABILITIES[action_type]
        if capability is not None and not self.capabilities[capability]:
            return False
        if emergency_stopped:
            return action_type in EMERGENCY_ALLOWED_ACTIONS
        if mode == "observe":
            return action_type not in HOST_CHANGING_ACTIONS and not automated
        if mode == "interactive":
            return not automated
        if mode == "approval-based":
            return not automated or (
                action_type in AUTOMATIC_ACTIONS
                and action_type in self.allowed_automatic_actions
            )
        if mode == "guarded-autonomous":
            if not automated:
                return True
            return (
                self.capabilities["guarded_autonomy"]
                and action_type in GUARDED_ACTIONS
                and action_type in self.allowed_automatic_actions
            )
        if self.environment != "range-autonomous":
            return False
        return not automated or action_type in self.allowed_automatic_actions

    def protected_accounts(self) -> list[dict[str, str]]:
        return [dict(item) for item in self.identities]


def load_event_profile(path: str | Path) -> EventProfile:
    payload = read_private_json(path, 2 * 1024 * 1024)
    return EventProfile.from_dict(_object(payload, "event profile file"))


__all__ = [
    "AUTONOMY_MODES",
    "CAPABILITIES",
    "EMERGENCY_ALLOWED_ACTIONS",
    "EventProfile",
    "HOST_CHANGING_ACTIONS",
    "load_event_profile",
]
