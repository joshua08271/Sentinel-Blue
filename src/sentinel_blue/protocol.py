"""Wire and storage models shared by the controller and agents."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from . import __version__


# The agent independently rejects controller bodies above 2,000,000 bytes.
# Keep a wide safety margin for exact JSON serialization and future envelope
# fields, and use the same ceiling when leasing action rows.
MAX_AGENT_EGRESS_BYTES = 1_000_000
MAX_PENDING_ACTIONS_PER_RESPONSE = 32
MAX_DETECTION_CANDIDATES_PER_TELEMETRY = 64
MAX_DETECTION_CANDIDATES_PER_KIND = 8


@dataclass(slots=True)
class Account:
    name: str
    account_id: str
    privileged: bool = False
    enabled: bool = True
    source: str = "local"
    groups: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Session:
    username: str
    source: str = "unknown"
    session_id: str = ""
    process_id: int | None = None
    privileged: bool = False
    interactive: bool = True
    process_identity: dict[str, Any] | None = None


@dataclass(slots=True)
class Service:
    name: str
    state: str
    start_mode: str = "unknown"
    substate: str = "unknown"
    result: str = "unknown"
    restart_count: int = 0
    exit_code: int | None = None


@dataclass(slots=True)
class Interface:
    name: str
    addresses: list[str] = field(default_factory=list)


@dataclass(slots=True)
class Route:
    destination: str
    gateway: str = ""
    interface: str = ""
    metric: int | None = None


@dataclass(slots=True)
class Neighbor:
    address: str
    hardware_address: str = ""
    interface: str = ""
    state: str = "unknown"


@dataclass(slots=True)
class Listener:
    protocol: str
    address: str
    port: int
    process: str = ""


@dataclass(slots=True)
class IntegrityItem:
    path: str
    sha256: str
    size: int
    modified_at: float
    readable: bool = True
    security_descriptor_sha256: str = ""


@dataclass(slots=True)
class ProbeResult:
    name: str
    target: str
    healthy: bool
    latency_ms: float | None = None
    detail: str = ""


@dataclass(slots=True)
class ProcessObservation:
    name: str
    path: str
    username: str
    process_id: int
    parent_id: int = 0
    privileged: bool = False


@dataclass(slots=True)
class PersistenceItem:
    kind: str
    name: str
    owner: str = "unknown"
    enabled: bool = True
    sha256: str = ""


@dataclass(slots=True)
class SecurityEvent:
    event_id: str
    category: str
    outcome: str = "observed"
    account: str = "unknown"
    actor: str = "unknown"
    remote_address: str = "unknown"
    occurred_at: float = 0.0
    detail: str = ""


@dataclass(slots=True)
class FirewallState:
    enabled: bool
    provider: str = "unknown"
    rules_sha256: str = ""
    detail: str = ""


@dataclass(slots=True)
class Telemetry:
    agent_id: str
    hostname: str
    platform: str
    observed_at: float
    accounts: list[Account] = field(default_factory=list)
    sessions: list[Session] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    interfaces: list[Interface] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    neighbors: list[Neighbor] = field(default_factory=list)
    listeners: list[Listener] = field(default_factory=list)
    integrity: list[IntegrityItem] = field(default_factory=list)
    probes: list[ProbeResult] = field(default_factory=list)
    processes: list[ProcessObservation] = field(default_factory=list)
    persistence: list[PersistenceItem] = field(default_factory=list)
    security_events: list[SecurityEvent] = field(default_factory=list)
    firewall: FirewallState = field(default_factory=lambda: FirewallState(False))
    collector_errors: list[str] = field(default_factory=list)
    agent_version: str = __version__
    profile_id: str = ""
    profile_fingerprint: str = ""
    boot_id: str = "unknown"
    sequence: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class AlertCandidate:
    kind: str
    title: str
    summary: str
    severity: str
    confidence: float
    evidence: dict[str, Any]
    recommendation: str
    recommended_action: str


@dataclass(slots=True)
class ActionRequest:
    action_id: str
    agent_id: str
    action_type: str
    parameters: dict[str, Any]
    status: str
    created_at: float
    automated: bool = False
    risk: str = "high"
    expires_at: float = 0.0
    profile_id: str = ""
    profile_fingerprint: str = ""
    autonomy_mode: str = ""
