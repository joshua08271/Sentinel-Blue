# Sentinel Blue 1.5 resilience and continuity validation report

Validation date: 2026-08-13

## Result

Version 1.5 passed every locally executable certification gate. This release
closes additional first-use and uptime blind spots, but it is not competition-
proven and the synthetic results below are not an uptime guarantee.

The safety boundary remains human-governed: no arbitrary shell, global freeze,
blanket account deletion, universal root password, autonomous firewall rewrite,
or automatic account disablement. Resource and audit uncertainty are advisory.
The only new changing automation is a separately armed, probe-gated continuity
start of an approved baseline service, with a local agent gate, pre-state,
post-action validation, and rollback.

## New defensive and availability improvements

- Linux and Windows agents report audit evidence readiness, policy visibility,
  persistence, and time synchronization. An unavailable log source explicitly
  prevents “no events” from being interpreted as “clean.”
- Memory, disk, inode, CPU/load headroom is normalized and bounded. Exhaustion
  evidence cannot directly stop a process or restart a service.
- Inherently suspicious audit events alert on the first sample instead of
  waiting for baseline approval; their response remains evidence-only.
- Account creation, privilege, logon, actor, and source events are condensed
  into bounded identity chains for faster operator review.
- Probes support acyclic `depends_on` relationships, bounded layer/path budgets,
  cascade suppression, and root-cause display. Invalid, cyclic, oversized, or
  unsupported configurations fail before deployment.
- Safe SSH, FTP, MySQL, and PostgreSQL application handshakes supplement HTTP,
  HTTPS, DNS, SMTP, TLS, banner, and TCP checks. Optional latency budgets turn a
  scorer-timeout risk into a failed check; baseline-relative slowdown remains
  advisory.
- Every decision and action has a pre-action impact summary, affected objects,
  planned checks, reversibility, and rollback description.
- Continuity mode requires an approved baseline, an exact service-to-probe
  mapping, present failed probe results, repeated matching observations, a
  controller arm, normal containment permission, and a separate agent arm.
- The dashboard exposes identity chains, dependency state/root causes, audit
  readiness through baseline scoring, continuity state, and impact previews.
- Agent, launcher, controller, wire, probe, deployment, self-test, documentation,
  examples, packaging, and CI syntax checks were updated together.

## Automated results

| Validation | Result |
|---|---:|
| Python unit/integration suite | 172/172 passed |
| Python bytecode compilation | Passed |
| Dashboard and portal JavaScript syntax | Passed |
| Linux native collector smoke | Passed; audit/resource telemetry emitted |
| Packaged self-test | 16/16 checks passed |

The standard full certification on the final source completed in 111.659 seconds:

| Full preset | Result |
|---|---:|
| Hostile telemetry payloads | 15,000/15,000 rejected; 0 accepted |
| End-to-end scenarios | 2,500/2,500 correct |
| Encoded incidents | 1,966 detected; 0 missed |
| Encoded benign scenarios | 534 clear; 0 high-priority false alerts |
| Dry-run actions | 2,097 queued; 2,097 completed |
| Restoration attack scenarios | 500/500 passed |
| Sustained ingest | 10,000 events; 1,168.34 events/s; 1.688 ms p95 |
| Backup recovery | SQLite integrity `ok`; 16/16 agents recovered |

The separate maximum-bound campaigns also passed:

| Maximum campaign | Result |
|---|---:|
| Hostile telemetry fuzz | 50,000/50,000 rejected; 0 accepted |
| End-to-end range | 5,000/5,000 correct |
| High-priority incidents | 3,945 detected; 0 missed |
| Benign scenarios | 1,055 clear; 0 high-priority false alerts |
| Dry-run actions | 4,218 queued; 4,218 completed |
| Integrated restoration scenarios | 1,000/1,000 passed |
| Independent restoration policy attacks | 5,000/5,000 passed |
| Sustained ingest | 50,000 events; 1,121.82 events/s; 1.683 ms p95 |
| Combined maximum run | 302.215 seconds; all 16 gates passed |

The restoration campaign covered confirmed tamper, stale observations, deleted
files, failed scorer validation, operator undo, corrupt restore blobs, corrupt
manifests, interrupted replacement, and failed native configuration validation.
All changing actions in synthetic certification were dry-run except reversible
operations on disposable local files and a disposable child-process quarantine.

## Platform evidence and hard boundary

Linux code was exercised on the build host, including audit/resource collection,
application handshake fixtures, process suspend/resume, file watching, metadata/
xattrs, atomic transactions, and systemd-unit generation. The restricted
container did not permit full route/neighbor/interface enumeration; this was
reported as degraded collection rather than silently accepted.

Windows collection, auditpol/Event Log logic, resource CIM logic, ACL helpers,
OpenSSH validation, event mappings, Scheduled Task recovery, process APIs, and
WinRM scripts passed code, fixture, and argument-vector tests. There is no
Windows kernel, PowerShell, WinRM endpoint, Task Scheduler, IIS, Windows Event
Log, or NTFS ACL implementation in this environment, so native behavior remains
unverified.

Further progress now requires external fixtures:

1. Representative Windows Server/client and Ubuntu/Debian/Rocky guests with the
   actual scored services, audit policies, service managers, and safe reset.
2. Real SSH/WinRM paths and the practice event's authentication model.
3. The authorized portal's origins, console/iframe implementation, MFA,
   clipboard/upload policy, and any canvas/noVNC limitations.
4. The scorer's transactions, credentials, source addresses, latency cutoff,
   state mutations, and official Black/White/scoring identities.
5. Authorized Red Team and benign team activity long enough to measure uptime,
   alert burden, false decisions, recovery time, and inject interaction.

Until those gates pass, use the monitoring, dependency/latency probes, protected
identities, snapshots, and decision support. Keep live containment, restoration,
and continuity disabled on unvalidated event images. Do not convert these local
results into a promised CCDC uptime percentage.
