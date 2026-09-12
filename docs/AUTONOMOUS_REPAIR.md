# Coordinated autonomous repair in 1.9.32

Sentinel can now repair a declared service whose approved configuration was damaged or removed, including when the service is stopped. It can also restart a running but unhealthy application when its manifest explicitly permits this and a local application transaction fails. These are declarative repairs backed by approved files, not arbitrary shell commands generated from alerts.

## What changed

Previously, independent file restoration could roll back good configuration because service probes still failed while the service was stopped. At the same time, service recovery refused to start it because the files had changed. `repair_service` joins configuration restoration and service recovery into one journaled operation. It restores all selected files before checking configuration and starting the service. It commits only after three consecutive healthy rounds of the exact manifest transactions. Failed validation restores this operation's prior file contents, security metadata and native running/stopped state, provided no third-party changes prevent exact rollback.

The planner reports structured findings for missing/changed configuration, stopped services, unavailable accounts, stopped/unhealthy dependencies, local application failures, external-path/access failures and missing evidence. Dependency findings include an order from affected prerequisites toward the application. Each dependency needs its own approved recovery manifest and is repaired on its host before later healthy telemetry permits a dependent action. Cross-host dependency orchestration is not implemented.

Two consecutive fresh observations must describe the same fault, approved baseline and boot. A changing damaged-file fingerprint, baseline change, observation gap or incomplete collection resets confirmation. A running service must have a failed transaction to a numeric loopback address. A healthy loopback check with a failed remote check produces an external-path/access diagnosis; it does not authorize an automatic restart.

## Enable once for a declared service

Keep the existing release, TLS, identity, scope and event-approval configuration. Add `repair_service` to the profile's global `allowed_automatic_actions` and to the service's `allowed_automatic_actions`. The profile must permit `in_place_repair`, `file_restoration` and `structured_rollback`. Include `rollback_service_repair` in the service's `approval_actions` to expose manual Undo for a completed repair.

Add this object inside the existing service manifest, adjusting exact paths to that service:

```json
"repair_policy": {
  "restore_files": ["/etc/example/service.conf", "/etc/example/site.conf"],
  "restart_unhealthy": true,
  "validation_timeout_seconds": 30
}
```

On Windows use absolute Windows paths with JSON escaping. `restore_files` must contain at most 16 unique paths already declared in `required_files`. List configuration here, not changing business data. The planner rejects a repair overlapping another service's configuration or any declared `required_data` path/subdirectory. Shared files need a future multi-service transaction contract; they are not guessed safe.

Keep every service definition, executable/startup script and critical configuration that is needed to trust the service in `required_files` and in agent integrity collection. Declare all service accounts and same-host dependencies. Configure the exact `expected_transactions` on the agent, including meaningful local checks and any required application authentication. Numeric loopback targets such as `http://127.0.0.1:8080/health` are required to authorize a restart of an already running service; an IP/source label or DNS alias is insufficient evidence that a failed probe is local.

Start the controller with `--auto-recover-services`. Start the agent with both `--allow-service-recovery` and `--allow-restoration`, or the equivalent inventory flags. Approve a healthy baseline once; its capture action must complete successfully. Subsequent covered incidents do not require per-incident approval. Profiles without the new action retain the existing stopped-service recovery behavior. A declared repair action without `repair_policy` remains held with an explicit reason.

The validation window accepts 5–120 seconds. This is the application-probe grace, not a hard deadline for the entire action: native operations and an in-flight bounded probe round can add time. Existing probe scope, timeouts and transaction-count bounds remain in force. Increasing the window does not increase the 90-second initial observation freshness allowance.

## Execution and interruption handling

The agent independently rebuilds the repair contract from its manifest and current observation. It rechecks native service/dependency states, dependency transactions, unmodified files, every selected restore-point blob, and the observed state of each repair target before starting. The local repair must have both service and file-restoration permission.

A parent transaction reserves every child file-transaction ID before the first write. File bytes and metadata are verified individually; application/configuration checks occur after all selected files are restored. The success receipt binds the exact plan, file pins and stable probes. The controller rejects a success result missing those attestations. Changed files and service restarts are displayed together, with Undo tied to that exact parent transaction.

An interrupted parent is reconciled from its journals. Already healthy desired effects can be verified and committed; otherwise exact reversible effects can be undone with current local permission. Newer file contents or metadata cause a hold. A different approved profile cannot resume an unfinished parent transaction. This does not remove the separate controller crash-governance or action-envelope replay safeguards.

The new action shares the existing durable recovery budget with ordinary starts: five-minute cooldown, at most three attempts per service per hour, and no repeated mutation over an unresolved outcome. Renaming the action or restarting the process does not reset these limits. Signed change grants hold coordinated restoration of the same approved edit. Quarantining invalid baseline storage also invalidates pending repairs.

## Remaining limits

- There must already be a trustworthy, captured configuration and a confirmed manifest. This cannot infer a correct configuration from an initially broken or compromised baseline.
- Disabled/masked startup modes, unavailable required accounts, credential rotation, routing/firewall repair and unknown dependencies remain held. Diagnosing a symptom does not prove its cause or authorize a new policy.
- A restart does not eradicate an attacker or fix permanent configuration faults outside the selected files. WMI removal, application/fileless persistence and privileged agent tampering are unchanged.
- The native managers used are Windows SCM and Linux systemd. Application-specific repair, domain/database consistency and appliance recovery require additional adapters and contracts.
- Linux telemetry does not yet carry a general POSIX ownership/mode fingerprint. Content restoration preserves captured metadata, but a permissions-only change is not comprehensively diagnosed by this planner. Windows file security descriptors are part of its existing guarded contract.
- Local checks cannot establish an external scorer's reachability. The required external transactions must be exercised from the correct network position.
- No full-duration unattended competition uptime, complete-network opening time or arbitrary-failure recovery claim follows from these changes.

## Native acceptance

`tools/service_repair_native.py` creates uniquely named disposable loopback services. It checks damaged configuration pairs, a missing file, a running application with a recoverable internal failure, and an irrecoverable validation failure requiring rollback. It uses the real controller planner, baseline capture, agent action journal, native service manager, file restoration and HTTP probes. It does not replace or modify existing services. Each owned service is removed after its case.

The fixture supplies a controlled inventory containing only its own files, service and transactions, with a fixed fixture boot label and declared manual startup mode. File contents, Windows file security and native service states are read from the host. The controller uses an in-memory database in this fixture. This proves the coordinated repair path against native SCM/systemd operations; it does not exercise the complete production collector, native boot/start-mode discovery, cross-host transport or polling latency. The separate packaged lifecycle smoke test covers the authenticated controller/agent transport and restart governance.

Each repair clock begins immediately before the first fault observation and includes two immediate observations, controller planning, agent execution and stable validation (or rollback). It excludes fixture creation, baseline approval/capture, normal polling intervals, VM boot, payload staging and teardown. Failed-validation timings describe successful rollback of an unsuccessful repair, not service recovery. These timings must not be used as full incident-to-recovery latency or setup duration.

The Azure wrapper accepts `--fixture service-repair` and retains the existing exact resource/network checks, private payload transfer and deallocation cleanup. Existing Python is required; the Windows fixture compiles a small owned .NET service using installed Windows components. The native fixture follows Microsoft's [SC service creation contract](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/sc-create) and [ServiceBase initialization lifecycle](https://learn.microsoft.com/en-us/dotnet/api/system.serviceprocess.servicebase.onstart?view=netframework-4.8.1).

Results, timings and unresolved native failures are recorded separately in the release report. Unit tests use temporary files and controlled service-manager doubles; native evidence must be distinguished from those tests.

## Recorded 1.9.32 acceptance

Final native Linux and Windows fixtures each passed all four scenarios and 20 supporting assertions. The measured runtime SHA-256 is `7662aba26b73df7cb3314abefd754997fddb2ada88dbc4bfec2febd87ca54aac`.

| Controlled scenario | Linux | Windows | Outcome |
|---|---:|---:|---|
| Stopped service; two damaged configuration files | 1.834 s | 5.220 s | Configuration restored; stable service health |
| Stopped service; missing configuration file | 1.762 s | 3.788 s | File recreated; stable service health |
| Running application with recoverable internal failure | 1.729 s | 1.422 s | Authorized restart; stable service health |
| Persistent failure after configuration repair | 5.537 s | 9.098 s | Repair rejected; exact prior files and stopped state restored |

See `reports/autonomy-1.9.32-native.json` for the final native run and cleanup evidence, `reports/autonomy-1.9.32-initial-native.json` for the earlier candidate, and `reports/autonomy-1.9.32-local-validation.json` for the final local gates. The final local regression suite ran 952 tests: 949 passed and three skipped. The packaged self-test and authenticated lifecycle smoke check also passed. The measurement limits above apply to every native timing.
