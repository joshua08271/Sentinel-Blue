# Sentinel Blue 1.9.24

Sentinel Blue is a Python controller and host agent for authorized blue-team environments. It collects host state, detects changes, preserves evidence, and performs explicitly authorized recovery actions on Linux and Windows.

The downloadable `.pyz` runtime requires Python 3.11 or newer. The complete ZIP includes that runtime, source, tests, examples, and deployment tools.

```console
python sentinel-blue-1.9.24.pyz --help
python sentinel-blue-1.9.24.pyz doctor
python sentinel-blue-1.9.24.pyz self-test --json
```

Use `launcher --help` to prepare an inventory-based deployment. The launcher needs a reachable controller, an exact release checksum, an event profile, and the approved deployment credentials and routes. Browser access to a VM console alone does not provide SSH access.

Versions 1.9.17–1.9.19 fix native Linux recovery states, dependency configuration checks, independent service permissions, and ordinary controller shutdowns. Version 1.9.18 also keeps internal probe records out of remote-agent authority checks, avoids Windows inventory helper races, and reports blocked action admission as a conflict. See [the recovery guide](docs/AUTONOMOUS_SERVICE_RECOVERY.md) for activation requirements and behavior. It also preserves the integrity restoration, signed controller/agent protocol, protected identity policy, reversible containment, and native Windows persistence and firewall monitoring from earlier releases.

Version 1.9.19 processes queued captures before replacing their accepted telemetry and recollects after actions that arrived during collection. Windows firewall inventory has a bounded 60-second timeout.

Version 1.9.20 limits Windows helper concurrency to available CPUs, gives native inventories a bounded 60-second timeout, and collects process owners in bulk with PID and creation-time correlation. These changes address incomplete telemetry observed during the native Windows recovery exercise. Recovery still requires complete, fresh observations.

Version 1.9.21 dates telemetry at the start of collection, rejects partial PowerShell results accompanied by errors, and reports empty required account/service inventories as incomplete. Windows deployments and inventory helpers explicitly use normal CPU priority. Its native Windows pressure tests still exceeded a 120-second collection deadline.

Version 1.9.22 retrieves only the CIM properties used for service/process/boot observations and shares one PowerShell host across route, neighbor, and listener queries. Per-section failures remain explicit, and every existing network field is retained. Its native Linux/Windows service and file recovery checks passed. Sustained CPU load still exceeded a 120-second collection deadline, and a clean controller restart unexpectedly entered observe mode with emergency stop enabled. Those native failures remain unresolved; a passing local suite does not establish competition readiness.

Version 1.9.23 closes privileged-account review gaps: disabled logins and initial baseline membership no longer exempt unknown administrative identities, familiar account names need matching built-in identifiers, name collisions retain every account row, and protected UID/SID replacements raise an alert. Linux primary-group administrative membership is included. See [pre-existing privileged accounts](docs/PREEXISTING_PRIVILEGED_ACCOUNTS.md) for coverage and trust limits. Native validation of this candidate is pending.

Further work on 1.9.23 reproduces the clean-restart failure with a slow loopback probe and fixes its shutdown path. The controller drains active HTTP requests, relay probes, and maintenance work against one 20-second deadline. Queued probes stop before opening connections; a cancelled batch cannot become telemetry. Repeated stop signals remain handled through database cleanup. A worker that cannot drain or an uncertain governance write still leaves the crash marker set. The packaged local test preserves approved governance across a clean restart and resets to observation with emergency stop after a forced kill. The Azure restart case and Windows CPU-pressure case still need native retesting. CI now derives package paths from the current release version and runs this lifecycle check on Linux.

The default settings collect and report evidence. An event profile governs which actions may run automatically. An approved baseline is an explicit trust decision: it must be reviewed before promotion, especially on a host that might already be compromised. A compromised host with root or SYSTEM can interfere with its own defender; this package does not guarantee recovery from every such attack.

Version 1.9.24 shares a 75-second budget across Windows inventory queries, reuses the same boot identity throughout collection, and reports incomplete results explicitly. This bounds query contention without extending the 90-second evidence freshness limit. The service recovery panel shows durable cooldowns, unresolved outcomes, attempt limits, and the earliest possible retry time; fresh observations and normal authorization are still required. The native runner workflow measures real collection before, during, and after bounded CPU load. This candidate's validation results must be checked before deployment; these changes alone do not establish full-event competition readiness.

The Windows restore path compares the replacement file's security descriptor before changing it. Matching SACL components remain intact while changed owner, group, or DACL components are restored on the exclusive native handle. The complete descriptor must still match before publication; other differences require the full backup path and the same verification. See [endurance acceptance](docs/ENDURANCE_ACCEPTANCE.md) for the remaining practice-event gates.

Competition use requires the event's actual rules and permitted deployment paths. The included examples are templates and do not establish organizer approval or authorize a scored network.
