# Windows collection under CPU load

Sentinel Blue requires complete, fresh telemetry before autonomous service recovery. A slow native query can prevent a valid repair even when the service fault is otherwise repairable.

**Status: development candidate; this issue is not yet closed.** The direct-SCM candidate passed 951 local tests, with three platform/dependency skips, all fifteen packaged self-test checks, and the authenticated controller/agent lifecycle check. Its native Azure result was not received. The console first reported an expired token and then Azure portal pages returned `502 Bad Gateway` / `Connection refused`. An interrupt was attempted through the original console, but no response confirmed delivery. The final test's guest result, VM deallocation, IP association restoration and temporary-payload cleanup remain unknown. See `reports/windows-load-1.9.33-pending-native.json` for the exact runtime and recovery references. The earlier runs' verified cleanup does not establish cleanup for this last run.

The 1.9.33 work began with the exact released 1.9.32 runtime on an Azure Windows Server 2022 B1ms VM (one logical CPU, 2 GiB RAM). Idle collection took 23.752 seconds and collection after the load ended took 17.924 seconds. All three observations under one owned CPU worker exhausted the 75-second native inventory budget. Only the account query completed; the service section stalled. These observations correctly held recovery. The full baseline is in `reports/windows-load-1.9.33-baseline.json`.

## Changes

- Boot identity uses the same current PowerShell batch as accounts, services, sessions, topology, processes, persistence, firewall, interfaces and security events. The batch and its results are discarded after each collection.
- Only the finite inventory helper runs at Windows AboveNormal priority. The agent, monitored services and owned load worker retain their priorities. The existing deadline still kills an over-budget helper.
- Service inventory reads the local Service Control Manager directly with `EnumServicesStatusExW` and `QueryServiceConfigW`. One complete snapshot supplies service health and command-path persistence, replacing two `Win32_Service` CIM queries. Native state, startup mode, command path and exit code remain available. The service substate now reports the native SCM state in place of the generic CIM `Status` property.
- Service enumeration is bounded at 4,096 unique records and rejects incomplete pages, query failures and invalid native data. Persistence no longer silently stops at 1,024 service commands.
- Service restart history uses an exact native XPath selector for the System channel, Service Control Manager provider, event IDs 7031/7034 and the last fifteen minutes. Provider failures and more than 512 matching events make collection incomplete; an empty successful query remains valid.
- A crash is counted once when a service's display name equals its native name, avoiding a false restart-loop signal.
- The acceptance fixture collects the full production inventory before, during and after at least three minutes of CPU load. It also uses fresh native inventory to drive a real Windows service repair under another bounded CPU worker, with the normal fifteen-second observation interval.

## Preserved requirements

The native inventory budget remains 75 seconds. Telemetry is dated at collection start. Recovery still requires evidence no older than 90 seconds, a native boot identity, consecutive observations, no collection errors, an approved restore point and explicit per-service repair authority. No section is skipped or filled from a previous collection. CPU worker priority and workload must be reported as part of native evidence.

The repair fixture creates a unique loopback service, crashes it once to verify real restart-event evidence, then stops it and damages two owned configuration files. Successful acceptance requires approved bytes restored, the service running, stable HTTP transactions, and removal of the owned service and CPU workers. Temporary logon auditing is restored to its original policy.

During healthy collections, a concurrent HTTP monitor requires successful requests and a maximum scheduled response time of two seconds. This includes monitor scheduling delay, so a scheduling improvement for inventory cannot pass by starving the healthy fixture service.

Before the load phase, the native fixture compares SCM service identities, startup modes and command paths against CIM. A mismatch stops acceptance. The failing first candidate, which did not yet use direct SCM reads, is preserved in `reports/windows-load-1.9.33-first-candidate.json`.

The first candidate completed idle collection in 12.740 seconds, but all three loaded observations still timed out (75.976–76.448 seconds). That was a failed acceptance result. Direct SCM reads were added afterward; no loaded timing is available for that candidate yet.

## Remaining acceptance gate

Recover the retained Azure diagnostic directory and inspect the original runner before starting another test. Verify all four lab VMs are deallocated, the original network digest is restored, and temporary test payload containers are absent. If the original result is missing or incomplete, repeat `collection-pressure` with the exact candidate runtime checksum after cleanup. Closing the issue requires every full collection to be complete and fresh, native SCM/CIM parity, real crash-event detection, autonomous restoration and stable service health under load, and verified cleanup. A timeout, partial inventory, missing result or local-only test pass cannot satisfy this gate.

## Scope

These measurements concern observation and repair, not installation time or competition uptime. The fixture invokes the real controller planner and agent executor with an in-memory store; it does not measure remote transport, live scorer behavior or production poll alignment. VM boot and Azure orchestration are reported separately. A single small lab VM cannot establish reliability against every form of CPU, memory, disk or event-log exhaustion.
