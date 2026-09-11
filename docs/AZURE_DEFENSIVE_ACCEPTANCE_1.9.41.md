# Sentinel Blue 1.9.41 defensive Azure acceptance

Measured on 11 September 2026. This is a working defender release candidate;
complete autonomous competition readiness has **not** been established.
No live red-team exercise was executed.

## Exact program

Runtime: `sentinel-blue-1.9.41.pyz`

SHA-256:
`2f255164e29f7487cf5f19a6d8c181472df195006b282a06bac50b683f6fab19`

The runtime and supplied source match byte for byte. The generated zipapp entry
point disables the campaign commands, and their implementation modules are
absent. The source archive includes the defensive Azure harness, selected
regressions, example inventories, and operating instructions. Test harness
corrections do not change the runtime digest above.

## Scope

Tests used the existing `sb-linux-target` and `sb-windows-target` Azure VMs in
`sentinel-blue-range-wus2`. Windows is a single-core Standard_B1ms VM. Existing
operating systems, Python installations, packages and server roles were reused.
Each guest hosted its own controller and agent. These were actual native host
operations, but controller/agent network traffic and fixture probes stayed on
loopback. This is not a complete mixed-host network or external scoring test.

The wrapper required the exact existing network digest and runtime checksum,
removed the reserved public-IP associations while the VMs were off, and started
only the two defensive targets. `sb-redsim` and `sb-controller` remained off.
Delivery used expiring private Azure blobs. The cleanup wrapper deallocates the
targets, verifies all four VMs are off, restores the original network, retrieves
selected JSON evidence, and removes temporary blob staging. Installed packages
and server roles are deliberately retained; owned service fixtures are removed.

Reviewed network digest:
`974cd3c73f48ec5463a675ec216a7ced969d5873a7f022e0ba45a1f9420a6c72`

## Initial Azure acceptance

Run `90925704c655`, evidence directory
`/tmp/sentinel-defensive-kdvgb9z7` in the authenticated Cloud Shell.
Overall result: **failed**, with power, network and staging cleanup verified.

| Check | Linux | Windows |
| --- | --- | --- |
| Service setup and defender opening | Passed, 51.599 s measured opening | Failed; server-feature inventory exceeded its bounded check |
| Agent transport | Passed | Passed |
| Slow owned HTTP/readiness peers | Passed | Failed timing bound in one of six trials; all late results rejected |
| Controller continuity | Passed, including authorized crash resume | Passed basic enrollment, signed operations, backup and shutdown |
| Four ordinary native service faults | All passed | All passed |
| Recovery using full native telemetry | Blocked at baseline approval | Blocked at baseline approval |
| CPU collection pressure | Held after incomplete recovery diagnostics | Held after incomplete recovery diagnostics |

The opening clock runs from guest entry to readiness; payload delivery, VM boot
and prior dependency preparation are excluded. Linux's 51.599 seconds does not
prove the full first-upload-to-network-ready target of 180 seconds.

The native service cases exercised damaged files, a missing file, a running
unhealthy application, and validation failure with rollback. Linux repair
durations were 3.086, 1.875, 1.810 and 7.992 seconds; Windows durations were
4.559, 4.192, 1.661 and 13.395 seconds. These four cases used real owned native
services and the actual repair planner/executor with fixture-limited telemetry.
They do not substitute for the separate full-native-telemetry recovery check.

Windows feature discovery took 60.765 seconds and blocked dependent setup
tasks. Concurrent controller preparation was removed on single-core Windows
hosts to avoid competing with that discovery. Windows's timing failure was
0.953 seconds against a 0.25-second request budget plus 0.35-second scheduling
allowance. The late result was rejected. Neither deadline was increased.

A separate read-only Linux inspection after the first run found four running
executables whose on-disk paths had been unlinked. The collector correctly
reported incomplete coverage. The specific processes' cause was not established;
the error was not ignored or converted into trusted evidence.

## Corrections and follow-up

The native recovery report now retains collector errors, baseline-readiness
reasons and fixture cleanup even when approval fails. The fixture explicitly
declares capture-only authority for the standard host watch list; automatic
repair remains limited to its two owned files. Each protected file must belong
to one manifest. A follow-up exposed and corrected duplicate fixture-file
declarations. The service responsiveness monitor now begins after an initial
successful application transaction, rather than treating native process startup
as application readiness.

The first recovery follow-up found no Linux collector errors. Idle and
post-load collection took 3.332 and 3.018 seconds; loaded samples took 6.036 and
5.940 seconds during a bounded 90-second CPU workload. All four samples met the
existing recovery freshness and completeness gates. Probe deadlines also passed.
Native recovery itself was still blocked by the duplicate manifest declarations
in that attempt; those pressure results do not change its failed status.

This recovery follow-up was run `99bb79190bd4`, with evidence in
`/tmp/sentinel-defensive-6ntv6jr0`. Power, network and temporary staging cleanup
were verified. Windows native collection was complete and baseline-ready, but
capture was blocked by the same manifest overlap. Its idle/post-load collections
took 16.272/14.015 seconds; loaded samples took 59.527/70.464 seconds. All met the
existing gates, with little margin against the 75-second collection budget.
The strict probe check failed again: one of ten trials took 0.703 seconds, and
the subsequent healthy HTTP control failed at its 0.25-second budget. All ten
late results were rejected, and the fixture was removed.

### Corrected full acceptance with the 180-second opening limit

Run `dbf6c80a673c`, evidence directory `/tmp/sentinel-defensive-b8tsl3a2`.
Overall result: **failed**. All four VMs were deallocated, the original network
was restored, and temporary staging was removed.

Linux passed native autonomous recovery with the real full collector, including
approved backup capture, two observations separated by 15 seconds, restoration
of the missing file, service recovery, subsequent healthy transactions and
fixture removal. Recovery took **22.784 seconds**. The healthy application also
remained responsive during collection. The four ordinary fault cases, transport,
probe deadlines and controller continuity passed. Collection under load passed
at 9.153 and 11.019 seconds, with no errors.

Linux's combined opening failed a final SMB **read** at its declared three-second
timeout. SMB login and write passed, as did the other nine transactions. The
defender had reached authenticated readiness and approved baseline status at
51.369 seconds. That does not make the opening successful. The intermittent
SMB timing failure remains unresolved; no retry or larger Linux probe timeout
was used to conceal it.

Windows feature discovery passed in **16.394 seconds**, compared with the
earlier 60.765-second failure. This is consistent with avoiding overlapping
preparation on its single core, but one comparison does not establish causality
or a reliable upper bound. Other setup work exhausted the original 180-second
budget; the SMB-share task was still recorded as running and the defender had
not been constructed. This is an incomplete opening. Later phases were held
because the older harness omitted a cleanup receipt when no defender existed.
The report now explicitly distinguishes “not constructed” from unverified
cleanup; it does not convert an unfinished setup into a pass.

The diagnostic observer also now honors each declared probe timeout within the
remaining opening deadline. Previously it silently capped every transaction at
three seconds, including Windows SMB probes configured for five seconds. Linux's
explicit three-second SMB timeout is unchanged. Failure categories and operation
names are recorded without exporting credentials or raw provider responses.

### Windows completion diagnostic

A separate Windows-only run uses a 600-second diagnostic stop limit to measure
functional completion. The opening goal remains 180 seconds, and both values
are recorded separately. Run `f3e686c294b5`; its evidence directory is
`/tmp/sentinel-defensive-0c8tyfkm`. Overall result: **failed**. Power, network and
temporary staging cleanup were verified.

Native autonomous recovery **passed in 45.865 seconds**, using the full native
collector, real backup capture, two separated observations, restoration, service
recovery and subsequent healthy transactions. Application responsiveness during
collection and fixture cleanup passed. All four ordinary fault cases and the
basic Windows controller continuity smoke test passed.

Remaining failures were:

- Feature inventory timed out again at 61.200 seconds, so dependent setup tasks
  never executed and the defender was not started by the opening stage. The
  longer overall diagnostic limit cannot bypass this separate task deadline.
  The single-core scheduling correction therefore does **not** resolve feature
  discovery reliably. The subsequent SMB login failures concern the uncreated
  fixture account, not evidence of an independent credential defect.
- One of 15 transport waits took 0.790 seconds, exceeding that test's
  0.25-second budget plus 0.50-second scheduling allowance. Every request timed
  out, applied backoff, and drained its worker; the healthy signed request passed.
- All six slow HTTP/readiness results were rejected within the measured
  allowance, but the subsequent healthy HTTP control failed at its 0.25-second
  budget. The probe test consequently failed.
- One loaded collection took 76.021 seconds and reported eight errors after
  exceeding the 75-second collection budget. It was unusable for recovery.
  The other loaded sample took 59.370 seconds with no errors. Idle and post-load
  samples passed. One good loaded sample cannot qualify the failed workload.

This leaves Windows setup, timing and collection reliability on this B1ms host,
and the intermittent Linux SMB read, unresolved. No larger collection budget,
relaxed completeness requirement, skipped service check or automatic baseline
approval was introduced to obtain a passing result. Native repair success is
established for the owned service fixture on both operating systems; complete
competition readiness is not.

## Raw evidence

Selected JSON reports and hashes of every tested payload member are preserved
in the existing Azure storage account `sb7070f7890ddb8374aa8a`, private container
`sentinel-defensive-evidence-20260911`. Each blob is named `<run-id>.zip`.
This evidence archive is retained separately from the deleted temporary delivery
containers. It excludes command files containing signed access URLs, private
logs, credentials and protected-file contents.

| Run | Evidence archive SHA-256 |
| --- | --- |
| `90925704c655` | `3933d786e157ab4c4cc6cc65b846af75fe8fb59907c1835a49967ce021fc7a49` |
| `99bb79190bd4` | `c3f7256e58a0b90bbbf2a8f4a796591c9ac4e5eb89e4e782bcd8fc73322400bf` |
| `dbf6c80a673c` | `b453c1780fdab1bcbe2486e89eeb976d20a47d10ed24743ef6fa251cbcb5d68d` |
| `f3e686c294b5` | `52320aee14f649d9bc144f3f7c7fef65daf47de773fd5baf062bccb411f18671` |

## Local validation

194 regression tests passed from a fresh extraction of the supplied source
archive. Earlier runs passed 131 and 183 tests. These counts overlap and must
not be added. Coverage includes
the defensive distribution and payload, POSIX integrity budgets, Windows
inventory, baseline promotion, service-manifest authority, automatic recovery,
coordinated repair, controller/agent continuity, recovery operations and opening.

The exact packaged runtime also passed the local TLS smoke test with signed
operator actions, enrollment, backup verification, clean shutdown, authorized
controller crash resume, emergency-stop retention and buffered-agent replay.
The temporary certificate fallback was tested with OpenSSL unavailable.

To reproduce the supplied source tests from its extracted root:

```console
PYTHONPATH=.:src:tests python3 -m unittest discover -s tests
PYTHONPATH=.:src python3 -m tools.build_defensive_release --output dist --bundle
```

Use a POSIX environment for the complete supplied regression workflow; its
Azure control-plane helpers use POSIX file locking. The runtime itself supports
Linux and Windows. Azure guest acceptance needs the existing authorized Azure
lab and an authenticated Bash Cloud Shell;
the helper defaults to read-only network review. Execution requires the reviewed
runtime and network digests. No credentials are supplied in this distribution.

## Remaining readiness limits

A trusted starting baseline, the actual event's service manifests, credentials,
rules and permitted recovery actions remain required inputs. The program cannot
turn uncertain host evidence into proof of a clean root/SYSTEM host.

This validation does not establish one external controller managing the complete
mixed-OS network, boot-persistent deployment and VM-reboot continuity, all event
scoring transactions with real event data, or competition-length availability.
Resource-sensitive Windows checks and any failed follow-up gates remain release
acceptance limitations. Automatic action stays held when collection is stale or
incomplete; a hold is not a successful repair.

The older documents contain historical measurements. This report, tied to the
exact digest above, takes precedence for this candidate. A later passing run
does not erase the earlier failed attempts.
