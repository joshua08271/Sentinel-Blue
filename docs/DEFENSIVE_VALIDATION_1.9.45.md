# Sentinel Blue 1.9.45 defensive validation

The 1.9.43 Azure Windows setup attempt spent 61.931 seconds in two unsuccessful
feature-query attempts. A controlled regression also showed that restarting a
query after 30 seconds prevented a 45-second read from completing, despite an
existing 60-second total allowance.

Version 1.9.45 lets the compiler-owned Windows feature query use that allowance
continuously. One retry is still possible after an early uncertain return, but
it receives only the unused portion of the same allowance and caller deadline.
Late native results are explicitly uncertain and cannot authorize provisioning.
Runbooks retain their 30-second native-check allowance. The overall setup goal,
mutation replay safeguards, 75-second collection budget and recovery gates are
unchanged.

The focused setup suite passes all 40 tests, including slow continuous work,
early retry, total budget and late-success holds. [CI passed](https://github.com/joshua08271/Sentinel-Blue/actions/runs/34661333342):
221 Linux tests passed with two native Windows skips; all 52 selected Windows
tests passed, including real PowerShell provider execution and file-handle tests.
The packaged lifecycle, crash-resume/emergency-stop, telemetry replay, transport
and HTTP/readiness deadline fixtures passed. See [CI evidence](validation-1.9.45/ci.json)
and [local regression evidence](validation-1.9.45/local-tests.json).

The exact public runtime under test is SHA-256
`a48098b8cd6de91f0dbe3620ed3bee8c343b7dd876a922180247b76858f1c76d`,
from commit `d82b273f71945d2051ab8e6e953838d469fac33b`. Documentation and evidence
updates in the final bundle do not change those runtime bytes. The paired Azure
run completed with the following results:

| Defensive phase | Linux | Windows |
| --- | --- | --- |
| Setup and opening readiness | Passed | Failed |
| Authenticated transport | Passed | Passed |
| HTTP/readiness timing fixture | Passed | Failed |
| Controller continuity | Passed | Passed |
| Owned service repair | Passed | Passed |
| Native automatic recovery | Passed | Passed |
| Collection under finite CPU load | Passed | Failed |

Linux guest entry to readiness took 53.363 seconds, excluding payload transfer,
prior bootstrap dependencies and VM boot. Native automatic repair took 22.750
seconds. Loaded collections took 8.916 and 10.991 seconds with zero collector
errors. These are guest-local results, not a mixed-host event opening.

The one-core, 2 GiB Windows Server 2022 target still failed overall acceptance:

- Feature inventory passed in 16.510 seconds on this run, but the complete setup
  did not finish within 180 seconds. Measured acceptance returned after 181.963
  seconds, before fixture cleanup; final service checks were not completed. The
  persisted SMB-share task was still marked running and is not completion proof.
  The single successful feature measurement does not establish a timing cause
  or eliminate the earlier failure.
- All six deliberately slow HTTP/readiness results were rejected within the
  fixture's bound. The healthy HTTP control failed; the healthy readiness
  control passed. The maximum slow-case wall time was 0.4614 seconds for a
  0.25-second deadline plus the fixture's 0.35-second scheduling tolerance.
- Loaded collections took 76.189 and 76.280 seconds, each producing ten
  collector errors and holding recovery. The separate 75-second collection
  allowance was not extended. Idle and post-load collections completed without
  errors in 12.502 and 28.097 seconds.

Windows native automatic repair passed in 42.015 seconds. Its separate healthy
service responsiveness checks passed, with no failed requests and maximum
scheduled response times of 1.544 and 0.364 seconds. This pass does not erase
the prior 1.9.43 responsiveness failure or the current loaded-inventory failures.

All four VMs were deallocated, the original network restored, and temporary
private staging deletion verified. Owned fixture cleanup passed on both guests;
installed packages/features are retained by the fixture policy. See the
[Azure measurements](validation-1.9.45/azure-summary.json), including exact
runtime and private evidence archive hashes. Windows setup and load performance
remain unresolved; full competition readiness is unproven.

The preceding public versions passed their Linux and selected native Windows CI.
The 1.9.43 Azure Linux guest passed all seven defensive phases, while Windows
failed setup, healthy HTTP timing, collection responsiveness and loaded inventory.
The Windows service repair and controller continuity phases passed. All four VMs
were deallocated, the original network restored and private staging removed.
The subsequent [1.9.44 Linux retest](DEFENSIVE_VALIDATION_1.9.44.md) passed all
seven phases with cleanup verified. Current and historical measurements remain
tied to their exact runtime hashes.

Only owned defensive fixtures, ordinary faults, finite CPU load and bounded
loopback delays are tested. No live red-team campaign, full-event availability,
VM reboot continuity or external competition scorer result is claimed.
