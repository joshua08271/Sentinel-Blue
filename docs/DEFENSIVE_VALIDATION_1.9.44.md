# Sentinel Blue 1.9.44 defensive validation

This candidate adds an incomplete-coverage diagnostic when Linux has more than
2,000 unique loaded or installed services. Unloaded installed units count toward
the limit. The collector preserves its bounded observations and no longer
constructs records it will discard. Inert provider regressions failed for both
overflow cases before the fix and pass after it; the exact-limit control passes.

Version 1.9.43 added process-inventory overflow reporting on both platforms.
Its [CI run](https://github.com/joshua08271/Sentinel-Blue/actions/runs/34659310009)
passed 216 Linux tests with two native Windows skips and all 49 selected Windows
tests, including actual PowerShell provider-query execution and native file
handles. Packaged controller continuity and bounded transport fixtures passed.
See [machine-readable CI evidence](validation-1.9.43/ci.json).

Validation of 1.9.44 is in progress. A full isolated Azure acceptance run of the
public 1.9.43 runtime is running separately. It is not an acceptance result for
1.9.44. Exact runtime hashes and guest results will be recorded when available.
The earlier preflight verified the original four VMs off and the reviewed
network unchanged before boot. Final cleanup has not yet been reported.

No full competition, external scorer, mixed-host network, or VM reboot
continuity result is claimed. Historical Windows opening and collection timing
limits remain unresolved pending the new measurements. The test scope uses
owned fixtures, ordinary faults and finite load; no live red-team campaign runs.
