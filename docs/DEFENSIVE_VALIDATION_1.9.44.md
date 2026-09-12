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

Version 1.9.44 passed [Linux and native Windows CI](https://github.com/joshua08271/Sentinel-Blue/actions/runs/34660233853):
218 Linux tests passed with two Windows-only skips; all 49 selected Windows
tests passed. Packaged lifecycle, transport and deadline fixtures passed.
See [CI evidence](validation-1.9.44/ci.json).

The Linux-only Azure retest used public commit
`67f0ae0b54638b0079bb3016e8d152c4ed80bbef` and runtime SHA-256
`c115f1620f537fc77354aa0150e271cb0934d374e4ffa8ec44847c908f3a1cb8`.
All seven defensive phases passed. Guest entry to readiness took 75.413 seconds;
payload transfer and prior bootstrap dependencies are excluded. Native service
repair took 23.067 seconds. Collections took 4.183 seconds idle, 8.015 and 10.262
seconds under finite CPU load, and 3.251 seconds afterward, with no collector
errors. All four VMs were deallocated afterward, the original network restored,
and temporary private staging deletion verified. See [Azure evidence](validation-1.9.44/azure-summary.json).

Windows was not booted in this 1.9.44 Azure run. The paired 1.9.43 run's Windows
failures remain recorded against that version and do not prove 1.9.44 acceptance.

No full competition, external scorer, mixed-host network, or VM reboot
continuity result is claimed. Historical Windows opening and collection timing
limits remain unresolved for this version. The test scope uses
owned fixtures, ordinary faults and finite load; no live red-team campaign runs.
