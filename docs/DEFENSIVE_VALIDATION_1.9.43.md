# Sentinel Blue 1.9.43 defensive validation

This candidate follows the publicly published 1.9.42 defender. Both platforms
now report incomplete process coverage above the 4,096-entry inventory limit.
The Windows provider query retains one extra record to signal overflow; both
collectors retain bounded observations and report an error that holds automatic
recovery. The regression uses inert provider records, without creating thousands
of processes. Both platform overflow checks failed before the fix and pass after it.

The prior 1.9.42 release passed [Linux and native Windows CI](https://github.com/joshua08271/Sentinel-Blue/actions/runs/34658160560):
214 Linux tests passed with one Windows-only skip; all 46 selected Windows
tests passed. Packaged lifecycle, transport and deadline fixtures also passed.
Those CI results supersede the publication-blocked status recorded historically
inside the unchanged 1.9.42 bundle.

Version 1.9.43 passed [Linux and native Windows CI](https://github.com/joshua08271/Sentinel-Blue/actions/runs/34659310009):
216 Linux tests passed with two Windows-only skips; all 49 selected Windows
tests passed, including the real PowerShell provider regression. Packaged
lifecycle, transport and deadline fixtures passed. See [CI evidence](validation-1.9.43/ci.json).

The isolated Azure run used public commit
`ba01e4a9dd89ed8d110155c5a30bba89b421f698` and runtime SHA-256
`80a67e8a8eefe6e3033879b839c2eefa2c3dca796953cea5c6f441abafcc92aa`.
Linux passed all seven phases. Guest entry to readiness took 59.468 seconds;
payload transfer and prior bootstrap dependencies are excluded. Native service
repair took 23.431 seconds, and loaded collections took 8.654 and 6.148 seconds
with no collector errors.

Windows failed acceptance. The feature precheck used two unsuccessful attempts
totaling 61.931 seconds and held dependent setup tasks. The healthy HTTP control
failed, although all six deliberately slow HTTP/readiness results were rejected
within the fixture's timing bound. Native service repair completed in 42.548
seconds, but a 2.170-second scheduled response exceeded the 2-second service
responsiveness gate. Loaded collections took 76.188 and 76.040 seconds, each
reporting ten collector errors and holding recovery. Controller continuity,
transport and the separate service-repair phase passed.

Observed CPU credit balances remained positive; those metrics do not establish
credit exhaustion as the cause. All four VMs were deallocated afterward, the
original network restored, and temporary private staging deletion verified.
See [Azure measurements and cleanup evidence](validation-1.9.43/azure-summary.json).

The test boundary is owned service fixtures, ordinary faults, authenticated
controller continuity, bounded loopback delays and read-only native collection
under finite owned CPU load. No live red-team campaign is included. Historical
Windows opening and loaded-collection timing limits failed this run.
Full competition readiness is unproven.
