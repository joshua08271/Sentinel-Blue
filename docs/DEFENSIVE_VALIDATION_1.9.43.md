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

Current 1.9.43 validation is in progress. Focused local process and Windows-query
regressions pass; the real PowerShell provider test requires Windows CI.
Azure sign-in, public 1.9.42 download verification and read-only lab preflight
have succeeded. The preflight found all four original lab VMs deallocated and
the previously reviewed network unchanged. Guest tests of this candidate have
not yet run. Do not interpret preflight or the prior release's CI as an Azure
acceptance pass for 1.9.43.

The test boundary is owned service fixtures, ordinary faults, authenticated
controller continuity, bounded loopback delays and read-only native collection
under finite owned CPU load. No live red-team campaign is included. Historical
Windows opening and loaded-collection timing limits remain unresolved until
new measurements establish otherwise. Full competition readiness is unproven.
