# Windows collection under CPU load

Sentinel Blue requires complete, fresh observations before automatic service
recovery. A slow or failed native query holds recovery even when the service
fault is otherwise repairable. Current results and exact runtime hashes are in
[the validation report](DEFENSIVE_VALIDATION_1.9.44.md).

## Current behavior

One owned PowerShell helper runs the fixed boot, account, service, network,
process, persistence, firewall, interface, event and session queries. Native
modules and compiled code may be reused; observations never survive a cycle.
Each request has a fresh identity and requires every section plus an explicit
completion record. Failed requests destroy the helper before another collection.
The parent owns the helper process tree through a Windows job object.

The original inventory deadline is 75 seconds, including helper startup and IO.
Only this helper uses AboveNormal priority. The agent, observed services and
owned load workers retain their priorities. Telemetry is dated at collection
start and must satisfy the separate 90-second recovery freshness limit. Missing
records, malformed data, provider failures and exceeded limits remain errors.

Service enumeration reads SCM directly and is bounded at 4,096 records. Service
health and service-command persistence share the same current SCM snapshot.
Restart history uses the native System event channel and rejects incomplete or
oversized query results. Process queries retain one overflow record so more than
4,096 processes cannot silently appear to be complete coverage.

Integrity reads separately apply a 32 MiB per-file bound, 128 MiB aggregate
allowance and ten-second cooperative deadline. Native reads and metadata checks
share that budget, late snapshots are rejected, and handles close on failure.
A blocked OS call cannot be forcibly preempted by this cooperative deadline.

## Evidence and scope

The [1.9.41 Azure report](AZURE_DEFENSIVE_ACCEPTANCE_1.9.41.md) records both passing
native repairs and unsuccessful timing checks on the one-core, 2 GiB Windows
Server 2022 lab target. A later pass does not erase those failures. The older
1.9.33 report's unknown cleanup status is historical: later 1.9.41 runs recorded
cleanup, and the new preflight independently verified the original VMs off and
the reviewed network unchanged before testing.

The 1.9.43 GitHub Windows job passed native file-handle tests and an inert
provider test executing the real PowerShell process query. That CI result does
not measure the full Windows inventory under Azure load. Use each Azure report's
version and checksum before attributing a result to a later release.

`tools/measure_collection_pressure.py` measures native collection before,
during and after a finite owned CPU workload. It reports timing, counts, error
categories and worker cleanup without exporting native account names or raw
provider errors. `tools/azure_defensive_rehearsal.py` adds owned service repair
and guarded Azure power/network cleanup. These checks do not prove external
scorer health, VM-reboot continuity, a mixed-host deployment or
competition-length availability.
