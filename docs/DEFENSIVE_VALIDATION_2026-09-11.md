# Defensive integrity-collection update — 2026-09-11

This development change fixes boundedness and consistency problems in POSIX
file-integrity collection. It has not been deployed to competition hosts.

## Source and scope

The newest available source checkout was version 1.9.39 at
`0a664d5` (`Reuse owned Windows inventory host with fresh bounded requests`).
Work continues on `defensive-reliability-20260911`. The existing nine pending
files from that checkout were preserved without including them in this change.
The saved 1.9.40 assessment describes only a production version-string change
from its preceding candidate; its exact checkout was unavailable here. This
update does not claim to reconstruct that missing commit or promote a release.

The user's current instruction excludes live red-team testing. Validation for
this change used temporary files, fixture telemetry, in-memory controller state,
and mocked service operations. It did not run a live red-team exercise, contact
competition/cloud hosts, create accounts or persistence, or stop host services.

## Fixed behavior

- POSIX integrity collection limits each file to 32 MiB and the total content
  read per cycle to 128 MiB. A bounded EOF check also consumes the shared
  allowance when it returns data. Files need room for that one-byte check.
- A ten-second monotonic budget is checked between filesystem operations. Bytes
  read from a rejected snapshot still consume the shared allowance; each new
  collection starts with a fresh budget.
- Only regular-file snapshots are accepted. The collector compares descriptor
  and pathname identity, size, timestamps, ownership, and mode after hashing.
  Observable concurrent edits, replacement, truncation, growth, or metadata
  changes produce a collection error instead of a usable integrity item.
- Absent optional files remain distinct from access failures. Disappearance
  after opening, nonregular targets, unsupported reported sizes, and exhausted
  budgets remain explicit errors. Existing monitored symlink paths retain their
  original telemetry path and must still resolve to the same final snapshot.
- The descriptor is closed after both successful and unsuccessful reads. The
  existing incomplete-telemetry recovery gate remains in force.

## Verification

Python 3.12.14 on Linux: **76 tests passed**, with no skips or failures.
This includes **15 new POSIX integrity tests** and the existing collector,
service-recovery, coordinated repair, and rollback checks.

Run the same bounded validation from the repository root:

```bash
PYTHONPATH=src:tests python3 -m unittest -q \
  test_posix_integrity_budget test_collectors \
  test_service_recovery_regressions test_autonomous_service_recovery \
  test_service_repair
```

The file tests cover normal/empty files, both byte limits, cycle reset,
concurrent edits and replacement, metadata change during reading, absence
versus access failure, disappearance after opening, unsupported file types,
deadline exhaustion, descriptor cleanup, and existing monitored symlinks.

## Remaining limits

- The deadline is cooperative between OS calls. It cannot interrupt a blocked
  filesystem call, and is not a hard end-to-end collection deadline.
- A changing or oversized required file now explicitly holds automatic recovery.
  That is incomplete evidence, not successful collection or restored service
  availability. Larger integrity targets need a separately reviewed contract.
- This checks metadata consistency during a read; it does not add detection of
  persistent POSIX permissions/ownership drift across collection cycles.
- Windows performance, full-network setup under three minutes, unknown-malware
  detection, and competition uptime were not measured or improved by this
  validation. Earlier competition uptime estimates remain unvalidated.
- No GitHub workflow, native lab, cloud deployment, or release promotion was
  invoked for this change.
