# Sentinel Blue 1.9.42 defensive validation

This candidate continues the verified 1.9.41 defender source from
`azure-validation-1.9.41`, commit `d97ba985e90dac55dfa2854a4413ba1b61c1c393`.
The input bundle SHA-256 was
`a750a9f9d89e2015bf29b7681c460b6965b72783479b9a80dc070cae7aecd632`.
All input member checksums were verified before extraction.

## Changes

- Integrity collection prioritizes configured protected files and reports
  incomplete coverage when the 256-path limit is exceeded, a configured path
  is invalid, or directory discovery fails. Directory enumeration is bounded
  at 4,096 entries for each fixed discovery pattern. Optional absent application
  directories remain supported. Case-distinct configured paths are retained without assuming filesystem identity.
  The watcher and telemetry agent keep running;
  incomplete telemetry cannot authorize automatic recovery.
- Windows integrity reads now share a 128 MiB allowance and a ten-second
  cooperative deadline per cycle, retaining the 32 MiB per-file bound. Checks
  occur between native reads and metadata operations. Actual bytes remain
  charged if later validation fails, late snapshots are rejected, and cleanup
  releases file handles. Existing restoration callers retain their read behavior
  unless they explicitly supply a read budget.
- Source/installed CLI entry points default to the same defensive command set
  as the ZIP application. The distribution includes the new regression tests
  and separates current validation from historical Azure measurements.

## Validation status

Measured locally on 11 September 2026 with Python 3.12.14 on Linux.
Runtime SHA-256: `d410e4b1312fde354f60f756d1cbd18b8eaebaf5ab3b81c686e000d549789238`.

| Check | Result |
| --- | --- |
| Original 1.9.41 supplied suite | 194 passed |
| Updated supplied suite | 215 run: 214 passed, 1 native Windows test skipped on Linux |
| Packaged authenticated controller/agent lifecycle | Passed |
| Signed operations and authenticated backup verification | Passed |
| Clean restart and authorized controller crash resume | Passed; emergency stop retained |
| Offline telemetry buffering and replay | Passed |
| Agent transport with slow owned loopback responses | 15/15 passed; maximum 0.2505 s against a 0.25 s wait budget plus the existing 0.50 s allowance |
| HTTP/readiness deadlines | 10/10 passed; maximum 0.2504 s against a 0.25 s wait budget plus the existing 0.35 s allowance |
| Healthy requests after timing fixtures; worker cleanup | Passed |

The native lifecycle check restarted the controller in 0.430 seconds in this
local fixture. That is not a VM reboot, service-repair, or competition-uptime
measurement. Synthetic Windows API tests exercise the production read loop;
the platform-specific test must additionally pass on Windows. A prepared
GitHub workflow runs that test with focused Windows inventory/coverage tests.
Publishing that workflow and source was blocked by automatic approval review,
which requires explicit permission to publish to the repository. No new GitHub
CI run has occurred; local skips are not Windows passes.

Reproduction from the extracted source root:

```console
PYTHONPATH=.:src:tests python -m unittest discover -s tests -v
PYTHONPATH=.:src python -m tools.build_defensive_release --output dist --bundle
PYTHONPATH=.:src python tools/smoke_release.py dist/sentinel-blue-1.9.42.pyz --exercise-crash-resume
```

The complete suite uses POSIX-only Azure-control helper imports. The GitHub
Windows job selects the relevant portable/native Windows tests explicitly.
Only temporary local files, owned child processes and loopback peers were used
for these tests. No external attack targets were exercised.

Raw local evidence is included in `docs/validation-1.9.42/`.

## Limits

The file-read deadline is cooperative: it cannot interrupt an OS call blocked
inside a filesystem driver. The Windows inventory budget remains 75 seconds;
this patch does not establish that full collection fits it on a loaded B1ms VM.
An integrity limit produces an explicit hold, not a successful repair.

The earlier 1.9.41 Azure report is historical evidence only. Its intermittent
Linux SMB read, Windows feature-discovery/setup and load-sensitive timing
failures remain unresolved here. No new Azure run or live red-team exercise has
been performed for 1.9.42. A complete mixed-host network, external scoring,
VM-reboot continuity and competition-length availability remain unverified.
