# Endurance acceptance

The next competition milestone requires the exact candidate to survive a full
practice event on the intended Windows and Linux hosts, with repeated outages,
load, controller interruptions, protected organizer access, and measured scored
transactions. A passing unit suite or a short fixture run cannot complete that
milestone.

## Reproducible checks

Build the release with `python tools/build_release.py --output release`, then run:

```console
python tools/smoke_release.py release/sentinel-blue-1.9.24.pyz --exercise-lifecycle
python tools/endurance_recovery.py --runtime release/sentinel-blue-1.9.24.pyz --duration-seconds 330 --output endurance-report.json
python tools/measure_collection_pressure.py --load-seconds 180 --samples 3 --output collection-pressure.json
python tools/measure_collection_pressure.py --cpu-limit 1 --workers 1 --load-seconds 180 --samples 3 --output single-cpu-pressure.json
```

The signal lifecycle option requires POSIX. Other commands run on Windows and
Linux. Collection pressure invokes the real native collector; incomplete or
stale observations fail the check. The CPU limit changes only the measurement
process and its children, with the original affinity restored afterward. It
uses the native process affinity API on Windows and does not modify the
collector's reported CPU count or substitute collector output.

The 330-second recovery exercise uses signed controller/agent HTTP, real file
capture and preflight, durable action and result journals, actual loopback
transactions, and owned subprocess services. It disconnects the controller
after an action has completed, reopens persistent state, and requires result
reconciliation without another service start. A second immediate outage must
wait through the real five-minute cooldown before recovering. Neither the clock
nor the production attempt limits are changed. CI runs this exercise against
the built runtime on both operating systems.

The service adapter controls only its own child process. Its fixture inventory
does not establish native systemd/SCM, domain, or host-wide collection coverage.
The separate native runner campaigns retain their owner and disposable-host
gates. They also check real privileged account observations with the account
present in the baseline, and on Windows after disabling the owned account.

Reports distinguish action completion, result acknowledgement, hold reasons,
sampled scored uptime, authenticated control-endpoint uptime, and verified
cleanup. A successful durability check can coexist with poor scored uptime:
an immediate repeated outage deliberately spends most of the exercise waiting
for the cooldown. That is an operational limitation requiring a recovery plan,
not evidence that the cooldown should be removed.

## Full practice-event gate

Before treating a release as an unattended competition defender, retain:

- The exact source commit, runtime checksum, event profile, and approved service manifests.
- Native Windows and Linux results on the intended host sizes and service stacks.
- A complete event-length observation window with an agreed scored-transaction uptime target.
- Measured recovery after repeated outages, including exhaustion of the three-attempt hourly budget.
- Protected organizer/scoring access and tested operator recovery when automation is held.
- Clean restart, forced-crash governance, lost connectivity, and durable result reconciliation evidence.
- Native fixture cleanup records and a reviewed list of remaining failures.

Longer fixture runs accept up to 28,800 real seconds. They remain fixture
evidence and cannot substitute for a complete practice event on the intended
hosts. Reports always leave `full_competition_milestone_complete` false.
