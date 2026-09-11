# Controller continuity — 1.9.34 candidate

This change addresses controller disconnections interrupting the agent collection
loop and ordinary controller crashes unnecessarily stopping committed autonomy.
It does not introduce unrestricted offline repair authority.

## Agent behavior

Action-fetch failures are isolated from collection. A disconnect before collection
or during the final capture-order poll no longer skips the scan or discards its
sample. Samples enter the existing bounded, private telemetry spool and retry on
reconnection. The spool's existing item and byte limits still apply; this is not
unlimited outage retention.

The controller client shares monotonic retry backoff across action polling,
telemetry upload, and result delivery: 5, 10, then at most 15 seconds between retry
opportunities. A successful request resets backoff. An authenticated permanent
rejection remains available to the existing reconciliation logic. TLS, response
authentication, enrollment binding, and replay checks are unchanged. Truncated
HTTP responses and disconnects during response reading are also handled.

The agent still uses synchronous transport. A request already in flight can spend
its configured timeout (12 seconds by default); this change prevents stacked
timeouts across routes, not every possible network delay. DNS and slow response
behavior are not covered by an absolute request deadline. Collection duration and
the configured collection interval also contribute to recovery latency.

Only a verified, accepted telemetry document is used after uploading a batch.
Partial local execution failures still force recollection instead of being
misclassified as harmless fetch failures. The existing capture-before-publication
ordering is preserved.

An already delivered and accepted repair can finish its native checks and rollback
while the controller is down. Results remain in the durable action journal/outbox;
an acknowledgement lost after controller commit is retried without repeating the
action. Pending results continue to hold new action execution.

## Controller crash policy

Existing profiles retain the default stopped startup after an unclean shutdown.
An approved guarded-autonomous or range-autonomous profile can explicitly opt in:

```json
"recovery": {
  "baseline_promotion_delay_seconds": 60,
  "resume_after_controller_crash": true
}
```

Changing this policy changes the profile fingerprint. Use the normal profile and
release approval/rebinding workflow; editing a live profile does not transparently
grant new authority or preserve old enrollment bindings.

With the policy enabled, the controller can preserve the last committed governance
mode and revision only when protected recovery identity/anchor verification passes,
the governance row is valid and matches the profile, and no interrupted governance
transition remains. A committed emergency stop is preserved. An explicit forced
safe startup overrides the resume policy. Missing, corrupt, or rebound authority
does not gain permission to resume.

Governance changes now commit a write-ahead intent before the authority change. The
second transaction changes governance and clears intent together. A crash between
those commits leaves intent present, forcing stopped recovery. The independent
fail-safe write clears intent only while durably installing stopped governance.
A failed stop request is not reported as a successful durable stop; an intent that
cannot be written is not a committed change to prior authority.

After any crash, new defensive changes require a complete observation collected
after controller startup. The existing emergency rollback/release actions retain
their prior authority and freshness checks, so a damaged collector cannot deadlock
that recovery path. Existing native preflight,
freshness, consecutive-observation, action expiration, journal, and recovery-budget
checks still apply. Exact queued/dispatched action identities survive an authorized
restart; they are not recreated as new actions. An unknown execution outcome is
still held for reconciliation.

Transient governance persistence failures now synchronize the in-memory revision
with the committed fail-safe revision, so later explicit recovery is not stuck on
an obsolete revision.

## Verification and remaining limits

The final candidate passed 968 regression tests (971 discovered, 3 skipped),
all 15 packaged self-tests, both packaged process-kill scenarios, and native
Linux telemetry spooling/reconnection. In the owned loopback fixture, the
authorized controller relaunch reached its signed dashboard in 0.428 seconds;
the offline and reconnect agent cycles took 0.454 and 0.551 seconds. These are
single fixture measurements with their scope recorded in
[the validation report](../reports/continuity-1.9.34-validation.json).

Targeted tests cover every collection disconnect boundary, bounded retry/reset,
truncated responses, preserved capture ordering, lost acknowledgements and action
replay, policy opt-in, protected recovery, emergency stops, failed governance writes,
profile changes, and the post-start observation gate. The packaged lifecycle runner
also supports an actual POSIX process-kill check:

```console
python tools/smoke_release.py /path/to/sentinel-blue-1.9.34.pyz --exercise-lifecycle
python tools/smoke_release.py /path/to/sentinel-blue-1.9.34.pyz --exercise-crash-resume
```

The first checks default stopped recovery; the second checks authorized resumption
and then kills the controller again after a committed emergency stop. These are
owned loopback fixtures, not competition uptime measurements. Reports record the
tested runtime digest separately.

The process must still be restarted by its service manager or supervisor. This
change does not add a redundant controller, repair failed controller hardware or
storage, or install a controller supervisor. It does not authorize new local repair
decisions during a prolonged controller/network outage. A standalone offline
planner would require bounded delegated authority, stop/revocation semantics, and
joint controller/agent budget reconciliation; those remain unresolved portions of
the original availability issue.

The candidate inherits 1.9.33's unverified native Windows load changes. Local
regressions and POSIX process-kill acceptance cannot establish native Windows,
full-event, or fully autonomous competition uptime. Version 1.9.32 remains the last
validated release until the native acceptance gates are completed.
