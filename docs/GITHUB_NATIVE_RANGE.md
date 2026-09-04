# GitHub-hosted native red-on-blue range

`native-red-blue-lab.yml` runs a real, host-level defensive acceptance campaign
on one fresh GitHub-hosted Ubuntu runner. It complements the synthetic range;
it does not replace a representative multi-VM practice network.

## What is real

The workflow starts a hardened loopback HTTP service under systemd, collects a
healthy baseline, captures an authenticated restore point, and then applies six
native mutations to the disposable runner:

1. stops the systemd service and requires a manifest-bound HTTP transaction to
   pass after the approved restart;
2. changes both the content and mode of a protected file and requires two
   matching observations before automatic, probe-gated restoration;
3. creates an inert, comment-only root cron marker and verifies persistence
   detection and evidence capture;
4. creates a locked, credential-free duplicate-UID-zero account and verifies
   unapproved privileged-account detection;
5. runs a trusted copy of `sleep` from the private temporary range directory to
   emulate a suspicious privileged temporary process without collecting input;
6. opens a second listener on `127.0.0.1` and verifies new-listener detection
   without making an automatic network change.

Every resource has a run-derived fixed name. Cleanup stops the service and
process, closes the listener, deletes the test account and cron marker, removes
the unit and private range directory, reloads systemd, and verifies absence.
The job fails if cleanup cannot be verified.

## Hard gates

The native command refuses to run unless all of these facts are true:

- `GITHUB_ACTIONS=true` and `RUNNER_ENVIRONMENT=github-hosted`;
- the OS and kernel are Linux and the process entered through `sudo`;
- repository is exactly `joshua08271/Sentinel-Blue`;
- actor is exactly `joshua08271`;
- event is a same-repository pull request or an owner-triggered manual run;
- the exact `github-hosted-ephemeral-runner` confirmation is present;
- the run ID is numeric and all required native tools are available.

The in-process event profile authorizes only `127.0.0.0/8`, inventories only
`127.0.0.1`, and has no deployable release digest. It therefore cannot pass the
normal deployed-range gate. No secret is loaded, no public listener is opened,
and no external host is probed.

## Running it

The workflow runs automatically for owner-created, same-repository pull
requests to `main`. It can also be started from **Actions → native-red-blue-lab
→ Run workflow**. Fork pull requests are skipped.

The job uploads `sentinel-blue-native-red-blue-report`, a sanitized JSON report
containing scenario outcomes, detection and response timing, scope assertions,
and cleanup status. It intentionally excludes host inventory, command output,
account names, process IDs, and offensive procedures.

## Interpreting the result

A pass proves that this candidate detected and safely handled the six bounded
mutations on that GitHub Ubuntu image. It does not prove resistance to an
unknown root adversary, guarantee competition uptime, authorize deployment to
a scored network, or establish compliance with an event's rules. Deployment
still requires the approved event profile, exact service/scorer transactions,
official identity inventory, frozen release digest, and organizer approval.

Real malware, keylogging, credential collection, destructive denial of service,
external exploitation, and internet targets are intentionally outside this
workflow. Those are neither necessary nor appropriate for a public CI runner.
