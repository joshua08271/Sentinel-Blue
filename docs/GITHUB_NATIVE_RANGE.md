# GitHub-hosted native red-on-blue range

`native-red-blue-lab.yml` runs real, host-level defensive acceptance campaigns
on fresh GitHub-hosted Ubuntu and Windows runners. They complement the
synthetic range; they do not replace a representative multi-VM practice
network.

## What is real

### Linux runner

The Linux job starts a hardened loopback HTTP service under systemd, collects
a healthy baseline, captures an authenticated restore point, and then applies
six native mutations to the disposable runner:

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

### Windows runner

The Windows job captures an NTFS restore point and native collector baseline,
then launches one combined, inert attack wave. It requires Sentinel Blue to:

1. detect an enabled, randomly credentialed, run-scoped local Administrator
   account and preserve evidence before exact SID-bound removal;
2. detect a disabled hidden scheduled task whose only action is `cmd.exe /c
   exit 0`, preserve evidence, and remove only the marker-bound task;
3. detect a run-scoped machine Registry Run value whose command only exits,
   preserve its content fingerprint, and remove only the exact value when both
   its type and content still match;
4. detect ruleset drift from a disabled outbound block rule scoped to
   `127.0.0.1` and the run-owned inert executable, preserve evidence, remove
   only the fully identity-matched rule, and prove the baseline digest returns;
5. detect a listener bound only to `127.0.0.1`, observe it without changing the
   network, and close it;
6. detect a Microsoft-signed `cscript.exe` copy running an inert heartbeat from
   the user's temporary directory, reject a forged process identity without
   signaling it, then suspend and resume the exact handle-bound process;
7. detect simultaneous protected-file content and DACL drift, atomically
   restore both, exercise exact operator rollback, and restore the approved
   state again;
8. refuse restore-point capture through an NTFS symbolic link without changing
   the approved target.

Windows cleanup terminates the run-owned process, closes the listener, removes
the exact account, task, Registry Run value, and disabled firewall rule only
after identity checks, restores the protected file if needed, removes the
reparse fixture and temporary executable, deletes the private range directory,
and re-inventories all four named host fixtures. The job fails if any cleanup
assertion is unproven.

## Hard gates

The native command refuses to run unless all of these facts are true:

- `GITHUB_ACTIONS=true` and `RUNNER_ENVIRONMENT=github-hosted`;
- the OS and kernel match the selected Linux or Windows command;
- Linux enters through `sudo`; Windows requires the hosted administrator token;
- repository is exactly `joshua08271/Sentinel-Blue`;
- actor is exactly `joshua08271`;
- event is a same-repository pull request or an owner-triggered manual run;
- the platform-specific exact disposable-runner confirmation is present;
- the Windows command separately binds the pull-request head repository;
- the run ID is numeric and all required native tools are available.

The Linux in-process event profile authorizes only `127.0.0.0/8`, inventories
only `127.0.0.1`, and has no deployable release digest. The Windows action
executor has the same loopback-only network scope. Neither can pass the normal
deployed-range gate. No repository secret is loaded, no public listener is
opened, and no external host is probed. The Windows firewall fixture remains
disabled for its entire lifetime, so it never enforces a traffic policy. The
Windows account password is generated in memory, passed only through the
fixture process environment, is never reported, and the account is deleted
during the same campaign. The Registry command is never launched and would do
no more than exit if a login unexpectedly invoked it.

## Running it

The workflow runs automatically for owner-created, same-repository pull
requests to `main`. It can also be started from **Actions → native-red-blue-lab
→ Run workflow**. Fork pull requests are skipped.

The jobs upload `sentinel-blue-native-red-blue-report` and
`sentinel-blue-windows-native-red-blue-report`. These sanitized JSON reports
contain scenario outcomes, detection and response timing, scope assertions,
and cleanup status. They intentionally exclude host inventory, command output,
account names, SIDs, passwords, process IDs, and offensive procedures.

## Interpreting the result

A pass proves that this candidate detected and safely handled the bounded
mutations on those particular GitHub Ubuntu and Windows images. It does not
prove resistance to an unknown root/SYSTEM adversary, guarantee competition
uptime, authorize deployment to a scored network, or establish compliance with
an event's rules. Deployment still requires the approved event profile, exact
service/scorer transactions, official identity inventory, frozen release
digest, and organizer approval.

Real malware, keylogging, credential collection, destructive denial of service,
external exploitation, and internet targets are intentionally outside this
workflow. Those are neither necessary nor appropriate for a public CI runner.
