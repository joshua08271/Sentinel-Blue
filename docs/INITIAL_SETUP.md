# Initial setup within a 30-minute budget

Sentinel Blue's `setup` command provisions an explicitly described Windows/Linux
network before ordinary monitoring and recovery begins. It can install distro
packages and Windows Server features, apply reviewed Linux configuration files,
enable/start native services, and run pinned application-specific setup scripts.
It runs independent hosts concurrently and orders dependencies across hosts.

The 1,800-second budget is an execution target, not a promise that arbitrary
competition infrastructure can be rebuilt in that time. The report declares
success only when every task and every declared service passes final validation
before the deadline. Missing service coverage cannot be counted as completion.

## Inputs needed at the event

Prepare a private inventory using the actual event's host addresses, service
requirements, application data, scoring identities, and permitted management
routes. Review required configuration and credentials; do not infer an approved
baseline from an initially compromised host. A stopped application is supported.
An inaccessible VM or absent management route requires a separate provider or
console operation before guest provisioning can reach it.

The clock includes management preflight, installation, configuration, startup,
application checks, and elapsed time between resumptions. It excludes writing or
reviewing the event inventory. Keep inventory preparation and VM power-on times
as separate measurements when assessing the total competition opening time.

The controller needs Python 3.11+ and the exact approved `.pyz`. Linux SSH
targets need bash, GNU timeout, verified host keys, and working administrator
access. Windows WinRM requires a Windows/PowerShell controller, trusted HTTPS
WinRM, and current credentials or a private `Export-Clixml` credential file.
`local` is available for an explicitly scoped loopback host. A browser VM
console does not establish any of these management connections.

## Plan, review, and execute

The existing event profile must permit `initial_provisioning` explicitly. This
capability is separate from autonomous service recovery. Setup does not promote
baselines, reset recovery budgets, change the emergency-stop state, or silently
enable the ordinary defender.

```bash
python sentinel-blue-1.9.25.pyz setup --inventory private-inventory.json --plan-out private-plan.json
python sentinel-blue-1.9.25.pyz setup --inventory private-inventory.json --execute --approve-plan REVIEWED_SHA256 --state-dir private-setup-state --output setup-result.json
```

For an explicitly approved disposable range, add `--range-deployment`. The
profile and running package must satisfy the existing release integrity and
range/live approval gates. Any change to the scripts, configuration bytes,
hosts, probes, dependencies, or profile changes the plan digest. The full plan
contains scripts and may contain secrets; it is written privately. Console
progress and result reports contain timings, statuses, return codes, and output
hashes. They do not contain command output or configuration contents. Raw
command output is retained separately under the private setup state directory
for operator troubleshooting; each command log is limited to 16 MiB. Treat
those logs as potentially containing credentials and do not publish them.
WinRM currently returns only the remote script's exit code, so remote script
diagnostics must also be retained by the reviewed runbook on the target.

## Inventory setup section

`hosts` retains the ordinary inventory shape. Each setup task names one exact
host. `requires` may refer to tasks on other hosts. Tasks on the same host never
execute concurrently, including package operations.

```json
{
  "setup": {
    "budget_seconds": 1800,
    "max_parallel_hosts": 4,
    "tasks": [
      {
        "id": "web-packages",
        "host": "linux-web",
        "recipe": "linux-packages",
        "options": {"manager": "apt", "packages": ["nginx"]},
        "estimate_seconds": 300,
        "timeout_seconds": 600
      },
      {
        "id": "web",
        "host": "linux-web",
        "service_id": "nginx",
        "requires": ["web-packages"],
        "recipe": "linux-service",
        "options": {"service": "nginx", "enable": true},
        "estimate_seconds": 60,
        "timeout_seconds": 120
      }
    ]
  }
}
```

This fragment starts a preconfigured nginx installation. To create its required
configuration, add reviewed `files` and a configuration validator as below.
The complete inventory also needs an approved nginx service manifest with the
actual HTTP content checks. A default landing page does not prove event content,
authentication, HTTPS certificates, or application data are correct.

| Recipe | Supported operation | Required event-specific input |
|---|---|---|
| `linux-packages` | APT or DNF package installation; optional `cache_only` | Exact packages and chosen distro manager |
| `linux-service` | File publication, configuration validation, enable/unmask when explicitly selected, startup | Native service name, approved files, prior hashes, literal validation argv |
| `windows-features` | Windows Server roles/features, including management tools | Exact feature names; a required reboot is reported |
| `windows-service` | Enable/start existing Windows services | Exact service name and desired startup policy |
| `runbook` | Application, account, database, or other reviewed configuration | Hash-pinned check/apply scripts; optional rollback script |

Packages use the host's configured repositories and signature policies. Setup
does not disable repository authentication. `cache_only` avoids online package
downloads but fails when required packages are not cached. Package installation
can start distro services and run maintainer scripts; review those effects.

A `linux-service` file entry has `path`, `source: {path, sha256}`, `mode`, and
`previous_sha256`. The latter must be an exact digest or the literal `absent`.
The desired digest is also accepted for a resumed/idempotent publication. All
preconditions are checked before writing. Parent directories must exist, be
root-owned, and not be writable by other users; links and multiply linked
existing files are refused. Missing application directories can be created by
a preceding reviewed runbook. Modes are 0600, 0640, or 0644.

Configuration validation takes `validate_argv`, a literal argument array whose
executable is an absolute path. Native service recipes retain private backups
and restore their prior files/service state on an apply-time failure. Package
installation is not automatically undone. External application validation can
still fail after a process starts; that is reported as incomplete, and it does
not authorize deleting application data or undoing unrelated hosts' work.

Runbooks use `options.check`, `options.apply`, and optionally `options.rollback`,
each `{ "path": "private-script.sh", "sha256": "exact digest" }`. Windows scripts
are PowerShell. Checks must be non-mutating and return zero only for the desired
state. Apply scripts should be idempotent and contain explicit error handling.
Windows PowerShell children construct their own module search path to avoid
inheriting incompatible PowerShell 7 modules. Import custom modules by their
reviewed absolute path when a runbook needs a nonstandard module location.
Scripts execute with the target credentials' privileges; transport scoping
does not sandbox an administrator-written script's internal commands. Review
them as privileged code. Return code 30 means a reboot is required. Setup never
automatically reboots a host while other tasks may depend on it.

## Health and handoff

Each final service task uses `service_id` to bind to an unambiguous manifest on
that host. Setup runs its approved `expected_transactions`, including HTTP body
checks, DNS queries, TLS, protocol transactions, and FTP login plus an exact
download checksum. FTP verification files are limited to 64 KiB; passive data
connections remain pinned to the scoped server. TCP connectivity by itself is
not proof of database authentication or query correctness: add a meaningful
native/application check in the service runbook.
For A/AAAA DNS records, set `expected_answers` to the exact approved address
list. This verifies the queried name and its CNAME chain; an unrelated or wrong
address cannot satisfy that check. Without this field, a DNS probe only checks
for a successful response containing answers.

Setup endpoints use literal scoped IPs so verification works before DNS is
configured. DNS queries may contain the required event domain. TLS verification
remains subject to the probe configuration. The supplied checks must reproduce
the scorer's actual requirements; a successful generic probe is insufficient.

After setup, use the existing launcher to deploy/enroll the defender, review its
observations, and approve the intended baseline. Defense deployment and baseline
review are not currently included automatically in `setup` completion.

## Resume and failure behavior

Use the same command and state directory with `--resume`. The original start
time and deadline remain in force; completed tasks are rechecked. A file lock
prevents two controllers from using the same setup journal concurrently.
The optional `--started-at` Unix timestamp includes time spent before invoking
the command. It cannot be in the future or change an existing journal's start.
The [network acceptance helper](AZURE_SETUP_ACCEPTANCE.md) uses this to include
initial controller probes in the same 30-minute window.

An interrupted in-flight mutation becomes `uncertain`. It is not replayed, even
if a later probe looks healthy. Further mutations on that host are held, as are
dependent tasks; healthy independent hosts can finish. Review the remote
operation before constructing another approved run. Required reboots and
unknown transport outcomes are never reported as successful setup.

The deadline bounds admission and command waits. Process cleanup may take a few
additional seconds; an OS stall, remote orphan, or package manager interruption
cannot be declared safely completed merely because the timer expired.

## Evidence and limits

`tools/setup_native_rehearsal.py` exercises the packaged CLI on owner-gated,
ephemeral GitHub runners. Linux covers owned nginx, BIND, PostgreSQL, and vsftpd
instances; Windows covers an owned IIS site and DNS zone. Inputs and random
fixture credentials are private and removed. Successful stage/cleanup reports
are required. Package/feature installation state is measured rather than assumed.

These are single-host native rehearsals per OS. Local fixture tests separately
cover concurrency, dependency ordering, crash recovery, and budget exhaustion.
Neither establishes multi-VM Azure performance, real event deployment access,
Active Directory recovery, router reconstruction, or arbitrary scored services.
Use the private Azure lab for the separate full-network acceptance rehearsal.
The exact procedure and measurement command are in
[Azure setup acceptance](AZURE_SETUP_ACCEPTANCE.md).

Implementation references: [Ubuntu package management](https://ubuntu.com/server/docs/how-to/software/package-management/),
[Windows feature installation](https://learn.microsoft.com/en-us/powershell/module/servermanager/install-windowsfeature),
and [PowerShell remoting sessions](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssession).
The Windows child-process compatibility fix follows Microsoft's
[module path guidance](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_psmodulepath?view=powershell-7.5).
