# Competition opening

Use [current validation](DEFENSIVE_VALIDATION_1.9.44.md) for the distributed
runtime's measured results. The versioned native measurements below are
historical. They do not establish current event eligibility or opening times.

The opening target is **under 180 seconds from the first upload through scored
service readiness and active Sentinel Blue protection**, excluding VM creation
and boot. The new `opening` command enforces this combined completion gate.
A full Linux/Windows competition opening within that time is **not yet proven**.
The older `setup` command still measures service provisioning only.

## Exact supplied score columns

These catalogs transcribe the operator's two screenshots. They do not infer an
operating system, router implementation, NCAE database engine, scorer account,
DNS view, site content, database data, or the next event's rules.

### NCAE

| Binding ID | Score column | Required transaction |
| --- | --- | --- |
| `router-icmp` | Router ICMP | `icmp` |
| `ssh-login` | SSH Login | `ssh-login` |
| `smb-login` | SMB Login | `smb-login` |
| `smb-write` | SMB Write | `smb-write` |
| `smb-read` | SMB Read | `smb-read` |
| `www-content` | WWW Content | `http-content` |
| `www-ssl` | WWW SSL | `https` |
| `www-ssh` | WWW SSH | `ssh-login` |
| `sql-access` | SQL Access | `sql` |
| `sql-ssh` | SQL SSH | `ssh-login` |
| `dns-int` | DNS INT | `dns-forward` |
| `dynamic-dns` | Dynamic DNS | `dns-update` |
| `dns-ssh` | DNS SSH | `ssh-login` |

### GDDC / UAlbany

| Binding ID | Score column | Required transaction |
| --- | --- | --- |
| `router-icmp` | Router ICMP | `icmp` |
| `ssh-login` | SSH Login | `ssh-login` |
| `smb-login` | SMB Login | `smb-login` |
| `smb-write` | SMB Write | `smb-write` |
| `smb-read` | SMB Read | `smb-read` |
| `www-port-80` | WWW Port 80 | `http-port-80` |
| `www-content` | WWW Content | `http-content` |
| `www-ssl` | WWW SSL | `https` |
| `postgres-access` | Postgres Access | `postgres` |
| `dns-int-fwd` | DNS INT FWD | `dns-forward` |
| `dns-int-rev` | DNS INT REV | `dns-reverse` |
| `dns-ext-fwd` | DNS EXT FWD | `dns-forward` |
| `dns-ext-rev` | DNS EXT REV | `dns-reverse` |

NCAE `SQL Access` accepts an explicitly selected PostgreSQL or MySQL transaction;
it does not silently assume either. SQL Server is not implemented. GDDC requires
PostgreSQL specifically. Internal and external DNS require the actual records
and observer/view arrangement; two names aimed at one loopback server do not
establish separate DNS views. Router echo availability alone does not establish
routing, NAT, firewall correctness, or router configuration support.

## Other competitions using Linux

The [official WRCCDC 2026 Invitational 6 host readme](https://archive.wrccdc.org/images/2026/wrccdc-2026-invitationals-6/star-bars.local.readme.txt)
lists Fedora for a song application, Debian for a Kubernetes/POS stack, database
and mail hosts, Alpine for WordPress, and Rocky for Git. It also lists Windows
hosts with SMB/IIS, FTP/SMB/RDP and application roles, plus a pfSense router.
These are published host purposes, **not a recovered exact scoring manifest**.
They demonstrate why the NCAE/GDDC screenshots cannot be treated as a universal
Linux competition service list. Application data, mail, Git, Kubernetes, AD and
router configuration remain additional event-specific work when required.

## Prepare an event opening

Use the inventory and reviewed provisioning recipes described in
[initial setup](INITIAL_SETUP.md). Supply every event service in the event
profile, including required accounts, files, records, data, and transactions.
See `examples/competition/scoring-probes.example.json` for field examples, and the
two `*.score-columns.json` files for the exact catalog rows. These use
documentation addresses and placeholders; they are not deployment inventories.

A final setup task must cover each service and carry each named probe. Missing
coverage rejects the plan. The score catalog requires every one of its 13
columns, rejects weaker protocol substitutions, and rejects reused bindings.

Add an `opening` section to that inventory. This fragment is a schema example;
all 13 bindings and the actual event values are required before it can execute:

```json
{
  "opening": {
    "catalog": "gddc-ualbany",
    "budget_seconds": 180,
    "deployment_hosts": ["controller", "files", "web", "database", "dns", "router"],
    "scoring": {
      "smb-login": {"task": "files-ready", "probe": "SMB Login"},
      "smb-write": {"task": "files-ready", "probe": "SMB Write"},
      "smb-read": {"task": "files-ready", "probe": "SMB Read"}
    },
    "controller": {
      "host": "controller",
      "origin": "https://192.0.2.10:8765",
      "ca_file": "/private/controller-ca.pem",
      "operator_token_file": "/private/operator-token",
      "operator_principal": "opening-operator",
      "operator_epoch": 1,
      "enrollment_token_file": "/private/enrollment-token",
      "expected_mode": "guarded-autonomous",
      "bootstrap": {
        "check": {"path": "controller-check.sh", "sha256": "REPLACE_WITH_SHA256"},
        "apply": {"path": "controller-start.sh", "sha256": "REPLACE_WITH_SHA256"}
      },
      "activate": {
        "check": {"path": "defense-check.sh", "sha256": "REPLACE_WITH_SHA256"},
        "apply": {"path": "defense-activate.sh", "sha256": "REPLACE_WITH_SHA256"}
      }
    }
  }
}
```

The bootstrap and activation entries are optional only if their required state
already exists. They are hash-pinned runbooks, not generated controller or
baseline approvals. When starting with Sentinel absent, the bootstrap must
install/start the controller using its approved profile, TLS material, private
operator/enrollment credentials, recovery key and protected recovery anchor.
Activation must verify the approved baseline and defensive mode. See
[automatic service recovery](AUTONOMOUS_SERVICE_RECOVERY.md) for those gates.
A missing runbook never makes missing controller/defender state pass.

Every inventoried setup host must receive a working Sentinel agent. Linux SSH,
Windows WinRM and local execution are implemented. A pfSense/router appliance
that cannot run the agent needs a future explicit appliance readiness adapter;
omitting it is not a valid all-systems opening. Windows WinRM requires the
appropriate management host/authentication setup; a Linux controller with no
usable WinRM authentication is not a tested Windows deployment route.

### Scoring client prerequisites

The core compressed runtime still requires Python 3.11+. SSH and SMB probes
add optional observer dependencies, installed from the source package with
`python -m pip install '.[scoring]'` (Paramiko 5.0.0 and smbprotocol 1.17.0).
`psql`, Oracle MySQL's `mysql`, `nsupdate` and `ping` must be installed on the
observer when their corresponding checks are required. MariaDB client options
are not assumed interchangeable with MySQL. These dependencies are not included
inside the small `.pyz`. If installed after the first upload, their installation
time counts. The opening preflight rejects missing clients before declaring a
cold start. Availability alone does not authenticate a client or credential.

Scoring secrets must be private absolute files; POSIX password files must deny
group/other access. Windows files need an appropriate private ACL. SSH requires
verified `known_hosts` and never silently accepts a new key. SMB signs sessions,
requires encryption by default, pins one server and does not follow DFS referrals.
Its read operation checks exact SHA-256; its write operation exclusively creates
a fresh file in an approved directory, requires an acknowledged flush, reads it
back and deletes on close.
Timeouts cannot pass as successful cleanup.

PostgreSQL/MySQL access authenticates to the specified database and executes
`SELECT 1`. Optional `readwrite` requires explicit `allow_write` and an approved
probe table with `probe_key` and `probe_value` columns. It inserts a fresh value,
reads it, rolls back and checks that no probe row remains. MySQL requires InnoDB
before attempting a write; use a dedicated controlled transactional probe table.
This does not verify arbitrary event schema or application data.

Dynamic DNS requires an explicit zone, TSIG key, approved name prefix and IPv4
value. It creates a unique record, verifies exact UDP and TCP answers and deletes
using a value-dependent prerequisite. DNS forward/reverse probes verify exact
A/AAAA/PTR answers and support UDP or TCP. HTTPS supports an approved SNI/Host
name while connecting to a scoped IP, with certificate verification and an exact
`ca_sha256` when using a custom CA. Windows ICMP echo verification currently
supports IPv4; IPv6 is not established.

### Commands and the single clock

```console
python sentinel-blue-1.9.29.pyz opening --catalog gddc-ualbany
python sentinel-blue-1.9.29.pyz opening --inventory event.json --event-profile profile.json --runtime sentinel-blue-1.9.29.pyz --plan-out opening-plan.json
```

Review the complete plan and its printed digest. For a disposable range, append
`--range-deployment` to both planning and execution and use the approved
`range-autonomous` mode. A live event needs the actual event approval profile.

Record the Unix timestamp immediately before the first event package upload.
After that upload, invoke:

```console
python sentinel-blue-1.9.29.pyz opening --inventory event.json --event-profile profile.json --runtime sentinel-blue-1.9.29.pyz --execute --approve-plan REVIEWED_PLAN_SHA256 --started-at ORIGINAL_UPLOAD_UNIX_TIMESTAMP --state-dir /private/opening-state --output /private/opening-result.json
```

The command cannot discover a transfer performed before it was launched;
`--started-at` is required to include that prior transfer. Without it, the clock
starts when the command starts. Do not describe that narrower run as including
an earlier upload. Planning/configuration preparation is pre-event work only
when the rules allow it; otherwise include it in the original start time too.

Execution checks observer clients and initial scores, runs controller bootstrap,
provisions services, uploads/installs/enrolls agents, runs the reviewed activation,
then verifies final scores and the authenticated controller dashboard. Different
hosts work concurrently. With `opening.pipeline_deployment` enabled (the default),
a host starts upload/install/enrollment once its service tasks pass, while other
hosts continue setup. The combined work shares the same host concurrency limit;
mutations on one named host stay serialized. Local deployment callbacks are
serialized because local aliases may address the same operating system; represent
each physical host once in an operational inventory. Setting the option to `false`
retains separate service and deployment phases. Linux deployment batches files into one SCP transfer inside a
private staging directory. Remote mutation uncertainty stops automatic replay.

A pass requires all 13 final transactions, complete service setup, successful
deployment, matching controller release/profile, the intended autonomous mode,
no emergency stop, controller integrity, automatic service recovery, and fresh
enabled agents with approved complete baselines and no restoration blocker.
A staged file alone, pending baseline, timeout, reboot requirement, or missing
agent cannot pass. The deadline governs task admission and the pass result;
transport cleanup or an in-flight request can outlast it, so it is not a promise
that the process has exited at exactly 180 seconds. The durable journal refuses automatic replay; inspect any
interrupted mutation before preparing a fresh run. Setup's existing resume
command does not resume the whole opening.

Activation can return before an agent submits its first complete report. The
opening now polls authenticated readiness reads within the original deadline,
without redeploying or approving any missing baseline. Service checks run after
that wait, followed by a final defender verification, so delayed enrollment
cannot turn stale score results into a successful opening.

## Evidence boundary

Protocol fixtures and deadline tests establish specific behavior, not full-event
readiness. The Azure helper creates owned guest-local service instances; it does
not install Sentinel across the real competition network, configure a router,
restore real event data, or use a real scoring engine. Its service-only timer and
wider provider-delivery timer are reported separately. Package caches and existing
roles must remain disclosed. See [startup coverage](COMPETITION_STARTUP_COVERAGE.md)
for retained historical measurements and the current validation report for the
exact 1.9.27 bytes and observed outcomes.

## Native 1.9.27 measurements

On 9 September 2026, the corrected Linux fixture passed six service groups and
12 transactions in **39.764 seconds**, including fresh instance configuration,
scoring-client installation into its private observer directory, startup and
service checks. All ten distribution packages were already installed. Its
resume check performed no service restart, and fixture cleanup was verified.
The service clock starts after payload delivery and fixture-input generation.
This is guest-local service setup, not the combined opening timer.

The preceding Linux attempt took 148.502 seconds and failed because OpenSSH
lacked `/run/sshd`; the native service journal confirmed that cause. The helper
now creates the directory only when absent. That failed timing is not a pass.

The Windows target rejected the per-WRITE write-through request with
`InvalidParameter`. Native diagnostic trials isolated that request and verified
a normal write followed by FLUSH, exact readback and close. The runtime now uses
that sequence; it retains signing, encryption and delete-on-close. The Windows
scoring helper also explicitly includes the SHA-256-pinned Windows-only sspilib
dependency in its wheel set.

The latest Linux rehearsal passed all 12 transactions in **38.262 seconds**,
including resume without restarting services. The final Windows rehearsal passed
six IIS/DNS/SMB transactions in **79.696 seconds**, also with a successful resume.
Windows roles and Python were already installed, and the base IIS, DNS and SMB
services were running. Owned website/zone/share/account objects began absent.
Neither measurement includes first upload, full Sentinel deployment or activation.

A previous Windows resume failed when the built-in feature-inventory query timed
out, although all service transactions remained healthy. The setup runner now
permits one retry of that read-only query after an uncertain result, bounded by
the original deadline. It does not retry arbitrary runbooks or mutations. Linux's
latest native run preceded this Windows-only change; the final Windows run used
the released runtime bytes. Local tests exercise the retry-budget edge cases.

The original 1.9.27 raw reports are not included in this defender distribution.
Later [historical Azure evidence](AZURE_DEFENSIVE_ACCEPTANCE_1.9.41.md) and the
current validation report disclose failures and environment qualifications.
The complete event opening remains unproven.

## Current defensive Azure harness

The supplied `tools/azure_defensive_rehearsal.py` uses a private temporary blob
and checksum-verified download on each existing Linux and Windows target.
Execution requires the exact runtime and reviewed network digests. The default
mode reviews the network; `--execute` runs the guarded test and cleanup.

The current opening clock is guest-local. Read the reported `opening_clock_scope`
and separate orchestration/boot durations; do not add historical provider-timing
claims to this harness. `--mode full` measures setup, controller continuity,
ordinary owned service faults, bounded loopback transport and native collection
under finite CPU load. `--mode recovery` selects recovery, collection and probe
timing. Neither mode runs the separate native security campaign.

The helper supervises a separate controller and agent on each guest. It does not
establish one controller managing a mixed-OS network, boot-persistent installation,
all event score columns, real event data or competition-length defense. Fixture
baseline approval is explicit test authorization; it does not prove a competition's
starting files are clean.

The default setup stop limit is 180 seconds. `--setup-budget-seconds` supports
180 through 600 seconds for diagnosis; it does not change the reported
three-minute goal. Success still requires complete checks and verified cleanup.
VMs are deallocated before original public-IP associations are restored, and the
temporary blob container is deleted and checked. Review the explicit final
cleanup fields even when a guest test fails.

### Historical Windows telemetry rejection during completion testing

The first extended run on 10 September 2026 completed Linux services and Sentinel
in 67.677 seconds. Windows service setup and checks finished at 131.130 seconds,
but Sentinel never became ready during the 900-second measurement. Its agent kept
collecting; the controller rejected every report because one service exit code
exceeded the validator's signed 32-bit maximum. Additional waiting could not
resolve that failure.

The validator now preserves the full unsigned 32-bit range used by
[Win32_Service.ExitCode](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service).
Invalid types, negative values and overflow still fail validation. A stopped or
failed service remains reported as such; the change does not hide service errors
or relax baseline and final readiness requirements.

The corrected runtime (`5322fa5fd6f37b333899df24329e0f1e2076c7a49d74cbd534efb75b3e09607b`)
completed Windows services plus Sentinel in **191.526 seconds**, including final
service transactions and authenticated defender readiness. It exceeded the
three-minute target by 11.526 seconds. Service setup and checks reached readiness
at 151.499 seconds; Sentinel readiness followed at 188.344 seconds. The Azure
boot/guest-agent wait added 87.240 seconds outside this setup clock.

In the same corrected run, Linux reached defender readiness at 63.975 seconds
but failed a subsequent service check. That is a failed opening, not a 64-second
success. The helper now retains final service-check results even when they fail,
including the protocol and latency, to distinguish a service failure from a
defender failure. These diagnostic changes do not alter the runtime or pass gate.

The subsequent Linux-only run used the same corrected runtime and passed all 12
final transactions plus authenticated defender readiness in **69.449 seconds**.
Services were ready at 50.643 seconds and Sentinel at 66.875 seconds. The earlier
Linux failure did not reproduce; its specific transaction was not retained by
the older helper, so its cause remains unresolved. A later pass does not erase
that failed attempt or establish consistently successful openings.

The completed 1.9.29 per-guest timings were 69.449 seconds on Linux and
191.526 seconds on Windows. They retain the package/role, transfer, boot and
network-scope qualifications above; the full competition opening goal remains
unproven.


### Windows inventory execution in 1.9.30

The Windows agent now runs its nine fixed native inventory sections in one
PowerShell process. The queries retain account identities, services, topology,
processes, persistence references, every firewall filter type, interfaces,
security events and sessions. Each section executes in its own variable scope
and emits a separate, validated result. Session discovery runs last and excludes
the actual helper PID. The separate boot-identity check remains unchanged.

Missing records, provider exceptions, nonterminating errors, malformed rows and
expired collection budgets remain incomplete observations. A failed query cannot
borrow an earlier cycle's data. The original 75-second collection deadline and
the timestamp of the oldest collected evidence remain in force. Script bytes
are supplied through standard input, avoiding Windows' command-line length limit
and temporary privileged script files.

The native opening harness records the first inventory's per-section durations.
Read-only native checks after the measured opening verify UTF-8 text, empty
security-event results, failure isolation and shared-process scope. These checks
cannot turn an unsuccessful opening into a successful one.

The first native 1.9.30 Windows opening completed in **174.566 seconds**, including
six final service transactions and authenticated defender readiness. The agent
reached baseline readiness 22.021 seconds after launch, compared with 34.756
seconds in the prior 191.526-second run. All eight native query contract checks
passed. Runtime SHA256:
`884bb3c83b93e729f7dbe4573d802ea0159fb2f0b3cb1b33b404668de8bbe273`.

This run used the same existing Standard_B1ms Windows Server 2022 target, with
Python and server roles already installed and fresh owned IIS/DNS/SMB fixtures.
The private payload stage, provider dispatch, guest preparation, observer
downloads, service setup, Sentinel installation and all final readiness checks
remain inside the setup clock. VM boot and provider cleanup remain outside it.
A first result with 5.434 seconds of headroom does not establish a reliable
three-minute bound across Azure queue delays or a mixed-host competition.

The confirmation run used the same runtime bytes with the actual **180-second
limit** and completed in **162.710 seconds**. All six final service transactions,
authenticated defender readiness and eight native query checks passed again.
The agent-launch-to-baseline interval was 15.959 seconds. The measured Windows
results are therefore 174.566 and 162.710 seconds, both under three minutes.
These two trials retain the environment and scope limits above; provider queue
and host-load variation still prevent treating either result as a universal
maximum.
