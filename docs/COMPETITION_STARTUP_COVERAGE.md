# Competition startup coverage and timing

Historical coverage audit: 9 September 2026. Measured runtime: Sentinel Blue 1.9.26.

**For the current 1.9.27 code, see [competition opening](COMPETITION_OPENING.md).**
That version adds the exact supplied NCAE and GDDC/UAlbany catalogs, authenticated
SSH/SMB/SQL/dynamic-DNS probes, TCP/PTR verification, concurrent deployment, and
a combined opening completion gate. The following table preserves what was
actually tested in 1.9.26; its unsupported-code entries are historical.

**Complete NCAE service setup on Linux and Windows is not established.** The
current evidence covers separate Linux and Windows service fixtures. It does
not establish a complete event opening, and the existing `under_3_minutes`
setup flag excludes deploying and activating Sentinel Blue itself.

The NCAE example checklist discussed with the operator is a planning reference,
not an authoritative manifest for their next event. The exact event sheet,
including operating systems, accounts, content, records, data, ports, and
allowed access paths, is still needed. A separate previously supplied Windows
domain-controller topology was labeled GDDC; it must not be attributed to NCAE.

## Service coverage

These results describe the native Azure fixtures and the inspected code, not
every configuration that an operator-written runbook could implement.

| Requirement | Current evidence | Work still required |
| --- | --- | --- |
| Linux HTTP content | nginx installation and exact content check passed | Actual event site, application, virtual host, and scorer access |
| Windows HTTP content | Owned IIS site and content check passed; IIS was already installed and running | Cold IIS installation and the actual event site/configuration |
| DNS | Linux BIND and Windows DNS zone with exact A-answer checks passed over UDP | TCP DNS query/answer verification, actual event records, and checks from the scoring network |
| FTP login/read/write | Linux vsftpd anonymous read and exact download checksum passed | Event scoring-account login, upload/readback/cleanup transaction, and permissions; current FTP probe only downloads |
| MySQL read/write | Not tested; Linux fixture uses PostgreSQL login and `SELECT 1` | MySQL installation, event accounts/schema/data, and an approved read/write verification transaction |
| SSH login | SSH is a Linux management transport; no scored SSH login fixture was tested | Required scoring-account authentication and an application-level check |
| HTTPS content | HTTPS/TLS probes exist; native setup fixtures use HTTP | Event certificates, trust/hostname checks, bindings, and exact HTTPS content |
| ICMP | No dedicated ICMP probe in the current probe dispatcher | Echo verification from the intended observer and approved network policy |
| Additional Windows roles | Only an IIS site and DNS zone were exercised | Event-dependent AD/LDAP, RDP, WinRM service scoring, certificate services, or other roles |

A listening port is not proof of a successful login, file transfer, database
write, or correct application response. A PostgreSQL result does not establish
MySQL coverage. A management login does not establish access by the scorer's
account. Service coverage must be checked against the full event manifest, so
omitting an unsupported service cannot produce an all-services result.

The generic package, feature, service, and hash-pinned runbook recipes remain
useful building blocks. They do not supply arbitrary event data or a complete
preconfigured service catalog.

## Timing evidence

| Measurement | Linux | Windows |
| --- | ---: | ---: |
| Service setup, measured separately | 80.948 seconds | 138.477 seconds |
| Wider rehearsal | 447.737 seconds | Approximately 243.7 seconds |

The Linux wider stopwatch included Azure package delivery, input preparation,
setup, resume, and fixture cleanup. The Windows wider value is derived from
provider invocation file timestamps and is not the same stopwatch. Neither
includes VM creation/boot; neither measures full Sentinel Blue deployment and
activation. These times cannot be added together or replaced by their maximum
to claim a simultaneous network result. See [Azure setup acceptance](AZURE_SETUP_ACCEPTANCE.md)
for the measured initial states and limits.

## Revised opening target

The operator's target is **under 180 seconds including upload and Sentinel
Blue setup**, with VM creation and boot excluded. Thirty minutes remains the
broader recovery objective if the stretch target is missed. This is a new
end-to-end acceptance requirement, not a result already achieved by 1.9.26.

Start one monotonic clock before the first package upload or deployment command
for the already-booted competition network. Measure all required runtime
installation, package/configuration transfer, controller startup, agent
installation and enrollment, service installation/configuration/startup, and
final verification within that same interval. Management access or trust setup
performed after this point counts too. Record retries and operator intervention
without resetting the clock.

Completion requires all of the following:

1. Every service in the complete event manifest passes its actual required
   transactions from the intended external observer across the real network.
2. Every intended Sentinel Blue agent is enrolled and supplying complete, fresh
   evidence to the running controller.
3. The intended, explicitly approved defensive mode and baseline are active.
   Baseline review performed during the opening counts toward elapsed time;
   setup must not silently approve observations from a compromised host.
4. No required host, task, or mutation remains failed, uncertain, awaiting a
   reboot, or awaiting manual action.

Record whether packages, Python, features, credentials, trust material, and
approved configuration were prepared before the clock. A result with a warm
package cache or preinstalled role must keep that qualification. Do not exclude
work needed at the event merely to meet the target.

The current setup command and acceptance helper do not yet implement this
combined completion gate. Their existing timing flags must continue to be
described as service-setup results.

## Next implementation and acceptance work

First bind the event sheet to exact service recipes and scoring transactions,
including the missing authentication and read/write operations. Provide the
actual event data and approved identities; do not invent them from the test
fixtures.

Then join deployment, enrollment, approved defense activation, and service setup
under the single clock. The inspected launcher currently deploys hosts serially
and performs several separate SSH file transfers per Linux host. Those are
concrete performance candidates once complete coverage is defined. Preserve
checksum verification, transport trust, uncertain-operation handling, and
baseline approval when changing scheduling or transfer batching.

Finally run one simultaneous Linux/Windows rehearsal with every required scored
transaction initially failing, using the intended competition management paths
and final checks across hosts. Azure guest-local Run Command rehearsals remain
useful tests, but cannot substitute for this deployment and network evidence.

This audit changes documentation only. It adds no service support, timing result,
or new runtime release.
