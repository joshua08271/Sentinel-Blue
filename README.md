# Sentinel Blue 1.9.42

Sentinel Blue is a controller and host agent for authorized Linux and Windows
blue-team environments. It collects native telemetry, records changes, and can
restore approved configuration and recover declared services automatically.

This defender distribution omits the native and adversarial campaign commands.
The Azure acceptance runner uses service setup, ordinary faults in owned service
fixtures, controller continuity, bounded network timeout checks, and read-only
collection under CPU load. It does not run live red-team testing.

## Run the program

Extract the defender bundle. The `.pyz` is the runnable program; unpack the
included source archive into the same directory to read `docs/`, edit the
example inventories, or run the supplied tests. `VALIDATION.md` records
this candidate's measured results and remaining limits. `AZURE_ACCEPTANCE_1.9.41.md`
is retained historical evidence for the previous runtime only.

Python 3.11 or newer is required. The core runtime needs no third-party Python
packages. SSH and SMB scoring transactions require the optional dependencies
listed in `pyproject.toml`; credential-vault operations require `cryptography`.

```console
python sentinel-blue-1.9.42.pyz --version
python sentinel-blue-1.9.42.pyz --help
python sentinel-blue-1.9.42.pyz doctor --json
python sentinel-blue-1.9.42.pyz opening --help
```

`doctor` checks the local runtime and state directory. It does not certify a
competition deployment. See [competition opening](docs/COMPETITION_OPENING.md)
for the inventory, TLS, scoring transactions, service provisioning, and combined
opening procedure. Example inventories contain placeholders and must be bound
to the actual event's hosts, rules, services, credentials, and permitted actions.

## Automatic defense

Enable `controller --auto-recover-services` and `agent --allow-service-recovery`
with the reviewed event profile. Coordinated file repair also requires
`--allow-restoration` and explicitly listed files and actions. The controller
must have an approved baseline backed by verified restore points before it can
repair a service. See [automatic recovery](docs/AUTONOMOUS_SERVICE_RECOVERY.md)
and [coordinated repair](docs/AUTONOMOUS_REPAIR.md) for the complete contract.

Recovery requires consecutive fresh observations, independent agent preflight,
healthy dependencies, successful application transactions, and bounded retries.
Failed validation rolls the owned change back. Uncertain outcomes and an active
emergency stop hold further changes. The optional approved controller crash
resume policy preserves the emergency stop and replays buffered agent telemetry.

The launcher supports a systemd agent on Linux and an agent startup task on
Windows through their supported management transports. Local staging alone does
not install a boot-persistent service. Native Azure opening tests supervise
controller/agent processes and do not prove VM-reboot continuity.

## Changes and verification

Version 1.9.42 reports incomplete coverage when integrity discovery fails or
more than 256 unique files need monitoring. Explicit protected paths take
priority. Discovery has a finite directory-entry limit. The agent keeps reporting
telemetry; incomplete collection continues to hold automatic recovery.

Both platforms now apply a 32 MiB per-file limit, a 128 MiB aggregate allowance,
and a ten-second cooperative integrity-read deadline. Windows checks that
budget between native reads and metadata operations, closes held handles on
failure, and charges reads even when the final snapshot is rejected. A blocked
OS call is not preempted by this cooperative deadline. The separate Windows
inventory budget remains 75 seconds.

The installed/source command now defaults to the same defensive commands as
the packaged runtime. The source bundle includes the new coverage and read-budget
regressions. See [current validation](docs/DEFENSIVE_VALIDATION_1.9.42.md) for the
measured results and exact scope. Earlier Azure timings apply to 1.9.41 only.

A reviewed starting baseline is a trust decision. Sentinel cannot establish
that an already compromised root/SYSTEM host is clean, discover every unknown
application dependency, or guarantee a competition score. A full event opening
and competition-length availability require the actual event configuration and
an external scoring observer.
