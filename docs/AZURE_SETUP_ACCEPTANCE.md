# Azure setup acceptance

The real acceptance target is an inventoried, reachable network with all
declared application transactions initially failing. Measure it on the intended
VM sizes, from a controller that reaches both Windows and Linux targets through
the actual approved SSH/HTTPS WinRM management routes. The existing four-VM
Azure range is suitable once its access is available and its private setup
inventory is reviewed.

Azure access remains governed by [the existing OIDC workflow](AZURE_OIDC.md).
It is restricted to `main`, the `azure-lab` environment, one resource group,
and four exact VMs. The setup milestone does not widen those controls or claim
that the Azure identity/environment has been bootstrapped successfully. The
current Azure workflow supports verify, inventory, and deallocation; it does
not currently execute this acceptance harness.

## Reviewable rehearsal

1. Use the existing Azure guard to verify inventory and power state. Start only
   the approved lab VMs through the existing authorized management path. Record
   power-on/boot time separately. A guest setup script cannot start an unpowered
   VM without provider access.
2. On the lab controller, place the exact runtime, private inventory, reviewed
   runbooks/configuration, verified management credentials, and trusted host
   keys/WinRM certificates. Use a Windows controller for WinRM. Do not weaken
   certificate or host-key verification to make a connection succeed.
3. Prepare a disposable set of scored services. Establish their intended cold
   state using reviewed lab procedures; preserve required data and management
   access. The measurement tool does not stop arbitrary services or reset VMs.
4. Compile and review the setup plan. Every service manifest must have a final
   setup task. Include actual web content, DNS answers, database login/query
   checks, FTP content, and any dependency between hosts.
5. Run the packaged command through the acceptance measurement below. It first
   checks the initial state from the controller. It then retains the same
   starting timestamp throughout setup and verifies all services again at the
   end. Any initially healthy service, missing coverage, unresolved operation,
   failed transaction, or elapsed time at/above the budget prevents a pass.

```bash
python sentinel-blue-1.9.25.pyz setup --inventory private-inventory.json --plan-out private-plan.json
python tools/measure_setup_acceptance.py --inventory private-inventory.json --runtime sentinel-blue-1.9.25.pyz --approve-plan REVIEWED_SHA256 --state-dir private-acceptance-state --output private-acceptance-result.json
```

The helper requires an explicitly approved disposable-range profile and an
exact matching runtime checksum. It must run from the matching source package.
Its wall-clock result includes initial probes, management preflight, package
installation, configuration, service startup, and final probes. It excludes
manual inventory preparation, guest boot, and subsequent defender deployment
or baseline approval; retain those measurements separately when assessing the
whole competition opening.

An Azure VM Run Command invocation may stage or launch lab tooling through the
authorized provider path, but it must not replace the guest management transport
being evaluated and then be presented as competition deployment evidence.

## Required evidence

Retain the source commit and runtime checksum, actual VM sizes, initial package
and service state, service manifest coverage, overall elapsed time, per-stage
results, manual interventions, and final externally observed transactions. Run
again from a fresh disposable initial state when changing the source, service
stack, VM sizing, management transport, or package-cache assumptions.

For the all-services-down target, a pass requires every declared service to be
healthy in under 1,800 seconds with no manual intervention during that measured
run. A single-host GitHub result does not satisfy this multi-VM gate. A passing
setup measurement also does not establish uptime under a sustained red team.
