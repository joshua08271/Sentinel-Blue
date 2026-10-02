# Sentinel Blue

Sentinel Blue is a defensive automation assistant for authorized Linux cyber-range and blue-team environments.

## Current Linux test candidate: 2.0.28

Download the exact [sentinel-blue.pyz](sentinel-blue.pyz?raw=true) and [native validation code](validation-2.0.28.zip?raw=true). The application needs a compatible existing Python environment (3.11 or newer). The current 2.0.28 offline installer remains in the existing three-part download; the historical 2.0.20 installer below is a different release.

Application SHA-256: `9e3a7d254d4866be393eac5649211e656446ae1c16651ee0d4f64933a33d3ab5`.
Validation ZIP SHA-256: `416f1239f35f8028fa2f882f16dfe12d0cfe269e7daa25ad91f3a32cbf653aba`.

This release includes guarded recovery, durable inverse evidence, approved immutable-file protection, and independently guarded nftables/RouterOS 7 network recovery. Network recovery and SQL writes retain human approval per action. The validation scripts add read-only preflight, a real immutable enforcement check, isolated native nft JSON checks, fixed-window probe observation, and bounded approved-fault campaigns. Every script uses operator-provided paths and reviewed scope. They create no approval and provide no automatic campaign cleanup or resume.

The code ZIP contains seven generic Python files. Extract it privately and bind `SB_PYZ` to the exact application archive. Start with `preflight.py` on an idle authorized disposable VM. Run `nft_syntax.py` only with `unshare --net`; it refuses the host namespace. The immutable check uses unique temporary files and restores their native flags in its cleanup. Fault campaigns require an already reviewed running session, approved targets, authenticated baseline, declared transactions and an available recovery budget.

The separate [owned content lab helper](owned_content_lab.py?raw=true) prepares a new disposable fixture when no reviewed lab session exists. It requires root, real systemd, exactly one operator login and explicit approval of its newly owned fixture. It refuses hypervisors, existing Sentinel processes, an existing host ledger and pre-existing setup transactions. Its repair scope is limited to one new loopback HTTP service, two owned files and one content fault target; it never approves a production release or an existing session. Default host integrity observations are explicitly authorized for private baseline capture only, with no host integrity restoration or account mutation authority. An occupancy change stops its own session. The helper exercises one content fault followed by two bounded campaign rounds, retains a complete 180-second observation window, and checks its own process and service cleanup. Private evidence remains local; sampled transaction availability does not establish continuous or competition uptime.

Download the helper, application archive and unchanged validation ZIP into a private folder on an idle disposable VM. Review the helper before using its approval flags. Run with a compatible root Python environment:

```sh
sudo -n python3 -I -B owned_content_lab.py --ack-disposable-vm --approve-owned-fixture --console-evidence
```

The helper verifies the application and validation ZIP hashes above before creating its fixture. It retains bounded setup diagnostics and removes only completed native setup records proved to belong to its exact disposable service. Foreign, pending or unexpected records hold cleanup for review. The optional console evidence contains private sanitized timelines; keep it out of public repositories. A held result requires review before another run.

Native 2.0.28 acceptance and availability measurements remain unfinished; prior 2.0.20 measurements below do not certify this release.

## Historical 2.0.20 validation

The historical application is [the 2.0.20 archive](https://github.com/joshua08271/Sentinel-Blue/blob/2d809502a794d427603e28806cdd06308751a0e8/sentinel-blue.pyz). It requires a compatible existing Python environment. Matching source and rehearsal tools are in [candidate-2.0.20/source.tar.gz](candidate-2.0.20/source.tar.gz?raw=true).

The complete offline x86-64 Linux installer is published as transport pieces in [installer-2.0.20](installer-2.0.20/). Download its ten `installer.partNNN` files and `Join_Installer_2.0.20.py` into one folder, then run `python3 Join_Installer_2.0.20.py`. The standard-library joiner verifies all pieces and the complete file, refuses overwrite, and does not execute the installer. Enable execution on the assembled `.run` file, then open it. The installer includes Python and Tk; no dependency download is required.

Installer SHA-256: `b9c969ecb5f6984b5a56d3d8cc53b6e3fa16b49c3856eddd371bd7ca6b506da8`.
Application SHA-256: `c42513b57ca101ea85b43f5c37c0d65d14abb3f2d71d83bf1742571ab4394f4f`.

2.0.20 fixes private permissions when copying nested recovery-capsule metadata. Strict verification and latest-backup restore admission remain enforced. Existing failed capsules are not silently repaired. The storage rehearsal uses an isolated fixture ledger and verifies complete retained capsules.

Measured local results: 91 affected packaged checks passed; 18 adjacent checks ran with 17 passes and one native network-namespace skip; all 5,384 installer payload files verified. The ten-minute packaged storage run passed in 602.125 seconds, accepting 4,812 telemetry records with no other request or service-probe errors. Four archives and four complete capsules verified; backup sequences reached 11 and retention kept 8–11; controller restart preserved counters and all fixture processes stopped. This run used the build container, not native Kali.

Native Kali results for the exact published 2.0.20 installer: 2,781 tests ran in 791.412 seconds, with 2,766 passes, 15 skips and no failures or errors. Skips were 12 Windows-only checks plus optional dnspython, named-checkzone and wheel-build tooling checks. The ten-minute storage rehearsal passed in 603.334 seconds with 4,638 accepted records, nine verified 503 backpressure responses, no other request errors, four verified archives and four complete recovery capsules. Retention kept backup sequences 8–11; 12 nested ledger files and the latest restore capsule verified; database integrity, sequence preservation and process cleanup passed. The five-minute native GUI recording passed 19/19 checks, owned systemd repair/rollback recording passed 20/20, network-isolated offline startup passed seven case groups, and ordinary-user file-manager activation showed version 2.0.20 and the administrator gate. These are bounded single-VM checks, not full service-catalog or endurance acceptance.

The prior 2.0.19 native storage failure exposed the recovery-capsule defect corrected here. Its historical results remain separate from these 2.0.20 measurements.

This remains a test candidate. Full service-catalog, reboot, independent multi-host and endurance acceptance are unfinished. Controller, agent and desktop must use the same reviewed release. Use only on systems you own or are authorized to administer.
