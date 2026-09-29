# Sentinel Blue

Sentinel Blue is a defensive automation assistant for authorized Linux cyber-range and blue-team environments.

## Current Linux test candidate: 2.0.20

The current application is [sentinel-blue.pyz](sentinel-blue.pyz?raw=true). It requires a compatible existing Python environment. Matching source and rehearsal tools are in [candidate-2.0.20/source.tar.gz](candidate-2.0.20/source.tar.gz?raw=true).

The complete offline x86-64 Linux installer is published as transport pieces in [installer-2.0.20](installer-2.0.20/). Download its ten `installer.partNNN` files and `Join_Installer_2.0.20.py` into one folder, then run `python3 Join_Installer_2.0.20.py`. The standard-library joiner verifies all pieces and the complete file, refuses overwrite, and does not execute the installer. Enable execution on the assembled `.run` file, then open it. The installer includes Python and Tk; no dependency download is required.

Installer SHA-256: `b9c969ecb5f6984b5a56d3d8cc53b6e3fa16b49c3856eddd371bd7ca6b506da8`.
Application SHA-256: `c42513b57ca101ea85b43f5c37c0d65d14abb3f2d71d83bf1742571ab4394f4f`.

2.0.20 fixes private permissions when copying nested recovery-capsule metadata. Strict verification and latest-backup restore admission remain enforced. Existing failed capsules are not silently repaired. The storage rehearsal uses an isolated fixture ledger and verifies complete retained capsules.

Measured local results: 91 affected packaged checks passed; 18 adjacent checks ran with 17 passes and one native network-namespace skip; all 5,384 installer payload files verified. The ten-minute packaged storage run passed in 602.125 seconds, accepting 4,812 telemetry records with no other request or service-probe errors. Four archives and four complete capsules verified; backup sequences reached 11 and retention kept 8–11; controller restart preserved counters and all fixture processes stopped. This run used the build container, not native Kali.

The 2.0.20 native rerun is pending. The prior 2.0.19 native suite had 2,759 passes, 15 skips and two context-assumption failures out of 2,776 tests. Its owned-service repair, five-minute GUI recording and isolated offline startup passed; its storage run exposed the defect corrected here. Those prior results do not certify 2.0.20.

This remains a test candidate. Full service-catalog, reboot, independent multi-host and endurance acceptance are unfinished. Controller, agent and desktop must use the same reviewed release. Use only on systems you own or are authorized to administer.
