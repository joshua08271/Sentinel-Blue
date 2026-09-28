# Sentinel Blue

Sentinel Blue is a defensive automation assistant for Linux cyber-range and blue-team environments. Its desktop GUI provides local setup review and approval, service monitoring, alerts and verification prompts, credential storage, session recording, pause/resume, recovery, and withdrawal controls.

## Current script: 2.0.19 Linux test candidate

Download [sentinel-blue-2.0.19-linux-gui1-x86_64.run](sentinel-blue-2.0.19-linux-gui1-x86_64.run?raw=true). This single x86-64 Linux desktop installer includes the offline application runtime. Enable **Allow executing file as program** in its file properties if necessary, then double-click it.

Installer SHA-256: `6bb4432dd91b3fb0845c6d3515aaea50e986867785aba5b33f8da2b0110d5fb1`.

The smaller `sentinel-blue.pyz` contains the same application for a compatible existing Python/Linux desktop environment.

Version 2.0.19 corrects process-identity and process-group cleanup handling in nested Linux PID namespaces. Process identity, ownership, approval, ledger, and recovery guards remain enforced. This is a test candidate; native service and desktop acceptance testing is unfinished.

Use Sentinel Blue only on systems you own or are authorized to administer, and review competition rules before enabling automated changes.
