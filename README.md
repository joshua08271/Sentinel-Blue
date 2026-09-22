# Sentinel Blue

Sentinel Blue is a defensive automation assistant for Linux cyber-range and blue-team environments. The current release provides a desktop GUI for reviewing and approving local setup, monitoring configured services, handling alerts and verification prompts, storing credentials, recording sessions, and using pause, recovery, and withdrawal controls.

The program can configure supported local services, monitor their health, and perform guarded recovery actions according to the mode selected by the operator. Actions that need human judgment are surfaced in the GUI with the reason and requested response.

## Current script

`sentinel-blue.pyz` is the current Sentinel Blue 2.0.1 Linux GUI 1 application archive. It contains the Linux application code and Python dependencies. Windows-specific source is retained internally but was not changed by this Linux update.

This `.pyz` is intended for an existing compatible Python/Linux desktop environment. The larger self-contained offline `.run` installer is not included in this repository upload.

Use Sentinel Blue only on systems you own or are authorized to administer, and review competition rules before enabling automated changes.
