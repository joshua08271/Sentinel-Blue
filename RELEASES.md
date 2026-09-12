# Public defender releases

Latest: **Sentinel Blue Defender 1.9.45**.

- [Complete ZIP: runtime, matching source, instructions and validation](releases/sentinel-blue-defender-1.9.45.zip)
- [Runnable Python archive](releases/sentinel-blue-1.9.45.pyz)
- [SHA-256 checksums](releases/SHA256SUMS-1.9.45)
- [Final bundle verification](releases/verification-1.9.45.json)
- [Measured validation and remaining limitations](docs/DEFENSIVE_VALIDATION_1.9.45.md)

The ZIP SHA-256 is `a8f1a185b37b5a7b7ff20040b90204600b41eeda84dc9182861bdae1e9ec8cec`.
The runtime SHA-256 is `a48098b8cd6de91f0dbe3620ed3bee8c343b7dd876a922180247b76858f1c76d`.
The runtime is unchanged from tested public commit
`d82b273f71945d2051ab8e6e953838d469fac33b`; the final package adds completed evidence
and download instructions. An independent rebuild from its included source
reproduced all three archives exactly and passed 221 tests, with two native
Windows tests skipped on Linux.

The [1.9.45 CI run](https://github.com/joshua08271/Sentinel-Blue/actions/runs/34661333342)
passed 221 Linux tests and all 52 selected Windows tests. Packaged lifecycle,
authenticated transport and HTTP/readiness deadline fixtures passed.

Live Azure Linux passed all seven defensive phases. Windows passed transport,
controller continuity, service repair and native automatic recovery. Its feature
check completed in 16.510 seconds, but full setup did not finish within 180
seconds. The healthy HTTP timing control and loaded collections also failed.
Complete/fresh-observation recovery gates and timing budgets remain enforced.
All four VMs were deallocated, the original network restored, and temporary
staging removal verified. **Windows performance and full competition readiness
remain unresolved.**

Versions 1.9.43 and 1.9.44 and their exact results remain documented in the
source. The original [1.9.42 complete bundle](releases/sentinel-blue-defender-1.9.42.zip)
is unchanged; its historical publication-blocked text predates the later public
publication authorization.

The public branch retains its original `maintenance/defender-1.9.42` name.
[Pull request #3](https://github.com/joshua08271/Sentinel-Blue/pull/3) tracks this
work separately from the default branch.
