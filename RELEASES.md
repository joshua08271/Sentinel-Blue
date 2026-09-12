# Public defender releases

Latest runtime candidate: **1.9.45**, [releases/sentinel-blue-1.9.45.pyz](releases/sentinel-blue-1.9.45.pyz). The expanded branch source matches it. Runtime SHA-256: `a48098b8cd6de91f0dbe3620ed3bee8c343b7dd876a922180247b76858f1c76d`.

The 1.9.45 local suite ran 223 tests: 221 passed, two Windows-only tests skipped. Its Windows feature query can use one continuous read within the existing 60-second allowance, sharing any unused time with one early retry. Late native results hold setup. See [current validation](docs/DEFENSIVE_VALIDATION_1.9.45.md); current CI and Azure verification are pending.

Version 1.9.44 passed [Linux and Windows CI](https://github.com/joshua08271/Sentinel-Blue/actions/runs/34660233853) and all seven live Azure Linux defensive phases, with all VM, network and temporary staging cleanup verified. The earlier paired 1.9.43 Azure run passed Linux; Windows had setup, responsiveness and load failures. Those results remain tied to their exact runtime versions and do not establish 1.9.45 acceptance.

The original [1.9.42 complete bundle](releases/sentinel-blue-defender-1.9.42.zip) remains available unchanged. Its historical publication-blocked text predates the explicit public-publication authorization on 11 September 2026.

The public branch retains its original `maintenance/defender-1.9.42` name while later versions are developed. See [pull request #3](https://github.com/joshua08271/Sentinel-Blue/pull/3). The final 1.9.45 bundle will include the completed validation evidence.
