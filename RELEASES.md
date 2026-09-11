# Public defender releases

The latest runtime candidate is **1.9.43**, in [releases/sentinel-blue-1.9.43.pyz](releases/sentinel-blue-1.9.43.pyz). Source at this branch matches it. Runtime SHA-256: `80a67e8a8eefe6e3033879b839c2eefa2c3dca796953cea5c6f441abafcc92aa`.

Local validation: 218 tests run, 216 passed, two Windows-only tests skipped on Linux. Windows CI and live Azure acceptance are in progress; see [current validation](docs/DEFENSIVE_VALIDATION_1.9.43.md). A complete 1.9.43 bundle will follow the acceptance results.

The previous [1.9.42 complete bundle](releases/sentinel-blue-defender-1.9.42.zip) remains available unchanged. Its [Linux and Windows CI](https://github.com/joshua08271/Sentinel-Blue/actions/runs/34658160560) passed after the user explicitly authorized public publication on 11 September 2026. The publication-blocked text inside that historical bundle predates this authorization.

The public maintenance branch retains its original `maintenance/defender-1.9.42` name while subsequent versions are developed. See [pull request #3](https://github.com/joshua08271/Sentinel-Blue/pull/3).
