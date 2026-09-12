# Public defender releases

Latest runtime candidate: **1.9.44**, [releases/sentinel-blue-1.9.44.pyz](releases/sentinel-blue-1.9.44.pyz). The expanded branch source matches it. Runtime SHA-256: `c115f1620f537fc77354aa0150e271cb0934d374e4ffa8ec44847c908f3a1cb8`.

The 1.9.44 local suite ran 220 tests: 218 passed, two Windows-only tests skipped. CI and targeted Azure acceptance are pending. See [current validation](docs/DEFENSIVE_VALIDATION_1.9.44.md).

The public 1.9.43 runtime passed [Linux and Windows CI](https://github.com/joshua08271/Sentinel-Blue/actions/runs/34659310009). Its live Azure Linux run passed all seven guest-local defensive phases; the paired Windows run and final Azure cleanup are still in progress. These are separate results for the exact 1.9.43 runtime, not acceptance of 1.9.44.

The previous [1.9.42 complete bundle](releases/sentinel-blue-defender-1.9.42.zip) remains available unchanged. Its [CI](https://github.com/joshua08271/Sentinel-Blue/actions/runs/34658160560) passed after explicit public-publication authorization on 11 September 2026; publication-blocked text inside that historical bundle predates this authorization.

The public maintenance branch retains its original `maintenance/defender-1.9.42` name as later versions are developed. See [pull request #3](https://github.com/joshua08271/Sentinel-Blue/pull/3). The complete 1.9.44 bundle will include the final acceptance evidence.
