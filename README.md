# Sentinel Blue 1.9.13

Sentinel Blue is a defensive monitoring, validation, and guarded-restoration
orchestrator for systems the operator is authorized to administer. The core
runtime uses the Python standard library and supports Python 3.11 through 3.14.

## Release status

A version number identifies source compatibility; it is not, by itself, a
certification. Treat a commit as release-ready only when its required CI checks,
cross-platform package hashes, restore tests, and human review all pass. Draft
pull requests and candidate branches are not published releases.

## Safety boundary

- Use Sentinel Blue only on assets you own or are explicitly authorized to test.
- Keep adversarial validation inside isolated, disposable ranges.
- Preserve dry-run and approval gates until the target, rollback point, and
  competition rules have been verified.
- Do not store credentials, live tokens, private keys, or production evidence in
  the repository or release bundle.
- Sentinel Blue is not an exploitation framework and does not authorize scanning
  or interfering with third-party systems.

## Validate a checkout

```text
python -m unittest discover -s tests -v
python -m sentinel_blue self-test --scenarios 500 --fuzz-iterations 5000 --load-events 1000 --json
python -m sentinel_blue range --runs 1000 --json
python -m sentinel_blue restoration-lab --runs 1000 --json
```

These commands exercise local disposable state. Review `--help` before using
any operational command.

## Build and verify the defensive core

```text
python tools/check_release_consistency.py --expected 1.9.13
python tools/build_release.py --output release
python tools/check_release_consistency.py --expected 1.9.13 --bundle release/sentinel-blue-complete-lab-1.9.13.zip
python tools/smoke_release.py release/sentinel-blue-1.9.13.pyz
```

The complete bundle contains the zipapp, source archive, and `SHA256SUMS`.
Operational reports and credentials are deliberately excluded. Compare the
published digest through a trusted channel before running an artifact.

Azure federation setup is documented in `docs/AZURE_OIDC.md`. Example JSON
files are templates only and must not be populated with secrets before commit.

## Security reports

See `SECURITY.md`. Report exploitable details privately and never attach live
credentials, customer data, or evidence from systems you do not control.

## License

MIT; see `LICENSE`. Authorization, competition eligibility, privacy, and local
law remain the operator's responsibility.
