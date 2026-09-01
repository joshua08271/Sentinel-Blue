# Security policy

Sentinel Blue 1.9.13 is defensive software. Security fixes are developed on
reviewed candidate branches and are not considered released until required
validation and publication checks pass.

## Supported versions

The latest released 1.9.x build receives security fixes. Older candidates,
development artifacts, and browser-helper builds are not supported merely
because they remain downloadable. Verify the version and SHA-256 digest before
testing or deployment.

## Private reporting

Use the repository's private security-advisory channel when it is available.
Otherwise, contact the repository owner through an already established private
channel before sending technical details. Do not open a public issue containing:

- working exploit instructions or weaponized payloads;
- credentials, tokens, private keys, internal addresses, or cloud identifiers;
- production logs, personal data, or competition evidence;
- details that identify a system you are not authorized to test.

A useful private report includes the affected version and commit, operating
system, defensive impact, prerequisites, a minimal reproduction using disposable
local data, and the expected safe behavior. Redact all secrets.

## Research boundary

Test only assets you own or have explicit written authorization to assess. Use an
isolated disposable range, set cost and scope limits, and stop if testing could
affect third parties, production availability, or data integrity. Do not use
Sentinel Blue as authority to evade competition rules, provider policy, or law.

## Response and disclosure

Maintainers should reproduce the issue in an isolated environment, record the
affected boundary, add a regression test, and validate the fix across supported
platforms. Coordinate public disclosure only after a fixed release is available.
Security claims should state the tested scope and must not imply that any build
is invulnerable or fully autonomous.

## Release hygiene

Release inputs must be tracked regular files, deterministic bundles must match
across independent builds, and operational reports are excluded. Repository and
artifact audits must fail closed on unexpected files, credentials, archive path
ambiguities, checksum drift, or version mismatches.
