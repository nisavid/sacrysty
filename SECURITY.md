# Security policy

## Supported versions

Sacrysty has no released implementation or supported runtime yet. Security
reports are accepted for every known repository revision, but acceptance does
not promise a remediation deadline, backport, continued platform support, or a
release. Historical revisions remain identifiable and are not silently changed.

## Report a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/nisavid/sacrysty/security/advisories/new).
Do not open a public issue, pull request, or discussion for an undisclosed
vulnerability.

Include the affected component and immutable revision, expected impact,
reproduction steps or a proof of concept, and known mitigations. Do not include
real credentials, private keys, private deployment values, personal data, or
secret-bearing provider payloads. Do not test against a live deployment,
custody path, or production authority without its owner's separate explicit
permission.

The maintainer will coordinate disclosure with the reporter. The project may
suspend qualification or warn against an affected revision. An advisory is not
a promise to repair every historical version.

## Security boundary

Repository checks, CI attestations, hosting controls, and maintainer approval
are defense in depth. They do not establish a cryptographic protocol, custody
path, production authority, independent verification result, or adopter
acceptance.
