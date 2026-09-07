# Governance

## Scope

This document governs Sacrysty's public contracts, implementation, adapters,
profiles, fixtures, conformance and qualification assets, documentation, and
releases. It grants no authority over a system user's private deployment,
custody, ceremonies, or production operations.

## Maintainer responsibility

Ivan D Vasin begins as lead maintainer. The lead maintainer owns repository
administration, contribution admission, public compatibility declarations,
qualification status, advisory publication, and release coordination. A path
to shared stewardship may add scoped maintainers when sustained contribution
and independent review justify it; this repository does not pretend that a
multi-maintainer quorum exists today.

Project governance cannot create cryptographic authority, reinterpret failed
verification as success, or override a system user's acceptance policy.
Production authority belongs to each system user's separately governed
deployment.

## Change classes

- Normative or security-boundary changes require an ADR, threat-model review,
  conformance changes, compatibility analysis, and explicit maintainer approval.
- Core implementation changes must continue to satisfy the existing contract.
- Adapter-interface changes require capability, compatibility, and migration
  evidence.
- Material adapter changes renew every affected qualification record.
- Documentation, examples, and reference implementations cannot redefine a
  normative contract.
- Emergency security work may shorten ordinary review, but it cannot weaken a
  settled safety or verification gate.

## Releases and compatibility

Before 1.0, every public interface is experimental and releases are
need-driven. The project makes no cadence, backport, compatibility-window,
advance-notice, deprecation-window, remediation-time, platform-support, or
post-1.0 stability promise.

An incompatible upgrade never rewrites an accepted deployment lock. A system
user explicitly updates its profile or lock and renews affected qualification
and acceptance. Old releases remain immutable and identifiable; that does not
promise fixes or continued support.

A separate 1.0-readiness decision may define stronger promises only after
sustained external use exposes functionality, operations, maintenance, and
downstream consequences.

## Amendments and succession

Governance changes use the same review path as normative changes and state
their compatibility and stewardship effects. A later project transfer must
preserve release identities, contract history, advisories, attribution,
qualification records, and an authenticated continuity statement.
