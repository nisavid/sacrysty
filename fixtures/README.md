# Fixtures

This directory contains disposable, value-free canonical and hostile fixtures.
The RFC 9580 message is intentionally ordinary text; the conformance runner
derives the key, detached signature, and tampered variant in a temporary
directory so no secret or captured private evidence is committed.

Fixtures cannot contain production identifiers, secrets, provider payloads,
real custody values, or captured private evidence. Add a fixture only when its
bytes and expected machine-readable result are part of an accepted profile.
The case manifest in [`cases-v1.toml`](cases-v1.toml) names the implemented
tool-boundary vectors and records later protocol vectors as reserved under
their owning tickets; reserved cases carry no implied protocol semantics.
