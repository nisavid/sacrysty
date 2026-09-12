# Fixtures

This directory will contain disposable, value-free canonical and hostile
fixtures after their owning contracts are accepted.

Fixtures cannot contain production identifiers, secrets, provider payloads,
real custody values, or captured private evidence. The FIDO adapter's worker
fixture is generated inside the conformance runner and uses only synthetic
envelope and plaintext bytes.
