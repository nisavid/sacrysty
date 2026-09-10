# Fixtures

This directory will contain disposable, value-free canonical and hostile
fixtures after their owning contracts are accepted.

Fixtures cannot contain production identifiers, secrets, provider payloads,
real custody values, or captured private evidence. The canonical and hostile
public-record fixtures exercise the domain-model boundary. The canonical record
is accepted; each hostile record must be rejected for active or unnamespaced
extensions, an unknown required extension, or an unknown top-level field.
