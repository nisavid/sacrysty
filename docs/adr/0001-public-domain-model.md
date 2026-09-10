# ADR 0001: Public record domain model and inert extensions

- **Status:** accepted for the pre-1.0 public contract
- **Owning issue:** [Sacrysty #14](https://github.com/nisavid/sacrysty/issues/14)
- **Source decision:** [dotfiles #207](https://github.com/nisavid/dotfiles/issues/207#issuecomment-5470521497)

## Decision

Sacrysty publishes one closed, versioned public-record envelope. Record
families are `contract`, `profile`, `adapter`, `qualification`, and `release`.
The envelope identifies its schema version, publisher, stable record identity,
optional semantic version and content digest, and a family-specific object
body. Public metadata is value-free and owns reusable schemas and evidence
formats; system users own selection, exact pins, private bindings, and
acceptance evidence.

Extensions are namespaced metadata with an explicit `inert` state and
`optional` or `required` criticality. Optional unknown extensions may be
preserved; required unknown extensions, active extensions, unsupported
extension versions, unnamespaced keys, and unknown closed-envelope fields are
rejected before consumption. No extension can select an adapter, resolve a
secret, grant authority, or mutate a host or provider.

## Rationale and alternatives

Closed records prevent older readers from silently accepting new authority or
security semantics. Namespaced inert extensions preserve forward-compatible
documentary metadata without creating an ambient plugin mechanism. An open
envelope or executable extension hook would make unknown semantics observable
as success and would cross the public/adopter boundary.

## Review and compatibility

The threat-boundary review preserves the #207 invariant that failed,
unsupported, or indeterminate inputs never create positive authority. This is
a pre-1.0 incompatible contract addition: readers must explicitly support
`io.nisavid.sacrysty.public-record/v1`, and migrations produce a new digest
without rewriting a prior record. The executable conformance check accepts one
canonical fixture and rejects four hostile fixtures. It uses no external
runtime, secret, provider, host, or production value.

Genesis must bind its implementation and evidence to the immutable revision
containing this ADR, schema, and fixtures. Adapter implementation and genesis
integration remain downstream handoffs.
