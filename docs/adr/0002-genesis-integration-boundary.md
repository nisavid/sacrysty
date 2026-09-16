# ADR 0002: Genesis integration and conformance boundaries

- **Status:** proposed; requires maintainer approval of the integration revision
- **Owning issue:** [Establish Sacrysty's immutable public genesis](https://github.com/nisavid/sacrysty/issues/3)
- **Inputs:** [genesis input receipt](../provenance/genesis-inputs.md), ADR 0001,
  the signing profile, and the one-shot custody adapter contract

## Decision proposed for review

Assemble the settled public inputs in one candidate and validate their existing
boundaries together. Keep the Rust library empty until an owning decision
defines a concrete library or command interface. Record-family body schemas,
policy and registry behavior, operational protocols, and complete ceremony
procedures require their owning decisions before implementation or acceptance.
Codiquary owns release-authority, publication, verifier, protocol, and
executable release-conformance contracts. Sacrysty may consume their accepted
revisions, but this candidate neither defines nor restates their wire semantics.
[Codiquary #35](https://github.com/nisavid/codiquary/issues/35) remains the
operator's current decision for the first executable release-conformance
increment; no outcome is selected here.

The candidate's public-record check validates envelope structure and the
accepted inert-extension rules. It does not validate record-family bodies or
consume them operationally. Its baseline consumer understands no required
extensions. Invalid shapes and unsupported inputs fail even when Python
optimization is enabled.

The synthetic custody adapter bounds input, both output streams, and waiting
time. After worker creation, every completion path requests termination of
ordinary same-process-group descendants and boundedly attempts to reap the
worker leader. The adapter returns no plaintext result when the operating
system reports a group-cleanup error other than an already absent process
group. This fail-closed result does not establish operating-system cleanup
after a kernel denial. Duplicate response fields are rejected. Test controls
belong to disposable workers, rather than the adapter's environment forwarding
policy. A process group is not a sandbox for a worker that deliberately escapes
it.

The crypto probes record observed behavior for the selected standard tools.
They require clean source, portable hash tools, admitted JSON results, and
verified temporary cleanup before reporting success. Post-quantum capability
remains subject to the existing positive-operation and independent-verification
gate; explicit unsupported capability, indeterminate probe failure, and failed
round trip remain distinct results.

## Security considerations

The [threat and authority model](https://github.com/nisavid/dotfiles/issues/215#issuecomment-5464747293)
and [public-core boundary](https://github.com/nisavid/dotfiles/issues/207#issuecomment-5470521497)
remain controlling. Public metadata, worker output, and tool diagnostics are
inputs to validate. None supplies positive authority or permits private state
access. Invalid metadata must fail without execution. Excessive worker output
must fail before it can consume unbounded memory. A failed or unsupported tool
observation must retain that result.

The reference adapter exercises synthetic workers. Its tests do not establish
authenticator behavior, user verification, native dependency integrity,
plaintext custody, or production readiness. Exact plugin and platform
qualification remains with
[Qualify the FIDO custody adapter](https://github.com/nisavid/sacrysty/issues/16).

## Compatibility

The public-record envelope's serialized shape and the one-shot adapter's
intended bounds remain the input contracts. Correctly rejecting invalid shapes
or unsupported extensions can change results for callers that relied on the
incomplete checker. Such callers must correct their inputs; this candidate
does not silently migrate them.

Material adapter changes require renewed affected qualification. No existing
private deployment lock is changed, and no hardware qualification is claimed
by this integration. The project remains experimental before 1.0 with no new
support commitment.

## Acceptance evidence

The [genesis validation procedure](../agents/genesis-validation.md) identifies
the source, runtime, fixture, privacy, and review evidence to bind to the final
published revision. An independent security review and explicit maintainer
approval must cover that revision before this proposal is accepted. Passing
the integration suites alone does not close the broader genesis issue.
