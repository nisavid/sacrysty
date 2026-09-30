# Documentation

This directory holds architecture, decisions, provenance, and explanations of
the accepted operational boundaries. Executable operator procedures depend on
the contracts identified by the genesis work.

Normative behavior belongs in `contracts/`. Documentation explains and links
that behavior; it does not redefine it. Executable examples should come from
`fixtures/` and `conformance/` so prose does not drift from tested results.

- `adr/` records architectural decisions and proposals with explicit status.
- `agents/` documents repository mechanics for coding agents.
- [Cryptographic operations boundaries](explanation/operations-boundaries.md)
  explains the settled threat and custody constraints and the separate
  Sacrysty/Codiquary ownership boundary.
- `provenance/` records reviewed source evidence and ownership handoffs.
- [FIDO worker interface research](research/fido-worker-interfaces.md) records
  disposable CLI/plugin observations and inputs for the pending worker contract.
- [Generic FIDO plugin upstream baseline](research/fido-upstream-baseline.md)
  records source, support, provenance, and follow-up dispositions.

`agents/dco-provisioning.md` is the single operating procedure for DCO
provisioning, verification, migration, recovery, and rollback.

Published bodies of practice remain unnamed. Do not introduce a branded name
until an owning decision establishes that the concept needs one.
