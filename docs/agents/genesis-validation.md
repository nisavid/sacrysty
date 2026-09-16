# Validate a genesis integration candidate

Use this procedure when assembling Sacrysty's public genesis inputs or checking
a candidate for a downstream consumer. It produces source and test evidence
for the candidate. The owning issue controls acceptance of the complete genesis.

## Inputs and provenance

1. Read `CONTEXT.md`, the owning issue, and
   [the input receipt](../provenance/genesis-inputs.md).
2. Read the live native map and all dependency pages. Check assignments before
   work, and preserve the current coordinator's claim across a handoff.
3. Verify each source commit and its changed paths. Record copied, translated,
   retained, and superseded inputs. A closed issue or available Git object does
   not prove that its source is integrated or that its review covers the candidate.
4. Compare the candidate's claimed behavior with the accepted contracts. Keep
   undefined schemas and operational behavior with their owning decisions.

## Check the candidate

Run from a clean checkout of the candidate commit. Keep outputs outside the
checkout so they cannot become untracked inputs to the next check.

```sh
./scripts/check-conformance.sh
cargo fmt --all -- --check
cargo clippy --frozen --all-targets --all-features -- -D warnings
cargo build --frozen --all-targets --all-features
cargo test --frozen --all-targets --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --frozen --no-deps --all-features
```

The conformance entrypoint runs public-record, synthetic custody, and probe
regression checks in normal and optimized Python, then both disposable
crypto-tool probes. Probe regression tests use constructed tool responses;
only the subsequent crypto probes exercise the selected real tools. The
`--synthetic-only` option omits the crypto probes and reports that omission.
Neither mode is a hardware or adoption qualification. The empty Rust library
test harness establishes buildability and contains no behavioral tests.

Bind tool observations to the exact source commit, runtime versions,
executable/dependency identities, fixture bytes, and measured results. Check
that each crypto result names the tested commit. Record an unsupported or
unrun result directly; do not turn it into a pass for a different claim.

Native Linux and macOS build results belong to the revision that ran in CI.
Synthetic conformance on a platform does not establish that platform's
crypto-tool, authenticator, native-library, or custody support.

## Review and consumer handoff

Review the final candidate and each changed evidence dependency. A changed
candidate invalidates affected earlier passes. Bind independent review and
required maintainer approval to the published revision, and rerun checks when
publication or integration changes it.

Public evidence includes only reviewed, value-free fields. Inspect raw tool
logs before publishing: build logs can contain local paths, and arbitrary tool
diagnostics are not an approved public evidence format. Publish source and
result digests, commands, versions, limits, and review pointers without private
bindings, identifiers, or generated key material.

Pass the accepted revision, this procedure at that revision, the input receipt,
and the measured evidence to the named consumer through the tracker. The
consumer verifies those inputs before its own qualification. Public genesis
does not settle the consumer's deployment lock, bootstrap acceptance, ceremony,
or release authority.
