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
   Require complete history, then run `conformance/check-source-inventory.py` to
   compare every producer path with the commit, parent, tree, mode, blob bytes,
   byte length, and SHA-256 recorded in the source inventory. A shallow clone or
   missing object is a failure, not a skipped provenance check.
4. Compare the candidate's claimed behavior with the accepted contracts. Keep
   undefined schemas and operational behavior with their owning decisions.

## Check the candidate

Run from a clean checkout of the candidate commit. Keep outputs outside the
checkout so they cannot become untracked inputs to the next check. Create one
private, disposable validation root outside the checkout and start conformance
with an explicit value-free environment. Replace the two tool paths and the
external root below with the selected public tools and storage; do not forward
the caller's remaining environment.

```sh
mkdir -p ../sacrysty-validation/home ../sacrysty-validation/tmp \
  ../sacrysty-validation/xdg-config ../sacrysty-validation/gnupg
chmod 700 ../sacrysty-validation/home ../sacrysty-validation/tmp \
  ../sacrysty-validation/xdg-config ../sacrysty-validation/gnupg
env -i \
  PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin \
  HOME="$PWD/../sacrysty-validation/home" \
  TMPDIR="$PWD/../sacrysty-validation/tmp" \
  XDG_CONFIG_HOME="$PWD/../sacrysty-validation/xdg-config" \
  GNUPGHOME="$PWD/../sacrysty-validation/gnupg" \
  GIT_CONFIG_GLOBAL="$PWD/../sacrysty-validation/missing-global-gitconfig" \
  GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 \
  LANG=C LC_ALL=C PYTHONDONTWRITEBYTECODE=1 \
  SQ=/absolute/path/to/selected/sq SQV=/absolute/path/to/selected/sqv \
  ./scripts/check-conformance.sh
cargo fmt --all -- --check
cargo clippy --frozen --all-targets --all-features -- -D warnings
cargo build --frozen --all-targets --all-features
cargo test --frozen --all-targets --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --frozen --no-deps --all-features
```

The conformance entrypoint checks repository policy and whitespace; runs
public-record and synthetic custody checks; runs the crypto-runner and process
regressions; checks the full-history source inventory; then runs probe-result,
strict-JSON, and aggregate-result regressions. Each pre-probe Python check runs
in normal and optimized mode. Complete mode then runs both disposable
crypto-tool probes.
Probe regression tests use constructed tool responses; only the subsequent
crypto probes exercise the selected real tools. The `--synthetic-only` option
omits the real probes and reports that omission. Neither mode is a hardware or
adoption qualification. The empty Rust library test harness establishes
buildability and contains no behavioral tests.

Each selected `sq` or `sqv` process is limited to 120 seconds, 1 MiB on each
captured output stream, and 16 MiB per regular file. The aggregate limits each
complete probe runner to 900 seconds and 1 MiB on stdout and stderr. It
terminates ordinary same-process-group descendants before returning. The inner
helper proves selected-group absence, the runner consumes that receipt before
deleting disposable material, and the outer helper proves runner-group absence
and consumes the runner receipt before result storage may be removed. Missing
evidence retains the affected result directory and fails. These bounds fail
closed on timeout, overflow, live descendants, persistent denial, or cleanup
failure; they are not a sandbox for a process that deliberately escapes its
group or a recovery mechanism for uncatchable parent death.

Runner error and catchable-termination paths finalize their active helper and
disposable material before exiting; the shell exit trap is only a fallback. The
process helper reconstructs the selected environment from its explicit
serialized allowlist immediately before exec. On macOS it synthesizes the
startup `__CF_USER_TEXT_ENCODING` from the user ID with zero encoding and
region fields instead of forwarding an ambient value.

The runner result contains self-reported tool versions, not executable,
platform, or dependency identity. Bind those identities in a separate
validation or qualification receipt alongside the exact source commit, fixture
bytes, runtime versions, and measured results. The aggregate first requires a
zero runner status, then parses each result, checks its schema and mandatory
booleans, and requires the tested commit. Signing diagnostics count as normal
verifier rejection only for integer statuses 1 through 123. Record
`unsupported`, `probe-failed`, `round-trip-failed`, or unrun directly; only an
explicit recognized capability rejection is `unsupported`, and none becomes a
positive capability claim.

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
