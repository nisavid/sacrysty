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
   Run `conformance/check-source-inventory.py` to verify the retained source
   bundle and compare every producer path with the commit, parent, tree, mode,
   blob bytes, byte length, and SHA-256 recorded in the source inventory. Keep
   the bundle with the candidate; a shallow checkout is supported. Missing or
   altered bundled evidence is a failure. The checker imports only into external
   temporary storage and leaves the candidate's Git objects and refs untouched.
4. Compare the candidate's claimed behavior with the accepted contracts. Keep
   undefined schemas and operational behavior with their owning decisions.

## Merge and downstream consumption

Use the repository's permitted merge method. Before merging an integration
change, exercise source-inventory conformance and its regressions on a clean
checkout of the proposed merged tree with only the target branch's history.
After merge, identify the actual published commit and tree, verify the tree
against the reviewed candidate, and run the same checks from a fresh shallow
checkout. Retain the new command results with that published commit; earlier
receipts keep their original commit identities. Consumers bind their evidence
to the revision they actually test.

## Check the candidate

Run from a clean checkout of the candidate commit. The inputs are an existing
external storage directory, absolute paths to the selected public `sq`, `sqv`,
and Rustup executables, and the absolute Rustup home that already contains
toolchain 1.98.1. Toolchain installation is a host-local prerequisite, not part
of this procedure. Set the five placeholders below, then run the remaining block
unchanged. It creates a new private validation root for every invocation and
passes one value-free environment to every source, conformance, and Cargo step.

```bash
#!/usr/bin/env bash
export SACRYSTY_VALIDATION_PARENT=/absolute/path/to/external-storage
export SACRYSTY_RUSTUP=/absolute/path/to/rustup
export SACRYSTY_RUSTUP_HOME=/absolute/path/to/rustup-home
export SQ=/absolute/path/to/selected/sq
export SQV=/absolute/path/to/selected/sqv

set -Eeuo pipefail
umask 077

source_root=$(pwd -P)
validation_parent=$(CDPATH='' cd -- "$SACRYSTY_VALIDATION_PARENT" && pwd -P)
rustup_home=$(CDPATH='' cd -- "$SACRYSTY_RUSTUP_HOME" && pwd -P)
rustup=$SACRYSTY_RUSTUP
sq=$SQ
sqv=$SQV
validation_path=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin

case "$validation_parent" in
  "$source_root" | "$source_root"/*)
    printf 'validation storage must be outside the source checkout\n' >&2
    exit 1
    ;;
esac
case "$rustup_home" in
  "$source_root" | "$source_root"/*)
    printf 'Rustup home must be outside the source checkout\n' >&2
    exit 1
    ;;
esac
for executable in "$rustup" "$sq" "$sqv"; do
  case "$executable" in
    /*) ;;
    *)
      printf 'selected executable path must be absolute: %s\n' "$executable" >&2
      exit 1
      ;;
  esac
  if [[ ! -x $executable || -d $executable ]]; then
    printf 'selected executable is unavailable: %s\n' "$executable" >&2
    exit 1
  fi
done

validation_root=$(mktemp -d "$validation_parent/sacrysty-genesis-validation.XXXXXX")
mkdir -p \
  "$validation_root/home" \
  "$validation_root/tmp" \
  "$validation_root/xdg-cache" \
  "$validation_root/xdg-config" \
  "$validation_root/xdg-data" \
  "$validation_root/xdg-state" \
  "$validation_root/gnupg" \
  "$validation_root/cargo-home" \
  "$validation_root/cargo-target"
receipt=$validation_root/receipt.txt
printf 'schema=io.nisavid.sacrysty.genesis-validation/v1\n' >"$receipt"
printf 'validation_root=%s\n' "$validation_root" >>"$receipt"
printf 'private validation evidence: %s\n' "$validation_root"

run_in_validation_environment() {
  env -i \
    PATH="$validation_path" \
    HOME="$validation_root/home" \
    TMPDIR="$validation_root/tmp" \
    XDG_CACHE_HOME="$validation_root/xdg-cache" \
    XDG_CONFIG_HOME="$validation_root/xdg-config" \
    XDG_DATA_HOME="$validation_root/xdg-data" \
    XDG_STATE_HOME="$validation_root/xdg-state" \
    GNUPGHOME="$validation_root/gnupg" \
    GIT_CONFIG_GLOBAL="$validation_root/missing-global-gitconfig" \
    GIT_CONFIG_NOSYSTEM=1 \
    GIT_TERMINAL_PROMPT=0 \
    CARGO_HOME="$validation_root/cargo-home" \
    CARGO_TARGET_DIR="$validation_root/cargo-target" \
    RUSTUP_HOME="$rustup_home" \
    RUSTDOCFLAGS='-D warnings' \
    LANG=C \
    LC_ALL=C \
    PYTHONDONTWRITEBYTECODE=1 \
    SQ="$sq" \
    SQV="$sqv" \
    "$@"
}

candidate_head=
candidate_tree=
record_source_state() {
  local phase=$1
  local head tree status top
  head=$(run_in_validation_environment git rev-parse HEAD)
  tree=$(run_in_validation_environment git rev-parse 'HEAD^{tree}')
  top=$(run_in_validation_environment git rev-parse --show-toplevel)
  status=$(
    run_in_validation_environment \
      git status --porcelain=v1 --untracked-files=all
  )
  if [[ $top != "$source_root" || -n $status || -e $source_root/target ]]; then
    printf 'source checkout failed the %s-state check\n' "$phase" >&2
    printf 'result=failed phase=%s-source-state\n' "$phase" >>"$receipt"
    return 1
  fi
  printf '%s_head=%s\n%s_tree=%s\n%s_target_absent=true\n' \
    "$phase" "$head" "$phase" "$tree" "$phase" >>"$receipt"
  if [[ -z $candidate_head ]]; then
    candidate_head=$head
    candidate_tree=$tree
  elif [[ $head != "$candidate_head" || $tree != "$candidate_tree" ]]; then
    printf 'source revision changed at the %s-state check\n' "$phase" >&2
    printf 'result=failed phase=%s-source-revision\n' "$phase" >>"$receipt"
    return 1
  fi
}

run_validation_step() {
  local label=$1
  local result
  shift
  record_source_state "$label-before"
  if run_in_validation_environment "$@" \
    >"$validation_root/$label.stdout" \
    2>"$validation_root/$label.stderr"; then
    result=0
  else
    result=$?
  fi
  printf 'step_%s_status=%s\n' "$label" "$result" >>"$receipt"
  record_source_state "$label-after"
  if ((result != 0)); then
    printf 'result=failed phase=%s\n' "$label" >>"$receipt"
    printf 'validation step failed; private evidence retained: %s\n' \
      "$validation_root" >&2
    return "$result"
  fi
}

record_source_state before
run_validation_step conformance ./scripts/check-conformance.sh
run_validation_step cargo-fmt \
  "$rustup" run 1.98.1 cargo fmt --all -- --check
run_validation_step cargo-clippy \
  "$rustup" run 1.98.1 cargo clippy \
  --frozen --all-targets --all-features -- -D warnings
run_validation_step cargo-build \
  "$rustup" run 1.98.1 cargo build --frozen --all-targets --all-features
run_validation_step cargo-test \
  "$rustup" run 1.98.1 cargo test --frozen --all-targets --all-features
run_validation_step cargo-doc \
  "$rustup" run 1.98.1 cargo doc --frozen --no-deps --all-features
record_source_state after
printf 'result=passed\n' >>"$receipt"
printf 'genesis validation passed; private evidence retained: %s\n' \
  "$validation_root"
```

The block has no no-op path. Invalid inputs or a dirty checkout fail before a
positive result. A failed check retains its unique private root and records the
failing phase and any completed command's status; a successful check retains the
receipt and per-step streams for review. Every source observation requires a
clean checkout, an absent checkout-local `target/`, and the initial commit and
tree. Observations run before and after each validation command and the complete
sequence. A different commit fails even when its tree is unchanged; an observed
move from A to B fails before a later command can return to A. These are local
workflow checks: a change and reversal entirely between observations can go
undetected, and the observations do not isolate the checkout from concurrent
writers. Review the retained evidence, then remove only that exact root. Do not
publish its absolute paths or raw logs without reviewing them first.

The conformance entrypoint checks repository policy and whitespace; runs
public-record and synthetic custody checks; runs the crypto-runner and process
regressions; checks the bundled-source inventory; then runs probe-result,
strict-JSON, aggregate-result, and genesis-procedure regressions. Each pre-probe
Python check runs in normal and optimized mode. Complete mode then runs both
disposable crypto-tool probes.
The custody check uses the native C compiler from the explicit path to build a
temporary value-free worker under `TMPDIR`. That worker observes the exact
environment at final exec; it is a constructed test fixture, not the selected
FIDO plugin, native dependency closure, or hardware runtime.
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
