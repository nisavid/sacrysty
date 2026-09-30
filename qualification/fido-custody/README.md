# FIDO custody synthetic qualification

This directory contains candidate-bound, provisional synthetic CI evidence for
the FIDO custody adapter. It does not qualify the selected source, a real
worker, or any custody or production path.

## Document roles

- [`preparation-2026-09-16.md`](preparation-2026-09-16.md) is the preserved
  preparation record from that date. Its candidate revision and four-input
  inventory describe the source layer reviewed during preparation; they are
  historical and are not the inputs of the current workflow.
- [`real-worker-preparation-2026-09-30.md`](real-worker-preparation-2026-09-30.md)
  maps accepted real-worker requirements to producer inputs, possible platform
  observations, and join and invalidation conditions. It is a requirement and
  input inventory; it contains no real-worker execution or qualification result.
- [The qualification workflow](../../.github/workflows/fido-custody-qualification.yml)
  selects the current CI implementation and frozen synthetic source.
- [`run-synthetic-ci.sh`](run-synthetic-ci.sh) enforces the selected source
  revision and direct runtime input digests, executes both direct checker modes,
  and emits the candidate-bound result.
- [`test-run-synthetic-ci.sh`](test-run-synthetic-ci.sh) exercises the runner's
  import, result-invalidation, rejection, and failure-propagation boundaries
  before the workflow relies on a direct result.

The workflow and runner are the executable authority for the current source
selection. The result emitted by a particular run records the implementation,
workflow, source, runtime, exits, and limits that the run actually observed.

## Current source layer

The current workflow freezes synthetic source revision
[`81896a0c9f0b5af4f8c7e69e7d48da34e8e91318`](https://github.com/nisavid/sacrysty/commit/81896a0c9f0b5af4f8c7e69e7d48da34e8e91318).
The runner verifies the exact bytes of the current direct-FIDO runtime closure
before execution:

- `adapters/fido_custody.py`
- `adapters/fido-custody-v1.md`
- `conformance/check-fido-custody.py`
- `conformance/test_support.py`
- `sacrysty_runtime/__init__.py`
- `sacrysty_runtime/process_groups.py`
- `sacrysty_runtime/strict_json.py`

The expected SHA-256 values live in the runner and are copied into each emitted
result. They are not repeated here so this entrypoint cannot become a competing
input manifest.

The frozen `adapters` and `conformance` directories have no
`__init__.py`. For `ubuntu-24.04`, the workflow selects `/usr/bin/python3`;
for the `macos-15` arm64 image, it selects `/opt/homebrew/bin/python3`. It
supplies the per-platform path through the job matrix and environment, resolves
it to a concrete absolute executable, and passes that path to the behavioral
harness and runner. Direct callers must likewise select and pass an absolute
trusted native CPython executable.

Before invoking the selection, the runner resolves it and requires an
executable regular file with a Linux ELF or macOS Mach-O header. This rejects
script forwarding wrappers without running them. The runner then invokes the
resolved file with isolated, no-site startup and requires CPython to report
that same resolved file as `sys.executable`. Every later Python invocation in
the runner and harness uses that exact selection; no ambient `python3` lookup
is needed or executed.

The native executable remains part of the trusted host and toolchain boundary.
The format and self-identity checks do not attest a selected native binary or
contain malicious native code. The checker launcher binds the `adapters` and
`conformance` namespace package search paths directly to their frozen
directories, inserts the frozen source root ahead of the standard library
paths, imports each executable project module, and verifies that every module
file resolves to its declared path under that root before it runs the checker.
`PYTHONPATH`, user-site packages, `sitecustomize`, and ambient regular
packages therefore cannot replace the bound project modules.

The workflow checks out its own implementation revision separately from the
frozen source. It runs the behavioral harness, then the checker directly under
normal and optimized Python, using external disposable storage with bytecode
writes disabled. The result records both exits, source cleanliness before and
after execution, the selected executable's resolved path and SHA-256, runner
and Python facts, and the workflow and source identities.

## Result destination behavior

A well-formed invocation with available prerequisites and an existing source
directory canonicalizes the prospective result parent before creating it. A
parent within the source checkout is rejected without creating, deleting, or
changing a source path. After the parent is created, the runner canonicalizes
and checks it again.

Once that validation succeeds, the runner unlinks any existing non-directory
entry at the result path before source identity, digest, cleanliness,
architecture, hosted-runner, or implementation preflight. Unlinking replaces
only the destination directory entry: symbolic links are not followed, and
hard-link targets are not modified. A preflight failure after this point
therefore cannot leave an older passing result at a supported reused
destination. A completed attempt still replaces its result atomically through
a same-directory temporary file.

Wrong argument counts, unavailable commands, a missing source directory, an
invalid Python executable selection, an invalid result name, an uncreatable
result parent, and an existing directory at
the result path can fail before an old path is invalidated because the runner
cannot establish or perform the safe file operation. The hosted workflow does
not reuse such a path: it binds `RESULT_FILE` to the current job's
`runner.temp` directory. Direct callers that reuse a destination must satisfy
the validated invocation conditions above.

## Status and provenance

The dated preparation record explains why a CI-only synthetic increment was
selected. Current runs supersede only its source-selection and runtime-input
layer; they do not rewrite that historical evidence or turn its preparation
receipts into workflow inputs.

Each result identifies the preserved preparation report by repository path and
SHA-256 at its recorded implementation revision. That report retains the public
source URLs, immutable source references, and captured Typage file digests used
during preparation. The original temporary public-input and external-source
cache manifests are unavailable. Current results do not claim to verify those
manifests or repeat the historical source retrieval.

The current source is a candidate, not accepted genesis. A passing job is only
a provisional observation of its bound tuple. The [genesis integration](https://github.com/nisavid/sacrysty/pull/20)
owns source correction, review, and validation evidence.
Qualification requires fresh hosted runs and whole-increment review of this
runner and workflow bound to that source; source validation does not supply
those downstream results.

The maintained [genesis validation procedure](https://github.com/nisavid/sacrysty/blob/81896a0c9f0b5af4f8c7e69e7d48da34e8e91318/docs/agents/genesis-validation.md)
owns full source validation. This qualification runner invokes only the direct
synthetic custody checker against its separately frozen input set. The checker
uses the native C compiler to build a disposable environment-observation
fixture; that fixture is not the separately required immutable real worker.

## Invalidation and reconciliation

A change to the selected source revision, any file in the resolved direct
runtime closure, the workflow, runner, behavioral harness, Python runtime,
platform, architecture, or runner image invalidates the affected result. A
source correction requires the direct runtime closure to be established again,
all changed identities to be rebound, fresh hosted evidence, and review of the
same final tuple. The seven paths above must not be assumed to remain the
closure of a later source.

## Limits

This increment uses synthetic workers and value-free inputs. It supplies no
evidence for a real JSON worker, plugin, `age` executable, native FIDO library,
authenticator, PIN or biometric path, provider, keychain, personal host,
custody operation, release, adoption, accepted genesis, or production use.
Those layers require separately owned inputs, authority, and evidence.

[Qualify the FIDO custody adapter](https://github.com/nisavid/sacrysty/issues/16)
remains open until its independent gates are satisfied.
