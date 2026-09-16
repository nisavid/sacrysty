# FIDO custody synthetic qualification

This directory contains candidate-bound, provisional synthetic CI evidence for
the FIDO custody adapter. It does not qualify the selected source, a real
worker, or any custody or production path.

## Document roles

- [`preparation-2026-09-16.md`](preparation-2026-09-16.md) is the preserved
  preparation record from that date. Its candidate revision and four-input
  inventory describe the source layer reviewed during preparation; they are
  historical and are not the inputs of the current workflow.
- [The qualification workflow](../../.github/workflows/fido-custody-qualification.yml)
  selects the current CI implementation and frozen synthetic source.
- [`run-synthetic-ci.sh`](run-synthetic-ci.sh) enforces the selected source
  revision and direct runtime input digests, executes both direct checker modes,
  and emits the candidate-bound result.
- [`test-run-synthetic-ci.sh`](test-run-synthetic-ci.sh) exercises the runner's
  rejection and failure-propagation boundaries before the workflow relies on a
  direct result.

The workflow and runner are the executable authority for the current source
selection. The result emitted by a particular run records the implementation,
workflow, source, runtime, exits, and limits that the run actually observed.

## Current source layer

The current workflow freezes synthetic source revision
[`d421a7a08b6e0973e60b54a3796a9c62642f7615`](https://github.com/nisavid/sacrysty/commit/d421a7a08b6e0973e60b54a3796a9c62642f7615).
The runner verifies the exact bytes of the current direct-FIDO runtime closure
before execution:

- `adapters/fido_custody.py`
- `adapters/fido-custody-v1.md`
- `conformance/check-fido-custody.py`
- `conformance/test_support.py`
- `conformance/strict_json.py`

The expected SHA-256 values live in the runner and are copied into each emitted
result. They are not repeated here so this entrypoint cannot become a competing
input manifest.

The workflow checks out its own implementation revision separately from the
frozen source. It runs the behavioral harness, then the checker directly under
normal and optimized Python, using external disposable storage with bytecode
writes disabled. The result records both exits, source cleanliness before and
after execution, runner and Python facts, and the workflow and source
identities.

## Status and provenance

The dated preparation record explains why a CI-only synthetic increment was
selected. Current runs supersede only its source-selection and runtime-input
layer; they do not rewrite that historical evidence or turn its preparation
receipts into workflow inputs.

The current source is a published candidate, not accepted genesis. A passing
job is only a provisional observation of its bound tuple. The latest
[whole-increment review](https://github.com/nisavid/sacrysty/pull/21#issuecomment-5695643645)
requires source-owner corrections before acceptance; passing Linux or macOS
jobs do not clear those findings.

## Invalidation and reconciliation

A change to the selected source revision, any file in the resolved direct
runtime closure, the workflow, runner, behavioral harness, Python runtime,
platform, architecture, or runner image invalidates the affected result. A
source correction requires the direct runtime closure to be established again,
all changed identities to be rebound, fresh hosted evidence, and review of the
same final tuple. The five paths above must not be assumed to remain the closure
of a later source.

## Limits

This increment uses synthetic workers and value-free inputs. It supplies no
evidence for a real JSON worker, plugin, `age` executable, native FIDO library,
authenticator, PIN or biometric path, provider, keychain, personal host,
custody operation, release, adoption, accepted genesis, or production use.
Those layers require separately owned inputs, authority, and evidence.

[Qualify the FIDO custody adapter](https://github.com/nisavid/sacrysty/issues/16)
remains open until its independent gates are satisfied.
