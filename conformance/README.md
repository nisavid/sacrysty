# Conformance

Conformance assets exercise public contracts with disposable inputs. Their
results distinguish source behavior, runtime observations, qualification,
support, and production acceptance.

Run `./scripts/check-conformance.sh` from a clean repository checkout to run
the checks together. `--synthetic-only` runs the Python checks and explicitly
omits the crypto probes. The [genesis validation procedure](../docs/agents/genesis-validation.md)
describes revision binding and consumer handoff.

Set `TMPDIR` to an existing directory outside the checkout. Synthetic workers,
constructed repositories, probe artifacts, and aggregate result captures stay
under that external directory and are removed after each run.

Each check is also available separately:

| Command | Exercised surface | Evidence boundary |
| --- | --- | --- |
| `python3 conformance/check-domain-model.py` | Canonical and hostile serialized public-record fixtures | Strict JSON, schema-derived envelope structure, and inert-extension admission; no record-family or operational qualification. |
| `python3 conformance/test-domain-model.py` | Checker rejection and diagnostic behavior | Constructed valid and malformed envelopes, including optimized Python. |
| `./conformance/run-sq.sh` | The crypto-conformance profile and disposable `sq`/`sqv` operations | Observations for the selected tools and runtime; no project-wide support or adopter acceptance. |
| `python3 conformance/test-run-sq.py` | Crypto-probe source binding, portability, JSON, and cleanup | Constructed tool responses; no cryptographic capability claim. |
| `./conformance/run-signing-profile.sh` | Detached signatures and rejection diagnostics | The signing-profile fixture; no release-signing authority. |
| `python3 conformance/test-run-signing-profile.py` | Signing-runner source, store, JSON, verification, rejection, and cleanup controls | Constructed tool responses; no cryptographic capability claim. |
| `python3 conformance/check-fido-custody.py` | Synthetic one-shot custody workers | Success and failure paths; no authenticator, plugin, native-library, or production qualification. |
| `python3 conformance/check-source-inventory.py` | Producer commits and every inventoried source path | Complete Git object history, ancestry, tree membership, modes, blobs, byte lengths, and hashes; no hosted availability or review claim. |
| `python3 conformance/check-probe-result.py <crypto-conformance\|signing-profile> <result.json> <revision>` | Captured crypto-probe JSON | Required result identity, source binding, profile result, diagnostics, and mandatory check values; no qualification beyond the admitted observation. |

The crypto probes generate disposable key material in temporary directories
and disable default key and certificate stores. The
[crypto-conformance profile](../profiles/crypto-conformance-v1.toml) and
[case manifest](../fixtures/cases-v1.toml) state their intended claims.
RFC 9980 support requires the specified positive operations and independent
verification; an algorithm name in help output does not establish support. An
explicit capability rejection is `unsupported`; unknown generation failures
are `probe-failed`, and failures after generation are `round-trip-failed`.
Only the first is an admitted nonpositive observation for a passing run.

The domain checker implements only the JSON Schema constructs present in the
checked-in closed-envelope schema. It fails closed if that schema introduces an
unsupported construct; it is not a general JSON Schema implementation.

The aggregate captures each real probe's stdout, parses it as strict JSON,
checks its source revision and mandatory results, and requires a zero runner
exit status before announcing success. Malformed, missing, wrong-schema,
failed, indeterminate, or false-check evidence cannot pass the aggregate.

Bind recorded results to the tested source revision and selected runtime.
Documentation examples consume these fixtures and results. Genesis acceptance
also requires the independent checks and review recorded in the
[owning ticket](https://github.com/nisavid/sacrysty/issues/3).
