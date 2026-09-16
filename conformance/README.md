# Conformance

Conformance assets exercise public contracts with disposable inputs. Their
results distinguish source behavior, runtime observations, qualification,
support, and production acceptance.

Run `./scripts/check-conformance.sh` from a clean repository checkout to run
the checks together. `--synthetic-only` runs the Python checks and explicitly
omits the crypto probes. The [genesis validation procedure](../docs/agents/genesis-validation.md)
describes revision binding and consumer handoff.

Each check is also available separately:

| Command | Exercised surface | Evidence boundary |
| --- | --- | --- |
| `python3 conformance/check-domain-model.py` | Canonical and hostile public-record fixtures | Envelope and inert-extension checks; no record-family or operational qualification. |
| `python3 conformance/test-domain-model.py` | Checker rejection and diagnostic behavior | Constructed valid and malformed envelopes, including optimized Python. |
| `./conformance/run-sq.sh` | The crypto-conformance profile and disposable `sq`/`sqv` operations | Observations for the selected tools and runtime; no project-wide support or adopter acceptance. |
| `python3 conformance/test-run-sq.py` | Crypto-probe source binding, portability, JSON, and cleanup | Constructed tool responses; no cryptographic capability claim. |
| `./conformance/run-signing-profile.sh` | Detached signatures and rejection diagnostics | The signing-profile fixture; no release-signing authority. |
| `python3 conformance/check-fido-custody.py` | Synthetic one-shot custody workers | Success and failure paths; no authenticator, plugin, native-library, or production qualification. |

The crypto probes generate disposable key material in temporary directories
and disable default key and certificate stores. The
[crypto-conformance profile](../profiles/crypto-conformance-v1.toml) and
[case manifest](../fixtures/cases-v1.toml) state their intended claims.
RFC 9980 support requires the specified positive operations and independent
verification; an algorithm name in help output does not establish support.

Bind recorded results to the tested source revision and selected runtime.
Documentation examples consume these fixtures and results. Genesis acceptance
also requires the independent checks and review recorded in the
[owning ticket](https://github.com/nisavid/sacrysty/issues/3).
