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
under that external directory. A normal run removes them only after the nested
process and runner cleanup receipts are validated. Missing cleanup evidence
fails the run and retains the affected result directory for inspection.

Each check is also available separately:

| Command | Exercised surface | Evidence boundary |
| --- | --- | --- |
| `python3 conformance/check-domain-model.py` | Canonical and hostile serialized public-record fixtures | `envelope_admissible` checks strict JSON, schema-derived envelope structure, and inert extensions; family bodies remain unvalidated. |
| `python3 conformance/test-domain-model.py` | Checker rejection and diagnostic behavior | Constructed valid and malformed envelopes, including optimized Python. |
| `python3 conformance/test-strict-json.py` | Shared strict decoder | Duplicate members, non-finite numbers, UTF-8, syntax, exact finite decimals, and preserved JSON string content. |
| `./conformance/run-sq.sh` | The crypto-conformance profile and disposable `sq`/`sqv` operations | Observations for the selected tools and runtime; no project-wide support or adopter acceptance. |
| `python3 conformance/test-run-sq.py` | Crypto-probe source binding, portability, JSON, and cleanup | Constructed tool responses; no cryptographic capability claim. |
| `./conformance/run-signing-profile.sh` | Detached signatures and rejection diagnostics | The signing-profile fixture; no release-signing authority. |
| `python3 conformance/test-run-signing-profile.py` | Signing-runner source, store, JSON, verification, rejection, and cleanup controls | Constructed tool responses; no cryptographic capability claim. |
| `python3 conformance/test-sq-evidence-process.py` | Process bounds shared by the probe runners and aggregate | Constructed timeout, output, file-growth, exit-status, interruption, explicit environment, nested receipt, cleanup-denial, and ordinary same-process-group cases. |
| `python3 conformance/check-fido-custody.py` | Synthetic one-shot custody workers | Success and failure paths; no authenticator, plugin, native-library, or production qualification. |
| `python3 conformance/check-source-inventory.py` | Producer commits and every inventoried source path | Complete Git object history, ancestry, tree membership, modes, blobs, byte lengths, and hashes; no hosted availability or review claim. |
| `python3 conformance/test-source-inventory.py` | Source-inventory identity and history failure behavior | Checked-in inventory plus constructed identity, path-set, and shallow-history failures. |
| `python3 conformance/check-probe-result.py <crypto-conformance\|signing-profile> <result.json> <revision>` | Captured crypto-probe JSON | Required result identity, source binding, profile result, diagnostics, and mandatory check values; no qualification beyond the admitted observation. |
| `python3 conformance/test-probe-result.py` | Crypto-probe result admission behavior | Constructed complete, malformed, mismatched, abnormal-status, and false-check results; only verifier statuses 1 through 123 are rejection evidence. |
| `python3 conformance/test-check-conformance.py` | Aggregate runner and admission order | Both real runner interfaces with value-free fake tools, plus source-inspection failures, result admission, startup and operational cancellation, delayed cleanup, missing receipts, and ordinary same-process-group cleanup. |

The aggregate's internal synthetic-check sequence is defined once in
`synthetic-checks.txt`. Every listed check runs in normal and optimized Python.

The crypto probes generate disposable key material in temporary directories
and disable default key and certificate stores. Every selected `sq` or `sqv`
process has a 120-second limit, a 1 MiB limit on each captured stream, and a
16 MiB per-regular-file limit. The aggregate gives each complete probe runner
900 seconds and limits its stdout result and stderr to 1 MiB each. These fixed
internal limits have no configuration surface.

The process helper builds an explicit environment for every selected process.
It passes only a selected `PATH`, isolated temporary, home, XDG, GnuPG, and Git
settings, deterministic locale settings, and, for probe runners, the selected
`SQ` and `SQV` paths and a private cleanup-receipt path. Other caller variables
do not cross the boundary.

Each helper owns its `Popen` session leader until reaping. It sends nonzero
group signals only during that ownership, then requires definitive signal-zero
absence before writing a same-run process receipt. On catchable aggregate
cancellation, the runner waits for its active tool helper's receipt, deletes
its disposable material, and writes a runner receipt. The outer helper has a
separate cooperative window, cleans and reaps the runner group, validates that
runner receipt, and only then lets the aggregate remove its result directory.
Denial, live descendants, missing evidence, and bounded absence failures remain
failures. Timeout, output overflow, and file-growth failure likewise cannot
become unsupported or positive observations.

These process groups contain ordinary POSIX workers and descendants; they are
not a malicious-code sandbox. The procedure does not claim recovery from
uncatchable parent death, deliberate session escape, or persistent kernel
denial.

The [crypto-conformance profile](../profiles/crypto-conformance-v1.toml) and
[case manifest](../fixtures/cases-v1.toml) state their intended claims.
RFC 9980 support requires the specified positive operations and independent
verification; an algorithm name in help output does not establish support. An
explicit capability rejection is `unsupported`; unknown generation failures
are `probe-failed`, and failures after generation are `round-trip-failed`.
Only the first is an admitted nonpositive observation for a passing run.

The domain checker implements only the JSON Schema constructs present in the
checked-in closed-envelope schema. Its `envelope_admissible` entrypoint checks
that envelope and inert extensions but does not validate a record-family body.
It fails closed if the envelope schema introduces an unsupported construct; it
is not a general JSON Schema implementation.

The aggregate captures each real probe's bounded stdout and stderr, accepts the
runner's zero exit status, then parses stdout as strict JSON and checks its
source revision and mandatory results before announcing admission. Malformed,
oversized, missing, wrong-schema, failed, indeterminate, or false-check evidence
cannot pass the aggregate.

The result records contain the tools' self-reported version text. Bind an exact
executable, platform, and dependency identity in a separate validation or
qualification receipt; the result schema alone does not establish those
identities. Bind every recorded result to the tested source revision, fixture
bytes, and selected runtime.
Documentation examples consume these fixtures and results. Genesis acceptance
also requires the independent checks and review recorded in the
[owning ticket](https://github.com/nisavid/sacrysty/issues/3).
