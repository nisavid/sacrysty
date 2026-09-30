# FIDO worker interfaces: bounded research record

## Result

The frozen age v1.3.2 and unchanged Typage v0.3.1 sources expose a usable process seam for a one-shot worker, but the completed runtime evidence supports only a synthetic **recipient-v1 encryption** claim. It shows identity-driven plugin discovery, delivery of an encoded identity, failure of a secret request without a terminal, and, after age receives SIGINT, an EOF notification recorded by the fake plugin before cleanup; process-group absence was checked during cleanup. It does not exercise identity-v1, decryption, the Typage plugin, libfido2, an authenticator, PIN entry, biometric or other user verification, or a real worker.

This record is an implementation input, not a qualification, acceptance, advisory-clearance, release, containment, or production-suitability result. It does not settle publisher namespace, verification ownership, success meaning, or retained evidence.

The immutable publication inventory is [evidence-manifest.json](fido-worker-interfaces/evidence-manifest.json).

## Frozen inputs and candidate construction

The public source inputs are recorded in [source-inputs.json](fido-worker-interfaces/evidence/source-inputs.json) and the tag resolutions in [tag-and-update-identities.json](fido-worker-interfaces/evidence/tag-and-update-identities.json):

- age `v1.3.2` resolves to commit [`b74dce4cdbe35b5e5f66c06d9612b72f89028758`](https://github.com/FiloSottile/age/commit/b74dce4cdbe35b5e5f66c06d9612b72f89028758), tree `0e8fc91341a5f9e2ad142e75a879d6f9431e37e9`. The frozen archive SHA-256 is `413d6841e156bb1fd9757453637873d70f856a77419b638d6c158983f8591c5a`.
- Typage `v0.3.1` resolves to unchanged commit [`38b8b10cb22409de0eaa8a617a01f16dc2e3f9f4`](https://github.com/FiloSottile/typage/commit/38b8b10cb22409de0eaa8a617a01f16dc2e3f9f4), tree `32c74d41ad0d5140a0164775884932105a33b77f`. The frozen archive SHA-256 is `80ffb1a785b25ce854098b666efef983a5b55ad6febebdacf1c6ff72a3629fc8`.
- The Go FIDO wrapper input is `github.com/keys-pub/go-libfido2` commit [`2534349bd68588bf8aa87fafa6e8679de00d714e`](https://github.com/keys-pub/go-libfido2/commit/2534349bd68588bf8aa87fafa6e8679de00d714e), with frozen archive SHA-256 `02da33d853ab1f6b611e02b79d23ae7769dddddce19567d1fa7aa07d16c3eeea`.

Two disposable Linux/amd64 candidates changed only `go.mod` and `go.sum` to select `golang.org/x/crypto v0.56.0`:

- The age candidate and graph are in [age-xcrypto056-build.json](fido-worker-interfaces/evidence/age-xcrypto056-build.json), [age-xcrypto056-go.mod](fido-worker-interfaces/evidence/age-xcrypto056-go.mod), and [age-xcrypto056-go.sum](fido-worker-interfaces/evidence/age-xcrypto056-go.sum). Its artifact SHA-256 is `c5f1e2cb2e7380db9e4554410224d6ad5c91c1119bf78ddf9f8902f3736a7674`. Its recorded dependencies are `filippo.io/edwards25519 v1.2.0`, `filippo.io/hpke v0.4.0`, `filippo.io/nistec v0.0.4`, `golang.org/x/crypto v0.56.0`, `golang.org/x/sys v0.47.0`, and `golang.org/x/term v0.45.0`.
- The Typage plugin candidate and graph are in [plugin-xcrypto056-build.json](fido-worker-interfaces/evidence/plugin-xcrypto056-build.json), [plugin-xcrypto056-go.mod](fido-worker-interfaces/evidence/plugin-xcrypto056-go.mod), and [plugin-xcrypto056-go.sum](fido-worker-interfaces/evidence/plugin-xcrypto056-go.sum). Its artifact SHA-256 is `6bdd562b8adea968ab0026359cdf97901676ecc619024b54148f8e381d028733`. Its recorded dependencies include age `v1.3.2`, hpke `v0.4.0`, go-libfido2 `v1.5.4-0.20250104233141-2534349bd685`, pkg/errors `v0.9.1`, and the same x/crypto, x/sys, and x/term selections.

Both receipts identify `go1.26.6-X:nodwarf5`, `CGO_ENABLED=1`, and Linux/amd64. These are research builds, not selected distribution artifacts or qualified toolchains.

## Source-backed interface facts

age parses a plugin identity from an identity file and derives the lowercase plugin name from its Bech32 encoding. It then executes `age-plugin-<name> --age-plugin=recipient-v1` for identity-based encryption or `--age-plugin=identity-v1` for decryption. Resolution uses `PATH`; stock age has no CLI option that names an exact plugin executable. See [age plugin/client.go](https://github.com/FiloSottile/age/blob/b74dce4cdbe35b5e5f66c06d9612b72f89028758/plugin/client.go), [plugin/encode.go](https://github.com/FiloSottile/age/blob/b74dce4cdbe35b5e5f66c06d9612b72f89028758/plugin/encode.go), and [cmd/age/parse.go](https://github.com/FiloSottile/age/blob/b74dce4cdbe35b5e5f66c06d9612b72f89028758/cmd/age/parse.go).

For a worker whose envelope occupies stdin, the encoded Typage identity therefore needs a separate `-i PATH` input. `-j fido2prf` constructs a data-less plugin identity; Typage's parser expects its versioned credential data, so `-j` is not a substitute for the real encoded identity. The decryption-shaped CLI seam is `age -d -i IDENTITY_PATH`, with the envelope on stdin and plaintext on stdout. This shape is source-backed but was not executed by this probe.

Plugin interaction uses private child-process pipes. A `request-secret` stanza is handled by age's terminal UI, which opens `/dev/tty` on Unix and only falls back to stdin when stdin itself is a terminal. It does not read a secret from piped stdin or expose one through stdout. See [plugin/tui.go](https://github.com/FiloSottile/age/blob/b74dce4cdbe35b5e5f66c06d9612b72f89028758/plugin/tui.go) and [internal/term/term.go](https://github.com/FiloSottile/age/blob/b74dce4cdbe35b5e5f66c06d9612b72f89028758/internal/term/term.go).

Typage first probes for a matching credential, then requests an assertion with `UV: True`; it asks the age client for a PIN only if libfido2 returns `ErrPinRequired`. It returns the HMAC-secret value but no typed observation proving which verification path occurred. Absence of a PIN request is therefore not proof of built-in user verification. See [fido2prf.go](https://github.com/FiloSottile/typage/blob/38b8b10cb22409de0eaa8a617a01f16dc2e3f9f4/fido2prf/fido2prf.go) and the [plugin main](https://github.com/FiloSottile/typage/blob/38b8b10cb22409de0eaa8a617a01f16dc2e3f9f4/fido2prf/cmd/age-plugin-fido2prf/main.go).

The age client has no cancellation context or built-in timeout for this interaction. Closing a client connection closes its pipes, attempts to signal the plugin with `os.Interrupt`, and waits for it. The source does not bound that wait or establish hostile-descendant containment.

## Go advisory and scan interpretation

The exact-version OSV batch query preserved in [osv-query-results.json](fido-worker-interfaces/evidence/osv-query-results.json) found only [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), for `golang.org/x/crypto v0.56.0`. That advisory covers unmaintained `x/crypto/openpgp` packages and has no fixed-version event. The same query did not return [GO-2026-6354](https://pkg.go.dev/vuln/GO-2026-6354) or [GO-2026-6355](https://pkg.go.dev/vuln/GO-2026-6355), for which v0.56.0 is the recorded fixed selection. An empty exact-version result is limited to the queried tuple and database snapshot.

Pinned govulncheck v1.8.0 ran source scans at symbol level against the database last modified `2026-09-28T16:43:40Z`. Both the age and plugin streams contain a GO-2026-5932 finding whose entire trace is the module/version tuple, with no package, symbol, or caller chain: [age scan](fido-worker-interfaces/evidence/age-xcrypto056-scan-events.json) and [plugin scan](fido-worker-interfaces/evidence/plugin-xcrypto056-scan-events.json). Govulncheck's [result model](https://github.com/golang/vuln/blob/709015412431dd2b5b28a53c06c70bc02d49074c/internal/govulncheck/govulncheck.go) distinguishes module-, package-, and symbol-level traces. These retained findings establish that the selected module version is in each analyzed graph; they do not establish an imported OpenPGP package, a called vulnerable symbol, exploitability, or non-reachability. The zero scan exit statuses do not remove the findings or establish an accepted dependency closure.

The tool identity and raw receipts are [govulncheck-tool.json](fido-worker-interfaces/evidence/govulncheck-tool.json), [age-xcrypto056-govulncheck-receipt.json](fido-worker-interfaces/evidence/age-xcrypto056-govulncheck-receipt.json), and [plugin-xcrypto056-govulncheck-receipt.json](fido-worker-interfaces/evidence/plugin-xcrypto056-govulncheck-receipt.json). Go source scans do not cover the C toolchain, native libraries, runtime loader resolution, or another platform.

## Exact runtime observations

The retained probe is [probe.py](fido-worker-interfaces/evidence/probe.py), SHA-256 `6c7471d9ed5f0c5323647d90b48da537c436486fad00c81177350c828b59caa6`. Its [execution receipt](fido-worker-interfaces/evidence/interface-execution-receipt.json) records the expected age digest, a fresh session, closed outer stdin, piped outer stdout and stderr, exit 0 in 0.12132000299607171 seconds, empty outer streams, and only `observations.json` retained. The [observations](fido-worker-interfaces/evidence/observations.json) report `probe_status: complete`, `failure_class: none`, all premises true, and all cleanup fields true.

The fake plugin was the only `age-plugin-test` on a controlled `PATH`. For both branches, the probe's recorded premises establish `--age-plugin=recipient-v1`, delivery of the public synthetic encoded identity, one nonempty `wrap-file-key` request body carrying the key to be wrapped, the labels extension, and phase completion. This supports explicit identity-driven selection of that synthetic recipient-v1 executable. It does not support the identity-v1 or real-plugin seam.

In the secret-request branch:

- the fake plugin sent `request-secret`;
- age answered `fail`, exited nonzero, produced empty stdout, and did not place the synthetic prompt on stdout or stderr;
- stderr contained the warning that no terminal was available and the fake plugin's synthetic error;
- `error_ack` and `plugin_terminal_before_cleanup` are both recorded as `other`.

Those last two anomalous categories are retained as observed. This branch does not establish a successful ordinary protocol close. It does establish that stock age did not transport the requested secret through the bounded piped standard streams in this no-terminal session.

In the cancellation branch, SIGINT was sent to age only. age exited by SIGINT before cleanup; the fake plugin recorded an EOF notification before cleanup; captured stdout and stderr were empty. Final cleanup joined capture threads, removed fixtures, and confirmed that the owned process groups were absent after cleanup attempts. This is evidence for one fake-plugin EOF notification followed by successful final cleanup, not a general cancellation bound or descendant-containment property.

## Native library and profile limits

Passive ELF inspection of the unexecuted plugin candidate records interpreter `/lib64/ld-linux-x86-64.so.2` and `DT_NEEDED` entries for `libfido2.so.1` and `libc.so.6`: [fixed-plugin-linkage-metadata.json](fido-worker-interfaces/evidence/fixed-plugin-linkage-metadata.json). It does not identify the files the loader would select, their digests or transitive closure, or any loaded library. There is no corresponding macOS evidence. No real plugin or native FIDO stack ran.

At Sacrysty commit [`3cb793d2fee306df9b4960d5f9460b19d84eab85`](https://github.com/nisavid/sacrysty/commit/3cb793d2fee306df9b4960d5f9460b19d84eab85), [`profiles/README.md`](https://github.com/nisavid/sacrysty/blob/3cb793d2fee306df9b4960d5f9460b19d84eab85/profiles/README.md) reserves public profiles until their contracts settle. The published files cover OpenPGP conformance and signing; the frozen tree supplies no FIDO-specific profile artifact. Consequently, this packet supplies neither a FIDO profile digest nor an opaque factor alias.

## Audit commands

From `docs/research/`, the retained bytes can be checked without executing a candidate:

```sh
sha256sum -c <(jq -r '.files[] | "\(.sha256)  fido-worker-interfaces/\(.path)"' \
  fido-worker-interfaces/evidence-manifest.json)
sha256sum fido-worker-interfaces/evidence/probe.py \
  fido-worker-interfaces/evidence/observations.json \
  fido-worker-interfaces/evidence/interface-execution-receipt.json
python3 -m json.tool fido-worker-interfaces/evidence/observations.json >/dev/null
```

The material candidate and scan commands recorded in the receipts were:

```sh
# In the disposable age v1.3.2 source tree:
go mod edit -require=golang.org/x/crypto@v0.56.0
go mod tidy
go build -buildvcs=false -trimpath -o AGE_BINARY ./cmd/age
govulncheck -json -scan=symbol -db https://vuln.go.dev ./cmd/age

# In the disposable Typage v0.3.1 source tree:
go mod edit -require=golang.org/x/crypto@v0.56.0
go mod tidy
go build -buildvcs=false -trimpath -o PLUGIN_BINARY ./fido2prf/cmd/age-plugin-fido2prf
govulncheck -json -scan=symbol -db https://vuln.go.dev ./fido2prf/cmd/age-plugin-fido2prf

readelf -d PLUGIN_BINARY
readelf -l PLUGIN_BINARY
python3 fido-worker-interfaces/evidence/probe.py /absolute/path/to/AGE_BINARY \
  /absolute/path/to/FRESH_NONEXISTENT_OUTPUT_DIR
```

Exact artifact reproduction also depends on the recorded source archives, module files, custom Go toolchain, build environment, and scanner/database snapshot. The probe itself verifies the age digest before and after execution and rejects an existing output directory.

## Conclusions for the worker-contract decision

- Stock age provides the required stream allocation only at the source-interface level: an envelope can occupy stdin and result bytes stdout while an encoded plugin identity comes from a separate file.
- Plugin selection is by identity-derived name plus `PATH`, not an exact executable-path argument. Any claim about the selected plugin or its digest needs evidence from the component responsible for constructing and verifying that resolution.
- A PIN-required Typage path cannot use stock age's piped stdin/stdout seam in a fresh no-terminal session. The observed client response is `fail`; no successful PIN transport was observed.
- The existing sources cannot support a typed claim that authenticator UV occurred. A worker can observe a PIN request if it owns an interaction channel, but no PIN request alone does not prove another UV mode.
- SIGINT produced prompt age termination, and the fake plugin recorded EOF before cleanup in this fixture; final cleanup found the owned process groups absent. Those observations are insufficient for a general timeout, uncooperative-plugin, or hostile-descendant claim.
- The x/crypto v0.56.0 overlay built both candidates and removes the two cited fixed-version SSH records from the exact OSV response, but GO-2026-5932 remains as module-level scan evidence. Artifact admission and advisory policy remain outside this record.
- Effective native-library identity and a public FIDO profile remain unavailable. The recorded ELF names and unrelated public profiles cannot supply those bindings.

Before an implementation can truthfully populate closure- or profile-derived evidence, the pending contract choices must identify who verifies the worker, age binary, PATH-selected plugin, effective native libraries, and profile; what successful work means; and which observations may be retained. The missing discoverable inputs are the effective Linux and macOS native-library resolutions for the selected runtime and an immutable FIDO profile containing the fields the chosen evidence contract requires. This research does not choose those answers.
