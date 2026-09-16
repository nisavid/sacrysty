# FIDO custody qualification preparation

## Result

The smallest reproducible public increment is a candidate-bound CI-only source-and-simulated qualification slice for the frozen Python adapter on Linux and GitHub-hosted macOS. It can establish exact source identity and synthetic one-shot adapter behavior now, in parallel with genesis correction, provided its evidence is marked provisional and is reconciled and rerun if an input changes. It cannot qualify the real `age-plugin-fido2prf` path because no exact JSON worker, plugin binary, `age` binary, native-library closure, or hardware fixture has been supplied.

This completes preparation, not [Qualify the FIDO custody adapter](https://github.com/nisavid/sacrysty/issues/16). Linux hardware qualification remains a separately authorized, operator-present increment. macOS hardware, provider, keychain, personal-host, and production behavior remains explicitly unqualified and nonblocking under the accepted [platform-assurance boundary](https://github.com/nisavid/dotfiles/issues/258#platform-assurance).

## Accepted claim and frozen source

The accepted [preparation claim](https://github.com/nisavid/sacrysty/issues/16#issuecomment-5691997312) permits public-input assessment of exact artifact and runtime inputs, reproducible Linux and macOS CI checks, unavailable observations, and one bounded next increment. It permits no source edit, hardware or provider operation, custody actuation, or acceptance claim. The accepted [map](https://github.com/nisavid/sacrysty/issues/1#orchestration-and-handoffs) allows qualification preparation and macOS CI work against reconciled frozen inputs while genesis work continues.

The candidate revision is [`5a5a608b0123854a066550a89a53e830a124befa`](https://github.com/nisavid/sacrysty/commit/5a5a608b0123854a066550a89a53e830a124befa). Read-only verification confirmed these source inputs:

- `adapters/fido_custody.py`: SHA-256 `c8b3dcb5c1ce395393d10f4621cd4e478e1d08202485f41848943163a96ba690`
- `adapters/fido-custody-v1.md`: SHA-256 `9d037a6ef9b84eaddf103cd05c9fc5bc336a5d393bcd0dc57fb01387c51a3c4d`
- `conformance/check-fido-custody.py`: SHA-256 `b2b7191137b9e5e322ffb52ea7dd55d6ef96179e28e703bfb977199a9910189c`
- `conformance/test_support.py`: SHA-256 `45ff4ac487816dbe76652bf81f38ebd3caae89b1fd59ea16a3a094e8649ab067`

The checker imports `external_temporary_directory` from `conformance/test_support.py`; that helper selects and validates the external temporary root and creates the disposable directory. It is therefore an executable synthetic-check input, not incidental support code.

Genesis remains under its separate owner's correction and review. This revision and these digests identify a candidate, not accepted final genesis or qualification evidence. A change to any listed input requires ownership reconciliation and a fresh pass. Final-genesis acceptance is a later gate only for claims or consumers that require the accepted revision.

## Supported observations

The adapter is standard-library-only Python and implements one `unwrap` operation around a caller-supplied worker command. It starts the worker in a new session with a scrubbed environment and bounds input, output, and time. On each post-spawn completion path it requests `SIGKILL` for the worker process group, boundedly attempts to reap the leader, and fails closed when group cleanup reports an error other than an already-absent group. This is not a process sandbox and does not guarantee cleanup of descendants that escape the session or cannot be killed.

The adapter rejects malformed, partial, mismatched, cancelled, timed-out, cleanup-failed, and non-zero results. A successful JSON result must echo the requested profile, plugin, and `age` digests, provide plaintext matching its reported digest, and report `uv_mode` as `built-in` or `pin` ([frozen contract](https://github.com/nisavid/sacrysty/blob/5a5a608b0123854a066550a89a53e830a124befa/adapters/fido-custody-v1.md)).

The synthetic checker exercises successful built-in and PIN-labelled responses, full-duplex and pipe-capacity-exceeding input, worker crash, early input close, partial or duplicate JSON, digest mismatch, timeout, output limits, rejected UV values, debug-environment rejection, interruption, descendant cleanup, and constructed cleanup denial. It generates synthetic workers and proves no plugin, native library, authenticator, PIN, biometric, provider, or production behavior ([conformance inventory](https://github.com/nisavid/sacrysty/blob/5a5a608b0123854a066550a89a53e830a124befa/conformance/README.md)).

The preparation environment could not run the checker because it could not create the required disposable temporary directory. No test pass is claimed. The proposed GitHub-hosted jobs must supply writable disposable storage and produce the actual evidence.

## Artifact and runtime inventory

| Layer | Identity available now | Missing before the corresponding claim |
| --- | --- | --- |
| Sacrysty synthetic source | Candidate commit and four SHA-256 values above | Candidate-bound CI results; accepted-final-genesis status only for later claims that require it |
| Python runtime | Standard-library-only adapter source | Exact Python version, implementation, OS, and architecture from each CI job |
| JSON worker | Protocol shape specified by the adapter | Executable source and revision, build procedure, artifact digest, and accepted provenance binding |
| `age-plugin-fido2prf` source | Typage v0.3.1 is a factual candidate, not an accepted selection | Accepted immutable revision and per-platform binary digests |
| Plugin Go dependencies | The [v0.3.1 module manifest](https://github.com/FiloSottile/typage/blob/v0.3.1/go.mod) names Go `1.23.5`, `filippo.io/age v1.2.1-0.20240926110859-2214a556f604`, `go-libfido2 v1.5.4-0.20250104233141-2534349bd685`, `x/crypto v0.24.0`, `x/sys v0.30.0`, and `x/term v0.29.0` | Accepted plugin revision, exact Go distribution and digest, module verification, and build flags |
| `age` runtime | The request reserves an `age_digest` field | Exact CLI version, source/build provenance, artifact digest, and compatibility result |
| Native FIDO closure | libfido2 documents libcbor, OpenSSL 3+, zlib, and Linux libudev dependencies in its [README at commit `626a4d815b32ae57fc36321a358501ad7b5e79c9`](https://github.com/Yubico/libfido2/blob/626a4d815b32ae57fc36321a358501ad7b5e79c9/README.adoc) | Exact package/build versions, artifact digests, linkage, loader paths, and per-platform acquisition evidence |
| CI platforms | Accepted labels are `ubuntu-24.04` x86_64 and `macos-15` arm64 | Resolved runner-image versions and runtime facts from each job |
| Hardware and fixture | Target class is YubiKey Bio; source contains only synthetic workers | Exact model, firmware, transport, disposable credential/envelope identity, fixture digest, and operator-present authorization |

The captured Typage v0.3.1 module manifest has SHA-256 `4157aa19c18f41ac7c95ec7808e1953aa22cc2f9bdaf2d5b188b42622d873b29`; its FIDO2 PRF source has SHA-256 `776b865932881364cc284aa3ceed53ff0471e34217bb315195928475acfdb4b9`. The implementation first attempts built-in user verification and requests a PIN only when libfido2 reports that one is required, with HMAC-secret and user verification enabled ([v0.3.1 implementation](https://github.com/FiloSottile/typage/blob/v0.3.1/fido2prf/fido2prf.go)). This supports the meaning of the two UV paths but does not establish either path on a YubiKey Bio.

Typage's installation instructions use `@latest`, as shown by its [README at commit `38b8b10cb22409de0eaa8a617a01f16dc2e3f9f4`](https://github.com/FiloSottile/typage/blob/38b8b10cb22409de0eaa8a617a01f16dc2e3f9f4/README.md); that moving selector cannot identify a qualification artifact. A future evidence record must retain these captured source identities alongside any selected source revision and built artifact digests.

## Implementation gate for real-plugin qualification

The upstream `age-plugin-fido2prf` executable speaks the age plugin protocol. The Sacrysty adapter launches a different-shaped worker: it sends an age envelope on standard input and requires one exact JSON object containing plaintext and evidence on standard output. The frozen source provides no executable bridging those protocols.

`CustodyRequest` and `CustodyEvidence` record profile, plugin, and `age` digests, but no separate worker identity. Real-path qualification therefore cannot establish which bridge bytes processed the envelope unless an existing digest is explicitly defined to cover them.

The unresolved implementation question is:

> Which immutable executable implements the adapter's JSON worker protocol, how does it compose the selected `age` and `age-plugin-fido2prf` artifacts, and where is that executable's identity bound in the accepted evidence?

[Build the one-shot FIDO custody adapter](https://github.com/nisavid/sacrysty/issues/15) owns the pinned adapter contract, native-dependency boundary, and direct-tool/helper operation. The current genesis owner retains shared-source and conformance correction under [Establish Sacrysty's immutable public genesis](https://github.com/nisavid/sacrysty/issues/3). Qualification must report, not decide, a new digest meaning, worker protocol, custody contract, or source correction.

This is a future implementation gate for real-plugin qualification, not a defect or operator blocker in this preparation report and not a blocker for the candidate-bound synthetic CI slice.

## Reproducible check boundary

| Check | Linux CI | GitHub-hosted macOS CI | Claim |
| --- | --- | --- | --- |
| Verify candidate revision, four source digests, and clean checkout | Required | Required | Exact synthetic source input |
| Record runner image, OS, architecture, and Python identity | Required | Required | Exact observed runtime |
| Run `python3 -B conformance/check-fido-custody.py` directly | Required | Required | Synthetic adapter behavior |
| Run `python3 -B -O conformance/check-fido-custody.py` directly | Required | Required | Same behavior with assertions optimized out |
| Build a selected worker/plugin and record SHA-256, `file`, `go version -m`, module verification, and native linkage | Later, after artifact selection | Later, after artifact selection | Build and dependency identity only |
| Invoke a physical authenticator | Separately authorized operator-present Linux run only | Not available or required | Exact Linux hardware observation only |
| Exercise Proton Pass, a personal keychain, personal-host installation, production custody, or release signing | Not authorized | Not authorized | No claim |

The direct synthetic commands avoid the unsettled aggregate/tool-supervision path. Each job must use the runner's external disposable temporary directory, disable bytecode writes, retain value-free logs or results, and confirm a clean checkout after the checks. GitHub documents `ubuntu-24.04` as x64 and `macos-15` as arm64 for standard public-repository runners, but labels move; each run must capture its resolved image identity ([GitHub-hosted runners reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)).

## Linux hardware and macOS limits

A later Linux hardware increment requires a new operator-present handoff and separate authorization for disposable hardware work. Its evidence must bind the accepted adapter and worker revisions, plugin and `age` artifact digests, native closure, exact YubiKey Bio model and firmware, transport, profile revision, and value-free credential/envelope fixture digest. It must record successful built-in verification, the PIN path where the device exposes it, absent or mismatched device behavior, cancellation, timeout, failure cleanup, and observed support, recovery, and retirement limits. Synthetic results cannot replace these observations.

On macOS, required assurance ends at GitHub-hosted CI builds, dependencies, runner-accessible interoperability, value-free fixtures, simulated adapter checks, and public-artifact verification. Physical YubiKey interaction, live Proton Pass, desktop-keychain behavior, persistent installation, and personal-Mac or production integration remain untested and unqualified. These limits are nonblocking and never become passing claims.

## Support, recovery, retirement, and invalidation

For the frozen synthetic surface, support is one local unwrap through the exact worker JSON response. Every malformed, mismatched, unavailable, oversized, timed-out, cancelled, reported cleanup-failed, or non-zero path fails closed. The contract permits no weaker fallback or automatic retry; recovery requires a separately initiated operation after the cause is corrected. Process-group termination remains best-effort under the operating-system limits stated above.

Candidate-bound synthetic evidence is invalidated by changes to the adapter, contract, checker, `conformance/test_support.py`, workflow, Python runtime, platform, architecture, or relevant runner image. Build evidence is invalidated by changes to source, toolchain, flags, module graph, artifact bytes, platform, architecture, or any native dependency. Hardware evidence is invalidated by changes to the adapter or worker, plugin, `age`, native closure, device model or firmware, transport, credential fixture, profile, or observed UV path.

No evidence here establishes release intent, independent assertion verification, counter enforcement, production authority, personal custody, adopter acceptance, or accepted genesis.

## Recommended next increment

Add the disjoint CI-only source-and-simulated qualification slice under `qualification/fido-custody/` and `.github/workflows/fido-custody-qualification.yml` against candidate revision `5a5a608b0123854a066550a89a53e830a124befa`. It may run now under the reconciled ownership boundary. Mark every result candidate-bound and provisional; if any frozen input or ownership boundary changes, reconcile and rerun before relying on it.

Acceptance evidence for this increment is:

1. the candidate commit and all four expected source digests verified before execution;
2. direct normal and optimized synthetic checker passes on `ubuntu-24.04` x86_64 and `macos-15` arm64;
3. retained runner image, OS, architecture, Python, workflow, source, and primary-source receipt identities;
4. clean-checkout confirmation before and after the checks;
5. an evidence record limited to exercised synthetic behavior, with worker, plugin, `age`, native-library, hardware, provider, personal-host, and production results marked unqualified; and
6. a clean latest review pass over the same candidate-bound evidence and workflow revision.

Do not install or select the real plugin in this increment, and do not run the repository aggregate. The implementation owner must answer the worker-identity question and supply the exact executable closure before device-free real-build qualification or the separately authorized Linux hardware increment. Final-genesis acceptance and a same-revision rerun become gates only when a later claim or consumer depends on the accepted genesis.