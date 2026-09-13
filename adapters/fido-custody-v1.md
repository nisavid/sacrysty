# One-shot FIDO custody adapter v1

This is the public, value-free adapter contract owned by Sacrysty #15. It
orchestrates one invocation of an exactly pinned `age-plugin-fido2prf` artifact;
it does not implement FIDO, age, or cryptography.

The caller supplies an encrypted age envelope and the immutable profile,
plugin, and age artifact digests, after resolving and verifying that dependency
closure. The adapter starts a fresh worker with a
minimal scrubbed environment, sends the envelope through a pipe, and reads one
bounded response. The worker exits before the result is returned. Plaintext,
PINs, PRF output, credential handles, and file keys never appear in argv,
environment, logs, receipts, or durable temporary files. `AGEDEBUG=plugin` and
other protocol debugging are rejected.

The response is accepted only when it is one complete JSON object with
`status`, plaintext bytes, a matching SHA-256 digest, the three input digests,
an observed UV mode (`built-in` or `pin`), and a timing class. Any malformed,
partial, mismatched, cancelled, timed-out, or non-zero worker result fails
closed. There is no weaker fallback or automatic retry.

The adapter makes a narrow claim: a qualified local envelope unwrap completed
under the recorded artifact and profile inputs. It does not claim that FIDO
approved release intent, that an assertion was independently verified, or that
a counter was enforced. Those properties remain deferred to the isolated
signer profile. RFC 9980/ML-DSA remains capability-gated and unqualified under
the accepted #12 evidence.

The checked-in Python reference implementation is intentionally dependency-free
and is exercised only with synthetic workers. Run
`python3 conformance/check-fido-custody.py` after checkout; it installs nothing
and uses no credentials. A caller may wrap the adapter in a helper, but the
helper must pass the same value-free request fields and retain the returned
evidence. Roll back by removing the adapter files and any caller wiring; no
provider or custody state is changed. Real authenticator installation, device
qualification, native-library binding, and adopter custody belong to the
separate qualification and dotfiles lanes.
