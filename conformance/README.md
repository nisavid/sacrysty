# Conformance

This directory owns the public, value-free executable evidence for the crypto
tool boundary. The profile and result schemas keep protocol conformance,
runtime qualification, support status, and adopter acceptance separate.

Run the disposable `sq`/`sqv` probe from the repository root:

```sh
./conformance/run-sq.sh
```

The probe uses a temporary home-free directory, generates an RFC 9580 fixture
key at a fixed reference time, signs and verifies the checked-in message,
rejects a byte-tampered message, and probes RFC 9980 capability. Its JSON
output binds the source revision, fixed reference time, tool versions, exact fixture byte lengths,
SHA-256 and SHA-512 digests, and each result. SHA-512 is included for the
protocol-facing digest binding; SHA-256 remains a convenient file-integrity
cross-check. It never reads a default key store or writes outside its temporary
directory.

The probe qualifies RFC 9580 for the observed tool/runtime combination when
the positive round trip passes; this is an observation, not a project-wide
support commitment. RFC 9980 is capability-gated: a runtime is unqualified
until backend-specific generation and an independent round trip pass. Help text
or an algorithm name alone is not evidence of PQ support.

The selected profile and machine-readable evidence contract are in
[`profiles/crypto-conformance-v1.toml`](../profiles/crypto-conformance-v1.toml).
The checked-in message is a disposable public fixture; generated key material,
signatures, and revocation certificates are removed on exit.
