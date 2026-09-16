# Fixtures

This directory contains disposable, value-free canonical and hostile fixtures.

Fixtures cannot contain production identifiers, secrets, provider payloads,
real custody values, or captured private evidence.

- The `public-record-*.json` and `hostile-public-record-*.json` files exercise
  the public envelope and inert-extension boundary. Some hostile files are raw
  serialized inputs with duplicate members or non-JSON constants; they are
  intentionally invalid strict JSON rather than broken canonical fixtures.
- [`rfc9580/message.txt`](rfc9580/message.txt) and
  [`cases-v1.toml`](cases-v1.toml) supply the crypto-conformance probe. Reserved
  cases in the manifest do not establish protocol semantics or a passed check.
- [`signing/message.bin`](signing/message.bin) supplies the signing profile's
  exact-byte message. The runner generates and removes disposable key material.
- The FIDO custody runner creates synthetic worker programs at runtime. No
  device identifiers, FIDO credentials, or real worker artifacts are checked in.
