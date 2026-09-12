# Reusable signing and verification profile v1

This profile defines value-free detached OpenPGP signing and verification using
standard Sequoia tools. It is the reusable successor to the generic signing
portion of dotfiles #161.

Inputs are a byte sequence, an explicitly selected signing key, and a public
certificate supplied to verification. Outputs are a detached OpenPGP signature
and a verification result containing success or a diagnostic failure. A caller
must treat verification as failed unless `sqv` exits successfully against the
intended bytes and certificate.

The profile supports the RFC 9580 OpenPGP profile qualified by Sacrysty #12 on
the observed runtime. RFC 9980 / ML-DSA is capability-gated and is not a
supported algorithm in this profile; advertised tool help is insufficient.

Canonical invocation:

```sh
sq --cli-version 1.4.0 --home none --key-store none --cert-store none --time 20260910 sign --binary --signature-file message.sig --signer-file signing-key.pgp message.bin
sqv --time 20260910 --keyring=signer-cert.pgp --signature-file message.sig message.bin
```

The helper must use temporary value-free fixtures, never default personal key
stores, and must remove secret material after the run. Diagnostics should retain
command, exit status, and stderr while excluding secret bytes.
