# Signing and verification

Sacrysty's reusable signing profile accepts bytes and an explicit key or
certificate, then invokes Sequoia's `sq` signer and `sqv` verifier. The profile
is detached-signature based so callers can transport the payload and signature
separately. The executable evidence is `conformance/run-signing-profile.sh`.

A valid result means the verifier accepted the exact payload bytes with the
supplied certificate. Changed payload bytes, a changed signature, or a
certificate that does not match must produce a failure diagnostic. The helper
uses an isolated temporary home and deletes it on exit.

The current qualification is limited to RFC 9580 on the observed runtime. RFC
9980 / ML-DSA remains unsupported and capability-gated pending independent
qualification; this profile does not claim it.
