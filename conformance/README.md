# Conformance

Conformance assets will test accepted normative behavior independently from
ownership, qualification, support, and production acceptance.

Documentation examples should consume executable fixtures and conformance
results instead of copying expected behavior into prose. The synthetic
`check-fido-custody.py` runner exercises the one-shot adapter's success,
environment, timeout, crash, malformed-output, and digest-mismatch paths. It
does not qualify an authenticator, native library, or production artifact.
