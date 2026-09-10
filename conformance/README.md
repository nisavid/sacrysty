# Conformance

Conformance assets will test accepted normative behavior independently from
ownership, qualification, support, and production acceptance.

Documentation examples should consume executable fixtures and conformance
results instead of copying expected behavior into prose. The public-record
boundary has a value-free executable check:
`python3 conformance/check-domain-model.py`. It accepts the canonical fixture
and rejects four hostile fixtures. This proves envelope and inert-extension
shape only; it does not qualify a runtime, adapter, provider, or deployment.
