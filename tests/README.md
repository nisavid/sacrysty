# Tests

Repository-policy checks live under `scripts/`. Python conformance regressions
live beside their checkers and runners under `conformance/`; they exercise the
public envelope, synthetic adapter, provenance, and disposable probe boundaries.
The Rust library's empty Cargo test harness proves buildability only, and no Rust
integration or behavioral tests live in `tests/` yet.

A test describes only the behavior and externally oriented contract it proves.
New tests preserve ownership by contract, core, adapter, conformance, and
qualification surface.
