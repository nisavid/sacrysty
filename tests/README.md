# Tests

Repository-policy checks live under `scripts/`. The Rust library's empty Cargo
test harness proves buildability only. Add behavioral tests as public interfaces
are defined, preserving ownership by contract, core, adapter, conformance, and
qualification surface.

A test describes only the behavior and externally oriented contract it proves.
No implementation test suite exists yet.
