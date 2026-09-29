# Sacrysty

Sacrysty is the public, independently versioned home of a reusable
cryptographic-operations product. Its public-facing operator is Sacrystan, and
its prospective command is `sacryd`, pronounced “sacred.”

> [!IMPORTANT]
> This repository contains a non-operational Rust library, public-record
> envelope source, disposable `sq`/`sqv` conformance probes, and a synthetic
> Python custody adapter. Genesis integration is in progress. It has no Rust
> executable or public API, accepted genesis closure, qualified custody
> runtime, production authority, private deployment, or release.

## Current names and open choices

Sacrysty names the project and institution. Sacrystan names the public-facing
operator. The
[substrate decision](https://github.com/nisavid/sacrysty/issues/2#issuecomment-5568558765)
selects one root Rust package/library named `sacrysty`. The prospective `sacryd`
command will be added only when a concrete helper needs it. Documentation can
be useful before a CLI exists.

Background workers and published bodies of practice remain unnamed. The
public-record envelope schema is settled, but record-family body schemas are
not supplied. Command grammar, authority semantics, custody behavior, and
protocol implementation remain with their owning Wayfinder work. The
[public domain model](contracts/domain-model.md) defines the envelope and inert
extension boundary; it does not supply those operational contracts.

## Ownership boundary

This repository owns public reusable material:

- normative contracts and schemas after their owning decisions settle them;
- one primary implementation and its public interfaces;
- adapter interfaces and justified maintained reference adapters;
- public, non-secret policy profiles;
- disposable fixtures, conformance assets, and qualification records;
- operator, integrator, contributor, and incident documentation; and
- project governance, compatibility declarations, and release metadata.

Each system user owns its deployment: exact profile selection and locks,
private bindings, hosts, accounts, provider resources, opaque secret
references, protected state, ceremonies, production mutations, and acceptance
evidence. Ivan's dotfiles remain the first adopter and the owner of those
personal surfaces.

## Repository layout

- [`contracts/`](contracts/) contains the public-record envelope and its
  domain-model contract.
- [`src/`](src/) contains the empty library for the single primary distribution.
- [`adapters/`](adapters/) holds interfaces and maintained reference adapters
  only after a real seam is established.
- [`sacrysty_runtime/`](sacrysty_runtime/) contains private Python lifecycle and
  strict-decoding support shared by existing adapters and conformance checks;
  it is not a public product API.
- [`profiles/`](profiles/) holds public non-secret policy profiles.
- [`fixtures/`](fixtures/) and [`conformance/`](conformance/) hold disposable
  examples and executable contract evidence.
- [`qualification/`](qualification/) holds qualification formats, records, and
  prospective status records.
- [`release/`](release/) is reserved for versioned release metadata.
- [`docs/`](docs/) holds architecture, decisions, provenance, and future
  operator documentation.

## Build and validate the skeleton

Install Rust 1.98.1 with Rustup and a native C toolchain. The initial build
targets are Linux x86_64 GNU and macOS Apple Silicon. From the repository root:

```sh
cargo build --frozen
cargo test --frozen
./scripts/check-repository.sh
```

`rust-toolchain.toml` pins the compiler; `Cargo.toml` declares Rust edition 2024
and the minimum compiler. `Cargo.lock` and `.cargo/config.toml` keep Cargo
resolution locked and offline. Toolchain installation requires network access;
the subsequent Cargo commands do not. There are no dependencies to vendor.
When dependencies are introduced, commit their lockfile entries and vendored
sources with the corresponding Cargo source configuration.

The [native build workflow](.github/workflows/rust-build.yml) checks both target
architectures and records the actual compiler, OS, and native toolchain versions.
The empty test harness runs zero behavioral tests. These checks prove buildability
and repository policy, not minimum-OS support, a protocol, release, custody path,
authority, or deployment.

The [conformance entrypoint](conformance/README.md) lists the public-record,
crypto-tool, signing-profile, and synthetic custody checks. Their evidence has
separate scopes; passing a fixture does not qualify hardware or an adopter.
The [genesis input receipt](docs/provenance/genesis-inputs.md) identifies the
source decisions and immutable revisions assembled for integration.
The [operations boundaries](docs/explanation/operations-boundaries.md) explain
the accepted threat and custody constraints and the separate Sacrysty/Codiquary
ownership boundary.

## Project status

Follow the [implementation map](https://github.com/nisavid/sacrysty/issues/1)
for the current decisions, prerequisites, and route to the first public release.

Every public interface is experimental before 1.0. Releases are need-driven.
The project currently promises no release cadence, compatibility or deprecation
window, backports, remediation deadline, platform-support term, or post-1.0
stability. See [GOVERNANCE.md](GOVERNANCE.md),
[CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).
