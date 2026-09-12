# Sacrysty

Sacrysty is the planned public, independently versioned home of a reusable
cryptographic-operations product. Its public-facing operator is Sacrystan, and
its prospective command is `sacryd`, pronounced “sacred.”

> [!IMPORTANT]
> This repository contains a non-operational Rust library build skeleton and a
> value-free Python reference adapter. It has no Rust executable or public API,
> cryptographic-operations implementation,
> qualified runtime, protocol, schema, production authority, custody binding,
> key, credential, provider binding, trusted deployment, or release.

## Current names and open choices

Sacrysty names the project and institution. Sacrystan names the public-facing
operator. The
[substrate decision](https://github.com/nisavid/sacrysty/issues/2#issuecomment-5568558765)
selects one root Rust package/library named `sacrysty`. The prospective `sacryd`
command will be added only when a concrete helper needs it. Documentation can
be useful before a CLI exists.

Background workers and published bodies of practice remain unnamed. The
command grammar, schemas, authority semantics, custody model, and protocol
implementation remain open for their owning Wayfinder work.

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

- [`contracts/`](contracts/) is reserved for normative contracts and schemas.
- [`src/`](src/) contains the empty library for the single primary distribution.
- [`adapters/`](adapters/) holds interfaces and maintained reference adapters
  only after a real seam is established.
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

## Project status

Follow the [implementation map](https://github.com/nisavid/sacrysty/issues/1)
for the current decisions, prerequisites, and route to the first public release.

Every public interface is experimental before 1.0. Releases are need-driven.
The project currently promises no release cadence, compatibility or deprecation
window, backports, remediation deadline, platform-support term, or post-1.0
stability. See [GOVERNANCE.md](GOVERNANCE.md),
[CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).
