# Sacrysty

Sacrysty is the planned public, independently versioned home of a reusable
cryptographic-operations product. Its public-facing operator is Sacrystan, and
its prospective command is `sacryd`, pronounced “sacred.”

> [!IMPORTANT]
> This repository is in its language-neutral genesis stage. It has no
> implementation, package, supported runtime, protocol, schema, production
> authority, custody binding, key, credential, provider binding, trusted
> deployment, or release.

## Current names and open choices

Sacrysty names the project and institution. Sacrystan names the public-facing
operator. The `sacryd` command name does not select a language, package or
library coordinate, command grammar, source layout, or requirement to build a
CLI before one is useful.

Background workers and published bodies of practice remain unnamed. The
implementation substrate, package and library coordinates, command grammar,
schemas, authority semantics, custody model, and protocol implementation remain
open for their owning Wayfinder work.

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
- [`src/`](src/) is reserved for the single primary distribution after its
  substrate and coordinates are selected.
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

## Validate the scaffold

Run the language-neutral repository checks:

```sh
./scripts/check-repository.sh
```

These checks validate repository policy only. They do not prove a protocol,
implementation, release, custody path, authority, or deployment.

## Project status

Follow the [implementation map](https://github.com/nisavid/sacrysty/issues/1)
for the current decisions, prerequisites, and route to the first public release.

Every public interface is experimental before 1.0. Releases are need-driven.
The project currently promises no release cadence, compatibility or deprecation
window, backports, remediation deadline, platform-support term, or post-1.0
stability. See [GOVERNANCE.md](GOVERNANCE.md),
[CONTRIBUTING.md](CONTRIBUTING.md), and [SECURITY.md](SECURITY.md).
