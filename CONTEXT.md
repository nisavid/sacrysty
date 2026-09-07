# Sacrysty context

This file records only accepted terms and their source-level crosswalk. It does
not define cryptographic, authority, custody, or protocol semantics.

## Accepted names

| Surface | Accepted name | Technical crosswalk |
| --- | --- | --- |
| Project and institution | Sacrysty | The public reusable cryptographic-operations product in `nisavid/sacrysty`. |
| Public-facing operator | Sacrystan | The human-facing operator surface; its exact behavior and implementation remain unsettled. |
| Prospective command | `sacryd` | Pronounced “sacred.” A future thin entrypoint for a concrete helper, not a prerequisite for documentation. |

Background or internal workers and published bodies of practice remain unnamed.
Assign names only if and when those concepts need them.

## Ownership crosswalk

| Surface | Owner |
| --- | --- |
| Public contracts, implementation, adapter interfaces and maintained reference adapters, public profiles, fixtures, conformance, qualification records, documentation, governance, compatibility declarations, and releases | Sacrysty |
| Exact adopter locks, private or encrypted deployment bindings, real hosts and accounts, provider resources, opaque secret references, protected bootstrap state, ceremonies, production mutations, and acceptance evidence | The system user; Ivan's dotfiles are the first adopter |

The earlier planning labels `crypto-ops` and Cryptosacristy refer to the same
project lane in historical evidence. Sacrysty is the current project name;
Sacrystan and `sacryd` replace the earlier selected operator and command names.
Historical evidence remains unchanged.

## Current stage

The repository contains governance and a non-operational Rust library build
skeleton. The
[substrate decision](https://github.com/nisavid/sacrysty/issues/2#issuecomment-5568558765)
selects one root Cargo package/library named `sacrysty`; `src/lib.rs` is empty
apart from its documentation. There is no executable or public API. Add `sacryd`
only when a concrete helper needs it; documentation does not depend on a CLI.

Command grammar, schemas, authority semantics, custody model, and protocol
implementation remain unsettled. No cryptographic-operations implementation,
released package, private binding, or production state exists here.
