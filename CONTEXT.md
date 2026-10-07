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
| Generic cryptographic-operation contracts and implementation, adapter interfaces and maintained reference adapters, public profiles, value-free fixtures, cryptographic conformance, qualification records, documentation, governance, compatibility declarations, and Sacrysty releases | Sacrysty |
| Release-authority, publication, verifier, and protocol contracts, plus executable release conformance | Codiquary |
| Exact adopter locks, private or encrypted deployment bindings, real hosts and accounts, provider resources, opaque secret references, protected bootstrap state, ceremonies, production mutations, and acceptance evidence | The system user; Ivan's dotfiles are the first adopter |

The earlier planning labels `crypto-ops` and Cryptosacristy refer to the same
project lane in historical evidence. Sacrysty is the current project name;
Sacrystan and `sacryd` replace the earlier selected operator and command names.
Historical evidence remains unchanged.

## Current stage

The repository contains a non-operational Rust library, public-record envelope
source, disposable `sq`/`sqv` conformance probes, and a synthetic Python custody
adapter. The
[substrate decision](https://github.com/nisavid/sacrysty/issues/2#issuecomment-5568558765)
selects one root Cargo package/library named `sacrysty`; `src/lib.rs` remains a
documented build placeholder. There is no Rust executable or public product API.
Add `sacryd` only when a concrete helper needs it; documentation does not depend
on a CLI.

The public-record envelope and inert extension boundary are settled. Record-family
body schemas, command grammar, authority semantics, custody behavior, and protocol
implementation remain with their owning Wayfinder work. Genesis integration is
in progress; accepted genesis closure, a qualified custody runtime, private
deployment, and a release remain absent. Repository source and conformance
evidence grant no production authority.
