# Product

<!-- impeccable:product-schema 1 -->

## Platform

Terminal (CLI/TUI)

First accepted genesis requires interactive terminal guidance alongside a compact machine-oriented CLI and a small Rust library facade. The same guided jobs must support prompt-free calls. A graphical interface is not required.

Tooling note: Impeccable 4.3.1 has no terminal platform token. This section records the selected product scope without claiming engine recognition.

## Users

Technically proficient system owners managing their cryptographic identities and operations are the primary users. Ivan is the first adopter; developers and automation are integration users.

## Product Purpose

Sacrysty is the public reusable cryptographic-operations product. Sacrystan is its human-facing operator. First accepted public genesis must provide complete working, qualified paths for every required initial story, with maintained direct-tool/helper parity. These are acceptance requirements, not delivered functionality.

## Operating Context

Sacrystan must guide complete crypto jobs over explicit crypto operations. Jobs must support interactive and headless use, inspection, and resumption after interruption, with progress retained by the adopter.

One root Rust package/library named `sacrysty` is selected. The prospective thin command `sacryd`, pronounced “sacred,” is added only when a concrete helper needs it. Background workers and published bodies of practice remain unnamed.

The initial scaffold build targets are Linux x86_64 GNU and macOS Apple Silicon. They do not establish qualified terminal or runtime support.

## Capabilities and Constraints

Required genesis journeys cover:

- Identity and key lifecycle: construct certificates and subkeys, inspect material, validate bindings and continuity, rotate, revoke, and export public material.
- Sign intended bytes and independently verify detached signatures; encrypt and decrypt under the selected required profiles.
- Enroll role custody, wrap ciphertext, replace factors, recover, and retire custody; perform supplied operations in fresh role-specific workers and report their results and evidence.
- Select public profiles and compatible immutable implementations, interpret qualification limits, and consume the required public record bodies and operation evidence.
- Complete each human or machine story through maintained direct tools and helpers, including cleanup, recovery, and stop paths.

The selected integration classes are versioned serialized contracts, a compact machine-oriented CLI, and a deliberately small library facade. Machine results use versioned JSON envelopes on stdout, diagnostics use stderr, and exit classes and library errors are typed. Exact methods, commands, and wire shapes remain open. No additional language binding or terminal framework is selected. Public interfaces are experimental before 1.0; no post-1.0 support promise follows.

Sacrysty owns reusable crypto contracts and implementation, adapters, public profiles, conformance, qualification records, documentation, governance, compatibility declarations, and its releases. Codiquary owns release authority, publication, verifier state, and protocol semantics. Adopters own exact deployment locks, private bindings, operational state, real providers, ceremonies, production mutations, and acceptance evidence. Ivan’s dotfiles are the first adopter. Repository evidence grants no production authority.

The accepted custody contract retains the signer secret in a fresh role-specific worker; it supplies no universal private-key-return interface. Tests and examples use disposable, value-free fixtures.

## Evidence on Hand

[README.md](README.md) and [CONTEXT.md](CONTEXT.md) describe the current source shape: a non-operational Rust library, public-record envelope source, disposable crypto-tool probes, a signing profile, and a synthetic Python custody adapter. The root library has no public operation API or executable. Record-family body schemas remain unsupplied. This source does not establish accepted genesis closure, qualified custody runtime, private deployment, or a release.

The [full-genesis resolution](https://github.com/nisavid/sacrysty/issues/43#issuecomment-5994349617) sets the acceptance scope. Published signing-profile evidence and source research have bounded claims; they do not establish complete operation coverage or the required qualified RFC 9980 executable tuple. These documentary sources are not a fresh implementation survey or runtime validation. The accessibility baseline below is a confirmed requirement, not verified implementation.

## Product Principles

1. Complete the required jobs through working, qualified paths; declarations alone do not meet genesis acceptance.
2. Keep guided jobs and explicit operations available to people and automation.
3. Preserve inspectable, resumable progress under adopter ownership.
4. Maintain direct-tool/helper parity and state the limits of each body of evidence.
5. Preserve the distinct responsibilities of Sacrysty, Codiquary, and each adopter.

## Accessibility & Inclusion

First accepted genesis requires screen-reader-friendly output, keyboard-only use, remote and narrow terminal use, and no reliance on color. Additional language requirements remain open.

## Open Decisions

The [operation-interface decision](https://github.com/nisavid/sacrysty/issues/44) retains detailed requests, results, errors, methods, command grammar, consumed record-body schemas, the state model, adapter transport, compatibility, and implementation/procedure/qualification allocations. Cryptographic, authorization, custody, and protocol details remain with their owning decisions and reviews. This product record selects no new semantics or UI behavior.
