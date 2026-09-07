# Public repository handoff

Sacrysty begins from reviewed public design and planning work in
[`nisavid/dotfiles`](https://github.com/nisavid/dotfiles). Those records are
inputs to public repository work. They are not production state, cryptographic
authority, or permission to access a private deployment.

## Controlling records

- [Provision the public Sacrysty repository](https://github.com/nisavid/dotfiles/issues/260)
- [Sacrysty, Sacrystan, and `sacryd` naming amendment](https://github.com/nisavid/release-ops/issues/2#issuecomment-5565084063)
- [Reusable core, adapter, and adopter-profile boundary](https://github.com/nisavid/dotfiles/issues/207#issuecomment-5470521497)
- [Dotfiles reference-adoption profile](https://github.com/nisavid/dotfiles/issues/217#issuecomment-5500795081)
- [Operational delivery and first-adopter boundary](https://github.com/nisavid/dotfiles/issues/259#issuecomment-5532496281)

The generic repository shell is modeled on
[`nisavid/release-ops` at `100c37e288deaffacd5fa3d9fde94960eae635b7`](https://github.com/nisavid/release-ops/tree/100c37e288deaffacd5fa3d9fde94960eae635b7).
Only its already accepted Apache-2.0 licensing, DCO, Conventional Commits,
governance, policy CI, provenance, and language-neutral directory shape are
reused. No release-operations contract, Rust choice, package coordinate,
command grammar, schema, authority semantic, custody design, protocol
implementation, key, credential, provider binding, host state, or release is
copied or selected here.

## Ownership handoff

Sacrysty owns the generic public contracts, core implementation, adapter
interfaces and maintained reference adapters, public policy profiles, fixtures,
conformance assets, qualification formats and records, documentation,
governance, compatibility declarations, and releases.

Dotfiles remains the first system-user repository. It owns exact profile and
version locks, private and encrypted deployment bindings, real hosts and
accounts, provider resources, opaque secret references, protected bootstrap
state, ceremonies, production mutations, and acceptance evidence. Its adoption
and ceremony tickets remain in dotfiles; this repository neither reparents nor
duplicates them.

## Initial source receipt

This scaffold introduces policy and directory metadata only. It imports no
normative contract or executable artifact from dotfiles. Future genesis work
must identify every imported contract or executable artifact by its source
decision and immutable revision, state whether it was copied, translated, or
reimplemented, and bind its evidence to the final repository revision.
