# Repository instructions

## Project context

Read `CONTEXT.md` before planning or editing. Use its accepted terms in source,
tests, documentation, issues, and commits. Keep `README.md` as the verified
human entrypoint and put detailed contracts and decisions under `docs/`.

When introducing or revising domain concepts, follow the
[shared domain naming convention](https://github.com/nisavid/dotfiles/blob/main/docs/research/CRYPTO_RELEASE_OPS_NAMING.md#domain-naming-convention).

The repository contains a non-operational Rust library build skeleton. The
[substrate decision](https://github.com/nisavid/sacrysty/issues/2#issuecomment-5568558765)
selects one root package/library named `sacrysty`. Sacrystan is the public-facing
operator; add the prospective `sacryd` command (pronounced “sacred”) only when a
concrete helper needs it. Background workers and published bodies of practice
remain unnamed. Command grammar, schemas, authority semantics, custody model,
and protocol implementation remain with their owning Wayfinder work.

## Ownership boundary

Public reusable contracts, implementations, adapter interfaces and maintained
reference adapters, public policy profiles, fixtures, conformance assets,
qualification formats and records, documentation, governance, compatibility
declarations, and releases belong here.

Private deployment bindings, exact adopter locks, hosts, accounts, provider
resources, opaque secret references, protected bootstrap state, ceremonies,
production mutations, and acceptance evidence belong to each system user.
Ivan's dotfiles remain the first adopter and own those personal surfaces.

- Never add a plaintext secret, private key, credential, production identifier,
  private deployment value, or live-provider payload.
- Use disposable, value-free fixtures for every test and example.
- Do not access or mutate production keys, providers, hosts, DNS, custody state,
  ceremonies, or protected consumers from repository work.
- Repository validation proves only the layer it exercises; it does not grant
  production or adoption authority.
- Do not invent cryptographic primitives. Use established standards and reviewed
  implementations only after the owning design and qualification work settles
  them.

## Issue tracker

The [implementation map](https://github.com/nisavid/sacrysty/issues/1), its
native sub-issues, and its dependency edges are the source of truth. Claim a
Wayfinder ticket before working it. Refer to tickets by their linked titles
in human-facing prose.

Use the canonical `needs-triage`, `needs-info`, `ready-for-agent`,
`ready-for-human`, and `wontfix` labels. Wayfinder tickets use exactly one of
`wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, or
`wayfinder:task`; maps use `wayfinder:map`.

## Git and validation

This is a personal `nisavid` project. Use `Ivan D Vasin <ivan@nisavid.io>` for
Git work and the `nisavid` GitHub account for repository mutations. Prefix
branches with `ivan/`. Use Conventional Commits for commits and pull-request
titles. Sign off every commit under the DCO with `git commit --signoff`.

Before committing or publishing, run:

```sh
./scripts/check-repository.sh
git diff --check
```

Run every additional test or conformance suite that owns the changed surface.

## Change policy

- Keep one primary core distribution until a demonstrated dependency,
  privilege, platform, or release-cadence seam justifies another.
- Normative or security-boundary changes require an ADR, threat-model review,
  conformance changes, compatibility analysis, and explicit maintainer approval.
- Core changes test against existing contracts. Adapter-interface changes
  include migration evidence. Material adapter changes renew affected
  qualification.
- Documentation and examples cannot redefine normative behavior. Derive
  executable examples from fixtures and conformance assets.
- Before 1.0, incompatible changes require an explicit deployment-lock update
  and renewed affected qualification; never rewrite a user's accepted lock.
- Define the current increment before deepening it. Settle every valid finding
  within that increment and record later branches as follow-up.

## Pull requests

Use the pull-request template. State the owning issue, public surface,
provenance, compatibility effect, and exact validation run. Release, provider,
host, ceremony, custody, or production actuation requires separate explicit
authority.
