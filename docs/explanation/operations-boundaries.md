# Cryptographic operations ownership and boundaries

Sacrysty owns reusable, generic cryptographic operations. Codiquary owns
release-authority, publication, verifier, and protocol contracts, including
executable release conformance. A Sacrysty operation may later consume an
accepted Codiquary contract, but it cannot define, restate, or become a second
release authority plane.

## Canonical product ownership

Sacrysty's public work covers exact-byte cryptographic operations, standard-tool
evidence, generic custody adapter seams, value-free profiles, and the
qualification formats selected by its own decisions. A successful Sacrysty
operation is evidence about that operation. It does not select a release,
publish bytes, establish verifier state, or grant consumer authority.

Codiquary's accepted
[TUF direction](https://github.com/nisavid/codiquary/issues/18#issuecomment-5624996832)
controls its release trust plane. The
[release-conformance workstream](https://github.com/nisavid/codiquary/issues/26)
owns release, TUF, client, and adapter conformance and executable documentation;
it explicitly does not absorb Sacrysty's cryptographic-tool conformance.
[Codiquary #35](https://github.com/nisavid/codiquary/issues/35) is the current
operator decision for that workstream's first executable increment. Sacrysty
does not choose or duplicate that increment.

Each system user separately owns exact deployment locks, private bindings,
hosts, accounts, provider resources, secret references, protected state,
ceremonies, production mutations, and acceptance evidence.

## Threat and authority boundary

The accepted
[threat and authority model](https://github.com/nisavid/dotfiles/issues/215#issuecomment-5464747293)
requires failed, missing, stale, unsupported, indeterminate, or conflicting
inputs to stop positive action. Source, CI, transport, mirrors, publication
providers, ciphertext custody, and generic cryptographic evidence do not create
release authority. Sacrysty preserves that fail-closed boundary when producing
or consuming cryptographic evidence; this repository does not implement the
certifying identity, status authority, publication plane, TUF state machine, or
protected verifier. No continuity is claimed after all certifying and recovery
roots are lost or compromised, under coercion, after a cryptographic break, or
on a privileged compromised verifier host.

## Custody boundary

The accepted
[custody contract](https://github.com/nisavid/dotfiles/issues/208#issuecomment-5472198422)
keeps signer roles, FIDO credentials, recovery identities, passphrases, private
registry state, and ceremonies compartmentalized. Maintained external
cryptographic implementations are required; bespoke cryptography and threshold
custody are not authorized by this repository.

The one-shot boundary uses one fresh role-specific worker for one supplied
operation, then terminates it. Plaintext must not enter files, arguments,
environment, logs, provider payloads, caches, or long-lived services. Local
user verification does not prove approval of release intent. Recovery, factor
replacement, rotation, freeze, and incident decisions remain with their owning
authority and adopter contracts; no synthetic result exercises them.

Factor-set or recovery-recipient changes create a new immutable custody
revision and require every retained path to pass before promotion. Missing,
conflicting, or rolled-back private registry state stops normal use. Plausible
signer access freezes the affected role; confirmed unwrap, plaintext exposure,
unauthorized valid output, or demonstrated signer use requires revocation and
replacement under the owning authority contract. These are accepted downstream
constraints, not behavior implemented or qualified by this candidate.

## Current implementation boundary

The current candidate, assembled from the
[genesis inputs](../provenance/genesis-inputs.md), contains public-record
envelope checking, standard-tool disposable probes, a synthetic
[one-shot custody adapter](../../adapters/fido-custody-v1.md), and an empty Rust
library. The envelope is settled; record-family body schemas are not supplied.
The adapter bounds ordinary same-process-group descendants and cleanup, but it
is not an operating-system sandbox against a malicious worker.

The [conformance work](../../conformance/README.md) validates serialized
envelopes, synthetic process behavior, source provenance, and disposable tool
observations. It supplies no release protocol implementation, executable
release conformance, hardware or plugin qualification, public API, private
adoption, or production authority.

## Remaining Sacrysty work

Future Sacrysty decisions may define the record-family bodies needed for its
generic cryptographic evidence, stable helper and library request/result
semantics, adapter equivalence, and exact tool, platform, plaintext-boundary,
and custody qualification. They must consume rather than duplicate any
Codiquary-owned release contract.

The [full genesis issue](https://github.com/nisavid/sacrysty/issues/3) remains
open. This page records ownership and accepted boundaries; it is not an
executable ceremony, publication, verification, recovery, rotation, or release
procedure.
