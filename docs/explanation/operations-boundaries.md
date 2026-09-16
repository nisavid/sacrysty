# Operations boundaries

Sacrysty gives a Sacrystan a provider-neutral safety boundary for release operations: only certified authority can create trust, and every failed, missing, stale, or conflicting gate stops positive action. Preventing unauthorized release acceptance outranks availability, convenience, and metadata privacy. The [normative threat model](https://github.com/nisavid/dotfiles/issues/215#issuecomment-5464747293) controls every implementation, profile, and adapter.

## Threat and authority

Protected assets include the certifying identity and continuity history, signer secrets and envelopes, factors and recovery material, release records and artifacts, lifecycle state, signatures, DNSSEC binding, verifier state, archives, and value-free evidence. Compromise of only the network, source or CI, a mirror, a publication provider, ciphertext custody, a factor, or an envelope grants no authority. No continuity is promised after every certifying and recovery root is lost or compromised, under coercion, after a cryptographic break, or on a privileged compromised verifier host.

Only the certifying identity may create or expand positive authority. DNSSEC authenticates initial binding, discovery, and freshness but cannot add a signer. A release signer acts only on exact manifests within its certified scope. A separate status role may withdraw or freeze but cannot restore authority. Provider, host, or CI control and factor or envelope possession grant none. The verifier and its authenticated update path are a separate authority. Signing, recovery, rewrapping, factor enrollment, lifecycle changes, freezes, and trust transitions require explicit human presence.

## Custody and authorization

The accepted [custody contract](https://github.com/nisavid/dotfiles/issues/208#issuecomment-5472198422) keeps release and status signer secrets, FIDO credentials, recovery identities, passphrases, registry state, and ceremonies separate, even if one person or device serves both roles. Each role and signer tenure has one canonical signer bundle. Every factor-set or recovery-recipient change creates a new immutable custody revision over the unchanged bundle. Any listed recipient may unwrap it; an explicit monotonic private pointer, not a provider’s “latest” marker, selects the active revision. Maintained external implementations are required; bespoke cryptography and threshold custody are not.

Proton Pass is a reference ciphertext-custody adapter, not a trust root or core dependency. Two encrypted offline recovery copies remain independent of it and ordinary host state. Ordinary use occurs on one explicitly qualified operator host through local user-verification-gated FIDO unwrap. That gate does not prove approval of exact release intent; the trusted host displays and canonicalizes it. One fresh role-specific worker performs one supplied operation and exits. Plaintext may not enter files, arguments, environment, logs, provider payloads, caches, or long-lived services. Unattended signing is outside the baseline.

## Recovery and factor replacement

During a provider outage, current offline ciphertext may be used with ordinary FIDO. If no FIDO path works, offline recovery may authorize one exact operation in a qualified environment. Each further operation needs a fresh recovery ceremony, and the role remains recovery-only until an ordinary factor and full recovery state return. New or replacement media must pass canary checks on both copies; one must also recover the current revision and verify the signer fingerprint without signing.

Adding or removing a factor creates a new revision and verifies every retained path before promotion. PIN lock, reset, controlled deletion, or factor-only loss uses a surviving factor or recovery path to replace the credential while retaining the signer. Historical factor-envelope pairs remain exposure paths while both survive. Missing, conflicting, or rolled-back private registry state stops normal signing and never becomes public verification authority.

## Rotation and incidents

Factor-only loss, ciphertext-only exposure, provider outage, controlled media failure, or host compromise proven to exclude a signer-use window is repaired with the same signer. Plausible factor-plus-envelope access, recovery-material-plus-passphrase access, host compromise during an uncertain signer-use window, or unexplained valid output freezes the role. Unresolved signer access requires a fresh signer. Confirmed unwrap, plaintext exposure, an unauthorized valid signature, or demonstrated signer use requires revocation and replacement.

Incidents stay scoped to the affected role unless shared evidence crosses compartments. Status-signer compromise alone does not rotate the release signer. Only the certifying identity may authorize a fresh signer, issue terminal revocation, restore positive authority, or clear a security freeze. Routine tenure rotation likewise uses a fresh certified signer; after verified cutover, predecessor secret-bearing custody is retired without private rollback escrow.

## Current implementation boundary

The [public-core boundary](https://github.com/nisavid/dotfiles/issues/207#issuecomment-5470521497) makes core contracts and adapter interfaces normative; profiles narrow policy, while private bindings add real values without creating generic semantics.

The current candidate, assembled from the [genesis inputs](../provenance/genesis-inputs.md), has only public-record envelope checking, standard-tool disposable probes, a synthetic [one-shot custody adapter](../../adapters/fido-custody-v1.md), and an empty Rust library. Its process group bounds ordinary descendants and cleanup; it is not an OS sandbox against a malicious worker. The synthetic [conformance work](../../conformance/README.md) establishes no hardware or plugin qualification, public API, or operational implementation.

## Contracts still required

Before generic executable documentation can be completed, Sacrysty needs normative contracts for:

- record-family bodies and canonical manifest, status, lifecycle, and signing-scope rules;
- publication transactions, canonical and mirror behavior, archives, readback, and reconciliation;
- verifier bootstrap and updates, freshness, highest-seen state, conflicts, and historical verification;
- operator state transitions and value-free receipts for signing, recovery, factor replacement, rotation, and failures;
- stable helper, library, and adapter request, result, and failure semantics, with conformance rules proving helper equivalence; and
- exact platform, dependency, authenticator, plaintext-boundary, qualification, and acceptance requirements.

The [full genesis issue](https://github.com/nisavid/sacrysty/issues/3) remains open. This page does not substitute for those executable ceremony, publication, verification, recovery, rotation, or equivalence procedures.