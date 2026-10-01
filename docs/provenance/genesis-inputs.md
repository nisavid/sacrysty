# Genesis integration inputs

The genesis candidate assembles the public source inputs below. This receipt
identifies their origins; acceptance of the complete genesis belongs to
[Establish Sacrysty's immutable public genesis](https://github.com/nisavid/sacrysty/issues/3).

| Input | Owning decision | Immutable source revision | Integration |
| --- | --- | --- | --- |
| Rust library and native build checks | [Single-package library skeleton](https://github.com/nisavid/sacrysty/issues/6#issuecomment-5569532765) | `4934e821e04f8a7d5740086a19fdb66a73e6a0dc` | Retained through the base history. |
| Repository security and quality controls | [GitHub controls](https://github.com/nisavid/sacrysty/issues/8#issuecomment-5574014764) | `a96c715ebc593999fe9f0f5a0b0a94e453826178` | Retained through the base history; live configuration is separate from source. |
| Public-record envelope, ADR, and fixtures | [Public domain model](https://github.com/nisavid/sacrysty/issues/14#issuecomment-5626182792) | `b7b23d92fa9d1535683f7417051ebb2c886c1d28` | Original producer objects retained in the source bundle; checker corrected and shared entrypoints reconciled. |
| Crypto-conformance profile and probe | [Crypto conformance](https://github.com/nisavid/sacrysty/issues/12#issuecomment-5626207980) | `cad9c98aa2a122368e31f4ab14aeff4e6c95a6cf` | Original producer objects retained in the source bundle; probe corrected and shared entrypoints reconciled. |
| Synthetic one-shot custody adapter | [FIDO adapter](https://github.com/nisavid/sacrysty/issues/15#issuecomment-5654982477) | `2579e8011e298a8863ae4a6ee439d5faf2e037b7` | Retained from the merged adapter PR. |
| Signing profile and disposable probe | [Signing profile](https://github.com/nisavid/sacrysty/issues/13#issuecomment-5654982348) | `5a4332f7c2801df808fee58e7997cdb3ed9c855d` | Retained from the merged signing-profile PR and used as the integration base. |

At the integration audit on 2026-09-16, both producer commits had the
library-skeleton revision as their parent and were absent from `main` ancestry.
GitHub served the public-domain commit; its commit API returned 404 for the
crypto-conformance commit. That source was recovered from the retained Git
object. The producer's tracker pointer and a retained object do not establish
that an input was publicly reachable or reviewed as part of the final candidate.

## File provenance and integration changes

The [source inventory](genesis-source-inventory.json) records all 35 path entries
introduced or changed by the four contract and conformance inputs. Each entry
binds the original path and mode to its commit, parent, tree, blob, byte length,
and SHA-256. Repeated paths identify distinct producer versions. These are
source identities, not qualification results or hashes of the integrated files.

The [source bundle](genesis-sources.bundle) carries the four original producer
commits and their complete reachable objects under `refs/heads/producer-12`,
`producer-13`, `producer-14`, and `producer-15`. It is a standalone Git bundle,
61,436 bytes, with SHA-256
`2ad3bdfdac795e880f4fe28e74ae3593a1b0f4141b7ca921d55c148a06c893b0`.
The checker pins that artifact, imports its verified bytes into a disposable
bare repository, verifies its complete objects and exact producer refs, and
compares all inventory entries against those objects. It never checks out or
executes the historical source. The bundle includes historical public files
needed to retain the original commit identities; those files are evidence,
not the candidate's maintained implementation.

Provenance verification depends on the bundle carried by the candidate, so it
works after squash or rebase merges and from shallow checkouts. The candidate's
ancestry is not part of this contract. Missing or altered evidence fails even
when another local Git object database happens to contain the original source.
The inventory proves source identity and recoverability, not source approval,
integration correctness, or a signature-based trust claim. Review and tests
must still cover the final integrated revision.

The integrated tree retains the source fixtures, profiles, schema, and contracts,
with an explicit clarification of the envelope check's limits. Shared README
files and the ADR index describe the assembled candidate. The domain checker,
custody adapter, custody checks, and crypto-conformance probe contain the
corrections described in [ADR 0002](../adr/0002-genesis-integration-boundary.md),
with focused regression cases. The retained signing-profile probe now shares
the isolated-store, hashing, JSON, and verified-cleanup boundary with the crypto
probe. The integration diff is the authoritative record of those translations.

The bundled-source inventory check, validation entrypoint, native CI
invocation, and [consumer procedure](../agents/genesis-validation.md) exercise
the assembled tree. They establish no additional product interface or
operational authority.

## Direct FIDO source closure

The earlier five-input provisional qualification tuple is superseded because
the adapter and its runtime closure changed. The complete repository-local
source closure for a renewed direct synthetic FIDO check is:

- `adapters/fido-custody-v1.md`—the consumed contract;
- `adapters/fido_custody.py`—the reference adapter;
- `conformance/check-fido-custody.py`—the direct checker;
- `conformance/test_support.py`—the checker's external-storage guard;
- `sacrysty_runtime/__init__.py`—the internal package initializer;
- `sacrysty_runtime/process_groups.py`—the shared owned-group lifecycle; and
- `sacrysty_runtime/strict_json.py`—the shared response decoder.

There are no `adapters` or `conformance` package initializer files in this
tree. A downstream qualification must bind every path above, its integrated
commit and runtime, and the qualification owner's runner, workflow, and tests.
This receipt does not rebind that qualification or its hosted evidence.

## Controlling public decisions

The source follows the ownership and compatibility boundary in
[the reusable-core decision](https://github.com/nisavid/dotfiles/issues/207#issuecomment-5470521497),
the goal-first documentation routes in
[the documentation decision](https://github.com/nisavid/dotfiles/issues/211#issuecomment-5500606485),
and the independent genesis/bootstrap boundary in
[the operational delivery decision](https://github.com/nisavid/dotfiles/issues/259#issuecomment-5532496281).
The [reference-adoption profile](https://github.com/nisavid/dotfiles/issues/217#issuecomment-5500795081)
owns adopter requirements. It supplies no private values or production authority
to this candidate.

The public-record envelope does not supply record-family body schemas or
operational protocols. The synthetic custody adapter does not qualify an
authenticator or plugin. Historical tool observations do not qualify the
integration runtime. Renew the relevant checks and reviews on the final
candidate, preserving each result's scope and limitations.

## Published increments and remaining joins

The original 35-entry inventory and four-producer source bundle above retain
their original identities and scope. The later inputs below have separate
publication and evidence records; this index does not add them to that bundle
or convert their evidence into complete genesis acceptance.

| Public increment | Published identity | Evidence and limits |
| --- | --- | --- |
| [Frozen synthetic CI](https://github.com/nisavid/sacrysty/pull/21) | `3cb793d2fee306df9b4960d5f9460b19d84eab85`; checked source `81896a0c9f0b5af4f8c7e69e7d48da34e8e91318` | The [real-worker preparation](../../qualification/fido-custody/real-worker-preparation-2026-09-30.md#evidence-already-held-with-its-original-limits) records the original candidate, merge and synthetic limits; it supplies no real-worker qualification. |
| [FIDO interface research](https://github.com/nisavid/sacrysty/pull/31) | `f9294262c31f2588135792445bebdd2953b4d06d` | The [interface record](../research/fido-worker-interfaces.md) and its separate evidence manifest retain bounded research observations, not artifact admission or hardware qualification. |
| [Generic FIDO plugin upstream baseline](https://github.com/nisavid/sacrysty/pull/32) | `04f081ebc37f9d3574d7af9e0bb246d645a39cf4` | The [upstream baseline](../research/fido-upstream-baseline.md) records 41 upstream source paths at Typage `38b8b10cb22409de0eaa8a617a01f16dc2e3f9f4`; its source manifest is distinct from the 35-entry genesis inventory. |
| [Real-worker qualification preparation](https://github.com/nisavid/sacrysty/pull/33) | `26e664b68ac00c15f1979879987a57a86aaa52c9` | The [maintained inventory](../../qualification/fido-custody/real-worker-preparation-2026-09-30.md) records producer inputs and dependent joins. Its anchor remains `04f081ebc37f9d3574d7af9e0bb246d645a39cf4`; preparation is not execution. |
| [Timeout-fixture correction](https://github.com/nisavid/sacrysty/pull/35) | `1fa60aad363c2a1c02fd72e51bdc71c73bca3466` | The correction is confined to the synthetic timeout fixture. It does not change production deadlines or resolve the subsequent macOS process-group cleanup cause. |
| [Publisher namespace implementation](https://github.com/nisavid/sacrysty/pull/34) | `9232530a16413242ea28bfb417138637b24b9768`, tree `732b4037f0f0ada415950e8aeea55b1510fce323` | The published tree matches reviewed candidate `724fc4fb65fed50f09d93896b8d744779a3d5106`. [ADR 0004](../adr/0004-publisher-namespace.md) records scoped review and maintainer approval. Source-inventory checks and their regressions passed in normal and optimized Python, with repository-policy and whitespace checks, from a fresh shallow checkout of the published revision. This was not a complete genesis-validation invocation. |

The [genesis validation procedure](../agents/genesis-validation.md) remains the
consumer entrypoint. Final integration must join accepted contracts, every
changed source and evidence input, executed validation receipts, independent
review, applicable qualification, and required approval on the revision each
consumer actually tests. Passing checks on an earlier candidate retain their
original source identity; a matching tree does not relabel an executed receipt.

[ADR 0002](../adr/0002-genesis-integration-boundary.md) leaves generic policy
and registry behavior and family-body schemas with their owning decisions.
The [operations boundary](../explanation/operations-boundaries.md) retains
helper equivalence and complete reusable operational procedures with their
owning decisions. Codiquary retains release/publication/verifier/protocol contracts;
system users retain private ceremonies, deployment locks, and adoption.
The [real-worker inventory](../../qualification/fido-custody/real-worker-preparation-2026-09-30.md)
remains the producer-input checklist before dependent qualification. Broader
genesis acceptance and downstream consumer acceptance remain open.
