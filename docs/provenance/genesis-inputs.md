# Genesis integration inputs

The genesis candidate assembles the public source inputs below. This receipt
identifies their origins; acceptance of the complete genesis belongs to
[Establish Sacrysty's immutable public genesis](https://github.com/nisavid/sacrysty/issues/3).

| Input | Owning decision | Immutable source revision | Integration |
| --- | --- | --- | --- |
| Rust library and native build checks | [Single-package library skeleton](https://github.com/nisavid/sacrysty/issues/6#issuecomment-5569532765) | `4934e821e04f8a7d5740086a19fdb66a73e6a0dc` | Retained through the base history. |
| Repository security and quality controls | [GitHub controls](https://github.com/nisavid/sacrysty/issues/8#issuecomment-5574014764) | `a96c715ebc593999fe9f0f5a0b0a94e453826178` | Retained through the base history; live configuration is separate from source. |
| Public-record envelope, ADR, and fixtures | [Public domain model](https://github.com/nisavid/sacrysty/issues/14#issuecomment-5626182792) | `b7b23d92fa9d1535683f7417051ebb2c886c1d28` | Producer commit retained as an ancestor; checker corrected and shared entrypoints reconciled. |
| Crypto-conformance profile and probe | [Crypto conformance](https://github.com/nisavid/sacrysty/issues/12#issuecomment-5626207980) | `cad9c98aa2a122368e31f4ab14aeff4e6c95a6cf` | Producer commit retained as an ancestor; probe corrected and shared entrypoints reconciled. |
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

The integrated tree retains the source fixtures, profiles, schema, and contracts,
with an explicit clarification of the envelope check's limits. Shared README
files and the ADR index describe the assembled candidate. The domain checker,
custody adapter, custody checks, and crypto-conformance probe contain the
corrections described in [ADR 0002](../adr/0002-genesis-integration-boundary.md),
with focused regression cases. The signing-profile probe is retained unchanged.
The integration diff is the authoritative record of those translations.

The new validation entrypoint, native CI invocation, and
[consumer procedure](../agents/genesis-validation.md) exercise the assembled
tree. They establish no additional product interface or operational authority.

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

The public-record envelope does not supply record-family schemas or operational
protocols. The synthetic custody adapter does not qualify an authenticator or
plugin. Historical tool observations do not qualify the integration runtime.
Renew the relevant checks and reviews on the final candidate, preserving each
result's scope and limitations.
