# ADR 0003: Enforce DCO with the maintained GitHub App

## Status

Accepted. Operational rollout and rollback receipts belong to
[Recover Dependabot updates with the maintained DCO app][owning issue].

[owning issue]: https://github.com/nisavid/sacrysty/issues/22

## Context

Before this decision, the repository ran `.github/workflows/dco.yml`, which
called `scripts/check-dco.sh` for every pull request. That local checker
duplicated a maintained DCO implementation. It already selected commits with
`git rev-list --no-merges`, then required an exact, case-sensitive author name
and email sign-off for every remaining commit, including Bot-associated ones.
The repository needs ordinary DCO enforcement that preserves truthful human
certification while allowing normal bot-authored dependency updates.

The reviewed public upstream snapshot is `dcoapp/app` at
`822df17d83077098d659f4f673b18deba5d7405e`. Its source and fixtures establish
the implementation semantics described below. They do not establish the
identity or revision of a hosted deployment.

## Decision

Use the maintained hosted DCO GitHub App with app ID `1861` and its defaults:

- each human-authored, non-merge commit requires a recognized `Signed-off-by:
  NAME <EMAIL>` trailer; the captured name and email are compared
  case-insensitively, and each field is checked independently against the
  commit author or committer, without a separate general email-syntax check;
- repository members remain subject to sign-off;
- bot-authored and merge commits are exempt per commit;
- individual and third-party remediation commits remain disabled; and
- someone with repository write access may manually approve a failed check as
  an explicit exception.

Use these defaults only when reviewable readbacks at the actual default-branch
revisions Probot resolves show that neither this repository's `.github/dco.yml`
nor `nisavid/.github`'s `.github/dco.yml` supplies configured or inherited
policy. A file or `_extends` chain is a scope and qualification question, not
authorization to change owner configuration. The protected branch requires a
current applicable `DCO` check from app ID `1861`, while preserving every
unrelated rule and required check. Follow `docs/agents/dco-provisioning.md` when
verifying or changing this enforcement.

After the DCO migration lands, retain the Dependabot pull request and its bot
commit. Refresh it without rewriting the bot commit, then put the Cocogitto
correction in a separate, truthfully signed maintainer commit.

## Alternatives

- Keep the custom Actions checker. This retains duplicated policy and its
  bot-incompatible behavior, so it is rejected without a concrete requirement
  the maintained app cannot satisfy.
- Self-host the maintained source. This adds deployment identity, dependency,
  operations, and release responsibilities that this repository does not own.
- Disable DCO enforcement. This weakens the truthful contribution record.
- Enable individual or third-party remediation. This changes who can repair an
  unsigned contribution and is unnecessary for the accepted behavior.

## Compatibility and migration

The human contribution policy continues to require truthful certification for
every human-authored commit, including repository-member and human-authored
merge commits. Automated enforcement compatibility broadens from the local
checker's case-sensitive author name-and-email pair to the app's
case-insensitive comparisons, where the name and email each independently may
match the author or committer. The gate's ordinary merge exemption is
preserved; its Bot exemption is new. A mixed pull request passes only when
every non-exempt human commit passes. Manual approval is available but does
not create or replace a sign-off.

The externally visible required-check identity changes from `DCO compliance`
under integration `15368` to `DCO` under integration `1861`. Automation that
names the old check must migrate. This affects repository contribution
enforcement only; it changes no cryptographic-domain contract, release
signature, qualification result, adopter lock, or production authority.

The staged migration verifies the selected repositories and installed
permissions, observes app-bound current-head successes for a real bot-only pull
request and the signed-human migration pull request, exercises supported
recheck, and observes one missing-signoff human failure from app ID `1861`
before switching each affected repository's rule. It then replaces and reads
back only the required-check identity before merging the local workflow and
checker removal. The retained Dependabot refresh and signed Cocogitto follow-up
happen afterward; their mixed current-head check completes the owning issue but
is not a prerequisite for the migration pull request.

## Conformance

The pinned upstream suite passed four suites and 287 tests under Node.js
24.18.1 in a disposable environment without network access or credentials. The
supplied tests directly exercise isolated signed and unsigned human commits,
multi-human success and failure, isolated Bot and merge exemptions, parser
branches, membership, remediation, and recheck behavior. They do not directly
combine an unsigned Bot commit with an unsigned human commit. An isolated
fixture against the pinned upstream implementation must show that a Bot commit
plus an unsigned human commit rejects the human commit, and that a Bot commit
plus a signed human commit succeeds. Keep the fixture receipts and completion
state in the owning issue.

Repository-source validation checks the local workflow and checker removal,
documentation consistency, and preservation of unrelated workflow pins. It
does not alone establish effective configuration. That requires reviewable
readbacks of this repository's and the owner configuration repository's
`.github/dco.yml` paths at the actual default-branch revisions Probot resolves,
or conclusive repository metadata when no owner revision exists. Inaccessible
or ambiguous responses and any configured or inherited policy stop
qualification under the accepted defaults.

Hosted integration evidence is narrower and tied to controlled pull requests.
It requires current-head `DCO` checks from app ID `1861` for a bot-only pull
request and the signed-human migration pull request before the switch, one
missing-signoff human failure before switching each affected repository, and
the retained mixed bot/signed-human pull request afterward. It also requires a
supported recheck response, both effective-configuration path readbacks, exact
selected-repository and installed-permission readback, and complete protection
readback. Other negative and parser cases do not need duplicate hosted pull
requests.

Every positive qualification, recheck, already-correct no-op, and pre-merge
conformance receipt must retain the check output and show the ordinary automated
success from the reviewed source: output title `DCO` and output summary
`All commits are signed off!`. The manual-success summary
`Commit sign-off was manually approved.` proves only an explicit exception and
never routine qualification. Missing, ambiguous, error, or manual output is not
inferred to be an automated pass. A negative receipt instead retains its actual
observed outcome and reason.

Any intentionally unsigned hosted fixture is a separate, explicitly authorized
non-merge draft fixture that cannot merge. It must not weaken routine human
sign-off, rewrite the original bot contribution, or use manual approval as the
test. Its bounded protocol is reviewed separately and recorded in the owning
issue before execution.

## Threat boundary

The hosted app receives repository metadata, pull-request and content read
access, and check write access. Its result becomes a merge gate, and its manual
action lets a user with write access create a successful check. Branch
protection must therefore bind the required check to app ID `1861`, and manual
exceptions need an attributable reason and receipt.

The public snapshot shows application logic and declared direct dependency
ranges. It proves neither the hosted app's deployed revision or operator,
dependency resolution or safety, webhook delivery, push provenance, release
authority, nor adopter authority. A live check proves only the observed app
identity, head, and result. It does not expand this repository's release,
provider, host, ceremony, custody, or production authority.

## Rollback

Rollback is scoped to this repository. First retain both effective-configuration
path readbacks at their actual resolving revisions. Then prepare one reviewed
source candidate that restores the pinned local workflow, checker, and
executable-file policy entry and makes all current contribution and enforcement
claims truthful for the restored legacy behavior. In particular, update
`CONTRIBUTING.md`, this ADR's status and compatibility sections, and
`docs/agents/dco-provisioning.md` in place to distinguish the legacy checker's
exact, case-sensitive author-pair matching and checks on Bot-associated
non-merge commits from the hosted app's behavior. Preserve the procedure's
single discoverable path and historical receipts.

Observe `DCO compliance` from integration `15368` on that complete candidate's
current head before replacing only `DCO` from integration `1861` with the
legacy pair. Read back the complete rule and require that pair to be the only
semantic change. Preserve other selected repositories, installations, required
checks, and protection controls. Remove this repository from the hosted app
selection only if the migration added it, and only after the local replacement
is live.
