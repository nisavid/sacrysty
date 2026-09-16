# Operate ordinary DCO enforcement

Use this single procedure to provision, verify, migrate, recover, or roll back
the maintained DCO GitHub App for `nisavid/sacrysty`. Migration receipts belong
to [Recover Dependabot updates with the maintained DCO app][owning issue].
Other repositories may adapt this procedure, but it is not a global convention.
A custom checker is justified only by a concrete requirement the maintained app
cannot meet.

[owning issue]: https://github.com/nisavid/sacrysty/issues/22

This procedure changes contribution enforcement only. It grants no release,
deployment, provider, host, ceremony, custody, or adopter authority. Only the
repository coordinator may change the installation or repository settings.

For the current migration, the selected installer is blocked by its
approval-review gate. Authorized source preparation and publication may
proceed, but installation, protection mutation, and merging remain blocked
until that gate clears. The qualification and required-check ordering below
remain unchanged.

## Routine state

- GitHub App `DCO`, app ID `1861`, is installed for the exact intended
  repositories, including `nisavid/sacrysty`. Unrelated selections are
  preserved.
- No `.github/dco.yml` is present. Default automated enforcement requires
  sign-off from non-exempt humans and repository members, exempts commits with
  Bot-associated authors and ordinary merge commits per commit, and disables
  individual and third-party remediation.
- The parser recognizes a `Signed-off-by: NAME <EMAIL>` trailer line. Its
  captured name and email are compared case-insensitively, and each field
  independently may match the commit author or committer. It does not
  separately establish general email-address syntax.
- The protected branch requires a current applicable `DCO` check from app ID
  `1861`. Every unrelated protection and required check remains unchanged.
- An ordinary automated success has output title `DCO` and output summary
  `All commits are signed off!` in the reviewed upstream source.
- **Set DCO to pass** is a manual exception available to a user with write
  access. Its output summary is `Commit sign-off was manually approved.` It is
  not a contribution sign-off or routine conformance evidence.

For routine contributions, sign off every human-authored commit, including
human-authored merge commits, even though the app exempts ordinary merge
commits from its automated gate. Confirm the app-bound check applies to the
pull request's current head. Preserve bot commits rather than rewriting or
signing them on a bot's behalf.

## Keep evidence layers separate

1. **Upstream fixture evidence** establishes behavior of the reviewed
   `dcoapp/app` revision. At the accepted revision, four suites and 287 tests
   passed under Node.js 24.18.1 in a disposable environment without network
   access or credentials. The supplied tests directly cover isolated signed
   and unsigned human commits, multi-human success and failure, isolated bot
   and merge exemptions, parser branches, membership, remediation, and recheck
   behavior. They do not directly combine an unsigned Bot commit with an
   unsigned human commit, and they do not identify the hosted deployment. An
   isolated fixture against the pinned upstream implementation must show that
   a Bot commit plus an unsigned human commit rejects the human commit, and
   that a Bot commit plus a signed human commit succeeds. Keep the fixture
   receipts and completion state in the owning issue.
2. **Repository-source evidence** establishes removal of the local checker,
   absence of a configuration override, and agreement of maintained docs. It
   does not prove hosted delivery or settings.
3. **Hosted integration evidence** establishes only the selected repositories,
   approved installation permissions, registered app identity, observed check
   origin and head, recheck response, and repository-setting readback at the
   time recorded.

Do not reproduce every upstream fixture as a hosted pull request. The one
required hosted negative is the missing-signoff human failure specified below;
keep the additional parser, merge, membership, remediation, and negative cases
at the fixture layer. Repeat hosted evidence only when its pull-request head,
selected repository, approved permission, app registration, or required-check
rule changes.

## Verify registration and installation

Read the public app registration and retain its app ID, registered permissions,
and events:

```sh
gh api /apps/dco --jq '{id,slug,permissions,events}'
```

Require app ID `1861` and compare the registration with the reviewed upstream
access needs. Registration data does not prove which repositories selected the
app or which permissions an installation approved.

Use the signed-in GitHub installation settings to read back the exact selected
repository list and approved installation permissions. Preserve that list
exactly when adding or removing `nisavid/sacrysty`; never broaden the selection
to all repositories or expose secrets. The installation settings need not show
registered events because `/apps/dco` is the registration readback for them.

`GET /user/installations` requires an app-authorized user token. An HTTP 403
from the current GitHub CLI token is not evidence of a bad installation and
does not imply any token or configuration change. Use the signed-in settings UI
as the supported fallback. Ask the user to log in only if access to that UI is
actually blocked.

Confirm the tested base has no `.github/dco.yml`. Its absence selects
`require.members: true`, `allowRemediationCommits.individual: false`, and
`allowRemediationCommits.thirdParty: false` in the reviewed source.

## Inspect a current applicable check

Resolve the pull request's current head with `gh pr view`. Query all check-run
pages for that commit, select app ID `1861` and check name `DCO`, then retain the
latest applicable run:

```sh
gh api --paginate --slurp \
  "/repos/nisavid/sacrysty/commits/HEAD_SHA/check-runs?per_page=100" \
  --jq '[.[].check_runs[] | select(.name == "DCO" and .app.id == 1861)]
        | sort_by(.id) | last
        | {id,name,head_sha,status,conclusion,app:{id:.app.id,slug:.app.slug},
           output:{title:.output.title,summary:.output.summary},html_url}'
```

Require the returned `head_sha` to equal the pull request's current head and the
status and conclusion to match the case being verified. Same-named checks from
other apps and checks on earlier heads do not count. Rechecks may leave more
than one related run or attempt, so do not infer an exact count across check
apps; retain the current applicable matching result.

For every positive qualification, recheck, already-correct no-op, and pre-merge
conformance receipt, require `status: completed`, `conclusion: success`, output
title `DCO`, and output summary `All commits are signed off!`. Missing,
ambiguous, error, or manual-approval output is not an automated pass. Keep a
manual approval only as the explicit exception described below. For the
required negative receipt, retain its actual status and conclusion and its
output summary as the observed outcome and reason; do not infer either from an
expected success or failure.

To exercise recovery, submit a non-bot pull-request review or inline review
comment containing this line by itself:

```text
@dcoapp recheck
```

Record the response and the resulting current-head matching check. A closed
pull request, bot actor, or command not on its own line is expected to be a
no-op. If a supported recheck produces no applicable result, inspect the
installation and authorized delivery diagnostics; do not weaken protection.

## Migrate from the legacy checker

Read the complete applicable rule before choosing a path, and classify every
required-check entry for these two identities:

- If only `DCO` from integration `1861` is required, verify the complete routine
  state, including configuration, selected repositories, approved permissions,
  current applicable automated success, and the whole desired rule. Record that
  verification as a no-op with no installation or ruleset mutation.
- If only `DCO compliance` from GitHub Actions integration `15368` is required,
  start the staged migration below and keep it active through the switch.
- If both identities, neither identity, or a duplicate of either identity is
  present, stop for adjudication without changing the installation or ruleset.

Never add the old required check to make the staged migration reachable.

### 1. Record the starting state

Record the migration pull request's head and base, the complete applicable
ruleset, required checks with integration IDs, the public registration
readback, and the installation settings readback. Discover the applicable
ruleset live rather than assuming a stored numeric ID:

```sh
gh api /repos/nisavid/sacrysty/rulesets --paginate \
  --jq '.[] | {id,name,target,enforcement}'
gh api /repos/nisavid/sacrysty/rulesets/RULESET_ID >rules-before.json
```

Stop if ownership, authority, destination, repository selection, or protection
differs from the accepted increment.

### 2. Establish the pre-switch integration evidence

While both checks can report without changing protection, record:

- a successful app-bound current-head check on a real bot-only pull request;
- a successful app-bound current-head check on the signed-human DCO migration
  pull request; and
- a supported recheck response with its current-head matching check.

Before switching each affected repository's rule, also record one current-head
failure from app ID `1861` for a human commit whose sign-off is missing. An
intentionally unsigned hosted fixture must be a separate, explicitly
authorized, non-merge draft fixture that cannot merge. Never weaken routine
human sign-off, rewrite the original bot contribution, or use **Set DCO to
pass** as the test. This procedure does not design or authorize that fixture;
its concrete bounded protocol must be reviewed separately and recorded in the
owning issue before execution. Do not duplicate the other upstream negative,
parser, merge, membership, or remediation cases on GitHub.

### 3. Replace the required check and land the migration

Immediately before the write, confirm that only `DCO compliance` from
integration `15368` is present. If that state changed, stop and classify it
again under the entry rules above.

Replace only `DCO compliance` with integration ID `15368` by `DCO` with
integration ID `1861`. Preserve every other rule, parameter, bypass actor,
required check, and integration ID value-for-value. Read back the complete
ruleset, compare it with `rules-before.json` using existing JSON and diff
helpers, and require the DCO pair to be the only semantic change and the
resulting pair to be new-only. Before merging, confirm the new required check is
satisfied by the migration pull request's current applicable automated-success
result.

Merge the reviewed source change only after that readback. It removes
`.github/workflows/dco.yml` and `scripts/check-dco.sh`; the shared repository
checker's owner separately removes only `scripts/check-dco.sh` from its
executable-file list.

### 4. Complete the retained Dependabot recovery

After the DCO migration lands, refresh the retained Dependabot pull request
without rewriting its bot commit. Add the Cocogitto `command: check` correction
as a separate maintainer commit with a truthful matching sign-off. Record the
successful current-head `DCO` result from app ID `1861` for this mixed
bot/signed-human pull request.

This retained update is required to complete the owning issue. It is dependent
work after the DCO migration, not a prerequisite for merging the migration pull
request.

## Failure and no-op handling

- Wrong app ID, wrong account, broadened repository scope, lost unrelated
  selections, unapproved or unexpected permissions, or missing readback: stop
  before changing protection.
- Missing, stale, or differently originated `DCO` check: request a supported
  recheck, then stop and investigate the installation if it remains absent.
- An upstream fixture regression or unexpected real bot-only, signed-human, or
  mixed result: stop; do not compensate with a custom checker or manual
  approval.
- A relevant head, configuration, installation, registration, or rule change:
  invalidate only the dependent evidence and repeat it on the new state.
- No installation or settings authority, a pending approval-review gate,
  blocked supported UI access, or a protection mismatch: leave installation
  and protection unchanged and return the exact blocker. Separately authorized
  source preparation or publication may continue.
- An already-correct installation, selection, configuration, or required-check
  pair is a documented no-op only after verifying the complete desired state.
  Preserve it without mutation.

If an authorized manual exception is necessary, record the actor, reason,
check-run URL, and head SHA. The resulting success proves only manual approval.

## Completion receipts

Close the owning issue only with reviewable, secret-free receipts for:

- the source revision, reviewed upstream revision, and upstream fixture-suite
  result;
- public app registration ID, permissions, and events;
- exact selected repositories and approved installation permissions from a
  supported readback;
- absence of `.github/dco.yml` on the tested base;
- one current-head missing-signoff human failure from app ID `1861` for each
  affected repository, under the separately reviewed fixture protocol;
- current-head ordinary automated-success checks for the real bot-only pull
  request, signed-human migration pull request, and retained mixed
  bot/signed-human pull request;
- the recheck response and resulting ordinary automated-success check;
- complete ruleset readback before and after the required-check replacement;
  and
- any manual exception, failure, no-op, or rollback action.

## Scoped rollback

Rollback only `nisavid/sacrysty`. Restore the pinned local DCO workflow and
checker first, coordinate restoration of its executable-file policy entry, and
observe a passing `DCO compliance` check from integration `15368` on the
current head. Replace only the DCO required-check pair, read back the complete
rule, and confirm every unrelated control remains identical. Then remove only
`nisavid/sacrysty` from the app's selected repositories if this migration added
it. Never remove other repositories or the whole installation as a shortcut.
Record the corresponding registration, selection, check, and settings receipts.
