# Contributing to Sacrysty

Contributions should leave the public source reviewable, reproducible, and
explicit about what their evidence proves.

## Prepare a change

1. Link the issue that owns the change and claim it when the Wayfinder protocol
   applies.
2. Read `CONTEXT.md` and preserve the public/private ownership boundary.
3. Update normative source before derived fixtures, reference output, or
   documentation.
4. Use a Conventional Commit message.
5. Certify every human-authored commit under the
   [Developer Certificate of Origin 1.1](https://developercertificate.org/) by
   adding a sign-off whose name matches the commit author or committer name and
   whose email independently matches the author or committer email. Name and
   email comparisons are case-insensitive:

   ```sh
   git commit --signoff
   ```

   Repository members are subject to the same requirement as other human
   contributors, including for human-authored merge commits. The app's
   automated enforcement exempts commits with Bot-associated authors and
   ordinary merge commits. The sign-off records that you have the right to
   submit the contribution under this project's license; it is not a
   cryptographic release signature.

   The app recognizes `Signed-off-by: NAME <EMAIL>` trailer lines and compares
   the captured fields as described above. It does not separately establish
   that the captured email has general email-address syntax.

   This repository does not accept individual or third-party remediation
   commits. Amend or recreate your own unsigned commit and sign it off. Do not
   sign off another contributor's work unless the DCO truthfully permits you to
   submit it. A maintainer's signed follow-up certifies only that follow-up.
6. Run `./scripts/check-repository.sh`, `git diff --check`, and every focused
   test or conformance suite for the changed surface.

If Cocogitto is installed, `cog install-hook --all` installs the checked-in
commit-message and pre-push hooks.

## Scope and evidence

- Keep production keys, credentials, provider resources, host bindings,
  private configuration, and acceptance evidence out of the repository.
- Use disposable, value-free fixtures. Never test an undisclosed report against
  a live deployment.
- Bind qualification claims to exact implementations, interfaces, platforms,
  dependencies, profiles, fixtures, suites, and evidence.
- Describe a green check at the layer it exercised. Repository policy is not a
  release or deployment acceptance result.
- Do not split a distribution or adapter merely to mirror a directory. Show the
  dependency, privilege, platform, or release seam first.

## Pull requests

Use the pull-request template. State the outcome, owning boundary, authorizing
issue, provenance, compatibility effect, checks run, and whether the change has
any release, provider, host, ceremony, custody, or production authority.
Resolve review findings on the same final revision that carries the reported
evidence.

The maintained DCO GitHub App evaluates pull-request commits. Its `DCO` result
is the repository enforcement signal; a manual approval by someone with write
access is an explicit exception, not a replacement sign-off. Maintainers follow
`docs/agents/dco-provisioning.md` when provisioning or changing that check.
