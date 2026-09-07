# Outcome

<!-- State the capability, contract, or fix this change delivers. -->

## Boundary

- Owning surface:
- Authorizing issue:
- Release, provider, host, ceremony, custody, or production authority: none

## Provenance and compatibility

- Source decision or prior revision:
- Contract, profile, adapter, or deployment-lock effect:
- Migration or renewed qualification required:

## Validation

<!-- List exact checks run against the published revision and what they prove. -->

- [ ] `./scripts/check-repository.sh`
- [ ] `git diff --check`
- [ ] Focused tests, fixtures, and conformance checks for every affected surface
- [ ] DCO sign-off and Conventional Commit checks pass

## Review

- [ ] Public source and private deployment ownership remain separate.
- [ ] No secret, private binding, production identifier, or live-provider payload is present.
- [ ] Normative or security-boundary changes include the required ADR, threat review, conformance, and compatibility evidence.
- [ ] Claims are no broader than the evidence tied to this revision.
