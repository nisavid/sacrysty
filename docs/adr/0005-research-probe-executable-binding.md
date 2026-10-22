# ADR 0005: Bind research probe execution to sealed verified bytes

- **Status:** implemented for review; maintainer authorized the scoped fix and tests
- **Owning issue:** [Retained FIDO probe can execute different bytes than it hashes](https://linear.app/nisavid/issue/IDV-2094)
- **Scope:** the retained FIDO interface research probe only

## Context and decision

The probe hashed a file descriptor, closed it, then executed the original path
twice. Another principal able to replace that directory entry could substitute
a program and restore the expected bytes before the final pathname hash.
Before/after digests therefore did not establish executable identity.

The recorded artifact is Linux/amd64. Copy it from one non-following,
nonblocking source descriptor into a private Linux memfd, checking both the
initial regular/executable-file premise and the actual copied-byte limit.
Seal the snapshot against writes, growth, shrinkage, and seal changes before
hashing it. Admit only the pinned digest. Keep the descriptor open for both
launches and execute through `/proc/self/fd` with explicit descriptor inheritance.
Close it during finalization. Missing sealing support, denied sealing, or denied
descriptor execution fails closed without executing the original pathname.

## Alternatives and threat-model impact

Retaining the original descriptor alone does not prevent changes through another
descriptor or hard link. A private on-disk copy would require a trusted staging
namespace and protection against replacement of every ancestor. A sealed memfd
protects both the object identity and its bytes without introducing that new
filesystem trust assumption. Source changes while copying must still produce
the exact pinned digest after sealing or admission fails.

The attacker model excludes control of the probe process, kernel, and operator
identity. The output directory and its ancestor namespace remain trusted: they
hold the synthetic plugin, identity, and traces. This change does not establish
native-loader closure, plugin authenticity, process-group containment, hardware
qualification, or production authority. The separate process-group ownership
finding is outside this increment.

## Compatibility and historical evidence

The two absolute CLI arguments, fixed age digest, fresh output requirement,
synthetic protocol, stream/time limits, and cleanup behavior remain. Reruns now
require Linux file sealing and executable `/proc/self/fd` support. The pinned
Linux/amd64 artifact already excludes a macOS execution claim; no portable
fallback is promised.

New observations use schema `sacrysty-age-interface-probe-v3`. Digest premises
describe the sealed executed object, with an explicit sealed-executable premise
and binding/digest record. A later source-path change does not invalidate the
snapshot. Consumers needing v2 observations must not relabel v3 output.

The original receipt and observations remain byte-for-byte unchanged. The
research document links the original script and inventory at immutable revision
`42be6287db9bfdd2e938c03e825e44ab463ee7cb`; the current inventory identifies the
maintained script. No new execution of the historical age artifact is claimed.
No production deployment or adopter lock is modified.

## Conformance and review

The owning synthetic suite executes disposable scripts and a native executable
from the sealed object. It exercises both launches, source replacement and
restoration, same-inode writes, symlinks, ancestor replacement, unlinking,
seal enforcement, size/digest/premise rejection, partial writes, failure cleanup,
and unavailable execution support. A constructed trace producer exercises the
main routine and v3 receipt; it is not an age protocol implementation.

Independent boundary investigation identified same-inode writes and historical
evidence attribution as required parts of the fix. Candidate review and final
validation results belong in the owning issue; merge approval and any new
artifact qualification remain separate.
