# ADR 0004: Publisher namespace and record identity

- **Status:** accepted for the pre-1.0 public contract through [publisher namespace implementation](https://github.com/nisavid/sacrysty/pull/34)
- **Owning issue:** [Establish Sacrysty's immutable public genesis](https://github.com/nisavid/sacrysty/issues/3)
- **Source decision:** [Publisher namespace decision](https://github.com/nisavid/sacrysty/issues/28#issuecomment-5916220812)

## Context and decision

This decision supersedes the publisher-relationship paragraph in
[ADR 0002](0002-genesis-integration-boundary.md#decision-proposed-for-review).

The public-record envelope already requires `publisher` and a qualified
`record_id`, but independent field grammars admit a record ID from an unrelated
namespace. `publisher` identifies the namespace owner. The qualifier before
the colon in `record_id` equals `publisher` or extends it at a dot boundary.

Unchanged redistribution preserves `publisher` and `record_id`. A different
publisher needs a new record ID. An unrelated qualifier or prefix lookalike is
invalid. This is an identity-consistency rule; it supplies no proof of
namespace control, signing authority, or release acceptance.

## Alternatives and boundary

Accepting any separately well-formed qualifier leaves the two identity fields
inconsistent. Requiring exact equality would reject existing record-family
qualifiers such as `io.nisavid.sacrysty.contract`. Dot-boundary extension keeps
that useful shape while excluding plain string-prefix matches.

The JSON Schema retains the existing grammar and structural checks. Its
supported subset cannot compare `publisher` with the `record_id` qualifier;
`envelope_admissible` performs that semantic check after schema validation.
Record-family body schemas remain separate and are not supplied by this change.

## Compatibility and migration

Canonical records whose qualifier already equals or extends their publisher
remain admissible with their existing IDs. Records with unrelated qualifiers
or prefix lookalikes become invalid even if their fields separately satisfy
the JSON Schema. Their publishers must issue new IDs in the proper namespace;
changing the publisher while keeping the old ID is invalid. A reader or
redistributor must not silently rewrite an accepted record or deployment lock.
Any affected adopter selection and qualification are separate work.

## Conformance and review

Value-free fixtures and the serialized checker cover equality, dot-boundary
extension, mismatch, and prefix lookalikes under normal and optimized Python.
The checks establish envelope admission only.

The renewed threat-model and affected security review was clean within the
publisher namespace scope on candidate
`724fc4fb65fed50f09d93896b8d744779a3d5106`; its report SHA-256 is
`d335d01803d817064fd42f8fc7f9cb849b55690e7b5240e4a42eecd599520722`.
I approved the namespace rule and proceeding to squash-merge once current
checks and feedback were clear, retaining the unresolved original macOS
cleanup cause as an open diagnostic follow-up. The published revision
[`9232530a16413242ea28bfb417138637b24b9768`](https://github.com/nisavid/sacrysty/commit/9232530a16413242ea28bfb417138637b24b9768)
has the reviewed tree `732b4037f0f0ada415950e8aeea55b1510fce323`.
This approval covers the publisher change. Genesis acceptance, any affected
adopter-lock update, and renewed affected qualification remain separate.
The successful unmodified macOS rerun establishes no causal cleanup repair.
