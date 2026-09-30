# ADR 0004: Publisher namespace and record identity

- **Status:** proposed for the pre-1.0 public contract; maintainer approval pending
- **Owning issue:** [Establish Sacrysty's immutable public genesis](https://github.com/nisavid/sacrysty/issues/3)
- **Source decision:** [Publisher namespace decision](https://github.com/nisavid/sacrysty/issues/28#issuecomment-5916220812)

## Context and decision

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
The checks establish envelope admission only. The repository-required
threat-model review is a separate bounded review of the final normative
revision. Its result, explicit maintainer approval, genesis acceptance, and
adopter-lock updates remain pending.
