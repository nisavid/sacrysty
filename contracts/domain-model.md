# Public domain model

This document defines the public record boundary consumed by Sacrysty genesis.
It is normative for serialized public metadata; protocol, authority, custody,
and command semantics remain with their owning decisions.

## Records and ownership

Every public record is a closed, versioned envelope. `record_type` identifies
the record family and `schema_version` identifies the envelope schema. The
`body` is validated by the record family's schema before it is consumed.

| Record | Sacrysty owns | A system user owns |
| --- | --- | --- |
| `contract` | Contract identity, version, schema digest, and compatibility declaration | Local selection and deployment lock |
| `profile` | Profile schema and compatibility rules | Profile values, publisher choice, exact pins, and private bindings |
| `adapter` | Adapter-interface schema and metadata contract | Adapter selection and local installation |
| `qualification` | Qualification-record schema and public evidence format | Local acceptance and deployment evidence |
| `release` | Release metadata and immutable source/artifact references | Adoption and operational acceptance |

Public records may contain names, versions, digests, capabilities, URLs, and
value-free evidence. They never contain resolved secrets, private bindings,
provider payloads, host paths, authenticator identifiers, protected bootstrap
state, ceremony values, or production acceptance claims.

Writers emit one declared schema version. Readers accept only versions they
explicitly support. A migration creates a new record with a new digest and
retains the source identity; it never silently drops an unknown field or
enumeration value.

## Envelope

The normative envelope is `io.nisavid.sacrysty.public-record/v1` (see
`contracts/schemas/public-record-envelope-v1.schema.json`). Its required
fields are `record_type`, `schema_version`, `record_id`, `publisher`, and
`body`. `record_id` is publisher-qualified and stable for the record's
identity; a changed body receives a new `content_digest` and version.

The envelope is closed. Unknown top-level fields are rejected so a security or
authority-relevant value cannot be smuggled through an older reader. The body
is an object and is closed by its record-family schema.

## Inert extensions

Extensions are metadata only until a later decision defines an active
interface. They live in the `extensions` object and use a reverse-domain key
such as `example.invalid.audit`. Each value must have `state: "inert"`, a
string `version`, and an explicit `criticality` of `optional` or `required`.

An implementation that understands an optional extension may preserve and
report it, but must not execute it. An unknown optional extension is preserved
without changing the record's meaning. An unknown required extension is
rejected as unsupported. Any extension whose state is not `inert`, any
unnamespaced key, and any extension with an unsupported schema version is
rejected before parsing the record body. No extension can grant authority,
select an adapter, resolve a secret, or cause a provider or host mutation.

These rules make the extension surface forward-compatible for documentary
metadata while keeping activation impossible until a separate public decision,
interface, implementation, and qualification exist.

## Genesis handoff

Genesis consumes the envelope schema, record-family schemas, ownership table,
and hostile fixtures in this directory. It must bind its implementation and
validation to the immutable revision containing these files. Adapter work and
genesis integration start only after a fresh handoff revalidates the native
Wayfinder graph and coordinates with the conformance worker.
