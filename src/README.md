# Core implementation

This directory contains the non-operational library for the single root
`sacrysty` Cargo package, selected by the
[substrate decision](https://github.com/nisavid/sacrysty/issues/2#issuecomment-5568558765).

`lib.rs` has no public API or behavior. Add a thin `sacryd` entrypoint only when
a concrete helper needs it. Command grammar, schemas, authority semantics,
custody model, and protocol implementation remain with their owning design work.
