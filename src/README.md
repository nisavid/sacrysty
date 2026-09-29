# Core implementation

This directory contains the non-operational library for the single root
`sacrysty` Cargo package, selected by the
[substrate decision](https://github.com/nisavid/sacrysty/issues/2#issuecomment-5568558765).

`lib.rs` has no public API or behavior. The public-record envelope schema is
settled, but record-family body schemas are not supplied. Add a thin `sacryd`
entrypoint only when a concrete helper needs it. Command grammar, authority
semantics, custody behavior, and protocol implementation remain with their
owning design work.
