# Adapters

This directory is reserved for narrow adapter interfaces and maintained
reference adapters after an owning decision establishes a real variation seam.
An adapter must not become a source of generic semantics or production
authority.

Concrete adapter roles, capabilities, transports, custody boundaries, and
provider relationships follow their owning design tickets. Selection and
failure behavior follow the accepted
[core and adapter boundary](https://github.com/nisavid/dotfiles/issues/207#issuecomment-5470521497).
The [one-shot FIDO custody adapter v1](fido-custody-v1.md) is the first
value-free reference adapter. Its dependency and artifact inputs remain
explicitly pinned by the caller; real authenticator qualification and private
adopter bindings stay outside this repository.
