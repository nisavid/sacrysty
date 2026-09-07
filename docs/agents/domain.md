# Domain documentation

This is a single-context repository. Read root `CONTEXT.md` for accepted names
and the ownership crosswalk. System-wide architectural decisions live under
`docs/adr/`; reusable contract sources will live under `contracts/` after their
owning decisions settle them.

Do not introduce a second bounded context merely to mirror an adapter or
directory. Record a real ownership, privilege, platform, dependency, or
release-cadence seam first.
