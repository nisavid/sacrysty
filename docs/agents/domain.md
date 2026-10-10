# Domain documentation

This is a single-context repository. Read root `GLOSSARY.md` for accepted names
and `CONTEXT.md` for the source-level crosswalk, ownership, and current stage.
System-wide architectural decisions live under
`docs/adr/`; settled reusable public contract sources live under `contracts/`.
The current checker admits only the closed public-record envelope and inert
extensions. Record-family body schemas remain absent and unvalidated.

Do not introduce a second bounded context merely to mirror an adapter or
directory. Record a real ownership, privilege, platform, dependency, or
release-cadence seam first.
