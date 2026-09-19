# Qualification

This directory records the qualification boundary for public, value-free tool
evidence. A result from `conformance/run-sq.sh` is a runtime observation bound
to one source revision and fixture digest, with self-reported `sq` and `sqv`
version text. Exact executable, platform, and dependency identity requires a
separate validation or qualification receipt. Neither artifact is a production
or adopter qualification.

A record must bind its claim to immutable inputs and state its limitations and
invalidation triggers. RFC 9580 support requires the positive `sq`/`sqv` round
trip and tamper rejection. This qualifies only the observed tool/runtime
combination and makes no project-wide support commitment. RFC 9980 remains
unqualified unless a backend-specific positive operation and independent round
trip are recorded. Tool, backend, platform, fixture, or protocol changes
invalidate the observation; the runner also refuses a dirty source tree so its
revision binding cannot silently describe uncommitted inputs.
