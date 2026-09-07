#!/usr/bin/env bash

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$root"

required=(
  README.md
  AGENTS.md
  CONTEXT.md
  LICENSE
  NOTICE
  GOVERNANCE.md
  CONTRIBUTING.md
  CODE_OF_CONDUCT.md
  SECURITY.md
  CHANGELOG.md
  contracts/README.md
  src/README.md
  adapters/README.md
  profiles/README.md
  fixtures/README.md
  conformance/README.md
  qualification/README.md
  release/README.md
  docs/README.md
  docs/provenance/public-repository-handoff.md
)

missing=0
for path in "${required[@]}"; do
  if [[ ! -s "$path" ]]; then
    printf 'required repository file is missing or empty: %s\n' "$path" >&2
    missing=1
  fi
done
(( missing == 0 )) || exit 1

for path in scripts/check-repository.sh scripts/check-dco.sh .hooks/commit-msg.sh .hooks/pre-push.sh; do
  if [[ ! -x "$path" ]]; then
    printf 'required executable bit is missing: %s\n' "$path" >&2
    exit 1
  fi
done

unpinned=0
while IFS= read -r line; do
  if [[ ! "$line" =~ uses:[[:space:]]+[^[:space:]@]+@[0-9a-f]{40}([[:space:]]|$) ]]; then
    printf 'GitHub Action is not pinned to a full commit SHA: %s\n' "$line" >&2
    unpinned=1
  fi
done < <(grep -R -h -E '^[[:space:]]*uses:' .github/workflows || true)
(( unpinned == 0 )) || exit 1

if git grep -nI $'\r' -- . ':!LICENSE' ':!NOTICE'; then
  printf 'carriage returns found in tracked text\n' >&2
  exit 1
fi

printf 'repository policy checks passed\n'
