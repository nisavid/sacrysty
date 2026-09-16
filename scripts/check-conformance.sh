#!/usr/bin/env bash

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$root"

mode=complete
if [[ $# -eq 1 && $1 == --synthetic-only ]]; then
  mode=synthetic
elif [[ $# -ne 0 ]]; then
  printf 'usage: %s [--synthetic-only]\n' "$0" >&2
  exit 64
fi

if [[ -n $(git status --porcelain=v1 --untracked-files=all) ]]; then
  printf 'conformance evidence requires a clean worktree\n' >&2
  exit 1
fi

printf 'source_revision=%s\n' "$(git rev-parse HEAD)"
./scripts/check-repository.sh
git diff --check
python3 -B conformance/check-domain-model.py
python3 -B -O conformance/check-domain-model.py
python3 -B conformance/test-domain-model.py
python3 -B -O conformance/test-domain-model.py
python3 -B conformance/check-fido-custody.py
python3 -B -O conformance/check-fido-custody.py
python3 -B conformance/test-run-sq.py
python3 -B -O conformance/test-run-sq.py

if [[ $mode == complete ]]; then
  ./conformance/run-sq.sh
  ./conformance/run-signing-profile.sh
else
  printf 'crypto-tool probes not run: synthetic-only mode\n'
fi

printf '%s conformance checks passed\n' "$mode"
