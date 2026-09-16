#!/usr/bin/env bash

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd "$root"
source "$root/conformance/sq-evidence-lib.sh"

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

source_revision=$(git rev-parse HEAD)
temporary_root=$(sq_evidence_external_tmp_root "$root")
result_directory=$(mktemp -d "$temporary_root/sacrysty-conformance-results.XXXXXX")
cleanup_results() {
  if [[ -n ${result_directory:-} ]]; then
    sq_evidence_remove_and_verify \
      "$result_directory" 'temporary conformance-result directory'
  fi
}
trap cleanup_results EXIT

printf 'source_revision=%s\n' "$source_revision"
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
python3 -B conformance/test-run-signing-profile.py
python3 -B -O conformance/test-run-signing-profile.py
python3 -B conformance/check-source-inventory.py
python3 -B -O conformance/check-source-inventory.py
python3 -B conformance/test-source-inventory.py
python3 -B -O conformance/test-source-inventory.py
python3 -B conformance/test-probe-result.py
python3 -B -O conformance/test-probe-result.py
python3 -B conformance/test-check-conformance.py
python3 -B -O conformance/test-check-conformance.py

run_and_admit_probe() {
  local kind=$1
  local runner=$2
  local output=$3
  local runner_status
  set +e
  "$runner" >"$output"
  runner_status=$?
  set -e
  python3 -B conformance/check-probe-result.py \
    "$kind" "$output" "$source_revision"
  if [[ $runner_status -ne 0 ]]; then
    printf '%s probe exited with status %s\n' "$kind" "$runner_status" >&2
    return 1
  fi
  cat -- "$output"
}

if [[ $mode == complete ]]; then
  run_and_admit_probe \
    crypto-conformance ./conformance/run-sq.sh "$result_directory/run-sq.json"
  run_and_admit_probe \
    signing-profile ./conformance/run-signing-profile.sh \
    "$result_directory/run-signing-profile.json"
else
  printf 'crypto-tool probes not run: synthetic-only mode\n'
fi

removed_result_directory=$result_directory
if ! cleanup_results || [[ -e $removed_result_directory ]]; then
  exit 1
fi
result_directory=
trap - EXIT
printf '%s conformance checks passed\n' "$mode"
