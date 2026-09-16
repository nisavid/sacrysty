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

active_probe_supervisor=
aggregate_interrupted_status=
aggregate_signal_failure=
interrupt_aggregate() {
  local interrupted_status=$1
  if [[ -n $aggregate_interrupted_status ]]; then
    return
  fi
  aggregate_interrupted_status=$interrupted_status
  if [[ -z $active_probe_supervisor ]]; then
    trap - INT TERM
    exit "$aggregate_interrupted_status"
  fi
  # Bash starts the asynchronous helper with SIGINT ignored. Use the helper's
  # handled termination signal for both caller interruption paths.
  if ! kill -s TERM "$active_probe_supervisor"; then
    printf 'aggregate could not signal its active probe supervisor\n' >&2
    aggregate_signal_failure=1
  fi
}
trap 'interrupt_aggregate 130' INT
trap 'interrupt_aggregate 143' TERM

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
python3 -B conformance/test-sq-evidence-process.py
python3 -B -O conformance/test-sq-evidence-process.py
python3 -B conformance/check-source-inventory.py
python3 -B -O conformance/check-source-inventory.py
python3 -B conformance/test-source-inventory.py
python3 -B -O conformance/test-source-inventory.py
python3 -B conformance/test-probe-result.py
python3 -B -O conformance/test-probe-result.py
python3 -B conformance/test-strict-json.py
python3 -B -O conformance/test-strict-json.py
python3 -B conformance/test-check-conformance.py
python3 -B -O conformance/test-check-conformance.py

run_and_admit_probe() {
  local kind=$1
  local runner=$2
  local output=$3
  local runner_stderr="${output}.stderr"
  local runner_status_file="${output}.status"
  local runner_status
  local supervisor_status
  python3 -B "$SQ_EVIDENCE_PROCESS_HELPER" \
    probe "$runner_status_file" "$output" "$runner_stderr" -- "$runner" &
  active_probe_supervisor=$!
  if wait "$active_probe_supervisor"; then
    supervisor_status=0
  else
    supervisor_status=$?
  fi
  if [[ -n $aggregate_interrupted_status ]]; then
    # A trapped signal interrupts wait before the helper necessarily exits.
    # Re-wait so its process-group and nested-session cleanup completes first.
    wait "$active_probe_supervisor" || :
  fi
  active_probe_supervisor=
  if [[ -s $runner_stderr ]]; then
    cat "$runner_stderr" >&2
  fi
  if [[ -n $aggregate_signal_failure ]]; then
    return 1
  fi
  if [[ -n $aggregate_interrupted_status ]]; then
    return "$aggregate_interrupted_status"
  fi
  if (( supervisor_status != 0 )); then
    return 1
  fi
  runner_status=$(sq_evidence_read_status "$runner_status_file")
  if [[ $runner_status -ne 0 ]]; then
    printf '%s probe exited with status %s\n' "$kind" "$runner_status" >&2
    return 1
  fi
  python3 -B conformance/check-probe-result.py \
    "$kind" "$output" "$source_revision"
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
