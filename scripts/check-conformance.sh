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

if ! source_status=$(git status --porcelain=v1 --untracked-files=all); then
  printf 'conformance evidence could not inspect source worktree\n' >&2
  exit 1
fi
if [[ -n $source_status ]]; then
  printf 'conformance evidence requires a clean worktree\n' >&2
  exit 1
fi

source_revision=$(git rev-parse HEAD)
temporary_root=$(sq_evidence_external_tmp_root "$root")
result_directory=$(mktemp -d "$temporary_root/sacrysty-conformance-results.XXXXXX")
result_directory_removal_permitted=1
cleanup_results() {
  if [[ -n ${result_directory:-} ]]; then
    if [[ -n ${result_directory_removal_permitted:-} ]]; then
      sq_evidence_remove_and_verify \
        "$result_directory" 'temporary conformance-result directory'
    else
      printf 'temporary conformance-result directory retained: %s\n' \
        "$result_directory" >&2
      return 1
    fi
  fi
}
trap cleanup_results EXIT

active_probe_supervisor=
active_probe_cancellation_marker=
active_probe_cancellation_requested=
aggregate_interrupted_status=
aggregate_signal_failure=
request_active_probe_cancellation() {
  if [[ -n $active_probe_cancellation_requested ]]; then
    return
  fi
  active_probe_cancellation_requested=1
  if ! : >"$active_probe_cancellation_marker"; then
    printf 'aggregate could not record probe cancellation\n' >&2
    aggregate_signal_failure=1
  fi
}
interrupt_aggregate() {
  local interrupted_status=$1
  if [[ -n $aggregate_interrupted_status ]]; then
    return
  fi
  aggregate_interrupted_status=$interrupted_status
  if [[ -z $active_probe_cancellation_marker ]]; then
    trap - INT TERM
    exit "$aggregate_interrupted_status"
  fi
  request_active_probe_cancellation
}
trap 'interrupt_aggregate 130' INT
trap 'interrupt_aggregate 143' TERM

printf 'source_revision=%s\n' "$source_revision"
./scripts/check-repository.sh
git diff --check
synthetic_check_count=0
while IFS= read -r synthetic_check || [[ -n $synthetic_check ]]; do
  if [[ ! $synthetic_check =~ ^conformance/[a-z0-9][a-z0-9-]*\.py$ ||
    ! -f $synthetic_check ]]; then
    printf 'invalid synthetic check manifest entry: %s\n' "$synthetic_check" >&2
    exit 1
  fi
  python3 -B "$synthetic_check"
  python3 -B -O "$synthetic_check"
  synthetic_check_count=$((synthetic_check_count + 1))
done <conformance/synthetic-checks.txt
if ((synthetic_check_count == 0)); then
  printf 'synthetic check manifest is empty\n' >&2
  exit 1
fi

run_and_admit_probe() {
  local kind=$1
  local runner=$2
  local output=$3
  local runner_stderr="${output}.stderr"
  local runner_status_file="${output}.status"
  local cleanup_receipt="${runner_status_file}.cleanup"
  local runner_status
  local supervisor_status
  active_probe_cancellation_marker="${runner_status_file}.cancel"
  active_probe_cancellation_requested=
  result_directory_removal_permitted=
  python3 -B "$SQ_EVIDENCE_PROCESS_HELPER" \
    probe "$runner_status_file" "$output" "$runner_stderr" -- "$runner" &
  active_probe_supervisor=$!
  if [[ -n $aggregate_interrupted_status ]]; then
    request_active_probe_cancellation
  fi
  if wait "$active_probe_supervisor"; then
    supervisor_status=0
  else
    supervisor_status=$?
  fi
  if [[ -n $aggregate_interrupted_status ]]; then
    # A trapped signal interrupts wait before the helper necessarily exits.
    # Re-wait so its process-group and nested-session cleanup completes first.
    trap '' INT TERM
    wait "$active_probe_supervisor" || :
    trap 'interrupt_aggregate 130' INT
    trap 'interrupt_aggregate 143' TERM
  fi
  active_probe_supervisor=
  if sq_evidence_consume_process_cleanup_receipt "$cleanup_receipt"; then
    result_directory_removal_permitted=1
  else
    aggregate_signal_failure=1
  fi
  active_probe_cancellation_marker=
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
