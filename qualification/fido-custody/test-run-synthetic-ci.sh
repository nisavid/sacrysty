#!/usr/bin/env bash
set -euo pipefail

test_source_identity_rejection() {
  local output_file="$scratch_directory/source-identity-rejection.log"
  local result_file="$scratch_directory/source-identity-rejection.json"

  if bash "$runner" "$root_directory" "$result_file" x86_64 \
    >"$output_file" 2>&1; then
    printf 'expected a mismatched source revision to be rejected\n' >&2
    return 1
  fi
  grep -F \
    'source revision mismatch: expected d421a7a08b6e0973e60b54a3796a9c62642f7615' \
    "$output_file" >/dev/null
}

test_checker_failure_propagation() {
  local output_file="$scratch_directory/checker-failure.log"
  local result_file="$scratch_directory/checker-failure.json"
  local missing_temporary_root="$scratch_directory/missing"

  if TMPDIR="$missing_temporary_root" \
    bash "$runner" "$source_root" "$result_file" "$(uname -m)" \
    >"$output_file" 2>&1; then
    printf 'expected direct checker failures to fail the qualification run\n' >&2
    return 1
  fi
  grep -F 'RuntimeError: TMPDIR is unavailable' "$output_file" >/dev/null
  python3 -B - "$result_file" <<'PY'
import json
import pathlib
import sys

result = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert result["checks"] == {"normal_exit": 1, "optimized_exit": 1}
PY
}

test_imported_dependency_digest_rejection() {
  local controlled_source="$scratch_directory/controlled-source"
  local control_result="$scratch_directory/dependency-control.json"
  local mismatch_result="$scratch_directory/dependency-mismatch.json"
  local output_file="$scratch_directory/dependency-mismatch.log"
  local disposable_root="$scratch_directory/dependency-tmp"

  mkdir "$controlled_source" "$disposable_root"
  cp -R "$source_root/." "$controlled_source"
  TMPDIR="$disposable_root" \
    bash "$runner" "$controlled_source" "$control_result" "$(uname -m)"

  printf '\n' >>"$controlled_source/conformance/strict_json.py"
  if TMPDIR="$disposable_root" \
    bash "$runner" "$controlled_source" "$mismatch_result" "$(uname -m)" \
    >"$output_file" 2>&1; then
    printf 'expected a changed imported dependency to be rejected\n' >&2
    return 1
  fi
  grep -F \
    'source digest mismatch for conformance/strict_json.py:' \
    "$output_file" >/dev/null
  if [[ -e $mismatch_result ]]; then
    printf 'dependency mismatch must be rejected before checker execution\n' >&2
    return 1
  fi
}

test_successful_candidate_run_records_observations() {
  local result_file="$scratch_directory/success.json"
  local disposable_root="$scratch_directory/tmp"
  local workflow_file="$root_directory/.github/workflows/fido-custody-qualification.yml"

  mkdir "$disposable_root"
  TMPDIR="$disposable_root" \
    bash "$runner" "$source_root" "$result_file" "$(uname -m)"
  python3 -B - "$result_file" "$workflow_file" "$source_root" <<'PY'
import hashlib
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
workflow_path = pathlib.Path(sys.argv[2])
source_root = pathlib.Path(sys.argv[3])
result = json.loads(result_path.read_text(encoding="utf-8"))
expected_workflow_digest = hashlib.sha256(workflow_path.read_bytes()).hexdigest()
strict_json_path = source_root / "conformance/strict_json.py"
expected_strict_json_digest = hashlib.sha256(strict_json_path.read_bytes()).hexdigest()
assert result["outcome"] == "passed"
assert result["candidate_bound"] is True
assert result["provisional"] is True
assert result["checks"] == {"normal_exit": 0, "optimized_exit": 0}
assert result["source"]["clean_before"] is True
assert result["source"]["clean_after"] is True
assert result["source"]["sha256"]["conformance/strict_json.py"] == expected_strict_json_digest
assert result["workflow"]["file_sha256"] == expected_workflow_digest
assert result["runner"]["observed_architecture"] == result["runner"]["expected_architecture"]
assert result["python"]["implementation"]
assert result["python"]["version"]
PY
}

main() {
  if (($# != 1)); then
    printf 'usage: %s FROZEN_SOURCE_ROOT\n' "$0" >&2
    return 2
  fi
  if [[ -z ${TEST_TMPDIR:-} ]]; then
    printf 'TEST_TMPDIR must name writable disposable storage\n' >&2
    return 2
  fi

  local prerequisite script_path script_directory
  for prerequisite in bash cp grep mkdir mktemp python3 realpath rm uname; do
    if ! command -v "$prerequisite" >/dev/null; then
      printf 'required command is unavailable: %s\n' "$prerequisite" >&2
      return 2
    fi
  done

  script_path=$(realpath -- "${BASH_SOURCE[0]}")
  script_directory=${script_path%/*}
  root_directory=$(realpath -- "$script_directory/../..")
  runner="$root_directory/qualification/fido-custody/run-synthetic-ci.sh"
  source_root=$(realpath -- "$1")
  scratch_directory=$(mktemp -d "$TEST_TMPDIR/fido-qualification-tdd.XXXXXX")
  trap 'rm -rf -- "$scratch_directory"' EXIT

  test_source_identity_rejection
  test_checker_failure_propagation
  test_imported_dependency_digest_rejection
  test_successful_candidate_run_records_observations
  printf 'fido custody qualification runner tests passed\n'
}

main "$@"
