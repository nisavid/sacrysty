#!/usr/bin/env bash
set -euo pipefail

test_ambient_python_packages_are_excluded() {
  local ambient_root="$scratch_directory/ambient-python"
  local adapters_marker="$scratch_directory/ambient-adapters-ran"
  local conformance_marker="$scratch_directory/ambient-conformance-ran"
  local sitecustomize_marker="$scratch_directory/ambient-sitecustomize-ran"
  local result_file="$scratch_directory/ambient-python-result.json"
  local disposable_root="$scratch_directory/ambient-python-tmp"

  mkdir -p "$ambient_root/adapters" "$ambient_root/conformance" "$disposable_root"
  cat >"$ambient_root/sitecustomize.py" <<'PY'
import os
import pathlib

pathlib.Path(os.environ["SACRYSTY_SITECUSTOMIZE_MARKER"]).write_text(
    "ran", encoding="ascii"
)
PY
  cat >"$ambient_root/adapters/__init__.py" <<'PY'
import os
import pathlib

pathlib.Path(os.environ["SACRYSTY_ADAPTERS_MARKER"]).write_text(
    "ran", encoding="ascii"
)
PY
  cat >"$ambient_root/conformance/__init__.py" <<'PY'
import os
import pathlib

pathlib.Path(os.environ["SACRYSTY_CONFORMANCE_MARKER"]).write_text(
    "ran", encoding="ascii"
)
PY
  cp "$source_root/adapters/fido_custody.py" \
    "$ambient_root/adapters/fido_custody.py"
  cp "$source_root/conformance/test_support.py" \
    "$ambient_root/conformance/test_support.py"

  PYTHONPATH="$ambient_root" \
    SACRYSTY_ADAPTERS_MARKER="$adapters_marker" \
    SACRYSTY_CONFORMANCE_MARKER="$conformance_marker" \
    SACRYSTY_SITECUSTOMIZE_MARKER="$sitecustomize_marker" \
    TMPDIR="$disposable_root" \
    bash "$runner" "$source_root" "$result_file" "$(uname -m)"

  local marker
  for marker in \
    "$adapters_marker" \
    "$conformance_marker" \
    "$sitecustomize_marker"; do
    if [[ -e $marker ]]; then
      printf 'ambient Python startup or package code ran: %s\n' "$marker" >&2
      return 1
    fi
  done

  python3 -I -S -B - "$result_file" <<'PY'
import json
import pathlib
import sys

result = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
assert result["outcome"] == "passed"
assert result["checks"] == {"normal_exit": 0, "optimized_exit": 0}
PY
}

test_failed_preflight_invalidates_reused_results() {
  local output_file="$scratch_directory/reused-result-preflight.log"
  local regular_result="$scratch_directory/reused-regular.json"
  local symlink_result="$scratch_directory/reused-symlink.json"
  local symlink_target="$scratch_directory/reused-symlink-target"
  local symlink_expected="$scratch_directory/reused-symlink-expected"
  local hardlink_result="$scratch_directory/reused-hardlink.json"
  local hardlink_target="$scratch_directory/reused-hardlink-target"
  local hardlink_expected="$scratch_directory/reused-hardlink-expected"

  printf '{"outcome":"passed","stale":true}\n' >"$regular_result"
  if bash "$runner" "$root_directory" "$regular_result" x86_64 \
    >"$output_file" 2>&1; then
    printf 'expected a mismatched source revision to be rejected\n' >&2
    return 1
  fi
  grep -F \
    'source revision mismatch: expected a05ca4ca1d2deb49cd47842d24da7692cb0ae9bd' \
    "$output_file" >/dev/null
  if [[ -e $regular_result || -L $regular_result ]]; then
    printf 'failed preflight retained a reused regular result\n' >&2
    return 1
  fi

  printf 'symlink target must remain unchanged\n' >"$symlink_target"
  printf 'symlink target must remain unchanged\n' >"$symlink_expected"
  ln -s "$symlink_target" "$symlink_result"
  if bash "$runner" "$root_directory" "$symlink_result" x86_64 \
    >"$output_file" 2>&1; then
    printf 'expected a mismatched source revision to be rejected\n' >&2
    return 1
  fi
  if [[ -e $symlink_result || -L $symlink_result ]]; then
    printf 'failed preflight retained a reused symbolic-link result\n' >&2
    return 1
  fi
  if ! cmp -s "$symlink_expected" "$symlink_target"; then
    printf 'failed preflight modified a symbolic-link target\n' >&2
    return 1
  fi

  printf 'hard-link target must remain unchanged\n' >"$hardlink_target"
  printf 'hard-link target must remain unchanged\n' >"$hardlink_expected"
  ln "$hardlink_target" "$hardlink_result"
  if bash "$runner" "$root_directory" "$hardlink_result" x86_64 \
    >"$output_file" 2>&1; then
    printf 'expected a mismatched source revision to be rejected\n' >&2
    return 1
  fi
  if [[ -e $hardlink_result || -L $hardlink_result ]]; then
    printf 'failed preflight retained a reused hard-link result\n' >&2
    return 1
  fi
  if ! cmp -s "$hardlink_expected" "$hardlink_target"; then
    printf 'failed preflight modified a hard-link target\n' >&2
    return 1
  fi
}

test_source_contained_result_request_preserves_source() {
  local controlled_source="$scratch_directory/contained-result-source"
  local existing_result="$controlled_source/existing-result.json"
  local expected_result="$scratch_directory/contained-result-expected"
  local missing_result="$controlled_source/missing/result.json"
  local output_file="$scratch_directory/contained-result.log"
  local status_before status_after

  mkdir "$controlled_source"
  cp -R "$source_root/." "$controlled_source"
  printf '{"outcome":"passed","stale":true}\n' >"$existing_result"
  printf '{"outcome":"passed","stale":true}\n' >"$expected_result"
  status_before=$(git -C "$controlled_source" status --porcelain=v1 --untracked-files=all)

  if bash "$runner" "$controlled_source" "$existing_result" "$(uname -m)" \
    >"$output_file" 2>&1; then
    printf 'expected source-contained result storage to be rejected\n' >&2
    return 1
  fi
  grep -F \
    'result storage must be outside the synthetic source checkout' \
    "$output_file" >/dev/null
  if ! cmp -s "$expected_result" "$existing_result"; then
    printf 'invalid result request deleted or changed a source-contained file\n' >&2
    return 1
  fi

  if bash "$runner" "$controlled_source" "$missing_result" "$(uname -m)" \
    >"$output_file" 2>&1; then
    printf 'expected missing source-contained result storage to be rejected\n' >&2
    return 1
  fi
  grep -F \
    'result storage must be outside the synthetic source checkout' \
    "$output_file" >/dev/null
  if [[ -e ${missing_result%/*} ]]; then
    printf 'invalid result request created a directory in the source checkout\n' >&2
    return 1
  fi

  status_after=$(git -C "$controlled_source" status --porcelain=v1 --untracked-files=all)
  if [[ $status_after != "$status_before" ]]; then
    printf 'invalid result requests changed the controlled source checkout\n' >&2
    return 1
  fi
}

test_source_identity_rejection() {
  local output_file="$scratch_directory/source-identity-rejection.log"
  local result_file="$scratch_directory/source-identity-rejection.json"

  if bash "$runner" "$root_directory" "$result_file" x86_64 \
    >"$output_file" 2>&1; then
    printf 'expected a mismatched source revision to be rejected\n' >&2
    return 1
  fi
  grep -F \
    'source revision mismatch: expected a05ca4ca1d2deb49cd47842d24da7692cb0ae9bd' \
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
  python3 -I -S -B - "$result_file" <<'PY'
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

  local dependency
  for dependency in \
    adapters/fido_custody.py \
    adapters/fido-custody-v1.md \
    conformance/check-fido-custody.py \
    conformance/test_support.py \
    sacrysty_runtime/__init__.py \
    sacrysty_runtime/process_groups.py \
    sacrysty_runtime/strict_json.py; do
    printf '\n' >>"$controlled_source/$dependency"
    if TMPDIR="$disposable_root" \
      bash "$runner" "$controlled_source" "$mismatch_result" "$(uname -m)" \
      >"$output_file" 2>&1; then
      printf 'expected a changed imported dependency to be rejected\n' >&2
      return 1
    fi
    grep -F \
      "source digest mismatch for $dependency:" \
      "$output_file" >/dev/null
    if [[ -e $mismatch_result || -L $mismatch_result ]]; then
      printf 'dependency mismatch must be rejected before checker execution\n' >&2
      return 1
    fi
    cp "$source_root/$dependency" "$controlled_source/$dependency"
  done
}

test_result_links_do_not_mutate_source() {
  local controlled_source="$scratch_directory/linked-result-source"
  local result_directory="$scratch_directory/linked-result-output"
  local disposable_root="$scratch_directory/linked-result-tmp"
  local symlink_result="$result_directory/symlink-result.json"
  local symlink_target="$controlled_source/sacrysty_runtime/strict_json.py"
  local hardlink_result="$result_directory/hardlink-result.json"
  local hardlink_target="$controlled_source/conformance/test_support.py"

  mkdir "$controlled_source" "$result_directory" "$disposable_root"
  cp -R "$source_root/." "$controlled_source"

  ln -s "$symlink_target" "$symlink_result"
  TMPDIR="$disposable_root" \
    bash "$runner" "$controlled_source" "$symlink_result" "$(uname -m)"
  if [[ -L $symlink_result ]]; then
    printf 'result writing followed an existing symlink\n' >&2
    return 1
  fi
  if ! cmp -s "$source_root/sacrysty_runtime/strict_json.py" "$symlink_target"; then
    printf 'result writing modified a symlinked source file\n' >&2
    return 1
  fi

  ln "$hardlink_target" "$hardlink_result"
  TMPDIR="$disposable_root" \
    bash "$runner" "$controlled_source" "$hardlink_result" "$(uname -m)"
  if [[ $hardlink_result -ef $hardlink_target ]]; then
    printf 'result writing retained a hard link to a source file\n' >&2
    return 1
  fi
  if ! cmp -s "$source_root/conformance/test_support.py" "$hardlink_target"; then
    printf 'result writing modified a hard-linked source file\n' >&2
    return 1
  fi
  if [[ -n $(git -C "$controlled_source" status --porcelain=v1 --untracked-files=all) ]]; then
    printf 'linked result writing left the controlled source dirty\n' >&2
    return 1
  fi

  python3 -I -S -B - "$symlink_result" "$hardlink_result" <<'PY'
import json
import pathlib
import sys

for result_path in map(pathlib.Path, sys.argv[1:]):
    result = json.loads(result_path.read_text(encoding="utf-8"))
    assert result["outcome"] == "passed"
    assert result["source"]["clean_after"] is True
PY
}

test_successful_candidate_run_records_observations() {
  local result_file="$scratch_directory/success.json"
  local disposable_root="$scratch_directory/tmp"
  local workflow_file="$root_directory/.github/workflows/fido-custody-qualification.yml"

  mkdir "$disposable_root"
  TMPDIR="$disposable_root" \
    bash "$runner" "$source_root" "$result_file" "$(uname -m)"
  python3 -I -S -B - "$result_file" "$workflow_file" "$source_root" <<'PY'
import hashlib
import json
import pathlib
import sys

result_path = pathlib.Path(sys.argv[1])
workflow_path = pathlib.Path(sys.argv[2])
source_root = pathlib.Path(sys.argv[3])
result = json.loads(result_path.read_text(encoding="utf-8"))
expected_workflow_digest = hashlib.sha256(workflow_path.read_bytes()).hexdigest()
expected_inputs = {
    "adapters/fido_custody.py",
    "adapters/fido-custody-v1.md",
    "conformance/check-fido-custody.py",
    "conformance/test_support.py",
    "sacrysty_runtime/__init__.py",
    "sacrysty_runtime/process_groups.py",
    "sacrysty_runtime/strict_json.py",
}
assert set(result["source"]["sha256"]) == expected_inputs
for relative_path in expected_inputs:
    expected_digest = hashlib.sha256((source_root / relative_path).read_bytes()).hexdigest()
    assert result["source"]["sha256"][relative_path] == expected_digest
assert result["source"]["revision"] == "a05ca4ca1d2deb49cd47842d24da7692cb0ae9bd"
assert result["outcome"] == "passed"
assert result["candidate_bound"] is True
assert result["provisional"] is True
assert result["checks"] == {"normal_exit": 0, "optimized_exit": 0}
assert result["source"]["clean_before"] is True
assert result["source"]["clean_after"] is True
assert result["workflow"]["file_sha256"] == expected_workflow_digest
preparation = result["preparation_receipts"]
assert preparation["file"] == "qualification/fido-custody/preparation-2026-09-16.md"
preparation_path = workflow_path.parents[2] / preparation["file"]
assert preparation["file_sha256"] == hashlib.sha256(preparation_path.read_bytes()).hexdigest()
assert preparation["historical_manifest_bytes"] == "unavailable"
assert "public_inputs_manifest_sha256" not in preparation
assert "primary_sources_manifest_sha256" not in preparation
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
  for prerequisite in bash cmp cp git grep ln mkdir mktemp python3 realpath rm uname; do
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

  test_ambient_python_packages_are_excluded
  test_failed_preflight_invalidates_reused_results
  test_source_contained_result_request_preserves_source
  test_result_links_do_not_mutate_source
  test_source_identity_rejection
  test_checker_failure_propagation
  test_imported_dependency_digest_rejection
  test_successful_candidate_run_records_observations
  printf 'fido custody qualification runner tests passed\n'
}

main "$@"
