#!/usr/bin/env bash
set -euo pipefail

readonly expected_source_revision=001099750319aa47ca12b4e7466990577e9ced17
readonly expected_public_inputs_manifest=4fa2c5ba1f9795c9c6fb63f11e342702e6e22cd3225d94ad8dd4a8130685a574
readonly expected_primary_sources_manifest=7d20b934f9c5acda27e914336db0e01eed8693bf5253e8f42104f3df75214e8e

hash_file() {
  python3 -B - "$1" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

verify_digest() {
  local relative_path=$1
  local expected_digest=$2
  local observed_digest

  observed_digest=$(hash_file "$source_root/$relative_path")
  if [[ $observed_digest != "$expected_digest" ]]; then
    printf 'source digest mismatch for %s: expected %s, observed %s\n' \
      "$relative_path" "$expected_digest" "$observed_digest" >&2
    exit 1
  fi
}

main() {
  if (($# != 3)); then
    printf 'usage: %s SOURCE_ROOT RESULT_FILE EXPECTED_ARCH\n' "$0" >&2
    return 2
  fi

  local prerequisite
  for prerequisite in git mkdir python3 realpath uname; do
    if ! command -v "$prerequisite" >/dev/null; then
      printf 'required command is unavailable: %s\n' "$prerequisite" >&2
      return 2
    fi
  done

  local source_root=$1
  local result_file=$2
  local expected_arch=$3
  local script_path script_directory implementation_root
  local observed_source_revision source_status_before observed_arch
  local implementation_revision workflow_file workflow_file_digest
  local workflow_revision workflow_ref result_parent
  local resolved_result_parent resolved_source_root
  local normal_exit optimized_exit source_status_after clean_after

  script_path=$(realpath -- "${BASH_SOURCE[0]}")
  script_directory=${script_path%/*}
  implementation_root=$(realpath -- "$script_directory/../..")

  observed_source_revision=$(git -C "$source_root" rev-parse --verify "HEAD^{commit}")
  if [[ $observed_source_revision != "$expected_source_revision" ]]; then
    printf 'source revision mismatch: expected %s, observed %s\n' \
      "$expected_source_revision" "$observed_source_revision" >&2
    exit 1
  fi

  source_status_before=$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)
  if [[ -n $source_status_before ]]; then
    printf 'source checkout is not clean before checks\n' >&2
    exit 1
  fi

  verify_digest adapters/fido_custody.py \
    c8b3dcb5c1ce395393d10f4621cd4e478e1d08202485f41848943163a96ba690
  verify_digest adapters/fido-custody-v1.md \
    9d037a6ef9b84eaddf103cd05c9fc5bc336a5d393bcd0dc57fb01387c51a3c4d
  verify_digest conformance/check-fido-custody.py \
    3124257c09af05d7325d1ffb4cb5397456355591485b1739a39fcd2b94c397c1
  verify_digest conformance/test_support.py \
    45ff4ac487816dbe76652bf81f38ebd3caae89b1fd59ea16a3a094e8649ab067

  observed_arch=$(uname -m)
  if [[ $observed_arch != "$expected_arch" ]]; then
    printf 'runner architecture mismatch: expected %s, observed %s\n' \
      "$expected_arch" "$observed_arch" >&2
    exit 1
  fi

  if [[ ${GITHUB_ACTIONS:-} == true ]]; then
    if [[ ${RUNNER_ENVIRONMENT:-} != github-hosted ]]; then
      printf 'qualification requires a GitHub-hosted runner\n' >&2
      exit 1
    fi
    if [[ -z ${ImageOS:-} || -z ${ImageVersion:-} ]]; then
      printf 'runner image identity is unavailable\n' >&2
      exit 1
    fi
    if [[ ${RUNNER_OS:-} != "${SACRYSTY_EXPECTED_RUNNER_OS:-}" ||
      ${RUNNER_ARCH:-} != "${SACRYSTY_EXPECTED_RUNNER_ARCH:-}" ]]; then
      printf 'GitHub runner OS or architecture does not match the workflow matrix\n' >&2
      exit 1
    fi
  fi

  implementation_revision=$(git -C "$implementation_root" rev-parse --verify "HEAD^{commit}")
  workflow_file="$implementation_root/.github/workflows/fido-custody-qualification.yml"
  if [[ ! -f $workflow_file ]]; then
    printf 'workflow file is unavailable in the implementation checkout\n' >&2
    exit 1
  fi
  workflow_file_digest=$(hash_file "$workflow_file")
  workflow_revision=${SACRYSTY_WORKFLOW_SHA:-$implementation_revision}
  workflow_ref=${SACRYSTY_WORKFLOW_REF:-local}
  if [[ -n ${SACRYSTY_WORKFLOW_SHA:-} && $implementation_revision != "$workflow_revision" ]]; then
    printf 'implementation revision mismatch: workflow %s, checkout %s\n' \
      "$workflow_revision" "$implementation_revision" >&2
    exit 1
  fi
  if [[ $workflow_revision == "$expected_source_revision" ]]; then
    printf 'workflow implementation and frozen synthetic source must be distinct\n' >&2
    exit 1
  fi

  if [[ $result_file == */* ]]; then
    result_parent=${result_file%/*}
  else
    result_parent=.
  fi
  mkdir -p "$result_parent"
  resolved_result_parent=$(cd "$result_parent" && pwd -P)
  resolved_source_root=$(cd "$source_root" && pwd -P)
  if [[ $resolved_result_parent == "$resolved_source_root" ||
    $resolved_result_parent == "$resolved_source_root"/* ]]; then
    printf 'result storage must be outside the synthetic source checkout\n' >&2
    exit 1
  fi

  export PYTHONDONTWRITEBYTECODE=1
  set +e
  python3 -B "$source_root/conformance/check-fido-custody.py"
  normal_exit=$?
  python3 -B -O "$source_root/conformance/check-fido-custody.py"
  optimized_exit=$?
  set -e

  source_status_after=$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)
  if [[ -z $source_status_after ]]; then
    clean_after=true
  else
    clean_after=false
  fi

  python3 -B - \
    "$result_file" \
    "$workflow_revision" \
    "$workflow_ref" \
    "$workflow_file_digest" \
    "$implementation_revision" \
    "$observed_source_revision" \
    "$expected_arch" \
    "$observed_arch" \
    "$normal_exit" \
    "$optimized_exit" \
    "$clean_after" \
    "$expected_public_inputs_manifest" \
    "$expected_primary_sources_manifest" <<'PY'
import hashlib
import json
import os
import pathlib
import platform
import sys

(
    result_file,
    workflow_revision,
    workflow_ref,
    workflow_file_digest,
    implementation_revision,
    source_revision,
    expected_arch,
    observed_arch,
    normal_exit,
    optimized_exit,
    clean_after,
    public_inputs_manifest,
    primary_sources_manifest,
) = sys.argv[1:]

normal_exit = int(normal_exit)
optimized_exit = int(optimized_exit)
clean_after = clean_after == "true"
checks_passed = normal_exit == 0 and optimized_exit == 0 and clean_after
record = {
    "record_kind": "candidate-bound FIDO synthetic CI implementation evidence",
    "candidate_bound": True,
    "provisional": True,
    "outcome": "passed" if checks_passed else "failed",
    "workflow": {
        "revision": workflow_revision,
        "ref": workflow_ref,
        "file": ".github/workflows/fido-custody-qualification.yml",
        "file_sha256": workflow_file_digest,
        "implementation_revision": implementation_revision,
        "github_sha": os.environ.get("GITHUB_SHA", "local-unavailable"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local-unavailable"),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "local-unavailable"),
    },
    "source": {
        "revision": source_revision,
        "clean_before": True,
        "clean_after": clean_after,
        "sha256": {
            "adapters/fido_custody.py": "c8b3dcb5c1ce395393d10f4621cd4e478e1d08202485f41848943163a96ba690",
            "adapters/fido-custody-v1.md": "9d037a6ef9b84eaddf103cd05c9fc5bc336a5d393bcd0dc57fb01387c51a3c4d",
            "conformance/check-fido-custody.py": "3124257c09af05d7325d1ffb4cb5397456355591485b1739a39fcd2b94c397c1",
            "conformance/test_support.py": "45ff4ac487816dbe76652bf81f38ebd3caae89b1fd59ea16a3a094e8649ab067",
        },
    },
    "preparation_receipts": {
        "public_inputs_manifest_sha256": public_inputs_manifest,
        "primary_sources_manifest_sha256": primary_sources_manifest,
        "scope": "Referenced from the reviewed preparation; manifest bytes are not workflow inputs.",
    },
    "checks": {
        "normal_exit": normal_exit,
        "optimized_exit": optimized_exit,
    },
    "runner": {
        "expected_architecture": expected_arch,
        "observed_architecture": observed_arch,
        "runner_os": os.environ.get("RUNNER_OS", "local-unavailable"),
        "runner_arch": os.environ.get("RUNNER_ARCH", "local-unavailable"),
        "runner_environment": os.environ.get("RUNNER_ENVIRONMENT", "local"),
        "requested_label": os.environ.get("SACRYSTY_RUNNER_LABEL", "local-unavailable"),
        "image_os": os.environ.get("ImageOS", "unavailable"),
        "image_version": os.environ.get("ImageVersion", "unavailable"),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
    },
    "python": {
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "version_detail": sys.version,
        "executable_sha256": hashlib.sha256(pathlib.Path(sys.executable).read_bytes()).hexdigest(),
    },
    "limits": [
        "Synthetic workers only; no real JSON worker, age plugin, or age executable was selected or run.",
        "No native FIDO library, authenticator, PIN, biometric, provider, keychain, personal host, custody state, release signing, or production path was exercised.",
        "A passing result does not qualify genesis, a custody implementation, hardware, provider behavior, personal adoption, or production use.",
        "Local execution is not GitHub-hosted or macOS evidence.",
        "A relevant source, workflow, runtime, platform, architecture, or runner-image change invalidates this result.",
    ],
}
pathlib.Path(result_file).write_text(
    json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

  printf 'candidate-bound provisional result: %s\n' "$result_file"
  if ((normal_exit != 0 || optimized_exit != 0)) || [[ $clean_after != true ]]; then
    return 1
  fi
}

main "$@"
