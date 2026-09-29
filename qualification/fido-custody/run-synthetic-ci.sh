#!/usr/bin/env bash
set -euo pipefail

readonly expected_source_revision=81896a0c9f0b5af4f8c7e69e7d48da34e8e91318
readonly checker_launcher='import importlib
import importlib.machinery
import pathlib
import runpy
import sys
import types

root = pathlib.Path(sys.argv[1]).resolve()
sys.path.insert(0, str(root))
for package_name in ("adapters", "conformance"):
    package_path = root / package_name
    package_spec = importlib.machinery.ModuleSpec(
        package_name,
        loader=None,
        is_package=True,
    )
    package_spec.submodule_search_locations = [str(package_path)]
    package = types.ModuleType(package_name)
    package.__package__ = package_name
    package.__path__ = [str(package_path)]
    package.__spec__ = package_spec
    sys.modules[package_name] = package
expected_modules = {
    "adapters.fido_custody": "adapters/fido_custody.py",
    "conformance.test_support": "conformance/test_support.py",
    "sacrysty_runtime": "sacrysty_runtime/__init__.py",
    "sacrysty_runtime.process_groups": "sacrysty_runtime/process_groups.py",
    "sacrysty_runtime.strict_json": "sacrysty_runtime/strict_json.py",
}
for module_name, relative_path in expected_modules.items():
    module = importlib.import_module(module_name)
    module_file = getattr(module, "__file__", None)
    if module_file is None:
        raise RuntimeError(f"project module origin unavailable: {module_name}")
    observed_path = pathlib.Path(module_file).resolve()
    expected_path = (root / relative_path).resolve()
    if observed_path != expected_path:
        raise RuntimeError(
            f"project module origin mismatch for {module_name}: "
            f"expected {expected_path}, observed {observed_path}"
        )
runpy.run_path(
    str(root / "conformance/check-fido-custody.py"),
    run_name="__main__",
)
'

hash_file() {
  "$python_executable" -I -S -B - "$1" <<'PY'
import hashlib
import pathlib
import sys

print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())
PY
}

canonicalize_path() {
  "$python_executable" -I -S -B - "$1" <<'PY'
import pathlib
import sys

print(pathlib.Path(sys.argv[1]).resolve(strict=False))
PY
}

invalidate_result_entry() {
  "$python_executable" -I -S -B - "$1" <<'PY'
import os
import stat
import sys

result_path = sys.argv[1]
try:
    status = os.lstat(result_path)
except FileNotFoundError:
    raise SystemExit(0)
if stat.S_ISDIR(status.st_mode):
    print("result file path is an existing directory", file=sys.stderr)
    raise SystemExit(1)
try:
    os.unlink(result_path)
except FileNotFoundError:
    pass
except IsADirectoryError:
    print("result file path is an existing directory", file=sys.stderr)
    raise SystemExit(1)
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

select_native_cpython() {
  local requested=$1
  local resolved magic

  if [[ $requested != /* ]]; then
    printf 'Python executable selection must be absolute\n' >&2
    return 2
  fi
  if ! resolved=$(realpath -- "$requested"); then
    printf 'Python executable selection cannot be resolved\n' >&2
    return 2
  fi
  if [[ ! -f $resolved || ! -x $resolved ]]; then
    printf 'Python executable selection must name an executable regular file\n' >&2
    return 2
  fi
  if ! magic=$(LC_ALL=C od -An -N4 -tx1 "$resolved" | tr -d '[:space:]'); then
    printf 'Python executable selection cannot be inspected\n' >&2
    return 2
  fi
  case $magic in
    7f454c46 | cafebabe | bebafeca | cafebabf | bfbafeca | feedface | cefaedfe | feedfacf | cffaedfe)
      ;;
    *)
      printf 'selected Python executable must be a native ELF or Mach-O file\n' >&2
      return 2
      ;;
  esac

  if ! "$resolved" -I -S -B - "$resolved" <<'PY'; then
import pathlib
import platform
import sys

selected = pathlib.Path(sys.argv[1]).resolve(strict=True)
invoked = pathlib.Path(sys.executable).resolve(strict=True)
if platform.python_implementation() != "CPython":
    raise RuntimeError("selected executable is not CPython")
if invoked != selected:
    raise RuntimeError(
        f"selected executable identity mismatch: selected {selected}, invoked {invoked}"
    )
PY
    printf 'selected native executable must directly identify as CPython\n' >&2
    return 2
  fi

  printf '%s\n' "$resolved"
}

main() {
  if (($# != 4)); then
    printf 'usage: %s SOURCE_ROOT RESULT_FILE EXPECTED_ARCH PYTHON_EXECUTABLE\n' "$0" >&2
    return 2
  fi

  local prerequisite
  for prerequisite in git mkdir od realpath tr uname; do
    if ! command -v "$prerequisite" >/dev/null; then
      printf 'required command is unavailable: %s\n' "$prerequisite" >&2
      return 2
    fi
  done

  local source_root=$1
  local result_file=$2
  local expected_arch=$3
  local python_executable
  local script_path script_directory implementation_root
  local observed_source_revision source_status_before observed_arch
  local implementation_revision workflow_file workflow_file_digest preparation_digest
  local workflow_revision workflow_ref result_parent result_name
  local prospective_result_parent resolved_result_parent resolved_result_file
  local resolved_source_root
  local normal_exit optimized_exit source_status_after clean_after

  if ! python_executable=$(select_native_cpython "$4"); then
    return 2
  fi

  script_path=$(realpath -- "${BASH_SOURCE[0]}")
  script_directory=${script_path%/*}
  implementation_root=$(realpath -- "$script_directory/../..")

  if [[ ! -d $source_root ]]; then
    printf 'source root must name an existing directory\n' >&2
    return 2
  fi
  resolved_source_root=$(cd "$source_root" && pwd -P)

  if [[ $result_file == */* ]]; then
    result_parent=${result_file%/*}
  else
    result_parent=.
  fi
  result_name=${result_file##*/}
  if [[ -z $result_name || $result_name == . || $result_name == .. ]]; then
    printf 'result file must name a file within its parent directory\n' >&2
    exit 1
  fi

  prospective_result_parent=$(canonicalize_path "$result_parent")
  if [[ $prospective_result_parent == "$resolved_source_root" ||
    $prospective_result_parent == "$resolved_source_root"/* ]]; then
    printf 'result storage must be outside the synthetic source checkout\n' >&2
    exit 1
  fi
  mkdir -p "$result_parent"
  resolved_result_parent=$(cd "$result_parent" && pwd -P)
  if [[ $resolved_result_parent == "$resolved_source_root" ||
    $resolved_result_parent == "$resolved_source_root"/* ]]; then
    printf 'result storage must be outside the synthetic source checkout\n' >&2
    exit 1
  fi
  resolved_result_file="$resolved_result_parent/$result_name"
  invalidate_result_entry "$resolved_result_file"

  source_root=$resolved_source_root
  observed_source_revision=$(git -C "$source_root" rev-parse --verify "HEAD^{commit}")
  if [[ $observed_source_revision != "$expected_source_revision" ]]; then
    printf 'source revision mismatch: expected %s, observed %s\n' \
      "$expected_source_revision" "$observed_source_revision" >&2
    exit 1
  fi

  verify_digest adapters/fido-custody-v1.md \
    3a2a8c4262c1a1876a596f9032b71bf9c7f4e08bb786c8eb980c8d691f71ad3c
  verify_digest adapters/fido_custody.py \
    93ad77be96df82d69f79d2016dcbaa2e113e34c24097776ac3c5d318d4b87eb7
  verify_digest conformance/check-fido-custody.py \
    1018646728e43f14f566c06efc1e89789d93e81bbd913d94a356579fc463f571
  verify_digest conformance/test_support.py \
    53f8a6c30422031342ed47215ac5d9b91c0f1ab8d55defc306fdeb28e3cd1692
  verify_digest sacrysty_runtime/__init__.py \
    9a544524cda604a26f6451e1f81c14450d6e027487c5b6ee02401dfd24b8acf0
  verify_digest sacrysty_runtime/process_groups.py \
    024fe15f456e884b0be14060b2b08dc1a7873eecbf3a2257a9b0e86a105a4662
  verify_digest sacrysty_runtime/strict_json.py \
    6ac33fd9ea97c03b5a0dcb24a62cab599dc6fbf58703f343f96c48e3d526d79e

  source_status_before=$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)
  if [[ -n $source_status_before ]]; then
    printf 'source checkout is not clean before checks\n' >&2
    exit 1
  fi

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
  preparation_digest=$(hash_file "$script_directory/preparation-2026-09-16.md")
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

  export PYTHONDONTWRITEBYTECODE=1
  set +e
  "$python_executable" -I -S -B -c "$checker_launcher" "$source_root"
  normal_exit=$?
  "$python_executable" -I -S -B -O -c "$checker_launcher" "$source_root"
  optimized_exit=$?
  set -e

  source_status_after=$(git -C "$source_root" status --porcelain=v1 --untracked-files=all)
  if [[ -z $source_status_after ]]; then
    clean_after=true
  else
    clean_after=false
  fi

  "$python_executable" -I -S -B - \
    "$resolved_result_file" \
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
    "$python_executable" \
    "$preparation_digest" <<'PY'
import hashlib
import json
import os
import pathlib
import platform
import sys
import tempfile

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
    python_executable,
    preparation_digest,
) = sys.argv[1:]

selected_executable = pathlib.Path(python_executable)
invoked_executable = pathlib.Path(sys.executable).resolve(strict=True)
if invoked_executable != selected_executable:
    raise RuntimeError("result emitter executable does not match the selected executable")

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
            "adapters/fido-custody-v1.md": "3a2a8c4262c1a1876a596f9032b71bf9c7f4e08bb786c8eb980c8d691f71ad3c",
            "adapters/fido_custody.py": "93ad77be96df82d69f79d2016dcbaa2e113e34c24097776ac3c5d318d4b87eb7",
            "conformance/check-fido-custody.py": "1018646728e43f14f566c06efc1e89789d93e81bbd913d94a356579fc463f571",
            "conformance/test_support.py": "53f8a6c30422031342ed47215ac5d9b91c0f1ab8d55defc306fdeb28e3cd1692",
            "sacrysty_runtime/__init__.py": "9a544524cda604a26f6451e1f81c14450d6e027487c5b6ee02401dfd24b8acf0",
            "sacrysty_runtime/process_groups.py": "024fe15f456e884b0be14060b2b08dc1a7873eecbf3a2257a9b0e86a105a4662",
            "sacrysty_runtime/strict_json.py": "6ac33fd9ea97c03b5a0dcb24a62cab599dc6fbf58703f343f96c48e3d526d79e",
        },
    },
    "preparation_receipts": {
        "file": "qualification/fido-custody/preparation-2026-09-16.md",
        "file_sha256": preparation_digest,
        "historical_manifest_bytes": "unavailable",
        "scope": "Primary-source URLs and captured file identities are retained in the preparation report at the implementation revision. Historical cache manifests are unavailable; no manifest verification is claimed.",
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
        "executable": str(selected_executable),
        "implementation": platform.python_implementation(),
        "version": platform.python_version(),
        "version_detail": sys.version,
        "executable_sha256": hashlib.sha256(selected_executable.read_bytes()).hexdigest(),
    },
    "limits": [
        "Synthetic workers only; no real JSON worker, age plugin, or age executable was selected or run.",
        "No native FIDO library, authenticator, PIN, biometric, provider, keychain, personal host, custody state, release signing, or production path was exercised.",
        "A passing result does not qualify genesis, a custody implementation, hardware, provider behavior, personal adoption, or production use.",
        "Local execution is not GitHub-hosted or macOS evidence.",
        "The selected native CPython executable is trusted host/toolchain input; its native code is not attested or contained.",
        "A relevant source, workflow, runtime, platform, architecture, or runner-image change invalidates this result.",
    ],
}
result_path = pathlib.Path(result_file)
temporary_path = None
try:
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=result_path.parent,
        prefix=".fido-qualification-result.",
        delete=False,
    ) as temporary_file:
        temporary_path = pathlib.Path(temporary_file.name)
        temporary_file.write(json.dumps(record, indent=2, sort_keys=True) + "\n")
    os.replace(temporary_path, result_path)
    temporary_path = None
finally:
    if temporary_path is not None:
        temporary_path.unlink(missing_ok=True)
PY

  printf 'candidate-bound provisional result: %s\n' "$result_file"
  if ((normal_exit != 0 || optimized_exit != 0)) || [[ $clean_after != true ]]; then
    return 1
  fi
}

main "$@"
