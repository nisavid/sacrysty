#!/usr/bin/env bash

# Exact shared safety primitives for the two disposable sq/sqv evidence runners.
# This file is not a command framework and must not be used with real keys.

# shellcheck disable=SC2034 # Read by the scripts that source this library.
SQ_EVIDENCE_SQ_COMMON=(
  --cli-version 1.4.0
  --home none
  --key-store none
  --cert-store none
)
SQ_EVIDENCE_PROCESS_HELPER=$(
  CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P
)/sq_evidence_process.py
SQ_EVIDENCE_PROCESS_CLEANUP_RECEIPT='io.nisavid.sacrysty.process-cleanup/v1'
SQ_EVIDENCE_RUNNER_CLEANUP_RECEIPT='io.nisavid.sacrysty.runner-cleanup/v1'
SQ_EVIDENCE_ACTIVE_PROCESS_RECEIPT=
SQ_EVIDENCE_INNER_CLEANUP_WAIT_SECONDS=2.75

sq_evidence_require_tools() {
  command -v "$1" >/dev/null
  command -v "$2" >/dev/null
  command -v python3 >/dev/null
}

sq_evidence_require_clean_source() {
  local root=$1
  local label=$2
  local source_status
  if ! source_status=$(
    git -C "$root" status --porcelain=v1 --untracked-files=all
  ); then
    printf '%s evidence could not inspect source worktree\n' "$label" >&2
    return 1
  fi
  if [[ -n $source_status ]]; then
    printf '%s evidence requires a clean worktree\n' "$label" >&2
    return 1
  fi
}

sq_evidence_run_process() {
  local mode=$1
  local status_path=$2
  local stdout_path=$3
  local stderr_path=$4
  local cleanup_receipt="${status_path}.cleanup"
  local helper_status=0
  shift 4
  SQ_EVIDENCE_ACTIVE_PROCESS_RECEIPT=$cleanup_receipt
  python3 -B "$SQ_EVIDENCE_PROCESS_HELPER" \
    "$mode" "$status_path" "$stdout_path" "$stderr_path" -- "$@" ||
    helper_status=$?
  if [[ -n $SQ_EVIDENCE_ACTIVE_PROCESS_RECEIPT ]]; then
    sq_evidence_consume_process_cleanup_receipt "$cleanup_receipt" || return 1
    SQ_EVIDENCE_ACTIVE_PROCESS_RECEIPT=
  fi
  return "$helper_status"
}

sq_evidence_run_tool() {
  sq_evidence_run_process tool "$@"
}

sq_evidence_run_probe() {
  sq_evidence_run_process probe "$@"
}

sq_evidence_consume_process_cleanup_receipt() {
  local path=$1
  if [[ ! -r $path ]]; then
    printf 'selected process cleanup receipt is unavailable\n' >&2
    return 1
  fi
  if ! python3 -B - "$path" "$SQ_EVIDENCE_PROCESS_CLEANUP_RECEIPT" <<'PY'
import pathlib
import sys

path, expected = sys.argv[1:]
try:
    matches = pathlib.Path(path).read_bytes() == f"{expected}\n".encode("ascii")
except OSError:
    matches = False
raise SystemExit(0 if matches else 1)
PY
  then
    printf 'selected process cleanup receipt is invalid\n' >&2
    return 1
  fi
  if ! rm -- "$path"; then
    printf 'selected process cleanup failed: receipt removal\n' >&2
    return 1
  fi
}

sq_evidence_confirm_active_process_cleanup() {
  if [[ -z $SQ_EVIDENCE_ACTIVE_PROCESS_RECEIPT ]]; then
    return
  fi
  sq_evidence_consume_process_cleanup_receipt \
    "$SQ_EVIDENCE_ACTIVE_PROCESS_RECEIPT" || return 1
  SQ_EVIDENCE_ACTIVE_PROCESS_RECEIPT=
}

sq_evidence_await_active_process_cleanup() {
  if [[ -z $SQ_EVIDENCE_ACTIVE_PROCESS_RECEIPT ]]; then
    return
  fi
  if ! python3 -B - \
    "$SQ_EVIDENCE_ACTIVE_PROCESS_RECEIPT" \
    "$SQ_EVIDENCE_PROCESS_CLEANUP_RECEIPT" \
    "$SQ_EVIDENCE_INNER_CLEANUP_WAIT_SECONDS" <<'PY'
import pathlib
import sys
import time

path = pathlib.Path(sys.argv[1])
expected = f"{sys.argv[2]}\n".encode("ascii")
deadline = time.monotonic() + float(sys.argv[3])
while True:
    try:
        content = path.read_bytes()
    except FileNotFoundError:
        content = b""
    except OSError:
        raise SystemExit(1)
    if content == expected:
        raise SystemExit(0)
    if content and not expected.startswith(content):
        raise SystemExit(1)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SystemExit(1)
    time.sleep(min(0.01, remaining))
PY
  then
    printf 'selected process cleanup receipt is unavailable\n' >&2
    return 1
  fi
  sq_evidence_confirm_active_process_cleanup
}

sq_evidence_write_runner_cleanup_receipt() {
  local receipt=${SACRYSTY_RUNNER_CLEANUP_RECEIPT:-}
  local expected_parent
  local noclobber_was_set=
  local previous_umask
  local receipt_parent
  if [[ -z $receipt ]]; then
    return
  fi
  if [[ -e $receipt || -z ${TMPDIR:-} ]]; then
    printf 'runner cleanup receipt path is invalid\n' >&2
    return 1
  fi
  expected_parent=$(CDPATH='' cd -- "$TMPDIR/../.." && pwd -P) || return 1
  receipt_parent=$(CDPATH='' cd -- "$(dirname -- "$receipt")" && pwd -P) || return 1
  if [[ $receipt_parent != "$expected_parent" ]]; then
    printf 'runner cleanup receipt path is invalid\n' >&2
    return 1
  fi
  previous_umask=$(umask)
  if [[ -o noclobber ]]; then
    noclobber_was_set=1
  else
    set -o noclobber
  fi
  umask 077
  if ! printf '%s\n' "$SQ_EVIDENCE_RUNNER_CLEANUP_RECEIPT" >"$receipt"; then
    umask "$previous_umask"
    if [[ -z $noclobber_was_set ]]; then
      set +o noclobber
    fi
    printf 'runner cleanup receipt cannot be written\n' >&2
    return 1
  fi
  umask "$previous_umask"
  if [[ -z $noclobber_was_set ]]; then
    set +o noclobber
  fi
}

sq_evidence_finish_runner_cleanup() {
  local path=$1
  local label=$2
  sq_evidence_confirm_active_process_cleanup || return 1
  sq_evidence_remove_and_verify "$path" "$label" || return 1
  sq_evidence_write_runner_cleanup_receipt
}

sq_evidence_exit_runner() {
  local requested_status=$1
  local path=$2
  local label=$3
  local await_active_cleanup=$4
  local final_status=$requested_status

  # Error and signal paths own mandatory finalization directly. EXIT remains a
  # fallback for shell failures that do not reach either catchable path.
  trap - ERR EXIT
  trap '' INT TERM
  if [[ $await_active_cleanup == 1 ]] &&
    ! sq_evidence_await_active_process_cleanup; then
    final_status=1
  fi
  if [[ -n $path ]]; then
    if ! sq_evidence_finish_runner_cleanup "$path" "$label"; then
      final_status=1
    fi
  elif ! sq_evidence_confirm_active_process_cleanup ||
    ! sq_evidence_write_runner_cleanup_receipt; then
    final_status=1
  fi
  exit "$final_status"
}

sq_evidence_result_paths() {
  local stem=$1
  SQ_EVIDENCE_STATUS_PATH="${stem}.status"
  SQ_EVIDENCE_STDOUT_PATH="${stem}.stdout"
  SQ_EVIDENCE_STDERR_PATH="${stem}.stderr"
}

sq_evidence_require_success_at_stem() {
  local label=$1
  local stem=$2
  shift 2
  sq_evidence_result_paths "$stem"
  sq_evidence_require_tool_success \
    "$label" "$SQ_EVIDENCE_STATUS_PATH" "$SQ_EVIDENCE_STDOUT_PATH" \
    "$SQ_EVIDENCE_STDERR_PATH" "$@"
}

sq_evidence_require_rejection_at_stem() {
  local label=$1
  local stem=$2
  shift 2
  sq_evidence_result_paths "$stem"
  sq_evidence_require_tool_rejection \
    "$label" "$SQ_EVIDENCE_STATUS_PATH" "$SQ_EVIDENCE_STDOUT_PATH" \
    "$SQ_EVIDENCE_STDERR_PATH" "$@"
}

sq_evidence_classical_round_trip() {
  local work=$1
  local message=$2
  local sq_bin=$3
  local sqv_bin=$4
  SQ_EVIDENCE_KEY="$work/classical-key.pgp"
  SQ_EVIDENCE_CERTIFICATE="$work/classical-cert.pgp"
  SQ_EVIDENCE_SIGNATURE="$work/message.sig"
  SQ_EVIDENCE_TAMPERED_MESSAGE="$work/tampered-message.bin"
  SQ_EVIDENCE_TAMPERED_SIGNATURE="$work/tampered-signature.sig"
  SQ_EVIDENCE_OTHER_KEY="$work/other-key.pgp"
  SQ_EVIDENCE_OTHER_CERTIFICATE="$work/other-cert.pgp"

  sq_evidence_require_success_at_stem \
    'classical key generation' "$work/generate" \
    "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 key generate \
    --own-key --userid 'Sacrysty Fixture <fixture@example.invalid>' \
    --profile rfc9580 --cipher-suite cv25519 --without-password \
    --output "$SQ_EVIDENCE_KEY" --rev-cert "$work/revocation.pgp"
  sq_evidence_require_success_at_stem \
    'classical certificate extraction' "$work/extract" \
    "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" key delete \
    --cert-file "$SQ_EVIDENCE_KEY" --output "$SQ_EVIDENCE_CERTIFICATE"
  sq_evidence_require_success_at_stem \
    'classical detached signing' "$work/sign" \
    "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 sign \
    --signer-file "$SQ_EVIDENCE_KEY" --signature-file "$SQ_EVIDENCE_SIGNATURE" \
    --binary "$message"
  sq_evidence_require_success_at_stem \
    'classical independent verification' "$work/verify" \
    "$sqv_bin" --time 20260910 --keyring "$SQ_EVIDENCE_CERTIFICATE" \
    --signature-file "$SQ_EVIDENCE_SIGNATURE" "$message"

  cp "$message" "$SQ_EVIDENCE_TAMPERED_MESSAGE"
  printf 'tamper\n' >>"$SQ_EVIDENCE_TAMPERED_MESSAGE"
  sq_evidence_require_rejection_at_stem \
    'tampered-message verification' "$work/tampered-message" \
    "$sqv_bin" --time 20260910 --keyring "$SQ_EVIDENCE_CERTIFICATE" \
    --signature-file "$SQ_EVIDENCE_SIGNATURE" "$SQ_EVIDENCE_TAMPERED_MESSAGE"

  cp "$SQ_EVIDENCE_SIGNATURE" "$SQ_EVIDENCE_TAMPERED_SIGNATURE"
  printf 'tamper\n' >>"$SQ_EVIDENCE_TAMPERED_SIGNATURE"
  sq_evidence_require_rejection_at_stem \
    'tampered-signature verification' "$work/tampered-signature" \
    "$sqv_bin" --time 20260910 --keyring "$SQ_EVIDENCE_CERTIFICATE" \
    --signature-file "$SQ_EVIDENCE_TAMPERED_SIGNATURE" "$message"

  sq_evidence_require_success_at_stem \
    'wrong-certificate key generation' "$work/other-generate" \
    "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 key generate \
    --own-key --userid 'Sacrysty Other Fixture <other@example.invalid>' \
    --profile rfc9580 --cipher-suite cv25519 --without-password \
    --output "$SQ_EVIDENCE_OTHER_KEY" --rev-cert "$work/other-revocation.pgp"
  sq_evidence_require_success_at_stem \
    'wrong-certificate extraction' "$work/other-extract" \
    "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" key delete \
    --cert-file "$SQ_EVIDENCE_OTHER_KEY" --output "$SQ_EVIDENCE_OTHER_CERTIFICATE"
  sq_evidence_require_rejection_at_stem \
    'wrong-certificate verification' "$work/wrong-certificate" \
    "$sqv_bin" --time 20260910 --keyring "$SQ_EVIDENCE_OTHER_CERTIFICATE" \
    --signature-file "$SQ_EVIDENCE_SIGNATURE" "$message"
}

sq_evidence_read_status() {
  local path=$1
  local status
  if [[ ! -r $path ]]; then
    printf 'selected process status is invalid\n' >&2
    return 1
  fi
  status=$(<"$path")
  if [[ ! $status =~ ^[0-9]+$ ]]; then
    printf 'selected process status is invalid\n' >&2
    return 1
  fi
  printf '%s\n' "$status"
}

sq_evidence_require_tool_success() {
  local label=$1
  local status_path=$2
  local stdout_path=$3
  local stderr_path=$4
  local child_status
  shift 4
  sq_evidence_run_tool \
    "$status_path" "$stdout_path" "$stderr_path" "$@" || return 1
  child_status=$(sq_evidence_read_status "$status_path") || return 1
  if (( child_status != 0 )); then
    printf '%s exited with status %s\n' "$label" "$child_status" >&2
    return 1
  fi
}

sq_evidence_require_tool_rejection() {
  local label=$1
  local status_path=$2
  local stdout_path=$3
  local stderr_path=$4
  local child_status
  shift 4
  sq_evidence_run_tool \
    "$status_path" "$stdout_path" "$stderr_path" "$@" || return 1
  child_status=$(sq_evidence_read_status "$status_path") || return 1
  if (( child_status == 0 )); then
    printf '%s unexpectedly succeeded\n' "$label" >&2
    return 1
  fi
  if (( child_status >= 124 )); then
    printf '%s did not complete normally (status %s)\n' \
      "$label" "$child_status" >&2
    return 1
  fi
}

sq_evidence_external_tmp_root() {
  local source_root=$1
  local configured=${TMPDIR:-/tmp}
  local resolved_source
  local resolved_tmp
  resolved_source=$(CDPATH='' cd -- "$source_root" && pwd -P)
  resolved_tmp=$(CDPATH='' cd -- "$configured" && pwd -P) || {
    printf 'temporary directory is unavailable\n' >&2
    return 1
  }
  case "$resolved_tmp" in
    "$resolved_source" | "$resolved_source"/*)
      printf 'temporary directory must be outside the source checkout\n' >&2
      return 1
      ;;
  esac
  printf '%s\n' "$resolved_tmp"
}

sq_evidence_select_hash_tools() {
  if command -v sha256sum >/dev/null 2>&1 \
    && command -v sha512sum >/dev/null 2>&1; then
    SQ_EVIDENCE_HASH_TOOLS=gnu
  elif command -v shasum >/dev/null 2>&1; then
    SQ_EVIDENCE_HASH_TOOLS=shasum
  else
    printf 'SHA-256 and SHA-512 tools are unavailable\n' >&2
    return 1
  fi
}

sq_evidence_hash() {
  local algorithm=$1
  local path=$2
  case "${SQ_EVIDENCE_HASH_TOOLS:-}:$algorithm" in
    gnu:256) sha256sum -- "$path" | awk '{print $1}' ;;
    gnu:512) sha512sum -- "$path" | awk '{print $1}' ;;
    shasum:256) shasum -a 256 "$path" | awk '{print $1}' ;;
    shasum:512) shasum -a 512 "$path" | awk '{print $1}' ;;
    *)
      printf 'unsupported hash request\n' >&2
      return 1
      ;;
  esac
}

sq_evidence_json_string() {
  python3 -c '
import json
import sys

value = sys.stdin.buffer.read().decode("utf-8", "backslashreplace")
json.dump(value, sys.stdout, ensure_ascii=True)
'
}

sq_evidence_json_redacted_file() {
  python3 - "$1" "$2" <<'PY'
import json
import os
import pathlib
import sys

path, temporary_path = sys.argv[1:]
value = pathlib.Path(path).read_bytes().replace(
    os.fsencode(temporary_path), b"<temporary>"
)
json.dump(
    value.decode("utf-8", "backslashreplace"),
    sys.stdout,
    ensure_ascii=True,
)
PY
}

sq_evidence_remove_and_verify() {
  local path=$1
  local label=$2
  if [[ -z $path || $path == / ]]; then
    printf '%s cleanup refused unsafe path\n' "$label" >&2
    return 1
  fi
  if ! rm -rf -- "$path"; then
    printf '%s cleanup failed\n' "$label" >&2
    return 1
  fi
  if [[ -e $path ]]; then
    printf '%s cleanup failed\n' "$label" >&2
    return 1
  fi
}
