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

sq_evidence_require_tools() {
  command -v "$1" >/dev/null
  command -v "$2" >/dev/null
  command -v python3 >/dev/null
}

sq_evidence_require_clean_source() {
  local root=$1
  local label=$2
  if [[ -n $(git -C "$root" status --porcelain=v1 --untracked-files=all) ]]; then
    printf '%s evidence requires a clean worktree\n' "$label" >&2
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
