#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Public, disposable profile evidence. Every key and signature is created in a
# temporary directory; the default personal stores are disabled.
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
source "$root/conformance/sq-evidence-lib.sh"
work=
sq_evidence_trace_runner_phase runner-sourced
cleanup_work() {
  sq_evidence_trace_runner_phase cleanup-entered
  if [[ -n ${work:-} ]]; then
    sq_evidence_finish_runner_cleanup \
      "$work" 'temporary signing-profile directory'
  else
    sq_evidence_confirm_active_process_cleanup
    sq_evidence_write_runner_cleanup_receipt
  fi
}
# shellcheck disable=SC2329 # Invoked by the ERR trap below.
fail_runner() {
  local status=$1
  sq_evidence_trace_runner_phase "error-handler-${status}"
  if ((BASH_SUBSHELL > 0)); then
    sq_evidence_trace_runner_phase error-handler-deferred
    return "$status"
  fi
  sq_evidence_exit_runner \
    "$status" "${work:-}" 'temporary signing-profile directory' 0
}
# shellcheck disable=SC2329 # Invoked by the TERM trap below.
interrupt_runner() {
  sq_evidence_trace_runner_phase term-handler
  sq_evidence_exit_runner \
    143 "${work:-}" 'temporary signing-profile directory' 1
}
trap cleanup_work EXIT
trap 'fail_runner $?' ERR
trap interrupt_runner TERM
sq_evidence_trace_runner_phase handlers-registered

sq_bin=${SQ:-sq}
sqv_bin=${SQV:-sqv}
sq_evidence_require_tools "$sq_bin" "$sqv_bin"
sq_evidence_require_clean_source "$root" signing-profile
sq_evidence_select_hash_tools
temporary_root=$(sq_evidence_external_tmp_root "$root")
work=$(mktemp -d "$temporary_root/sacrysty-signing-profile.XXXXXX")
message="$work/message.bin"
cp "$root/fixtures/signing/message.bin" "$message"
sq_evidence_classical_round_trip "$work" "$message" "$sq_bin" "$sqv_bin"
sig=$SQ_EVIDENCE_SIGNATURE

tampered_message_command=$(
  printf '%s' "$sqv_bin --time 20260910 --keyring classical-cert.pgp --signature-file message.sig tampered-message.bin" \
    | sq_evidence_json_string
)
tampered_signature_command=$(
  printf '%s' "$sqv_bin --time 20260910 --keyring classical-cert.pgp --signature-file tampered-signature.sig message.bin" \
    | sq_evidence_json_string
)
wrong_certificate_command=$(
  printf '%s' "$sqv_bin --time 20260910 --keyring other-cert.pgp --signature-file message.sig message.bin" \
    | sq_evidence_json_string
)
source_revision=$(git -C "$root" rev-parse HEAD)
sq_evidence_require_tool_success \
  'sq version' "$work/sq-version.status" \
  "$work/sq-version.stdout" "$work/sq-version.stderr" \
  "$sq_bin" version
sq_version=$(
  cat "$work/sq-version.stdout" "$work/sq-version.stderr" \
    | sq_evidence_json_string
)
sq_evidence_require_tool_success \
  'sqv version' "$work/sqv-version.status" \
  "$work/sqv-version.stdout" "$work/sqv-version.stderr" \
  "$sqv_bin" --version
sqv_version=$(
  cat "$work/sqv-version.stdout" "$work/sqv-version.stderr" \
    | sq_evidence_json_string
)
message_bytes=$(wc -c <"$message" | tr -d ' ')
signature_bytes=$(wc -c <"$sig" | tr -d ' ')
message_sha256=$(sq_evidence_hash 256 "$message")
message_sha512=$(sq_evidence_hash 512 "$message")
signature_sha256=$(sq_evidence_hash 256 "$sig")
signature_sha512=$(sq_evidence_hash 512 "$sig")
tampered_message_status=$(cat "$work/tampered-message.status")
tampered_message_stderr=$(
  sq_evidence_json_redacted_file "$work/tampered-message.stderr" "$work"
)
tampered_signature_status=$(cat "$work/tampered-signature.status")
tampered_signature_stderr=$(
  sq_evidence_json_redacted_file "$work/tampered-signature.stderr" "$work"
)
wrong_certificate_status=$(cat "$work/wrong-certificate.status")
wrong_certificate_stderr=$(
  sq_evidence_json_redacted_file "$work/wrong-certificate.stderr" "$work"
)
removed_work=$work
if ! cleanup_work || [[ -e $removed_work ]]; then
  exit 1
fi
work=
trap - ERR EXIT TERM
cat <<EOF_JSON
{
  "schema": "io.nisavid.sacrysty.signing-profile-result/v1",
  "source_revision": "$source_revision",
  "reference_time": "20260910",
  "sq_version": $sq_version,
  "sqv_version": $sqv_version,
  "profile": "openpgp-rfc9580-classical-v1",
  "fixtures": {
    "message": {"bytes": $message_bytes, "sha256": "$message_sha256", "sha512": "$message_sha512"},
    "signature": {"bytes": $signature_bytes, "sha256": "$signature_sha256", "sha512": "$signature_sha512"}
  },
  "checks": {
    "detached_sign_verify": true,
    "tampered_message_rejected": true,
    "tampered_signature_rejected": true,
    "wrong_certificate_rejected": true,
    "temporary_key_material_removed": true
  },
  "diagnostics": {
    "tampered_message": {"command": $tampered_message_command, "exit_status": $tampered_message_status, "stderr": $tampered_message_stderr},
    "tampered_signature": {"command": $tampered_signature_command, "exit_status": $tampered_signature_status, "stderr": $tampered_signature_stderr},
    "wrong_certificate": {"command": $wrong_certificate_command, "exit_status": $wrong_certificate_status, "stderr": $wrong_certificate_stderr}
  },
  "production_values_policy": "forbidden",
  "rfc9980": "unsupported-capability-gated"
}
EOF_JSON
