#!/usr/bin/env bash
set -euo pipefail

# Public, disposable profile evidence. Every key and signature is created in a
# temporary directory; the default personal stores are disabled.
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
source "$root/conformance/sq-evidence-lib.sh"
sq_bin=${SQ:-sq}
sqv_bin=${SQV:-sqv}
sq_evidence_require_tools "$sq_bin" "$sqv_bin"
sq_evidence_require_clean_source "$root" signing-profile
sq_evidence_select_hash_tools
temporary_root=$(sq_evidence_external_tmp_root "$root")

work=$(mktemp -d "$temporary_root/sacrysty-signing-profile.XXXXXX")
cleanup_work() {
  if [[ -n ${work:-} ]]; then
    sq_evidence_remove_and_verify "$work" 'temporary signing-profile directory'
  fi
}
trap cleanup_work EXIT
message="$work/message.bin"
key="$work/signing-key.pgp"
cert="$work/signer-cert.pgp"
sig="$work/message.sig"
tampered="$work/tampered.bin"
tampered_sig="$work/tampered.sig"
wrong_key="$work/wrong-key.pgp"
wrong_cert="$work/wrong-cert.pgp"
cp "$root/fixtures/signing/message.bin" "$message"

sq_evidence_require_tool_success \
  'signing key generation' "$work/generate.status" \
  "$work/generate.stdout" "$work/generate.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 key generate --own-key \
  --userid 'Sacrysty Fixture <fixture@example.invalid>' --profile rfc9580 \
  --cipher-suite cv25519 --without-password --output "$key" \
  --rev-cert "$work/revocation.asc"
sq_evidence_require_tool_success \
  'signing certificate extraction' "$work/extract.status" \
  "$work/extract.stdout" "$work/extract.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" key delete \
  --cert-file "$key" --output "$cert"
sq_evidence_require_tool_success \
  'detached signing' "$work/sign.status" \
  "$work/sign.stdout" "$work/sign.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 sign --binary \
  --signature-file "$sig" --signer-file "$key" "$message"
sq_evidence_require_tool_success \
  'independent detached-signature verification' "$work/verify.status" \
  "$work/verify.stdout" "$work/verify.stderr" \
  "$sqv_bin" --time 20260910 --keyring "$cert" --signature-file "$sig" \
  "$message"

run_rejection() {
  local status_file=$1
  shift
  sq_evidence_require_tool_rejection \
    'negative verification' "$status_file" \
    "${status_file}.stdout" "${status_file}.stderr" "$@"
}

cp "$message" "$tampered"
printf 'tamper\n' >>"$tampered"
run_rejection "$work/tampered-message.status" "$sqv_bin" --time 20260910 \
  --keyring "$cert" --signature-file "$sig" "$tampered"
cp "$sig" "$tampered_sig"
printf 'tamper\n' >>"$tampered_sig"
run_rejection "$work/tampered-signature.status" "$sqv_bin" --time 20260910 \
  --keyring "$cert" --signature-file "$tampered_sig" "$message"

sq_evidence_require_tool_success \
  'wrong-certificate key generation' "$work/wrong-generate.status" \
  "$work/wrong-generate.stdout" "$work/wrong-generate.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 key generate --own-key \
  --userid 'Sacrysty Other Fixture <other@example.invalid>' --profile rfc9580 \
  --cipher-suite cv25519 --without-password --output "$wrong_key" \
  --rev-cert "$work/wrong-revocation.asc"
sq_evidence_require_tool_success \
  'wrong-certificate extraction' "$work/wrong-extract.status" \
  "$work/wrong-extract.stdout" "$work/wrong-extract.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" key delete \
  --cert-file "$wrong_key" --output "$wrong_cert"
run_rejection "$work/wrong-certificate.status" "$sqv_bin" --time 20260910 \
  --keyring "$wrong_cert" --signature-file "$sig" "$message"

tampered_message_command=$(
  printf '%s' "$sqv_bin --time 20260910 --keyring signer-cert.pgp --signature-file message.sig tampered.bin" \
    | sq_evidence_json_string
)
tampered_signature_command=$(
  printf '%s' "$sqv_bin --time 20260910 --keyring signer-cert.pgp --signature-file tampered.sig message.bin" \
    | sq_evidence_json_string
)
wrong_certificate_command=$(
  printf '%s' "$sqv_bin --time 20260910 --keyring wrong-cert.pgp --signature-file message.sig message.bin" \
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
  sq_evidence_json_redacted_file "$work/tampered-message.status.stderr" "$work"
)
tampered_signature_status=$(cat "$work/tampered-signature.status")
tampered_signature_stderr=$(
  sq_evidence_json_redacted_file "$work/tampered-signature.status.stderr" "$work"
)
wrong_certificate_status=$(cat "$work/wrong-certificate.status")
wrong_certificate_stderr=$(
  sq_evidence_json_redacted_file "$work/wrong-certificate.status.stderr" "$work"
)
removed_work=$work
if ! cleanup_work || [[ -e $removed_work ]]; then
  exit 1
fi
work=
trap - EXIT
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
