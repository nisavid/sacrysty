#!/usr/bin/env bash
set -euo pipefail

# Public, disposable conformance probe. It creates all key material in a
# temporary directory and removes it on exit. It never uses a default key or
# certificate store.
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
source "$root_dir/conformance/sq-evidence-lib.sh"
sq_bin=${SQ:-sq}
sqv_bin=${SQV:-sqv}
sq_evidence_require_tools "$sq_bin" "$sqv_bin"
sq_evidence_require_clean_source "$root_dir" conformance
sq_evidence_select_hash_tools
temporary_root=$(sq_evidence_external_tmp_root "$root_dir")

work_dir=$(mktemp -d "$temporary_root/sacrysty-conformance.XXXXXX")
cleanup_work_dir() {
  if [[ -n ${work_dir:-} ]]; then
    sq_evidence_remove_and_verify "$work_dir" 'temporary conformance directory'
  fi
}
trap cleanup_work_dir EXIT

message="$work_dir/message.txt"
key="$work_dir/fixture-key.pgp"
revocation="$work_dir/fixture-revocation.pgp"
certificate="$work_dir/fixture-cert.pgp"
signature="$work_dir/message.sig"
tampered="$work_dir/tampered.txt"
tampered_signature="$work_dir/tampered.sig"
other_key="$work_dir/other-key.pgp"
other_certificate="$work_dir/other-cert.pgp"
cp "$root_dir/fixtures/rfc9580/message.txt" "$message"

sq_evidence_require_tool_success \
  'classical key generation' "$work_dir/generate.status" \
  "$work_dir/generate.stdout" "$work_dir/generate.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 key generate \
  --own-key --userid 'Sacrysty Fixture <fixture@example.invalid>' \
  --profile rfc9580 --cipher-suite cv25519 --without-password \
  --output "$key" --rev-cert "$revocation"
sq_evidence_require_tool_success \
  'classical certificate extraction' "$work_dir/extract.status" \
  "$work_dir/extract.stdout" "$work_dir/extract.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" key delete \
  --cert-file "$key" --output "$certificate"
sq_evidence_require_tool_success \
  'classical detached signing' "$work_dir/sign.status" \
  "$work_dir/sign.stdout" "$work_dir/sign.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 sign \
  --signer-file "$key" --signature-file "$signature" --binary "$message"
sq_evidence_require_tool_success \
  'classical independent verification' "$work_dir/verify.status" \
  "$work_dir/verify.stdout" "$work_dir/verify.stderr" \
  "$sqv_bin" --time 20260910 --keyring "$certificate" \
  --signature-file "$signature" "$message"

cp "$message" "$tampered"
printf 'tamper\n' >>"$tampered"
sq_evidence_require_tool_rejection \
  'tampered-message verification' "$work_dir/tamper.status" \
  "$work_dir/tamper.stdout" "$work_dir/tamper.stderr" \
  "$sqv_bin" --time 20260910 --keyring "$certificate" \
  --signature-file "$signature" "$tampered"

cp "$signature" "$tampered_signature"
printf 'tamper\n' >>"$tampered_signature"
sq_evidence_require_tool_rejection \
  'tampered-signature verification' "$work_dir/tampered-signature.status" \
  "$work_dir/tampered-signature.stdout" "$work_dir/tampered-signature.stderr" \
  "$sqv_bin" --time 20260910 --keyring "$certificate" \
  --signature-file "$tampered_signature" "$message"

sq_evidence_require_tool_success \
  'wrong-certificate key generation' "$work_dir/other-generate.status" \
  "$work_dir/other-generate.stdout" "$work_dir/other-generate.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 key generate \
  --own-key --userid 'Sacrysty Other Fixture <other@example.invalid>' \
  --profile rfc9580 --cipher-suite cv25519 --without-password \
  --output "$other_key" --rev-cert "$work_dir/other-rev.pgp"
sq_evidence_require_tool_success \
  'wrong-certificate extraction' "$work_dir/other-extract.status" \
  "$work_dir/other-extract.stdout" "$work_dir/other-extract.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" key delete \
  --cert-file "$other_key" --output "$other_certificate"
sq_evidence_require_tool_rejection \
  'wrong-certificate verification' "$work_dir/wrong-certificate.status" \
  "$work_dir/wrong-certificate.stdout" "$work_dir/wrong-certificate.stderr" \
  "$sqv_bin" --time 20260910 --keyring "$other_certificate" \
  --signature-file "$signature" "$message"

# RFC 9980 is capability-gated. Only the tool's explicit capability rejection
# is "unsupported"; other generation failures and failed round trips are
# indeterminate failures and make this probe fail.
recognized_pqc_capability_rejection() {
  python3 - "$1" "$2" <<'PY'
import pathlib
import sys

try:
    lines = [
        line.strip()
        for path in sys.argv[1:]
        for line in pathlib.Path(path).read_bytes().decode("utf-8").splitlines()
        if line.strip()
    ]
except (OSError, UnicodeDecodeError):
    raise SystemExit(1)
expected = ["Error: Unsupported public key algorithm: ML-DSA-65+Ed25519"]
raise SystemExit(0 if lines == expected else 1)
PY
}

pqc_result=probe-failed
pqc_probe_status=1
sq_evidence_run_tool \
  "$work_dir/pqc.status" "$work_dir/pqc.stdout" "$work_dir/pqc.stderr" \
  "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 key generate \
  --own-key --userid 'Sacrysty PQC Probe <pqc@example.invalid>' \
  --profile rfc9580 --cipher-suite mldsa65-ed25519 --without-password \
  --output "$work_dir/pqc-key.pgp" --rev-cert "$work_dir/pqc-rev.pgp"
pqc_generation_status=$(sq_evidence_read_status "$work_dir/pqc.status")
if (( pqc_generation_status == 0 )); then
  sq_evidence_run_tool \
    "$work_dir/pqc-extract.status" \
    "$work_dir/pqc-extract.stdout" "$work_dir/pqc-extract.stderr" \
    "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" key delete \
    --cert-file "$work_dir/pqc-key.pgp" --output "$work_dir/pqc-cert.pgp"
  pqc_extract_status=$(sq_evidence_read_status "$work_dir/pqc-extract.status")
  if (( pqc_extract_status == 0 )); then
    sq_evidence_run_tool \
      "$work_dir/pqc-sign.status" \
      "$work_dir/pqc-sign.stdout" "$work_dir/pqc-sign.stderr" \
      "$sq_bin" "${SQ_EVIDENCE_SQ_COMMON[@]}" --time 20260910 sign \
      --signer-file "$work_dir/pqc-key.pgp" \
      --signature-file "$work_dir/pqc.sig" --binary "$message"
    pqc_sign_status=$(sq_evidence_read_status "$work_dir/pqc-sign.status")
  else
    pqc_sign_status=1
  fi
  if (( pqc_sign_status == 0 )); then
    sq_evidence_run_tool \
      "$work_dir/pqc-verify.status" \
      "$work_dir/pqc-verify.stdout" "$work_dir/pqc-verify.stderr" \
      "$sqv_bin" --time 20260910 --keyring "$work_dir/pqc-cert.pgp" \
      --signature-file "$work_dir/pqc.sig" "$message"
    pqc_verify_status=$(sq_evidence_read_status "$work_dir/pqc-verify.status")
  else
    pqc_verify_status=1
  fi
  if (( pqc_extract_status == 0 && pqc_sign_status == 0 && pqc_verify_status == 0 )); then
    pqc_result=qualified-for-observed-runtime
    pqc_probe_status=0
  else
    pqc_result=round-trip-failed
  fi
elif recognized_pqc_capability_rejection \
  "$work_dir/pqc.stdout" "$work_dir/pqc.stderr"; then
  pqc_result=unsupported
  pqc_probe_status=0
fi

source_revision=$(git -C "$root_dir" rev-parse HEAD)
sq_evidence_require_tool_success \
  'sq version' "$work_dir/sq-version.status" \
  "$work_dir/sq-version.stdout" "$work_dir/sq-version.stderr" \
  "$sq_bin" version
sq_version=$(
  cat "$work_dir/sq-version.stdout" "$work_dir/sq-version.stderr" \
    | sq_evidence_json_string
)
sq_evidence_require_tool_success \
  'sqv version' "$work_dir/sqv-version.status" \
  "$work_dir/sqv-version.stdout" "$work_dir/sqv-version.stderr" \
  "$sqv_bin" --version
sqv_version=$(
  cat "$work_dir/sqv-version.stdout" "$work_dir/sqv-version.stderr" \
    | sq_evidence_json_string
)
message_bytes=$(wc -c <"$message" | tr -d ' ')
signature_bytes=$(wc -c <"$signature" | tr -d ' ')
tampered_bytes=$(wc -c <"$tampered" | tr -d ' ')
tampered_signature_bytes=$(wc -c <"$tampered_signature" | tr -d ' ')
message_sha256=$(sq_evidence_hash 256 "$message")
message_sha512=$(sq_evidence_hash 512 "$message")
signature_sha256=$(sq_evidence_hash 256 "$signature")
signature_sha512=$(sq_evidence_hash 512 "$signature")
tampered_sha256=$(sq_evidence_hash 256 "$tampered")
tampered_sha512=$(sq_evidence_hash 512 "$tampered")
tampered_signature_sha256=$(sq_evidence_hash 256 "$tampered_signature")
tampered_signature_sha512=$(sq_evidence_hash 512 "$tampered_signature")

removed_work_dir=$work_dir
if ! cleanup_work_dir || [[ -e $removed_work_dir ]]; then
  exit 1
fi
work_dir=
trap - EXIT

cat <<EOF
{
  "schema": "io.nisavid.sacrysty.crypto-conformance-result/v1",
  "source_revision": "$source_revision",
  "reference_time": "20260910",
  "sq_version": $sq_version,
  "sqv_version": $sqv_version,
  "fixture_sha256": "$message_sha256",
  "fixture_sha512": "$message_sha512",
  "fixture_bytes": $message_bytes,
  "result": {
    "openpgp-rfc9580-classical-v1": "qualified-for-observed-runtime",
    "openpgp-rfc9980-pqc-v1": "$pqc_result"
  },
  "fixtures": {
    "message": {"bytes": $message_bytes, "sha256": "$message_sha256", "sha512": "$message_sha512"},
    "signature": {"bytes": $signature_bytes, "sha256": "$signature_sha256", "sha512": "$signature_sha512"},
    "tampered_message": {"bytes": $tampered_bytes, "sha256": "$tampered_sha256", "sha512": "$tampered_sha512"},
    "tampered_signature": {"bytes": $tampered_signature_bytes, "sha256": "$tampered_signature_sha256", "sha512": "$tampered_signature_sha512"}
  },
  "checks": {
    "sq_sign_verify": true,
    "sqv_detached_verify": true,
    "tampered_message_rejected": true,
    "tampered_signature_rejected": true,
    "wrong_certificate_rejected": true,
    "temporary_key_material_removed": true,
    "production_values": false
  }
}
EOF
exit "$pqc_probe_status"
