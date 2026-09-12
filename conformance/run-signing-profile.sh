#!/usr/bin/env bash
set -euo pipefail

# Public, disposable profile evidence. Every key and signature is created in a
# temporary directory; the default personal stores are disabled.
root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
sq_bin=${SQ:-sq}
sqv_bin=${SQV:-sqv}
command -v "$sq_bin" >/dev/null
command -v "$sqv_bin" >/dev/null

if [ -n "$(git -C "$root" status --porcelain)" ]; then
  echo 'signing-profile evidence requires a clean worktree' >&2
  exit 1
fi

work=$(mktemp -d "${TMPDIR:-/tmp}/sacrysty-signing-profile.XXXXXX")
cleanup_work() { rm -rf "$work"; }
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

common=(--cli-version 1.4.0 --home none --key-store none --cert-store none)
"$sq_bin" "${common[@]}" --time 20260910 key generate --own-key \
  --userid 'Sacrysty Fixture <fixture@example.invalid>' --profile rfc9580 \
  --cipher-suite cv25519 --without-password --output "$key" \
  --rev-cert "$work/revocation.asc" >"$work/generate.log" 2>&1
"$sq_bin" "${common[@]}" key delete --cert-file "$key" --output "$cert" >"$work/extract.log" 2>&1
"$sq_bin" "${common[@]}" --time 20260910 sign --binary \
  --signature-file "$sig" --signer-file "$key" "$message" >"$work/sign.log" 2>&1
"$sqv_bin" --time 20260910 --keyring "$cert" --signature-file "$sig" \
  "$message" >"$work/verify.log" 2>&1

run_rejection() {
  local status_file=$1
  shift
  set +e
  "$@" >"${status_file}.stdout" 2>"${status_file}.stderr"
  local status=$?
  set -e
  printf '%s' "$status" >"$status_file"
  if [ "$status" -eq 0 ]; then
    echo 'negative verification unexpectedly succeeded' >&2
    exit 1
  fi
}

cp "$message" "$tampered"
printf 'tamper\n' >>"$tampered"
run_rejection "$work/tampered-message.status" "$sqv_bin" --time 20260910 \
  --keyring "$cert" --signature-file "$sig" "$tampered"
cp "$sig" "$tampered_sig"
printf 'tamper\n' >>"$tampered_sig"
run_rejection "$work/tampered-signature.status" "$sqv_bin" --time 20260910 \
  --keyring "$cert" --signature-file "$tampered_sig" "$message"

"$sq_bin" "${common[@]}" --time 20260910 key generate --own-key \
  --userid 'Sacrysty Other Fixture <other@example.invalid>' --profile rfc9580 \
  --cipher-suite cv25519 --without-password --output "$wrong_key" \
  --rev-cert "$work/wrong-revocation.asc" >"$work/wrong-generate.log" 2>&1
"$sq_bin" "${common[@]}" key delete --cert-file "$wrong_key" --output "$wrong_cert" >"$work/wrong-extract.log" 2>&1
run_rejection "$work/wrong-certificate.status" "$sqv_bin" --time 20260910 \
  --keyring "$wrong_cert" --signature-file "$sig" "$message"

sha256() { sha256sum "$1" | awk '{print $1}'; }
sha512() { sha512sum "$1" | awk '{print $1}'; }
json_escape() { sed -e 's/\\/\\\\/g' -e 's/"/\\"/g' | tr '\n' ' '; }
redact_stderr() { sed "s|$work|<temporary>|g" "$1" | json_escape; }
source_revision=$(git -C "$root" rev-parse HEAD)
sq_version=$("$sq_bin" version 2>&1 | tr '\n' ' ' | sed 's/[[:space:]]*$//')
sqv_version=$("$sqv_bin" --version)
message_bytes=$(wc -c <"$message" | tr -d ' ')
signature_bytes=$(wc -c <"$sig" | tr -d ' ')
message_sha256=$(sha256 "$message")
message_sha512=$(sha512 "$message")
signature_sha256=$(sha256 "$sig")
signature_sha512=$(sha512 "$sig")
tampered_message_status=$(cat "$work/tampered-message.status")
tampered_message_stderr=$(redact_stderr "$work/tampered-message.status.stderr")
tampered_signature_status=$(cat "$work/tampered-signature.status")
tampered_signature_stderr=$(redact_stderr "$work/tampered-signature.status.stderr")
wrong_certificate_status=$(cat "$work/wrong-certificate.status")
wrong_certificate_stderr=$(redact_stderr "$work/wrong-certificate.status.stderr")
cleanup_work
trap - EXIT
cleanup_verified=false
[ ! -e "$work" ] && cleanup_verified=true
cat <<EOF_JSON
{
  "schema": "io.nisavid.sacrysty.signing-profile-result/v1",
  "source_revision": "$source_revision",
  "reference_time": "20260910",
  "sq_version": "$sq_version",
  "sqv_version": "$sqv_version",
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
    "temporary_key_material_removed": $cleanup_verified
  },
  "diagnostics": {
    "tampered_message": {"command": "sqv --time 20260910 --keyring signer-cert.pgp --signature-file message.sig tampered.bin", "exit_status": $tampered_message_status, "stderr": "$tampered_message_stderr"},
    "tampered_signature": {"command": "sqv --time 20260910 --keyring signer-cert.pgp --signature-file tampered.sig message.bin", "exit_status": $tampered_signature_status, "stderr": "$tampered_signature_stderr"},
    "wrong_certificate": {"command": "sqv --time 20260910 --keyring wrong-cert.pgp --signature-file message.sig message.bin", "exit_status": $wrong_certificate_status, "stderr": "$wrong_certificate_stderr"}
  },
  "production_values_policy": "forbidden",
  "rfc9980": "unsupported-capability-gated"
}
EOF_JSON
