#!/usr/bin/env bash
set -euo pipefail

# Public, disposable conformance probe. It creates all key material in a
# temporary directory and removes it on exit. It never uses a default key or
# certificate store.
root_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
sq_bin=${SQ:-sq}
sqv_bin=${SQV:-sqv}
command -v "$sq_bin" >/dev/null
command -v "$sqv_bin" >/dev/null
command -v python3 >/dev/null

if [[ -n $(git -C "$root_dir" status --porcelain=v1 --untracked-files=normal) ]]; then
  echo 'conformance evidence requires a clean worktree' >&2
  exit 1
fi

if command -v sha256sum >/dev/null 2>&1 && command -v sha512sum >/dev/null 2>&1; then
  hash_tools=gnu
elif command -v shasum >/dev/null 2>&1; then
  hash_tools=shasum
else
  echo 'SHA-256 and SHA-512 tools are unavailable' >&2
  exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/sacrysty-conformance.XXXXXX")
cleanup_work_dir() {
  if [[ -n ${work_dir:-} ]]; then
    rm -rf -- "$work_dir"
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

"$sq_bin" --cli-version 1.4.0 --home none --key-store none --cert-store none --time 20260910 key generate \
  --own-key --userid 'Sacrysty Fixture <fixture@example.invalid>' \
  --profile rfc9580 --cipher-suite cv25519 --without-password \
  --output "$key" --rev-cert "$revocation" >"$work_dir/generate.log" 2>&1
"$sq_bin" --cli-version 1.4.0 --home none --key-store none --cert-store none key delete --cert-file "$key" --output "$certificate" >"$work_dir/extract.log" 2>&1
"$sq_bin" --cli-version 1.4.0 --home none --key-store none --cert-store none --time 20260910 sign --signer-file "$key" \
  --signature-file "$signature" --binary "$message" >"$work_dir/sign.log" 2>&1
"$sqv_bin" --time 20260910 --keyring "$certificate" --signature-file "$signature" \
  "$message" >"$work_dir/verify.log" 2>&1

cp "$message" "$tampered"
printf 'tamper\n' >>"$tampered"
if "$sqv_bin" --time 20260910 --keyring "$certificate" --signature-file "$signature" \
  "$tampered" >"$work_dir/tamper.log" 2>&1; then
  echo 'tampered-message unexpectedly verified' >&2
  exit 1
fi

cp "$signature" "$tampered_signature"
printf 'tamper\n' >>"$tampered_signature"
if "$sqv_bin" --time 20260910 --keyring "$certificate" --signature-file "$tampered_signature" \
  "$message" >"$work_dir/tampered-signature.log" 2>&1; then
  echo 'tampered-signature unexpectedly verified' >&2
  exit 1
fi

"$sq_bin" --cli-version 1.4.0 --home none --key-store none --cert-store none --time 20260910 key generate \
  --own-key --userid 'Sacrysty Other Fixture <other@example.invalid>' \
  --profile rfc9580 --cipher-suite cv25519 --without-password \
  --output "$other_key" --rev-cert "$work_dir/other-rev.pgp" >"$work_dir/other-generate.log" 2>&1
"$sq_bin" --cli-version 1.4.0 --home none --key-store none --cert-store none key delete \
  --cert-file "$other_key" --output "$other_certificate" >"$work_dir/other-extract.log" 2>&1
if "$sqv_bin" --time 20260910 --keyring "$other_certificate" --signature-file "$signature" \
  "$message" >"$work_dir/wrong-certificate.log" 2>&1; then
  echo 'signature unexpectedly verified with wrong certificate' >&2
  exit 1
fi

# RFC 9980 is capability-gated. A failed probe is recorded as unqualified;
# it must never be reported as PQ support merely because help lists an option.
pqc_result=unsupported
if "$sq_bin" --cli-version 1.4.0 --home none --key-store none --cert-store none --time 20260910 key generate \
  --own-key --userid 'Sacrysty PQC Probe <pqc@example.invalid>' \
  --profile rfc9580 --cipher-suite mldsa65-ed25519 --without-password \
  --output "$work_dir/pqc-key.pgp" --rev-cert "$work_dir/pqc-rev.pgp" \
  >"$work_dir/pqc.log" 2>&1; then
  if "$sq_bin" --cli-version 1.4.0 --home none --key-store none --cert-store none \
    key delete --cert-file "$work_dir/pqc-key.pgp" --output "$work_dir/pqc-cert.pgp" \
    >"$work_dir/pqc-extract.log" 2>&1 \
    && "$sq_bin" --cli-version 1.4.0 --home none --key-store none --cert-store none \
      --time 20260910 sign --signer-file "$work_dir/pqc-key.pgp" \
      --signature-file "$work_dir/pqc.sig" --binary "$message" >"$work_dir/pqc-sign.log" 2>&1 \
    && "$sqv_bin" --time 20260910 --keyring "$work_dir/pqc-cert.pgp" --signature-file "$work_dir/pqc.sig" \
      "$message" >"$work_dir/pqc-verify.log" 2>&1; then
    pqc_result=qualified
  else
    pqc_result=round-trip-failed
  fi
fi

sha256() {
  if [[ $hash_tools == gnu ]]; then
    sha256sum -- "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

sha512() {
  if [[ $hash_tools == gnu ]]; then
    sha512sum -- "$1" | awk '{print $1}'
  else
    shasum -a 512 "$1" | awk '{print $1}'
  fi
}

json_string() {
  python3 -c 'import json, sys; json.dump(sys.stdin.read(), sys.stdout)'
}

source_revision=$(git -C "$root_dir" rev-parse HEAD)
sq_version=$("$sq_bin" version 2>&1 | json_string)
sqv_version=$("$sqv_bin" --version 2>&1 | json_string)
message_bytes=$(wc -c <"$message" | tr -d ' ')
signature_bytes=$(wc -c <"$signature" | tr -d ' ')
tampered_bytes=$(wc -c <"$tampered" | tr -d ' ')
tampered_signature_bytes=$(wc -c <"$tampered_signature" | tr -d ' ')
message_sha256=$(sha256 "$message")
message_sha512=$(sha512 "$message")
signature_sha256=$(sha256 "$signature")
signature_sha512=$(sha512 "$signature")
tampered_sha256=$(sha256 "$tampered")
tampered_sha512=$(sha512 "$tampered")
tampered_signature_sha256=$(sha256 "$tampered_signature")
tampered_signature_sha512=$(sha512 "$tampered_signature")

removed_work_dir=$work_dir
if ! cleanup_work_dir || [[ -e $removed_work_dir ]]; then
  echo 'temporary conformance directory cleanup failed' >&2
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
