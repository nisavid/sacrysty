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
trap 'rm -rf "$work"' EXIT
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

cp "$message" "$tampered"
printf 'tamper\n' >>"$tampered"
if "$sqv_bin" --time 20260910 --keyring "$cert" --signature-file "$sig" \
  "$tampered" >"$work/tampered-message.log" 2>&1; then
  echo 'tampered message unexpectedly verified' >&2
  exit 1
fi
cp "$sig" "$tampered_sig"
printf 'tamper\n' >>"$tampered_sig"
if "$sqv_bin" --time 20260910 --keyring "$cert" --signature-file "$tampered_sig" \
  "$message" >"$work/tampered-signature.log" 2>&1; then
  echo 'tampered signature unexpectedly verified' >&2
  exit 1
fi

"$sq_bin" "${common[@]}" --time 20260910 key generate --own-key \
  --userid 'Sacrysty Other Fixture <other@example.invalid>' --profile rfc9580 \
  --cipher-suite cv25519 --without-password --output "$wrong_key" \
  --rev-cert "$work/wrong-revocation.asc" >"$work/wrong-generate.log" 2>&1
"$sq_bin" "${common[@]}" key delete --cert-file "$wrong_key" --output "$wrong_cert" >"$work/wrong-extract.log" 2>&1
if "$sqv_bin" --time 20260910 --keyring "$wrong_cert" --signature-file "$sig" \
  "$message" >"$work/wrong-certificate.log" 2>&1; then
  echo 'signature unexpectedly verified with wrong certificate' >&2
  exit 1
fi

sha256() { sha256sum "$1" | awk '{print $1}'; }
sha512() { sha512sum "$1" | awk '{print $1}'; }
source_revision=$(git -C "$root" rev-parse HEAD)
sq_version=$("$sq_bin" version 2>&1 | tr '\n' ' ' | sed 's/[[:space:]]*$//')
sqv_version=$("$sqv_bin" --version)
cat <<EOF_JSON
{
  "schema": "io.nisavid.sacrysty.signing-profile-result/v1",
  "source_revision": "$source_revision",
  "reference_time": "20260910",
  "sq_version": "$sq_version",
  "sqv_version": "$sqv_version",
  "profile": "openpgp-rfc9580-classical-v1",
  "fixtures": {
    "message": {"bytes": $(wc -c <"$message" | tr -d ' '), "sha256": "$(sha256 "$message")", "sha512": "$(sha512 "$message")"},
    "signature": {"bytes": $(wc -c <"$sig" | tr -d ' '), "sha256": "$(sha256 "$sig")", "sha512": "$(sha512 "$sig")"}
  },
  "checks": {
    "detached_sign_verify": true,
    "tampered_message_rejected": true,
    "tampered_signature_rejected": true,
    "wrong_certificate_rejected": true,
    "temporary_key_material": true,
    "production_values": false
  },
  "rfc9980": "unsupported-capability-gated"
}
EOF_JSON
