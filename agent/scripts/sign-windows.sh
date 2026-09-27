#!/usr/bin/env bash
# Authenticode-signs Windows files (.exe, .msi) with jsign, from macOS, Linux or Windows.
#   agent/scripts/sign-windows.sh FILE...
#
# Since June 2023 public code-signing keys live in hardware or a cloud HSM, so pick one:
#
#   Azure Trusted Signing (recommended; see docs/SIGNING.md):
#     NEXUS_TRUSTED_SIGNING_ENDPOINT   e.g. https://eus.codesigning.azure.net
#     NEXUS_TRUSTED_SIGNING_ACCOUNT    the Trusted Signing account name
#     NEXUS_TRUSTED_SIGNING_PROFILE    the certificate profile name
#     AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
#                                      an app registration with the "Trusted Signing Certificate
#                                      Profile Signer" role on the account
#   DigiCert KeyLocker (an OV/EV certificate bought from DigiCert):
#     NEXUS_DIGICERT_API_KEY, NEXUS_DIGICERT_CLIENT_CERT (base64 .p12), NEXUS_DIGICERT_CLIENT_CERT_PASSWORD,
#     NEXUS_DIGICERT_KEYPAIR_ALIAS
#   A .pfx (older certificates issued before the HSM rule):
#     NEXUS_WINDOWS_CERT (base64 .pfx), NEXUS_WINDOWS_CERT_PASSWORD
#
# With none set it signs nothing and says so (exit 0), so unsigned dev builds still work.
# NEXUS_JSIGN overrides the jsign command (e.g. "java -jar jsign-7.5.jar").
set -euo pipefail
[[ $# -gt 0 ]] || { echo "usage: sign-windows.sh FILE..." >&2; exit 2; }

jsign_cmd=(${NEXUS_JSIGN:-jsign})
common=(--name "Votal Nexus agent" --url "https://votal.ai" --alg SHA-256 --tsmode RFC3161 --replace)
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

if [[ -n "${NEXUS_TRUSTED_SIGNING_ENDPOINT:-}" ]]; then
  for v in NEXUS_TRUSTED_SIGNING_ACCOUNT NEXUS_TRUSTED_SIGNING_PROFILE AZURE_TENANT_ID AZURE_CLIENT_ID AZURE_CLIENT_SECRET; do
    [[ -n "${!v:-}" ]] || { echo "Trusted Signing needs $v" >&2; exit 1; }
  done
  # An access token for the signing service (client credentials; no Azure CLI needed).
  token="$(curl -fsS "https://login.microsoftonline.com/$AZURE_TENANT_ID/oauth2/v2.0/token" \
    --data-urlencode "grant_type=client_credentials" \
    --data-urlencode "client_id=$AZURE_CLIENT_ID" \
    --data-urlencode "client_secret=$AZURE_CLIENT_SECRET" \
    --data-urlencode "scope=https://codesigning.azure.net/.default" | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')"
  store=(--storetype TRUSTEDSIGNING --keystore "${NEXUS_TRUSTED_SIGNING_ENDPOINT#https://}" --storepass "$token"
    --alias "$NEXUS_TRUSTED_SIGNING_ACCOUNT/$NEXUS_TRUSTED_SIGNING_PROFILE" --tsaurl "http://timestamp.acs.microsoft.com")
  how="Azure Trusted Signing ($NEXUS_TRUSTED_SIGNING_ACCOUNT/$NEXUS_TRUSTED_SIGNING_PROFILE)"
elif [[ -n "${NEXUS_DIGICERT_API_KEY:-}" ]]; then
  printf '%s' "${NEXUS_DIGICERT_CLIENT_CERT:?NEXUS_DIGICERT_CLIENT_CERT is required}" | base64 --decode > "$tmp/client.p12"
  store=(--storetype DIGICERTONE --keystore "https://clientauth.one.digicert.com"
    --storepass "$NEXUS_DIGICERT_API_KEY|$tmp/client.p12|${NEXUS_DIGICERT_CLIENT_CERT_PASSWORD:?}"
    --alias "${NEXUS_DIGICERT_KEYPAIR_ALIAS:?NEXUS_DIGICERT_KEYPAIR_ALIAS is required}" --tsaurl "http://timestamp.digicert.com")
  how="DigiCert KeyLocker ($NEXUS_DIGICERT_KEYPAIR_ALIAS)"
elif [[ -n "${NEXUS_WINDOWS_CERT:-}" ]]; then
  printf '%s' "$NEXUS_WINDOWS_CERT" | base64 --decode > "$tmp/cert.pfx"
  store=(--storetype PKCS12 --keystore "$tmp/cert.pfx" --storepass "${NEXUS_WINDOWS_CERT_PASSWORD:?NEXUS_WINDOWS_CERT_PASSWORD is required}"
    --tsaurl "${NEXUS_TIMESTAMP_URL:-http://timestamp.digicert.com}")
  how="a .pfx certificate"
else
  echo "note: Windows files are not Authenticode-signed (see docs/SIGNING.md): $*"
  exit 0
fi

for f in "$@"; do
  echo "==> sign $(basename "$f") with $how"
  "${jsign_cmd[@]}" "${store[@]}" "${common[@]}" "$f"
done
