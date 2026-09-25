#!/usr/bin/env bash
# Builds the macOS installer package: a universal binary plus a LaunchDaemon.
#   build-pkg.sh VERSION RELEASE_DIR OUT_DIR
set -euo pipefail
version="$1"; rel="$2"; outdir="$3"
here="$(cd "$(dirname "$0")" && pwd)"
root="$(mktemp -d)"; trap 'rm -rf "$root"' EXIT
bindir="$root/Library/Application Support/Nexus/bin"
mkdir -p "$bindir" "$outdir"

lipo -create -output "$bindir/nexus-agent" "$rel/nexus-agent-darwin-arm64" "$rel/nexus-agent-darwin-amd64"
chmod 755 "$bindir/nexus-agent"
if [[ -n "${NEXUS_CODESIGN_IDENTITY:-}" ]]; then
  codesign --force --timestamp --options runtime --sign "$NEXUS_CODESIGN_IDENTITY" "$bindir/nexus-agent"
fi

pkg="$outdir/nexus-agent-$version.pkg"
sign=(); [[ -n "${NEXUS_INSTALLER_IDENTITY:-}" ]] && sign=(--sign "$NEXUS_INSTALLER_IDENTITY" --timestamp)
echo "==> pkgbuild $pkg"
pkgbuild --root "$root" --scripts "$here/scripts" --identifier ai.votal.nexus-agent --version "$version" \
  --install-location / ${sign[@]+"${sign[@]}"} "$pkg"

notary=()
if [[ -n "${NEXUS_NOTARY_KEY:-}" ]]; then
  # An App Store Connect API key: works on CI runners (no keychain profile).
  notary=(--key "$NEXUS_NOTARY_KEY" --key-id "${NEXUS_NOTARY_KEY_ID:?NEXUS_NOTARY_KEY_ID is required}" --issuer "${NEXUS_NOTARY_ISSUER:?NEXUS_NOTARY_ISSUER is required}")
elif [[ -n "${NEXUS_NOTARY_PROFILE:-}" ]]; then
  notary=(--keychain-profile "$NEXUS_NOTARY_PROFILE")
fi
if [[ ${#notary[@]} -gt 0 ]]; then
  [[ ${#sign[@]} -gt 0 ]] || { echo "notarization needs NEXUS_INSTALLER_IDENTITY" >&2; exit 1; }
  echo "==> notarize (Apple checks it for malware and records it; usually a few minutes)"
  out_json="$(xcrun notarytool submit "$pkg" "${notary[@]}" --wait --output-format json)"
  echo "$out_json"
  if ! grep -q '"status" *: *"Accepted"' <<<"$out_json"; then
    id="$(sed -n 's/.*"id" *: *"\([^"]*\)".*/\1/p' <<<"$out_json" | head -1)"
    [[ -n "$id" ]] && xcrun notarytool log "$id" "${notary[@]}" || true
    echo "notarization was not accepted" >&2; exit 1
  fi
  xcrun stapler staple "$pkg"
else
  echo "note: $pkg is not signed/notarized (set NEXUS_INSTALLER_IDENTITY and NEXUS_NOTARY_PROFILE)"
fi
