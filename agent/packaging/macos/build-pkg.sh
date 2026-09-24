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

if [[ -n "${NEXUS_NOTARY_PROFILE:-}" ]]; then
  [[ ${#sign[@]} -gt 0 ]] || { echo "notarization needs NEXUS_INSTALLER_IDENTITY" >&2; exit 1; }
  echo "==> notarize"
  xcrun notarytool submit "$pkg" --keychain-profile "$NEXUS_NOTARY_PROFILE" --wait
  xcrun stapler staple "$pkg"
else
  echo "note: $pkg is not signed/notarized (set NEXUS_INSTALLER_IDENTITY and NEXUS_NOTARY_PROFILE)"
fi
