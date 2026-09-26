#!/usr/bin/env bash
# Builds, signs and packages an agent release (DEV-01, DEV-07).
#
#   agent/scripts/release.sh 0.2.0 "What changed"
#
# Output: agent/dist/releases/<version>/ (binaries + signed release.json, what
# the API serves to agents) and agent/dist/installers/ (macOS .pkg).
#
# Environment:
#   NEXUS_RELEASE_KEY         private Ed25519 release key file. Default agent/dist/release.key;
#                             a dev key is generated there if missing (never in CI).
#   NEXUS_RELEASE_PUBKEYS     extra public keys agents should trust (key rotation), comma-separated
#   NEXUS_CODESIGN_IDENTITY   "Developer ID Application: …": codesign macOS binaries (hardened runtime)
#   NEXUS_INSTALLER_IDENTITY  "Developer ID Installer: …": sign the .pkg
#   NEXUS_NOTARY_PROFILE      notarytool keychain profile: notarize and staple the .pkg
#   NEXUS_NOTARY_KEY, NEXUS_NOTARY_KEY_ID, NEXUS_NOTARY_ISSUER
#                             …or an App Store Connect API key (.p8 path, key ID, issuer ID), for CI
#   Windows Authenticode signing: see agent/scripts/sign-windows.sh (Azure Trusted Signing,
#                             DigiCert KeyLocker or a .pfx)
#   NEXUS_BUNDLE_OSQUERY      1 (default): ship osquery (pinned in packaging/osquery/osquery.lock) in the
#                             installers; 0: agent only
#   NEXUS_TARGETS             default: "darwin/arm64 darwin/amd64 windows/amd64 windows/arm64 linux/amd64 linux/arm64"
#   NEXUS_TEST_BREAK          test only: "selftest" or "checkin" builds a deliberately broken release
set -euo pipefail

version="${1:?usage: release.sh VERSION [NOTES]}"
notes="${2:-}"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "version must be MAJOR.MINOR.PATCH" >&2; exit 1; }

agent="$(cd "$(dirname "$0")/.." && pwd)"
dist="$agent/dist"
out="$dist/releases/$version"
targets="${NEXUS_TARGETS:-darwin/arm64 darwin/amd64 windows/amd64 windows/arm64 linux/amd64 linux/arm64}"
export GOTOOLCHAIN=local

[[ -e "$out/release.json" ]] && { echo "release $version already exists: releases are immutable, bump the version" >&2; exit 1; }

key="${NEXUS_RELEASE_KEY:-$dist/release.key}"
if [[ ! -f "$key" ]]; then
  [[ -n "${CI:-}" ]] && { echo "NEXUS_RELEASE_KEY is required in CI" >&2; exit 1; }
  echo "==> No release key: generating a DEV key in $dist (agents built with it trust only it)"
  (cd "$agent" && go run ./cmd/nexus-release keygen --out "$dist")
fi
pub="${key%.key}.pub"
[[ -f "$pub" ]] || { echo "missing public key $pub next to the release key" >&2; exit 1; }
keys="$(tr -d '\n' < "$pub")${NEXUS_RELEASE_PUBKEYS:+,$NEXUS_RELEASE_PUBKEYS}"

mkdir -p "$out"
for t in $targets; do
  os="${t%/*}"; arch="${t#*/}"
  bin="$out/nexus-agent-$os-$arch"; [[ "$os" == windows ]] && bin="$bin.exe"
  echo "==> build $os/$arch"
  ldflags="-s -w -X main.version=$version -X main.releaseKeys=$keys ${NEXUS_TEST_BREAK:+-X main.testBreak=$NEXUS_TEST_BREAK}"
  (cd "$agent" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -ldflags "$ldflags" -o "$bin" ./cmd/nexus-agent)
  if [[ "$os" == darwin && -n "${NEXUS_CODESIGN_IDENTITY:-}" ]]; then
    codesign --force --timestamp --options runtime --sign "$NEXUS_CODESIGN_IDENTITY" "$bin"
  fi
done

# Authenticode-sign the Windows binaries now, so the release signature below covers the signed bytes
# (the MSI then ships exactly the binary agents would self-update to).
win=("$out"/nexus-agent-windows-*.exe)
[[ -e "${win[0]}" ]] && "$agent/scripts/sign-windows.sh" "${win[@]}"

# Sign last: the release signature covers the exact (codesigned) bytes agents download.
(cd "$agent" && go run ./cmd/nexus-release sign --key "$key" --version "$version" --dir "$out" --notes "$notes")

# osquery for the installers (not the self-update release: agents update themselves, osquery comes with installers).
if [[ "${NEXUS_BUNDLE_OSQUERY:-1}" == 1 ]]; then
  "$agent/packaging/osquery/fetch.sh" "$dist/osquery"
  export NEXUS_OSQUERY_DIR="$dist/osquery"
fi

if command -v pkgbuild >/dev/null && [[ -f "$out/nexus-agent-darwin-arm64" && -f "$out/nexus-agent-darwin-amd64" ]]; then
  "$agent/packaging/macos/build-pkg.sh" "$version" "$out" "$dist/installers"
fi
if [[ -f "$out/nexus-agent-linux-amd64" || -f "$out/nexus-agent-linux-arm64" ]]; then
  "$agent/packaging/linux/build-packages.sh" "$version" "$out" "$dist/installers"
fi
[[ -z "${NEXUS_CODESIGN_IDENTITY:-}" ]] && echo "note: macOS binaries are not codesigned (set NEXUS_CODESIGN_IDENTITY)"
echo "==> release $version ready in $out"
