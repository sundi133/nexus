#!/usr/bin/env bash
# Checks that a release is signed the way enterprises and MDMs expect. Fails loudly otherwise.
#   agent/scripts/verify-signatures.sh RELEASE_DIR INSTALLERS_DIR [--mac] [--windows]
#
#   --mac      (on macOS) binaries: Developer ID, hardened runtime, secure timestamp;
#              .pkg: Developer ID Installer, notarized and stapled, accepted by Gatekeeper
#   --windows  (anywhere, with osslsigncode) .exe and .msi: valid Authenticode signature and timestamp
#   NEXUS_EXPECT_TEAM_ID  (optional) the Apple Team ID every macOS signature must carry
set -euo pipefail
rel="${1:?release dir}"; inst="${2:?installers dir}"; shift 2
mac=0; win=0
for a in "$@"; do case "$a" in --mac) mac=1 ;; --windows) win=1 ;; esac; done
fail=0
ok() { echo "  ok   $*"; }
bad() { echo "  FAIL $*"; fail=1; }

if [[ $mac == 1 ]]; then
  echo "==> macOS"
  for b in "$rel"/nexus-agent-darwin-*; do
    [[ -e "$b" ]] || continue
    if ! codesign --verify --strict --verbose=2 "$b" 2>/dev/null; then bad "$(basename "$b"): signature invalid"; continue; fi
    info="$(codesign -dvvv "$b" 2>&1)"
    grep -q "Authority=Developer ID Application" <<<"$info" && ok "$(basename "$b"): Developer ID" || bad "$(basename "$b"): not signed with a Developer ID Application certificate"
    grep -q "flags=.*runtime" <<<"$info" && ok "$(basename "$b"): hardened runtime" || bad "$(basename "$b"): hardened runtime missing (notarization will refuse it)"
    grep -q "^Timestamp=" <<<"$info" && ok "$(basename "$b"): secure timestamp" || bad "$(basename "$b"): no secure timestamp"
    if [[ -n "${NEXUS_EXPECT_TEAM_ID:-}" ]]; then grep -q "TeamIdentifier=$NEXUS_EXPECT_TEAM_ID" <<<"$info" && ok "$(basename "$b"): team $NEXUS_EXPECT_TEAM_ID" || bad "$(basename "$b"): wrong team"; fi
  done
  for p in "$inst"/*.pkg; do
    [[ -e "$p" ]] || continue
    pkgutil --check-signature "$p" | grep -q "Developer ID Installer" && ok "$(basename "$p"): Developer ID Installer" || bad "$(basename "$p"): not signed with a Developer ID Installer certificate"
    xcrun stapler validate "$p" >/dev/null 2>&1 && ok "$(basename "$p"): notarization ticket stapled" || bad "$(basename "$p"): not notarized/stapled"
    spctl --assess --type install --verbose=2 "$p" 2>&1 | grep -q "accepted" && ok "$(basename "$p"): Gatekeeper accepts it" || bad "$(basename "$p"): Gatekeeper rejects it"
    # Bundled osquery: still exactly as osquery signed it.
    if pkgutil --payload-files "$p" 2>/dev/null | grep -q "osquery.app/Contents/MacOS/osqueryd"; then
      x="$(mktemp -d)"
      pkgutil --expand-full "$p" "$x/pkg" >/dev/null 2>&1
      app="$(find "$x/pkg" -type d -name osquery.app | head -1)"
      info="$(codesign -dv "$app" 2>&1 || true)"
      codesign --verify --strict --deep "$app" 2>/dev/null && grep -q "TeamIdentifier=3522FA9PXF" <<<"$info" && ok "$(basename "$p"): bundled osquery signed by osquery" || bad "$(basename "$p"): bundled osquery.app signature is broken"
      rm -rf "$x"
    fi
  done
fi

if [[ $win == 1 ]]; then
  echo "==> Windows"
  for f in "$rel"/nexus-agent-windows-*.exe "$inst"/*.msi; do
    [[ -e "$f" ]] || continue
    # Chain trust is Windows' job (checked in CI with Get-AuthenticodeSignature); here: signed and timestamped.
    out="$(osslsigncode verify -in "$f" 2>&1 || true)"
    grep -q "Signer's certificate" <<<"$out" && ok "$(basename "$f"): Authenticode signature" || { bad "$(basename "$f"): not Authenticode-signed"; continue; }
    grep -q "Timestamp time" <<<"$out" && ok "$(basename "$f"): timestamped" || bad "$(basename "$f"): not timestamped (it would stop verifying when the certificate expires)"
  done
fi

[[ $fail == 0 ]] && echo "==> signatures OK" || { echo "==> signature problems (see FAIL lines)" >&2; exit 1; }
