#!/usr/bin/env bash
# Fetches the osquery build Nexus bundles, checks it against osquery.lock, and lays it out
# for the installers:
#   agent/packaging/osquery/fetch.sh OUT_DIR [PLATFORMS]
#     PLATFORMS: comma-separated darwin,windows,linux (default all), e.g. "windows" on a Windows CI runner
#     OUT_DIR/darwin/osquery.app             universal, signed by osquery (Apple team 3522FA9PXF)
#     OUT_DIR/windows-amd64/osqueryd.exe     Authenticode-signed by osquery
#     OUT_DIR/windows-arm64/osqueryd.exe
#     OUT_DIR/linux-amd64/osqueryd
#     OUT_DIR/linux-arm64/osqueryd
#     OUT_DIR/LICENSE-osquery.txt, OUT_DIR/VERSION
#
#   agent/packaging/osquery/fetch.sh update VERSION
#     downloads VERSION and rewrites osquery.lock with its hashes (review the diff before committing)
#
# Downloads are cached in NEXUS_OSQUERY_CACHE (default agent/dist/osquery-cache).
# Any hash mismatch stops the build: the lock file is the only thing trusted.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
lock="$here/osquery.lock"
cache="${NEXUS_OSQUERY_CACHE:-$here/../../dist/osquery-cache}"
mkdir -p "$cache"

artifacts() { # the files a version needs
  local v="$1"
  echo "osquery-${v}_1.macos_arm64.tar.gz"   # despite the name: a universal osquery.app
  echo "osquery-${v}.windows_x86_64.zip"
  echo "osquery-${v}.windows_arm64.zip"
  echo "osquery_${v}-1.linux_amd64.deb"
  echo "osquery_${v}-1.linux_arm64.deb"
}
url() { # release asset, or the licence from the tagged source tree
  if [[ "$2" == LICENSE-Apache-2.0 ]]; then echo "https://raw.githubusercontent.com/osquery/osquery/$1/LICENSE-Apache-2.0"; else echo "https://github.com/osquery/osquery/releases/download/$1/$2"; fi
}
sha() { shasum -a 256 "$1" 2>/dev/null | cut -d' ' -f1 || sha256sum "$1" | cut -d' ' -f1; }
download() { # version file → path in cache
  local p="$cache/$1/$2"
  if [[ ! -s "$p" ]]; then
    mkdir -p "$cache/$1"
    echo "==> download $2" >&2
    curl -fsSL --retry 3 -o "$p.part" "$(url "$1" "$2")"
    mv "$p.part" "$p"
  fi
  echo "$p"
}

if [[ "${1:-}" == update ]]; then
  v="${2:?usage: fetch.sh update VERSION}"
  {
    echo "# osquery bundled with the Nexus agent. Written by: fetch.sh update $v"
    echo "# Downloads must match these SHA-256 hashes exactly."
    echo "version $v"
    for f in $(artifacts "$v") LICENSE-Apache-2.0; do echo "$f $(sha "$(download "$v" "$f")")"; done
  } > "$lock"
  cat "$lock"
  exit 0
fi

out="${1:?usage: fetch.sh OUT_DIR [PLATFORMS] | fetch.sh update VERSION}"
platforms=",${2:-darwin,windows,linux},"
want() { [[ "$platforms" == *",$1,"* ]]; }
version="$(awk '$1 == "version" { print $2 }' "$lock")"
[[ -n "$version" ]] || { echo "no version in $lock" >&2; exit 1; }
fetched() { # file → verified path
  local p want got
  p="$(download "$version" "$1")"
  want="$(awk -v f="$1" '$1 == f { print $2 }' "$lock")"
  got="$(sha "$p")"
  if [[ -z "$want" || "$got" != "$want" ]]; then
    rm -f "$p"
    echo "SHA-256 mismatch for $1 (expected ${want:-nothing in osquery.lock}, got $got): refusing to bundle it" >&2
    exit 1
  fi
  echo "$p"
}

rm -rf "$out"; mkdir -p "$out"
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

# macOS: the whole app bundle, untouched: its signature and Endpoint Security entitlement live in it.
if want darwin; then
tar -xzf "$(fetched "osquery-${version}_1.macos_arm64.tar.gz")" -C "$tmp" opt/osquery/lib/osquery.app
mkdir -p "$out/darwin"
mv "$tmp/opt/osquery/lib/osquery.app" "$out/darwin/osquery.app"
if command -v codesign >/dev/null; then
  codesign --verify --strict --deep "$out/darwin/osquery.app"
  info="$(codesign -dv "$out/darwin/osquery.app" 2>&1)" # captured: grep -q in a pipe can SIGPIPE codesign under pipefail
  grep -q "TeamIdentifier=3522FA9PXF" <<<"$info" || { echo "osquery.app isn't signed by osquery's Apple team" >&2; exit 1; }
fi
fi

# Windows: osqueryd.exe alone (osqueryi is the same program).
want windows && for arch in x86_64:amd64 arm64:arm64; do
  z="$(fetched "osquery-${version}.windows_${arch%%:*}.zip")"
  mkdir -p "$out/windows-${arch##*:}"
  unzip -q -o -j "$z" "osquery-${version}.windows_${arch%%:*}/Program Files/osquery/osqueryd/osqueryd.exe" -d "$out/windows-${arch##*:}"
  if command -v osslsigncode >/dev/null; then
    # Signer only: osslsigncode exits non-zero when it can't build the chain without a CA bundle; Windows checks that.
    sig="$(osslsigncode verify -in "$out/windows-${arch##*:}/osqueryd.exe" 2>&1 || true)"
    grep -q "Signer's certificate" <<<"$sig" && grep -q "Subject: CN=OSQUERY a Series of LF Projects" <<<"$sig" || { echo "osqueryd.exe (${arch##*:}) isn't signed by osquery" >&2; exit 1; }
  fi
done

# Linux: osqueryd from the .deb (the same binary the .rpm has).
want linux && for arch in amd64 arm64; do
  d="$(fetched "osquery_${version}-1.linux_${arch}.deb")"
  mkdir -p "$tmp/deb-$arch" "$out/linux-$arch"
  (cd "$tmp/deb-$arch" && ar x "$d" data.tar.gz && tar -xzf data.tar.gz ./opt/osquery/bin/osqueryd)
  install -m 0755 "$tmp/deb-$arch/opt/osquery/bin/osqueryd" "$out/linux-$arch/osqueryd"
done

cp "$(fetched LICENSE-Apache-2.0)" "$out/LICENSE-osquery.txt"
echo "$version" > "$out/VERSION"
echo "==> osquery $version ready in $out"
