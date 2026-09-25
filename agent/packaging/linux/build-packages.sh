#!/usr/bin/env bash
# Builds .deb and .rpm packages from a release directory.
#   build-packages.sh VERSION RELEASE_DIR OUT_DIR [ARCHES]
set -euo pipefail
version="${1#v}"; rel="$2"; outdir="$3"; arches="${4:-amd64 arm64}"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$outdir"
nfpm=(go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.3)
for arch in $arches; do
  bin="$(cd "$rel" && pwd)/nexus-agent-linux-$arch"
  [[ -f "$bin" ]] || { echo "skipping $arch: $bin not found" >&2; continue; }
  # nfpm doesn't expand variables in content paths: render the config.
  cfg="$(mktemp "$here/.nfpm-XXXXXX.yaml")"
  sed -e "s|\${NEXUS_VERSION}|$version|g" -e "s|\${NEXUS_ARCH}|$arch|g" -e "s|\${NEXUS_BIN}|$bin|g" "$here/nfpm.yaml" > "$cfg"
  for fmt in deb rpm; do
    echo "==> $fmt $arch"
    (cd "$here" && "${nfpm[@]}" package --config "$cfg" --packager "$fmt" --target "$(cd "$outdir" && pwd)/")
  done
  rm -f "$cfg"
done
ls -1 "$outdir"
