#!/usr/bin/env bash
# Builds .deb and .rpm packages from a release directory.
#   build-packages.sh VERSION RELEASE_DIR OUT_DIR [ARCHES]
set -euo pipefail
version="${1#v}"; rel="$2"; arches="${4:-amd64 arm64}"
here="$(cd "$(dirname "$0")" && pwd)"
# Absolute before anything changes directory (nfpm runs from the packaging folder).
mkdir -p "$3"
outdir="$(cd "$3" && pwd)"
nfpm=(go run github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.41.3)
for arch in $arches; do
  bin="$(cd "$rel" && pwd)/nexus-agent-linux-$arch"
  [[ -f "$bin" ]] || { echo "skipping $arch: $bin not found" >&2; continue; }
  # nfpm doesn't expand variables in content paths: render the config.
  cfg="$(mktemp "$here/.nfpm-XXXXXX.yaml")"
  osq=""
  if [[ -n "${NEXUS_OSQUERY_DIR:-}" && -f "$NEXUS_OSQUERY_DIR/linux-$arch/osqueryd" ]]; then
    d="$(cd "$NEXUS_OSQUERY_DIR" && pwd)"
    osq="  - { src: $d/linux-$arch/osqueryd, dst: /opt/nexus/osquery/osqueryd, file_info: { mode: 0755 } }\n  - { src: $d/LICENSE-osquery.txt, dst: /opt/nexus/osquery/LICENSE-osquery.txt, file_info: { mode: 0644 } }"
  fi
  sed -e "s|\${NEXUS_VERSION}|$version|g" -e "s|\${NEXUS_ARCH}|$arch|g" -e "s|\${NEXUS_BIN}|$bin|g" -e "s|^#OSQUERY#.*|$osq|" "$here/nfpm.yaml" > "$cfg"
  for fmt in deb rpm; do
    echo "==> $fmt $arch"
    (cd "$here" && "${nfpm[@]}" package --config "$cfg" --packager "$fmt" --target "$outdir/")
  done
  rm -f "$cfg"
done
ls -1 "$outdir"
