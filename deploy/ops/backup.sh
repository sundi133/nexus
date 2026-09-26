#!/usr/bin/env bash
# Logical backup of the Nexus database (custom format) with a SHA-256 checksum.
#   DATABASE_URL=postgres://nexus_owner:…@host:5432/nexus deploy/ops/backup.sh ./backups
#   PG_CONTAINER=nexus-postgres-1 deploy/ops/backup.sh ./backups      # use the tools inside a container
# Production should also use the database's point-in-time recovery (WAL archiving / managed PITR);
# these dumps are the portable, restore-tested second line (docs/OPERATIONS.md).
set -euo pipefail
OUT_DIR="${1:-./backups}"
mkdir -p "$OUT_DIR"
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
FILE="$OUT_DIR/nexus-$STAMP.dump"
if [ -n "${PG_CONTAINER:-}" ]; then
  docker exec "$PG_CONTAINER" pg_dump -U "${PGUSER:-nexus_owner}" -d "${PGDATABASE:-nexus}" --format=custom > "$FILE"
else
  pg_dump "${DATABASE_URL:?set DATABASE_URL or PG_CONTAINER}" --format=custom > "$FILE"
fi
shasum -a 256 "$FILE" | awk '{print $1}' > "$FILE.sha256"
echo "backup: $FILE ($(du -h "$FILE" | cut -f1), sha256 $(cut -c1-12 "$FILE.sha256")…)"
