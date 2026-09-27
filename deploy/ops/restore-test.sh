#!/usr/bin/env bash
# Proves a backup restores: loads it into a scratch database on the same server, checks the schema
# version, row counts and tenant isolation (RLS + policies), then drops the scratch database.
#   PG_CONTAINER=nexus-postgres-1 deploy/ops/restore-test.sh backups/nexus-….dump
#   DATABASE_URL=postgres://nexus_owner:…@host:5432/nexus deploy/ops/restore-test.sh backups/nexus-….dump
set -euo pipefail
DUMP="${1:?usage: restore-test.sh <dump file>}"
[ -f "$DUMP.sha256" ] && { [ "$(shasum -a 256 "$DUMP" | awk '{print $1}')" = "$(cat "$DUMP.sha256")" ] || { echo "checksum mismatch: $DUMP is corrupted"; exit 1; }; echo "  ok   checksum"; }
SCRATCH="nexus_restore_$(date +%s)"
SRC_DB="${PGDATABASE:-nexus}"
if [ -n "${PG_CONTAINER:-}" ]; then
  psql_src()  { docker exec -i "$PG_CONTAINER" psql -U "${PGUSER:-nexus_owner}" -d "$SRC_DB" -tAq -v ON_ERROR_STOP=1 "$@"; }
  psql_to()   { docker exec -i "$PG_CONTAINER" psql -U "${PGUSER:-nexus_owner}" -d "$SCRATCH" -tAq -v ON_ERROR_STOP=1 "$@"; }
  restore()   { docker exec -i "$PG_CONTAINER" pg_restore -U "${PGUSER:-nexus_owner}" -d "$SCRATCH" --exit-on-error < "$DUMP"; }
else
  BASE="${DATABASE_URL:?set DATABASE_URL or PG_CONTAINER}"
  psql_src()  { psql "$BASE" -tAq -v ON_ERROR_STOP=1 "$@"; }
  psql_to()   { psql "${BASE%/*}/$SCRATCH" -tAq -v ON_ERROR_STOP=1 "$@"; }
  restore()   { pg_restore -d "${BASE%/*}/$SCRATCH" --exit-on-error "$DUMP"; }
fi
cleanup() { psql_src -c "DROP DATABASE IF EXISTS $SCRATCH" >/dev/null 2>&1 || true; }
trap cleanup EXIT

START=$(date +%s)
psql_src -c "CREATE DATABASE $SCRATCH" >/dev/null
restore
echo "  ok   restored into $SCRATCH in $(( $(date +%s) - START ))s"

LATEST=$(ls "$(dirname "$0")/../../apps/api/migrations" | sort | tail -1)
GOT=$(psql_to -c "SELECT max(version) FROM schema_migrations")
[ "$GOT" = "$LATEST" ] && echo "  ok   schema at $GOT" || echo "  note schema at $GOT (this checkout ships $LATEST)"

UNPROTECTED=$(psql_to -c "SELECT string_agg(c.relname, ', ') FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE n.nspname = 'public' AND c.relkind = 'r' AND c.relname <> 'schema_migrations'
    AND (NOT c.relrowsecurity OR NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid))")
[ -z "$UNPROTECTED" ] && echo "  ok   row-level security and policies restored on every table" || { echo "  FAIL tables without RLS after restore: $UNPROTECTED"; exit 1; }

for t in organizations users audit_events devices applications; do
  a=$(psql_src -c "SELECT count(*) FROM $t"); b=$(psql_to -c "SELECT count(*) FROM $t")
  # The source keeps changing after the dump (audit, sessions…), so the copy may trail it but never exceed it.
  [ "$b" -gt 0 ] && [ "$b" -le "$a" ] && echo "  ok   $t: $b rows (live: $a)" || { echo "  FAIL $t: restored $b, live $a"; exit 1; }
done
echo "==> restore test passed"
