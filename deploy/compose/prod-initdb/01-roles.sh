#!/bin/sh
# Creates the runtime role with the password from the environment.
# nexus_owner (POSTGRES_USER) owns the schema and runs migrations; nexus_app is what the
# API uses, and row-level security always applies to it.
set -e
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE nexus_app LOGIN PASSWORD '${NEXUS_APP_DB_PASSWORD}';
GRANT CONNECT ON DATABASE ${POSTGRES_DB} TO nexus_app;
SQL
