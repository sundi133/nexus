#!/usr/bin/env bash
# Boots the production images with production settings and checks the essentials, then tears down.
#   deploy/compose/smoke-test.sh            (needs Docker; builds the images)
set -euo pipefail
cd "$(dirname "$0")"
ENV_FILE=$(mktemp)
trap 'docker compose -p nexus-smoke -f docker-compose.prod.yml -f smoke.override.yml --env-file "$ENV_FILE" down -v >/dev/null 2>&1; rm -f "$ENV_FILE"' EXIT
rand() { openssl rand -base64 32 | tr -d '\n'; }
cat > "$ENV_FILE" <<ENV
NEXUS_CONSOLE_HOST=nexus.localhost
NEXUS_API_HOST=api.nexus.localhost
NEXUS_OWNER_DB_PASSWORD=$(rand | tr -dc 'A-Za-z0-9' | head -c 24)
NEXUS_APP_DB_PASSWORD=$(rand | tr -dc 'A-Za-z0-9' | head -c 24)
NEXUS_SEAL_KEYS=1:$(rand)
NEXUS_SMTP_URL=smtp://localhost:1025
NEXUS_MAIL_FROM="Votal Nexus <no-reply@nexus.localhost>"
NEXUS_METRICS_TOKEN=$(rand | tr -dc 'A-Za-z0-9' | head -c 32)
ENV
set -a; . "$ENV_FILE"; set +a
compose() { docker compose -p nexus-smoke -f docker-compose.prod.yml -f smoke.override.yml --env-file "$ENV_FILE" "$@"; }

echo "==> starting db, migrations, api, worker, web (production mode)"
compose up -d --build --wait db migrate api worker web >/dev/null
pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; compose logs --tail 40 api worker migrate; exit 1; }

curl -fs localhost:18080/readyz | grep -q '"ok":true' && pass "API ready, schema current" || fail "readyz"
EMAIL="smoke-$RANDOM@smoke-test.example"
TOKEN=$(curl -fs -X POST localhost:18080/v1/signup -H 'content-type: application/json' \
  -d "{\"organization_name\":\"Smoke\",\"email\":\"$EMAIL\",\"password\":\"violet-harbor-quartz-smoke\",\"given_name\":\"S\"}" | sed -E 's/.*"token":"([^"]+)".*/\1/')
[ -n "$TOKEN" ] && pass "signup" || fail "signup"
curl -fs localhost:18080/v1/me -H "authorization: Bearer $TOKEN" | grep -q "$EMAIL" && pass "authenticated call" || fail "/v1/me"
[ "$(curl -s -o /dev/null -w '%{http_code}' localhost:18080/v1/users)" = 401 ] && pass "deny by default" || fail "anonymous call not refused"
[ "$(curl -s -o /dev/null -w '%{http_code}' localhost:18080/metrics)" = 401 ] && pass "metrics need the token" || fail "metrics open"
curl -fs localhost:18080/metrics -H "authorization: Bearer $NEXUS_METRICS_TOKEN" | grep -q nexus_http_requests_total && pass "metrics scrape" || fail "metrics"
H=$(curl -fsI localhost:13100/login)
echo "$H" | grep -qi "content-security-policy: default-src 'self'" && pass "console CSP" || fail "CSP header"
echo "$H" | grep -qi "strict-transport-security" && pass "console HSTS" || fail "HSTS header"
compose ps --format '{{.Service}} {{.Status}}' | grep -q "worker.*Up" && pass "worker running" || fail "worker"
echo "==> production smoke test passed"
