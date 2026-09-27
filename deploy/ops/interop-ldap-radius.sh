#!/usr/bin/env bash
# Checks Nexus's LDAP directory and RADIUS server with the standard tools admins use: OpenLDAP's
# ldapsearch and FreeRADIUS's radclient. Needs an API started with NEXUS_LDAP_PORT and
# NEXUS_RADIUS_PORT, and creates its own organization.
#   API=http://localhost:8099 LDAP_PORT=1389 RADIUS_PORT=1812 deploy/ops/interop-ldap-radius.sh
set -euo pipefail
API=${API:-http://localhost:8099}
LDAP_PORT=${LDAP_PORT:-1389}
RADIUS_PORT=${RADIUS_PORT:-1812}
pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; exit 1; }
json() { node -e "let s='';process.stdin.on('data',d=>s+=d).on('end',()=>{const v=JSON.parse(s);console.log(${1})})"; }
call() { curl -fsS -X "$1" "$API$2" -H 'content-type: application/json' ${TOKEN:+-H "authorization: Bearer $TOKEN"} ${3:+-d "$3"}; }

RUN=$RANDOM$RANDOM
PW="interop-${RUN}-Quartz-violet"
TOKEN=$(call POST /v1/signup "{\"organization_name\":\"Interop $RUN\",\"email\":\"admin-$RUN@interop.example\",\"password\":\"$PW\",\"given_name\":\"A\"}" | json v.token)
call PATCH /v1/org/settings '{"mfa_policy":"off"}' >/dev/null
BOB="bob-$RUN@interop.example"
call POST /v1/users "{\"email\":\"$BOB\",\"given_name\":\"Bob\",\"family_name\":\"Builder\",\"password\":\"$PW\"}" >/dev/null
call PUT /v1/directory-services '{"ldap_enabled":true,"radius_enabled":true,"radius_mfa":"off"}' >/dev/null
ACCOUNT=$(call POST /v1/directory-services/ldap/service-accounts '{"name":"interop"}')
DN=$(echo "$ACCOUNT" | json v.dn)
SVC_PW=$(echo "$ACCOUNT" | json v.password)
BASE=$(call GET /v1/directory-services | json v.ldap.base_dn)

echo "==> LDAP with ldapsearch"
OUT=$(ldapsearch -LLL -x -H "ldap://127.0.0.1:$LDAP_PORT" -D "$DN" -w "$SVC_PW" -b "$BASE" "(mail=$BOB)" mail cn sn)
echo "$OUT" | grep -q "^mail: $BOB" && echo "$OUT" | grep -q "^cn: Bob Builder" && pass "a service account finds Bob" || fail "service search: $OUT"
OUT=$(ldapsearch -LLL -x -H "ldap://127.0.0.1:$LDAP_PORT" -D "uid=$BOB,ou=users,$BASE" -w "$PW" -b "$BASE" "(objectClass=*)" dn)
echo "$OUT" | grep -qi "dn: uid=$BOB,ou=users,$BASE" && pass "Bob binds with his Nexus password and sees his entry" || fail "user bind: $OUT"
if ldapsearch -LLL -x -H "ldap://127.0.0.1:$LDAP_PORT" -D "uid=$BOB,ou=users,$BASE" -w "wrong" -b "$BASE" "(objectClass=*)" dn >/dev/null 2>&1; then fail "a wrong password was accepted"; fi
pass "a wrong password is refused"

if ! command -v radclient >/dev/null; then echo "  skip radclient isn't installed (apt-get install freeradius-utils)"; exit 0; fi
echo "==> RADIUS with radclient"
SECRET=$(call POST /v1/directory-services/radius/clients '{"name":"interop","address":"127.0.0.1"}' | json v.secret)
auth() { printf 'User-Name = "%s"\nUser-Password = "%s"\nMessage-Authenticator = 0x00\n' "$1" "$2" | radclient -x -r 1 -t 3 "127.0.0.1:$RADIUS_PORT" auth "$SECRET" 2>&1 || true; }
OUT=$(auth "$BOB" "$PW")
echo "$OUT" | grep -q "Access-Accept" && pass "radclient: Access-Accept for the right password" || fail "radius accept: $OUT"
OUT=$(auth "$BOB" "wrong-password")
echo "$OUT" | grep -q "Access-Reject" && pass "radclient: Access-Reject for a wrong one" || fail "radius reject: $OUT"
call DELETE "/v1/directory-services/radius/clients/$(call GET /v1/directory-services | json 'v.radius.clients[0].id')" >/dev/null
echo "==> LDAP and RADIUS interop passed"
