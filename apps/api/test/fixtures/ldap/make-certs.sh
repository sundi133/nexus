#!/usr/bin/env bash
# Makes a throwaway CA and a server certificate for the test LDAP server (localhost, 127.0.0.1).
# Usage: make-certs.sh <dir>   Nothing here is secret or committed.
set -euo pipefail
dir="${1:?output directory}"
mkdir -p "$dir"
cd "$dir"
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=Nexus Test LDAP CA" -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n" > ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 30 -extfile ext.cnf -out server.crt 2>/dev/null
chmod 644 ./*.key ./*.crt
echo "$dir/ca.crt"
