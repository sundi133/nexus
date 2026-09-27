#!/usr/bin/env bash
# High-availability drill on a Kubernetes cluster (CI uses kind): installs the chart, then, under
# steady traffic, does what production does to it and checks nobody notices.
#   1. rolling restart of the API       -> no failed requests
#   2. a node drain evicts an API pod   -> no failed requests
#   3. an upgrade with a new migration  -> no failed requests; the migration Job runs once
#   4. a worker is killed without warning -> the other worker keeps running jobs
#   5. the database restarts (as in a managed failover) -> the API recovers by itself, no pod restarts
# Needs: kubectl, helm, and the images votal/nexus-api:ci and votal/nexus-web:ci in the cluster.
set -euo pipefail
cd "$(dirname "$0")"
NS=nexus-drill
REL=nexus
k() { kubectl -n "$NS" "$@"; }
pass() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; k get pods -o wide; k logs -l app.kubernetes.io/component=api --tail 30 --prefix || true; exit 1; }

kubectl create namespace "$NS" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
k apply -f postgres.yaml >/dev/null
k rollout status statefulset/postgres --timeout 180s >/dev/null
echo "==> installing the chart"
helm upgrade --install "$REL" ../nexus -n "$NS" -f values.yaml --wait --timeout 6m >/dev/null
k wait --for=condition=complete job -l app.kubernetes.io/component=migrate --timeout 120s >/dev/null && pass "migrations ran as a Job"
[ "$(k get deploy $REL-api -o jsonpath='{.status.readyReplicas}')" = 3 ] && pass "3 API pods ready" || fail "API pods"
[ "$(k get deploy $REL-worker -o jsonpath='{.status.readyReplicas}')" = 2 ] && pass "2 workers ready" || fail "workers"
[ "$(k get deploy $REL-web -o jsonpath='{.status.readyReplicas}')" = 2 ] && pass "2 console pods ready" || fail "console"
k create configmap drill-load --from-file=load.mjs --dry-run=client -o yaml | k apply -f - >/dev/null

# Starts steady traffic from inside the cluster (through the Service, like an ingress would).
load() {
  k delete pod "drill-$1" --ignore-not-found --wait >/dev/null
  k apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: { name: drill-$1 }
spec:
  restartPolicy: Never
  containers:
    - name: load
      image: votal/nexus-api:ci
      imagePullPolicy: Never
      command: [node, /drill/load.mjs]
      env:
        - { name: BASE, value: "http://$REL-api:8080" }
        - { name: SECONDS_TO_RUN, value: "$2" }
      volumeMounts: [{ name: d, mountPath: /drill }]
  volumes: [{ name: d, configMap: { name: drill-load } }]
YAML
  k wait --for=condition=Ready "pod/drill-$1" --timeout 60s >/dev/null
  sleep 8   # signed up, traffic flowing
}
# Waits for the load to finish; prints its summary; fails if any request failed (or more than $2).
result() {
  k wait --for=jsonpath='{.status.phase}'=Succeeded "pod/drill-$1" --timeout 300s >/dev/null || { k logs "drill-$1" | tail -20; fail "load $1 didn't finish"; }
  local s; s=$(k logs "drill-$1" | grep '^SUMMARY ' | sed 's/^SUMMARY //')
  echo "       $s" | cut -c1-400
  local ok failed; ok=$(echo "$s" | sed -E 's/.*"ok":([0-9]+).*/\1/'); failed=$(echo "$s" | sed -E 's/.*"failed":([0-9]+).*/\1/')
  [ "$ok" -gt 100 ] || fail "$1: too little traffic ($ok)"
  [ "$failed" -le "${2:-0}" ] || fail "$1: $failed failed requests"
}

echo "==> 1. rolling restart of the API under traffic"
load restart 100
k rollout restart deploy/$REL-api >/dev/null
k rollout status deploy/$REL-api --timeout 240s >/dev/null
result restart && pass "rolling restart: no failed requests"

echo "==> 2. node maintenance: an API pod is evicted (the PodDisruptionBudget allows one at a time)"
load evict 60
POD=$(k get pods -l app.kubernetes.io/component=api -o jsonpath='{.items[0].metadata.name}')
kubectl create --raw "/api/v1/namespaces/$NS/pods/$POD/eviction" -f - <<JSON >/dev/null
{"apiVersion":"policy/v1","kind":"Eviction","metadata":{"name":"$POD","namespace":"$NS"}}
JSON
sleep 1
SECOND=$(k get pods -l app.kubernetes.io/component=api --no-headers | awk -v p="$POD" '$1 != p && $2 == "1/1" && $3 == "Running" { print $1; exit }')
if kubectl create --raw "/api/v1/namespaces/$NS/pods/$SECOND/eviction" -f - >/dev/null 2>&1 <<JSON
{"apiVersion":"policy/v1","kind":"Eviction","metadata":{"name":"$SECOND","namespace":"$NS"}}
JSON
then fail "a second eviction was allowed while one pod was already down"; fi
pass "a second simultaneous eviction is refused"
k rollout status deploy/$REL-api --timeout 180s >/dev/null
result evict && pass "eviction: no failed requests"

echo "==> 3. upgrade to a release with a new migration, under traffic"
load upgrade 90
# Stands in for a new release: a new image tag with a new (backward-compatible) migration.
helm upgrade "$REL" ../nexus -n "$NS" -f values.yaml --set image.api.tag=ci2 --wait --timeout 6m >/dev/null
k wait --for=condition=complete job -l app.kubernetes.io/component=migrate --timeout 120s >/dev/null
# Helm replaces the previous release's Job with this one's (a Job per release, named per image and revision).
JOBS=$(k get jobs -l app.kubernetes.io/component=migrate -o jsonpath='{.items[*].metadata.name}')
[[ "$JOBS" == *-2 ]] && [ "$(echo "$JOBS" | wc -w | tr -d ' ')" = 1 ] && pass "the new release's migration Job ran ($JOBS)" || fail "migration jobs: $JOBS"
k logs -l app.kubernetes.io/component=migrate --tail 50 | grep -q "applied 9999_drill.sql" && pass "the new release's migration applied" || fail "new migration not applied"
result upgrade && pass "upgrade: no failed requests"

echo "==> 4. a worker is killed without warning"
W=$(k get pods -l app.kubernetes.io/component=worker -o jsonpath='{.items[0].metadata.name}')
k delete pod "$W" --grace-period=0 --force >/dev/null 2>&1
sleep 3
[ "$(k get deploy $REL-worker -o jsonpath='{.status.readyReplicas}')" -ge 1 ] && pass "the other worker keeps running" || fail "no worker left"
k rollout status deploy/$REL-worker --timeout 120s >/dev/null && pass "the killed worker is replaced"

echo "==> 5. the database restarts (a managed failover looks like this to the API)"
RESTARTS_BEFORE=$(k get pods -l app.kubernetes.io/component=api -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{" "}{end}')
load dbrestart 100
k delete pod postgres-0 >/dev/null
k rollout status statefulset/postgres --timeout 180s >/dev/null
k wait --for=condition=Ready pod/postgres-0 --timeout 120s >/dev/null
T0=$(date +%s)
until [ "$(k get deploy $REL-api -o jsonpath='{.status.readyReplicas}')" = 3 ]; do
  [ $(( $(date +%s) - T0 )) -lt 90 ] || fail "API not ready 90 s after the database came back"
  sleep 2
done
pass "API ready again $(( $(date +%s) - T0 ))s after the database came back"
result dbrestart 100000   # requests fail while the database is down; what matters is recovery
LAST=$(k logs drill-dbrestart | grep '^{' | tail -2 | head -1)
echo "$LAST" | grep -q '"failed":0' && pass "traffic flowing again with no errors ($LAST)" || fail "still failing after recovery: $LAST"
RESTARTS_AFTER=$(k get pods -l app.kubernetes.io/component=api -o jsonpath='{range .items[*]}{.status.containerStatuses[0].restartCount}{" "}{end}')
[ "$RESTARTS_BEFORE" = "$RESTARTS_AFTER" ] && pass "no API pod restarted (they reconnected)" || fail "API pods restarted: $RESTARTS_BEFORE -> $RESTARTS_AFTER"

echo "==> HA drill passed"
