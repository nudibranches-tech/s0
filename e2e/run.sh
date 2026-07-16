#!/usr/bin/env bash
# Local end-to-end: gateway -> sidecar OPA (real) -> MinIO backend -> audit spill.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out
rm -f out/audit-spill.ndjson
pkill -f 'target/release/hyperfluid-s3-gateway' 2>/dev/null || true

echo "== build gateway + smoke driver =="
( cd .. && cargo build --release --bin hyperfluid-s3-gateway --example e2e_smoke )

echo "== up minio + opa =="
docker compose up -d
cleanup() { kill "${GW:-0}" 2>/dev/null || true; docker compose down -v >/dev/null 2>&1 || true; }
trap cleanup EXIT

wait_for() { for _ in $(seq 1 40); do curl -s -o /dev/null "$1" && return 0; sleep 0.5; done; return 1; }
wait_for localhost:8181/health || { echo "opa not ready"; docker compose logs opa; exit 1; }
wait_for localhost:9000/minio/health/live || { echo "minio not ready"; exit 1; }

echo "-- opa loaded data.tenants: $(curl -s localhost:8181/v1/data/tenants | head -c 120)"

echo "== start gateway (sidecar OPA mode) =="
GATEWAY_CONFIG="$PWD/gateway.e2e.json" ../target/release/hyperfluid-s3-gateway >out/gateway.log 2>&1 &
GW=$!
wait_for localhost:8014/ || { echo "gateway not ready"; cat out/gateway.log; exit 1; }

echo "== run smoke =="
../target/release/examples/e2e_smoke
RC=$?

echo "== drain audit (shutdown flush -> spill) =="
sleep 3
kill "$GW"; wait "$GW" 2>/dev/null || true; GW=0
if [ -s out/audit-spill.ndjson ]; then
  echo "-- $(wc -l <out/audit-spill.ndjson) decision records spilled; sample:"
  head -1 out/audit-spill.ndjson | (command -v jq >/dev/null && jq '{path,action:.input.action,object:.input.object,allow:.result.allow,outcome:.gateway.outcome,sub:.requested_by}' || cat)
else
  echo "WARN: no audit spill produced"; RC=1
fi

exit $RC
