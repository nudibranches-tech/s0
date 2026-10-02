#!/usr/bin/env bash
# The Garage leg of the compat run: a real client -> the real s0 -> a real Garage, with an
# `s3` backend on the `garage` profile. Unlike the silo leg in run.sh, which records what
# clients do, this leg ASSERTS: it exits non-zero on the first property that does not hold,
# so CI can run it (`.github/workflows/conformance.yml`, job `garage`).
#
# Usage:  tests/compat/garage.sh       (or `tests/compat/run.sh garage`)
# Env:    KEEP=1     leave the stack up afterwards
#         GW_BIN=…   use this gateway binary instead of building target/release/s0
# Needs:  docker, curl, python3 with boto3.
#
# What it proves:
#
#  * Two tenants of one organization sharing ONE upstream Garage key stay apart. The key
#    holds read+write on both tenants' buckets (Garage's per-key, per-bucket grant — it
#    has no IAM), so Garage itself would serve either bucket to either tenant; only the
#    v3 bundle's placement keeps them apart (ADR-009). Each tenant's principal holds a
#    WILDCARD grant, so every refusal below is the placement, never a missing grant.
#  * The key shape is Garage's per-organization identity: a second organization's key,
#    granted on its own bucket only, cannot reach the first organization's buckets on
#    Garage directly.
#  * An `aws-chunked` PUT carrying a CRC32 trailer (every modern SDK's default upload) goes
#    through s0 to Garage and reads back byte-identical with no stored Content-Encoding —
#    the s0 0.3.3 regression class, which MinIO tolerated and therefore never showed. Both
#    PutObject and UploadPart are sent that way.
#  * The client signs with `us-east-1`; Garage refuses any scope but its own `s3_region`,
#    so every success here is also s0 re-signing upstream with the backend's region.
#
# s0 reaches Garage over TLS, through `tls_relay.py`, as a deployment must: Garage
# terminates no TLS. It is also load-bearing for the trailer checks. Over plain HTTP the
# upstream SDK signs the aws-chunked trailer (STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER),
# and Garage v2.4.1 verifies that trailer signature against a non-standard string to sign
# (the PAYLOAD algorithm label and the last data chunk's signature, where SigV4 specifies
# the TRAILER label and the final zero-length chunk's), so every such upload is refused
# `InvalidRequest: Invalid payload signature`. Over TLS the SDK sends the unsigned trailer
# form, which Garage reads correctly. A Garage endpoint must therefore be https.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="${GARAGE_STATE:-/tmp/s0-compat-garage}"
# v2.4.1, pinned by digest: the plan's capability findings were checked against this
# release's source, so a different Garage is a different claim.
GARAGE_IMAGE="${GARAGE_IMAGE:-dxflrs/garage:v2.4.1@sha256:9c96caa2612d3411acc5b0e6701fb238dbfba33e533a6d7d3d811a4b12d0d020}"
GARAGE_NAME=s0compat-garage
GARAGE_S3_PORT=3900
GARAGE_RPC_PORT=3901
GARAGE_TLS_PORT=3443
GW_PORT=8124
REGION=garage

command -v docker >/dev/null || { echo "MISSING: docker" >&2; exit 1; }
command -v curl >/dev/null || { echo "MISSING: curl" >&2; exit 1; }
command -v openssl >/dev/null || { echo "MISSING: openssl" >&2; exit 1; }
python3 -c 'import boto3' 2>/dev/null || { echo "MISSING: python3 boto3" >&2; exit 1; }

if [ -z "${GW_BIN:-}" ]; then
  # Always rebuild: an asserting leg run against a stale binary proves nothing about HEAD.
  (cd "$ROOT" && cargo build --release)
  GW_BIN="$ROOT/target/release/s0"
fi
[ -x "$GW_BIN" ] || { echo "no gateway binary at $GW_BIN" >&2; exit 1; }

cleanup() {
  if [ "${KEEP:-0}" = "1" ]; then
    echo "KEEP=1 — s0 at http://127.0.0.1:$GW_PORT, Garage at http://127.0.0.1:$GARAGE_S3_PORT"
    return
  fi
  [ -f "$STATE/gw.pid" ] && kill "$(cat "$STATE/gw.pid")" 2>/dev/null || true
  [ -f "$STATE/tls.pid" ] && kill "$(cat "$STATE/tls.pid")" 2>/dev/null || true
  docker rm -f "$GARAGE_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT

rm -rf "$STATE"; mkdir -p "$STATE"

# ── Garage: one node, replication 1, its own region ─────────────────────────────
# No [s3_web] (no anonymous website path) and no [admin] listener: the leg drives
# Garage with its CLI over RPC inside the container.
RPC_SECRET="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
cat > "$STATE/garage.toml" <<TOML
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "127.0.0.1:$GARAGE_RPC_PORT"
rpc_public_addr = "127.0.0.1:$GARAGE_RPC_PORT"
rpc_secret = "$RPC_SECRET"

[s3_api]
s3_region = "$REGION"
api_bind_addr = "127.0.0.1:$GARAGE_S3_PORT"
TOML
# The config holds the RPC secret.
chmod 600 "$STATE/garage.toml"

docker rm -f "$GARAGE_NAME" >/dev/null 2>&1 || true
docker run -d --name "$GARAGE_NAME" --network host \
  -v "$STATE/garage.toml:/etc/garage.toml:ro" "$GARAGE_IMAGE" >/dev/null

garage() { docker exec "$GARAGE_NAME" /garage "$@" 2>/dev/null; }

NODE=""
for _ in $(seq 1 40); do
  NODE="$(garage node id -q | cut -d@ -f1)" && [ -n "$NODE" ] && break
  sleep 1
done
[ -n "$NODE" ] || { echo "Garage did not come up" >&2; docker logs "$GARAGE_NAME" >&2; exit 1; }
garage layout assign -z dc1 -c 1G "$NODE" >/dev/null
garage layout apply --version 1 >/dev/null

# `key create` prints the id and secret once; read them off its output.
key_field() { sed -n "s/^$1:[[:space:]]*//p"; }
new_key() { # name -> "<id> <secret>"
  local out; out="$(garage key create "$1")"
  printf '%s %s\n' "$(key_field 'Key ID' <<<"$out")" "$(key_field 'Secret key' <<<"$out")"
}
read -r ORG_ONE_ID ORG_ONE_SECRET < <(new_key org-one)
read -r ORG_TWO_ID ORG_TWO_SECRET < <(new_key org-two)
[ -n "$ORG_ONE_ID" ] && [ -n "$ORG_ONE_SECRET" ] && [ -n "$ORG_TWO_ID" ] && [ -n "$ORG_TWO_SECRET" ] \
  || { echo "could not read the Garage keys" >&2; exit 1; }

# Buckets are made by the operator's side (here the CLI), never through s0: s0 is
# data-plane only. Each key gets read+write — never owner — on its own organization's
# buckets only.
for b in acme-data globex-data; do
  garage bucket create "$b" >/dev/null
  garage bucket allow --read --write "$b" --key org-one >/dev/null
done
garage bucket create other-org-data >/dev/null
garage bucket allow --read --write other-org-data --key org-two >/dev/null

GARAGE_UP=0
for _ in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$GARAGE_S3_PORT/" || true)" != "000" ] && { GARAGE_UP=1; break; }
  sleep 1
done
[ "$GARAGE_UP" = 1 ] || { echo "Garage's S3 port did not come up" >&2; docker logs "$GARAGE_NAME" >&2; exit 1; }

# ── TLS in front of Garage, from a throwaway CA s0 is told to trust ─────────────
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=s0 compat CA" \
  -keyout "$STATE/ca.key" -out "$STATE/ca.pem" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=127.0.0.1" \
  -keyout "$STATE/tls.key" -out "$STATE/tls.csr" 2>/dev/null
printf 'subjectAltName=IP:127.0.0.1\nbasicConstraints=CA:FALSE\nextendedKeyUsage=serverAuth\n' > "$STATE/tls.ext"
openssl x509 -req -in "$STATE/tls.csr" -CA "$STATE/ca.pem" -CAkey "$STATE/ca.key" -CAcreateserial \
  -days 1 -extfile "$STATE/tls.ext" -out "$STATE/tls.pem" 2>/dev/null
python3 "$ROOT/tests/compat/tls_relay.py" "$GARAGE_TLS_PORT" "$GARAGE_S3_PORT" "$STATE/tls.pem" "$STATE/tls.key" \
  >"$STATE/tls.log" 2>&1 & echo $! > "$STATE/tls.pid"
TLS_UP=0
for _ in $(seq 1 20); do
  curl -s -o /dev/null --cacert "$STATE/ca.pem" "https://127.0.0.1:$GARAGE_TLS_PORT/" && { TLS_UP=1; break; }
  sleep 0.5
done
[ "$TLS_UP" = 1 ] || { echo "the TLS relay did not come up" >&2; cat "$STATE/tls.log" >&2; exit 1; }

# ── s0: one `s3` backend on the garage profile, two tenants on one upstream key ──
cat > "$STATE/bundle.json" <<'JSON'
{
  "grant_schema_version": 3,
  "backend": { "id": "garage", "kind": "s3" },
  "org_settings": { "freeze_writes": false, "reserved_tag_keys": [] },
  "tenants": {
    "acme": {
      "user_attributes": { "acme-user": { "groups": [], "attributes": [] } },
      "bucket_attributes": {
        "acme-data": { "denylist": {}, "object_name": "data", "created_at": "2026-10-01T08:00:00Z" }
      },
      "s3_grants": { "acme-user": [ { "bucket": "*", "actions": ["*"], "prefixes": [] } ] },
      "group_grants": {}
    },
    "globex": {
      "user_attributes": { "globex-user": { "groups": [], "attributes": [] } },
      "bucket_attributes": {
        "globex-data": { "denylist": {}, "object_name": "data", "created_at": "2026-10-01T09:00:00Z" }
      },
      "s3_grants": { "globex-user": [ { "bucket": "*", "actions": ["*"], "prefixes": [] } ] },
      "group_grants": {}
    }
  }
}
JSON

cat > "$STATE/gateway.json" <<JSON
{
  "listen": "127.0.0.1:$GW_PORT",
  "sts": {
    "master_key_hex": "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
    "signing_key_hex": "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100",
    "session_ttl_secs": 3600
  },
  "pdp": { "mode": "embedded", "cache_capacity": 10000 },
  "audit": { "sink_url": "http://127.0.0.1:9099/api/v1/decision-logs", "spill_path": "$STATE/audit-spill.ndjson" },
  "backends": [ { "id": "garage", "kind": "s3", "profile": "garage", "endpoint_url": "https://127.0.0.1:$GARAGE_TLS_PORT", "region": "$REGION", "force_path_style": true } ],
  "tenants": [
    { "tenant": "acme",   "organization_id": "org-one", "backend_id": "garage", "owner_access_key": "$ORG_ONE_ID", "owner_secret_key": "$ORG_ONE_SECRET" },
    { "tenant": "globex", "organization_id": "org-one", "backend_id": "garage", "owner_access_key": "$ORG_ONE_ID", "owner_secret_key": "$ORG_ONE_SECRET" }
  ],
  "static_credentials": [
    { "access_key_id": "AKIAACME",   "secret_access_key": "acme-secret",   "principal_sub": "acme-user",   "tenant": "acme",   "organization_id": "org-one", "groups": [] },
    { "access_key_id": "AKIAGLOBEX", "secret_access_key": "globex-secret", "principal_sub": "globex-user", "tenant": "globex", "organization_id": "org-one", "groups": [] }
  ],
  "bundle_path": "$STATE/bundle.json",
  "bundle_poll_secs": 2
}
JSON
chmod 600 "$STATE/gateway.json"

# SSL_CERT_FILE replaces the trust store the upstream client loads with the throwaway CA.
SSL_CERT_FILE="$STATE/ca.pem" GATEWAY_CONFIG="$STATE/gateway.json" "$GW_BIN" >"$STATE/gw.log" 2>&1 & echo $! > "$STATE/gw.pid"
GW_UP=0
for _ in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$GW_PORT/" || true)" != "000" ] && { GW_UP=1; break; }
  sleep 1
done
[ "$GW_UP" = 1 ] || { echo "the gateway did not come up" >&2; tail -40 "$STATE/gw.log" >&2; exit 1; }

# ── drive and assert ────────────────────────────────────────────────────────────
export S0_EP="http://127.0.0.1:$GW_PORT" GARAGE_EP="http://127.0.0.1:$GARAGE_S3_PORT" GARAGE_REGION="$REGION"
export ORG_ONE_ID ORG_ONE_SECRET ORG_TWO_ID ORG_TWO_SECRET
export AWS_EC2_METADATA_DISABLED=true
if ! python3 "$ROOT/tests/compat/garage_checks.py"; then
  echo "── gateway log (tail) ──" >&2
  tail -40 "$STATE/gw.log" >&2
  exit 1
fi
