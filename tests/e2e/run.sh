#!/usr/bin/env bash
# Real-stack end-to-end: real S3 clients (aws-cli) -> s0-gas gateway -> MinIO
# backend, with the embedded OPA (regorus) engine and a pushed policy bundle.
# Proves the security properties against a real S3 stack, not mocks — most
# importantly that a server-side copy whose SOURCE is denied is blocked (the
# Ceph RGW-OPA copy gap), enforced through an off-the-shelf client.
#
# Uses `docker --network host` throughout so it works even where the Docker NAT
# chain for published ports is unavailable, and identically in CI.
#
# Env overrides: GW_ENDPOINT, MINIO_ENDPOINT, MINIO_IMAGE, AWSCLI_IMAGE,
# GW_BIN (prebuilt binary; else cargo build).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E="$ROOT/tests/e2e"
STATE="/tmp/s0-gas-e2e"

GW_ENDPOINT="${GW_ENDPOINT:-http://127.0.0.1:8014}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://127.0.0.1:9000}"
MINIO_IMAGE="${MINIO_IMAGE:-minio/minio:latest}"
AWSCLI_IMAGE="${AWSCLI_IMAGE:-amazon/aws-cli:latest}"

MINIO_NAME="s0gas-e2e-minio"
BACKEND_AK="minioadmin"; BACKEND_SK="minioadmin"
WORK="$(mktemp -d)"
GW_PID=""
PASS=0; FAIL=0

c_grn=$'\033[32m'; c_red=$'\033[31m'; c_dim=$'\033[2m'; c_rst=$'\033[0m'
pass() { PASS=$((PASS+1)); echo "  ${c_grn}PASS${c_rst} $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ${c_red}FAIL${c_rst} $1"; [ -n "${2:-}" ] && echo "       ${c_dim}${2}${c_rst}"; }
info() { echo "${c_dim}==> $*${c_rst}"; }

cleanup() {
  info "cleanup"
  if [ -n "$GW_PID" ]; then
    kill "$GW_PID" 2>/dev/null
    for _ in 1 2 3 4 5; do kill -0 "$GW_PID" 2>/dev/null || break; sleep 0.3; done
    kill -9 "$GW_PID" 2>/dev/null
  fi
  docker rm -f "$MINIO_NAME" >/dev/null 2>&1
  rm -rf "$WORK" "$STATE"
}
trap cleanup EXIT

wait_http() { # url name tries — up when the endpoint answers with any HTTP status
  local url=$1 name=$2 tries=${3:-40} i code
  for i in $(seq 1 "$tries"); do
    code=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
    [ "$code" != "000" ] && { info "$name up (HTTP $code, ${i}s)"; return 0; }
    sleep 1
  done
  echo "${c_red}$name did not come up at $url${c_rst}"; return 1
}

# aws-cli as an arbitrary identity; default endpoint = the gateway.
aws_id() { # ak sk [--endpoint X] args...
  local ak=$1 sk=$2; shift 2
  local ep="$GW_ENDPOINT"
  if [ "${1:-}" = "--endpoint" ]; then ep="$2"; shift 2; fi
  docker run --rm --network host \
    -e AWS_ACCESS_KEY_ID="$ak" -e AWS_SECRET_ACCESS_KEY="$sk" -e AWS_DEFAULT_REGION=us-east-1 \
    -e AWS_EC2_METADATA_DISABLED=true \
    -e AWS_REQUEST_CHECKSUM_CALCULATION=when_required \
    -e AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
    -v "$WORK":/work -w /work "$AWSCLI_IMAGE" --endpoint-url "$ep" "$@"
}
aws_open()    { aws_id AKIAOPEN  open-virtual-secret  "$@"; }
aws_admin()   { aws_id AKIAADMIN admin-virtual-secret "$@"; }
aws_backend() { aws_id "$BACKEND_AK" "$BACKEND_SK" --endpoint "$MINIO_ENDPOINT" "$@"; }

# expect ok|deny "label" <command...>
expect() {
  local mode=$1 label=$2; shift 2
  local out rc
  out=$("$@" 2>&1); rc=$?
  if [ "$mode" = ok ]; then
    [ $rc -eq 0 ] && pass "$label" || fail "$label" "expected success, rc=$rc: $out"
  else
    if [ $rc -ne 0 ] && echo "$out" | grep -qiE "accessdenied|forbidden|403"; then
      pass "$label"
    else
      fail "$label" "expected AccessDenied, rc=$rc: $out"
    fi
  fi
}

# expect_code "S3Code" "label" <command...> — command must fail with that S3 error code.
expect_code() {
  local code=$1 label=$2; shift 2
  local out rc
  out=$("$@" 2>&1); rc=$?
  if [ $rc -ne 0 ] && echo "$out" | grep -qi "$code"; then
    pass "$label"
  else
    fail "$label" "expected $code, rc=$rc: $out"
  fi
}

echo "============================================================"
echo " s0-gas end-to-end: aws-cli -> gateway -> MinIO (embedded OPA)"
echo "============================================================"

# --- 1. backend ------------------------------------------------------------
info "starting MinIO ($MINIO_IMAGE)"
docker rm -f "$MINIO_NAME" >/dev/null 2>&1
docker run -d --network host --name "$MINIO_NAME" \
  -e MINIO_ROOT_USER="$BACKEND_AK" -e MINIO_ROOT_PASSWORD="$BACKEND_SK" \
  "$MINIO_IMAGE" server /data --address :9000 >/dev/null || { echo "failed to start minio"; exit 1; }
wait_http "$MINIO_ENDPOINT/minio/health/live" minio || exit 1

# --- 2. seed the backend directly (control-plane / admin path) -------------
info "seeding backend buckets + objects (direct, backend creds)"
printf 'hello from the open bucket\n'     > "$WORK/greeting.txt"
printf 'quarterly report, non-sensitive\n'> "$WORK/report.txt"
printf 'PRIVATE material\n'               > "$WORK/private.txt"
printf 'TOP SECRET classified material\n' > "$WORK/classified.txt"
aws_backend s3 mb s3://open   >/dev/null 2>&1
aws_backend s3 mb s3://secret >/dev/null 2>&1
aws_backend s3 cp /work/greeting.txt   s3://open/pub/greeting.txt    >/dev/null
aws_backend s3 cp /work/report.txt     s3://open/pub/report.txt      >/dev/null
aws_backend s3 cp /work/private.txt    s3://open/private/secret.txt  >/dev/null
aws_backend s3 cp /work/classified.txt s3://secret/classified.txt    >/dev/null

# --- 3. build + run the gateway -------------------------------------------
if [ -z "${GW_BIN:-}" ]; then
  info "building gateway (debug)"
  ( cd "$ROOT" && cargo build --bin s0 ) || { echo "cargo build failed"; exit 1; }
  GW_BIN="$ROOT/target/debug/s0"
fi
info "seeding pushed policy bundle -> $STATE/bundle.json"
mkdir -p "$STATE"
cp "$E2E/bundle.e2e.json" "$STATE/bundle.json"
info "starting gateway -> $GW_ENDPOINT"
GATEWAY_CONFIG="$E2E/gateway.e2e.json" RUST_LOG="${RUST_LOG:-s0=info,warn}" \
  "$GW_BIN" > "$WORK/gateway.log" 2>&1 &
GW_PID=$!
wait_http "$GW_ENDPOINT/" gateway || { echo "gateway failed to start"; tail -n 20 "$WORK/gateway.log"; exit 1; }

# --- 4. scenarios through the gateway (virtual creds, real client) --------
echo ""; echo "-- object read / list / write ------------------------------"
expect ok   "AKIAOPEN GET open/pub/greeting.txt"              aws_open s3api get-object --bucket open --key pub/greeting.txt /work/dl1.txt
expect ok   "AKIAOPEN LIST open (narrowed to pub/)"           aws_open s3api list-objects-v2 --bucket open
expect deny "AKIAOPEN GET secret/classified.txt (no grant)"   aws_open s3api get-object --bucket secret --key classified.txt /work/dl2.txt
expect deny "AKIAOPEN GET open/private/secret.txt (off-prefix)" aws_open s3api get-object --bucket open --key private/secret.txt /work/dl3.txt
expect ok   "AKIAOPEN PUT open/pub/uploaded.txt"              aws_open s3api put-object --bucket open --key pub/uploaded.txt --body /work/report.txt
expect deny "AKIAOPEN PUT open/private/x.txt (off-prefix)"    aws_open s3api put-object --bucket open --key private/x.txt --body /work/report.txt

echo ""; echo "-- COPY: the Ceph RGW-OPA gap, via a real client -----------"
expect deny "AKIAOPEN COPY secret/classified -> open (SOURCE denied => blocked)" \
  aws_open  s3api copy-object --bucket open --key pub/stolen.txt --copy-source secret/classified.txt
expect_code "404" "stolen.txt was never created" \
  aws_admin s3api head-object --bucket open --key pub/stolen.txt
expect ok   "AKIAOPEN COPY open/pub/greeting -> open/pub/copy (both allowed)" \
  aws_open  s3api copy-object --bucket open --key pub/copy.txt --copy-source open/pub/greeting.txt
expect ok   "AKIAADMIN COPY secret/classified -> open (ABAC: admin allowed)" \
  aws_admin s3api copy-object --bucket open --key pub/admin-copy.txt --copy-source secret/classified.txt

echo ""; echo "-- listing narrowing / filtering ---------------------------"
open_ls="$(aws_open s3api list-objects-v2 --bucket open --query 'Contents[].Key' --output text 2>&1)"
if echo "$open_ls" | grep -q "private/secret.txt"; then
  fail "listing narrowed for AKIAOPEN" "private/secret.txt leaked: $open_ls"
else
  pass "listing narrowed for AKIAOPEN (private/secret.txt hidden)"
fi
admin_ls="$(aws_admin s3api list-objects-v2 --bucket open --query 'Contents[].Key' --output text 2>&1)"
if echo "$admin_ls" | grep -q "private/secret.txt"; then
  pass "admin sees unfiltered listing (private/secret.txt present)"
else
  fail "admin sees unfiltered listing" "expected private/secret.txt in: $admin_ls"
fi

echo ""; echo "-- multi-delete per-key filtering (blind spot) -------------"
# One allowed key (pub/report.txt) + one denied key (private/secret.txt) in the
# same DeleteObjects. The gateway strips the denied key; only pub/report.txt goes.
aws_open s3api delete-objects --bucket open \
  --delete 'Objects=[{Key=pub/report.txt},{Key=private/secret.txt}]' >/dev/null 2>&1
expect_code "404" "allowed key pub/report.txt was deleted" \
  aws_admin s3api head-object --bucket open --key pub/report.txt
expect ok "denied key private/secret.txt survived the multi-delete" \
  aws_admin s3api head-object --bucket open --key private/secret.txt

echo ""; echo "-- anonymous / unknown identity ----------------------------"
anon_code="$(curl -s -o /dev/null -w '%{http_code}' "$GW_ENDPOINT/open/pub/greeting.txt")"
[ "$anon_code" = "403" ] && pass "anonymous GET (no creds) rejected (403)" || fail "anonymous GET rejected" "got HTTP $anon_code"
expect_code InvalidAccessKeyId "unknown access key rejected" \
  aws_id AKIABOGUS bogus-secret s3api get-object --bucket open --key pub/greeting.txt /work/dl4.txt

echo ""; echo "-- live revocation (policy is live, not baked in creds) ----"
expect ok "AKIAOPEN GET open/pub/greeting.txt (still granted)" \
  aws_open s3api get-object --bucket open --key pub/greeting.txt /work/dl5.txt
info "revoking open-user's grant in the bundle; waiting for the 2s refresh"
cat > "$STATE/bundle.json" <<'JSON'
{
  "org_settings": { "freeze_writes": false, "reserved_tag_keys": [] },
  "tenants": {
    "acme": {
      "user_attributes": { "open-user": { "groups": [], "attributes": [] }, "admin-user": { "groups": [], "attributes": [] } },
      "bucket_attributes": {},
      "s3_grants": { "admin-user": [ { "bucket": "*", "actions": ["*"], "prefixes": [] } ] },
      "group_grants": {}
    }
  }
}
JSON
sleep 4
expect deny "AKIAOPEN GET open/pub/greeting.txt (grant revoked => denied)" \
  aws_open s3api get-object --bucket open --key pub/greeting.txt /work/dl6.txt

# --- 5. verdict ------------------------------------------------------------
echo ""
echo "============================================================"
echo " RESULT: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
[ "$FAIL" -eq 0 ]
