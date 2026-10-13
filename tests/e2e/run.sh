#!/usr/bin/env bash
# Real-stack end-to-end: real S3 clients (aws-cli) -> s0 gateway -> MinIO backend,
# with a pushed policy bundle. Proves the security properties against a real S3 stack
# rather than mocks — most importantly that a server-side copy whose SOURCE is denied is
# blocked, enforced through an off-the-shelf client.
#
#   PDP_MODE=embedded  (default) the in-process regorus engine
#   PDP_MODE=sidecar             a real OPA container on loopback — the shipping default
#
# Both modes run the identical scenario list, so an engine divergence shows up here as
# well as in the parity gate.
#
# Uses `docker --network host` throughout so it works even where the Docker NAT chain for
# published ports is unavailable, and identically in CI.
#
# Env overrides: PDP_MODE, GW_ENDPOINT, MINIO_ENDPOINT, MINIO_IMAGE, OPA_IMAGE,
# AWSCLI_IMAGE, GW_BIN (prebuilt binary; else cargo build).
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
E2E="$ROOT/tests/e2e"
STATE="/tmp/s0-e2e"

GW_ENDPOINT="${GW_ENDPOINT:-http://127.0.0.1:8014}"
MINIO_ENDPOINT="${MINIO_ENDPOINT:-http://127.0.0.1:9000}"
# pgsty/silo, a maintained MinIO fork: MinIO no longer publishes public images
# (docker.io/minio/minio is gone, quay.io/minio/minio answers 401), which kills the job
# before a single scenario runs. Pinned to a release so a new upstream can't break CI.
MINIO_IMAGE="${MINIO_IMAGE:-pgsty/silo:RELEASE.2026-09-16T00-00-00Z}"
# Pinned to the parity gate's oracle: the OPA major version selects the rego dialect
# (>=1.0 parses v1, 0.x parses v0), so a sidecar on the wrong side of that line answers
# different questions than the embedded engine. Held equal to `EXPECTED_OPA_VERSION` in
# tests/parity.rs by `the_opa_oracle_is_pinned_to_the_production_version_everywhere`.
OPA_IMAGE="${OPA_IMAGE:-openpolicyagent/opa:1.13.1-static}"
PDP_MODE="${PDP_MODE:-embedded}"
AWSCLI_IMAGE="${AWSCLI_IMAGE:-amazon/aws-cli:latest}"

MINIO_NAME="s0gas-e2e-minio"
OPA_NAME="s0gas-e2e-opa"
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
  docker rm -f "$OPA_NAME" >/dev/null 2>&1
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
echo " s0 end-to-end: aws-cli -> gateway -> MinIO (PDP: $PDP_MODE)"
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

# In sidecar mode OPA is the engine, so it needs the same document s0 polls. s0's bundle
# is `{policy, data}`; OPA wants them as two files. Re-run after any bundle rewrite, or
# the sidecar keeps deciding against the previous revision — which is exactly how a
# revocation test passes while revocation is broken.
sync_opa_data() {
  [ "$PDP_MODE" = sidecar ] || return 0
  mkdir -p "$STATE/opa"
  python3 - "$STATE/bundle.json" "$STATE/opa" "$ROOT/policy/gateway/authz.rego" <<'PYEOF'
import json, pathlib, shutil, sys
# Mirror s0's own `parse_bundle`: a `data` key means `{policy, data}`; anything else is
# the data document itself. Getting this wrong hands OPA an empty document, which denies
# every request while looking perfectly healthy.
bundle = json.loads(pathlib.Path(sys.argv[1]).read_text())
out = pathlib.Path(sys.argv[2])
if isinstance(bundle, dict) and "data" in bundle:
    data, policy = bundle["data"], bundle.get("policy")
else:
    data, policy = bundle, None
(out / "data.json").write_text(json.dumps(data))
if policy:
    (out / "authz.rego").write_text(policy)
else:
    shutil.copyfile(sys.argv[3], out / "authz.rego")
PYEOF
}

GW_CONFIG="$E2E/gateway.e2e.json"
if [ "$PDP_MODE" = sidecar ]; then
  sync_opa_data
  info "starting sidecar OPA ($OPA_IMAGE)"
  docker rm -f "$OPA_NAME" >/dev/null 2>&1
  # --watch reloads on file change, so the revocation scenario reaches OPA too.
  docker run -d --network host --name "$OPA_NAME" -v "$STATE/opa:/policy:ro" \
    "$OPA_IMAGE" run --server --watch --addr=0.0.0.0:8181 --log-level=error \
    /policy/authz.rego /policy/data.json >/dev/null || { echo "failed to start opa"; exit 1; }
  wait_http "http://127.0.0.1:8181/health" opa || exit 1
  GW_CONFIG="$STATE/gateway.sidecar.json"
  python3 - "$E2E/gateway.e2e.json" "$GW_CONFIG" <<'PYEOF'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg["pdp"] = {"mode": "sidecar", "base_url": "http://127.0.0.1:8181", "timeout_ms": 2000}
json.dump(cfg, open(sys.argv[2], "w"), indent=2)
PYEOF
fi

info "starting gateway -> $GW_ENDPOINT"
GATEWAY_CONFIG="$GW_CONFIG" RUST_LOG="${RUST_LOG:-s0=info,warn}" \
  "$GW_BIN" > "$WORK/gateway.log" 2>&1 &
GW_PID=$!
wait_http "$GW_ENDPOINT/" gateway || { echo "gateway failed to start"; tail -n 20 "$WORK/gateway.log"; exit 1; }

# --- 4. scenarios through the gateway (virtual creds, real client) --------
echo ""; echo "-- object read / list / write ------------------------------"
expect ok   "AKIAOPEN GET open/pub/greeting.txt"              aws_open s3api get-object --bucket open --key pub/greeting.txt /work/dl1.txt
# An unbounded list — no prefix at all — is denied for a prefix-scoped principal, the
# same way `s3:ListBucket` with an `s3:prefix` condition denies it in AWS. The gateway
# deliberately does NOT narrow a listing the caller never scoped: a filtered listing
# comes back with no signal that it was filtered, and reads as the whole bucket.
expect deny "AKIAOPEN LIST open (unbounded, no prefix)"       aws_open s3api list-objects-v2 --bucket open
expect ok   "AKIAOPEN LIST open --prefix pub/ (inside grant)" aws_open s3api list-objects-v2 --bucket open --prefix pub/
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

echo ""; echo "-- CORS: browser preflights and responses ------------------"
# The rule is the bucket owner's, written on the backend with the backend credential — the
# control plane's job. A client cannot write it through the gateway (asserted below), and
# the gateway only ever reads it back. Written before the first request that carries an
# Origin, so no negative answer is cached ahead of it.
cat > "$WORK/cors-open.json" <<'JSON'
{"CORSRules":[{"AllowedOrigins":["*"],"AllowedMethods":["PUT"],"AllowedHeaders":["content-type"],"ExposeHeaders":["ETag"],"MaxAgeSeconds":3000}]}
JSON
cat > "$WORK/cors-secret.json" <<'JSON'
{"CORSRules":[{"AllowedOrigins":["https://app.example.com"],"AllowedMethods":["GET","PUT"],"AllowedHeaders":["*"],"ExposeHeaders":["ETag"],"MaxAgeSeconds":60}]}
JSON
aws_backend s3 mb s3://nocors >/dev/null 2>&1
aws_backend s3api put-bucket-cors --bucket open   --cors-configuration file:///work/cors-open.json   >/dev/null 2>&1
aws_backend s3api put-bucket-cors --bucket secret --cors-configuration file:///work/cors-secret.json >/dev/null 2>&1

BROWSER_ORIGIN="https://app.proarchives360.fr"
# `aws s3 presign` signs a GET and is the only presigner on hand. A preflight is judged on
# its own Origin / Access-Control-Request-* headers and on the credential in the URL, not on
# the method the URL was signed for, so it stands in for the browser's URL.
presigned_open="$(aws_open s3 presign s3://open/pub/cors-probe.txt --expires-in 600)"
presigned_nocors="$(aws_open s3 presign s3://nocors/x.txt --expires-in 600)"
presigned_secret="$(aws_open s3 presign s3://secret/x.txt --expires-in 600)"
# The same URL with the credential taken out, and with an access key the gateway does not know.
unsigned_open="${presigned_open%%\?*}"
bogus_open="${unsigned_open}?X-Amz-Credential=AKIABOGUS%2F20260101%2Fus-east-1%2Fs3%2Faws4_request"

preflight() { # url origin method [request-headers] -> response head on stdout
  local url=$1 origin=$2 method=$3 reqh=${4:-}
  local args=(-s -o /dev/null -D - -X OPTIONS "$url" -H "Origin: $origin" -H "Access-Control-Request-Method: $method")
  [ -n "$reqh" ] && args+=(-H "Access-Control-Request-Headers: $reqh")
  curl "${args[@]}" | tr -d '\r'
}
# expect_head "label" "<head>" <status> [header-regex ...]
expect_head() {
  local label=$1 head=$2 want=$3; shift 3
  local got re
  got="$(printf '%s\n' "$head" | head -n1 | awk '{print $2}')"
  [ "$got" = "$want" ] || { fail "$label" "wanted HTTP $want, got ${got:-none}: $head"; return; }
  for re in "$@"; do
    printf '%s\n' "$head" | grep -qiE "$re" || { fail "$label" "no header matching /$re/ in: $head"; return; }
  done
  pass "$label"
}
expect_no_cors_headers() { # "label" "<head>"
  if printf '%s\n' "$2" | grep -qi '^access-control-'; then
    fail "$1" "unexpected CORS header in: $2"
  else
    pass "$1"
  fi
}

head="$(preflight "$presigned_open" "$BROWSER_ORIGIN" PUT content-type)"
expect_head "preflight PUT from an allowed origin: 200 and the bucket's rule" "$head" 200 \
  '^access-control-allow-origin: \*$' '^access-control-allow-methods: PUT$' \
  '^access-control-allow-headers: content-type$' '^access-control-expose-headers: ETag$' \
  '^access-control-max-age: 3000$' '^vary:.*Origin'
head="$(preflight "$presigned_secret" "https://app.example.com" PUT "content-type, x-amz-meta-k")"
expect_head "preflight against a named-origin rule echoes the origin" "$head" 200 \
  '^access-control-allow-origin: https://app.example.com$' '^vary:.*Origin'
expect_head "preflight from an origin the rule does not name: 403" \
  "$(preflight "$presigned_secret" "https://evil.example" PUT)" 403
expect_head "preflight for a method the rule does not allow: 403" \
  "$(preflight "$presigned_secret" "https://app.example.com" DELETE)" 403
expect_head "preflight asking for a header the rule does not allow: 403" \
  "$(preflight "$presigned_open" "$BROWSER_ORIGIN" PUT "content-type, authorization")" 403
expect_head "preflight on a bucket with no CORS configuration: 403" \
  "$(preflight "$presigned_nocors" "$BROWSER_ORIGIN" PUT)" 403
expect_head "preflight with no credential: 403" \
  "$(preflight "$unsigned_open" "$BROWSER_ORIGIN" PUT)" 403
expect_head "preflight with an unknown access key: 403" \
  "$(preflight "$bogus_open" "$BROWSER_ORIGIN" PUT)" 403
refused_a="$(preflight "$unsigned_open" "$BROWSER_ORIGIN" PUT | grep -viE '^(date|HTTP)')"
refused_b="$(preflight "$presigned_nocors" "$BROWSER_ORIGIN" PUT | grep -viE '^(date|HTTP)')"
[ "$refused_a" = "$refused_b" ] && pass "refusals do not say why (no credential and no rule look the same)" \
  || fail "refusals do not say why" "$refused_a // $refused_b"
expect_head "OPTIONS that is not a preflight: 403, never s3s's 501" \
  "$(curl -s -o /dev/null -D - -X OPTIONS "$GW_ENDPOINT/open/pub/x" | tr -d '\r')" 403

# Actual requests, signed in the Authorization header as an SDK would, from a browser origin.
printf 'cors upload\n' > "$WORK/cors-body.txt"
curl_signed_put() { # url [extra curl args...]
  local url=$1; shift
  curl -s -o /dev/null -D - -X PUT "$url" --aws-sigv4 "aws:amz:us-east-1:s3" \
    --user "AKIAOPEN:open-virtual-secret" -H "x-amz-content-sha256: UNSIGNED-PAYLOAD" \
    -H "Content-Type: text/plain" --data-binary @"$WORK/cors-body.txt" "$@" | tr -d '\r'
}
expect_head "PUT from a browser origin: ACAO and ETag exposed" \
  "$(curl_signed_put "$GW_ENDPOINT/open/pub/cors-put.txt" -H "Origin: $BROWSER_ORIGIN")" 200 \
  '^access-control-allow-origin: \*$' '^access-control-expose-headers: ETag$' '^etag: '
upload_id="$(aws_open s3api create-multipart-upload --bucket open --key pub/cors-mpu.bin --query UploadId --output text 2>/dev/null)"
expect_head "UploadPart from a browser origin: ACAO and ETag exposed" \
  "$(curl_signed_put "$GW_ENDPOINT/open/pub/cors-mpu.bin?partNumber=1&uploadId=${upload_id}" -H "Origin: $BROWSER_ORIGIN")" 200 \
  '^access-control-allow-origin: \*$' '^access-control-expose-headers: ETag$' '^etag: '
aws_open s3api abort-multipart-upload --bucket open --key pub/cors-mpu.bin --upload-id "$upload_id" >/dev/null 2>&1
head="$(curl_signed_put "$GW_ENDPOINT/open/private/cors-denied.txt" -H "Origin: $BROWSER_ORIGIN")"
expect_head "an S3 error answered to a browser origin carries ACAO too" "$head" 403 \
  '^access-control-allow-origin: \*$'
head="$(curl_signed_put "$GW_ENDPOINT/open/pub/cors-plain.txt")"
expect_head "PUT with no Origin is served as before" "$head" 200 '^etag: '
expect_no_cors_headers "PUT with no Origin carries no CORS headers" "$head"

expect deny "AKIAADMIN GetBucketCors through the gateway stays refused" \
  aws_admin s3api get-bucket-cors --bucket open
expect deny "AKIAADMIN PutBucketCors through the gateway stays refused" \
  aws_admin s3api put-bucket-cors --bucket open --cors-configuration file:///work/cors-open.json

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
# The sidecar decides against its own copy, so the revocation has to reach it too.
sync_opa_data
sleep 4
expect deny "AKIAOPEN GET open/pub/greeting.txt (grant revoked => denied)" \
  aws_open s3api get-object --bucket open --key pub/greeting.txt /work/dl6.txt

# --- 5. verdict ------------------------------------------------------------
echo ""
echo "============================================================"
echo " RESULT: ${PASS} passed, ${FAIL} failed"
echo "============================================================"
[ "$FAIL" -eq 0 ]
