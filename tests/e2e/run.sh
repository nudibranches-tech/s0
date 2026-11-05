#!/usr/bin/env bash
# Real-stack end-to-end: real S3 clients (aws-cli) and a stock OpenSSH sftp client ->
# s0 gateway (S3 and SFTP fronts) -> MinIO backend, with a pushed policy bundle. Proves the security properties against a real S3 stack
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
# Fixed by gateway.e2e.json (frontends.sftp.listen).
SFTP_HOST=127.0.0.1; SFTP_PORT=2222
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

# sftp_as <key> <login> [ssh options...] — run the sftp batch read from stdin as <login>.
# A batch stops at its first failing command and exits non-zero.
sftp_as() {
  local key=$1 login=$2; shift 2
  sftp -q -b - -P "$SFTP_PORT" -i "$WORK/${key}_key" \
    -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 \
    -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$WORK/known_hosts" \
    "$@" "$login@$SFTP_HOST"
}

# sftp_expect ok|fail "label" <key> <login> [ssh options...] <<< "batch"
sftp_expect() {
  local mode=$1 label=$2; shift 2
  local out rc
  out=$(sftp_as "$@" 2>&1); rc=$?
  if [ "$mode" = ok ]; then
    [ $rc -eq 0 ] && pass "$label" || fail "$label" "expected success, rc=$rc: $out"
  else
    [ $rc -ne 0 ] && pass "$label" || fail "$label" "expected failure, rc=0: $out"
  fi
}

# same_object <bucket/key> <local file> — the backend holds exactly these bytes.
same_object() {
  rm -f "$WORK/.check"
  aws_backend s3 cp "s3://$1" /work/.check >/dev/null 2>&1 && cmp -s "$WORK/.check" "$2"
}

wait_tcp() { # host port name tries
  local i
  for i in $(seq 1 "${4:-40}"); do
    (exec 3<>"/dev/tcp/$1/$2") 2>/dev/null && { info "$3 up (${i}s)"; return 0; }
    sleep 1
  done
  echo "${c_red}$3 did not come up at $1:$2${c_rst}"; return 1
}

echo "============================================================"
echo " s0 end-to-end: aws-cli + OpenSSH sftp -> gateway -> MinIO (PDP: $PDP_MODE)"
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

# SFTP: a host key for the gateway and three client keys. `drop` is a create-only
# partner, `ops` an operator on the same prefix, `stranger` a key no account lists.
command -v sftp >/dev/null && command -v ssh-keygen >/dev/null \
  || { echo "the SFTP scenarios need the OpenSSH client (sftp, ssh-keygen)"; exit 1; }
info "OpenSSH client: $(ssh -V 2>&1)"
ssh-keygen -q -t ed25519 -N '' -C s0-e2e-host -f "$STATE/ssh_host_ed25519_key"
for k in drop ops stranger; do ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$WORK/${k}_key"; done
# Pin the host key, as partners are told to.
echo "[$SFTP_HOST]:$SFTP_PORT $(cut -d' ' -f1,2 "$STATE/ssh_host_ed25519_key.pub")" > "$WORK/known_hosts"
fpr() { ssh-keygen -lf "$1" | awk '{print $2}'; }
python3 - "$STATE/bundle.json" "$(fpr "$WORK/drop_key.pub")" "$(fpr "$WORK/ops_key.pub")" <<'PY'
import json, sys
path, drop_fp, ops_fp = sys.argv[1:]
b = json.load(open(path))
def account(sub, fp):
    return {"tenant": "acme", "subject_key": "sa:" + sub,
            "home": {"bucket": "open", "prefix": "drop/"},
            "authorized_keys": [{"key_type": "ssh-ed25519", "fingerprint": fp}]}
b["sftp"] = {"version": 1, "accounts": {
    "acme-drop": account("partner-drop", drop_fp),
    "acme-ops": account("sftp-ops", ops_fp)}}
t = b["tenants"]["acme"]
for sub in ("partner-drop", "sftp-ops"):
    t["user_attributes"][sub] = {"groups": [], "attributes": []}
# The drop partner can only create; the operator can read, list, create and delete but
# not overwrite, so its renames are create-only too.
t["s3_grants"]["partner-drop"] = [
    {"bucket": "open", "actions": ["create_objects"], "prefixes": ["drop/"]}]
t["s3_grants"]["sftp-ops"] = [
    {"bucket": "open", "actions": ["read_objects", "list_objects", "create_objects", "delete_objects"],
     "prefixes": ["drop/"]}]
json.dump(b, open(path, "w"), indent=2)
PY

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
wait_tcp "$SFTP_HOST" "$SFTP_PORT" "sftp front" || { tail -n 20 "$WORK/gateway.log"; exit 1; }

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

echo ""; echo "-- SFTP: stock OpenSSH client -> SFTP front -> MinIO --------"
printf 'id,amount\n1,10\n' > "$WORK/small.csv"
head -c $((20 * 1024 * 1024)) /dev/urandom > "$WORK/big.bin"   # > part_size: multipart
cp "$WORK/small.csv" "$WORK/other.csv"; printf '2,20\n' >> "$WORK/other.csv"
sftp_expect ok   "drop partner uploads a file" drop acme-drop <<EOF
put $WORK/small.csv small.csv
EOF
same_object open/drop/small.csv "$WORK/small.csv" \
  && pass "the upload landed byte for byte under the home prefix" \
  || fail "the upload landed byte for byte under the home prefix"
sftp_expect ok   "drop partner uploads 20 MiB (multipart, pipelined writes)" drop acme-drop <<EOF
put $WORK/big.bin big.bin
EOF
same_object open/drop/big.bin "$WORK/big.bin" \
  && pass "the multipart upload is intact" || fail "the multipart upload is intact"
sftp_expect fail "drop partner cannot overwrite (create-only)" drop acme-drop <<EOF
put $WORK/other.csv small.csv
EOF
same_object open/drop/small.csv "$WORK/small.csv" \
  && pass "the original survived the refused overwrite" \
  || fail "the original survived the refused overwrite"
sftp_expect fail "drop partner cannot read" drop acme-drop <<EOF
get small.csv $WORK/should-not-exist.csv
EOF
rm -f "$WORK/big.dl"
sftp_expect ok   "operator lists and downloads" ops acme-ops <<EOF
ls
get big.bin $WORK/big.dl
EOF
cmp -s "$WORK/big.dl" "$WORK/big.bin" \
  && pass "the download matches the upload" || fail "the download matches the upload"
# OpenSSH's `rename` sends posix-rename@openssh.com, which overwrites, so it needs
# write_objects; `rename -l` sends the legacy SSH_FXP_RENAME, whose target is
# create-only. The backend is check_then_write (the default), so a create-only rename is
# guarded by the in-flight claim and a re-check before its commit.
sftp_expect fail "operator's overwriting rename is refused (no write_objects)" ops acme-ops <<EOF
put $WORK/other.csv other.csv
rename other.csv renamed.csv
EOF
sftp_expect ok   "operator's create-only rename to a fresh name" ops acme-ops <<EOF
rename -l other.csv renamed.csv
EOF
same_object open/drop/renamed.csv "$WORK/other.csv" \
  && pass "the renamed object holds the source bytes" \
  || fail "the renamed object holds the source bytes"
out=$(sftp_as ops acme-ops <<<"rename -l renamed.csv small.csv" 2>&1); rc=$?
if [ $rc -ne 0 ] && echo "$out" | grep -q "Failure"; then
  pass "a create-only rename onto an existing file is refused (file exists)"
else
  fail "a create-only rename onto an existing file is refused (file exists)" "rc=$rc: $out"
fi
same_object open/drop/small.csv "$WORK/small.csv" \
  && pass "the rename target was not overwritten" \
  || fail "the rename target was not overwritten"
same_object open/drop/renamed.csv "$WORK/other.csv" \
  && pass "the rename source is still there" \
  || fail "the rename source is still there"

# A client that connects and says nothing is cut off at handshake_timeout_secs (5 in
# gateway.e2e.json), not held until the transport's much longer inactivity timeout.
start=$SECONDS
timeout 60 bash -c "exec 3<>/dev/tcp/$SFTP_HOST/$SFTP_PORT; cat <&3 >/dev/null" 2>/dev/null
took=$((SECONDS - start))
[ "$took" -le 10 ] && pass "a silent client is disconnected at the handshake timeout (${took}s)" \
  || fail "a silent client is disconnected at the handshake timeout" "held for ${took}s"

# The ban. Last among the SFTP scenarios: it bans this address on the SFTP front for
# 15 minutes. An agent-style client offers a key no account lists before the right one;
# that connection logs in, so its rejected key must not count toward the ban (10
# failures in 5 minutes).
ok_logins=0
for i in $(seq 1 12); do
  sftp_as stranger acme-drop -i "$WORK/drop_key" <<<"pwd" >/dev/null 2>&1 && ok_logins=$((ok_logins + 1))
done
[ "$ok_logins" -eq 12 ] && pass "12 logins that try a wrong key first are not banned" \
  || fail "12 logins that try a wrong key first are not banned" "only $ok_logins/12 logged in"
for i in $(seq 1 10); do sftp_as stranger acme-drop <<<"pwd" >/dev/null 2>&1; done
sleep 1
sftp_expect fail "10 failed connections ban the address; the right key is then refused" drop acme-drop <<EOF
pwd
EOF

# Session records: a refused login is a denial on the audit stream, not an allowed event.
python3 - "$STATE/audit-spill.ndjson" <<'PY' && pass "auth_failed records are denials (outcome=denied)" || fail "auth_failed records are denials (outcome=denied)" "see $STATE/audit-spill.ndjson"
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
failed = [r for r in recs if (r.get("session_event") or {}).get("event") == "auth_failed"]
assert failed, "no auth_failed record"
bad = [r for r in failed if r["gateway"]["outcome"] != "denied" or r["result"]["allow"]]
assert not bad, bad[:1]
PY

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
