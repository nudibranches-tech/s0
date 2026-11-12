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
# AWSCLI_IMAGE, LFTP_IMAGE, PARAMIKO_IMAGE, PARAMIKO_VERSION, GW_BIN (prebuilt binary;
# else cargo build).
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
# The SFTP client matrix beyond OpenSSH: lftp (alpine package) and paramiko (pinned pip
# release), each installed into a stock image at run time.
LFTP_IMAGE="${LFTP_IMAGE:-alpine:3.20}"
PARAMIKO_IMAGE="${PARAMIKO_IMAGE:-python:3.12-slim}"
PARAMIKO_VERSION="${PARAMIKO_VERSION:-3.5.1}"

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
# `native`: tenant beta's bucket (the conditional_create: native scenarios). nar/: the
# SFTP narrowing scenario, whose reader holds nar/in/a/ and nar/in/b/ only.
aws_backend s3 mb s3://native >/dev/null 2>&1
for k in nar/top.txt nar/in/a/x.txt nar/in/b/y.txt nar/in/c/z.txt; do
  aws_backend s3 cp /work/report.txt "s3://open/$k" >/dev/null
done

# --- 3. build + run the gateway -------------------------------------------
if [ -z "${GW_BIN:-}" ]; then
  info "building gateway (debug)"
  ( cd "$ROOT" && cargo build --bin s0 ) || { echo "cargo build failed"; exit 1; }
  GW_BIN="$ROOT/target/debug/s0"
fi
info "seeding pushed policy bundle -> $STATE/bundle.json"
mkdir -p "$STATE"
cp "$E2E/bundle.e2e.json" "$STATE/bundle.json"

# SFTP: a host key for the gateway and the client keys. `drop` is a create-only
# partner, `ops` an operator on the same prefix, `stranger` a key no account lists,
# `narrow` a reader scoped to two sub-prefixes of its home, `native` a create-only partner
# of tenant beta (whose backend is declared conditional_create: native), and `revoke` a
# key the revocation scenario removes while its session is open.
command -v sftp >/dev/null && command -v ssh-keygen >/dev/null \
  || { echo "the SFTP scenarios need the OpenSSH client (sftp, ssh-keygen)"; exit 1; }
info "OpenSSH client: $(ssh -V 2>&1)"
ssh-keygen -q -t ed25519 -N '' -C s0-e2e-host -f "$STATE/ssh_host_ed25519_key"
for k in drop ops stranger narrow native revoke; do ssh-keygen -q -t ed25519 -N '' -C "$k" -f "$WORK/${k}_key"; done
# Pin the host key, as partners are told to.
echo "[$SFTP_HOST]:$SFTP_PORT $(cut -d' ' -f1,2 "$STATE/ssh_host_ed25519_key.pub")" > "$WORK/known_hosts"
fpr() { ssh-keygen -lf "$1" | awk '{print $2}'; }
python3 - "$STATE/bundle.json" "$(fpr "$WORK/drop_key.pub")" "$(fpr "$WORK/ops_key.pub")" \
  "$(fpr "$WORK/narrow_key.pub")" "$(fpr "$WORK/native_key.pub")" "$(fpr "$WORK/revoke_key.pub")" <<'PY'
import json, sys
path, drop_fp, ops_fp, narrow_fp, native_fp, revoke_fp = sys.argv[1:]
b = json.load(open(path))
def account(sub, fp, tenant="acme", bucket="open", prefix="drop/"):
    return {"tenant": tenant, "subject_key": "sa:" + sub,
            "home": {"bucket": bucket, "prefix": prefix},
            "authorized_keys": [{"key_type": "ssh-ed25519", "fingerprint": fp}]}
b["sftp"] = {"version": 1, "accounts": {
    "acme-drop": account("partner-drop", drop_fp),
    "acme-ops": account("sftp-ops", ops_fp),
    "acme-narrow": account("sftp-narrow", narrow_fp, prefix="nar/"),
    "acme-revoke": account("sftp-revoke", revoke_fp),
    "beta-drop": account("partner-native", native_fp, tenant="beta", bucket="native")}}
t = b["tenants"]["acme"]
for sub in ("partner-drop", "sftp-ops", "sftp-narrow", "sftp-revoke"):
    t["user_attributes"][sub] = {"groups": [], "attributes": []}
# The narrow reader holds two sub-prefixes of its home and nothing else, so a listing of
# its home is narrowed to them (allowed_prefixes) rather than denied or shown whole.
t["s3_grants"]["sftp-narrow"] = [
    {"bucket": "open", "actions": ["read_objects", "list_objects"],
     "prefixes": ["nar/in/a/", "nar/in/b/"]}]
t["s3_grants"]["sftp-revoke"] = [
    {"bucket": "open", "actions": ["read_objects", "list_objects", "create_objects"],
     "prefixes": ["drop/"]}]
# Tenant beta: a create-only drop on a backend declared conditional_create: native.
b["tenants"]["beta"] = {
    "user_attributes": {"partner-native": {"groups": [], "attributes": []}},
    "bucket_attributes": {},
    "s3_grants": {"partner-native": [
        {"bucket": "native", "actions": ["create_objects"], "prefixes": ["drop/"]}]},
    "group_grants": {}}
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

# push_bundle '<python>' — edit the pushed bundle in place (the code sees it as `b`),
# hand it to the sidecar too, and wait out the 2s poll.
push_bundle() {
  python3 - "$STATE/bundle.json" "$1" <<'PY'
import json, sys
path, code = sys.argv[1:]
b = json.load(open(path))
exec(code)
json.dump(b, open(path + ".tmp", "w"), indent=2)
PY
  mv "$STATE/bundle.json.tmp" "$STATE/bundle.json"
  sync_opa_data
  sleep 4
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

# audit_has '<python predicate over a record r>' — some spilled audit record matches.
audit_has() {
  python3 - "$STATE/audit-spill.ndjson" "$1" <<'PY'
import json, sys
recs = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
pred = eval("lambda r: " + sys.argv[2])
def ev(r): return r.get("session_event") or {}
sys.exit(0 if any(pred(r) for r in recs) else 1)
PY
}

# open_uploads <bucket> <key> — the keys of multipart uploads still open on the backend.
open_uploads() {
  aws_backend s3api list-multipart-uploads --bucket "$1" --prefix "$2" \
    --query 'Uploads[].Key' --output text 2>&1 | grep -v '^None$'
}

# The names a batch of `ls -1 <dir>` printed, without the echoed `sftp>` commands and
# without the directory prefix OpenSSH puts on them.
ls_names() { grep -v '^sftp>' | sed 's#/$##; s#.*/##' | sort; }

echo ""; echo "-- SFTP: listing narrowed to the granted prefixes ----------"
# acme-narrow's home is open/nar/; it holds nar/in/a/ and nar/in/b/ only. Its home and
# nar/in/ are wider than any grant, so they list as the granted entries alone: `in`, then
# `a` and `b` — never nar/top.txt or nar/in/c/.
root_ls=$(sftp_as narrow acme-narrow <<<"ls -1" 2>&1 | ls_names)
[ "$root_ls" = "in" ] && pass "narrowed home lists only the granted path (in)" \
  || fail "narrowed home lists only the granted path (in)" "got: $(echo $root_ls)"
in_ls=$(sftp_as narrow acme-narrow <<<"ls -1 in" 2>&1 | ls_names)
[ "$(echo $in_ls)" = "a b" ] && pass "narrowed in/ lists a and b, not c" \
  || fail "narrowed in/ lists a and b, not c" "got: $(echo $in_ls)"
a_ls=$(sftp_as narrow acme-narrow <<<"ls -1 in/a" 2>&1 | ls_names)
[ "$a_ls" = "x.txt" ] && pass "a granted prefix lists its objects (in/a/x.txt)" \
  || fail "a granted prefix lists its objects (in/a/x.txt)" "got: $(echo $a_ls)"
sftp_expect fail "an ungranted sibling (in/c) is refused, not listed" narrow acme-narrow <<<"ls -1 in/c"

echo ""; echo "-- freeze_writes (S3 and SFTP) -----------------------------"
info "freezing org writes in the bundle; waiting for the 2s refresh"
push_bundle 'b["org_settings"]["freeze_writes"] = True'
expect deny "frozen: AKIAOPEN PUT open/pub/frozen.txt refused" \
  aws_open s3api put-object --bucket open --key pub/frozen.txt --body /work/report.txt
expect ok   "frozen: AKIAOPEN GET open/pub/greeting.txt still served" \
  aws_open s3api get-object --bucket open --key pub/greeting.txt /work/dl-frozen.txt
sftp_expect fail "frozen: operator sftp put refused" ops acme-ops <<EOF
put $WORK/small.csv frozen.csv
EOF
expect_code "404" "frozen: nothing landed at drop/frozen.csv" \
  aws_backend s3api head-object --bucket open --key drop/frozen.csv
rm -f "$WORK/frozen.dl"
sftp_expect ok   "frozen: operator sftp get still works" ops acme-ops <<EOF
get small.csv $WORK/frozen.dl
EOF
cmp -s "$WORK/frozen.dl" "$WORK/small.csv" \
  && pass "frozen: the download is intact" || fail "frozen: the download is intact"
push_bundle 'b["org_settings"]["freeze_writes"] = False'
sftp_expect ok   "thawed: operator sftp put works again" ops acme-ops <<EOF
put $WORK/small.csv thawed.csv
EOF

echo ""; echo "-- SFTP: abort on disconnect -------------------------------"
# A 32 MiB put throttled to 2 MiB/s, killed (client and its ssh) after a multipart
# upload is open: nothing may be committed and no upload may be left on the backend.
head -c $((32 * 1024 * 1024)) /dev/urandom > "$WORK/abort.bin"
set -m   # the background job gets its own process group, so sftp and ssh die together
sftp_as ops acme-ops -l 16384 <<<"put $WORK/abort.bin abort.bin" >/dev/null 2>&1 &
abort_pgid=$!
set +m
inflight=""
for _ in $(seq 1 20); do
  sleep 1
  inflight=$(open_uploads open drop/abort.bin)
  [ -n "$inflight" ] && break
done
[ -n "$inflight" ] && pass "the interrupted upload was in flight (multipart upload open)" \
  || fail "the interrupted upload was in flight (multipart upload open)"
disown "$abort_pgid"   # no "Killed" job notice in the output
kill -9 -- "-$abort_pgid" 2>/dev/null
left=""
for _ in $(seq 1 10); do
  sleep 1
  left=$(open_uploads open drop/abort.bin)
  [ -z "$left" ] && break
done
[ -z "$left" ] && pass "killing the client aborts the multipart upload (none left)" \
  || fail "killing the client aborts the multipart upload (none left)" "still open: $left"
expect_code "404" "nothing was committed at drop/abort.bin" \
  aws_backend s3api head-object --bucket open --key drop/abort.bin
audit_has '"abort.bin" in json.dumps(r) and "\"commit\": \"aborted\"" in json.dumps(r)' \
  && pass "the transfer is audited as aborted" \
  || fail "the transfer is audited as aborted" "see $STATE/audit-spill.ndjson"

echo ""; echo "-- conditional create: the native conformance probe --------"
# ADR-012 D8: `native` is an operator assertion that the backend honours If-None-Match: *.
# Before relying on it: two conditional writes to one fresh key, the second must be 412,
# for PutObject and for CompleteMultipartUpload, directly against MinIO.
native_ok=1
probe_mpu() { # key — one conditional multipart upload of a single part
  local id et
  id=$(aws_backend s3api create-multipart-upload --bucket native --key "$1" \
    --query UploadId --output text) || return 1
  et=$(aws_backend s3api upload-part --bucket native --key "$1" --upload-id "$id" \
    --part-number 1 --body /work/small.csv --query ETag --output text) || return 1
  aws_backend s3api complete-multipart-upload --bucket native --key "$1" --upload-id "$id" \
    --multipart-upload "Parts=[{ETag=$et,PartNumber=1}]" --if-none-match '*' || {
    rc=$?; aws_backend s3api abort-multipart-upload --bucket native --key "$1" \
      --upload-id "$id" >/dev/null 2>&1; return $rc; }
}
probe() { # label <command...> — 1st must succeed, 2nd must be 412
  local label=$1 out rc; shift
  out=$("$@" 2>&1); rc=$?
  if [ $rc -ne 0 ]; then fail "$label: first conditional write" "rc=$rc: $out"; native_ok=0; return; fi
  out=$("$@" 2>&1); rc=$?
  if [ $rc -ne 0 ] && echo "$out" | grep -q "PreconditionFailed"; then
    pass "$label: second conditional write is 412 PreconditionFailed"
  else
    fail "$label: second conditional write is 412 PreconditionFailed" "rc=$rc: $out"; native_ok=0
  fi
}
probe "MinIO PutObject If-None-Match: *" \
  aws_backend s3api put-object --bucket native --key probe/put --body /work/small.csv --if-none-match '*'
probe "MinIO CompleteMultipartUpload If-None-Match: *" probe_mpu probe/mpu
info "MinIO ($MINIO_IMAGE) If-None-Match: * conformance: $([ $native_ok = 1 ] && echo PASS || echo FAIL)"

echo ""; echo "-- SFTP: create-only on a conditional_create: native backend --"
if [ "$native_ok" = 1 ]; then
  # MinIO's own trace shows what the commit carried; s0 is only one of its callers.
  docker exec "$MINIO_NAME" mc alias set e2e http://127.0.0.1:9000 "$BACKEND_AK" "$BACKEND_SK" >/dev/null 2>&1
  docker exec "$MINIO_NAME" mc admin trace -v e2e > "$WORK/minio-trace.log" 2>&1 &
  trace_pid=$!
  sleep 1
  sftp_expect ok   "native: create-only partner uploads a file" native beta-drop <<EOF
put $WORK/small.csv first.csv
EOF
  sftp_expect fail "native: an upload onto an existing key is refused" native beta-drop <<EOF
put $WORK/other.csv first.csv
EOF
  same_object native/drop/first.csv "$WORK/small.csv" \
    && pass "native: the original survived" || fail "native: the original survived"
  # The race: the key does not exist at OPEN, and another writer creates it while the
  # upload is streaming. On a native backend nothing re-checks before the commit, so only
  # the conditional commit (412) can refuse it — and the refusal must come at CLOSE.
  race() { # label size_mib kbit_per_s
    local label=$1 out rc
    head -c $(($2 * 1024 * 1024)) /dev/urandom > "$WORK/race.bin"
    sftp_as native beta-drop -l "$3" <<<"put $WORK/race.bin race-$2.bin" > "$WORK/race.out" 2>&1 &
    local pid=$!
    # A multipart upload shows on the backend once its first part is out: create the key
    # then. A single PUT shows nothing before its commit, so give it the time to OPEN.
    if [ "$2" -gt 8 ]; then
      for _ in $(seq 1 20); do [ -n "$(open_uploads native "drop/race-$2.bin")" ] && break; sleep 0.5; done
    else
      sleep 2
    fi
    aws_backend s3 cp /work/other.csv "s3://native/drop/race-$2.bin" >/dev/null 2>&1
    wait "$pid"; rc=$?; out=$(cat "$WORK/race.out")
    if [ $rc -ne 0 ] && echo "$out" | grep -qi "close"; then
      pass "native: $label losing a concurrent create is refused at CLOSE"
    else
      fail "native: $label losing a concurrent create is refused at CLOSE" "rc=$rc: $out"
    fi
    same_object "native/drop/race-$2.bin" "$WORK/other.csv" \
      && pass "native: $label the concurrent writer's object was not overwritten" \
      || fail "native: $label the concurrent writer's object was not overwritten"
    [ -z "$(open_uploads native "drop/race-$2.bin")" ] \
      && pass "native: $label no upload left open" || fail "native: $label no upload left open"
  }
  race "single PUT (6 MiB)" 6 6144
  race "multipart (16 MiB)" 16 16384
  sleep 1
  kill "$trace_pid" 2>/dev/null; wait "$trace_pid" 2>/dev/null
  python3 - "$WORK/minio-trace.log" <<'PY' \
    && pass "native: the commits carried If-None-Match: * (MinIO trace)" \
    || fail "native: the commits carried If-None-Match: * (MinIO trace)" "see $WORK/minio-trace.log"
import re, sys
log = open(sys.argv[1], errors="replace").read()
# One entry per request, each opening with `<host> [REQUEST s3.<Api>] ...`; every line
# carries the host prefix.
entries = re.split(r"\n(?=\S+ \[REQUEST )", log)
def conditional(e): return re.search(r"(?m)^\S+ If-None-Match: \*$", e)
put = [e for e in entries if "[REQUEST s3.PutObject]" in e and "/race-6.bin" in e]
done = [e for e in entries if "[REQUEST s3.CompleteMultipartUpload]" in e and "/race-16.bin" in e]
assert put and done, (len(put), len(done))
assert any(conditional(e) for e in put), "PutObject without If-None-Match"
assert any(conditional(e) for e in done), "CompleteMultipartUpload without If-None-Match"
PY
else
  fail "native: skipped — MinIO does not honour If-None-Match: *, so no backend may be declared native"
fi

echo ""; echo "-- SFTP client matrix: lftp and paramiko -------------------"
printf 'lftp,1\n' > "$WORK/lftp.csv"; printf 'paramiko,1\n' > "$WORK/paramiko.csv"
rm -f "$WORK/lftp.dl" "$WORK/paramiko.dl"
lftp_out=$(docker run --rm --network host -v "$WORK":/work "$LFTP_IMAGE" sh -c '
  apk add -q --no-progress lftp openssh-client-default >/dev/null || exit 3
  lftp -c "set sftp:auto-confirm no; set sftp:connect-program \"ssh -a -x -i /work/ops_key -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/work/known_hosts\"; open -u acme-ops, -p '"$SFTP_PORT"' sftp://'"$SFTP_HOST"'; put /work/lftp.csv -o lftp.csv; get lftp.csv -o /work/lftp.dl; cls -1"' 2>&1); rc=$?
[ $rc -eq 0 ] && pass "lftp: login (pinned host key) + put + get + ls" \
  || fail "lftp: login (pinned host key) + put + get + ls" "rc=$rc: $lftp_out"
echo "$lftp_out" | grep -qx "lftp.csv" && cmp -s "$WORK/lftp.dl" "$WORK/lftp.csv" \
  && same_object open/drop/lftp.csv "$WORK/lftp.csv" \
  && pass "lftp: the file round-trips and is listed" \
  || fail "lftp: the file round-trips and is listed" "$lftp_out"

cat > "$WORK/paramiko_e2e.py" <<'PY'
import sys, paramiko
host, port = sys.argv[1], int(sys.argv[2])
c = paramiko.SSHClient()
c.load_host_keys("/work/known_hosts")          # pinned; anything else is refused
c.set_missing_host_key_policy(paramiko.RejectPolicy())
c.connect(host, port=port, username="acme-ops",
          pkey=paramiko.Ed25519Key.from_private_key_file("/work/ops_key"),
          allow_agent=False, look_for_keys=False)
t = c.get_transport()
print(f"NEGOTIATED out={t.local_cipher}/{t.local_mac} in={t.remote_cipher}/{t.remote_mac}")
s = c.open_sftp()
s.put("/work/paramiko.csv", "paramiko.csv", confirm=False)   # confirm=True would stat
s.get("paramiko.csv", "/work/paramiko.dl")
assert "paramiko.csv" in s.listdir("."), s.listdir(".")
# ADR-012 D3's floor: an AEAD cipher, or else an encrypt-then-MAC MAC.
aead = {"chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com"}
floor = all(ci in aead or (mac or "").endswith("-etm@openssh.com")
            for ci, mac in ((t.local_cipher, t.local_mac), (t.remote_cipher, t.remote_mac)))
print("FLOOR_OK" if floor else "FLOOR_BELOW")
c.close()
PY
pm_out=$(docker run --rm --network host -v "$WORK":/work "$PARAMIKO_IMAGE" sh -c '
  pip install -q --disable-pip-version-check --root-user-action=ignore "paramiko=='"$PARAMIKO_VERSION"'" >/dev/null || exit 3
  python -I /work/paramiko_e2e.py '"$SFTP_HOST $SFTP_PORT" 2>&1); rc=$?
[ $rc -eq 0 ] && pass "paramiko $PARAMIKO_VERSION: login (pinned host key) + put + get + ls" \
  || fail "paramiko $PARAMIKO_VERSION: login (pinned host key) + put + get + ls" "rc=$rc: $pm_out"
cmp -s "$WORK/paramiko.dl" "$WORK/paramiko.csv" && same_object open/drop/paramiko.csv "$WORK/paramiko.csv" \
  && pass "paramiko: the file round-trips" || fail "paramiko: the file round-trips" "$pm_out"
echo "$pm_out" | grep -q FLOOR_OK \
  && pass "paramiko: negotiated algorithms meet the D3 floor ($(echo "$pm_out" | grep -o 'out=[^ ]*'))" \
  || fail "paramiko: negotiated algorithms meet the D3 floor (AEAD or EtM)" "$pm_out"

echo ""; echo "-- SFTP: revocation mid-session ----------------------------"
# An open, idle session whose key the next bundle removes is closed by the sweep on the
# bundle swap — before the client sends anything else — and audited as such.
rm -f "$WORK/rv.fifo" "$WORK/rv.out"; mkfifo "$WORK/rv.fifo"
sftp_as revoke acme-revoke < "$WORK/rv.fifo" > "$WORK/rv.out" 2>&1 &
rv_pid=$!
exec 7> "$WORK/rv.fifo"
echo "pwd" >&7
for _ in $(seq 1 20); do grep -q "Remote working directory" "$WORK/rv.out" && break; sleep 0.5; done
rv_ssh=""   # the ssh under sftp: it holds the connection, and exits when the gateway closes it
for p in $(pgrep -f -- "$WORK/revoke_key"); do
  [ "$(ps -o comm= -p "$p")" = ssh ] && rv_ssh=$p
done
if grep -q "Remote working directory" "$WORK/rv.out" && [ -n "$rv_ssh" ]; then
  pass "revocable session is open"
else
  fail "revocable session is open" "$(cat "$WORK/rv.out")"
fi
info "removing acme-revoke from the bundle; waiting for the 2s refresh"
push_bundle 'del b["sftp"]["accounts"]["acme-revoke"]'
gone=0
[ -n "$rv_ssh" ] && for _ in $(seq 1 10); do
  kill -0 "$rv_ssh" 2>/dev/null || { gone=1; break; }; sleep 1
done
[ "$gone" = 1 ] && pass "the idle session is closed by the gateway (no client request sent)" \
  || fail "the idle session is closed by the gateway (no client request sent)"
audit_has 'ev(r).get("event") == "disconnected" and ev(r).get("login") == "acme-revoke" and "credential_revoked" in r["result"]["reason"]' \
  && pass "audited: disconnected with credential_revoked" \
  || fail "audited: disconnected with credential_revoked" "see $STATE/audit-spill.ndjson"
exec 7>&-
kill "$rv_pid" 2>/dev/null; wait "$rv_pid" 2>/dev/null
sftp_expect fail "the removed key cannot log in again" revoke acme-revoke <<<"pwd"

echo ""; echo "-- SFTP: the ban (last: it bans this address) --------------"
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
