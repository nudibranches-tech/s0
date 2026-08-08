#!/usr/bin/env bash
# Rebuild the evidence behind `matrix.md`: real clients -> real s0 -> real backend, with
# every request read off the wire.
#
# NOT part of `cargo test`. It needs four third-party binaries and a container runtime,
# which is exactly why the matrix is a checked-in document rather than an assertion — a
# compat claim that only holds on a machine with `mc` installed is not a claim CI can
# make, and pretending otherwise would produce a green suite that proves nothing.
#
# Usage:  tests/compat/run.sh [scenario…]     (default: all)
# Env:    KEEP=1  leave the stack up afterwards
#
# What it proves, and why each piece is there:
#
#  * The gateway is the REAL serving path (`target/release/s0` + a config), not a test
#    fixture, because the matrix's job is to catch things the in-process tests cannot —
#    §5 of matrix.md is a forward-path header-encoding bug that only appears once bytes
#    reach a backend.
#  * A transparent recording proxy sits in front of the gateway and forwards the request
#    line, ALL headers (Host verbatim) and the body unchanged, so SigV4 still verifies.
#    That is what makes "which ops does this client actually issue" an observation rather
#    than a reading of the client's documentation.
#  * Three principals, because the answer depends on the grant: a wildcard grant hides
#    both blockers in matrix.md.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STATE="${STATE:-/tmp/s0-compat}"
GW_BIN="${GW_BIN:-$ROOT/target/release/s0}"
BACKEND_IMAGE="${BACKEND_IMAGE:-minio/minio:latest}"
BACKEND_NAME=s0compat-backend
GW_PORT=8114
PROXY_PORT=8113
BACKEND_PORT=9000

need() { command -v "$1" >/dev/null || { echo "MISSING: $1 — install it or skip its rows"; return 1; }; }
echo "== client versions (record these in matrix.md) =="
need aws     && aws --version
need mc      && mc --version | head -1
need rclone  && rclone --version | head -1
python3 -c "import boto3,botocore;print('boto3',boto3.__version__,'botocore',botocore.__version__)" 2>/dev/null
need docker  || exit 1

[ -x "$GW_BIN" ] || { echo "building $GW_BIN"; (cd "$ROOT" && cargo build --release) || exit 1; }

cleanup() {
  [ "${KEEP:-0}" = "1" ] && { echo "KEEP=1 — stack left up at http://127.0.0.1:$PROXY_PORT"; return; }
  [ -f "$STATE/gw.pid" ]    && kill "$(cat "$STATE/gw.pid")"    2>/dev/null
  [ -f "$STATE/proxy.pid" ] && kill "$(cat "$STATE/proxy.pid")" 2>/dev/null
  docker rm -f "$BACKEND_NAME" >/dev/null 2>&1
}
trap cleanup EXIT

rm -rf "$STATE"; mkdir -p "$STATE"

# ── backend ────────────────────────────────────────────────────────────────────
docker rm -f "$BACKEND_NAME" >/dev/null 2>&1
docker run -d --name "$BACKEND_NAME" --network host \
  -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
  "$BACKEND_IMAGE" server /data --address ":$BACKEND_PORT" >/dev/null || exit 1
for _ in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$BACKEND_PORT/")" != "000" ] && break
  sleep 1
done

# ── bundle: three principals, because the grant is half the answer ─────────────
cat > "$STATE/bundle.json" <<'JSON'
{
  "org_settings": { "freeze_writes": false, "reserved_tag_keys": [] },
  "tenants": { "acme": {
    "user_attributes": {
      "wildcard-user": { "groups": [], "attributes": [] },
      "scoped-user":   { "groups": [], "attributes": [] },
      "objonly-user":  { "groups": [], "attributes": [] }
    },
    "bucket_attributes": {},
    "s3_grants": {
      "wildcard-user": [ { "bucket": "*", "actions": ["*"], "prefixes": [] } ],
      "scoped-user": [
        { "bucket": "scoped-b", "actions": ["read_objects","list_objects","write_objects","delete_objects"], "prefixes": ["team-a/"] },
        { "bucket": "scoped-b", "actions": ["read"], "prefixes": [] }
      ],
      "objonly-user": [
        { "bucket": "scoped-b", "actions": ["read_objects","list_objects","write_objects","delete_objects"], "prefixes": [] }
      ]
    },
    "group_grants": {}
  } }
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
  "backends": [ { "id": "backend", "kind": "remote_s3", "endpoint_url": "http://127.0.0.1:$BACKEND_PORT", "region": "us-east-1", "force_path_style": true } ],
  "tenants": [ { "tenant": "acme", "organization_id": "org-acme", "backend_id": "backend", "owner_access_key": "minioadmin", "owner_secret_key": "minioadmin" } ],
  "static_credentials": [
    { "access_key_id": "AKIAWILD",   "secret_access_key": "wild-secret",   "principal_sub": "wildcard-user", "tenant": "acme", "organization_id": "org-acme", "groups": [] },
    { "access_key_id": "AKIASCOPED", "secret_access_key": "scoped-secret", "principal_sub": "scoped-user",   "tenant": "acme", "organization_id": "org-acme", "groups": [] },
    { "access_key_id": "AKIAOBJ",    "secret_access_key": "obj-secret",    "principal_sub": "objonly-user",  "tenant": "acme", "organization_id": "org-acme", "groups": [] }
  ],
  "bundle_path": "$STATE/bundle.json",
  "bundle_poll_secs": 2
}
JSON

# ── the recording proxy ────────────────────────────────────────────────────────
# Host is forwarded verbatim, so the signature the client computed still verifies at the
# gateway. Anything that rewrote it would make every row a 403 for the wrong reason.
cat > "$STATE/recproxy.py" <<'PY'
import http.server, socket, json, threading, time
UP=("127.0.0.1",8114); WIRE="/tmp/s0-compat/wire.ndjson"; lock=threading.Lock()
class H(http.server.BaseHTTPRequestHandler):
    protocol_version="HTTP/1.1"
    def log_message(self,*a): pass
    def _do(self):
        body=b""; cl=self.headers.get("Content-Length")
        if cl: body=self.rfile.read(int(cl))
        elif self.headers.get("Transfer-Encoding","").lower()=="chunked":
            while True:
                line=self.rfile.readline(); body+=line
                n=int(line.split(b";")[0].strip() or b"0",16)
                body+=self.rfile.read(n+2)
                if n==0: break
        raw=self.requestline.encode()+b"\r\n"
        for k,v in self.headers.items(): raw+=f"{k}: {v}\r\n".encode()
        raw+=b"\r\n"+body
        s=socket.create_connection(UP,10); s.sendall(raw); s.settimeout(30); resp=b""
        try:
            while True:
                d=s.recv(65536)
                if not d: break
                resp+=d
                if b"\r\n\r\n" in resp:
                    head,_,rest=resp.partition(b"\r\n\r\n")
                    hdrs={}
                    for h in head.decode("latin1").split("\r\n")[1:]:
                        if ":" in h:
                            k,_,v=h.partition(":"); hdrs[k.strip().lower()]=v.strip()
                    if "content-length" in hdrs:
                        if len(rest)>=int(hdrs["content-length"]): break
                    elif hdrs.get("transfer-encoding","").lower()=="chunked":
                        if rest.endswith(b"0\r\n\r\n"): break
                    elif self.command=="HEAD": break
        except socket.timeout: pass
        s.close()
        head,_,rb=resp.partition(b"\r\n\r\n")
        with lock, open(WIRE,"a") as f:
            f.write(json.dumps({"t":time.time(),"method":self.command,"target":self.path,
                "req_headers":dict(self.headers.items()),
                "status":head.split(b"\r\n")[0].decode("latin1"),
                "resp":rb[:400].decode("latin1","replace")})+"\n")
        self.wfile.write(resp); self.wfile.flush()
    do_GET=do_PUT=do_POST=do_DELETE=do_HEAD=do_OPTIONS=_do
class S(http.server.ThreadingHTTPServer):
    daemon_threads=True; allow_reuse_address=True
S(("127.0.0.1",8113),H).serve_forever()
PY
sed -i "s|/tmp/s0-compat/wire.ndjson|$STATE/wire.ndjson|" "$STATE/recproxy.py"
python3 "$STATE/recproxy.py" >"$STATE/proxy.log" 2>&1 & echo $! > "$STATE/proxy.pid"

S0_CONFIG="$STATE/gateway.json" "$GW_BIN" >"$STATE/gw.log" 2>&1 & echo $! > "$STATE/gw.pid"
for _ in $(seq 1 40); do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PROXY_PORT/")" != "000" ] && break
  sleep 1
done

# ── drive ──────────────────────────────────────────────────────────────────────
EP="http://127.0.0.1:$PROXY_PORT"
# rclone is driven at the gateway DIRECTLY, not through the recorder. The recorder is a
# ~40-line HTTP/1.1 proxy and rclone is the one client here that leans hard on connection
# reuse for its HEAD probes; through the recorder those intermittently stall, which would
# put a proxy artefact in the matrix and call it a gateway fault. rclone's op inventory is
# already established from the aws-cli/boto3/mc rows plus its own error messages, which
# name the operation (`operation error S3: CreateBucket …`), so nothing is lost.
EP_RCLONE="http://127.0.0.1:$GW_PORT"
W="$STATE/wire.ndjson"; : > "$W"
D="$STATE/work"; mkdir -p "$D/up" "$D/down"
echo hello > "$D/up/a.txt"; echo second > "$D/up/b.txt"
python3 -c "open('$D/big.bin','wb').write(b'x'*12*1024*1024)"

export AWS_DEFAULT_REGION=us-east-1 AWS_EC2_METADATA_DISABLED=true
export AWS_REQUEST_CHECKSUM_CALCULATION=when_required AWS_RESPONSE_CHECKSUM_VALIDATION=when_required

step() { # label cmd…
  local label=$1; shift
  local mark; mark=$(wc -l < "$W")
  local out rc; out=$(timeout 120 "$@" 2>&1); rc=$?
  printf '\n### %s  (rc=%s)\n' "$label" "$rc"
  echo "$out" | tail -3 | sed 's/^/    /'
  tail -n +$((mark+1)) "$W" | python3 -c '
import sys,json
for l in sys.stdin:
    d=json.loads(l); s=d["status"].split(" ",1)[-1]; r=d["resp"]
    code=r.split("<Code>")[1].split("</Code>")[0] if "<Code>" in r else ""
    print("    wire: %-6s %-64s -> %-20s %s" % (d["method"], d["target"][:64], s, code))'
}

as_wild()   { export AWS_ACCESS_KEY_ID=AKIAWILD   AWS_SECRET_ACCESS_KEY=wild-secret;   }
as_scoped() { export AWS_ACCESS_KEY_ID=AKIASCOPED AWS_SECRET_ACCESS_KEY=scoped-secret; }
as_obj()    { export AWS_ACCESS_KEY_ID=AKIAOBJ    AWS_SECRET_ACCESS_KEY=obj-secret;    }

rc_conf() { # sub secret -> a config file
  local f="$STATE/rclone-$1.conf"
  printf '[s0]\ntype = s3\nprovider = Ceph\naccess_key_id = %s\nsecret_access_key = %s\nendpoint = %s\nregion = us-east-1\nforce_path_style = true\n' "$1" "$2" "$EP_RCLONE" > "$f"
  echo "$f"
}

echo; echo "═══ aws-cli, wildcard principal ═══"
as_wild
step "aws s3 ls"                aws --endpoint-url $EP s3 ls
step "aws s3 mb"                aws --endpoint-url $EP s3 mb s3://compat-aws
step "aws s3 cp up"             aws --endpoint-url $EP s3 cp "$D/up/a.txt" s3://compat-aws/a.txt
step "aws s3 ls bucket"         aws --endpoint-url $EP s3 ls s3://compat-aws/
step "aws s3 sync up"           aws --endpoint-url $EP s3 sync "$D/up" s3://compat-aws/sync/
step "aws s3 cp 12MiB"          aws --endpoint-url $EP s3 cp "$D/big.bin" s3://compat-aws/big.bin
step "aws s3 rm --recursive"    aws --endpoint-url $EP s3 rm s3://compat-aws/sync/ --recursive
step "aws --acl private"        aws --endpoint-url $EP s3 cp "$D/up/a.txt" s3://compat-aws/p.txt --acl private
step "aws --acl public-read"    aws --endpoint-url $EP s3 cp "$D/up/a.txt" s3://compat-aws/q.txt --acl public-read
step "aws list-object-versions" aws --endpoint-url $EP s3api list-object-versions --bucket compat-aws
step "aws get-bucket-versioning" aws --endpoint-url $EP s3api get-bucket-versioning --bucket compat-aws
step "aws put-object-acl"       aws --endpoint-url $EP s3api put-object-acl --bucket compat-aws --key a.txt --acl private
step "aws get-object-attributes (multi)" aws --endpoint-url $EP s3api get-object-attributes --bucket compat-aws --key a.txt --object-attributes ETag ObjectSize

echo; echo "═══ mc, wildcard principal ═══"
MCD="$STATE/mc"; rm -rf "$MCD"
step "mc alias set"     mc --config-dir "$MCD" alias set s0 $EP AKIAWILD wild-secret
step "mc ls"            mc --config-dir "$MCD" ls s0
step "mc mb"            mc --config-dir "$MCD" mb s0/compat-mc
step "mc cp up"         mc --config-dir "$MCD" cp "$D/up/a.txt" s0/compat-mc/a.txt
step "mc ls bucket"     mc --config-dir "$MCD" ls s0/compat-mc
step "mc version info"  mc --config-dir "$MCD" version info s0/compat-mc
step "mc rb --force"    mc --config-dir "$MCD" rb --force s0/compat-mc

echo; echo "═══ rclone, wildcard principal ═══"
RCW=$(rc_conf AKIAWILD wild-secret)
step "rclone lsd"          rclone --config "$RCW" --retries 1 lsd s0:
step "rclone mkdir"        rclone --config "$RCW" --retries 1 mkdir s0:compat-rc
step "rclone copy"         rclone --config "$RCW" --retries 1 copy "$D/up" s0:compat-rc/up
step "rclone purge"        rclone --config "$RCW" --retries 1 purge s0:compat-rc

echo; echo "═══ BLOCKER-1: rclone copy as a SCOPED principal ═══"
aws --endpoint-url $EP s3 mb s3://scoped-b >/dev/null 2>&1
RCS=$(rc_conf AKIASCOPED scoped-secret)
step "rclone copy (no flag) — EXPECTED FATAL" rclone --config "$RCS" --retries 1 copy "$D/up/a.txt" s0:scoped-b/team-a/x/
step "rclone copy --s3-no-check-bucket — EXPECTED OK" rclone --config "$RCS" --retries 1 --s3-no-check-bucket copy "$D/up/a.txt" s0:scoped-b/team-a/x/

echo; echo "═══ BLOCKER-2: mc ls <bucket> as an OBJECT-VERBS-ONLY principal ═══"
MCO="$STATE/mc-obj"; rm -rf "$MCO"
step "mc alias set (obj)"  mc --config-dir "$MCO" alias set oo $EP AKIAOBJ obj-secret
step "mc ls bucket (obj) — EXPECTED FATAL" mc --config-dir "$MCO" ls oo/scoped-b
as_obj
step "aws s3 cp (obj) — EXPECTED OK"       aws --endpoint-url $EP s3 cp "$D/up/a.txt" s3://scoped-b/oo.txt

echo; echo "═══ boto3 ═══"
AWS_ACCESS_KEY_ID=AKIAWILD AWS_SECRET_ACCESS_KEY=wild-secret python3 - "$EP" <<'PY'
import sys, boto3
from botocore.config import Config
ep=sys.argv[1]
s3=boto3.client("s3",endpoint_url=ep,region_name="us-east-1",
    config=Config(s3={"addressing_style":"path"},retries={"max_attempts":1},
                  request_checksum_calculation="when_required",
                  response_checksum_validation="when_required"))
def t(label,fn):
    try: fn(); print(f"    {label:46} OK")
    except Exception as e: print(f"    {label:46} {repr(e)[:110]}")
B="compat-boto"
t("create_bucket",       lambda: s3.create_bucket(Bucket=B))
t("put_object",          lambda: s3.put_object(Bucket=B,Key="a.txt",Body=b"x"))
t("get_object_attributes multi", lambda: s3.get_object_attributes(Bucket=B,Key="a.txt",ObjectAttributes=["ETag","ObjectSize"]))
t("put_object_tagging",  lambda: s3.put_object_tagging(Bucket=B,Key="a.txt",Tagging={"TagSet":[{"Key":"tier","Value":"gold"}]}))
t("ACL public-read (must FAIL)", lambda: s3.put_object(Bucket=B,Key="p",Body=b"x",ACL="public-read"))
t("ACL private (must pass)",     lambda: s3.put_object(Bucket=B,Key="q",Body=b"x",ACL="private"))
t("get_bucket_versioning (must FAIL)", lambda: s3.get_bucket_versioning(Bucket=B))
PY

echo
echo "═══ every op the gateway saw, with its verdict ═══"
python3 - "$W" <<'PY'
import sys, json, collections
seen=collections.Counter()
for l in open(sys.argv[1]):
    d=json.loads(l); r=d["resp"]
    code=r.split("<Code>")[1].split("</Code>")[0] if "<Code>" in r else ""
    msg=r.split("<Message>")[1].split("</Message>")[0] if "<Message>" in r else ""
    op = msg.rsplit(": ",1)[-1] if "not permitted by the gateway" in msg else ""
    seen[(d["method"], d["target"].split("&")[0][:40], d["status"].split()[1], code, op)] += 1
for (m,t,s,c,op),n in sorted(seen.items()):
    print(f"  {n:3}x {m:6} {t:42} {s:4} {c} {op}")
PY
echo
echo "gateway log: $STATE/gw.log     wire: $W"
