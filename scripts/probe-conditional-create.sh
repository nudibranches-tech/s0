#!/usr/bin/env bash
# Does an S3 backend honour `If-None-Match: *`? (ADR-014 D8)
#
# `backends[].conditional_create: native` is an operator ASSERTION: s0 then relies on the
# backend to refuse a create-only commit onto an existing key. A backend that ignores the
# header would turn create-only into overwrite with no error anywhere. Run this against
# the backend (the same version, the same gateway/proxy in front of it) before declaring
# it native, and again after every backend upgrade.
#
# Writes only under a fresh random prefix of BUCKET, and deletes what it wrote.
#
#   ENDPOINT=https://rgw.example:443 BUCKET=probe \
#   AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
#   bash scripts/probe-conditional-create.sh
#
# Env: ENDPOINT, BUCKET (must exist, writable), AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
# (required); REGION (us-east-1); INSECURE=1 (skip TLS verification); AWS_CLI=local (use
# the `aws` on PATH instead of the pinned container); AWSCLI_IMAGE.
#
# Exit: 0 every check passed (`native` is safe to declare); 1 at least one check failed
# (keep `check_then_write`); 2 the probe could not run (credentials, bucket, network).
set -uo pipefail

: "${ENDPOINT:?ENDPOINT is required}" "${BUCKET:?BUCKET is required}"
: "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}" "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"
REGION="${REGION:-us-east-1}"
AWSCLI_IMAGE="${AWSCLI_IMAGE:-amazon/aws-cli:2.27.50}"
PREFIX="s0-conditional-create-probe/$(date +%s)-$RANDOM"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
printf 'first\n' >"$WORK/a.txt"
printf 'second\n' >"$WORK/b.txt"

tls=()
[ "${INSECURE:-}" = 1 ] && tls=(--no-verify-ssl)
# Set by must_refuse: the verdict is read from the HTTP status in aws-cli's debug log, not
# from its error message. Ceph RGW (tentacle) answers a correct 412 with an empty
# <Message/>, which some aws-cli releases fail to format ("argument of type 'NoneType' is
# not iterable"): the backend is right, the client's message is not.
debug=()

s3api() {
  if [ "${AWS_CLI:-}" = local ]; then
    (cd "$WORK" && AWS_DEFAULT_REGION="$REGION" AWS_EC2_METADATA_DISABLED=true \
      AWS_REQUEST_CHECKSUM_CALCULATION=when_required \
      AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
      aws --endpoint-url "$ENDPOINT" "${tls[@]}" "${debug[@]}" s3api "$@")
  else
    docker run --rm --network host -v "$WORK:/work" -w /work \
      -e AWS_ACCESS_KEY_ID -e AWS_SECRET_ACCESS_KEY -e AWS_DEFAULT_REGION="$REGION" \
      -e AWS_EC2_METADATA_DISABLED=true \
      -e AWS_REQUEST_CHECKSUM_CALCULATION=when_required \
      -e AWS_RESPONSE_CHECKSUM_VALIDATION=when_required \
      "$AWSCLI_IMAGE" --endpoint-url "$ENDPOINT" "${tls[@]}" "${debug[@]}" s3api "$@"
  fi
}

PASS=0; FAIL=0; written=()
ok() { PASS=$((PASS + 1)); echo "  PASS $1"; }
ko() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; [ -n "${2:-}" ] && echo "       $2"; }

# A plain (unconditional) write: the "other writer". Its failure is a setup failure.
plain_put() {
  local out
  if ! out=$(s3api put-object --bucket "$BUCKET" --key "$1" --body "$2" 2>&1); then
    echo "probe cannot write to s3://$BUCKET/$1: $out" >&2
    exit 2
  fi
  written+=("$1")
}

cond_put() { s3api put-object --bucket "$BUCKET" --key "$1" --body "$2" --if-none-match '*'; }

# One conditional multipart upload of a single part; aborts the upload if the commit fails.
cond_mpu() {
  local id et rc
  id=$(s3api create-multipart-upload --bucket "$BUCKET" --key "$1" \
    --query UploadId --output text) || return 1
  et=$(s3api upload-part --bucket "$BUCKET" --key "$1" --upload-id "$id" \
    --part-number 1 --body "$2" --query ETag --output text) || return 1
  s3api complete-multipart-upload --bucket "$BUCKET" --key "$1" --upload-id "$id" \
    --multipart-upload "Parts=[{ETag=$et,PartNumber=1}]" --if-none-match '*' && return 0
  rc=$?
  s3api abort-multipart-upload --bucket "$BUCKET" --key "$1" --upload-id "$id" >/dev/null 2>&1
  return $rc
}

body_is() { # key expected-file — the object still holds what the first writer wrote
  s3api get-object --bucket "$BUCKET" --key "$1" got.txt >/dev/null 2>&1 &&
    cmp -s "$WORK/got.txt" "$2"
}

must_create() { # label <command...>
  local label=$1 out; shift
  if out=$("$@" 2>&1); then ok "$label"; else ko "$label" "$out"; fi
}

must_refuse() { # label key expected-body <command...>
  local label=$1 key=$2 keep=$3 out rc; shift 3
  debug=(--debug)
  out=$("$@" 2>&1); rc=$?
  debug=()
  if [ $rc -ne 0 ] && echo "$out" | grep -qE 'HTTP/1\.1" 412 '; then
    if body_is "$key" "$keep"; then ok "$label"; else ko "$label" "412, but the object changed"; fi
  elif [ $rc -eq 0 ]; then
    ko "$label" "accepted: the backend ignored If-None-Match and overwrote the object"
  else
    ko "$label" "refused, but not with 412 PreconditionFailed (rc=$rc): $(echo "$out" | grep -E 'HTTP/1\.1" [0-9]{3} |Error' | tail -3)"
  fi
}

echo "If-None-Match: * conformance of $ENDPOINT (s3://$BUCKET/$PREFIX/)"
if ! out=$(s3api head-bucket --bucket "$BUCKET" 2>&1); then
  echo "probe cannot reach s3://$BUCKET at $ENDPOINT: $out" >&2
  exit 2
fi

k="$PREFIX/put-fresh"; written+=("$k")
must_create "PutObject onto a fresh key is accepted" cond_put "$k" a.txt
must_refuse "PutObject onto a key it created itself is 412" "$k" "$WORK/a.txt" cond_put "$k" b.txt

k="$PREFIX/put-other-writer"
plain_put "$k" a.txt
must_refuse "PutObject onto a key another writer created is 412" "$k" "$WORK/a.txt" cond_put "$k" b.txt

k="$PREFIX/mpu-fresh"; written+=("$k")
must_create "CompleteMultipartUpload onto a fresh key is accepted" cond_mpu "$k" a.txt
must_refuse "CompleteMultipartUpload onto a key it created itself is 412" "$k" "$WORK/a.txt" cond_mpu "$k" b.txt

k="$PREFIX/mpu-other-writer"
plain_put "$k" a.txt
must_refuse "CompleteMultipartUpload onto a key another writer created is 412" "$k" "$WORK/a.txt" cond_mpu "$k" b.txt

for k in "${written[@]}"; do
  s3api delete-object --bucket "$BUCKET" --key "$k" >/dev/null 2>&1
done
leftover=$(s3api list-multipart-uploads --bucket "$BUCKET" --prefix "$PREFIX/" \
  --query 'length(Uploads || `[]`)' --output text 2>/dev/null || echo "?")
[ "$leftover" = 0 ] || echo "  note: $leftover multipart upload(s) left under $PREFIX/"

echo "$PASS passed, $FAIL failed"
if [ "$FAIL" -eq 0 ]; then
  echo "verdict: conditional_create: native is safe to declare for this backend"
  exit 0
fi
echo "verdict: keep conditional_create: check_then_write (ADR-014 D8 residual race)"
exit 1
