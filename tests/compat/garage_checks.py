"""Assertions of the Garage compat leg. Driven by tests/compat/garage.sh, which starts
Garage and s0 and exports the endpoints and keys this reads. Exits non-zero, listing every
failed check, if any property does not hold."""

import base64
import http.client
import os
import sys
import zlib
from urllib.parse import quote, urlsplit

import boto3
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from botocore.config import Config
from botocore.credentials import Credentials
from botocore.exceptions import ClientError

S0_EP = os.environ["S0_EP"]
GARAGE_EP = os.environ["GARAGE_EP"]
GARAGE_REGION = os.environ["GARAGE_REGION"]
# What clients sign with. Garage only accepts its own `s3_region`, so a request that
# succeeds upstream was re-signed by s0 with the backend's region.
CLIENT_REGION = "us-east-1"

FAILURES = []


def client(endpoint, key, secret, region, validate_response_checksums=True):
    return boto3.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=key,
        aws_secret_access_key=secret,
        region_name=region,
        config=Config(
            s3={"addressing_style": "path"},
            retries={"max_attempts": 1},
            response_checksum_validation="when_supported" if validate_response_checksums else "when_required",
        ),
    )


acme = client(S0_EP, "AKIAACME", "acme-secret", CLIENT_REGION)
globex = client(S0_EP, "AKIAGLOBEX", "globex-secret", CLIENT_REGION)
org_one = client(GARAGE_EP, os.environ["ORG_ONE_ID"], os.environ["ORG_ONE_SECRET"], GARAGE_REGION)
# Garage v2.4.1 answers a GET of a multipart object with its composite CRC32 but without the
# `-<parts>` suffix or a COMPOSITE checksum type, so an SDK validates it as a full-object
# checksum and fails — on Garage directly as much as through s0. The multipart object is read
# with response validation off and compared byte for byte instead.
acme_unvalidated = client(S0_EP, "AKIAACME", "acme-secret", CLIENT_REGION, validate_response_checksums=False)
org_two = client(GARAGE_EP, os.environ["ORG_TWO_ID"], os.environ["ORG_TWO_SECRET"], GARAGE_REGION)


def check(label, ok, detail=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  ({detail})" if detail and not ok else ""))
    if not ok:
        FAILURES.append(label)


def expect_ok(label, fn):
    try:
        out = fn()
    except Exception as e:  # noqa: BLE001 — any failure is the finding
        check(label, False, repr(e)[:200])
        return None
    check(label, True)
    return out


def expect_denied(label, fn, codes=("AccessDenied",), status=403):
    try:
        fn()
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        got = e.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        # HEAD has no body, so its refusal carries the status alone.
        check(label, got == status and (code in codes or code == str(status)),
              f"status={got} code={code}")
        return
    except Exception as e:  # noqa: BLE001
        check(label, False, repr(e)[:200])
        return
    check(label, False, "the request succeeded")


def bucket_names(c):
    return sorted(b["Name"] for b in c.list_buckets().get("Buckets", []))


# The byte quota garage.sh's bundle states on acme-data (ADR-010), and what this script has
# written there so far: every write to acme-data below goes through `charge`.
ACME_QUOTA = 6 * 1024 * 1024
ACME_WRITTEN = 0


def charge(n):
    global ACME_WRITTEN
    ACME_WRITTEN += n


def chunked_trailer_put(path, data, query="", content_length=True):
    """A PUT the way a current SDK sends one over TLS: `aws-chunked`, unsigned payload, a
    CRC32 trailer. botocore only does this over https, so the request is built here; the
    signature is botocore's own SigV4. With `content_length=False` the body goes out with
    `Transfer-Encoding: chunked` and no Content-Length at all, as boto3 ≥ 1.36 sends it;
    with it, Content-Length is the encoded length, as aws-cli and Java v2 send it. Either
    way the object's size is only in X-Amz-Decoded-Content-Length.
    Returns (status, headers, body)."""
    crc = base64.b64encode(zlib.crc32(data).to_bytes(4, "big")).decode()
    body = b""
    for i in range(0, len(data), 64 * 1024):
        chunk = data[i:i + 64 * 1024]
        body += f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
    body += b"0\r\n" + f"x-amz-checksum-crc32:{crc}\r\n".encode() + b"\r\n"

    url = f"{S0_EP}{quote(path)}" + (f"?{query}" if query else "")
    host = urlsplit(S0_EP).netloc
    headers = {
        "Host": host,
        "Content-Encoding": "aws-chunked",
        "X-Amz-Content-SHA256": "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
        "X-Amz-Decoded-Content-Length": str(len(data)),
        "X-Amz-Trailer": "x-amz-checksum-crc32",
        "X-Amz-Sdk-Checksum-Algorithm": "CRC32",
    }
    if content_length:
        headers["Content-Length"] = str(len(body))
    else:
        headers["Transfer-Encoding"] = "chunked"
    req = AWSRequest(method="PUT", url=url, data=body, headers=headers)
    SigV4Auth(Credentials("AKIAACME", "acme-secret"), "s3", CLIENT_REGION).add_auth(req)
    conn = http.client.HTTPConnection(host, timeout=60)
    target = urlsplit(url).path + (f"?{urlsplit(url).query}" if urlsplit(url).query else "")
    if content_length:
        conn.request("PUT", target, body=body, headers=dict(req.headers.items()))
    else:
        conn.request("PUT", target, body=iter([body]), headers=dict(req.headers.items()),
                     encode_chunked=True)
    resp = conn.getresponse()
    out = (resp.status, {k.lower(): v for k, v in resp.getheaders()}, resp.read())
    conn.close()
    return out


def read(c, bucket, key):
    obj = c.get_object(Bucket=bucket, Key=key)
    return obj["Body"].read(), obj.get("ContentEncoding")


print("== the shared upstream key reaches both tenants' buckets on Garage itself ==")
expect_ok("globex writes its own bucket through s0",
          lambda: globex.put_object(Bucket="globex-data", Key="secret.txt", Body=b"globex-only"))
expect_ok("acme writes its own bucket through s0",
          lambda: acme.put_object(Bucket="acme-data", Key="hello.txt", Body=b"hello"))
charge(len(b"hello"))
got = expect_ok("acme reads its own object back", lambda: read(acme, "acme-data", "hello.txt"))
check("acme's object reads back byte-identical", got is not None and got[0] == b"hello")
names = expect_ok("the org key lists buckets on Garage directly", lambda: bucket_names(org_one))
check("the org key sees BOTH tenants' buckets (so only s0 keeps them apart)",
      names is not None and {"acme-data", "globex-data"} <= set(names), str(names))
got = expect_ok("the org key reads globex's object on Garage directly",
                lambda: read(org_one, "globex-data", "secret.txt"))
check("…and gets it", got is not None and got[0] == b"globex-only")

print("== through s0, tenant acme cannot reach tenant globex's bucket (wildcard grant) ==")
expect_denied("GetObject on globex-data", lambda: acme.get_object(Bucket="globex-data", Key="secret.txt"))
expect_denied("HeadObject on globex-data", lambda: acme.head_object(Bucket="globex-data", Key="secret.txt"))
expect_denied("PutObject on globex-data",
              lambda: acme.put_object(Bucket="globex-data", Key="planted.txt", Body=b"x"))
expect_denied("DeleteObject on globex-data",
              lambda: acme.delete_object(Bucket="globex-data", Key="secret.txt"))
expect_denied("ListObjectsV2 on globex-data", lambda: acme.list_objects_v2(Bucket="globex-data"))
expect_denied("HeadBucket on globex-data", lambda: acme.head_bucket(Bucket="globex-data"))
expect_denied("CopyObject from globex-data into acme-data",
              lambda: acme.copy_object(Bucket="acme-data", Key="stolen.txt",
                                       CopySource={"Bucket": "globex-data", "Key": "secret.txt"}))
expect_denied("GetObject on a bucket the bundle does not place (another organization's)",
              lambda: acme.get_object(Bucket="other-org-data", Key="any"))
got = expect_ok("globex's object is still there", lambda: read(globex, "globex-data", "secret.txt"))
check("…untouched", got is not None and got[0] == b"globex-only")
expect_denied("nothing was planted in globex-data",
              lambda: globex.head_object(Bucket="globex-data", Key="planted.txt"),
              codes=("NoSuchKey", "NotFound"), status=404)
expect_denied("nothing was copied into acme-data",
              lambda: acme.head_object(Bucket="acme-data", Key="stolen.txt"),
              codes=("NoSuchKey", "NotFound"), status=404)

print("== ListBuckets is answered from the bundle, per tenant ==")
names = expect_ok("acme lists buckets", lambda: bucket_names(acme))
check("acme sees only acme-data", names == ["acme-data"], str(names))
names = expect_ok("globex lists buckets", lambda: bucket_names(globex))
check("globex sees only globex-data", names == ["globex-data"], str(names))

print("== Garage's per-organization key shape ==")
expect_denied("the other organization's key cannot read acme-data on Garage",
              lambda: org_two.get_object(Bucket="acme-data", Key="hello.txt"))
names = expect_ok("the other organization's key lists buckets", lambda: bucket_names(org_two))
check("…and sees only its own bucket", names == ["other-org-data"], str(names))

print("== aws-chunked + CRC32 trailer uploads through s0 (the 0.3.3 regression class) ==")
payload = os.urandom(200 * 1024 + 17)
status, headers, body = chunked_trailer_put("/acme-data/chunked.bin", payload)
check("PutObject with an aws-chunked CRC32 trailer is accepted", status == 200,
      f"status={status} body={body[:300]!r}")
charge(len(payload))
got = expect_ok("…reads back through s0", lambda: read(acme, "acme-data", "chunked.bin"))
check("…byte-identical through s0", got is not None and got[0] == payload)
check("…with no aws-chunked Content-Encoding stored",
      got is not None and "aws-chunked" not in (got[1] or ""), str(got and got[1]))
got = expect_ok("…reads back on Garage directly", lambda: read(org_one, "acme-data", "chunked.bin"))
check("…byte-identical on Garage", got is not None and got[0] == payload)

mpu = expect_ok("CreateMultipartUpload (CRC32)",
                lambda: acme.create_multipart_upload(Bucket="acme-data", Key="mp.bin",
                                                     ChecksumAlgorithm="CRC32"))
if mpu is not None:
    part1 = os.urandom(5 * 1024 * 1024)
    part2 = os.urandom(1024 + 3)
    upload_id = mpu["UploadId"]
    parts = []
    for number, data in ((1, part1), (2, part2)):
        status, headers, body = chunked_trailer_put(
            "/acme-data/mp.bin", data, query=f"partNumber={number}&uploadId={quote(upload_id, safe='')}")
        check(f"UploadPart {number} with an aws-chunked CRC32 trailer is accepted", status == 200,
              f"status={status} body={body[:300]!r}")
        charge(len(data))
        part = {"PartNumber": number, "ETag": headers.get("etag", "")}
        if "x-amz-checksum-crc32" in headers:
            part["ChecksumCRC32"] = headers["x-amz-checksum-crc32"]
        parts.append(part)
    expect_ok("CompleteMultipartUpload",
              lambda: acme.complete_multipart_upload(Bucket="acme-data", Key="mp.bin", UploadId=upload_id,
                                                     MultipartUpload={"Parts": parts}))
    got = expect_ok("…the multipart object reads back",
                    lambda: read(acme_unvalidated, "acme-data", "mp.bin"))
    check("…byte-identical", got is not None and got[0] == part1 + part2)
    check("…with no aws-chunked Content-Encoding stored",
          got is not None and "aws-chunked" not in (got[1] or ""), str(got and got[1]))

print("== a byte quota sizes aws-chunked writes by their decoded length (ADR-010) ==")
# boto3's framing: no Content-Length at all. Fill acme-data to 64 bytes short of its quota.
fill = os.urandom(ACME_QUOTA - ACME_WRITTEN - 64)
status, headers, body = chunked_trailer_put("/acme-data/fill.bin", fill, content_length=False)
check("PutObject without Content-Length (Transfer-Encoding: chunked) is accepted under a quota",
      status == 200, f"status={status} body={body[:300]!r}")
charge(len(fill))
got = expect_ok("…reads back through s0", lambda: read(acme, "acme-data", "fill.bin"))
check("…byte-identical", got is not None and got[0] == fill)
# Past the limit by one byte, in both framings: refused before it reaches Garage.
for framed in (False, True):
    over = os.urandom(ACME_QUOTA - ACME_WRITTEN + 1)
    status, headers, body = chunked_trailer_put("/acme-data/over.bin", over, content_length=framed)
    check(f"one byte past the quota is refused QuotaExceeded (Content-Length: {framed})",
          status == 403 and b"QuotaExceeded" in body, f"status={status} body={body[:300]!r}")
expect_denied("…and nothing was stored",
              lambda: acme.head_object(Bucket="acme-data", Key="over.bin"),
              codes=("NoSuchKey", "NotFound"), status=404)
# The remaining 64 bytes fit exactly. Encoded (chunk header, CRC32 trailer) they are ~110
# on the wire: charged by their encoded Content-Length they would be refused.
last = os.urandom(ACME_QUOTA - ACME_WRITTEN)
status, headers, body = chunked_trailer_put("/acme-data/last.bin", last, content_length=True)
check("the last bytes of the quota fit, charged their decoded length", status == 200,
      f"status={status} body={body[:300]!r}")
charge(len(last))

if FAILURES:
    print(f"\n{len(FAILURES)} check(s) FAILED:", file=sys.stderr)
    for f in FAILURES:
        print(f"  - {f}", file=sys.stderr)
    sys.exit(1)
print("\nGarage leg: all checks passed")
