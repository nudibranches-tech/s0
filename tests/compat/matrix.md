# Client compatibility matrix — the 29-op scope (plan task 63, risk 8)

**Measured, not asserted.** Every row below was produced by running the real client
against a real `s0` binary in front of a real S3 backend, and reading the requests off
the wire with a transparent recording proxy (`run.sh` rebuilds the whole stack). Where a
row could not be measured it says so.

| | |
|---|---|
| gateway | `s0` release build, embedded regorus PDP, shipped `policy/gateway/authz.rego` |
| backend | MinIO `RELEASE.2025-*` over `remote_s3`, path-style |
| aws-cli | **2.36.9** (`Python/3.14.6`) — measured |
| boto3 / botocore | **1.40.72 / 1.40.72** — measured |
| mc | **RELEASE.2025-08-13T08-35-41Z** — measured |
| rclone | **v1.74.4**, `provider = Ceph` — measured |
| s3fs | **out of scope** (settled; see plan §6.4) |

**Independently re-measured at the end of M4** on a second harness — a recording endpoint
that answers *every* op successfully (so a client that aborts on its first denial cannot
hide what it would have issued next), then the same commands against the real gateway.
Both blockers below reproduced; the `mc alias set` and `mc stat <bucket>` rows were
corrected as a result, and the plan's risk-8 premise was corrected in §2. Where the two
harnesses disagreed, the real-stack number is the one written down.

Three principals were used, because the answer depends on the *grant*, not only on the op:

- **W** — wildcard: `{bucket:"*", actions:["*"]}`
- **S** — scoped: `read/list/write/delete_objects` on `team-a/` of one bucket, plus
  `list_buckets` + `read_bucket` on that bucket
- **O** — object-verbs only: the four object verbs, **no** `read_bucket`, **no**
  `list_buckets`, **no** `create_bucket`

---

## 1. Release blockers — denied-and-fatal

### BLOCKER-1 — `rclone copy` / `rclone sync` into a bucket the principal cannot create

| | |
|---|---|
| op | `CreateBucket` — **Enforced** |
| principals | **S** and **O**. Not W (a wildcard grant confers `create_bucket`). |
| symptom | `Failed to copy: failed to prepare upload: operation error S3: CreateBucket, StatusCode: 403 … deny: no grant matches action/scope` — **rc=1, nothing is uploaded** |
| fatal | **YES** |

rclone issues a `CreateBucket` before its first upload into a bucket as an
"exists?" probe and treats a non-2xx that is not `BucketAlreadyOwnedByYou` as fatal.
Against AWS/RGW that probe succeeds (you own the bucket); against s0 a principal with
object grants but no `create_bucket` grant gets a 403 and the transfer aborts. Confirmed
against a clean control: the same command with `--s3-no-check-bucket` returns rc=0 and
uploads, the same command without it returns rc=1 every time.

Three ways out, in order of preference:

1. **`--s3-no-check-bucket`** on the client (or `no_check_bucket = true` in
   `rclone.conf`). Measured working. This is the documented rclone flag for exactly this
   situation and costs the gateway nothing.
2. Let `CreateBucket` on an **existing** bucket answer the way the backend would
   (`BucketAlreadyOwnedByYou`) rather than 403. **Rejected here**: it turns
   `create_bucket` into a bucket-existence oracle for any principal, which is the
   information `HeadBucket` is enforced to withhold.
3. Give the projection a `create_bucket` grant. **Rejected**: creating buckets is not
   implied by writing objects into one, and this would grant it to every uploader.

**Nothing in this repo fixes BLOCKER-1.** It is a documented client flag, and it must be
in the rclone instructions the product ships before rclone is called supported.

### BLOCKER-2 — `mc ls <alias>/<bucket>` without `read_bucket`

| | |
|---|---|
| ops | `HeadBucket`, `GetBucketLocation` — both **Enforced**, both on `read_bucket` |
| principal | **O** only |
| symptom | `mc: <ERROR> Unable to list folder. Access Denied.` — rc=1 |
| fatal | **YES for principal O; disappears entirely once the grant carries `read_bucket`** (measured both ways) |

This is not a gateway defect, it is the projection invariant from ADR-006 §D2 made
visible: **a projection that emits object verbs without `read_bucket` and `list_buckets`
produces a principal whose data path works and whose navigation does not.** With
`read_bucket` added to the same grant, `mc ls` returns rc=0 and the listing. The
hyperfluid-side creator-grant and the seeded system bundles must carry both verbs.

---

## 2. Denied-and-degraded — noisy, not fatal

These are ops outside the 29 that a client probes and then copes with. Each was measured
returning `403 AccessDenied: operation is not permitted by the gateway: <Op>`.

| op | client | when | client behaviour | fatal |
|---|---|---|---|---|
| `GetBucketVersioning` | rclone | `purge`, `rmdir`, any bucket-level delete | logs `ERROR … Failed to read versioning status, assuming unversioned`, then **continues and succeeds** | no |
| `GetBucketVersioning` | mc | `mc version info` | hard error, rc=1 | **only that subcommand** |
| `GetObjectLockConfiguration` | mc | first `cp`/`mirror` into a bucket | silently ignored, transfer proceeds | no |
| `ListObjectVersions` | mc | `mc rb --force` | tried twice, both 403, then `DeleteBucket` proceeds | no (see caveat) |
| `ListObjectVersions` | aws-cli | `s3api list-object-versions` | rc=254 | only that command |
| `PutObjectAcl` | aws-cli | `s3api put-object-acl` | rc=254 | only that command |
| `GetBucketNotificationConfiguration` | mc | `mc stat <bucket>` only | ignored, field omitted | no |
| `GetBucketNotificationConfiguration` | aws-cli, boto3, rclone | **never observed** | — | — |
| `GetBucketTagging`, `GetBucketReplication`, `GetBucketEncryption`, `GetBucketLifecycleConfiguration` | mc | `mc stat <bucket>` only | ignored, fields omitted | no |

**Caveat on the two versioning rows.** rclone's "assuming unversioned" and mc's skipped
`ListObjectVersions` are only harmless because this gateway does not enable versioning:
`PutBucketVersioning` is denied, so no bucket reachable through s0 can be versioned by an
s0 client. If a bucket is versioned **out of band**, `rclone purge` will delete current
versions only and `mc rb --force` will leave versions behind, and both will then report a
`BucketNotEmpty` failure they cannot explain. Recorded, not fixed.

**Plan risk 8 was partly out of date, and in the safe direction.** It named
`GetBucketVersioning` / `GetBucketNotification` / `GetBucketLocation` as the connect
probes. Measured on current versions: **none of the three is a connect probe.**
`GetBucketNotificationConfiguration` appears only inside `mc stat <bucket>`, a diagnostic
command, and only there; `GetBucketVersioning` appears only on bucket-level *delete*
paths and in `mc version info`; `GetBucketLocation` **is** in the 29 and is what
`mc alias set` probes (together with `HeadBucket`, on a random bucket name — and mc
tolerates a 403 on both, measured). The premise was wrong in the safe direction: the
probes are rarer than the plan feared, and the one that is ubiquitous is already
enforced.

---

## 3. Per-command results

`rc` is the process exit code. All runs are with principal **W** unless the row says
otherwise.

### aws-cli 2.36.9 — no fatal cells

| command | ops issued | rc |
|---|---|---|
| `s3 ls` | ListBuckets | 0 |
| `s3 mb` | CreateBucket | 0 |
| `s3 cp` (up) | PutObject | 0 |
| `s3 ls s3://b/` | ListObjectsV2 | 0 |
| `s3 sync` (up) | ListObjectsV2, PutObject × n | 0 |
| `s3 sync` (down) | ListObjectsV2, GetObject × n | 0 |
| `s3 cp` (down) | HeadObject, GetObject | 0 |
| `s3 cp` s3→s3 | CopyObject | 0 |
| `s3 cp` 12 MiB | CreateMultipartUpload, UploadPart × 2, CompleteMultipartUpload | 0 |
| `s3 rm` | DeleteObject | 0 |
| `s3 rm --recursive` | ListObjectsV2, DeleteObject × n | 0 |
| `s3 rb` | DeleteBucket | 0 |
| `s3 presign` + curl | GetObject (presigned) | 0, HTTP 200 |
| `s3api head-bucket` | HeadBucket | 0 |
| `s3api get-bucket-location` | GetBucketLocation | 0 |
| `s3api get/put-object-tagging` | GetObjectTagging / PutObjectTagging | 0 |
| `s3api list-multipart-uploads` | ListMultipartUploads | 0 |
| `s3api list-object-versions` | ListObjectVersions | 254 — **denied** |
| `s3api get-bucket-versioning` | GetBucketVersioning | 254 — **denied** |
| `s3api put-object-acl` | PutObjectAcl | 254 — **denied** |

Principal **S**: every data-path command above still rc=0; `head-bucket` on a bucket
outside the grant is a 403, and an out-of-prefix `cp` is a 403 with
`deny: no grant matches action/scope` — which is the intended outcome, not a compat
failure. Principal **O**: `s3 ls` is an empty listing (by design, see ADR-007), everything
else still works.

### mc RELEASE.2025-08-13 — one fatal subcommand, one fatal cell at principal O

| command | ops issued | rc |
|---|---|---|
| `alias set` (no `--api`) | GetBucketLocation **and HeadBucket**, both on a random `probe-bsign-<rand>` bucket | 0 — and still 0 when **both are 403**, which is what a real principal gets, since no grant names a random bucket. Measured both ways. |
| `alias set --api S3v4` | *(none — the flag is what the probe exists to determine)* | 0 |
| `ls` | ListBuckets | 0 |
| `mb` / `mb --with-lock` | CreateBucket | 0 |
| `cp` (up) | GetBucketLocation, **GetObjectLockConfiguration (403, ignored)**, HeadObject, ListObjectsV2, PutObject | 0 |
| `ls <bucket>` | GetBucketLocation, HeadBucket, ListObjectsV2 | 0 (**rc=1 for principal O — BLOCKER-2**) |
| `mirror` | GetBucketLocation, ListObjectsV2, PutObject × n | 0 |
| `cp` (down) | GetBucketLocation, HeadObject, GetObject | 0 |
| `cp` 12 MiB | CreateMultipartUpload, UploadPart, CompleteMultipartUpload | 0 |
| `cp` s3→s3 | CopyObject | 0 |
| `rm` | GetBucketLocation, HeadObject × 2, DeleteObjects | 0 |
| `rm --recursive` | + ListObjectsV2 (paged) | 0 |
| `rb --force` | GetBucketLocation, HeadBucket, **ListObjectVersions × 2 (403, ignored)**, DeleteBucket | 0 |
| `stat <object>` | GetBucketLocation, ListObjectsV2, HeadObject | 0 |
| `stat <bucket>` | GetBucketLocation, HeadBucket, then **eight** sub-resource probes — GetBucketVersioning, GetObjectLockConfiguration, GetBucketReplication, GetBucketEncryption, **GetBucketPolicy (enforced)**, GetBucketTagging, GetBucketLifecycleConfiguration, GetBucketNotificationConfiguration — seven of which 403 | 0 for a principal that can also list the bucket root; it simply prints fewer fields. rc=1 for principal **O**, from the root listing, not from the probes. |
| `du` | GetBucketLocation, HeadBucket, ListObjectsV2 | 0 |
| `tag set` / `tag list` | PutObjectTagging / GetObjectTagging | 0 |
| `anonymous get` | GetBucketPolicy | 0 |
| `version info` | GetBucketVersioning | 1 — **denied, fatal for this subcommand** |

### rclone v1.74.4 — one fatal cell (BLOCKER-1)

| command | ops issued | rc |
|---|---|---|
| `lsd` | ListBuckets | 0 |
| `mkdir` | CreateBucket | 0 |
| `ls` / `lsjson` / `size` | ListObjectsV2 (+ HeadObject per object for `lsjson`) | 0 |
| `copy` / `sync` (up) | HeadObject, ListObjectsV2, **CreateBucket**, PutObject × n, HeadObject × n | 0 for **W**; **1 for S and O — BLOCKER-1** |
| `copy` / `sync` (up) `--s3-no-check-bucket` | as above minus CreateBucket | 0 for all three |
| `copy` of a file whose remote copy already **matches** | HeadObject, **CopyObject** — rclone's `SetModTime` is a server-side copy onto the same key, not a no-op | 0 — but it means an ordinary `rclone copy` needs `read_objects` **and** `write_objects` on that key even when nothing is transferred |
| `sync` (down) | ListObjectsV2, GetObject × n | 0 |
| `copy` 12 MiB (`--s3-chunk-size 5M`) | CreateMultipartUpload, UploadPart × 3, CompleteMultipartUpload | 0 |
| `copyto` s3→s3 | CopyObject | 0 |
| `deletefile` | HeadObject × 2, DeleteObject | 0 |
| `purge` | **GetBucketVersioning (403, degraded)**, ListObjectsV2, DeleteObject × n, DeleteBucket | 0 |
| `about` | *(none — rclone answers locally; S3 has no `about`)* | 1 (not the gateway) |

### boto3 1.40.72 — no fatal cells

boto3 issues exactly the API called and probes nothing, so its matrix is the op list. All
29 behaved as designed. Two rows are worth writing down:

| call | result | note |
|---|---|---|
| `get_object_attributes(["ETag","ObjectSize"])` | **200 after the fix in this change** | it was `400 InvalidArgument` before — see §5 |
| `put_bucket_cors` | `501 NotImplemented` | **from MinIO**, not from s0. The identical call direct to MinIO fails identically. The gateway authorized and forwarded it. Untested against RGW. |

---

## 4. The ACL regression fix, over the wire

The M4 ACL work is the one place where the gateway deliberately refuses something the
backend would have accepted, so it is measured with a positive control on every row.

| request | outcome |
|---|---|
| `aws s3 cp --acl private` | **allowed** (rc=0) — the no-op tier |
| `aws s3 cp --acl public-read` | **403** `deny (gateway): the request carries the canned ACL "public-read" …` |
| `aws s3 cp --acl bucket-owner-full-control` | **allowed** under a wildcard grant — the conferring tier taking a real `write_object_acl` decision |
| `boto3 put_object(ACL="public-read")` | **403**, same reason |
| `boto3 put_object(ACL="private")` | **allowed** |
| `rclone --s3-acl private` (existing bucket) | **allowed** |
| `rclone --s3-acl public-read` | **403** — and note it surfaces on rclone's `CreateBucket` probe, i.e. as a *bucket* ACL refusal |
| `aws s3api create-bucket --acl private` | **allowed** |
| `aws s3api create-bucket --acl public-read` | **403** `… does not authorize bucket ACLs at all` |
| `aws s3api put-object-acl` | **403 at the gate** — `PutObjectAcl` is not in the 29 |
| `aws s3 cp --acl public-read-write` | **403** — public tier |
| `aws s3 cp --acl authenticated-read` | **403** — public tier |
| `aws s3 cp --acl log-delivery-write` | **403** — a canned name this build does not recognize is treated as public. Stricter than S3, deliberate, one-line reversible. |
| `aws s3api delete-object --bypass-governance-retention` | **403** — refused in code, unconditionally; no verb can express a WORM override |
| `aws s3api put-object --tagging tier=gold` (key not reserved) | **allowed** |
| `aws s3api put-object-tagging` on `hyperfluid/…` | **403** — reserved key |
| any tag write with `org_settings.reserved_tag_keys` **absent** | **403** — tagging is inert until the control plane publishes the list. Tag *reads* and plain writes are unaffected (measured). |

The rows above were re-measured end to end at the close of M4: 19 of 19 behaved as
written, each with its own positive control on the same identity.

`mc` and `rclone` (Ceph provider) send no ACL header by default, so the common path costs
nothing. `s3cmd`, which sends `x-amz-acl: private` on every upload, is covered by the
no-op tier but was **not measured** (not in the four).

**Measured hole, recorded not fixed:** `mc mb --with-lock` is **allowed**. It sets
`x-amz-bucket-object-lock-enabled: true`, which is an uninspected rider on `CreateBucket`
(already on that op's blind-spot list). A `create_bucket` grant therefore lets a caller
turn on object lock for a new bucket, and the gateway refuses every bypass afterwards.

---

## 5. A defect this matrix found, and the change fixed

`GetObjectAttributes` with **more than one attribute** was broken by the gateway:

```
client  -> s0 :  x-amz-object-attributes: ETag,ObjectSize      → 400 InvalidArgument
s0      -> RGW:  x-amz-object-attributes: "ETag,ObjectSize"    ← the quotes are s0's
client  -> MinIO (direct, same SDK): works
```

`s3s`'s `parse_list_header` (`http/de.rs:118-132`) iterates `headers.get_all(name)` and
never splits on the comma, so a single header with comma-separated values parses to a
one-element list; the AWS SDK then quotes any element containing a comma. One attribute
worked, two did not.

Fixed in `access::split_comma_list`, applied in the `get_object_attributes`,
`list_objects` and `list_objects_v2` hooks (the only two `list`-shaped headers s3s
forwards), and pinned by
`tests/security_regressions.rs::a_comma_separated_list_header_survives_the_forward_intact`.
Re-measured end to end afterwards: one, two and three attributes all return 200.

This is the argument for the matrix existing. No unit test would have found it — every
in-repo test stops at the decision, and this was a forward-path encoding bug in an op the
gateway correctly *authorized*.

---

## 6. What this matrix does NOT cover

- **RGW.** The backend here is MinIO. `PutBucketCors` is `501` on MinIO and untested
  against RGW; `GetObjectAttributes` semantics and multipart part accounting may differ.
  The one thing MinIO cannot stand in for is RGW's `<tenant>:<bucket>` addressing, which
  `tenant_local_bucket_name` guards and which no client here exercises.
- **`PostObject`** (browser form upload). None of the four clients issue it; it is
  covered by `tests/gate_blackbox.rs::a_form_upload_is_authorized_on_its_form_carried_key`
  over real HTTP instead.
- **STS session credentials.** Every run used a static credential. The session-token path
  (`X-Amz-Security-Token` in header and query) has its own tests but is not in this matrix.
- **s3cmd, Cyberduck, Hadoop `s3a`, the AWS SDKs other than Python.** Not measured. `s3a`
  in particular is a known sender of `bucket-owner-full-control`, which lands in the
  conferring tier and needs a `write_object_acl` grant the projection does not emit today.
- **`s3fs`** — explicitly out of scope.
- **Versioned buckets**, for the reason in §2.
