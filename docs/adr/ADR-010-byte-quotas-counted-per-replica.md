# ADR-010: Byte quotas on a backend without native ones, counted per replica

- **Status**: Accepted — implemented (src/quota.rs, src/pdp/bundle.rs, src/access/mod.rs, src/proxy/mod.rs)
- **Date**: 2026-10-02
- **Owners**: gateway team (this repo); measuring `used_bytes` and projecting the limits is
  control-plane integration
- **Related**: `src/quota.rs` (`QuotaLedger`, `QuotaReservation`), `src/pdp/bundle.rs`
  (`BucketPlacement::quotas`), `src/access/mod.rs` (`hold_quota`, `copy_size`),
  `src/proxy/mod.rs` (`forward`), `tests/quota.rs`, `tests/fixture_drift.rs`; builds on
  ADR-009 (the v3 bundle)

## Context

Ceph RGW enforces byte quotas itself, per bucket and per user, so a gateway in front of it
needs none. A generic S3 backend often has no quota at all, or one per bucket and nothing
for the total of a tenant or of an organization. The control plane knows the limits and
measures what each bucket holds, but a measurement is minutes old by the time it reaches the
gateway: enforced on that alone, a client can write without bound between two collections.

## Decision

From `grant_schema_version` 3 the bundle may state a quota,
`{ "limit_bytes": u64, "used_bytes": u64, "collected_at": RFC 3339 }`, at three levels:

| Level | Where in `data` | What counts against it |
|---|---|---|
| bucket | `tenants[<tenant>].bucket_attributes[<S3 name>].quota` | writes to that bucket |
| tenant | `tenants[<tenant>].quota` | writes to any of the tenant's buckets |
| backend | `backend_quota` | writes by every tenant on this backend |

A level with no `quota` (or `null`) has no limit. A document with none anywhere (the Ceph
shape) enforces and counts nothing, and below v3 the key is not read at all.

**The check.** Once the policy has allowed a write, and before its record is held, the write
is refused with `QuotaExceeded` (HTTP 403, RGW's convention) when, at any level,
`used_bytes + counted + this write > limit_bytes`. `counted` is what this replica accepted
since that level's `collected_at`. The refusal is an ordinary decision record whose reason
carries the figures; the client is told only which level is full. A quota the bundle states
but the gateway cannot read refuses the writes it covers (`AccessDenied`), and a write of
unstated size under a quota is refused `MissingContentLength`; both answer a fixed sentence,
since the record's reason names the tenant or backend and the bundle's defect. A caller the
policy refuses is refused as before and learns nothing about any quota.

What a write is charged:

| Operation | Bytes |
|---|---|
| `PutObject`, `UploadPart` | the `Content-Length` forwarded (s3s sets it to the decoded length of an `aws-chunked` body). A write with none is refused `MissingContentLength` (411) where a quota applies |
| `PostObject` | the size of the file s3s aggregated |
| `CopyObject`, `UploadPartCopy` | the length of `x-amz-copy-source-range`, or else the source's size from one `HeadObject` on the backend, asked only where a quota applies and only after both halves of the copy were allowed |
| `CompleteMultipartUpload` | zero, since its parts were charged as they arrived; still a write, so it is refused once a level is already over its limit |
| `CreateMultipartUpload`, deletes, tagging | nothing |

**The count.** One ledger per process, per level, in memory:

- A write is **in flight** from its admission until the backend answers. The check and the
  reservation are one step under one lock, at every level at once, so two writers on one
  replica can never both take the last bytes of a limit.
- The forward path settles it: kept when the backend accepted it, given back when the backend
  refused it with a 4xx. When the outcome is unknown it is kept only if the write may have
  been stored: the request was dispatched to the backend (marked right before the call) and
  its client body, for `PutObject` and `UploadPart`, was delivered whole, without an error.
  A request dropped before dispatch (refused by s3s after the access hook, a client gone
  first) and a body that failed or stopped short give their bytes back, since an S3 write
  stores nothing without its whole body; otherwise a client could declare the remaining
  quota, hang up, and block the level for every writer until the next collection. A 5xx or
  a timeout once the body was sent stays counted.
- A kept write is stamped with the time it completed, in one-second slots, at most 256 per
  level; past that the two oldest merge under the later stamp, which only ever keeps bytes
  counted longer.
- A bundle whose `collected_at` for a level is newer than the one the level is counted
  against becomes its basis: its `used_bytes` replaces the old figure, and the slots that
  completed at or before it are dropped. In-flight writes are never dropped, and an older
  `collected_at` (a request still pinned to the previous revision) never moves the basis back.
- A quota the bundle states but the gateway cannot read refuses the writes it covers
  (`AccessDenied`, naming the defect) and leaves reads alone; it is logged at `error` on load.

**Per replica (the v1 answer).** Counters are not shared between replicas. Each replica
refuses only what *it* would take past a limit, so N replicas together can overshoot a limit
by what the other N − 1 accepted between two collections. That is accepted for v1: the
overshoot is bounded by write volume over one collection interval, the next collection
brings every replica's basis back to what the backend holds, and a backend's own per-bucket
limit, where it has one, remains a hard backstop at the bucket level.

**What `collected_at` means.** Every write that completed at or before `collected_at` is in
`used_bytes`. For a measurement that takes time (a listing), that is the time it started: a
later stamp hides the writes that completed while it ran, and the gateway would drop them
from its count. The comparison is between the collector's clock and the gateway's, so skew
between the two shifts the window by the skew.

## Alternatives considered

- **Shared counters** (a coordination store, or replicas exchanging counts). Exact across
  replicas, but a stateful dependency on the path of every write, with no good answer when it
  is down: failing closed refuses all writes, failing open is no quota. Not for v1.
- **Enforce on `used_bytes` alone.** The overshoot is bounded only by write throughput times
  the collection interval, per client. Rejected.
- **Reset the counter to zero when a collection arrives.** On a single replica it forgets
  every write accepted between the measurement and the bundle's arrival. Rejected for the
  completion-stamped count above.
- **Count on admission and never give back.** A write the backend refused would count until
  the next collection. Kept only where the outcome is unknown and the write may have landed.
- **Keep every write whose outcome is unknown.** Free for an attacker: a declared
  `Content-Length` equal to the remaining quota and a closed connection would hold the
  level full, org-wide on a backend quota, until each next collection. Rejected for
  tracking dispatch and body delivery.
- **Refuse copies under a quota**, since their size is not in the request. That breaks every
  client that copies server-side. Rejected for sizing the source with one `HeadObject`.

## Consequences

- On a backend with quotas, a copy without a range costs one extra `HeadObject`. If it fails
  the copy is refused, answered as the copy would have been (`NoSuchKey`, `AccessDenied`,
  otherwise the re-minted backend error) under the refusal record's decision id.
- Overwrites and deletes are not subtracted between collections: a tenant near its limit can
  be refused a write that would not have grown its usage, until the next collection.
- A restarted replica forgets what it accepted before the restart; until the next collection
  its own earlier writes count toward the overshoot the way another replica's do.
- Memory is bounded per level, and a level that no longer has a limit, or holds nothing, is
  forgotten the first time a write is charged under a newer revision.
- s3s does not hold an `aws-chunked` body to its declared `x-amz-decoded-content-length`
  (see `docs/substrate-api.md`, Traps). The count is the declared length, which is also the
  `Content-Length` the gateway frames its upstream request with.
