# ADR-007: Response obligations — bucket visibility, gateway-owned listing order, and the empty answer

- **Status**: Proposed
- **Date**: 2026-07-28
- **Owners**: gateway team (this repository); the `visible_buckets` derivation in the projected bundle is control-plane integration (out of scope here)
- **Related**: `src/proxy/obligations.rs`, `src/proxy/bucketfilter.rs`, `src/access/mod.rs` (`list_buckets`), `src/authz/decision.rs`; ADR-004 (list narrowing and the fan-out cursor), ADR-002 (audit record shape), ADR-006 (grant projection)
- **Scope**: Establishes the channel by which an authorization decision restricts a **response**, and settles the three questions `ListBuckets` forces: what the empty answer looks like, who owns the ordering and the cursor, and what happens when a policy says nothing.

---

## Context

Every enforcement in this gateway so far acts on a **request**: refuse it, rewrite its
prefix, drop the multi-delete keys the PDP denied. `ListBuckets` cannot be enforced that
way, and the reason is structural rather than incidental.

The forward is re-signed with the per-`(backend, tenant)` **owner** credential
(`proxy::build_proxy`) — that is the whole architecture: the caller's identity is
authorized at the gateway, and the backend leg carries a single tenant-scoped credential.
So the backend answers `ListBuckets` with the tenant's **entire** bucket namespace, for
every principal, always. There is no request parameter that narrows it to what the caller
was granted. The restriction has to be applied to the answer.

ADR-004 weighed response filtering for `ListObjects` and **rejected** it, on the grounds
that filtering post-hoc breaks `ContinuationToken`/`IsTruncated`/`MaxKeys` and that the
filtering implementation then owns re-pagination — while prefix rewriting achieves the
same restriction with none of that. That reasoning holds and is not reopened. It simply
does not apply here: there is no `ListBuckets` request parameter to rewrite, so the choice
is between filtering the response and not enforcing at all. This ADR therefore accepts the
re-pagination burden ADR-004 identified, and discharges it explicitly below rather than
leaving it implied.

That makes `ListBuckets` the first place the gateway withholds information the backend
already returned, and three sub-problems fall out of it.

**1. Filtering destroys the backend's pagination.** `max-buckets` and
`continuation-token` describe offsets in the backend's sequence. Remove entries and those
offsets stop describing the client's sequence: a page of 1000 comes back with 3 visible
buckets and a token pointing into a list the client cannot see.

**2. Resuming by name assumes an order nobody promised.** The obvious cursor — "skip
while `name <= last_name`" — is correct only if the backend returns buckets in a stable
ascending order across pages. The S3 API documents no such guarantee for `ListBuckets`,
and it is **unverified for RGW**, whose bucket listing comes off the user's bucket index
rather than a sorted key namespace. This is accepted review defect B-9.

**3. The empty answer is an oracle.** Two different principals end up with nothing to
show: one that may not enumerate at all, and one that may and holds no bucket grants. If
those produce different statuses — `403` and `200` — the status code answers "does this
credential hold `list_buckets` in this tenant?" for anyone who cares to ask. If they
produce the same status by different code paths, one contacting the backend and one not,
the same question is answerable with a stopwatch.

## Decision

### The obligation channel

Obligations are split by *when* they can be applied, and the second kind gets a carrier.

A **request obligation** is applied by the typed hook on the parsed input before anything
is forwarded (`narrow_prefix`, multi-delete key filtering). A **response obligation**
cannot be: the thing to be restricted does not exist when the decision is made. It travels
from the hook to `GatewayS3` in a single `Arc<ResponseObligations>` request extension,
which subsumes the ad-hoc `Arc<ListFanout>` extension ADR-004 introduced.

One extension type, not one per obligation, so that "did the hook impose anything on this
response?" has exactly one place to look.

**Absence is not permission.** Only an access hook installs the value, so its absence
means no decision was applied — and `GatewayS3::list_buckets` refuses outright rather
than forwarding. This is the `AuthzProof` argument transposed to a response transform:
for this operation, forwarding *is* the leak, so the proof alone is not enough.

### `Obligations` gains `visible_buckets`, `all_buckets_visible`, `must_understand`

`visible_buckets` is a set of exact bucket **names** — not prefixes, not patterns.
`bucket_patterns` from the master plan is deliberately **not** implemented: there is no
settled pattern grammar, and an unvalidated glob in a visibility allowlist widens rather
than narrows. Under `deny_unknown_fields` a policy emitting it therefore denies, which is
the correct behavior for an obligation the PEP cannot apply.

**The empty case is the opposite of `allowed_prefixes`'.** Empty `allowed_prefixes` means
"unscoped within what was already allowed"; empty `visible_buckets` means **nothing is
visible**. The asymmetry is the point: a policy that forgot to say anything about bucket
visibility must not thereby publish the tenant's namespace. `all_buckets_visible` is the
only unfiltered path and a rego author has to type it out; setting it alongside a
non-empty `visible_buckets` is a denial rather than a guess about which was meant.

`must_understand` closes the skew `deny_unknown_fields` cannot. That guard fires when the
*field* is unknown to an older binary. It says nothing about a policy that needs an
obligation actually applied while some replicas are older. `must_understand` names what
must be honored, and a name outside the implemented set is a denial — so a premature push
is a loud, uniform refusal rather than silent partial enforcement across a fleet.

**This is a rollout ordering constraint on the control plane, not an implementation
detail:** a policy emitting `visible_buckets` denies every request it touches on a binary
built before the field existed. The binary ships first, always.

### The listing is gateway-ordered and gateway-paginated

Rather than assume an ordering RGW does not promise, the gateway drains the backend's
bucket list, intersects it with the visibility set, sorts by name, and cuts its own page.
The cursor is the existing `fanout::Cursor`, bound by `scope_hash` to the visibility scope
it was issued under, so a grant change mid-listing is a loud `InvalidArgument` rather than
a silently re-based page (ADR-004's rule, unchanged).

Stated plainly, because it is a visible behavior change and not an internal one: **the
order of a `ListBuckets` response from this gateway is the gateway's, not the backend's.**
It is a plain lexicographic sort of the names, so it is identical across replicas.

The client's `max-buckets` is clamped to `limits.max_buckets_per_page` rather than
honored — the page boundaries belong to the gateway now. The drain is bounded by
`limits.max_bucket_list_pages`, and a tenant that exceeds it is **refused** rather than
under-reported: an authorization-filtered listing that quietly omitted buckets is
indistinguishable from a revoked grant, which is the one failure a caller cannot debug.

### The empty answer is an empty listing, at one cost

A `ListBuckets` the caller may not make returns `200` with an empty `<Buckets/>`, not
`403` — and so does an allowed one with nothing visible. Both go through the **same
branch**, and neither contacts the backend, so they are indistinguishable in status, in
body, and in latency.

This is not a weakening of deny-by-default. The default with no obligation is *nothing
visible*; a bucket becomes visible only by being named. What changed is the shape of the
refusal, not its strictness. The distinction between the two cases is preserved exactly
where it belongs — the audit record says `Denied` for one and `Allowed` for the other —
and the hook mints no `AuthzProof` on the denied path, because nothing is fetched.

### Owner and Initiator are withheld

`ListBuckets` returns `Owner`; `ListMultipartUploads` and `ListParts` return `Owner` and
`Initiator`. Under this gateway all three name the **shared tenant-owner credential** the
forward was re-signed as — the same value for every principal in the tenant, and never the
principal who actually created the object or upload. They are dropped rather than
forwarded or remapped: forwarding publishes the backend identity the re-signing design
exists to keep off the wire, and substituting the caller would invent a canonical user id
the backend never issued.

`ListMultipartUploads` additionally re-applies the request's (already narrowed) prefix to
the returned uploads. The hook narrows `prefix` to a granted scope and the backend is
expected to honor it, but that is not something the gateway can observe — and the keys of
in-flight uploads are exactly what a prefix-scoped principal must not see. `ListParts`
keeps its parts: the caller holds `read_objects` on that key, and part sizes and ETags
describe an object it may read outright. Over-filtering a response breaks multipart
clients for no security gain.

## Alternatives considered

**Forward `ListBuckets` unfiltered.** Publishes the tenant's whole bucket namespace to
anyone holding one grant. This is the status quo the decision exists to end.

**Answer `403` when the visible set is empty.** Simpler, consistent with every other op,
and it turns the status code into a probe for `list_buckets` membership. Rejected.

**Trust the backend's order and resume by name.** Cheaper — no drain, no sort, constant
memory. Correct only under an ordering guarantee RGW does not give (B-9). Rejected;
revisit if RGW's ordering is ever established, in which case the drain becomes an
optimization to remove rather than a correctness property to restore.

**`bucket_patterns` as a glob.** Fewer bundle bytes for a wildcard-shaped grant. Rejected
for v1: pattern semantics are an authorization surface, and getting `*` subtly wrong in an
allowlist over-shares silently.

**Per-bucket `HeadBucket` instead of a drain.** Avoids reading the namespace, but costs N
round trips and loses `creation_date`. Rejected.

## Consequences

**Accepted:**

- One `ListBuckets` reads the tenant's whole bucket list. Bucket counts are per tenant,
  not per object — tens to hundreds in the target deployments — and the bound is explicit
  and configurable.
- Response order changes for any client that (incorrectly) depended on RGW's order.
- Bucket listings no longer carry `Owner`; multipart listings no longer carry
  `Owner`/`Initiator`. Clients that display them will show nothing there.
- A wildcard-granted subject with even one denylist entry anywhere in the tenant loses the
  unrestricted view and sees only its explicitly-named grants. The bundle cannot enumerate
  the tenant's buckets, so "all except these" is not expressible; the fallback is
  conservative in the safe direction and is recorded as such.

**Residual, not solved here:**

- Visibility in the shipped default module is derived as "every bucket the subject holds
  any grant on", gated on holding `list_buckets` somewhere. The authoritative derivation —
  including subtraction of deny grants — belongs to the projection (master plan §2.4) and
  arrives with it.
- A bucket created between two pages of a client's walk appears or not according to its
  position in the gateway's sort, not according to when it was created. This is inherent
  to any name-ordered cursor and is not a new property.
