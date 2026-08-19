# ADR-004: ListObjects narrowing — single-prefix rewrite and bounded multi-prefix fan-out with a gateway-owned cursor

- **Status**: Accepted — implemented (src/proxy/fanout.rs)
- **Date**: 2026-07-15
- **Owners**: gateway team (this repository); grant projection, grant-authoring lint, and corpus adoption are control-plane integration (out of scope for this repository)
- **Related**: `policy/gateway/authz.rego`; `src/authz/input.rs`; `src/authz/decision.rs`; ADR-001 (corpus / drift control), ADR-002 (audit record shape)
- **Scope**: Multi-prefix list handling — fan-out versus response filtering — and the ContinuationToken/IsTruncated/MaxKeys semantics the gateway owns when it narrows a listing. It does not reopen the settled invariants or the engines-through-gateway posture; engine listings traverse the same path as every other consumer's.

---

> **The unbounded case is a DENY, not a narrowing.** A list naming no prefix (or `prefix=`)
> is refused unless the principal holds a whole-bucket grant. AWS denies the same request
> (`s3:ListBucket` under an `s3:prefix` condition), and a narrowed listing is a filtered
> view returned with no signal that it is filtered, so `aws s3 ls s3://bucket/` would be
> read as the bucket's contents. Narrowing (D2) and bounded fan-out (D3/D4) apply to a
> request naming a prefix WIDER than the grants that overlaps them, which is the shape that
> reaches them; the obligation types, the cursor, the pagination semantics and every
> invariant below are unaffected. See `policy/gateway/authz.rego::narrowed`.

## Context

A prefix-scoped subject must not enumerate the whole bucket. Object keys are data — they
can embed identifiers (ADR-002 R7) — so enumeration is disclosure, not harmless metadata,
which is why the premise is *must not* enumerate rather than *should not*.

Three cases must be decided, not left to the implementer:

- **Single prefix grant** → rewrite `input.prefix`. Cheap, correct, transparent.
- **Multiple prefix grants** → cannot be expressed as one S3 `prefix` param. Either fan out
  and merge, or filter the response DTO. Both are only possible because the gateway is on
  the parsed path.
- **Fail closed** if neither is implemented for the case at hand.

This is decidable only because of the gateway's shape: it is an S3 API re-issuer with a
policy gate in the middle, so the decision and the forwarded request derive from the same
parsed input. Narrowing a listing means mutating or synthesizing typed DTOs; a byte proxy
could do neither, and forwarding a request unparsed is never an escape hatch here.

### What the PDP side already provides

`policy/gateway/authz.rego` computes `narrowed(p, req)` — the more specific of (grant
prefix, requested prefix) per overlapping grant, undefined for disjoint pairs — collects
the effective scopes in `scoped_prefixes` / `scoped_arr`, and denies when nothing overlaps.
`list_obligations` emits `{}` (whole-bucket, or the single scope equals the request),
`{"narrow_prefix": p}`, or `{"allowed_prefixes": [...]}`. The PDP emits *intent*; ordering,
normalization and pagination are PEP-owned by design, which is what keeps the dual-engine
parity gate order-insensitive.

The verdict type is `src/authz/decision.rs::Obligations { narrow_prefix, allowed_prefixes }`;
the input contract is `src/authz/input.rs::OpaInput.prefix`. Audit needs no new fields: one
record per list *request* (each page is a request), with `result.obligations` exposing the
rewrite the PEP applied, so the trail shows what was actually enumerated (ADR-002 D1/D4).
The golden corpus already covers `narrow_prefix` / `allowed_prefixes` cases, compared
order-insensitively (ADR-001 Gate A).

### What the host S3 framework provides

Typed hooks run post-deserialization with `&mut S3Request<Input>`, so `prefix`,
`start_after`, `continuation_token` and `delimiter` are `Option<String>` assignable in
place. `S3Request.extensions` is the sanctioned channel for handing per-request state from
the typed hook to the `S3` impl, and the access hook and dispatch impl move the *same*
request value, which is how request/decision correspondence holds by construction.
`s3s_aws::Proxy` wraps one `aws_sdk_s3::Client` that is cheap to clone. regorus has no
`crypto.*` builtins, so anything cryptographic (the cursor token) must live in the PEP or
the parity gate is unsatisfiable.

The pagination surface this ADR must keep truthful: `ListObjectsV2Input` carries
`continuation_token` / `delimiter` / `encoding_type` / `fetch_owner` / `max_keys` /
`prefix` / `start_after`; `ListObjectsV2Output` carries `next_continuation_token`,
`is_truncated`, `key_count`, `contents`, `common_prefixes` plus the echoed request
parameters. In v1, `marker` is the cursor and `next_marker` is only populated when a
`delimiter` is set.

### Sequencing constraint

Multi-prefix subjects arise from the union of subject and group grants, which the control
plane's grant projection emits. Until it lands no production principal holds any prefix
grant, so the rollout order in D6 tracks reality rather than mere prudence.

---

## Decision

### D1 — One mechanism, three tiers; fail closed on any unimplemented tier

Narrowing is one mechanism with three execution tiers, selected by the PDP's obligation
(`policy/gateway/authz.rego::list_obligations`):

| Effective scopes for the request | Obligation | PEP execution |
|---|---|---|
| Whole-bucket grant, or one scope equal to the requested prefix | `{}` | Forward unchanged |
| Exactly one scope, ≠ requested prefix | `narrow_prefix` | **D2**: in-place `input.prefix` rewrite in the `&mut` typed hook |
| More than one scope | `allowed_prefixes` | **D3/D4**: bounded fan-out-and-merge with a gateway-owned cursor |
| Zero overlapping scopes | — (deny) | Already denied by rego (`grant_matches` fails) |

**Response filtering is rejected** for the multi-prefix case (A1: the
ContinuationToken/IsTruncated/MaxKeys problem is structural, not fixable). Fan-out is the
choice, and the degenerate case matters: **single-prefix rewrite *is* fan-out with N=1**.
The architecture is one design; D2 is its fast path.

**Fail-closed floor** (missing data ⇒ deny): whenever the PEP receives an obligation it
cannot execute — `allowed_prefixes` before the executor ships, or a scope count above the
D3 bound — it **denies**. There is no "forward as requested" fallback anywhere on this path.

### D2 — Single prefix: rewrite `input.prefix` in the typed `&mut` hook (ship first)

- The `S3Access::list_objects_v2` / `list_objects` hooks build the OPA input, get the
  verdict, and on `obligations.narrow_prefix = p` set `req.input.prefix = Some(p)` before
  returning `Ok(())`.
- `continuation_token` / `start_after` (v2) and `marker` (v1) pass through untouched: they
  are *positions inside the narrowed listing*, and the narrowing is re-derived from policy
  on every page. Scope is never derived from the cursor (D5-I1), so a stale or foreign
  cursor can at worst mis-position, never widen, the view — live revocation holds
  mid-pagination.
- Pagination correctness is inherited from the backend: one backend listing, whose own
  `next_continuation_token` / `is_truncated` / `key_count` are truthful for the narrowed
  scope. Nothing to re-paginate — this is why rewrite is preferred.
- The dispatch layer restores the *echoed* `prefix` in the output to the client's requested
  value; what was actually enumerated is recorded in `result.obligations`.

### D3 — Multiple prefixes: bounded fan-out-and-merge in the dispatching `impl S3`

A fan-out cannot run in the access hook (it returns `S3Result<()>` and can only mutate one
input or deny). Placement:

1. The typed hook, on `allowed_prefixes`, inserts a `ListScope { requested, normalized }`
   into `req.extensions` and returns `Ok(())`.
2. The dispatching `impl S3` in front of `s3s_aws::Proxy` intercepts the list ops when the
   extension is present and runs the **executor** against a clone of the pooled
   per-`(backend, tenant)` client; otherwise it delegates 1:1. Every backend request the
   executor issues is synthesized from the same typed, decided value, and every issued
   `prefix` is an element of the decided scope set (executor invariant E1, pinned by test).

**Normalization (PEP-owned):** the rego emits the raw overlap set, which can legitimately
contain contained pairs (grants `a/` and `a/b/` both applicable). The executor computes:

```
normalize(S):
    sort S ascending by byte order; drop duplicates
    keep p only if no previously kept q is a byte-prefix of p
→ P₀ < P₁ < … < Pₙ₋₁, pairwise non-containing
```

**Order lemma (why "merge" is concatenation, not a re-sort).** The keyspace of prefix `p` is
the interval `[p, succ(p))` in byte order, where `succ(p)` strips trailing `0xFF` bytes and
increments the last remaining byte (all-`0xFF` ⇒ +∞ sentinel, never skip). For two
non-containing prefixes `p < q`, every key under `p` sorts before every key under `q`. After
normalization the intervals are pairwise disjoint and totally ordered, so the authorized
listing is exactly the **concatenation of the per-prefix listings in normalized order** — no
k-way merge, no re-sort, no duplicates. This is what makes the D4 cursor a two-field token
instead of a merge-state snapshot.

**Delimiter synthesis** (required in the same change — `aws s3 ls` always sends
`delimiter=/`). With delimiter `D` and requested prefix `R`, a grant deeper than the current
"directory" must surface as a rolled-up CommonPrefix, exactly as a native listing would:

- For each normalized `Pᵢ`: if `Pᵢ[len(R)..]` contains `D`, do **not** list `Pᵢ`; its
  candidate entry is the synthetic CommonPrefix `R + (segment of Pᵢ up to and including the
  first D)`. Group consecutive `Pᵢ` sharing a candidate; emit the CommonPrefix iff an
  existence probe (LIST `prefix=Pᵢ`, `max_keys=1`, within the group) finds ≥ 1 key — probes
  stay inside granted scopes, never on the synthetic prefix itself.
- Otherwise `Pᵢ` lies directly in directory `R`: fan-out LIST with `prefix=Pᵢ`,
  `delimiter=D` passed through.
- The recursion terminates into D2/pass-through: drilling into a synthesized CommonPrefix
  eventually makes the requested prefix equal or extend a grant.

Example: grants `{a/b/, a/c/}`, request `R=""`, `D="/"` → one probed synthetic CommonPrefix
`a/`, zero content listings — what a native root listing shows, with no leak of sibling keys
outside the grants.

**Bound, fail closed above it.** Config `list_fanout_max_prefixes` (default **16**). Above
it the PEP denies with `"deny: list fan-out bound exceeded (N > 16); narrow the request
prefix"` — a PEP-composed verdict override, following the ADR-002 D4 precedent, which leaves
the parity gate unaffected (it compares raw per-question engine outputs). Without a bound a
hostile client makes the gateway issue arbitrary *backend* work: a page crossing all
prefixes costs up to `n` LISTs plus up to `n` probes, so at n=16 that is ≤ 32 backend RTTs
per page. The deny is actionable because `scoped_arr` is computed against the *requested*
prefix, so a narrower prefix shrinks `n`, and the message says so.

### D4 — The gateway-owned merged cursor

**Why gateway-owned:** the backend's `next_continuation_token` is a position inside *one*
per-prefix listing; the client-visible listing spans `n` of them, so something must carry
"(which prefix, where inside it)" across pages. It cannot be server-side state — a cursor
table would break the property that any instance can serve any page. So the cursor is a
**self-contained, sealed, client-held token** carrying **position only, never authority**.

**Resume by key, not by embedded backend token.** The position is a single S3 key, resumed
via `start_after` (v2) / `marker` (v1) — plain S3 API surface, the only safe assumption for
a backend-agnostic gateway. AWS-style continuation tokens are themselves obfuscated key
positions, so this is the same seek the backend would do.

**Token contents and sealing** (PEP-side Rust; token crypto must not touch rego):

```
token := base64url( AEAD_seal( gateway_key, {
    v:          1,                                # schema version
    scope_hash: H(tenant, backend_id, bucket, R, D, P₀‥Pₙ₋₁),   # normalized, ordered
    resume_key: last emitted Contents key
                | succ(last emitted CommonPrefix)               # CP-successor rule
} ) )
```

The **CP-successor rule** is load-bearing: if a page ends on CommonPrefix `a/b/x/`, resuming
with `start_after = "a/b/x/"` would re-emit it, because keys under it sort *after* the CP
string. Resuming with `succ("a/b/x/") = "a/b/x0"` skips the rolled-up subtree, which is what
the backend's own token does internally.

**Page algorithm** (v2 shown; v1 is identical with `marker` in place of token/`start_after`
and needs **no gateway token at all** — its cursor is already a plain key supplied by the
client, and `next_marker` is emitted only when a delimiter is set):

```
serve_page(client: {R, D?, M, token?, start_after?}):
 1. PDP decision for THIS page request (one decision + one audit record per page —
    ADR-002 D4). Deny ⇒ done.
 2. P = normalize(obligations.allowed_prefixes); n = |P|
    n > list_fanout_max_prefixes ⇒ deny (D3). n == 1 ⇒ D2 path. n == 0 ⇒ unreachable (rego denied).
 3. resume key k:
      token present   ⇒ unseal; require known v AND scope_hash == H(recomputed from step 2)
                        else reject InvalidArgument (fail closed — client restarts listing)
                        k = token.resume_key            # token wins over start_after (AWS rule)
      else start_after present ⇒ k = start_after
      else k = ⊥
 4. budget = M (validated into the AWS domain, ≤ 1000, before fan-out);
    out = []; i = smallest index with succ(Pᵢ) > k   (i = 0 if k = ⊥)
 5. while budget > 0 and i < n:
      if D set and Pᵢ extends beyond the first D after R:
          synthesize CommonPrefix for the group at i (existence-probed, D3);
          if emitted and CP > k: out += CP; budget -= 1
          i = index past the group; continue
      resp = backend LIST(bucket, prefix=Pᵢ, delimiter=D, start_after=k if k≠⊥,
                          max_keys=budget, encoding/fetch_owner/… passed through)
      out += resp.contents, resp.common_prefixes; budget -= |entries(resp)|
      if resp.is_truncated: k = resume_key(last entry of resp)   # stay on Pᵢ
      else: i += 1                                               # Pᵢ exhausted
 6. is_truncated := (last resp was truncated) or (i < n)
    # may yield one legal empty terminal page when all remaining prefixes are empty
 7. if is_truncated: next_continuation_token = seal(v, scope_hash, resume_key(last emitted entry))
 8. respond: contents / common_prefixes = out (order lemma ⇒ already globally sorted),
    key_count = |out|, is_truncated, next_continuation_token,
    echoed prefix=R, delimiter=D, max_keys=M, start_after / continuation_token
    as sent by the client
```

**Correctness ledger — every pagination field, and who makes it truthful under fan-out:**

| Output field | Fan-out semantics |
|---|---|
| `contents` / `common_prefixes` | Concatenation in normalized prefix order (order lemma) + probed synthetic CPs; globally sorted, duplicate-free by disjointness |
| `key_count` | Recomputed: emitted Contents + CommonPrefixes (both count against MaxKeys, AWS semantics) |
| `max_keys` | The client's value is the page **budget**; each backend call requests the *remaining* budget, so pages fill to `M` across prefix boundaries instead of collapsing |
| `is_truncated` | Step 6: true iff the current prefix is unexhausted or prefixes remain; never the backend's whole-bucket flag |
| `next_continuation_token` | The sealed gateway token (step 7); present iff truncated |
| echoed `prefix`/`delimiter`/`start_after`/`continuation_token` | The client's own request values |
| v1 `next_marker` | Last emitted entry, only when delimiter set (v1 rule); v1 resume is stateless from the client's `marker` via the step-4 skip rule |

**Revocation mid-listing:** every page re-runs the PDP and re-derives the scope set, and
`scope_hash` binds the token to that exact set. A grant change between pages ⇒ hash mismatch
⇒ token rejected ⇒ the client restarts under the new policy, so live revocation holds
*within* a paginated listing. A token replayed by a different principal carries no
authority: the decision is made for the presenting principal, and the hash only matches if
that principal's effective scope set is identical.

**Failure atomicity:** if any backend call in a page fails, the whole page fails; the audit
record carries `outcome = "error"` and the failing call's `backend_status`. No partial pages.

**Caching:** list decisions carry no on-demand data (tags are never populated for lists) and
`resource_key()` already includes the requested prefix, so the revision-keyed decision cache
applies to list verdicts and their obligations unchanged.

### D5 — Invariants this decision adds (testable, corpus-pinned)

- **I1 — Scope from decision only.** Cursors (gateway tokens, backend tokens on the D2 path,
  v1 markers, `start_after`) carry position, never scope. Every page's enumerable set is
  derived exclusively from that page's fresh PDP decision.
- **I2 — Containment (E1).** Every backend LIST the gateway issues on a narrowed path has
  `prefix` equal to a normalized element of the decided scope set (or a probe inside one).
- **I3 — No unnarrowed forward.** A request whose obligation the PEP cannot execute is
  denied, never forwarded as requested.
- **I4 — Token fail-closed.** Unknown version, failed AEAD open, or `scope_hash` mismatch ⇒
  reject the token; never "best effort" resume.
- **I5 — One record per page**, with `result.obligations` recording the scopes; PEP-composed
  denies are recorded like every other deny.

### D6 — Rollout order (the default, decided)

1. **Single-prefix first** (D2): the hook rewrite plus the `{}`-obligation pass-through,
   against hand-written bundles, with zero new pagination machinery.
2. **Multi-prefix fan-out second** (D3+D4): executor, delimiter synthesis, bound and cursor
   as one change, because `aws s3 ls` sends a delimiter and hits the synthesis path
   immediately. Sequencing tracks the control-plane grant projection.
3. **Interim behavior between 1 and 2**: `allowed_prefixes` ⇒ deny with the fixed reason
   `"deny: multi-prefix list not yet supported; narrow the request prefix"`.
4. `ListObjectVersions`, `ListMultipartUploads`, `ListParts` remain **off the allowlist**
   until each gets this same analysis — their cursors are multi-part
   (`key_marker`/`version_id_marker`, `upload_id_marker`) and this resume rule does not
   cover them.

---

## Alternatives considered

**A1 — Response filtering (list broad at the backend, drop unauthorized entries).**
Rejected; the pagination problem is structural.

- **MaxKeys**: a backend page of `M` filters to `k ≤ M`, so honoring the client's page size
  needs an unbounded loop that scans the *bucket's* keyspace to find the *grant's* keys —
  O(bucket), not O(granted), and a self-DoS lever a client can pull by listing broadly.
- **IsTruncated**: the backend's flag means "more keys in the bucket", not "more authorized
  keys"; the truthful flag needs unbounded look-ahead.
- **ContinuationToken**: the backend token points mid-bucket, so the gateway must wrap it in
  its own token anyway — filtering does not avoid the gateway-owned cursor, it adds the scan
  to it.
- **CommonPrefixes**: deciding which rolled-up CPs to drop re-implements grant-prefix
  intersection in the response path — a second copy of `narrowed()` to drift from, the exact
  failure class ADR-001's drift control exists to prevent.
- Confidentiality is weaker: the backend transfers unauthorized key names to the gateway on
  every page; fan-out never requests them.

**A2 — Deny all multi-prefix listings, permanently.** Rejected: denial breaks `aws s3 ls`
and every GUI, and multi-prefix subjects are a first-class outcome of the grant model (a
user in two groups holds two prefixes on day one). Denial survives only as the interim
(D6.3) and above-bound (D3) posture.

**A3 — Cursor embedding the backend's `next_continuation_token` per prefix.** Rejected: it
stores backend-opaque state with unspecified validity semantics in a client-held token, and
it is non-uniform (v1 has no token to embed, so two resume mechanisms would coexist).
Resume-by-key costs the same seek and works on v1, v2 and every S3-compatible backend.

**A4 — Server-side cursor state (token = ID into a gateway store).** Rejected: it adds
cross-instance shared state, breaks any-instance paging, and creates an eviction/leak
surface. The sealed token achieves the same with zero state.

**A5 — Parallel fan-out (issue all n LISTs concurrently, k-way merge).** Rejected as the
baseline, kept as a possible optimization behind the same contract. Sequential concatenation
is *lazy*: a page fully inside P₀ costs exactly one backend call, where parallel issue pays
n calls of wasted work and re-introduces merge state into the cursor.

**A6 — Forward unnarrowed and rely on per-object GET authorization.** Rejected by the
premise: key names are data (ADR-002 R7), enumeration is disclosure, and per-object gating
of reads does not un-disclose the namespace.

**A7 — Enforce the fan-out bound in rego.** Rejected: the bound is an execution-capacity
property of the PEP/deployment, not access intent, and putting it in policy would require
injecting deployment config into the bundle. The *authoring-time* guard against absurd grant
sets belongs in the control plane.

---

## Consequences

**What must hold for the security claim** ("a prefix-scoped subject cannot enumerate beyond
its grants, and every enumeration is decided and audited per page"):

1. Invariants D5-I1…I5 hold — in particular no unnarrowed forward (I3) and
   scope-from-decision-only (I1). I2 (containment) is the executor's testable core.
2. The typed hooks for both list ops ship together with the allowlist entry; an allowlisted
   list op without a narrowing hook is fail-open, because typed hooks default to `Ok(())`.
3. Token sealing keys are gateway-owned and per-site, shared across the site's instances so
   any instance can open any token; rotation uses a two-key acceptance window, and an
   unopenable token is a clean fail-closed restart, never an error loop.
4. Per-page decisions are actually per-page: the decision-cache key includes the requested
   prefix, so a cached verdict is only reused for an identical question at the same bundle
   revision.

**Risks / accepted costs:**

- **Latency**: a fan-out page is multi-RTT by construction (≤ n LISTs + ≤ n probes, bounded
  at 32 by default). The list path gets its own benchmark and CI perf gate; the bound is the
  knob.
- **One legal-but-odd empty terminal page** when all remaining prefixes are empty. AWS
  clients tolerate empty final pages; conformance tests plus `aws s3 ls`/rclone/boto3 smoke
  tests must confirm before GA.
- **Synthetic-CP divergence**: existence probes make synthesized CommonPrefixes match native
  semantics (only non-empty directories appear) at the cost of ≤ n probe calls. We pay the
  probes; without them, empty "directories" appear.
- **Token size**: sealed resume keys can approach ~1.4 KB (key length ≤ 1024 bytes) — larger
  than AWS tokens but opaque per the S3 contract; the header/URI caps the gateway owns must
  admit it.
- **`encoding_type=url`**: the merge must operate on consistently decoded keys and encode
  exactly once in the merged output; pinned by a dedicated conformance test rather than
  assumed.
- **Behavior shift at the bound**: a subject accumulating a 17th prefix grant flips from
  fan-out to actionable deny. Mitigated at the source by the grant-authoring lint and by the
  deny message; the alternative (unbounded amplification) is worse.
- **Engine listings** traverse this same path, so listing storms from engines are part of
  capacity sizing, with the same bound protecting the backends.

**Follow-ups (this repository):**

- Property test: executor output ≡ reference model (filter of a full synthetic listing) over
  randomized keyspaces, grant sets, `max_keys`, delimiters and resume points — including the
  CP-successor rule and `succ()` carry/`0xFF` edges.
- Corpus: multi-prefix, overlap-normalization and delimiter-synthesis cases in
  `policy/testdata/corpus.json`, with `allowed_prefixes` compared order-insensitively.
- Metrics: fan-out width histogram, backend calls per page, token rejects (by cause) and
  above-bound denies — the last two page when sustained, since they indicate policy churn or
  client breakage.

---

## Control-plane integration (out of scope for this repository)

- **Grant projection** (`s3_grants` / `group_grants`): precondition for any production
  multi-prefix traffic. No new shape is needed — the grant contract in
  `policy/gateway/authz.rego` already carries `prefixes: [...]`.
- **Grant-authoring lint**: warn on, and require override to exceed,
  `list_fanout_max_prefixes` (default 16) effective prefix scopes per (subject ∪ groups,
  bucket, action); surface the deployed bound to authors.
- **Golden corpus**: adopt the multi-prefix and delimiter-synthesis obligation cases; the
  parity gate replays them through OPA and regorus.
- **No extractor change**: the ADR-002 record shape is unchanged — `result.obligations`
  already carries `narrow_prefix`/`allowed_prefixes`.
- **Client-facing docs**: listings are scope-narrowed; continuation tokens are opaque and may
  exceed AWS's typical size; token invalidation on policy change means "restart the listing";
  above-bound listings return an actionable deny asking for a narrower prefix.
