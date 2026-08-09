# ADR-004: ListObjects narrowing — single-prefix rewrite and bounded multi-prefix fan-out with a gateway-owned cursor

- **Status**: Proposed
- **Date**: 2026-07-15
- **Owners**: gateway team (this repository); grant projection, grant-authoring lint, and corpus adoption are control-plane integration (out of scope for this repository)
- **Related**: `policy/gateway/authz.rego`; `src/authz/input.rs`; `src/authz/decision.rs`; ADR-001 (corpus / drift control), ADR-002 (audit record shape)
- **Scope**: Resolves the open question of multi-prefix list handling — fan-out versus response filtering — and fixes the ContinuationToken/IsTruncated/MaxKeys semantics the gateway owns when it narrows a listing. It does not reopen the settled invariants or the engines-through-gateway posture; engine listings traverse the same path as every other consumer's.

---

> **AMENDED 2026-08-09 — the motivating case is now a DENY, not a narrowing.** This ADR was
> written around "a prefix-scoped subject issuing `ListObjectsV2` with no `prefix`", and it
> chose to rewrite that request into the grant. That choice is reversed for the **unbounded**
> case only: a list naming no prefix (or `prefix=`) is refused unless the principal holds a
> whole-bucket grant. Two reasons, both recorded in `policy/gateway/authz.rego::narrowed` and
> in `s0-plan/AWS-PARITY.md`: (1) AWS denies it — `s3:ListBucket` + a `s3:prefix` condition
> fails when the request carries no prefix, and AWS does not narrow; (2) a narrowed listing
> is a filtered view returned with no signal that it is filtered, so `aws s3 ls s3://bucket/`
> is read as the bucket's contents. "Denying outright … breaks `aws s3 ls`" below was the
> reasoning; what it actually breaks is `aws s3 ls` *without a prefix*, and breaking it
> loudly is the point.
>
> **Everything else in this ADR stands unchanged.** Narrowing (D2) and bounded fan-out
> (D3/D4) still apply to a request that names a prefix WIDER than the grant(s) and overlaps
> them, which is now the shape that reaches them; the obligation types, the cursor, the
> pagination semantics, the fail-closed floor and every invariant are untouched. Hyperfluid's
> pushed `s3.rego` — the module production actually evaluates — already denied the unbounded
> case; this amendment records that s0's compiled-in default was brought into line with it.

## Context

The problem and the shape of its solution space:

A prefix-scoped subject issuing `ListObjectsV2` with no `prefix` must not enumerate the whole
bucket. Denying outright is safe but breaks `aws s3 ls` and every GUI. Because the typed hook
receives `&mut S3Request<Input>`, the preferred move is to **rewrite `input.prefix`** to the
granted scope before forwarding. *(Amended 2026-08-09 — see the note above: the unbounded
case is denied. The rewrite survives for an over-broad but overlapping prefix.)*

Three cases must be decided, not left to the implementer:

- **Single prefix grant** → rewrite `input.prefix`. Cheap, correct, transparent.
- **Multiple prefix grants** → cannot be expressed as one S3 `prefix` param. Either fan out
  and merge, or filter the response DTO. Both are only possible because the gateway is on the
  parsed path. Pick one.
- **Fail closed** if neither is implemented for the case at hand.

Response filtering carries a ContinuationToken/IsTruncated/MaxKeys correctness problem:
filtering post-hoc breaks page sizes and the truncation flag, so a filtering implementation
owns re-pagination. Rewrite is preferred.

This is only decidable because of the gateway's shape: it is an S3 API re-issuer with a policy
gate in the middle, so the decision and the forwarded request derive from the same parsed
input — forwarding a request unparsed is never an escape hatch in this design. Narrowing a
listing means mutating or synthesizing typed DTOs; a byte proxy could do neither
(`src/authz/decision.rs` says exactly this about `Obligations`).

The disclosure at stake is real: object keys are data. In some deployments keys embed
identifiers (ADR-002 R7 gives examples where object keys carry sensitive path components), so
an over-broad LIST is not "harmless metadata" — enumeration is disclosure, which is why the
premise is *must not* enumerate, not *should not*.

### What exists vs what is planned

**Implemented (this repository):**

- **The PDP side of narrowing is fully implemented** in `policy/gateway/authz.rego`:
  - `narrowed(p, req)` computes, per overlapping prefix grant, "the more specific of (grant
    prefix, requested prefix)"; disjoint pairs are undefined (no overlap ⇒ not in scope).
  - `scoped_prefixes` / `scoped_arr` collect the effective scopes for the request;
    `grant_matches` for `list_objects` holds iff a whole-bucket grant applies
    (`whole_bucket_list`) or `count(scoped_arr) > 0` — zero overlap denies
    ("deny: no grant matches action/scope").
  - `list_obligations` emits `{}` (no narrowing needed: whole-bucket, or the single scope
    equals the requested prefix), `{"narrow_prefix": p}` (exactly one effective scope,
    different from the request), or `{"allowed_prefixes": [...]}` (more than one).
  - The rego header notes "Ordering of `allowed_prefixes` is normalized in the PEP so the
    dual-engine parity gate is order-insensitive" — the PDP emits *intent*; execution
    (ordering, normalization, pagination) is PEP-owned by design.
- **The verdict types**: `src/authz/decision.rs::Obligations { narrow_prefix, allowed_prefixes }`,
  whose doc already states the open choice this ADR closes: "When more than one, a single S3
  `prefix` param cannot express them — the PEP fans out or filters."
- **The input contract**: `src/authz/input.rs::OpaInput.prefix` — "List prefix — present for
  `ListObjects*`. May be rewritten by an obligation."
- **Audit**: ADR-002 D1/D4 — one record per list *request* (each page is a request);
  `result.obligations` expose any list-narrowing rewrite the PEP applied, so the audit trail
  shows *what was actually enumerated*. No new audit fields are needed here.
- **The golden corpus** covers `narrow_prefix` / `allowed_prefixes` cases
  (`policy/testdata/corpus.json`; ADR-001 Gate A), compared order-insensitively.

**Implemented (host S3 framework — the `s3s` crate):**

- Typed hooks run post-deserialization with `&mut S3Request<{Op}Input>` — they can **mutate
  the input in place**, which is where key/prefix rewrites happen. For `ListObjectsV2`,
  `input.prefix` / `.start_after` / `.continuation_token` / `.delimiter` are `Option<String>`,
  assignable in place.
- The pagination surface this ADR must keep truthful:
  - `ListObjectsV2Input`: `bucket` (required), `continuation_token`, `delimiter`,
    `encoding_type`, `fetch_owner`, `max_keys: Option<i32>`, `prefix`, `start_after`, ….
  - `ListObjectsV2Output`: `next_continuation_token`, `is_truncated`, `key_count`,
    `contents`, `common_prefixes`, plus echoed `prefix`/`delimiter`/`start_after`/
    `continuation_token`.
  - `ListObjectsInput` (v1): `marker` is the cursor; output `next_marker` is only populated
    when a `delimiter` is set.
- `S3Request<T>` fields are all `pub`, including `extensions` — the sanctioned channel for
  handing per-request state from the typed hook to the `S3` impl. The access hook and the
  dispatch impl move the *same* request value (`access.<op>(&mut s3_req)` then
  `s3.<op>(s3_req)`), which is how request/decision correspondence holds by construction.
- `s3s_aws::Proxy` wraps exactly one private `aws_sdk_s3::Client`; the client is cheap to
  clone, so the client pool can hand the executor a clone of the same client it built the
  `Proxy` from.
- regorus has no `crypto.*` builtins, so anything cryptographic (the cursor token below) must
  live in the PEP, not in rego, or the dual-engine parity gate is unsatisfiable.

**Planned (this repository):** the `list_objects_v2` / `list_objects` typed hooks themselves,
the fan-out executor in the dispatching `impl S3` (`src/proxy/mod.rs`, the client-pool layer —
itself pending), and the cursor-token sealing and key management. This ADR specifies them.

**External (control plane):** the data-plane grant projection (`s3_grants` / `group_grants`).
Until it lands, **no production principal can hold any prefix grant at all** — multi-prefix
subjects arise precisely from the union of subject and group grants that projection will emit.
This is why the rollout order in D6 is aligned with reality, not just prudent: single-prefix
ships against hand-written bundles; multi-prefix traffic cannot exist before the control-plane
projection does.

---

## Decision

### D1 — One mechanism, three tiers; fail closed on any unimplemented tier

Narrowing is one mechanism with three execution tiers, selected by the PDP's obligation
(`policy/gateway/authz.rego::list_obligations` — already implemented):

| Effective scopes for the request | Obligation | PEP execution |
|---|---|---|
| Whole-bucket grant, or one scope equal to the requested prefix | `{}` | Forward unchanged |
| Exactly one scope, ≠ requested prefix | `narrow_prefix` | **D2**: in-place `input.prefix` rewrite in the `&mut` typed hook |
| More than one scope | `allowed_prefixes` | **D3/D4**: bounded fan-out-and-merge with a gateway-owned cursor |
| Zero overlapping scopes | — (deny) | Already denied by rego (`grant_matches` fails) |

**Response filtering is rejected** for the multi-prefix case (analysis in Alternatives A1 —
the ContinuationToken/IsTruncated/MaxKeys problem is structural, not fixable). Fan-out is the
choice, and note the degenerate case: **single-prefix rewrite *is* fan-out with N=1** — one
backend LIST whose prefix is the one effective scope, with the backend's own pagination
reused. The architecture is one design; D2 is its fast path.

**Fail-closed floor** (missing data ⇒ deny): whenever the PEP receives an obligation it cannot
execute — `allowed_prefixes` before the executor ships (D6), or a scope count above the D3
bound — it **denies**. An unnarrowed listing must never reach the backend for a prefix-scoped
subject, under any failure or staging condition. There is no "forward as requested" fallback
anywhere on this path.

### D2 — Single prefix: rewrite `input.prefix` in the typed `&mut` hook (ship first)

The preferred form — cheap, correct, transparent — on the seam built for it: the typed hook
takes `&mut S3Request<Input>` and it is mutable on purpose.

- The `S3Access::list_objects_v2` / `list_objects` hooks build the OPA input (`prefix` =
  requested prefix or absent, per `src/authz/input.rs`), get the verdict, and on
  `obligations.narrow_prefix = p` set `req.input.prefix = Some(p)` before returning `Ok(())` —
  the field is a plain `Option<String>`.
- `continuation_token` / `start_after` (v2) and `marker` (v1) pass through untouched: they are
  *positions inside the narrowed listing*, and the narrowing is re-derived from policy on
  every page request. Scope is never derived from the cursor (see D5-I1), so a stale or
  foreign cursor can at worst mis-position, never widen, the view — each page's disclosure is
  bounded by that page's fresh decision, so live revocation holds mid-pagination.
- Pagination correctness is inherited from the backend: one backend listing, its own
  `next_continuation_token`/`is_truncated`/`key_count` are truthful for the narrowed scope.
  Nothing to re-paginate — this is why rewrite is preferred.
- The dispatch layer restores the *echoed* `prefix` in the output to the client's requested
  value, so both D2 and D3 present the client's own request parameters back to it; what was
  actually enumerated is recorded in `result.obligations` (ADR-002 D1).

### D3 — Multiple prefixes: bounded fan-out-and-merge in the dispatching `impl S3`

A fan-out cannot run in the access hook (it returns `S3Result<()>` and can only mutate one
input or deny). Placement:

1. The typed hook, on `allowed_prefixes`, inserts a `ListScope { requested, normalized }`
   value into `req.extensions` (`S3Request.extensions` is `pub`) and returns `Ok(())`.
2. The dispatching `impl S3` in front of `s3s_aws::Proxy` (`src/proxy/mod.rs`, the client-pool
   layer) intercepts `list_objects_v2`/`list_objects` when the extension is present and runs
   the **executor** against a clone of the pooled per-`(backend, tenant)` `aws_sdk_s3::Client`
   (clones are cheap); otherwise it delegates 1:1 to the `Proxy`. Request/decision
   correspondence holds: every backend request the executor issues is synthesized from the
   same typed, decided value — no bytes are re-parsed, and every issued `prefix` is an element
   of the decided scope set (executor invariant E1, pinned by test).

**Normalization (PEP-owned, per the rego's own division of labor):** the rego emits the raw
overlap set — it can legitimately contain contained pairs (grants `a/` and `a/b/` both
applicable). The executor computes:

```
normalize(S):
    sort S ascending by byte order; drop duplicates
    keep p only if no previously kept q is a byte-prefix of p
→ P₀ < P₁ < … < Pₙ₋₁, pairwise non-containing
```

**Order lemma (why "merge" is concatenation, not a re-sort).** The keyspace of prefix `p` is
the interval `[p, succ(p))` in byte order, where `succ(p)` strips trailing `0xFF` bytes and
increments the last remaining byte (all-`0xFF` ⇒ +∞ sentinel, never skip). For two
non-containing prefixes `p < q`, they differ at some first byte, and every key under `p`
keeps that byte difference against every key under `q` — so **all keys under `p` sort before
all keys under `q`**. After normalization the intervals are pairwise disjoint and totally
ordered; therefore the authorized listing is exactly the **concatenation of the per-prefix
listings in normalized order**. S3 returns each per-prefix page already sorted, so the merged
stream is globally sorted with no k-way merge, no re-sort, and no duplicates. This is what
makes the cursor in D4 a two-field token instead of a merge-state snapshot.

**Delimiter synthesis (required in the same milestone — `aws s3 ls` always sends
`delimiter=/`, and GUI breakage is the stated motivation).** With delimiter `D` and requested
prefix `R`, a grant deeper than the current "directory" must surface as a rolled-up
CommonPrefix, exactly as a native listing would:

- For each normalized `Pᵢ`: if `Pᵢ[len(R)..]` contains `D`, do **not** list `Pᵢ`; its
  candidate entry is the synthetic CommonPrefix `R + (segment of Pᵢ up to and including the
  first D)`. Group consecutive `Pᵢ` sharing a candidate; emit the CommonPrefix iff an
  existence probe (LIST `prefix=Pᵢ`, `max_keys=1`, within the group) finds ≥ 1 key — probes
  stay inside granted scopes, never on the synthetic prefix itself.
- Otherwise `Pᵢ` lies directly in directory `R`: fan-out LIST with `prefix=Pᵢ`,
  `delimiter=D` passed through.
- The recursion terminates into D2/pass-through: drilling into a synthesized CommonPrefix
  eventually makes the requested prefix equal or extend a grant, where `list_obligations`
  yields `{}` or a single `narrow_prefix`.

Example: grants `{a/b/, a/c/}`, request `R=""`, `D="/"` → one probed synthetic CommonPrefix
`a/`, zero content listings — exactly what a native root listing shows, with no leak of
sibling keys outside the grants.

**Bound, fail closed above it.** Config `list_fanout_max_prefixes` (default **16**). If the
normalized scope count `n` exceeds it, the PEP denies with the PEP-composed reason
`"deny: list fan-out bound exceeded (N > 16); narrow the request prefix"` — PEP-composed
verdict overrides follow the ADR-002 D4 precedent (`Decision::deny`), and the parity gate is
unaffected (it compares raw per-question engine outputs). Rationale, parallel to the PDP's own
semantic caps (otherwise a hostile client makes the gateway issue arbitrary *backend* work): a
client page crossing all prefixes costs up to `n` LISTs plus up to `n` delimiter probes; at
n=16 that is ≤ 32 backend RTTs per page, a bounded ~10× amplification that fits a posture of
budgeted, benchmarked latency. The deny is actionable: `scoped_arr` is computed against the
*requested* prefix (`narrowed()`), so supplying a narrower prefix shrinks `n` — the error
message says so. Beyond 16 effective prefixes per (subject, bucket, action) the grant model is
being misused (that is group/whole-bucket territory), which a grant-authoring lint in the
control plane enforces at the source.

### D4 — The gateway-owned merged cursor

**Why gateway-owned:** the backend's `next_continuation_token` is a position inside *one*
per-prefix backend listing; the client-visible listing spans `n` of them. Something must
carry "(which prefix, where inside it)" across pages. It cannot be server-side state — the
gateway is stateless, and a cursor table would break exactly the mesh property (any instance
serves any page) that revision-keyed decisions already guarantee. So the cursor is a
**self-contained, sealed, client-held token**, and it carries **position only, never
authority**.

**Resume by key, not by embedded backend token.** The token's position is a single S3 key,
resumed via `start_after` (v2) / `marker` (v1) — plain S3 API surface, which is the only safe
assumption for a backend-agnostic gateway (assume nothing but the plain S3 API surface).
Embedding the backend's opaque token was considered and rejected (Alternatives A3). Cost
parity: AWS-style continuation tokens are themselves obfuscated key positions; resuming by
`start_after` is the same seek the backend would do.

**Token contents and sealing** (PEP-side Rust; regorus has no crypto builtins, so token crypto
must not touch rego, keeping the dual-engine parity gate satisfiable):

```
token := base64url( AEAD_seal( gateway_key, {
    v:          1,                                # schema version
    scope_hash: H(tenant, backend_id, bucket, R, D, P₀‥Pₙ₋₁),   # normalized, ordered
    resume_key: last emitted Contents key
                | succ(last emitted CommonPrefix)               # CP-successor rule
} ) )
```

The **CP-successor rule** is load-bearing: if a page ends on CommonPrefix `a/b/x/`, resuming
with `start_after = "a/b/x/"` would re-emit it (keys under it sort *after* the CP string).
Resuming with `succ("a/b/x/") = "a/b/x0"` skips the entire rolled-up subtree, which is what
the backend's own token does internally.

**Page algorithm** (v2 shown; v1 is identical with `marker` in place of token/`start_after`
and needs **no gateway token at all** — its cursor is already a plain key supplied by the
client, and `next_marker` is emitted per v1 semantics, i.e. only when a delimiter is set):

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
| `max_keys` | The client's value is the page **budget**; each backend call requests the *remaining* budget, so pages fill to `M` across prefix boundaries (fill-forward) instead of collapsing |
| `is_truncated` | Step 6: true iff the current prefix is unexhausted or prefixes remain; never the backend's whole-bucket flag |
| `next_continuation_token` | The sealed gateway token (step 7); present iff truncated |
| echoed `prefix`/`delimiter`/`start_after`/`continuation_token` | The client's own request values |
| v1 `next_marker` | Last emitted entry, only when delimiter set (v1 rule); v1 resume is stateless from the client's `marker` via the step-4 skip rule |

**Revocation mid-listing:** every page re-runs the PDP (step 1) and re-derives the scope set;
`scope_hash` binds the token to that exact set. A grant change between pages ⇒ hash mismatch
⇒ token rejected, fail closed, client restarts under the new policy. The live-revocation
property therefore holds *within* a paginated listing, not just between listings. A token
replayed by a different principal carries no authority: the decision is made for the
presenting principal, and the hash only matches if that principal's effective scope set is
identical — in which case the token reveals nothing they could not already list.

**Failure atomicity:** if any backend call in a page fails, the whole page fails (mapped per
the dispatch layer's error conventions); the audit record carries `outcome = "error"` and the
failing call's `backend_status` (ADR-002 D1). No partial pages.

**Caching:** list decisions carry no on-demand data (`OpaInput::has_on_demand_data` is false
— tags are never populated for lists), and `resource_key()` already includes the requested
prefix, so the revision-keyed decision cache applies to list verdicts and their obligations
unchanged: obligations are pure functions of (bundle revision, input).

### D5 — Invariants this decision adds (testable, corpus-pinned)

- **I1 — Scope from decision only.** Cursors (gateway tokens, backend tokens on the D2 path,
  v1 markers, `start_after`) carry position, never scope. Every page's enumerable set is
  derived exclusively from that page's fresh PDP decision.
- **I2 — Containment (E1).** Every backend LIST the gateway issues on a narrowed path has
  `prefix` equal to a normalized element of the decided scope set (or a probe inside one);
  unit/property tests pin this on the executor.
- **I3 — No unnarrowed forward.** A request whose obligation the PEP cannot execute (staging
  gap, bound exceeded, malformed obligation) is denied, never forwarded as requested.
- **I4 — Token fail-closed.** Unknown version, failed AEAD open, or `scope_hash` mismatch ⇒
  reject the token; never "best effort" resume.
- **I5 — One record per page** (ADR-002 D4), with `result.obligations` recording the scopes;
  PEP-composed denies (bound, staging) are recorded like every other deny.

### D6 — Rollout order (the default, decided)

1. **Ship single-prefix first** (D2): the hook rewrite plus the `{}`-obligation pass-through.
   This unblocks `aws s3 ls` and GUIs for the dominant case with zero new pagination
   machinery, against hand-written bundles.
2. **Multi-prefix fan-out second** (D3+D4): executor, delimiter synthesis, bound, cursor —
   one milestone, because `aws s3 ls` sends a delimiter and would hit the synthesis path
   immediately. Sequencing tracks the control-plane grant projection: multi-prefix subjects
   cannot exist in production before it lands.
3. **Interim behavior between 1 and 2**: `allowed_prefixes` ⇒ deny with the fixed reason
   `"deny: multi-prefix list not yet supported; narrow the request prefix"` — the fail-closed
   rule applied literally.
4. `ListObjectVersions`, `ListMultipartUploads`, `ListParts` remain **off the allowlist**
   (deny-by-default backstop) until each gets this same analysis — their cursors are
   multi-part (`key_marker`/`version_id_marker`, `upload_id_marker`) and are not covered by
   this ADR's resume rule.

---

## Alternatives considered

**A1 — Response filtering (list broad at the backend, drop unauthorized entries from the
DTO).** Rejected; rewrite is preferred, and the named ContinuationToken/IsTruncated/MaxKeys
problem is structural:

- **MaxKeys**: a backend page of `M` entries filters down to `k ≤ M` — under-filled or empty
  pages. To honor the client's page size the gateway must loop backend pages until the budget
  fills, and the loop is unbounded: it scans the *bucket's* keyspace to find the *grant's*
  keys. Cost is O(bucket), not O(granted): a 10-key grant in a 10⁸-key bucket costs ~10⁵
  backend pages per client listing. Fan-out is O(granted + n). This asymmetry alone is
  disqualifying at scale and is a self-DoS lever a client can pull by listing broadly.
- **IsTruncated**: the backend's flag means "more keys in the bucket", not "more authorized
  keys". Emitting it verbatim lies to the client (clients keep paging through empty pages);
  computing the truthful flag requires look-ahead scanning to the next authorized key —
  unbounded again.
- **ContinuationToken**: the backend token points mid-bucket, into ranges the subject may
  hold no grant on. To resume, the gateway must wrap it in its own token anyway — **filtering
  does not avoid the gateway-owned cursor; it adds the scan to it.** Every piece of D4
  machinery would still be needed.
- **CommonPrefixes/KeyCount**: with a delimiter, deciding which rolled-up CPs to drop
  re-implements grant-prefix intersection in the *response* path — a second copy of the
  narrowing logic to drift from the rego's (`narrowed()`), the exact failure class ADR-001's
  drift control exists to prevent. `key_count` must be recomputed either way.
- Confidentiality is also weaker: the backend momentarily materializes and transfers
  unauthorized key names to the gateway on every page; fan-out never requests them at all.

**A2 — Deny all multi-prefix listings, permanently.** Rejected. A working mechanism must be
chosen precisely because denial breaks `aws s3 ls` and every GUI. Multi-prefix subjects are a
first-class outcome of the grant model (subject grants ∪ group grants,
`policy/gateway/authz.rego::grants`), not an edge case — a user in two groups holds two
prefixes on day one of the projection. Denial survives only as the interim (D6.3) and
above-bound (D3) posture.

**A3 — Gateway cursor embedding the backend's `next_continuation_token` per prefix.**
Rejected. It stores backend-opaque state with unspecified validity/lifetime semantics in a
client-held token, coupling the cursor to each backend's token behavior — against the "assume
nothing but the plain S3 API surface" principle and needless on heterogeneous backends (the
whole reason the gateway exists). It is also non-uniform: v1 has no token to embed, so two
resume mechanisms would coexist. Resume-by-key costs the same backend seek and works
identically on v1/v2 and on every S3-compatible backend.

**A4 — Server-side cursor state (token = ID into a gateway store).** Rejected: contradicts the
stateless-gateway posture (decision cache keyed on bundle revision → cache coherence across
the mesh by construction). A cursor store adds cross-instance shared state (a third cross-site
flow beyond bundles and audit), breaks any-instance paging, and creates an eviction/leak
surface. The sealed token achieves the same with zero state.

**A5 — Parallel fan-out (issue all n LISTs concurrently, k-way merge).** Rejected as the
baseline, kept as a possible optimization behind the same contract. Sequential concatenation
is *lazy*: a page fully inside P₀ costs exactly one backend call; parallel issue pays n calls
of wasted work and re-introduces merge-state into the cursor. The order lemma makes
sequential both simpler and no less correct; benchmark first, optimize on evidence.

**A6 — Forward unnarrowed and rely on per-object GET authorization ("listing is harmless").**
Rejected by the premise that a prefix-scoped subject must not enumerate the bucket, and by the
deployments this gateway exists for: key names are data (ADR-002 R7 — keys may embed sensitive
identifiers). Enumeration is disclosure; per-object gating of reads does not un-disclose the
namespace.

**A7 — Enforce the fan-out bound in rego.** Rejected. The bound is an execution-capacity
property of the PEP/deployment, not access intent; putting it in policy would require
injecting deployment config into the bundle and would complicate the obligation surface the
parity gate compares. The PEP-composed deny follows the ADR-002 D4 precedent for PEP-owned
verdict composition. (The *authoring-time* guard against absurd grant sets belongs in the
control plane.)

---

## Consequences

**What must hold for the security claim** ("a prefix-scoped subject cannot enumerate beyond
its grants, and every enumeration is decided and audited per page"):

1. Invariants D5-I1…I5 hold — in particular no unnarrowed forward (I3) and
   scope-from-decision-only (I1). I2 (containment) is the executor's testable core.
2. The typed hooks for both list ops are implemented and on the allowlist as one change; an
   allowlisted list op without a narrowing hook would be fail-open (typed hooks default to
   `Ok(())`).
3. Token sealing keys are gateway-owned, per-site (backend credentials and, likewise, token
   keys never leave the site), shared across the site's instances so any instance can open any
   token; rotation uses a two-key acceptance window, and an unopenable token is a clean
   fail-closed restart, never an error loop.
4. Per-page decisions are actually per-page: the decision-cache key includes the requested
   prefix (`resource_key()`), so a cached verdict is only reused for an identical question at
   the same bundle revision — revocation still lands as a new revision (I1 stays true with
   caching on).

**Risks / accepted costs:**

- **Latency**: a fan-out page is multi-RTT by construction (≤ n LISTs + ≤ n probes, bounded
  32 at the default). Accepted within the latency budget discipline — the list path gets its
  own benchmark and CI perf gate; the bound is the knob.
- **One legal-but-odd empty terminal page** when all remaining prefixes are empty (D4 step
  6). AWS clients tolerate empty final pages; conformance tests (Ceph `s3-tests`, MinIO Mint)
  plus `aws s3 ls`/rclone/boto3 smoke tests must confirm before GA.
- **Synthetic-CP divergence**: existence probes make synthesized CommonPrefixes match native
  semantics (only non-empty directories appear) at the cost of ≤ n probe calls; without
  probes, empty "directories" could appear. We pay the probes.
- **Token size**: sealed resume keys can approach ~1.4 KB (key length ≤ 1024 bytes) — larger
  than AWS tokens but opaque per the S3 contract; the header/URI caps the gateway owns must
  admit it. Verified in conformance tests.
- **`encoding_type=url`**: the merge must operate on consistently decoded keys and encode
  exactly once in the merged output; pinned by a dedicated conformance test rather than
  assumed (where s3s performs URL encoding is not settled here).
- **Behavior shift at the bound**: a subject accumulating a 17th prefix grant flips from
  fan-out to actionable deny. Mitigated at the source by the control-plane grant-authoring
  lint and by the deny message; the alternative (unbounded amplification) is worse.
- **Engine listings** (proxy mode) traverse this same path; listing storms from engines are
  part of capacity sizing, with the same bound protecting the backends.

**Follow-ups (this repository):**

- Implement D2 hooks + interim deny, then the D3/D4 executor in the dispatch layer once the
  client pool lands.
- Property test: executor output ≡ reference model (filter of a full synthetic listing) over
  randomized keyspaces, grant sets, `max_keys`, delimiters, and resume points — including the
  CP-successor rule and `succ()` carry/`0xFF` edges.
- Corpus: add multi-prefix, overlap-normalization, and delimiter-synthesis cases to
  `policy/testdata/corpus.json` (obligation side); keep `allowed_prefixes` comparison
  order-insensitive (ADR-001 Gate A).
- Metrics: fan-out width histogram, backend calls per page, token rejects (by cause),
  above-bound denies — the last two page when sustained (they indicate policy churn or client
  breakage).

---

## Control-plane integration (out of scope for this repository)

These items are implemented by the control plane against this repository's policy contract:

- **Grant projection** (`s3_grants` / `group_grants`): precondition for any production
  multi-prefix traffic. No new shape is needed — the documented grant contract in
  `policy/gateway/authz.rego` already carries `prefixes: [...]`.
- **Grant-authoring lint**: warn on, and require override to exceed, more than
  `list_fanout_max_prefixes` (default 16) effective prefix scopes per (subject ∪ groups,
  bucket, action); surface the deployed bound to authors. Above the bound, listing denies at
  the gateway by design (D3) — authoring is where to prevent it.
- **Golden corpus**: adopt the multi-prefix and delimiter-synthesis obligation cases; the
  parity gate replays them through OPA and regorus.
- **No extractor change**: the ADR-002 record shape is unchanged — `result.obligations`
  already carries `narrow_prefix`/`allowed_prefixes`. A test should confirm the stored variant
  round-trips obligations for list records.
- **Client-facing docs**: listings are scope-narrowed; continuation tokens are opaque and may
  exceed AWS's typical size; token invalidation on policy change means "restart the listing";
  above-bound listings return an actionable deny asking for a narrower prefix.

Gateway-side work (this repository) is the Follow-ups above, in D6 order: D2 hooks + interim
deny → executor + cursor + key management → property/conformance/perf gates.
