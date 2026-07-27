# ADR-003: Object-tag ABAC — TOCTOU window and tag-cache invalidation

- **Status**: Proposed
- **Date**: 2026-07-15
- **Owners**: gateway team (this repo)
- **Related**: `src/authz/input.rs`, `src/pdp/cache.rs`, `src/pdp/mod.rs`, `policy/gateway/authz.rego`, `src/audit/record.rs`; ADR-001 (direct-path closure), ADR-002 (decision-log record shape)

## Context

s0's second policy generation is a **future ABAC system** — attribute-based rules over principal
attributes, resource attributes, and **object tags**. The OPA input contract reserves the field
for it — `"object_tags": { ... } | null // fetched on demand for ABAC` — with the standing
instruction: ABAC is the same input plus additional rego over `principal.attributes`,
`object_tags`, and resource attributes, and the two problems below must be resolved *before* the
tag path is built.

Two problems define this ADR:

1. **TOCTOU.** Tags are read at decision time; the object can be retagged before the op lands at
   the backend. Either accept and document the window, or don't build tag-based denies for ops
   where the window matters.
2. **Cache invalidation is broken by direct paths.** Write-through invalidation only works for
   tag writes *you see*. If direct-to-backend traffic can write tags (see ADR-001), the cache goes
   stale from writes never observed, and stale tags → wrong decision. There are exactly three
   resolutions: (i) direct-to-backend principals cannot write tags, (ii) a short-TTL-only tag
   cache (which largely removes the reason to cache), or (iii) tag-based ABAC ships only after the
   direct-path question resolves to "no direct path".

   **Tag ABAC must not ship before this is answered.**

The surrounding settled decisions that bound the design space:

- **Decision cache** (settled): keyed on `(bundle_revision, principal, action, resource)`; no
  invalidation logic exists; and — load-bearing here — **do not cache decisions whose input
  includes on-demand data (object tags) unless that data's version is part of the key.**
- **Direct-path closure** (ADR-001): the direct-to-backend credential exposure is real until
  closed. The direct creds are tenant-owner creds vended to users and configured into an analytics
  query engine and its catalog, plus infrastructure control-plane creds. Dispositions are
  constrained: data-touching creds have only one disposition — close them — so the "no direct
  path" state is reachable but not yet in force.
- **Backend-agnostic enforcement**: never depend on a backend-native capability for
  authorization; assume nothing but the plain S3 API surface.

Why the two problems are structurally different:

- **TOCTOU is inherent to the S3 surface.** The plain S3 API has no atomic
  "execute-only-if-tags-unchanged" primitive: `GetObjectTagging` returns the tag set (plus the
  object's `x-amz-version-id` on versioned buckets — which is **not** a tag-state identifier,
  because `PutObjectTagging` mutates the tags of an existing version in place), and conditional
  request headers are content/ETag-based, not tag-based. So a window between the tag read and the
  backend executing the forwarded op always exists, even with a single enforcement path; it can be
  shrunk, never closed.
- **Cache/freshness corruption from unseen writers is contingent** — it exists exactly as long as
  direct paths exist. A direct writer flips a tag with **no decision record**, and every
  subsequent gateway decision — cached or not — evaluates attacker-controlled, unaudited state
  while producing an audit record that faithfully embeds the forged tags as if they were governed.
  A direct data *read* bypasses audit for itself; a direct tag *write* poisons the audited path's
  future correctness. That is categorically worse.

What is implemented in this repo today (already consistent with the decision below):

- `src/authz/input.rs`: `object_tags: Option<BTreeMap<String, String>>` is reserved in the wire
  schema and documented as gated — never populated until the direct-path question resolves;
  `OpaInput::has_on_demand_data()` returns `object_tags.is_some()`; `OpaInput::resource_key()`
  deliberately **excludes** tags from the cache identity.
- `src/pdp/cache.rs`: `CachingPdp::decide` **refuses to cache** any input where
  `has_on_demand_data()` is true (bypass straight to the inner engine) — their freshness is not
  bounded by the revision. Cache keys are `(revision, full principal, resource_key)`.
- `policy/gateway/authz.rego`: **no rule reads `object_tags`.** The shipped policy is the grant
  model only (membership + denylist + freeze + grants). In production the platform pushes the
  policy as a bundle; the in-repo module is the compiled-in default and dual-engine parity oracle,
  so shipping ABAC means the bundle carries tag rego and the in-repo default/oracle grows matching
  cases.
- `src/audit/record.rs` / ADR-002: the audit record embeds the full `OpaInput`, so `object_tags?`
  is already part of the frozen record schema — when tags ship, every tag-bearing decision is
  audited **with the tag values it decided on**, with no consumer change (additive-only, unknown
  fields ignored).

What is not yet built:

- This repo: the on-demand `GetObjectTagging` fetch, any ABAC rego, and tag ops on the operation
  allowlist (today they are absent from the allowlist, hence denied by the `check()` backstop).
- External: the direct-path closure itself (ADR-001); the data-plane grant projection and any
  action-vocabulary extension; and shared-corpus cases for tags.

## Decision

Tag ABAC is a **planned capability**, specified now so the code and schema already anticipate it,
gated on one design invariant rather than shipped.

### D1. Object-tag ABAC ships only once no ungoverned writer can mutate tags on governed data

Object-tag ABAC — any rego that reads `input.object_tags` — **does not ship** until **no
credential outside the gateway can mutate tags on gateway-governed data**. That is exactly the
direct-path closure of ADR-001: the data-touching tenant-owner exposures **closed** (the only
disposition available to them), and any residual infrastructure credential (e.g. a
storage-operator admin) verifiably isolated on a non-data path. This is not new policy — ADR-001
already mandates those dispositions and already routes engines through the gateway; this ADR makes
tag ABAC *sequenced behind* their execution. It is the only self-consistent resolution of the
cache problem (D4), which is why it is chosen over options (i) and (ii).

**Scope of the gate — precise on purpose:**

- **Gated**: ABAC over `object_tags` (on-demand, per-object, data-plane-mutable state).
- **Not gated**: ABAC over **bundle-carried attributes** — `principal.attributes` and
  `bucket_attributes` (including `sensitivity`, which the bundle already carries but does not
  enforce). Those attributes ride the per-org bundle, so decisions over them are revision-keyed
  and cache-correct by the existing cache construction, with no on-demand fetch and no TOCTOU
  beyond bundle-propagation latency. Bucket-sensitivity ABAC can therefore ship first and deliver
  ABAC value while the direct paths close (see A6).

### D2. Until the gate opens: `object_tags` is never populated, and the code already enforces the fallback

Interim posture, all three layers of which are implemented:

1. **The PEP never fetches tags and never populates `object_tags`** — `src/authz/input.rs`
   documents the field as gated. No code path in the gateway issues `GetObjectTagging` for
   decision input.
2. **No policy reads tags** — `policy/gateway/authz.rego` contains no `object_tags` reference; the
   grant model is tag-blind by construction.
3. **The cache is hardened against drift** — if a future change populates `object_tags` anyway,
   `src/pdp/cache.rs` refuses to cache the decision (`has_on_demand_data()` bypass), so the failure
   mode degrades to per-request evaluation, never a stale cached verdict. The pairing is deliberate
   and must be preserved as a pair: `resource_key()` **excludes** tags from the key, which would
   let a tag-bearing decision collide with the tag-free decision for the same
   `(revision, principal, resource)` — that exclusion is sound *only because* tag-bearing inputs
   are never inserted. Neither half may change without the other.

Tag-surface ops (`GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging`,
`GetBucketTagging`, `PutBucketTagging`) stay **off the operation allowlist** until the gate opens,
so the `check()` backstop denies them — every operation you support is an operation you own, and
ops you do not own must be denied. Adding them to the allowlist and implementing their typed hooks
is part of the ship-gate change, not before.

### D3. Post-gate evaluation design: on-demand fetch, policy-driven and fail-closed; tags only ever restrict

When the gate opens:

- **Fetch predicate lives in bundle data, default off.** The PEP fetches `GetObjectTagging` (via
  the request's per-tenant backend client) only when the bundle marks the scope as tag-ruled — an
  additive key on the existing `bucket_attributes` shape, e.g.
  `bucket_attributes[<bucket>].tag_rules == true`. This keeps the hot path at one PDP evaluation
  (no "ask rego whether it needs tags" two-phase eval, which would double PDP calls and complicate
  dual-engine parity), keeps the predicate revision-consistent with the policy that consumes it,
  and protects the latency budget: the +1 backend RTT is paid only on buckets that opted into tag
  rules.
- **Fetch failure ⇒ deny** for tag-ruled scopes (missing data ⇒ deny). A tagging-API outage on the
  backend thus denies tag-ruled buckets — the correct failure direction; availability of tag-blind
  buckets is unaffected.
- **Tags only restrict; they never grant.** The rego shape is
  `allow if { …existing grant path… ; not tag_denied }` — a tag rule can narrow what a matched
  grant allows, never authorize absent a grant. Consequence: an absent tag set or an
  attacker-written tag can only *reduce* access (self-DoS at worst), never broaden it. The
  privilege that remains dangerous is tag **removal** (declassification), which D5 gates as a
  first-class grant action.
- **New rego stays inside the regorus-supported builtin subset** (object/map lookups, `in`,
  equality — nothing exotic is needed for tag matching), so the dual-engine parity gate remains
  passable. Like the base policy, ABAC rego is delivered in the pushed bundle, with the in-repo
  module as its compiled-in default and parity oracle.

### D4. Post-gate cache rule: a tag-bearing decision is never cached unless a tag-version is part of the key — and initially, it is simply never cached

The cache invariant is held, not softened. Two consequences:

1. **There is no valid tag-version available from the backend.** The plain S3 surface exposes no
   tag revision: `GetObjectTagging` returns no generation token, and the object `version-id` does
   not qualify because tags are mutable *per version* in place. A tag-version must therefore be
   **gateway-minted** — a monotonic counter per `(backend, tenant, bucket, key)` bumped on every
   tag mutation the gateway forwards — which is sound **iff the gateway observes every tag write**.
   That is exactly the D1 gate condition: the versioned-key fix is itself only constructible after
   the direct paths close, which is the deep reason option (iii) is the only self-consistent
   resolution.
2. **Initial shipped posture: tag-bearing decisions are not cached at all.** This is already the
   behavior of `src/pdp/cache.rs` and it satisfies the cache invariant vacuously. The fetch itself
   is the dominant cost (one backend RTT), not the PDP eval, so a decision cache that still has to
   re-fetch tags to validate a version buys little. A gateway-minted tag-version counter is
   additionally **state**, in tension with the stateless-mesh posture (per-instance counters break
   cache coherence across the mesh; a shared store breaks statelessness). Versioned tag caching (or
   a tag-value cache) is therefore deferred to its own ADR, justified only by measured p99 need
   under the benchmark gate, and must resolve the mesh question explicitly.

### D5. Tag mutation is a privileged, governed operation

A tag write changes future authorization outcomes, so it is grant-adjacent: **whoever can retag
can lift tag-based restrictions.** At gate-open:

- `GetObjectTagging` / `PutObjectTagging` / `DeleteObjectTagging` join the operation allowlist with
  typed hooks, per-user authorization, and one decision record each.
- Tag **reads** map to the existing `read_objects` action on the object key. Tag **mutation**
  requires a new, additive grant action — proposed **`manage_tags`** — in the grant vocabulary.
  `write_objects` must **not** imply the right to declassify: writing data and rewriting the
  attributes a policy keys on are different privileges. The action set is a schema example, the
  rego's `action_matches` is vocabulary-agnostic (`policy/gateway/authz.rego` matches membership in
  `g.actions`), and `crate::model::Action` grows a variant additively — but the **grant
  projection** must emit it, which is external work.
- **Data ops that carry initial tags** (`PutObjectInput.tagging`,
  `CopyObjectInput.tagging`/`tagging_directive`, `CreateMultipartUploadInput.tagging`, `PostObject`
  form tagging) are permitted under plain `write_objects`: they classify the writer's **own new
  object/version**, and under D3's tags-only-restrict rule they cannot broaden anyone's access.
  Mutating an **existing** object's tags is only possible through the `manage_tags`-gated tagging
  ops. This inventory is part of the ship-gate review so no tag-bearing input field ships
  unexamined.
- Backend-side tag-driven behaviors (e.g. lifecycle expiration rules filtered by tags) are
  configured via `manage_lifecycle`-gated ops and execute inside the backend, not as gateway
  decisions — one more reason retention semantics do not belong to tag ABAC (D6, Class I).

### D6. The residual TOCTOU window: definition, and which deny classes tolerate it

Post-gate, one window remains: **from the `GetObjectTagging` read (in the typed hook,
pre-decision) to the backend completing the forwarded op** — milliseconds, bounded by in-flight
request duration, racing only *other gateway-audited requests* (every writer that could race is
itself producing a decision record, so the forensic ordering is reconstructible from the audit
stream, ADR-002). It can be shrunk by a re-read immediately before forward (one extra RTT), never
closed (no tag-CAS exists on the S3 surface). Deny classes are classified normatively:

- **Class R — tolerates the window (build these):** restrictive tag rules on
  **reversible/non-destructive ops** — `read_objects`, `list_objects`, HeadObject. Worst case: one
  read proceeds milliseconds after a restricting retag landed — operationally indistinguishable
  from the read having arrived milliseconds earlier, and fully audited with the decision-time tags
  (`src/audit/record.rs` embeds the input). The exposure is detectable, attributable, and bounded.
- **Class I — does not tolerate the window (never express as tag ABAC):** tag rules intended as
  the **sole guard on irreversible ops** — hold/retention semantics such as "tag `hold=legal` ⇒
  deny `delete_objects`/lifecycle expiry/overwrite". A delete decided just before the hold tag
  lands destroys data; a millisecond window with an irreversible consequence is not acceptable at
  the regulated bar. Retention and hold semantics belong to the **grant model** (bundle-carried
  deny rules, freshness bounded by bundle propagation) and to data-protection mechanisms (e.g.
  bucket versioning as compensation against overwrite — a data-protection feature, not an authz
  dependency, so backend-agnostic enforcement is not violated). Where a tag rule is nevertheless
  attached to an irreversible op, the PEP performs the pre-forward re-read to shrink the window,
  but this ADR's position is that Class I rules should not be authored at all.
- **Class N — never supported:** **tags as a revocation mechanism.** "Retag to cut off access now"
  lives inside the TOCTOU window by construction. Revocation is a grant change landing as a new
  bundle revision (which invalidates every cached decision by construction) — or the
  `freeze_writes` kill-switch. Operator and policy-author documentation must state this
  explicitly.

### D7. Preconditions to ship

Before any rego reading `object_tags` reaches production:

- **No ungoverned tag writer.** The ADR-001 direct-path closure is *executed*, not merely decided:
  data-touching credentials closed, residual infrastructure credentials verifiably isolated on
  non-data paths, with **standing detection** — the exposure inventory maintained as an artifact
  with a per-backend check that alerts on any non-gateway credential (detection tooling may be
  backend-specific because it is detection, not the enforcement mechanism) — rather than a one-time
  audit.
- **Tag-op surface landed.** Allowlist entries and typed hooks for the tagging ops; `manage_tags`
  live in the grant projection; the D5 data-op tagging-field inventory reviewed.
- **Cache posture verified in CI.** A test pins that `CachingPdp` never caches an input with
  `object_tags` populated (`src/pdp/cache.rs` bypass), and that `resource_key()`'s tag-exclusion is
  only ever paired with that refusal (D2).
- **Dual-engine parity extended.** ABAC rego confined to regorus-supported builtins; the shared
  decision corpus extended with tag cases; OPA/regorus replay identical.
- **TOCTOU documentation shipped.** Class R/I/N taxonomy in policy-author docs; "tags are not
  revocation" in operator docs (D6).
- **Audit continuity confirmed.** Tag-bearing records flow through the ADR-002 contract unchanged
  (`object_tags` is already in the frozen `OpaInput` schema; additive, consumers ignore unknown
  fields).

## Alternatives considered

- **A1 — Option (i): "direct-to-backend principals cannot write tags."** Rejected as the gate
  condition because it is unenforceable on the real inventory: the direct creds are **tenant-owner**
  creds, which on the plain S3 surface can `PutObjectTagging` every object in the tenant.
  Constraining them per-op would require backend-native IAM scoping — disqualified as a mechanism
  (any design that depends on a backend-native capability for authorization is disqualified) and
  unavailable on arbitrary S3-compatible backends. Moreover the direct-path closure already rules
  that data-touching creds have only the close disposition, so option (i)'s precondition converges
  to option (iii) anyway. Choosing (i) would just be (iii) with extra steps and a weaker
  verification story.
- **A2 — Option (ii): short-TTL tag cache.** Rejected. It largely removes the reason to cache.
  Worse, a TTL converts policy correctness into a latency knob: within the TTL, a wrong allow is
  still a wrong allow — now unattributable to any observable event — which fails the regulated bar.
  And it reintroduces exactly the invalidation-logic failure class the decision cache was designed
  to eliminate ("no invalidation logic exists" is the settled property; a TTL is invalidation logic
  with a tunable wrongness window).
- **A3 — Write-through invalidation on gateway-observed tag writes, shipped before the direct paths
  close.** Rejected: write-through invalidation only works for tag writes *you see*, and the
  inventory is verified non-empty until closed, so "writes you never observe" is the present state
  of the world, not a hypothetical. Post-gate, write-through becomes a possible optimization but is
  subsumed by D4's version-counter analysis (both require total observation; both are deferred to
  the follow-up caching ADR).
- **A4 — Ship tag ABAC uncached-only before the direct paths close** ("no cache ⇒ no staleness").
  Rejected. Staleness is not only a cache property: the *decision itself* reads state a direct
  writer can flip without any decision record, so policy outcomes come to depend on a channel
  outside the audited enforcement point — violating the enforcement guarantee (it holds **only if**
  no consumer can reach a backend directly) in the worst way: an unaudited direct tag write
  **declassifies** an object, and every later gateway decision faithfully allows on forged inputs
  while emitting audit records that launder them. It also contradicts the explicit sequencing
  twice over: do not ship tag ABAC before the tag-write question is answered, and ship only after
  **both** the cache question and the direct-path question are.
- **A5 — Close TOCTOU with backend-native mechanisms** (backend-specific conditional semantics,
  backend IAM, object lock as an authz primitive). Rejected by the backend-agnostic constraint
  (enforcement must not depend on a backend-native capability; the current backend is not the
  design envelope), and moot besides: standard S3 has no tag-conditional execution primitive to
  depend on. Bucket versioning is retained only as *data protection* against the Class I overwrite
  case, never as the authorization mechanism.
- **A6 — Project tags into the OPA bundle instead of fetching on demand** (make tags control-plane
  data, revision-keyed and cache-correct by the existing construction). Rejected as the general
  mechanism: tags are per-object data-plane state at object cardinality — projecting them makes the
  per-org bundle scale with object count and turns every tag write into a control-plane round-trip
  plus mesh-wide bundle push, with tag-effect latency equal to bundle propagation; it also
  presupposes the platform observes every tag write, which is again the direct-path precondition.
  **Retained as a carve-out** for small, slow-moving attribute sets: this is exactly the existing
  `bucket_attributes` pattern (`sensitivity` is already carried), which is why D1 excludes
  bundle-carried-attribute ABAC from the gate — it is cache-correct today and needs no new
  machinery.

## Consequences

**What must hold for the security claim** (post-gate, tag rules live):

- **I1 — No ungoverned tag writer, continuously.** Every credential able to mutate tags on
  governed data routes through the gateway. A regression here is silent decision-input corruption —
  hence the standing detection requirement, not a one-time attestation.
- **I2 — Tags only restrict.** No rego path may authorize from tags absent a matched grant (D3).
  This is what makes attacker-written or missing tags fail safe.
- **I3 — Tag mutation is always allowlisted + hooked + `manage_tags`-granted + audited**; no
  data-op side channel can mutate an *existing* object's tags (D5 inventory).
- **I4 — The cache never holds a tag-bearing decision without a tag-version in the key**; in the
  shipped posture, it never holds one at all (`src/pdp/cache.rs`, pinned by CI). The
  `resource_key()`-excludes-tags / refuses-to-cache pairing changes only as a pair (D2).
- **I5 — Class I rules are not expressed as tag ABAC**; revocation is never performed by retagging
  (D6). This is a policy-authoring invariant enforced by review and documentation, not code — name
  it in the policy-author guide.
- **I6 — ABAC rego stays inside the regorus builtin subset** and the shared corpus covers tag
  cases, or the dual-engine swap is forfeited.

**Risks and follow-ups:**

- **R1 — The capability couples to external timelines.** The direct-path closure is control-plane
  work this repo cannot do; product pressure to ship ABAC early will land here. This ADR exists to
  make the refusal citable ("do not ship" is the explicit instruction), and D1's carve-out
  (bucket-attribute ABAC, e.g. `sensitivity` enforcement) gives product a shippable ABAC increment
  that is cache-correct today.
- **R2 — Latency: +1 backend RTT per tag-ruled decision, uncached.** This can exceed the
  gateway-added p99 budget on its own; the mitigation is the D3 fetch predicate (default off,
  per-bucket opt-in) and the benchmark gate. If measured need demands caching, that is the deferred
  D4 ADR, which must solve the tag-version counter vs statelessness tension explicitly.
- **R3 — Fail-closed fetch means tagging-API outage denies tag-ruled buckets.** Correct direction,
  but an availability consequence operators must know: scoping tag rules narrowly limits the blast
  radius.
- **R4 — Convention-guarded field.** `object_tags` population is currently prevented by code review
  plus the `src/authz/input.rs` doc, not by the compiler. Repo follow-up: put the fetch/population
  path behind a compile-time feature (`tag-abac`, off by default) so accidental pre-gate population
  is unbuildable, and add the cache-posture CI test now rather than at gate time.
- **R5 — Pre-gate tags exist and are untrusted.** Nothing stops today's direct-path writers (or
  `PutObject.tagging` through the gateway) from writing tags *before* the gate opens; the gate only
  guarantees governance *going forward*. Because tags only restrict (I2), pre-existing tags cannot
  grant access, but policy authors must not assume historical tag values were ever governed. If a
  deployment needs trusted initial classifications, that is a one-time, audited retag migration at
  gate-open (operator runbook item).
- **R6 — Decision records grow.** Tag-bearing records embed the tag map (bounded: S3 caps object
  tags at 10 keys); covered by ADR-002's size analysis margin and additivity. No consumer change
  needed.

## Control-plane integration (out of scope for this repository)

Shipping tag ABAC depends on external work the platform owns: the direct-path closure of ADR-001
(close the tenant-owner credentials vend and replace it with gateway-issued per-user credentials;
migrate the analytics engine and its catalog off the tenant-owner cred onto the gateway path with
per-user identity; isolate + prefix-bound infrastructure creds and document why each is not a data
path; and stand up the exposure inventory as a maintained artifact with recurring per-backend
non-gateway-credential detection); adding `manage_tags` to the data-plane grant action vocabulary
and the bundle projection (additive to the Grant shape consumed by `policy/gateway/authz.rego`);
adding the D3 fetch-predicate key to `bucket_attributes` in the projection (additive, same delivery
mechanism); and extending the shared decision corpus with object-tag cases (allow-with-tags,
tag-deny, missing-tags, tag-fetch-failed ⇒ deny) for the dual-engine gate. No decision-log consumer
change is required (ADR-002 additivity); surfacing `input.object_tags` for audit queries is a
nice-to-have.

This repo (gated behind D7 unless noted):

- **Now, not gated:** `tag-abac` compile-time feature gating any `object_tags`-population path
  (R4), plus the CI test pinning `src/pdp/cache.rs`'s refusal to cache on-demand-data decisions.
- Typed hooks + operation-allowlist entries for the tagging ops; `manage_tags` mapping in
  `crate::model::Action` (additive).
- ABAC rego module (tags-only-restrict shape, regorus-safe builtins) + pre-forward re-read for any
  tag rule attached to an irreversible op (D6).
- Policy-author + operator docs: Class R/I/N taxonomy, "tags are not revocation", the R3
  availability note, the R5 pre-gate-tags caveat.
