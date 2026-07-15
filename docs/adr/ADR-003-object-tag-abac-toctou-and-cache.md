# ADR-003: Object-tag ABAC — TOCTOU window, tag-cache invalidation, and the §7.1 ship-gate

- **Status**: Proposed
- **Date**: 2026-07-15
- **Owners**: gateway team (this repo); companion work: platform team (§7.1 closure), console team (grant projection)
- **Related**: PROMPT §1, §2, §3.4, §3.7, §4.3.2, §5, §5.2, §6.1, §6.2, §6.5–§6.7, §7.1, §8 (spike 8), §9.3, §9.5; `src/authz/input.rs`, `src/pdp/cache.rs`, `src/pdp/mod.rs`, `policy/gateway/authz.rego`, `src/audit/record.rs`; ADR-002

## Context

The gateway's second policy generation is "a future ABAC system — attribute-based rules
over principal attributes, resource attributes, and **object tags**" (§1). The §5 input
contract reserves the field for it — `"object_tags": { ... } | null // fetched on demand
for ABAC` — and §5 instructs: "**ABAC (future):** same input, additional rego over
`principal.attributes`, `object_tags`, resource attributes. **See §5.2 before building the
tag path.**"

§5.2 names the two problems this ADR resolves, and ends with an instruction:

1. **TOCTOU.** "Tags are read at decision time; the object can be retagged before the op
   lands at the backend. Accept and document the window, or don't build tag-based denies
   for ops where the window matters."
2. **Cache invalidation is broken by §7.** "Write-through invalidation only works for tag
   writes *you see*. If direct-to-RGW traffic can write tags (§7.1), your cache goes stale
   from writes you never observe, and stale tags → wrong decision." §5.2 offers exactly
   three resolutions: (i) direct-to-RGW principals cannot write tags, (ii) short-TTL-only
   tag cache ("which largely removes the reason to cache"), or (iii) "tag-based ABAC ships
   only after §7.1 resolves to 'no direct path'."

   "**Do not ship tag ABAC before this is answered.**"

The surrounding settled decisions that bound the design space:

- §4.3.2 (decision cache, settled): key on `(bundle_revision, principal, action, resource)`;
  "no invalidation logic exists"; and — load-bearing here — "**Do not cache decisions whose
  input includes on-demand data (object tags, §5.2) unless that data's version is part of
  the key.**"
- §7.1 (blocker, not footnote): the direct-to-backend credential inventory is **verified
  non-empty** — tenant-owner creds vended to users via the credentials endpoint, the same
  tenant-owner cred used by Trino/Iceberg catalogs via Lakekeeper, the Rook admin ops user,
  per-OrgStorage admin (§3.7). Dispositions are constrained: "'accept in writing that
  they're outside the model' is NOT an available disposition for any credential that can
  reach user-attributable data … Data-touching creds have only option (a)" — close them.
- §8 spike 8: "Object-tag ABAC — **only after §5.2 and §7.1 are answered**." Open
  questions: "§5.2 tag cache invalidation. **Blocker for tag ABAC.**"
- §6.7: never depend on a backend-native capability for authorization; assume nothing but
  the plain S3 API surface.

Why the two problems are structurally different:

- **TOCTOU is inherent to the S3 surface.** The plain S3 API has no atomic
  "execute-only-if-tags-unchanged" primitive: `GetObjectTagging` returns the tag set (plus
  the object's `x-amz-version-id` on versioned buckets — which is **not** a tag-state
  identifier, because `PutObjectTagging` mutates the tags of an existing version in place),
  and conditional request headers are content/ETag-based, not tag-based. So a window
  between the tag read and the backend executing the forwarded op always exists, even with
  a single enforcement path; it can be shrunk, never closed (§6.7 forbids backend-specific
  escape hatches, and none exist in standard S3 anyway).
- **Cache/freshness corruption from unseen writers is contingent** — it exists exactly as
  long as §7.1's direct paths exist. A direct writer flips a tag with **no decision record**
  (§6.6 violation at the source), and every subsequent gateway decision — cached or not —
  evaluates attacker-controlled, unaudited state while producing an audit record that
  faithfully embeds the forged tags as if they were governed. A direct data *read* bypasses
  audit for itself; a direct tag *write* poisons the audited path's future correctness.
  That is categorically worse.

What EXISTS in this repo today (already consistent with the decision below):

- `src/authz/input.rs`: `object_tags: Option<BTreeMap<String, String>>` is reserved in the
  wire schema and documented as "**Gated behind §7.1 — never populated until the
  direct-path question resolves**"; `OpaInput::has_on_demand_data()` returns
  `object_tags.is_some()`; `OpaInput::resource_key()` deliberately **excludes** tags from
  the cache identity.
- `src/pdp/cache.rs`: `CachingPdp::decide` **refuses to cache** any input where
  `has_on_demand_data()` is true (bypass straight to the inner engine) — "their freshness
  is not bounded by the revision" (module doc). Cache keys are
  `(revision, full principal, resource_key)` per §4.3.2.
- `policy/gateway/authz.rego`: **no rule reads `object_tags`.** The shipped policy is the
  grant model only (membership + denylist + freeze + grants).
- `src/audit/record.rs` / ADR-002 D1: the audit record embeds the full `OpaInput`, so
  `object_tags?` is already part of the frozen record schema — when tags ship, every
  tag-bearing decision is audited **with the tag values it decided on**, with no extractor
  change (ADR-002 I6: additive-only, unknown fields ignored).

What is NOT-YET-BUILT:

- This repo: the on-demand `GetObjectTagging` fetch, any ABAC rego, tag ops on the §6.2
  allowlist (today they are absent from the allowlist, hence denied by the `check()`
  backstop).
- Platform side: §7.1 closure itself (executing the dispositions on the verified inventory);
  the data-plane grant projection (§3.3–§3.4) and any action-vocabulary extension; the
  golden decision corpus cases for tags (the corpus is "a platform asset, not a repo
  asset", §6.5).

## Decision

### D1. Object-tag ABAC ships only after §7.1 resolves to "no direct path" — §5.2 option (iii)

Object-tag ABAC — any rego that reads `input.object_tags` — **does not ship** until §7.1 is
resolved such that **no credential outside the gateway can mutate tags on gateway-governed
data**. Concretely, the two data-touching tenant-owner exposures in the §3.7 seed inventory
(the credentials-endpoint vend and the Trino/Lakekeeper catalog cred) must be **closed**
(§7.1 disposition (a) — the only one available to them), and the infra creds (Rook,
per-OrgStorage admin) must be isolated + prefix-bounded with a documented rationale that
they are not a data path (§7.1 disposition (b)). This is not new policy — §7.1 already
mandates those dispositions and §6.5 already routes engines through the gateway; this ADR
makes tag ABAC *sequenced behind* their execution, exactly as spike 8 orders it.

**Scope of the gate — precise on purpose:**

- **Gated**: ABAC over `object_tags` (on-demand, per-object, data-plane-mutable state).
- **Not gated**: ABAC over **bundle-carried attributes** — `principal.attributes` and
  `bucket_attributes` (including `sensitivity`, which the bundle already carries but does
  not enforce, §3.4). Those attributes ride the per-Org bundle, so decisions over them are
  revision-keyed and cache-correct by the existing §4.3.2 construction, with no on-demand
  fetch and no TOCTOU beyond bundle-propagation latency — "already the policy-freshness
  bound" (§4.3.2). Bucket-sensitivity ABAC can therefore ship first and deliver ABAC value
  while §7.1 closes (see A6).

### D2. Until the gate opens: `object_tags` is never populated, and the code already enforces the fallback

Interim posture, all three layers of which EXIST:

1. **The PEP never fetches tags and never populates `object_tags`** —
   `src/authz/input.rs` documents the field as gated behind §7.1. No code path in the
   gateway issues `GetObjectTagging` for decision input.
2. **No policy reads tags** — `policy/gateway/authz.rego` contains no `object_tags`
   reference; the grant model is tag-blind by construction.
3. **The cache is hardened against drift** — if a future change populates `object_tags`
   anyway, `src/pdp/cache.rs` refuses to cache the decision
   (`has_on_demand_data()` bypass), so the failure mode degrades to per-request evaluation,
   never to a stale cached verdict. Note the pairing is deliberate and must be preserved as
   a pair: `resource_key()` **excludes** tags from the key, which would let a tag-bearing
   decision collide with the tag-free decision for the same
   `(revision, principal, resource)` — that exclusion is only sound *because* tag-bearing
   inputs are never inserted. Neither half may be changed without the other.

Tag-surface ops (`GetObjectTagging`, `PutObjectTagging`, `DeleteObjectTagging`,
`GetBucketTagging`, `PutBucketTagging`) stay **off the §6.2 allowlist** until the gate
opens, so the `check()` backstop denies them ("Every operation you support is an operation
you own. Ops you do not own must be denied", §1.1/§6.2). Adding them to the allowlist and
implementing their typed hooks is part of the ship-gate change, not before.

### D3. Post-gate evaluation design: on-demand fetch, policy-driven and fail-closed; tags only ever restrict

When the gate opens:

- **Fetch predicate lives in bundle data, default off.** The PEP fetches
  `GetObjectTagging` (via the request's per-tenant backend client, §4.4) only when the
  bundle marks the scope as tag-ruled — an additive key on the existing
  `bucket_attributes` shape (§3.4), e.g. `bucket_attributes[<bucket>].tag_rules == true`.
  This keeps the hot path at one PDP evaluation (no "ask rego whether it needs tags"
  two-phase eval, which would double PDP calls and complicate §4.3.1 dual-engine parity),
  keeps the predicate revision-consistent with the policy that consumes it, and protects
  the §9.5 latency budget: the +1 backend RTT is paid only on buckets that opted into tag
  rules.
- **Fetch failure ⇒ deny** for tag-ruled scopes ("missing data ⇒ deny", §6.2). A
  tagging-API outage on the backend thus denies tag-ruled buckets — the correct failure
  direction; availability of tag-blind buckets is unaffected.
- **Tags only restrict; they never grant.** The rego shape is
  `allow if { …existing grant path… ; not tag_denied }` — a tag rule can narrow what a
  matched grant allows, never authorize absent a grant. Consequence: an absent tag set or
  an attacker-written tag can only *reduce* access (self-DoS at worst), never broaden it.
  The privilege that remains dangerous is tag **removal** (declassification), which D5
  gates as a first-class grant action.
- **New rego stays inside the regorus-supported builtin subset** (§4.3.1: object/map
  lookups, `in`, equality — nothing exotic is needed for tag matching), so the dual-engine
  parity gate remains passable.

### D4. Post-gate cache rule: a tag-bearing decision is never cached unless a tag-version is part of the key — and initially, it is simply never cached

The §4.3.2 sentence is held as an invariant, not a suggestion. Two consequences:

1. **There is no valid tag-version available from the backend.** The plain S3 surface
   (§6.7) exposes no tag revision: `GetObjectTagging` returns no generation token, and the
   object `version-id` does not qualify because tags are mutable *per version* in place.
   A tag-version must therefore be **gateway-minted** — a monotonic counter per
   `(backend, tenant, bucket, key)` bumped on every tag mutation the gateway forwards —
   which is sound **iff the gateway observes every tag write**. That is exactly the D1
   gate condition: the versioned-key fix is itself only constructible after §7.1 closes,
   which is the deep reason §5.2 option (iii) is the only self-consistent resolution.
2. **Initial shipped posture: tag-bearing decisions are not cached at all.** This is
   already the behavior of `src/pdp/cache.rs` and it satisfies the §4.3.2 invariant
   vacuously. The fetch itself is the dominant cost (one backend RTT), not the PDP eval,
   so a decision cache that still has to re-fetch tags to validate a version buys little.
   A gateway-minted tag-version counter is additionally **state**, in tension with the
   §9.3 stateless-mesh posture (per-instance counters break the "cache coherence across
   the mesh by construction" property; a shared store breaks statelessness). Versioned
   tag caching (or a tag-value cache) is therefore deferred to its own ADR, justified only
   by measured p99 need under §9.5's benchmark gate, and must resolve the mesh question
   explicitly.

### D5. Tag mutation is a privileged, governed operation

A tag write changes future authorization outcomes, so it is grant-adjacent: **whoever can
retag can lift tag-based restrictions.** At gate-open:

- `GetObjectTagging` / `PutObjectTagging` / `DeleteObjectTagging` join the §6.2 allowlist
  with typed hooks, per-user authorization, and one decision record each (§6.6).
- Tag **reads** map to the existing `read_objects` action on the object key. Tag
  **mutation** requires a new, additive grant action — proposed **`manage_tags`** — in the
  grant vocabulary. `write_objects` must **not** imply the right to declassify: writing
  data and rewriting the attributes policy keys on are different privileges. The action
  set in §5 is a schema example, the rego's `action_matches` is vocabulary-agnostic
  (`policy/gateway/authz.rego` matches membership in `g.actions`), and `crate::model::Action`
  grows a variant additively — but the **grant projection** must emit it, which is
  companion work (§3.3–§3.4, C3 below).
- **Data ops that carry initial tags** (`PutObjectInput.tagging`,
  `CopyObjectInput.tagging`/`tagging_directive`, `CreateMultipartUploadInput.tagging`,
  `PostObject` form tagging) are permitted under plain `write_objects`: they classify the
  writer's **own new object/version**, and under D3's tags-only-restrict rule they cannot
  broaden anyone's access. Mutating an **existing** object's tags is only possible through
  the `manage_tags`-gated tagging ops. This inventory is part of the ship-gate review (G4)
  so no tag-bearing input field ships unexamined.
- Backend-side tag-driven behaviors (e.g. lifecycle expiration rules filtered by tags) are
  configured via `manage_lifecycle`-gated ops and execute inside the backend, not as
  gateway decisions — one more reason retention semantics do not belong to tag ABAC (D6,
  Class I).

### D6. The residual TOCTOU window: definition, and which deny classes tolerate it

Post-gate, one window remains: **from the `GetObjectTagging` read (in the typed hook,
pre-decision) to the backend completing the forwarded op** — milliseconds, bounded by
in-flight request duration, racing only *other gateway-audited requests* (every writer that
could race is itself producing a decision record, so the forensic ordering is
reconstructible from the audit stream, ADR-002). It can be shrunk by a re-read immediately
before forward (one extra RTT), never closed (Context; no tag-CAS exists on the S3
surface). Per §5.2's instruction — "Accept and document the window, or don't build
tag-based denies for ops where the window matters" — deny classes are classified
normatively:

- **Class R — tolerates the window (build these):** restrictive tag rules on
  **reversible/non-destructive ops** — `read_objects`, `list_objects`, HeadObject. Worst
  case: one read proceeds milliseconds after a restricting retag landed — operationally
  indistinguishable from the read having arrived milliseconds earlier, and fully audited
  with the decision-time tags (`src/audit/record.rs` embeds the input). The exposure is
  detectable, attributable, and bounded.
- **Class I — does not tolerate the window (never express as tag ABAC):** tag rules
  intended as the **sole guard on irreversible ops** — hold/retention semantics such as
  "tag `hold=legal` ⇒ deny `delete_objects`/lifecycle expiry/overwrite". A delete decided
  just before the hold tag lands destroys data; a millisecond window with an irreversible
  consequence is not acceptable at the regulated bar (intro/§6.6). Retention and hold
  semantics belong to the **grant model** (bundle-carried deny rules, freshness bounded by
  bundle propagation, §4.3.2/§6.1) and to data-protection mechanisms (e.g. bucket
  versioning as compensation against overwrite — a data-protection feature, not an authz
  dependency, so §6.7 is not violated). Where a tag rule is nevertheless attached to an
  irreversible op, the PEP performs the pre-forward re-read to shrink the window, but this
  ADR's position is that Class I rules should not be authored at all.
- **Class N — never supported:** **tags as a revocation mechanism.** "Retag to cut off
  access now" lives inside the TOCTOU window by construction. Revocation is §6.1's job —
  a grant change landing as a new bundle revision (which invalidates every cached decision
  by construction, §4.3.2) — or the `freeze_writes` kill-switch (§3.5). Operator and
  policy-author documentation must state this explicitly.

### D7. Ship gate — the checklist that opens tag ABAC

All boxes checked, in order, before any rego reading `object_tags` reaches production:

- [ ] **G1 — §7.1 dispositions executed for data-touching creds** (option (a), close):
      the tenant-owner credentials endpoint no longer vends direct-to-RGW creds (replaced
      by gateway-issued per-user creds, §4.2); Trino/Iceberg catalogs migrated off the
      tenant-owner cred onto the gateway path with per-user identity (§6.5, already
      settled — this gate requires it *executed*, not just decided).
- [ ] **G2 — infra creds isolated** (option (b)): Rook admin ops and per-OrgStorage admin
      creds prefix-bounded and documented as non-data paths; prefix-bounding acknowledged
      as defense-in-depth only, where the backend supports it (§6.5/§6.7).
- [ ] **G3 — standing detection, not a one-time audit:** the §3.7 exposure inventory is a
      maintained artifact, with a per-backend operational check that alerts on any
      non-gateway credential existing on a bay (on Ceph: RGW key inventory; detection
      tooling may be backend-specific because it is detection, not the enforcement
      mechanism — §6.7 governs enforcement).
- [ ] **G4 — tag-op surface landed:** allowlist entries + typed hooks for the tagging ops;
      `manage_tags` action live in the grant projection (C3); the D5 data-op tagging-field
      inventory reviewed.
- [ ] **G5 — cache posture verified in CI:** a test pins that `CachingPdp` never caches an
      input with `object_tags` populated (`src/pdp/cache.rs` bypass) and that
      `resource_key()`'s tag-exclusion is only ever paired with that refusal (D2).
- [ ] **G6 — dual-engine parity extended:** ABAC rego confined to regorus-supported
      builtins; golden decision corpus (platform asset, §6.5) extended with tag cases;
      OPA/regorus replay identical (§4.3.1).
- [ ] **G7 — TOCTOU documentation shipped:** Class R/I/N taxonomy in policy-author docs;
      "tags are not revocation" in operator docs (D6).
- [ ] **G8 — audit continuity confirmed:** tag-bearing records flow through the ADR-002
      contract unchanged (`object_tags` is already in the frozen `OpaInput` schema;
      additive, extractor ignores unknown fields — ADR-002 I6).

## Alternatives considered

- **A1 — §5.2 option (i): "direct-to-RGW principals cannot write tags."** Rejected as the
  gate condition because it is unenforceable on the verified inventory: the direct creds
  are **tenant-owner** creds (§3.7), which on the plain S3 surface can `PutObjectTagging`
  every object in the tenant. Constraining them per-op would require backend-native IAM
  scoping — disqualified as a mechanism by §2/§6.7 ("Any design that depends on a
  backend-native capability for authorization … is disqualified") and unavailable on
  arbitrary S3-compatible bays. Moreover §7.1 already rules that data-touching creds
  "have only option (a)" — closing them — so option (i)'s precondition converges to
  option (iii) anyway. Choosing (i) would just be (iii) with extra steps and a weaker
  verification story.
- **A2 — §5.2 option (ii): short-TTL tag cache.** Rejected. The brief itself notes it
  "largely removes the reason to cache." Worse, a TTL converts policy correctness into a
  latency knob: within the TTL, a wrong allow is still a wrong allow — now unattributable
  to any observable event — which fails the regulated bar (intro/§6.6). And it
  reintroduces exactly the invalidation-logic failure class §4.3.2 was designed to
  eliminate ("no invalidation logic exists" is the settled property; a TTL is invalidation
  logic with a tunable wrongness window).
- **A3 — Write-through invalidation on gateway-observed tag writes, shipped before §7.1
  closes.** Rejected verbatim by §5.2: "Write-through invalidation only works for tag
  writes *you see*." The v4 inventory is verified non-empty (§7.1), so "writes you never
  observe" is the present state of the world, not a hypothetical. Post-gate, write-through
  becomes a possible optimization but is subsumed by D4's version-counter analysis (both
  require total observation; both are deferred to the follow-up caching ADR).
- **A4 — Ship tag ABAC uncached-only before §7.1 closes** ("no cache ⇒ no staleness").
  Rejected. Staleness is not only a cache property: the *decision itself* reads state a
  direct writer can flip without any decision record, so policy outcomes come to depend on
  a channel outside the audited enforcement point — violating §6.5's conditional ("the
  enforcement + audit guarantee holds **only if** no consumer can reach a backend
  directly") in the worst way: an unaudited direct tag write **declassifies** an object,
  and every later gateway decision faithfully allows on forged inputs while emitting audit
  records that launder them. It also contradicts the brief's explicit sequencing twice
  over: "Do not ship tag ABAC before this is answered" (§5.2) and spike 8's "only after
  §5.2 **and §7.1** are answered."
- **A5 — Close TOCTOU with backend-native mechanisms** (RGW-specific conditional
  semantics, backend IAM, object lock as an authz primitive). Rejected by the §6.7 hard
  constraint (backend-agnostic enforcement; Ceph is today's backend, not the design
  envelope), and moot besides: standard S3 has no tag-conditional execution primitive to
  depend on (Context). Bucket versioning is retained only as *data protection* against the
  Class I overwrite case, never as the authorization mechanism.
- **A6 — Project tags into the OPA bundle instead of fetching on demand** (make tags
  control-plane data, revision-keyed and cache-correct by the §4.3.2 construction).
  Rejected as the general mechanism: tags are per-object data-plane state at object
  cardinality — projecting them makes the per-Org bundle (§3.4) scale with object count
  and turns every tag write into a control-plane round-trip plus mesh-wide bundle push,
  with tag-effect latency equal to bundle propagation; it also presupposes the platform
  observes every tag write, which is again the §7.1 precondition. **Retained as a
  carve-out** for small, slow-moving attribute sets: this is exactly the existing
  `bucket_attributes` pattern (`sensitivity` is already carried, §3.4), which is why D1
  excludes bundle-carried-attribute ABAC from the gate — it is cache-correct today and
  needs no new machinery.

## Consequences

**What must hold for the security claim** (post-gate, tag rules live):

- **I1 — No ungoverned tag writer, continuously.** Every credential able to mutate tags on
  governed data routes through the gateway (G1–G3). A regression here is silent
  decision-input corruption — hence the standing detection requirement, not a one-time
  attestation.
- **I2 — Tags only restrict.** No rego path may authorize from tags absent a matched grant
  (D3). This is what makes attacker-written or missing tags fail safe.
- **I3 — Tag mutation is always allowlisted + hooked + `manage_tags`-granted + audited**;
  no data-op side channel can mutate an *existing* object's tags (D5 inventory).
- **I4 — The cache never holds a tag-bearing decision without a tag-version in the key**;
  in the shipped posture, it never holds one at all (`src/pdp/cache.rs`, pinned by G5).
  The `resource_key()`-excludes-tags / refuses-to-cache pairing changes only as a pair (D2).
- **I5 — Class I rules are not expressed as tag ABAC**; revocation is never performed by
  retagging (D6). This is a policy-authoring invariant and must be enforced by review and
  documentation, not code — name it in the policy-author guide (G7).
- **I6 — ABAC rego stays inside the regorus builtin subset** and the golden corpus covers
  tag cases, or the §4.3.1 dual-engine swap is forfeited.

**Risks and follow-ups:**

- **R1 — The gate couples tag ABAC to platform timelines.** §7.1 closure is companion
  work this repo cannot do; product pressure to ship ABAC early will land here. The ADR
  exists to make the refusal citable (§5.2's "Do not ship" is the brief's own words), and
  D1's carve-out (bucket-attribute ABAC, e.g. `sensitivity` enforcement) gives product a
  shippable ABAC increment that is cache-correct today.
- **R2 — Latency: +1 backend RTT per tag-ruled decision, uncached.** This can exceed the
  §9.5 gateway-added p99 budget on its own; the mitigation is the D3 fetch predicate
  (default off, per-bucket opt-in) and the benchmark gate from spike 1 onward. If measured
  need demands caching, that is the deferred D4 ADR, which must solve the tag-version
  counter vs §9.3 statelessness tension explicitly.
- **R3 — Fail-closed fetch means tagging-API outage denies tag-ruled buckets.** Correct
  direction (§6.2), but an availability consequence operators must know: scoping tag rules
  narrowly limits the blast radius.
- **R4 — Convention-guarded field.** `object_tags` population is currently prevented by
  code review + the `src/authz/input.rs` doc, not by the compiler. Repo follow-up: put the
  fetch/population path behind a compile-time feature (`tag-abac`, off by default) so
  accidental pre-gate population is unbuildable, and add the G5 CI test now rather than at
  gate time.
- **R5 — Pre-gate tags exist and are untrusted.** Nothing stops today's direct-path
  writers (or `PutObject.tagging` through the gateway) from writing tags *before* the gate
  opens; the gate only guarantees governance *going forward*. Because of I2
  (tags only restrict), pre-existing tags cannot grant access, but policy authors must not
  assume historical tag values were ever governed. If a deployment needs trusted initial
  classifications, that is a one-time, audited retag migration at gate-open (operator
  runbook item, G7).
- **R6 — Decision records grow.** Tag-bearing records embed the tag map (bounded: S3 caps
  object tags at 10 keys); covered by ADR-002 R5's size analysis margin and I6 additivity.
  No console change needed (G8).

## Companion work

Platform team (owns §7.1 closure — all of these are prerequisites G1–G3):

- [ ] **C1** — Revoke the tenant-owner credentials vend
      (`GET /harbors/{id}/buckets/{name}/credentials`, §3.7) and replace it with
      gateway-issued per-user credentials (§4.2); communicate the rclone/AWS-CLI endpoint
      change to users.
- [ ] **C2** — Migrate Trino/Iceberg (Lakekeeper) off the tenant-owner cred onto the
      gateway path with per-user identity, per settled §6.5 (proxy first; remote signing
      only if the pinned connector supports it).
- [ ] **C3** — Isolate + prefix-bound Rook admin ops and per-OrgStorage admin creds;
      document per §7.1(b) why each is not a data path.
- [ ] **C4** — Stand up the exposure inventory as a maintained artifact (§3.7: "an
      artifact you must CREATE") with a recurring non-gateway-credential detection check
      and alert per bay.

Console team (grant projection + corpus, §3.3–§3.4, §6.5):

- [ ] **C5** — Add `manage_tags` to the data-plane grant action vocabulary and the OPA
      bundle projection (additive to the Grant shape consumed by
      `policy/gateway/authz.rego`).
- [ ] **C6** — Add the D3 fetch-predicate key to `bucket_attributes` in the bundle
      projection (additive; same delivery mechanism, §3.4).
- [ ] **C7** — Extend the golden decision corpus with object-tag cases (allow-with-tags,
      tag-deny, missing-tags, tag-fetch-failed ⇒ deny) for the §4.3.1 dual-engine gate.
- [ ] **C8** — No decision-log/extractor change required (ADR-002 I6); confirm the stored
      variant surfaces `input.object_tags` for audit queries (nice-to-have, not blocking).

This repo (gated behind D7 unless noted):

- [ ] **C9** — Now, not gated: `tag-abac` compile-time feature gating any
      `object_tags`-population path (R4), plus the G5 CI test pinning
      `src/pdp/cache.rs`'s refusal to cache on-demand-data decisions.
- [ ] **C10** — Typed hooks + §6.2 allowlist entries for the tagging ops; `manage_tags`
      mapping in `crate::model::Action` (additive).
- [ ] **C11** — ABAC rego module (tags-only-restrict shape, regorus-safe builtins) +
      pre-forward re-read for any tag rule attached to an irreversible op (D6).
- [ ] **C12** — Policy-author + operator docs: Class R/I/N taxonomy, "tags are not
      revocation", R3 availability note, R5 pre-gate-tags caveat.
