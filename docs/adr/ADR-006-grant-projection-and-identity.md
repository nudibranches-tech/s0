# ADR-006: Grant projection contract and STS identity

- **Status**: Accepted — implemented (src/auth/sts.rs, src/model.rs)
- **Date**: 2026-07-15
- **Owners**: gateway team (this repository); the grant projection and the identity cutover are control-plane integration (out of scope for this repository)
- **Scope**: Freezes the two external contracts the gateway consumes but does not build:
  (1) the data-plane grant projection into the per-organization policy bundle, and
  (2) the STS identity the gateway mints and the control plane fronts.
- **Related**: `policy/gateway/authz.rego`, `src/authz/input.rs`, `src/auth/sts.rs`,
  `src/auth/mod.rs`, `src/identity.rs`, `src/pdp/bundle.rs`, `src/bundle_refresh.rs`,
  `src/model.rs`; ADR-001 (direct-path closure, drift control), ADR-002 (audit record shape),
  ADR-004 (list narrowing)

## Context

The gateway's premise is to **consume granular grants**: object operations plus an object-prefix
scope `/<tenant>/<bucket>/<prefix>`, projected into the policy bundle. Producing that projection is
control-plane work, external to this repository. The gateway must not be coded against a projection
that emits per-op/per-prefix S3 grants unless one actually does.

What a typical control plane already has: role-based access control with bucket-entity CRUD
permissions only (no data-plane verb, no object-prefix scope anywhere in the grant model); a
per-organization bundle carrying `tenants.<tenant>.user_attributes`,
`tenants.<tenant>.bucket_attributes` (denylist + `sensitivity`) and `org_settings.freeze_writes`,
polled by an in-backend defense-in-depth policy; and OIDC identity, per-organization realms, with
subjects keyed by the OIDC `sub`. Temporary S3 credentials are commonly brokered through the
backend's `AssumeRoleWithWebIdentity`, which delivers a backend-decorated session identity.

What already exists here: `policy/gateway/authz.rego` (deny-by-default; membership necessary but
not sufficient; an explicit grant must match `(action, bucket, object|prefix)`), the OPA input
(`src/authz/input.rs`), the STS authority (`src/auth/sts.rs`), bundle consumption
(`src/pdp/bundle.rs`, `src/bundle_refresh.rs`), and a golden decision corpus over hand-written
bundles in the target shape (`policy/testdata/corpus.json`, `tests/policy_corpus.rs`).

## Decision

### D1. Target grant shape the control plane MUST emit (normative)

The projection emits, per tenant slug, two additive maps whose values are arrays of one `Grant`
object type — exactly the contract `policy/gateway/authz.rego` consumes:

- `data.tenants[<tenant>].s3_grants[<oidc-sub>]  : [Grant]` — per-subject grants,
  **pre-expanded from roles** in the control plane.
- `data.tenants[<tenant>].group_grants[<group>]  : [Grant]` — per-group grants, resolved at
  decision time against `input.principal.attributes.groups` (`policy/gateway/authz.rego::grants`).

```jsonc
Grant := {
  "bucket":   "<bucket-name>" | "*",          // "*" = every bucket in the tenant
  "actions":  ["read_objects", ...] | ["*"],  // subset of the closed verb set, or ["*"]
  "prefixes": ["reports/2026/", ...]          // absent or [] ⇒ whole bucket
}
```

| Field | Type | Semantics (as implemented in `authz.rego`) |
|---|---|---|
| `bucket` | string | Exact bucket name within the tenant (`bucket_matches`), or the literal `"*"` for all buckets in the tenant. No globbing — `"*"` is a whole-field sentinel, not a pattern. |
| `actions` | array of string | Values drawn from the closed **6-verb** set (`src/model.rs::Action::as_str`): object-scoped `read_objects \| write_objects \| delete_objects \| write_object_tags`, listing `list_objects`, bucket- **and** account-scoped `read`; or the single-element `["*"]` (`action_matches`). Unknown verbs are a projection bug: they can never match and MUST be rejected at build time, not emitted. |
| `prefixes` | array of string | Raw object-key prefixes matched by `startswith(input.object, p)` (`object_in_scope`). Absent or empty ⇒ the grant scopes the whole bucket (`whole_bucket`). No wildcards, no regex; a `*` inside a prefix is a literal character. |

The vocabulary is data-plane only. There is no verb for creating, deleting or reconfiguring a
bucket, and none for object ACLs: a bucket made or re-configured through S3 has no control-plane
resource behind it, and an object ACL is access the control plane cannot revoke. `read` is the only
verb that is both bucket-scoped and account-scoped, which is why the rego gates every rule reading
it on the request shape.

The full **superset bundle** (target), with today's fields unchanged:

```jsonc
{
  "tenants": {
    "acme": {
      "user_attributes":   { "<oidc-sub>": { "groups": ["analysts"], "attributes": [] } },  // existing
      "bucket_attributes": { "data": { "denylist": { "<sub>": true },
                                       "sensitivity": "high" } },                           // existing
      "s3_grants": {                                                                         // new
        "<oidc-sub>": [
          { "bucket": "data", "actions": ["read_objects", "list_objects"],
            "prefixes": ["reports/2026/"] }
        ]
      },
      "group_grants": {                                                                      // new
        "analysts": [
          { "bucket": "data", "actions": ["*"], "prefixes": [] }
        ]
      }
    }
  },
  "org_settings": { "freeze_writes": false }                                                // existing
}
```

**Prefix normalization rules (the control plane MUST enforce at projection time):**

1. Prefixes are derived from the grant scope `/<tenant>/<bucket>/<prefix>` by stripping the
   `/<tenant>/<bucket>/` head; the emitted value is a bare key prefix (object keys never start
   with `/`).
2. Because matching is plain `startswith`, the prefix `"reports"` also matches `"reports-old/x"`.
   Folder-style scopes MUST therefore be emitted `/`-terminated (`"reports/"`); a
   non-`/`-terminated stem is allowed only as a deliberate choice, never as an accident of string
   handling.
3. An empty prefix after stripping means whole-bucket: emit `"prefixes": []` (or omit), never
   `"prefixes": [""]`.
4. The bucket- and account-scoped verb `read` ignores `prefixes` by design — the request carries no
   object key, so `authz.rego` checks only `(bucket, action)`. The projection MUST emit those grants
   with `"prefixes": []` so the data never implies a scoping the policy does not apply. This is
   sound only because `read` is its own verb: nothing here is reachable from a prefix-scoped
   `read_objects` grant.

**What is deliberately NOT in the shape:** no `s3_deny` / `s3_prefix_deny` / negative grants. The
deny surface stays the per-bucket `denylist`, the org-global `freeze_writes`, and — if needed later
— projected guardrails as OPA deny rules. Grants are purely additive; denies are separate mechanisms
evaluated ahead of grants (`authz.rego`: `allow` requires `not frozen`, `not denylisted`, `member`,
`grant_matches`).

### D2. Matching semantics are frozen by the gateway rego, not re-specified per team

`policy/gateway/authz.rego` is the single normative definition of what a grant means: membership
(`user_attributes` presence) is necessary but not sufficient; effective grants are the union of
`s3_grants[sub]` and `group_grants[g]` for each `g` in the principal's token groups; object ops
require the key under a granted prefix; list ops match a whole-bucket grant or overlap a prefix
grant, with narrowing obligations per ADR-004. The control plane writes the projection **against
that file**, and the shared acceptance gate is the golden corpus (D5) — not a prose re-statement
that could drift.

Three invariants follow directly from the rego and bind the projection:

- **Every granted sub MUST appear in `user_attributes`** for that tenant. A grant to a non-member is
  inert (`member` fails; deny reason `"deny: principal not a tenant member"`) — fail-closed but a
  silent product bug. Same for group grants.
- **Bucket visibility is what makes a bucket list non-empty.** Visibility is a response obligation
  (ADR-007) whose absent value means **nothing visible**, so a projection that emits object grants
  without granting enumeration produces a principal that can read and write its buckets and sees an
  empty `aws s3 ls`. The shipped module derives visibility from the grants a subject holds; the
  authoritative derivation, including subtraction of deny grants, is the projection's.
- **One group namespace.** Keys of `group_grants` MUST be byte-identical to the group strings in
  `user_attributes[sub].groups` and to the `groups` claim the STS mint copies from the OIDC token
  (`SessionClaims.groups`, `src/auth/sts.rs`). All three originate in the same identity provider, and
  the projection must not introduce a variant form (slug vs display name).

### D3. Delivery: the existing per-organization bundle grows to a superset — additively

- **Same endpoint, same builder, same gzip document.** One document serves both consumers: the
  in-backend defense-in-depth policy and this gateway (`src/bundle_refresh.rs`,
  `BundleSource::Http`).
- **Additive-only evolution.** `s3_grants` and `group_grants` sit under `tenants.<tenant>` next to
  the existing keys, which stay byte-for-byte what they are. Unknown data keys are inert in Rego, so
  the defense-in-depth policy's decisions cannot change — the control plane MUST still prove this
  with a regression test, because that rego also matches on request-time shapes the gateway never
  sees.
- **Revision semantics.** The gateway derives its bundle revision from the raw payload
  (`src/pdp/bundle.rs::content_revision`) and keys the decision cache on it, so any grant change
  lands as a new revision and every stale cached decision misses by construction — this is the
  live-revocation mechanism. Two consequences for the builder: (a) **every grant mutation MUST change
  the served bytes**, and the propagation SLO (build + gateway poll interval) is the documented
  revocation-latency bound; (b) serialization MUST be byte-stable for unchanged data (stable key
  order), so unchanged re-polls do not flap the revision and gratuitously empty the cache. A strong
  `ETag` is welcome but optional — content hashing already provides correctness.
- **One organization per document, per PDP.** `authz.rego` reads `data.org_settings.freeze_writes`
  at the top level and `BundleStore` holds one bundle. A gateway serving multiple organizations runs
  one engine+bundle per organization; nothing here namespaces organizations inside one document,
  deliberately.

### D4. STS identity: the gateway mints the identity, keyed by the bare OIDC `sub`

**The gateway mints its own sessions** (implemented, `src/auth/sts.rs`), and the control plane
**fronts the gateway's mint** instead of a backend STS. Reasoning:

1. **SigV4 forces it.** SigV4 verification recomputes an HMAC, so the verifier must hold or derive
   the plaintext secret for every principal. The gateway cannot derive the secret of a
   backend-minted session — those secrets are backend-internal — so fronting an existing backend
   broker could not terminate auth at the gateway at all.
2. **Portability settles direction.** A backend STS is disqualified by the constraint that the
   gateway must hold on any S3-compatible backend.

**The minted session (normative, as implemented in `src/auth/sts.rs`):**

- Access-key id `HFST<kid>.<sid>` (`STS_PREFIX`, `KID_SEP`); the `sid` is generated random at the
  mint endpoint (≥128-bit entropy — R5) and the `kid` names the master key that derived the secret.
  Decomposition splits on the **first** separator, so a `sid` may contain one and a `kid` may not
  (enforced in `StsAuthority::with_key_ring`).
- Secret `= hex(HMAC-SHA256(master_keys[kid], kid ‖ 0x00 ‖ sid))` (`derive_secret`) —
  deterministic, no per-session secret at rest, no hot-path store lookup. The `kid` is inside the
  MAC message as well as selecting the key, so the same material filed under two ids yields two
  distinct secrets and retiring an id is a real revocation.
- Claims ride in a signed HS256 token in `X-Amz-Security-Token`
  (`SessionClaims { sub, typ, groups, tenant, org, sid, exp }`), MAC'd with a **signing key distinct
  from every master key** (all ≥32 bytes, enforced in `StsAuthority::with_key_ring`) and bound to
  the access-key id (`verify_session` rejects `claims.sid != sid`, expired tokens, a `kid` no longer
  in the ring, and a JWS `kid` header that disagrees with the access-key id's).
- The response triple is `AssumeRoleWithWebIdentity`-shaped (`SessionCredentials`), so the `aws`
  CLI / SDKs / rclone work unchanged.
- **Revocation stays live in policy, not in the credential**: an unexpired session whose grant was
  revoked denies at the PDP on the next request, because the bundle revision moved (D3). There is
  deliberately no session kill-list; the per-principal levers are `denylist`, membership removal and
  `freeze_writes`.

**Identity shape and keying.** A backend's decorated rendering (a `$oidc$`-prefixed, optionally
tenant-qualified form) is just its way of writing "OIDC subject `sub`, in tenant `<tenant>`". The
gateway carries that identity as the **bare OIDC `sub` plus an explicit `tenant` claim** and keys
everything on the bare `sub`: `SessionClaims.sub` → `input.principal.sub`
(`src/identity.rs::to_opa_principal`) → `data.tenants[t].user_attributes[sub]` / `s3_grants[sub]` →
audit `requested_by` (ADR-002 D2). The projection therefore keys `s3_grants` by bare `sub`, exactly
as `user_attributes` already is. Where a transitional component needs the decorated form the mapping
is mechanical, but no gateway data structure stores it.

**The mint endpoint contract:**

- Request: an OIDC token from the caller's tenant provider, plus the requested `tenant` slug and TTL.
- Gateway-side validation before `StsAuthority::mint`: issuer = that tenant's provider, signature
  via the provider JWKS, `exp`/`aud` per agreed conventions; claims mapping `sub → sub` (bare),
  `groups → groups`; `org` from the gateway's per-organization deployment identity (the same trusted
  source ADR-002 uses for the org label); optional fast-fail membership check against the current
  bundle — a UX nicety only, since the PDP's `member` rule is authoritative on every request.
- TTL: default 1 hour, hard cap 12 hours (configurable). The cap is load-bearing: group membership
  rides in the token, so **group-revocation latency equals remaining TTL** (R4).
- Consumers: humans, agents, and per-query engine credentials — one mint path for every consumer
  class, each session carrying the end-user `sub`.

### D5. Sequencing: hand-written bundle now, projection swap behind an acceptance gate

- **Phase 0 (this repository — unblocked):** the gateway develops and tests against hand-written
  bundles in the D1 shape (`BundleSource::File`, `policy/testdata/corpus.json`). The corpus doubles
  as the executable specification of D1/D2 handed to the control-plane team.
- **Phase 1 (projection lands):** the control plane emits the superset bundle; a staging gateway
  flips to `BundleSource::Http`. **Acceptance gate:** (a) the golden corpus replays against a
  control-plane-emitted bundle with identical decisions, through both PDP engines (grant data is
  pure data, so it cannot introduce non-regorus builtins; the constraint stays on rego changes);
  (b) the defense-in-depth policy's regression test passes.
- **Phase 2 (identity cutover):** the control plane repoints its user-credential flow to the gateway
  mint and its object routes to the gateway endpoint; the backend-STS leg is scheduled for
  decommission under ADR-001's exposure closure.
- **Until Phase 1 completes, no production enforcement claim is made.** Without
  `s3_grants`/`group_grants` the gateway denies every object op — fail-closed by construction
  (`default allow := false`), which is the safe failure direction but also means the gateway is not
  usable, only safe.

## Alternatives considered

- **A1 — Code the gateway against a membership+denylist projection to ship sooner.** Rejected:
  bucket-granular membership is exactly the model the gateway exists to surpass.
- **A2 — Extend the existing defense-in-depth rego instead of defining a new grant contract.**
  Rejected: it has no prefix/op matching to port; the gateway rego is net-new and the in-backend
  policy stays as-is as the direct-path layer (ADR-001).
- **A3 — Project raw hierarchical resource-name grants + prefix-cascade and evaluate the cascade in
  gateway rego.** Rejected: the control plane must extend its model regardless, and projecting the
  finished flat shape keeps role/group expansion off the request hot path, keeps the gateway rego
  inside the regorus subset, and avoids importing control-plane path semantics into data-plane
  decisions. The hierarchical model remains the source; D1 is its projection.
- **A4 — A gateway-owned grants API or database instead of the bundle.** Rejected: the bundle
  revision is what makes the decision cache and live revocation correct by construction; an
  RPC-per-decision design would reintroduce the invalidation problem.
- **A5 — A second, separate bundle endpoint for the gateway.** Rejected: two builders over one
  grants source is the drift scenario in miniature — divergence *is* a bypass. Revisit only if
  superset size measurably burdens the backend-side OPA (R6), and then as a filtered *view* from the
  same builder.
- **A6 — Bake scopes into the credential (AWS-style session policy).** Rejected: no policy in
  credentials means live revocation and no session-policy size cap, and enforcement in gateway
  policy holds even on a "dumb" S3 backend.
- **A7 — Front an existing backend STS broker rather than minting.** Rejected: the gateway cannot
  derive backend session secrets, so it could not verify SigV4 — fronting fails technically, not
  just architecturally. The control-plane-facing half survives inverted: token-exchange fronts the
  gateway's mint (D4).
- **A8 — Random per-session secrets in a store instead of derivation.** Rejected: a store adds a
  hot-path dependency and a secrets-at-rest liability for zero policy benefit — revocation lives in
  policy either way.

## Consequences

**What must hold for the security claim** (object-level authorization per end-user):

- **I1 — No grant, no access.** `default allow := false` and membership-not-sufficient in
  `authz.rego`; the projection never emits implicit whole-tenant or whole-org grants — every allow
  traces to an explicit `Grant` an admin can point at.
- **I2 — One `sub` namespace.** Bundle keys (`user_attributes`, `s3_grants`), session claims
  (`SessionClaims.sub`), OPA input (`principal.sub`) and audit (`requested_by`) all carry the bare
  OIDC `sub`. Any decorated or aliased form anywhere breaks matching fail-closed (silent deny).
- **I3 — One group namespace** (D2): `group_grants` keys ≡ `user_attributes[…].groups` entries ≡
  token `groups` claims, byte-identical.
- **I4 — Revocation latency is bounded and known**: grant mutation → bundle bytes change → new
  `content_revision` → cache miss (D3). The bound is builder latency + gateway poll interval.
- **I5 — Key custody.** The STS master keys derive every session secret; the `signing_key`
  authenticates every claims token. Compromise of a master key ≈ mint authority. They are distinct
  by construction (`StsAuthority`), must be provisioned from a secrets manager/KMS, and never leave
  the gateway. Master-key rotation is online — add a `kid`, repoint `current_kid`, wait one
  `session_ttl_secs`, drop the old entry (procedure in `src/auth/sts.rs`). **Signing-key rotation is
  not online**: the token names its master key but not its signing key, so replacing the signing key
  invalidates every live session. Rotate it in a window, or add a JWS-header-selected signing ring
  first.
- **I6 — Credential domains stay disjoint.** The gateway honors only its own credential namespaces
  (`src/auth/mod.rs`); backend-minted or tenant-owner creds are unknown access-key ids at the
  gateway, and gateway creds are meaningless at the backend. Cross-domain reach is the direct-path
  exposure, dispositioned in ADR-001.

**Risks and follow-ups:**

- **R1 — The gateway is deny-everything on bundles without the projection.** Fail-closed but
  unusable. Interim demos run on hand-written bundles only (D5 Phase 0) and must not be represented
  as enforcing production grants.
- **R2 — Projection correctness is a security surface.** A projection bug that over-emits (wrong
  sub, over-broad prefix, stray `"*"`) grants real access. Mitigations: build-time validation, the
  corpus acceptance gate (D5), and the audit trail (ADR-002).
- **R3 — Prefix-stem pitfall.** `startswith` semantics mean an un-normalized stem grant captures
  sibling keys (`"reports"` ⊃ `"reports-old/…"`). Normalization is normative (D1 rule 2); a
  projection test must enforce it.
- **R4 — Group revocation lags by session TTL.** Grant expansion reads token groups, not bundle
  groups (`authz.rego::grants`), so removing a user from a group takes effect at session expiry —
  hence the 1h default TTL (D4). Immediate levers: membership removal, per-bucket `denylist`,
  `freeze_writes`. A decision-changing follow-up would intersect token groups with the bundle's
  `user_attributes[sub].groups`; it must go through the dual-engine corpus gate first, since it
  narrows decisions.
- **R5 — `sid` entropy is load-bearing.** The derived secret is only as unpredictable as the `sid`
  (the endpoint supplies it; `mint` accepts caller-fixed sids for testability). The endpoint must
  use ≥128-bit CSPRNG sids.
- **R6 — Bundle growth.** Per-subject role expansion multiplies (subjects × grants); prefer
  `group_grants` for cohorts to bound size. Watch gzipped size against the backend-side OPA and
  gateway memory; A5's filtered-view escape hatch exists if needed.
- **R7 — Control-plane-proxied traffic still bypasses the gateway until Phase 2.** The live broker
  path (control plane → backend STS → backend) is a direct path under ADR-001's inventory; this ADR
  provides its replacement (D4), ADR-001 owns its closure.

## Control-plane integration (out of scope for this repository)

- **Extend the permission catalog** with the operation family mapping 1:1 to the frozen gateway
  verbs (`src/model.rs::Action`) and an object-prefix scope on grants (`/<tenant>/<bucket>/<prefix>`).
- **Build the projection** emitting D1 exactly: roles pre-expanded into `s3_grants[sub]`;
  `group_grants[group]` keyed by the canonical group form; build-time validation — actions ⊆ closed
  set or `["*"]`; bucket = name or `"*"`; prefixes bare, never `""`, `/`-terminated unless a stem is
  intended; account-scoped grants ⇒ `prefixes: []`; every granted sub present in `user_attributes`.
- **Grow the bundle additively**: new keys under `tenants.<tenant>` only; existing keys unchanged;
  a regression test proving the defense-in-depth policy's decisions are identical on the superset
  bundle.
- **Endpoint semantics**: same per-organization route, gzip; byte-stable serialization for unchanged
  data; every grant mutation changes the served bytes; publish and monitor the build+propagation
  freshness SLO (= the revocation-latency bound).
- **Keep `user_attributes[sub].groups` authoritative and fresh** — it is the membership source and
  the target of the R4 tightening.
- **Repoint the STS flow**: user-credential resolution and object browse/upload/delete routes mint
  gateway sessions via the gateway STS and target the gateway's S3 endpoint; schedule the
  backend-STS leg for decommission with ADR-001.
- **Publish OIDC verification parameters per tenant** (issuer, JWKS URI, audience / token-exchange
  conventions) for the gateway mint, and agree the `AssumeRoleWithWebIdentity`-shaped mint API
  surface.
- **Contribute control-plane-emitted bundle fixtures + expected decisions** to the golden corpus, so
  D5's acceptance gate and the dual-engine parity gate run on real projection output in CI.
- **Explicit non-goal sign-off**: guardrails-on-S3 and `sensitivity` enforcement stay out of this
  contract; when productized they arrive as additional projected deny data + rego, through the same
  corpus gate.
