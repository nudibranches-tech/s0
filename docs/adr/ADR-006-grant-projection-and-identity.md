# ADR-006: Grant projection contract and STS identity

- **Status**: Proposed
- **Date**: 2026-07-15
- **Owners**: gateway team (this repository); the grant projection and the identity cutover are control-plane integration (out of scope for this repository)
- **Scope**: Freezes the two external contracts the gateway consumes but does not build:
  (1) the data-plane grant projection into the per-organization policy bundle, and
  (2) the STS identity the gateway mints and the control plane fronts. Consistent with the
  settled invariants and the engines-through-gateway posture; it does not reopen them.
- **Related**: `policy/gateway/authz.rego`, `src/authz/input.rs`, `src/auth/sts.rs`,
  `src/auth/mod.rs`, `src/identity.rs`, `src/pdp/bundle.rs`, `src/bundle_refresh.rs`,
  `src/model.rs`; ADR-001 (direct-path closure, drift control), ADR-002 (audit record shape),
  ADR-004 (list narrowing)

## Context

The gateway's premise is to **consume granular grants** — and today those grants do not yet
exist on the control-plane side. The data-plane grant (object operations plus an object-prefix
scope `/<tenant>/<bucket>/<prefix>`, and its projection into the gateway's policy data) is
**planned, external** work: it is what the gateway's whole premise depends on. The gateway must
not be coded against a projection that emits per-op/per-prefix S3 grants today, because none
does yet.

### What exists on the control-plane side

- **Role-based access control** (implemented): a typed permission catalog, roles and groups
  expanding into per-subject grants, hierarchical scope paths with ancestor prefix-cascade,
  projected into the control-plane RBAC policy (external) for **control-plane API**
  authorization. Data-plane bucket permissions are **bucket-entity CRUD only**
  (`bucket:create | bucket:read | bucket:update | bucket:delete`): there is **no**
  `read_objects | list_objects | write_objects | delete_objects | manage_lifecycle`
  permission, and **no object-prefix scope** anywhere in the grant model.
- **The per-organization bundle** (implemented): a gzipped document polled by a
  per-organization OPA running the in-backend defense-in-depth policy (external). The real data
  shape carries exactly `tenants.<tenant>.user_attributes`, `tenants.<tenant>.bucket_attributes`
  (denylist + `sensitivity`, the latter carried but not yet enforced), and
  `org_settings.freeze_writes`. There is **no** `s3_grants`, `s3_prefix_grants`, `s3_deny`,
  `s3_prefix_deny`, `native_principals`, or `tenant_owner_uid`.
- **Today's defense-in-depth rule** (implemented): membership + denylist, not grants — **no
  per-operation and no per-prefix logic exists**. There is nothing in it to "port" for
  prefix/op matching; the gateway policy is net-new.
- **Identity** (implemented): per-organization realms on an OIDC provider (e.g. Keycloak);
  subjects are the OIDC `sub`. The control plane already brokers temporary S3 credentials via
  the backend's `AssumeRoleWithWebIdentity`; the minted session identity arrives at the backend
  in a backend-specific decorated form. **This is the STS-identity-into-policy model the gateway
  wants, and it is already live** in that backend-coupled form — the gateway either mints the
  same identity shape itself or fronts the existing broker.

### What exists in this repository (the consumer side is already coded)

- `policy/gateway/authz.rego` — the net-new gateway policy. Deny-by-default; membership
  necessary but **not** sufficient; an explicit grant must match `(action, bucket, object|prefix)`.
  Its header documents the exact data contract this ADR makes normative:
  `data.tenants[t].s3_grants[sub]` and `data.tenants[t].group_grants[group]`, both arrays of
  `{bucket, actions[], prefixes[]}`, alongside the **reused** existing data (`user_attributes`,
  `bucket_attributes.denylist`, `org_settings.freeze_writes`).
- `src/authz/input.rs` — the OPA input the grants are matched against (`principal.sub`,
  `principal.attributes.groups`, `tenant`, `action`, `bucket`, `object?`, `prefix?`, …).
- `src/auth/sts.rs` — the STS authority: `HFST`-prefixed access-key ids, secrets derived as
  `hex(HMAC-SHA256(master, sid))` with no per-session secret at rest, a signed session-claims
  token (`sub`, `typ`, `groups`, `tenant`, `org`, `sid`, `exp`) bound to the access-key id,
  distinct master/signing keys. `src/auth/mod.rs` wires it into `S3Auth` next to the static
  credential store; `src/identity.rs` carries the resolved end-user identity to the typed hooks.
- `src/pdp/bundle.rs` + `src/bundle_refresh.rs` — bundle consumption: hot-swappable
  `BundleStore`, `content_revision` derived from the raw payload (the decision-cache key half),
  poll-and-reload from `BundleSource::Http` (the control-plane endpoint) or `BundleSource::File`
  (local dev).
- `policy/testdata/corpus.json` + `tests/policy_corpus.rs` — golden decision corpus over
  hand-written bundles in the target shape.

### What is planned

- **Control plane (external):** the object-op permission family, the prefix-scoped grant, the
  projection that expands roles/groups into the shape above, and the superset bundle that
  carries it. Also: repointing the live STS broker at the gateway.
- **This repository (follow-ups):** the mint HTTP endpoint that verifies an OIDC token against
  the tenant's provider before calling `StsAuthority::mint` (the authority and the derivation of
  minted credentials exist; the OIDC-facing endpoint does not), and flipping production config
  from `BundleSource::File` to `BundleSource::Http`.

This ADR exists so the gateway and the control plane build against one frozen contract: the
data-plane grant model and projection are greenfield control-plane work, sequenced with a
hand-written bundle so the gateway is not blocked, swapping to the real projection when it lands.

## Decision

### D1. Target grant shape the control plane MUST emit (normative)

The projection emits, per tenant slug, two additive maps whose values are arrays of one `Grant`
object type — exactly the contract `policy/gateway/authz.rego` already consumes:

- `data.tenants[<tenant>].s3_grants[<oidc-sub>]  : [Grant]` — per-subject grants,
  **pre-expanded from roles** in the control plane (roles and groups already expand into
  per-subject grants there; the projection reuses that expansion).
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
| `actions` | array of string | Values drawn from the closed set `read_objects \| list_objects \| write_objects \| delete_objects \| manage_lifecycle` (`src/model.rs::Action::as_str`), or the single-element `["*"]` (`action_matches`). Unknown verbs are a projection bug: they can never match and MUST be rejected at build time, not emitted. |
| `prefixes` | array of string | Raw object-key prefixes matched by `startswith(input.object, p)` (`object_in_scope`). Absent or empty ⇒ the grant scopes the whole bucket (`whole_bucket`). No wildcards, no regex; a `*` inside a prefix is a literal character. |

The full **superset bundle** (target), with today's fields unchanged:

```jsonc
{
  "tenants": {
    "acme": {
      "user_attributes":   { "<oidc-sub>": { "groups": ["analysts"], "attributes": [] } },  // implemented
      "bucket_attributes": { "data": { "denylist": { "<sub>": true },
                                       "sensitivity": "high" } },                           // implemented
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
  "org_settings": { "freeze_writes": false }                                                // implemented
}
```

**Prefix normalization rules (the control plane MUST enforce at projection time):**

1. Prefixes are derived from the grant scope `/<tenant>/<bucket>/<prefix>` by stripping the
   `/<tenant>/<bucket>/` head; the emitted value is a bare key prefix (object keys never start
   with `/`).
2. Because matching is plain `startswith`, the prefix `"reports"` also matches `"reports-old/x"`.
   Folder-style scopes MUST therefore be emitted `/`-terminated (`"reports/"`); emitting a
   non-`/`-terminated stem is allowed only as an explicit, deliberate choice, never as an
   accident of string handling.
3. An empty prefix after stripping means whole-bucket: emit `"prefixes": []` (or omit), never
   `"prefixes": [""]`.
4. `manage_lifecycle` (and other keyless bucket-level ops) ignores `prefixes` by design —
   `authz.rego`'s bucket-level rule checks only `(bucket, action)`. The projection MUST emit
   `manage_lifecycle` grants with `"prefixes": []` so the data never implies a scoping the
   policy does not apply.

**What is deliberately NOT in the shape:** no `s3_deny` / `s3_prefix_deny` / negative grants.
The deny surface stays what it is today: the per-bucket `denylist`, the org-global
`freeze_writes`, and — if the product needs them later — projected guardrails as OPA deny rules
(out of scope here). Grants are purely additive; denies are separate, existing mechanisms
evaluated ahead of grants (`authz.rego`: `allow` requires `not frozen`, `not denylisted`,
`member`, `grant_matches`).

### D2. Matching semantics are frozen by the gateway rego, not re-specified per team

`policy/gateway/authz.rego` is the single normative definition of what a grant means:
membership (`user_attributes` presence) is necessary but not sufficient; effective grants are
the union of `s3_grants[sub]` and `group_grants[g]` for each `g` in the principal's token
groups; object ops require the key under a granted prefix; list ops match a whole-bucket grant
or overlap a prefix grant, with narrowing obligations per ADR-004. The control plane writes the
projection **against that file**, and the shared acceptance gate is the golden corpus (D5) —
not a prose re-statement that could drift (ADR-001's drift-control logic applied to this
contract).

Two membership invariants follow directly from the rego and bind the projection:

- **Every granted sub MUST appear in `user_attributes`** for that tenant. A grant to a
  non-member is inert (`member` fails; deny reason `"deny: principal not a tenant member"`) —
  fail-closed but a silent product bug. Same for group grants: they only take effect for tenant
  members.
- **One group namespace.** Keys of `group_grants` MUST be byte-identical to the group strings
  the control plane puts in `user_attributes[sub].groups` and to the `groups` claim the STS mint
  copies from the OIDC token into the session (`SessionClaims.groups`, `src/auth/sts.rs`) — all
  three originate in the same OIDC provider and control-plane model, and the projection must not
  introduce a variant form (slug vs display name).

### D3. Delivery: the existing per-organization bundle grows to a superset — additively

The gateway reuses the existing bundle delivery mechanism and builder; the projection extends
the data.

- **Same endpoint, same builder, same gzip document.** The per-organization bundle endpoint
  serves one document that both consumers poll — the per-organization OPA running the in-backend
  defense-in-depth policy (external) and this gateway (`src/bundle_refresh.rs`,
  `BundleSource::Http`).
- **Additive-only evolution.** The new keys (`s3_grants`, `group_grants`) sit under
  `tenants.<tenant>` next to the existing ones; `user_attributes`, `bucket_attributes`, and
  `org_settings.freeze_writes` are byte-for-byte what they are today. Unknown data keys are inert
  in Rego, so the defense-in-depth policy's decisions cannot change — the control plane MUST
  still prove this with a regression test over the superset bundle, because that rego also
  matches on request-time shapes the gateway never sees.
- **Revision semantics.** The gateway derives its bundle revision from the raw payload
  (`src/pdp/bundle.rs::content_revision`) and keys the decision cache on it, so any grant change
  lands as a new revision and every stale cached decision misses by construction — this is the
  live-revocation mechanism. Two consequences for the builder: (a) **every grant mutation MUST
  change the served bytes** (no lossy or delayed projection), and the propagation SLO (build +
  gateway poll interval) is the documented revocation-latency bound; (b) serialization MUST be
  byte-stable for unchanged data (stable key order), so unchanged re-polls do not flap the
  revision and gratuitously empty the cache. A strong `ETag` is welcome but optional — content
  hashing already provides correctness.
- **One organization per document, per PDP.** `authz.rego` reads
  `data.org_settings.freeze_writes` at the top level; the gateway loads exactly one
  organization's bundle per engine (`BundleStore` holds one bundle). A gateway instance serving
  multiple organizations runs one engine+bundle per organization; nothing in this contract
  namespaces organizations inside one document, deliberately.

### D4. STS identity: the gateway mints the identity, keyed by the bare OIDC `sub`

There are two routes — front the existing broker, or mint the same `sub`-bearing session.
**Decision: the gateway mints its own sessions** (implemented, `src/auth/sts.rs`), and the
control plane **fronts the gateway's mint** instead of a backend STS. Reasoning:

1. **SigV4 forces it.** SigV4 verification recomputes an HMAC, so the verifier must hold or
   derive the plaintext secret for every principal. The gateway cannot derive the secret of a
   backend-minted session — those secrets are backend-internal — so fronting the existing broker
   could not terminate auth at the gateway at all.
2. **Portability settles direction.** The backend's `AssumeRoleWithWebIdentity` broker is a
   backend-specific convenience the gateway **supersedes**, not a dependency; a backend STS is
   disqualified for authorization by the portability constraint that the gateway must hold on any
   S3-compatible backend.

**The minted session (normative, as implemented in `src/auth/sts.rs`):**

- Access-key id `HFST<kid>.<sid>` (`STS_PREFIX`, `KID_SEP`); the `sid` is generated random at the
  mint endpoint (≥128-bit entropy — R5) and the `kid` names the master key that derived the
  secret. Decomposition splits on the **first** separator, so a `sid` may contain one and a
  `kid` may not (enforced in `StsAuthority::with_key_ring`).
- Secret `= hex(HMAC-SHA256(master_keys[kid], kid ‖ 0x00 ‖ sid))` (`derive_secret`) —
  deterministic, no per-session secret at rest, no hot-path store lookup; `S3Auth::get_secret_key`
  re-derives from the access-key id alone (`secret_for_access_key`, wired in `src/auth/mod.rs`).
  The `kid` is inside the MAC message as well as selecting the key, so the same material filed
  under two ids yields two distinct secrets and retiring an id is a real revocation.
- Claims ride in a signed HS256 token in `X-Amz-Security-Token`
  (`SessionClaims { sub, typ, groups, tenant, org, sid, exp }`), MAC'd with a **signing key
  distinct from every master key** (all ≥32 bytes, enforced in `StsAuthority::with_key_ring`) and
  bound to the access-key id (`verify_session` rejects `claims.sid != sid`, expired tokens, a
  `kid` no longer in the ring, and a JWS `kid` header that disagrees with the access-key id's).
- The response triple is `AssumeRoleWithWebIdentity`-shaped (`SessionCredentials`), so the `aws`
  CLI / SDKs / rclone work unchanged.
- **Revocation stays live in policy, not in the credential**: an unexpired session whose grant
  was revoked denies at the PDP on the next request, because the bundle revision moved (D3).
  There is deliberately no session kill-list; the per-principal emergency levers are the existing
  `denylist` / membership removal / `freeze_writes`.

**Identity shape and keying.** The session's identity is the same identity the live broker mints
— the backend's decorated rendering (a `$oidc$`-prefixed, optionally tenant-qualified form) is
just the backend's way of writing "OIDC subject `sub`, in tenant `<tenant>`". The gateway carries
that identity as the **bare OIDC `sub` plus an explicit `tenant` claim** and keys everything on
the bare `sub`: `SessionClaims.sub` → `input.principal.sub` (`src/identity.rs::to_opa_principal`)
→ `data.tenants[t].user_attributes[sub]` / `s3_grants[sub]` → audit `requested_by` (ADR-002 D2
already fixes this: the decorated form is a backend identity artifact the gateway supersedes).
The projection therefore keys `s3_grants` by bare `sub`, exactly as `user_attributes` already is
today. Where any transitional component needs the backend's decorated form, the mapping is
mechanical — but no gateway data structure stores it. This keeps decisions and audit lined up on
one identity across the platform.

**The mint endpoint contract (follow-up F1):**

- Request: an OIDC token from the caller's tenant provider (obtained directly or via the control
  plane's existing token-exchange, which stays — it must not be rebuilt), plus the requested
  `tenant` slug and TTL.
- Gateway-side validation before `StsAuthority::mint`: issuer = that tenant's provider, signature
  via the provider JWKS, `exp`/`aud` per agreed conventions; claims mapping `sub → sub` (bare),
  `groups → groups`; `org` from the gateway's per-organization deployment identity (the same
  trusted source ADR-002 uses for the org label); optional fast-fail membership check of `sub`
  against the current bundle's `tenants[tenant].user_attributes` — a UX nicety only, since the
  PDP's `member` rule is the authoritative check on every request.
- TTL: default 1 hour, hard cap 12 hours (configurable). The cap is load-bearing: group
  membership rides in the token, so **group-revocation latency equals remaining TTL** (R4).
- Consumers: humans (control-plane-proxied ops and CLI), AI agents (which get the same
  short-lived STS credentials), and per-query engine credentials — one mint path for every
  consumer class, each session carrying the end-user `sub`.

### D5. Sequencing: hand-written bundle now, projection swap behind an acceptance gate

- **Phase 0 (now, this repository — unblocked):** the gateway develops and tests against
  hand-written bundles in the D1 shape — `BundleSource::File` and `policy/testdata/corpus.json`
  already do this. The corpus doubles as the executable specification of D1/D2 handed to the
  control-plane team.
- **Phase 1 (projection lands):** the control plane emits the superset bundle; a staging gateway
  flips to `BundleSource::Http` against the real endpoint. **Acceptance gate:** (a) the golden
  corpus replays against a control-plane-emitted bundle with identical decisions, through both
  PDP engines (the dual-engine parity gate — note the grant data is pure data, so it cannot
  introduce non-regorus builtins; the constraint stays on rego changes); (b) the defense-in-depth
  policy's regression test passes.
- **Phase 2 (identity cutover):** the control plane repoints its user-credential flow to the
  gateway mint and its object routes to the gateway endpoint; the backend-STS leg is scheduled
  for decommission under ADR-001's exposure closure.
- **Until Phase 1 completes, no production enforcement claim is made.** With today's real bundle
  (no `s3_grants`/`group_grants`), the gateway denies every object op — fail-closed by
  construction (`default allow := false`; membership alone never suffices), which is the safe
  failure direction but also means the gateway is not usable, only safe.

## Alternatives considered

- **A1 — Code the gateway against today's projection (membership + denylist) to ship sooner.**
  Rejected: the gateway must not be coded against a projection that emits per-op/per-prefix S3
  grants today, because none does, and by mission — bucket-granular membership is exactly the
  model the gateway exists to surpass, since per-object / per-prefix is the point of this gateway.
- **A2 — Extend the existing defense-in-depth rego instead of defining a new grant contract.**
  Rejected: there is nothing in it to "port" for prefix/op matching; the gateway rego is net-new.
  The in-backend defense-in-depth policy (external) stays as-is as the direct-path layer
  (ADR-001).
- **A3 — Project raw hierarchical resource-name grants + prefix-cascade and evaluate the cascade
  in gateway rego.** Rejected. The control-plane catalog cannot express the grant at all today —
  no object-op verbs, no object-prefix scope anywhere in the grant model — so the control plane
  must extend its model regardless; given that, projecting the finished, flat, per-subject shape
  keeps role/group expansion out of the request hot path, keeps the gateway rego small (stay
  inside the regorus subset), and avoids importing control-plane path semantics into data-plane
  decisions. The hierarchical model remains the control-plane **source**; D1 is its **projection**.
- **A4 — A new, gateway-owned grants API or database instead of the bundle.** Rejected: reuse the
  existing delivery mechanism and builder rather than rebuilding the grant model; and the bundle
  revision is what makes the decision cache and live revocation correct by construction — an
  RPC-per-decision design would reintroduce the invalidation problem the revision key eliminates.
- **A5 — A second, separate bundle endpoint for the gateway.** Rejected: two builders over one
  grants source is the drift scenario in miniature — divergence *is* a bypass. Additive superset
  keys are inert to the defense-in-depth policy, so one document serves both consumers. Revisit
  only if superset size measurably burdens the backend-side OPA (R6) — and then as a filtered
  *view* from the same builder, never a second builder.
- **A6 — Bake scopes into the credential (AWS-style session policy) instead of projecting
  grants.** Rejected: no policy baked into credentials means live revocation and no
  session-policy size cap, and enforcement lives in gateway policy so it holds even on a "dumb"
  S3 backend.
- **A7 — Front an existing backend STS broker rather than minting.** Rejected: the gateway cannot
  derive backend session secrets, so it could not verify SigV4 — fronting fails technically, not
  just architecturally; plus the gateway supersedes the backend broker rather than depending on
  it, and must not depend on backend-native features. The control-plane-facing half survives
  inverted: control-plane token-exchange now fronts the **gateway's** mint (D4).
- **A8 — Random per-session secrets in a store instead of derivation.** Rejected: derive the
  session secret deterministically — no per-session secret at rest, no hot-path store lookup —
  implemented accordingly in `src/auth/sts.rs`. A store would add a hot-path dependency and a
  secrets-at-rest liability for zero policy benefit — revocation lives in policy either way.

## Consequences

**What must hold for the security claim** (object-level authorization per end-user):

- **I1 — No grant, no access.** `default allow := false` and membership-not-sufficient in
  `authz.rego`; the projection never emits implicit whole-tenant or whole-org grants — every
  allow traces to an explicit `Grant` a control-plane admin can point at.
- **I2 — One `sub` namespace.** Bundle keys (`user_attributes`, `s3_grants`), session claims
  (`SessionClaims.sub`), OPA input (`principal.sub`), and audit (`requested_by`) all carry the
  bare OIDC `sub` from the tenant's provider. Any decorated or aliased form anywhere breaks
  matching fail-closed (silent deny) at best.
- **I3 — One group namespace** (D2): `group_grants` keys ≡ `user_attributes[…].groups` entries ≡
  token `groups` claims, byte-identical.
- **I4 — Revocation latency is bounded and known**: grant mutation → bundle bytes change → new
  `content_revision` → cache miss (D3). The bound is builder latency + gateway poll interval, and
  it is the policy-freshness bound; the control plane documents and monitors it.
- **I5 — Key custody.** The STS master keys derive every session secret; the `signing_key`
  authenticates every claims token. Compromise of a master key ≈ mint authority. They are
  distinct by construction (`StsAuthority`) and must be provisioned from a secrets manager/KMS;
  they never leave the gateway (credentials never leave the site). Master-key rotation is
  online — add a `kid`, repoint `current_kid`, wait one `session_ttl_secs`, drop the old entry
  (procedure in `src/auth/sts.rs`). **Signing-key** rotation is not yet online: the token names
  its master key but not its signing key, so replacing the signing key invalidates every live
  session. Rotate it in a window, or add a JWS-header-selected signing ring first.
- **I6 — Credential domains stay disjoint.** The gateway honors only `HFST` sessions and its own
  static store (`src/auth/mod.rs`); backend-minted or tenant-owner creds are unknown access-key
  ids at the gateway (auth fail), and gateway creds are meaningless at the backend. Cross-domain
  reach = the direct-path exposure, dispositioned in ADR-001, not here.

**Risks and follow-ups:**

- **R1 — The gateway is deny-everything on real bundles until the projection lands.** Fail-closed
  but unusable; the whole plan gates on the control-plane projection work. Interim demos/pilots
  run on hand-written bundles only (D5 Phase 0) and must not be represented as enforcing
  production grants.
- **R2 — Projection correctness is now a security surface.** A projection bug that over-emits
  (wrong sub, over-broad prefix, stray `"*"`) grants real access. Mitigations: build-time
  validation (closed action set, normalized prefixes, member invariant), the corpus acceptance
  gate (D5), and the audit trail (every allow carries the matched request context per ADR-002, so
  over-grants are at least visible).
- **R3 — Prefix-stem pitfall.** `startswith` semantics mean an un-normalized stem grant captures
  sibling keys (`"reports"` ⊃ `"reports-old/…"`). Normalization is normative (D1 rule 2); a
  projection test must enforce it.
- **R4 — Group revocation lags by session TTL.** Grant expansion reads token groups, not bundle
  groups (`authz.rego::grants`), so removing a user from a group takes effect at session expiry —
  hence the 1h default TTL (D4). Immediate levers exist (membership removal kills `member`;
  per-bucket `denylist`; `freeze_writes`). **F3 (follow-up, decision-changing):** tighten rego to
  intersect token groups with the bundle's `user_attributes[sub].groups` — must go through the
  dual-engine corpus gate before shipping, since it narrows decisions.
- **R5 — `sid` entropy is load-bearing.** The derived secret is only as unpredictable as the
  `sid` (the endpoint supplies it; `mint` accepts caller-fixed sids for testability). F1 mandates
  ≥128-bit CSPRNG sids at the endpoint.
- **R6 — Bundle growth.** Per-subject role expansion multiplies (subjects × grants); prefer
  `group_grants` for cohorts to bound size. Watch gzipped size against the backend-side OPA and
  gateway memory; A5's filtered-view escape hatch exists if needed.
- **R7 — Control-plane-proxied traffic still bypasses the gateway until Phase 2.** The live broker
  path (control plane → backend STS → backend) is a direct path under ADR-001's inventory; this
  ADR provides its replacement (D4), ADR-001 owns its closure.

**Follow-ups in this repository:** **F1** — mint endpoint with per-tenant OIDC verification and
CSPRNG sids (D4). **F2** — master/signing key provisioning + rotation runbook (I5). **F3** —
group-intersection rego tightening decision (R4). **F4** — production config flips
`BundleSource::File` → `Http` with poll interval set from the freshness SLO.

## Control-plane integration (out of scope for this repository)

These items are implemented by the control plane against this repository's policy and identity
contracts.

- **Extend the permission catalog** with the object-operation family mapping 1:1 to the five
  gateway actions (`read_objects`, `list_objects`, `write_objects`, `delete_objects`,
  `manage_lifecycle`) and an object-prefix scope on grants (`/<tenant>/<bucket>/<prefix>`).
- **Build the projection** emitting D1 exactly: roles pre-expanded into `s3_grants[sub]`;
  `group_grants[group]` keyed by the canonical group form; build-time validation — actions ⊆
  closed set or `["*"]`; bucket = name or `"*"`; prefixes bare, never `""`, `/`-terminated unless
  a stem is intended; `manage_lifecycle` ⇒ `prefixes: []`; every granted sub present in
  `user_attributes` (D2 invariants).
- **Grow the bundle additively**: new keys under `tenants.<tenant>` only; `user_attributes` /
  `bucket_attributes` / `org_settings.freeze_writes` unchanged; a regression test proving the
  defense-in-depth policy's decisions are identical on the superset bundle.
- **Endpoint semantics**: same per-organization route, gzip; byte-stable serialization for
  unchanged data (the gateway hashes content for its cache-key revision, D3); every grant mutation
  changes the served bytes; publish and monitor the build+propagation freshness SLO (= the
  revocation-latency bound).
- **Keep `user_attributes[sub].groups` authoritative and fresh** — it is the membership source
  and the target of the R4/F3 tightening.
- **Repoint the STS flow**: the control plane's user-credential resolution (and its object
  browse/upload/delete routes) mint gateway sessions via the gateway STS and target the gateway's
  S3 endpoint — humans and AI agents alike; schedule the backend-STS leg for decommission with
  ADR-001.
- **Publish OIDC verification parameters per tenant** (issuer, JWKS URI, audience / token-exchange
  conventions) for the gateway mint (F1), and agree the `AssumeRoleWithWebIdentity`-shaped mint
  API surface.
- **Contribute control-plane-emitted bundle fixtures + expected decisions** to the golden corpus,
  making D5's acceptance gate and the dual-engine parity gate run on real projection output in CI.
- **Explicit non-goal sign-off**: guardrails-on-S3 and `sensitivity` enforcement stay out of this
  contract; when productized they arrive as additional projected deny data + rego, through the
  same corpus gate.
