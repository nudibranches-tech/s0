# ADR-006: Companion platform work — data-plane grant projection and STS identity

- **Status**: Proposed
- **Date**: 2026-07-15
- **Owners**: gateway team (this repo); companion work: console/platform team
- **Scope**: Freezes the two platform-side contracts the gateway consumes but does not build:
  (1) the data-plane grant projection into the per-Org OPA bundle (PROMPT §3.3–§3.4), and
  (2) the STS identity the gateway mints and the platform fronts (§3.1, §4.2). Consistent
  with the settled §6 invariants and the §6.5 engines-through-gateway posture; it does not
  reopen them.
- **Related**: PROMPT §3.1, §3.3, §3.4, §3.5, §4.2, §5, §6.1, §6.7, §8 (spikes 2, 6), open
  questions; `policy/gateway/authz.rego`, `src/authz/input.rs`, `src/auth/sts.rs`,
  `src/auth/mod.rs`, `src/identity.rs`, `src/pdp/bundle.rs`, `src/bundle_refresh.rs`,
  `src/model.rs`; ADR-001 (direct-path closure, drift control), ADR-002 (audit record shape),
  ADR-004 (list narrowing)

## Context

The gateway's premise is "consume granular grants" — and the brief is explicit that the
grants do not exist yet. §3.3: the data-plane grant ("object operations + an **object-prefix
scope** (`/<harbor>/<bucket>/<prefix>`), and its projection into the gateway's OPA data") is
**[NOT-YET-BUILT]** and "is the core companion task — the gateway's whole premise (consume
granular grants) depends on it. … **Do not code against a projection that emits
per-op/per-prefix S3 grants today — it does not.**"

### What EXISTS on the platform side (verified by the v4 brief)

- **Control-plane RBAC** (§3.3 [EXISTS]): a typed permission catalog
  (`domain/authz/permission.rs`, `<resource_type>:<action>`), roles and groups expanding
  into per-subject grants, HRN scope paths `hrn:<org>:<type>:<id>` with ancestor
  prefix-cascade, projected into OPA package `console.authz` for **control-plane API**
  authorization. Data-plane bucket permissions are **bucket-entity CRUD only**
  (`bucket:create | bucket:read | bucket:update | bucket:delete`): "There is **no**
  `read_objects | list_objects | write_objects | delete_objects | manage_lifecycle`
  permission, and **no object-prefix scope** anywhere in the grant model" (§3.3).
- **The per-Org bundle** (§3.4 [EXISTS]): gzipped, served at
  `GET /api/internal/v1/organizations/{organization_id}/ceph-bundle` (operator-internal),
  polled by a per-Org OPA running `ceph.authz`. The real data shape carries exactly
  `tenants.<harbor>.user_attributes`, `tenants.<harbor>.bucket_attributes`
  (denylist + `sensitivity`, the latter "carried but not yet enforced"), and
  `org_settings.freeze_writes`. "There is **no** `s3_grants`, `s3_prefix_grants`, `s3_deny`,
  `s3_prefix_deny`, `native_principals`, or `tenant_owner_uid`. v3 invented those field
  names."
- **Today's `ceph.authz` rule** (§3.4 [EXISTS]): "membership + denylist, not grants …
  **No per-operation and no per-prefix logic exists.**" And: "There is nothing in
  `ceph.rego` to 'port' for prefix/op matching; that rego is net-new."
- **Identity** (§3.1 [EXISTS]): per-Org Keycloak realms; "Subjects are the OIDC `sub`."
  The console already brokers temporary S3 creds via Keycloak token-exchange + RGW
  `AssumeRoleWithWebIdentity` (`handlers/buckets/mod.rs::resolve_user_s3_context`); the
  minted session identity arrives at RGW as `$oidc$<sub>` (untenanted role) or
  `<tenant>$oidc$<sub>` (tenanted role). "**This is exactly the STS-identity-into-OPA model
  you want, and it is already live** … Build your STS (§4.2) to mint the same identity
  shape, or front the existing broker."

### What EXISTS in this repo (the consumer side is already coded)

- `policy/gateway/authz.rego` — the net-new gateway policy. Deny-by-default; membership
  necessary but **not** sufficient; an explicit grant must match
  `(action, bucket, object|prefix)`. Its header documents the exact data contract this ADR
  makes normative: `data.tenants[t].s3_grants[sub]` and
  `data.tenants[t].group_grants[group]`, both arrays of
  `{bucket, actions[], prefixes[]}`, alongside the **reused** existing data
  (`user_attributes`, `bucket_attributes.denylist`, `org_settings.freeze_writes`).
- `src/authz/input.rs` — the §5 OPA input the grants are matched against
  (`principal.sub`, `principal.attributes.groups`, `tenant`, `action`, `bucket`,
  `object?`, `prefix?`, …).
- `src/auth/sts.rs` — the STS authority (§4.2): `HFST`-prefixed access-key ids, secrets
  derived as `hex(HMAC-SHA256(master, sid))` with no per-session secret at rest, signed
  session-claims token (`sub`, `typ`, `groups`, `tenant`, `org`, `sid`, `exp`) bound to the
  access-key id, distinct master/signing keys. `src/auth/mod.rs` wires it into `S3Auth`
  next to the static credential store; `src/identity.rs` carries the resolved end-user
  identity to the typed hooks.
- `src/pdp/bundle.rs` + `src/bundle_refresh.rs` — bundle consumption: hot-swappable
  `BundleStore`, `content_revision` derived from the raw payload (the §4.3.2 cache key
  half), poll-and-reload from `BundleSource::Http` (the console endpoint) or
  `BundleSource::File` (dev / spike 2).
- `policy/testdata/corpus.json` + `tests/policy_corpus.rs` — golden decision corpus over
  hand-written bundles in the target shape (spike 2 posture, §8).

### What is NOT-YET-BUILT

- **Platform:** the object-op permission family, the prefix-scoped grant, the projection
  that expands roles/groups into the shape above, and the superset bundle that carries it
  (§3.3–§3.4). Also: repointing the console's live STS broker at the gateway.
- **This repo (follow-ups, not companion):** the mint HTTP endpoint that verifies an OIDC
  token against the per-Org realm before calling `StsAuthority::mint` (the authority and
  verification of minted creds exist; the OIDC-facing endpoint does not), and flipping
  production config from `BundleSource::File` to `BundleSource::Http`.

This ADR exists so both teams build against one frozen contract, per the brief's open
question: "**§3.3–§3.4 data-plane grant model + projection is greenfield (companion console
task).** … Sequence it with spike 2's hand-written bundle so the gateway isn't blocked, and
swap to the real projection when it lands."

## Decision

### D1. Target grant shape the console MUST emit (normative)

The projection emits, per tenant (Harbor slug), two additive maps whose values are arrays
of one `Grant` object type — exactly the contract `policy/gateway/authz.rego` already
consumes:

- `data.tenants[<harbor>].s3_grants[<oidc-sub>]  : [Grant]` — per-subject grants,
  **pre-expanded from roles** on the console side (§3.3: roles and groups already "expand
  into per-subject grants" in the control plane; the projection reuses that expansion).
- `data.tenants[<harbor>].group_grants[<group>]  : [Grant]` — per-group grants, resolved at
  decision time against `input.principal.attributes.groups`
  (`policy/gateway/authz.rego::grants`).

```jsonc
Grant := {
  "bucket":   "<bucket-name>" | "*",          // "*" = every bucket in the tenant
  "actions":  ["read_objects", ...] | ["*"],  // subset of the closed §5 verb set, or ["*"]
  "prefixes": ["dicom/2026/", ...]            // absent or [] ⇒ whole bucket
}
```

| Field | Type | Semantics (as implemented in `authz.rego`) |
|---|---|---|
| `bucket` | string | Exact bucket name within the tenant (`bucket_matches`), or the literal `"*"` for all buckets in the tenant. No globbing — `"*"` is a whole-field sentinel, not a pattern. |
| `actions` | array of string | Values drawn from the closed set `read_objects \| list_objects \| write_objects \| delete_objects \| manage_lifecycle` (`src/model.rs::Action::as_str`, PROMPT §5), or the single-element `["*"]` (`action_matches`). Unknown verbs are a projection bug: they can never match and MUST be rejected at build time, not emitted. |
| `prefixes` | array of string | Raw object-key prefixes matched by `startswith(input.object, p)` (`object_in_scope`). Absent or empty ⇒ the grant scopes the whole bucket (`whole_bucket`). No wildcards, no regex; a `*` inside a prefix is a literal character. |

The full **superset bundle** (target), with today's fields unchanged:

```jsonc
{
  "tenants": {
    "st-anna-radiology": {
      "user_attributes":   { "<oidc-sub>": { "groups": ["radiology"], "attributes": [] } },  // EXISTS
      "bucket_attributes": { "imaging": { "denylist": { "<sub>": true },
                                          "sensitivity": "high" } },                        // EXISTS
      "s3_grants": {                                                                        // NEW
        "<oidc-sub>": [
          { "bucket": "imaging", "actions": ["read_objects", "list_objects"],
            "prefixes": ["dicom/2026/"] }
        ]
      },
      "group_grants": {                                                                     // NEW
        "radiology": [
          { "bucket": "imaging", "actions": ["*"], "prefixes": [] }
        ]
      }
    }
  },
  "org_settings": { "freeze_writes": false }                                               // EXISTS
}
```

**Prefix normalization rules (console MUST enforce at projection time):**

1. Prefixes are derived from the §3.3 grant scope `/<harbor>/<bucket>/<prefix>` by
   stripping the `/<harbor>/<bucket>/` head; the emitted value is a bare key prefix
   (object keys never start with `/`).
2. Because matching is plain `startswith`, the prefix `"reports"` also matches
   `"reports-old/x"`. Folder-style scopes MUST therefore be emitted `/`-terminated
   (`"reports/"`); emitting a non-`/`-terminated stem is allowed only as an explicit,
   deliberate choice in the console model, never as an accident of string handling.
3. An empty prefix after stripping means whole-bucket: emit `"prefixes": []` (or omit),
   never `"prefixes": [""]`.
4. `manage_lifecycle` (and other keyless bucket-level ops) ignores `prefixes` by design —
   `authz.rego`'s bucket-level rule checks only `(bucket, action)`. The projection MUST
   emit `manage_lifecycle` grants with `"prefixes": []` so the data never implies a
   scoping the policy does not apply.

**What is deliberately NOT in the shape:** no `s3_deny` / `s3_prefix_deny` / negative
grants — §3.4 lists those as fields v3 invented that do not exist, and the deny surface
stays what it is today: the per-bucket `denylist`, the org-global `freeze_writes` (§3.5),
and — if the product needs them later — projected guardrails as OPA deny rules (§3.5,
[NOT-YET-BUILT], out of scope here). Grants are purely additive; denies are separate,
existing mechanisms evaluated ahead of grants (`authz.rego`: `allow` requires
`not frozen`, `not denylisted`, `member`, `grant_matches`).

### D2. Matching semantics are frozen by the gateway rego, not re-specified per team

`policy/gateway/authz.rego` is the single normative definition of what a grant means:
membership (`user_attributes` presence) is necessary but not sufficient; effective grants
are the union of `s3_grants[sub]` and `group_grants[g]` for each `g` in the principal's
token groups; object ops require the key under a granted prefix; list ops match a
whole-bucket grant or overlap a prefix grant, with narrowing obligations per ADR-004
(§5.1). The console team writes the projection **against that file**, and the shared
acceptance gate is the golden corpus (D5) — not a prose re-statement that could drift
(ADR-001's drift-control logic applied to this contract).

Two membership invariants follow directly from the rego and bind the projection:

- **Every granted sub MUST appear in `user_attributes`** for that tenant. A grant to a
  non-member is inert (`member` fails; deny reason `"deny: principal not a tenant member"`)
  — fail-closed but a silent product bug. Same for group grants: they only take effect for
  tenant members.
- **One group namespace.** Keys of `group_grants` MUST be byte-identical to the group
  strings the platform puts in `user_attributes[sub].groups` and to the `groups` claim the
  STS mint copies from the OIDC token into the session (`SessionClaims.groups`,
  `src/auth/sts.rs`) — all three originate in the same per-Org Keycloak realm/console
  model, and the projection must not introduce a variant form (slug vs display name).

### D3. Delivery: the existing per-Org bundle endpoint grows to a superset — additively

Per §3.4's instruction ("**Reuse this delivery mechanism and bundle builder** … Reuse the
bundle plumbing; extend the projected data"):

- **Same endpoint, same builder, same gzip document**:
  `GET /api/internal/v1/organizations/{organization_id}/ceph-bundle` serves one per-Org
  document that both consumers poll — the in-RGW per-Org OPA (`ceph.authz`,
  defense-in-depth per §6.5/§7.1) and this gateway (`src/bundle_refresh.rs`,
  `BundleSource::Http`).
- **Additive-only evolution.** The new keys (`s3_grants`, `group_grants`) sit under
  `tenants.<harbor>` next to the existing ones; `user_attributes`, `bucket_attributes`,
  and `org_settings.freeze_writes` are byte-for-byte what they are today. Unknown data
  keys are inert in Rego, so `ceph.authz` decisions cannot change — the console MUST still
  prove this with a regression test over the superset bundle (C3), because that rego also
  matches on request-time shapes the gateway never sees (§3.7 native `<tenant>$<user>`
  recognition).
- **Revision semantics.** The gateway derives its bundle revision from the raw payload
  (`src/pdp/bundle.rs::content_revision`) and keys the §4.3.2 decision cache on it, so any
  grant change lands as a new revision and every stale cached decision misses by
  construction — this is the live-revocation mechanism of §6.1. Two consequences for the
  builder: (a) **every grant mutation MUST change the served bytes** (no lossy or delayed
  projection), and the propagation SLO (build + gateway poll interval) is the documented
  revocation-latency bound; (b) serialization MUST be byte-stable for unchanged data (stable
  key order), so unchanged re-polls do not flap the revision and gratuitously empty the
  cache. A strong `ETag` is welcome but optional — content hashing already provides
  correctness.
- **One Org per document, per PDP.** `authz.rego` reads `data.org_settings.freeze_writes`
  at the top level, mirroring the per-Org OPA posture of §3.4; the gateway loads exactly
  one Org's bundle per engine (`BundleStore` holds one bundle). A gateway instance serving
  multiple Orgs runs one engine+bundle per Org; nothing in this contract namespaces Orgs
  inside one document, deliberately.

### D4. STS identity: the gateway mints the platform identity, keyed by the bare OIDC `sub`

§4.2 offers two routes — "either front that broker or mint the same `sub`-bearing session."
**Decision: the gateway mints its own sessions** (implemented, `src/auth/sts.rs`), and the
platform's console **fronts the gateway's mint** instead of RGW's STS. Reasoning:

1. **SigV4 forces it.** "SigV4 verification recomputes an HMAC, so you must hold or derive
   the plaintext secret for every principal" (§4.2). The gateway cannot derive the secret
   of an RGW-minted session — those secrets are RGW-internal — so fronting the existing
   broker cannot terminate auth at the gateway at all.
2. **§6.7 already settles direction.** "The current RGW `AssumeRoleWithWebIdentity` broker
   (§3.1) is a Ceph-specific convenience the gateway **supersedes**, not a dependency";
   backend STS is disqualified for authorization by the §2 portability constraint.

**The minted session (normative, as implemented in `src/auth/sts.rs`):**

- Access-key id `HFST<sid>` (`STS_PREFIX`); the `sid` is generated random at the mint
  endpoint (≥128-bit entropy — R5).
- Secret `= hex(HMAC-SHA256(master_key, sid))` (`derive_secret`) — deterministic, "no
  per-session secret at rest, no hot-path store lookup" exactly as §4.2 prescribes;
  `S3Auth::get_secret_key` re-derives from the access-key id alone
  (`secret_for_access_key`, wired in `src/auth/mod.rs`).
- Claims ride in a signed HS256 token in `X-Amz-Security-Token`
  (`SessionClaims { sub, typ, groups, tenant, org, sid, exp }`), MAC'd with a **signing key
  distinct from the master key** (both ≥32 bytes, enforced in `StsAuthority::new`) and
  bound to the access-key id (`verify_session` rejects `claims.sid != sid` and expired
  tokens).
- The response triple is `AssumeRoleWithWebIdentity`-shaped (`SessionCredentials`), so
  `aws` CLI / SDKs / rclone work unchanged.
- **Revocation stays live in policy, not in the credential** (§6.1): an unexpired session
  whose grant was revoked denies at the PDP on the next request, because the bundle
  revision moved (D3). There is deliberately no session kill-list; the per-principal
  emergency levers are the existing `denylist` / membership removal / `freeze_writes`.

**Identity shape and keying.** The session's platform identity is the same identity the
live broker mints — §3.1's `$oidc$<sub>` / `<tenant>$oidc$<sub>` is the **RGW rendering**
of "OIDC subject `sub`, in tenant `<tenant>`". The gateway carries that identity as the
**bare OIDC `sub` plus an explicit `tenant` claim** and keys everything on the bare `sub`:
`SessionClaims.sub` → `input.principal.sub` (`src/identity.rs::to_opa_principal`) →
`data.tenants[t].user_attributes[sub]` / `s3_grants[sub]` → audit `requested_by`
(ADR-002 D2 already fixes this: the `$oidc$`-decorated form "is a backend identity
artifact the gateway supersedes (§6.7)"). The projection therefore keys `s3_grants` by
bare `sub`, exactly as `user_attributes` already is today (§3.4's example keys on
`<oidc-sub>`). Where any transitional component needs the RGW form, the mapping is
mechanical (`$oidc$` + optional tenant qualifier) — but no gateway data structure stores
it. This is spike 6's requirement verbatim: "Mint the platform's identity shape
(`$oidc$<sub>`, §3.1) so decisions and audit line up across the platform."

**The mint endpoint contract (repo follow-up F1 + companion C6/C7):**

- Request: an OIDC token from the caller's per-Org Keycloak realm (obtained directly or
  via the console's existing token-exchange, which stays — §7 forbids rebuilding it),
  plus the requested `tenant` (Harbor slug) and TTL.
- Gateway-side validation before `StsAuthority::mint`: issuer = that Org's realm,
  signature via the realm JWKS, `exp`/`aud` per C7's agreed conventions; claims mapping
  `sub → sub` (bare), `groups → groups`; `org` from the gateway's per-Org deployment
  identity (the same trusted source ADR-002 uses for the org label); optional fast-fail
  membership check of `sub` against the current bundle's
  `tenants[tenant].user_attributes` — a UX nicety only, since the PDP's `member` rule is
  the authoritative check on every request.
- TTL: default 1 hour, hard cap 12 hours (configurable). The cap is load-bearing: group
  membership rides in the token, so **group-revocation latency equals remaining TTL**
  (R4).
- Consumers per §3.1/§6.5: humans (console-proxied ops and CLI), AI agents ("AI agents get
  the same short-lived STS creds"), and the per-query engine credentials of §6.5 — one
  mint path for every consumer class, each session carrying the end-user `sub`.

### D5. Sequencing: hand-written bundle now, projection swap behind an acceptance gate

Per §8 spike 2 ("This uses a hand-written bundle on purpose — the real per-op/per-prefix
projection is companion work, §3.4; don't block the spike on it") and the open-questions
sequencing instruction:

- **Phase 0 (now, this repo — unblocked):** gateway develops and tests against
  hand-written bundles in the D1 shape — `BundleSource::File` and
  `policy/testdata/corpus.json` already do this. The corpus doubles as the executable
  specification of D1/D2 handed to the console team.
- **Phase 1 (projection lands):** console emits the superset bundle (C1–C5); staging
  gateway flips to `BundleSource::Http` against the real endpoint. **Acceptance gate:**
  (a) the golden corpus replays against a console-emitted bundle with identical decisions,
  through both PDP engines (the §4.3.1 dual-engine parity gate — note the grant data is
  pure data, so it cannot introduce non-regorus builtins; the constraint stays on rego
  changes); (b) the `ceph.authz` regression of C3 passes.
- **Phase 2 (identity cutover):** console repoints `resolve_user_s3_context` to the
  gateway mint and its object routes to the gateway endpoint (C6); the RGW-STS leg is
  scheduled for decommission under ADR-001's exposure closure.
- **Until Phase 1 completes, no production enforcement claim is made.** With today's real
  bundle (no `s3_grants`/`group_grants`), the gateway denies every object op — fail-closed
  by construction (`default allow := false`; membership alone never suffices), which is
  the safe failure direction but also means the gateway is not usable, only safe.

## Alternatives considered

- **A1 — Code the gateway against today's projection (membership + denylist) to ship
  sooner.** Rejected by §3.3 verbatim ("Do not code against a projection that emits
  per-op/per-prefix S3 grants today — it does not") and by mission: bucket-granular
  membership is exactly the model the gateway exists to surpass (§1: "per-object /
  per-prefix is the point of this gateway"; §2).
- **A2 — Port/extend `ceph.rego` instead of defining a new grant contract.** Rejected:
  §3.4 states there is "nothing in `ceph.rego` to 'port' for prefix/op matching; that rego
  is net-new". `ceph.authz` stays as-is as the direct-path defense-in-depth layer (§6.5,
  §7.1, ADR-001).
- **A3 — Project raw HRN grants (`hrn:<org>:<type>:<id>` + prefix-cascade) and evaluate
  the cascade in gateway rego.** Rejected. The HRN catalog cannot express the grant at
  all today — no object-op verbs, "no object-prefix scope anywhere in the grant model"
  (§3.3) — so the console must extend its model regardless; given that, projecting the
  finished, flat, per-subject shape keeps role/group expansion out of the request hot
  path, keeps the gateway rego small (a §4.3.1 concern: stay inside the regorus subset),
  and avoids importing control-plane path semantics (`startswith(pattern + "/")` over
  HRNs) into data-plane decisions. The HRN model remains the console-internal **source**;
  D1 is its **projection**.
- **A4 — A new, gateway-owned grants API or database instead of the bundle.** Rejected:
  §3.4 instructs "Reuse this delivery mechanism and bundle builder"; §7 forbids rebuilding
  the grant model; and the bundle revision is what makes the §4.3.2 decision cache and
  §6.1 live revocation correct by construction — an RPC-per-decision design would
  reintroduce the invalidation problem the revision key eliminates.
- **A5 — A second, separate bundle endpoint for the gateway.** Rejected: two builders over
  one grants source is the §7.1 drift scenario in miniature ("divergence *is* a bypass").
  Additive superset keys are inert to `ceph.authz`, so one document serves both consumers.
  Revisit only if superset size measurably burdens the RGW-side OPA (R6) — and then as a
  filtered *view* from the same builder, never a second builder.
- **A6 — Bake scopes into the credential (AWS-style session policy) instead of projecting
  grants.** Rejected by §6.1 verbatim ("No policy baked into credentials → **live
  revocation**, no session-policy size cap") and §6.7 (enforcement lives in gateway
  policy, holds even on a "dumb" S3 bay).
- **A7 — Front the existing RGW STS broker rather than minting.** Rejected: the gateway
  cannot derive RGW session secrets, so it could not verify SigV4 (§4.2) — fronting fails
  technically, not just architecturally; plus §6.7 ("supersedes, not a dependency") and
  §2's ban on backend-native dependence. The *console-facing* half survives inverted:
  console token-exchange now fronts the **gateway's** mint (D4, C6).
- **A8 — Random per-session secrets in a store instead of derivation.** Rejected by §4.2
  verbatim ("derive the session secret deterministically … No per-session secret at rest,
  no hot-path store lookup"); implemented accordingly in `src/auth/sts.rs`. A store would
  add a hot-path dependency and a secrets-at-rest liability for zero policy benefit —
  revocation lives in OPA either way.

## Consequences

**What must hold for the security claim** (object-level authorization per end-user, §6.6):

- **I1 — No grant, no access.** `default allow := false` and membership-not-sufficient in
  `authz.rego`; the projection never emits implicit whole-tenant or whole-org grants —
  every allow traces to an explicit `Grant` a console admin can point at.
- **I2 — One `sub` namespace.** Bundle keys (`user_attributes`, `s3_grants`), session
  claims (`SessionClaims.sub`), OPA input (`principal.sub`), and audit (`requested_by`)
  all carry the bare OIDC `sub` from the per-Org realm (§3.1). Any decorated or aliased
  form anywhere breaks matching fail-closed (silent deny) at best.
- **I3 — One group namespace** (D2): `group_grants` keys ≡ `user_attributes[…].groups`
  entries ≡ token `groups` claims, byte-identical.
- **I4 — Revocation latency is bounded and known**: grant mutation → bundle bytes change →
  new `content_revision` → cache miss (D3). The bound is builder latency + gateway poll
  interval, and it is the §6.1 policy-freshness bound; the console documents and monitors
  it (C4).
- **I5 — Key custody.** The STS `master_key` derives every session secret; the
  `signing_key` authenticates every claims token. Compromise of the master key ≈ mint
  authority. They are distinct by construction (`StsAuthority`) and must be provisioned
  from a secrets manager/KMS with a rotation procedure (F2); they never leave the gateway
  (§9.3 posture: credentials never leave the site).
- **I6 — Credential domains stay disjoint.** The gateway honors only `HFST` sessions and
  its own static store (`src/auth/mod.rs`); RGW-minted or tenant-owner creds are unknown
  access-key ids at the gateway (auth fail), and gateway creds are meaningless at RGW.
  Cross-domain reach = the direct-path exposure, dispositioned in ADR-001, not here.

**Risks and follow-ups:**

- **R1 — The gateway is deny-everything on real bundles until the projection lands.**
  Fail-closed but unusable; the whole plan gates on C1–C5. Interim demos/pilots run on
  hand-written bundles only (D5 Phase 0) and must not be represented as enforcing
  production grants.
- **R2 — Projection correctness is now a security surface.** A projection bug that
  over-emits (wrong sub, over-broad prefix, stray `"*"`) grants real access. Mitigations:
  build-time validation (closed action set, normalized prefixes, member invariant — C2),
  the corpus acceptance gate (D5), and the audit trail (every allow carries the matched
  request context per ADR-002, so over-grants are at least visible).
- **R3 — Prefix-stem pitfall.** `startswith` semantics mean an un-normalized stem grant
  captures sibling keys (`"reports"` ⊃ `"reports-old/…"`). Normalization is normative
  (D1 rule 2); C2 makes it a projection test.
- **R4 — Group revocation lags by session TTL.** Grant expansion reads token groups, not
  bundle groups (`authz.rego::grants`), so removing a user from a group takes effect at
  session expiry — hence the 1h default TTL (D4). Immediate levers exist (membership
  removal kills `member`; per-bucket `denylist`; `freeze_writes`). **F3 (follow-up,
  decision-changing):** tighten rego to intersect token groups with the bundle's
  `user_attributes[sub].groups` — must go through the dual-engine corpus gate before
  shipping, since it narrows decisions.
- **R5 — `sid` entropy is load-bearing.** The derived secret is only as unpredictable as
  the `sid` (the endpoint supplies it; `mint` accepts caller-fixed sids for testability).
  F1 mandates ≥128-bit CSPRNG sids at the endpoint.
- **R6 — Bundle growth.** Per-subject role expansion multiplies (subjects × grants);
  prefer `group_grants` for cohorts to bound size. Watch gzipped size against the RGW-side
  OPA and gateway memory; A5's filtered-view escape hatch exists if needed.
- **R7 — Console-proxied traffic still bypasses the gateway until Phase 2.** The live
  §3.1 broker path (console → RGW STS → RGW) is a direct path under ADR-001's inventory;
  this ADR provides its replacement (D4), ADR-001 owns its closure.

**Repo-side follow-ups (ours):** F1 — mint endpoint with per-Org OIDC verification and
CSPRNG sids (D4). F2 — master/signing key provisioning + rotation runbook (I5). F3 —
group-intersection rego tightening decision (R4). F4 — production config flips
`BundleSource::File` → `Http` with poll interval set from the C4 freshness SLO.

## Companion work (checklist for the console/platform team)

- [ ] **C1 — Extend the permission catalog** (`domain/authz/permission.rs`) with the
  object-operation family mapping 1:1 to the five gateway actions
  (`read_objects`, `list_objects`, `write_objects`, `delete_objects`,
  `manage_lifecycle`) and an object-prefix scope on grants
  (`/<harbor>/<bucket>/<prefix>`), per §3.3.
- [ ] **C2 — Build the projection** emitting D1 exactly: roles pre-expanded into
  `s3_grants[sub]`; `group_grants[group]` keyed by the canonical group form; build-time
  validation — actions ⊆ closed set or `["*"]`; bucket = name or `"*"`; prefixes bare,
  never `""`, `/`-terminated unless a stem is intended; `manage_lifecycle` ⇒
  `prefixes: []`; every granted sub present in `user_attributes` (D2 invariants).
- [ ] **C3 — Grow the bundle additively**: new keys under `tenants.<harbor>` only;
  `user_attributes` / `bucket_attributes` / `org_settings.freeze_writes` unchanged;
  regression test proving `ceph.authz` decisions are identical on the superset bundle.
- [ ] **C4 — Endpoint semantics**: same route
  (`…/organizations/{organization_id}/ceph-bundle`), gzip; byte-stable serialization for
  unchanged data (the gateway hashes content for its cache-key revision, D3); every grant
  mutation changes the served bytes; publish and monitor the build+propagation freshness
  SLO (= the §6.1 revocation-latency bound).
- [ ] **C5 — Keep `user_attributes[sub].groups` authoritative and fresh** — it is the
  membership source and the target of the R4/F3 tightening.
- [ ] **C6 — Repoint the console STS flow**: `resolve_user_s3_context` (and the console's
  object browse/upload/delete routes) mint gateway sessions via the gateway STS and target
  the gateway's S3 endpoint — humans and AI agents alike (§3.1); schedule the RGW-STS leg
  for decommission with ADR-001.
- [ ] **C7 — Publish OIDC verification parameters per Org** (issuer, JWKS URI, audience /
  token-exchange conventions) for the gateway mint (F1), and agree the
  `AssumeRoleWithWebIdentity`-shaped mint API surface.
- [ ] **C8 — Contribute console-emitted bundle fixtures + expected decisions** to the
  golden corpus (a "platform asset, not a repo asset", §6.5), making D5's acceptance gate
  and the §4.3.1 dual-engine parity gate run on real projection output in CI.
- [ ] **C9 — Explicit non-goal sign-off**: guardrails-on-S3 (§3.5) and `sensitivity`
  enforcement stay out of this contract; when productized they arrive as additional
  projected deny data + rego, through the same corpus gate.
