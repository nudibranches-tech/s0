# ADR-001: Dual-path direct-credential exposure and Rego drift control

- **Status**: Proposed
- **Date**: 2026-07-15
- **Scope**: Resolves PROMPT §7.1 items 1–3 (direct-credential inventory, per-credential disposition, cross-policy drift control). Consistent with the settled invariants of §6 and the §6.5 engines-through-gateway posture; it does not reopen them.

---

## Context

The gateway's entire security claim is **conditional**. PROMPT §2:

> "**Conditional.** The enforcement + audit guarantee holds **only if no consumer can reach a
> backend directly.** See §6.5 and §7.1 — this is an invariant, not a migration detail, and v4
> shows the current direct-path exposure is real and non-empty (it must be closed)."

And §6.5 makes the same point in credential terms: the gateway is the single audited
enforcement point for every S3 consumer, and

> "the security property is **conditional on there being no usable direct-to-backend
> credential** for anything that touches user-attributable data (see §7.1 — those creds must be
> *closed*, not merely tracked)."

§7.1 frames this as "a blocker, not a footnote": until the direct paths are dispositioned, the
gateway is a proxy with a policy engine, not an enforcement boundary. Two distinct problems
must be decided here:

1. **Dual-path exposure.** Credentials exist *today* that reach Ceph RGW without traversing
   any gateway. §3.7 is explicit that the exposure list is "an **artifact you must CREATE**,
   not a datum to read": there is no `native_principals` bundle field; native RGW users are
   recognized purely at request time by the `<tenant>$<user>` `user_id` shape in `ceph.rego`,
   and a native **tenant-owner** credential is authorized across the **entire tenant** — every
   bucket, no per-user/object/prefix scope. §3.7 verifies four concrete direct-to-RGW
   credentials (the seed inventory below).

2. **Rego drift.** Three policy codebases will evaluate the same organization's access
   intent (§7.1 item 3): `ceph.authz` (in-RGW hook — defense-in-depth), `datadock.authz`
   (Trino SQL PEP — defense-in-depth), and the gateway policy (the authz/audit path).
   §7.1: "Multiple policy codebases over one grants source means divergence *is* a bypass.
   Either generate them from one source, or run a shared conformance suite over all.
   Decide which."

### What EXISTS vs what is NOT-YET-BUILT (as relevant to this ADR)

**EXISTS (platform, verified by the v4 brief):**
- `GET /harbors/{id}/buckets/{name}/credentials` returns the **tenant-owner static
  credential** to any caller holding `bucket:read`, for rclone / AWS CLI use (§3.7 item 1).
- The **same tenant-owner credential** is configured into the Trino/Iceberg catalogs via
  Lakekeeper — a "direct, unaudited, shared-identity path" to S3, tenant-wide and unscoped
  (§3.7 item 2, §6.5).
- **Rook admin ops user** and **per-OrgStorage admin** — infra control-plane creds
  (§3.7 item 3), allowed today by explicit Rook/admin rules in `ceph.authz` (§3.4).
- `ceph.authz` itself: membership + per-bucket denylist, native-tenant-owner passthrough,
  an STS-mint allow, Rook/admin allows, `freeze_writes` (§3.4). **No per-op or per-prefix
  logic.** It stays as-is as the direct-path defense-in-depth layer (§7.1, §6.5).
- `datadock.authz`: SQL-logical enforcement only — "It never sees an S3 object key, performs
  no file-level authorization, and emits no per-object decision" (§6.5).
- The console decision-log sink with exactly two extractors (Console, Trino); records
  matching neither are dropped (§3.6).

**EXISTS (this repo):**
- The gateway policy `policy/gateway/authz.rego` — net-new, deny-by-default, membership
  necessary but not sufficient, grant × (action, bucket, object|prefix) matching, list-
  narrowing obligations. Its header documents the grant data contract it consumes.
- The OPA input contract `src/authz/input.rs` (§5 superset). Note: `object_tags` is
  documented there as "**Gated behind §7.1 — never populated until the direct-path question
  resolves**", i.e. the code already treats this ADR as a blocker for tag ABAC (§5.2).
- The audit record `src/audit/record.rs` — one OPA-decision-log-shaped record per request,
  `requested_by` = end-user `sub`, trusted org label for fail-closed attribution (§3.6, §6.6).
- The golden decision corpus `policy/testdata/corpus.json` (23 cases over two bundles) and
  its runner `tests/policy_corpus.rs`, which replays it through the embedded regorus PDP.
  The corpus self-describes as "engine-agnostic … and the seed of the §7.1 conformance
  corpus".

**NOT-YET-BUILT (companion, platform side):**
- The data-plane grant projection (`s3_grants` / `group_grants`) the gateway rego consumes
  (§3.3–§3.4) — the "one grants source" of §7.1 item 3 does not yet project S3 grants.
- Per-user gateway credentials for humans/CLI and per-query sub-bearing engine credentials
  (§6.5) — the replacements that make closure possible.
- The S3/Ceph decision-log extractor (§3.6) — without it, gateway audit records are dropped
  by the sink, so closure would be unobservable.
- The exposure inventory as an operational artifact, and the platform-owned golden corpus
  (§6.5: "the golden decision corpus is a **platform asset, not a repo asset**").

---

## Decision

Three decisions, one per §7.1 item.

### D1 — The direct-credential exposure inventory is a maintained platform-security artifact, seeded with the four verified §3.7 credentials

The inventory is **created and owned on the platform side** (it is not a bundle field and the
gateway consumes nothing from it at decision time — §3.7). It is a living document with an
owner, a review cadence, and one governing rule, taken verbatim from §7.1:

> Under the day-one per-user audit requirement, **"accept in writing that they're outside the
> model" is NOT an available disposition for any credential that can reach user-attributable
> data** — such a credential is, by definition, an unaudited direct path.

Every entry gets exactly one of the two §7.1 dispositions: **(a) close** (revoke; move the
consumer onto the gateway with a per-user, gateway-issued credential), or **(b) isolate +
prefix-bound** — available *only* to "a pure infrastructure/control-plane cred that never
touches tenant object data", with a documented justification of why it is not a data path.
Data-touching credentials have only option (a).

**Seed inventory (the four credentials verified in §3.7):**

| # | Credential | How it exists today [EXISTS] | Reach at the backend | Identity it acts under | Touches user-attributable data? | Disposition |
|---|---|---|---|---|---|---|
| 1 | Tenant-owner static credential, vended to end users | `GET /harbors/{id}/buckets/{name}/credentials` returns it to anyone holding `bucket:read` (rclone / AWS CLI) (§3.7) | Entire Ceph tenant — every bucket; native-tenant-owner passthrough in `ceph.authz`, "no per-user/object/prefix scope" (§3.7) | Shared tenant-owner — **not** the end user | **Yes** — it *is* end-user object access | **(a) CLOSE** |
| 2 | The same tenant-owner credential, configured into Trino/Iceberg catalogs via Lakekeeper | Engine catalogs reach S3 with it today — "a direct, unaudited, shared-identity path" (§6.5, §3.7) | Tenant-wide, unscoped | Shared service identity | **Yes** — table data files are user-attributable data | **(a) CLOSE** (per settled §6.5 posture) |
| 3 | Rook admin ops user | Infra control-plane cred for RGW provisioning; explicit allow in `ceph.authz` (§3.4, §3.7) | RGW admin/ops surface | Infra service | Intended **no** — must be *verified*, not assumed | **(b) isolate + bound** — conditional, see below |
| 4 | Per-OrgStorage admin | Infra control-plane cred per OrgStorage CRD (the CRD also sources `freeze_writes`, §3.5) | Per-OrgStorage admin surface | Infra service | Intended **no** — must be *verified*, not assumed | **(b) isolate + bound** — conditional, see below |

**Rows 1 and 2 share one underlying secret** (§3.7: "The **same** tenant-owner cred used by
the Trino/Iceberg catalogs"). Consequence for closure mechanics: revoking the endpoint is not
closure — copies already live in user rclone configs and in Lakekeeper. Closure = **rotate the
tenant-owner key at RGW**, which kills every outstanding copy in one event, and therefore must
be sequenced **after both consumers have migrated** (users onto gateway per-user creds; engines
onto the §6.5 engine path), or Trino and every CLI user break at once.

**Disposition detail, row 1 (close).** The credentials endpoint stops returning the
tenant-owner secret. Its replacement is a **gateway-issued per-user credential** (a
`sub`-bearing static pair or gateway-STS session, §4.2) plus the gateway endpoint URL —
rclone and the AWS CLI keep working, pointed at the gateway. This is consistent with §6.5's
ruling that per-user, decision-gated vending is "the *only* surviving role of credential
vending". The old key is then rotated at RGW and the rotation verified (a canary request with
the old key must fail).

**Disposition detail, row 2 (close).** Exactly the settled §6.5 engine posture — restated
here, not re-decided: Lakekeeper stops handing out the tenant-owner cred and instead vends a
**per-query STS credential carrying the querying user's `sub`, minted under an OPA decision**;
the engine's S3 endpoint becomes the gateway (**proxy mode first**; remote signing later as a
bandwidth optimization *only if* the pinned Trino Iceberg connector supports it — the §6.5
verify item). Both variants keep every object read authorized as the end user and logged
(§6.6).

**Disposition detail, rows 3–4 (isolate + bound, conditional).** Option (b) is granted only
while **all** of the following hold, and flips to (a) the moment any fails:
1. A written §7.1(b) justification exists: purpose, and why this is not a data path.
2. The binding is **technically verified**, not asserted: enumerate the credential's RGW
   caps; it must have no S3 object read/write capability — admin/ops API scope only. Where
   the backend can express a narrower bound (caps, prefix, IAM), apply the narrowest. Per
   §6.7 this backend-native scoping is **blast-radius defense-in-depth on a non-data path,
   never an authorization mechanism** — which is exactly why (b) is unavailable for anything
   data-touching.
3. Isolation: the secret exists only in the operator's namespace/secret store; network path
   restricted to RGW admin endpoints; never exposed on any tenant or user surface.
4. Detection: any object-data operation observed under these principals (RGW ops log /
   `ceph.authz` decision stream) alerts and is handled as an incident.
5. Rotation and a quarterly review are scheduled.

If verification in step 2 shows the credential *can* read or write tenant objects and that
capability cannot be removed, it is by definition data-touching, (b) is not available, and the
infra function must be re-plumbed so that its data-plane capability is gone — option (a).

**Beyond the seed — exhaustiveness is a process, not a snapshot.** §7.1 demands "the
exhaustive list"; §3.7's four entries are the *verified seed*, not a proof of completeness.
The inventory therefore ships with: (i) an initial enumeration sweep of all RGW users and keys
per tenant, reconciled against the seed; (ii) continuous detection — any principal observed on
the direct path that is not in the inventory is an incident; (iii) one already-known candidate
the sweep must fold in: the **per-user RGW STS sessions minted by the existing console broker**
(§3.1, `resolve_user_s3_context`). That path is per-user (identity-preserving) but
bucket-granular only and effectively unaudited today — no S3/Ceph extractor exists, so its
decisions are dropped by the sink (§3.6). §6.7 already marks the RGW STS broker as "a
Ceph-specific convenience the gateway **supersedes**": its disposition is (a) by migration —
console object routes move onto the gateway, after which the RGW-STS mint stops.

### D2 — What the gateway consumes, and what it must never consume

The gateway's runtime contract is unchanged by D1 and deliberately ignorant of the inventory:

- It consumes the per-Org bundle (`user_attributes`, `bucket_attributes`,
  `org_settings.freeze_writes` [EXISTS]; `s3_grants` / `group_grants` [NOT-YET-BUILT]) in
  exactly the shape documented in the header of `policy/gateway/authz.rego`. It does **not**
  read an exposure list, and no rego rule may branch on "is this principal also a native RGW
  user" — §3.7 killed `native_principals` as a datum.
- It authorizes with its **own per-tenant/per-backend credential** on the forward path
  (§4.4, §6.4) and never depends on backend IAM/STS/hooks for enforcement or audit (§6.7).
- It emits one decision record per request in the `src/audit/record.rs` shape (§6.6), which
  is what makes "closed" *observable* once the companion extractor lands.

### D3 — Drift control: a shared conformance suite over one grants source (chosen), not generation from one source

Of the two §7.1 options, we choose **"run a shared conformance suite over all"** policy
codebases, anchored on the single grants source of truth.

**What "one grants source" already means here:** the *data* is already generated from one
source — the console grants DB projects into per-Org bundles (§3.4 [EXISTS as mechanism];
the S3-grant superset is [NOT-YET-BUILT], §3.3). No layer hand-maintains grant data. What is
hand-written, and therefore what drifts, is the *policy code*. The suite pins the combined
behavior of the three hand-written policies over that one data source.

**The three layers under drift control** (roles per §6.5 — settled, not reopened):

| Layer | Package | Input domain | Role |
|---|---|---|---|
| In-RGW OPA hook | `ceph.authz` | RGW request: `user_id` shape, bucket. No body — cannot see copy-source, multi-delete keys, or POST form key (§2) | Defense-in-depth, Ceph-only; stays membership + denylist (§7.1) |
| Trino PEP | `datadock.authz` | SQL-logical: `catalog.schema.table[.column]`; never an S3 key (§6.5) | Defense-in-depth: row/column masking |
| Gateway | `hyperfluid.gateway` — `policy/gateway/authz.rego` (this repo) | Full parsed §5 superset (`src/authz/input.rs`) | **The** object-authz and audit path, all backends |

**Suite architecture:**

1. **Platform golden corpus.** Per §6.5 the corpus is "a platform asset, not a repo asset".
   This repo's `policy/testdata/corpus.json` is its **seed** (the file's own header says so):
   23 engine-agnostic cases covering grant/prefix/action matching, denylist-beats-membership,
   freeze_writes, list narrowing (`narrow_prefix` / `allowed_prefixes`), and the blind-spot
   decompositions (copy source-read/dest-write halves; per-key multi-delete). The platform
   corpus extends the seed with `ceph.authz` cases (membership, denylist, tenant-owner
   passthrough, admin allows, freeze) and `datadock.authz` cases (SQL-plane), plus the
   cross-layer invariant cases below.

2. **Gate A — dual-engine parity (this repo; partially implemented).** Every gateway policy
   or bundle revision replays the corpus through **both** OPA (sidecar, the shipping engine)
   and regorus (fast path); identical decisions required in CI before regorus may serve
   traffic (§4.3.1). Already implemented: the regorus leg (`tests/policy_corpus.rs` replays
   the corpus through the embedded PDP, comparing `allowed_prefixes` order-insensitively —
   the rego normalizes list-obligation ordering for exactly this reason). Remaining: the OPA
   sidecar leg of the same runner. Standing constraint that makes Gate A meaningful: all
   gateway rego stays inside regorus's supported builtins — no `crypto.*`, no `io.jwt.*`
   (verified builtin inventory in `docs/substrate-api.md` §7.8; §4.3.1 confirms the platform
   policy set is already inside the subset).

3. **Gate B — cross-layer conformance (platform CI; companion).** Runs on every change to
   any of: the three rego codebases, the bundle/projection builder, or the corpus. Each
   layer is evaluated through its own input adapter (the input domains differ by design —
   see "Alternatives" for why this is fatal to generation). Gate B asserts *relations*, not
   equality, because the layers are intentionally non-identical:
   - **I1 — kill-switch dominance:** `freeze_writes = true` ⇒ every write-class decision
     denies in the gateway **and** in `ceph.authz` (§3.5: "Keep honoring it in the gateway").
   - **I2 — denylist dominance on the direct dimension:** a denylisted `(sub, bucket)` denies
     in the gateway and in `ceph.authz` for that sub. (At RGW the gateway's forwarded request
     carries the gateway's backend cred, not the sub — I2's `ceph.authz` half guards the
     residual direct path only.)
   - **I3 — blast radius (§6.4):** the gateway's per-tenant backend credential is accepted by
     `ceph.authz` only within its own tenant; cross-tenant attempts deny.
   - **I4 — availability non-drift:** every gateway-allow, re-issued with the gateway's
     backend credential, is allowed by `ceph.authz`. A defense-in-depth layer that blocks the
     single legitimate path is also drift.
   - **I5 — engine-plane read consistency:** for a table/Data Container whose storage is
     prefix `P`, a `datadock.authz` read-allow for sub `S` implies a gateway
     `read_objects`-allow for `S` under `P` (else every governed query breaks at the object
     layer, §6.5). The converse direction — an SQL grant projected without its object-prefix
     grant — is flagged as a projection lint, not a policy assertion.
   - **I6 — deny-by-default floor (§6.2):** unknown action, unknown tenant, or missing grant
     data evaluates to deny at the gateway; corpus negative cases pin this.

**Why the conformance suite is the right branch** (and generation is not — details under
Alternatives): the three policies answer different questions over different input contracts
at different semantic levels, and two of them are *intentionally coarser* than the third
(§7.1 keeps `ceph.authz` "as-is"; §6.5 scopes `datadock.authz` to SQL-logical). The invariant
worth enforcing is dominance/consistency, which a test suite states directly and a generator
cannot express without inventing equivalences the brief explicitly rejects. And a generator
would itself need a conformance suite to be trusted — the suite is mandatory on both branches,
so generation adds a fourth policy-bearing codebase without removing any work.

---

## Alternatives considered

1. **Risk-register the existing direct creds ("accept in writing") and ship.** Rejected by
   the brief in as many words: §7.1 — not an available disposition for any credential that
   can reach user-attributable data; §6.5 — direct creds "must be *closed*, not merely
   tracked"; §2 — the whole guarantee "holds only if no consumer can reach a backend
   directly". A tracked bypass is still a bypass, and rows 1–2 are precisely
   user-attributable data paths.

2. **Keep vended credentials but scope them with backend IAM / prefix-bounded keys.**
   Rejected as an authorization mechanism by §6.7 ("**Any design that depends on a
   backend-native capability for authorization or audit is disqualified**" — and a plain S3
   bay may not support scoping at all) and by §6.5 ("Prefix-scoping backend creds is retained
   only as defense-in-depth … never the authorization/audit mechanism"). Independently fatal:
   a scoped direct credential still produces **zero per-request decision records** and acts
   under a shared identity — it fails §6.6 twice regardless of how tight the scope is.
   Scoping survives only inside disposition (b), on verified non-data paths.

3. **Vend per-user credentials that authenticate directly to RGW** (§6.5's rejected option
   "C"). Rejected: "audits only the vend, not each object op, so it fails the per-request
   bar" (§6.5). It would also re-couple identity to RGW's STS, which §6.7 forbids depending
   on and §6.7 explicitly supersedes.

4. **Treat engines as a trusted tier with a broad credential.** Rejected — §6.5 verified the
   premise false at the object layer (the Trino PEP "never sees an S3 object key, performs no
   file-level authorization, and emits no per-object decision") and rejects the posture
   outright ("fails per-user audit"). Settled; restated only because row 2's disposition
   depends on it.

5. **Generate all three policies from one source** (§7.1's other branch). Rejected for drift
   control:
   - The input contracts and semantic levels are disjoint: RGW-hook input (no body — it
     structurally cannot see the §2 blind spots), SQL-logical input (no object keys), and the
     §5 parsed superset. A generator spanning them must embed three enforcement semantics —
     it becomes a fourth policy codebase whose output still needs a conformance suite to
     trust. The suite is unavoidable either way; generation only adds surface.
   - The layers are *deliberately* non-equivalent: §7.1 keeps `ceph.authz` "as-is"
     (membership + denylist), §3.4 notes "There is nothing in `ceph.rego` to 'port' for
     prefix/op matching; that rego is net-new", and no generator output can be "coarser on
     purpose" without hand-written per-layer semantics — at which point it is not generation.
   - There is no function from object-prefix grants to `datadock.authz` row filters; the
     SQL plane's value-add (row/column masking) is not derivable from the S3 grant model.
   - A generator adds a new way to emit rego outside the regorus builtin subset, which Gate A
     exists to forbid (§4.3.1).
   What we *do* keep from this branch: the **data** stays generated from the one grants
   source (the §3.4 projection) — the rejection covers policy code only.

6. **One shared rego package with three entrypoints, imported by all layers.** A softer
   generation variant. Deferred/rejected: `ceph.authz` and `datadock.authz` live in the
   platform repo with their own deployment trains (RGW hook config; Trino plugin bundle);
   a cross-repo rego library couples releases for a semantic overlap that is actually small
   (`freeze_writes`, denylist, membership). Gate B asserts that overlap behaviorally without
   the coupling. Revisit only if the shared surface grows.

---

## Consequences

**The security claim, stated as its preconditions.** "The gateway is the enforcement boundary
and every object access is per-user authorized and audited" (§2, §6.5, §6.6) holds iff:
1. Rows 1–2 are closed: consumers migrated, the shared tenant-owner key **rotated at RGW and
   verified dead** — not merely un-vended.
2. Rows 3–4 hold all five (b)-conditions, re-verified on cadence; any failure flips them
   to (a).
3. The enumeration sweep found no additional data-touching direct credential, and continuous
   detection is alerting (unknown direct principal ⇒ incident).
4. The console broker's direct RGW-STS object path is retired behind the gateway (§6.7
   supersession).
5. Gates A and B are green for the deployed (policy, bundle, projection) triple.
6. Gateway audit records are actually ingested — the companion S3/Ceph extractor exists,
   otherwise the sink drops them (§3.6) and the audit half of the claim is unobservable.

**Risks and how this decision carries them:**
- **User-facing breakage (row 1).** rclone/CLI users hold the static cred today; closure
  invalidates it. Mitigation: the replacement endpoint (gateway per-user creds) ships first,
  a dated deprecation window is announced, and rotation is a scheduled, verified event. The
  long tail is bounded by the rotation date — deliberately no indefinite grace.
- **Rotation sequencing (rows 1–2 share a secret).** Rotating before Lakekeeper migrates
  breaks every Trino catalog; the runbook orders: engine migration → user migration →
  rotation → canary verification.
- **Engine bandwidth (row 2, proxy mode).** Gateway instances carry analytics scan bandwidth
  until/unless remote signing is verified for the pinned connector — size per §9.3/§9.5;
  this is the accepted §6.5 trade ("pick by bandwidth, not by whether the gateway is
  involved").
- **Rows 3–4 may prove data-capable.** The (b)→(a) flip condition is the mitigation; the
  cost of the flip (re-plumbing infra creds) is accepted rather than weakening the rule.
- **Inventory staleness.** A snapshot inventory decays; that is why D1 makes it a process
  (sweep + detection + owner + cadence), not a document.
- **Corpus governance.** If the corpus stays repo-local it silently stops being the platform
  contract (§6.5 forbids this). Promotion to the platform repo, with this repo consuming it
  read-only or contributing via PR, is a named companion item.
- **Gate B false confidence.** Adapters that mis-model a layer's real input make the suite
  green and worthless; each adapter must be reviewed by that layer's owner.

**Follow-ups inside this repo:**
- Tag ABAC stays blocked until this ADR's closures complete — already enforced in code
  (`src/authz/input.rs`: `object_tags` "never populated until the direct-path question
  resolves"; §5.2's stale-tag-cache hazard is *caused by* direct-path writes the gateway
  never sees).
- Add the OPA-sidecar leg to `tests/policy_corpus.rs` to complete Gate A (§4.3.1).
- Keep every new rego rule inside the regorus builtin subset; Gate A is the enforcement.

---

## Companion work (platform side — crisp checklist)

**Console / platform team:**
- [ ] Replace `GET /harbors/{id}/buckets/{name}/credentials`: stop returning the tenant-owner
      static credential; return a gateway-issued per-user (`sub`-bearing) credential + the
      gateway endpoint (§3.7 item 1, §6.5 "only surviving role of credential vending").
      Publish the deprecation window.
- [ ] Lakekeeper/engines: per-query, `sub`-bearing credential vend minted under an OPA
      decision; point engine S3 endpoints at the gateway (proxy mode, §6.5 impl 1).
- [ ] Verify remote-signing support in the pinned Trino Iceberg connector (§6.5 verify item);
      if unavailable, engines remain on proxy mode — no third option.
- [ ] Rotate the tenant-owner RGW key **after** both migrations above; verify the old key is
      dead (canary must fail). One event closes inventory rows 1–2.
- [ ] Rows 3–4 (Rook admin ops user; per-OrgStorage admin): caps audit; strip object-data
      capability or record the technical bound; namespace + network isolation; alert on any
      object-data op by these principals; written §7.1(b) justification; quarterly review.
      If any condition cannot be met → disposition (a).
- [ ] Operationalize the exposure inventory: initial radosgw-admin enumeration sweep per
      tenant reconciled against the seed; continuous unknown-direct-principal detection;
      named owner; review cadence. Fold in the §3.1 console-broker STS sessions and retire
      that path behind the gateway (§6.7).
- [ ] Data-plane grant projection: emit `s3_grants` / `group_grants` per the contract in
      `policy/gateway/authz.rego`'s header, over the existing bundle delivery (§3.3–§3.4).
      This is the "one grants source" Gate B stands on.
- [ ] Adopt `policy/testdata/corpus.json` as the seed of the **platform-owned** golden corpus
      (§6.5); add `ceph.authz` and `datadock.authz` adapters and cases; wire Gate B
      (cross-layer conformance, invariants I1–I6) into platform CI, triggered by changes to
      any of the three regos, the projection, or the corpus.
- [ ] Ship the S3/Ceph decision-log extractor for records labeled
      `hyperfluid.nudibranches.tech/data-dock-type: s3-gateway` with trusted org-id label
      (shape already fixed in `src/audit/record.rs`; §3.6) — prerequisite for closure being
      observable.
- [ ] Post-closure hardening review (platform-owned; the hook remains defense-in-depth per
      §6.5): once rows 1–2 are closed, alert on — and consider narrowing — the `ceph.authz`
      native-tenant-owner passthrough and admin allows, which then have no legitimate
      data-plane consumer.

**Gateway team (this repo):**
- [ ] Complete Gate A: OPA-sidecar replay leg beside the existing regorus leg in
      `tests/policy_corpus.rs`; identical-decision assertion per §4.3.1.
- [ ] Contribute corpus cases for every new rego branch; keep `allowed_prefixes` comparison
      order-insensitive; stay inside the regorus builtin subset.
- [ ] Keep `object_tags` ungated only after this ADR's closure conditions 1–4 are met and
      §5.2 is separately resolved.
