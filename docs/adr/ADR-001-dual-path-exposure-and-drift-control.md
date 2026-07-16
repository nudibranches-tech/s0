# ADR-001: Dual-path direct-credential exposure and Rego drift control

- **Status**: Proposed
- **Date**: 2026-07-15
- **Scope**: Why enforcement requires closing direct-to-backend credential paths, and how policy drift is controlled when more than one policy codebase evaluates the same access intent. It does not reopen the settled posture that every S3 consumer, engines included, reaches the backend only through the gateway.

---

## Context

s0's entire security claim is **conditional**:

> The enforcement and audit guarantee holds **only if no consumer can reach a backend directly.**

This is an invariant, not a migration detail. In a typical existing deployment the direct-path
exposure is real and non-empty, and it must be closed. Stated in credential terms: the gateway
is the single audited enforcement point for every S3 consumer, and the security property is
conditional on there being **no usable direct-to-backend credential** for anything that touches
user-attributable data — those credentials must be *closed*, not merely tracked. Until the
direct paths are dispositioned, the gateway is a proxy with a policy engine, not an enforcement
boundary.

Two distinct problems are decided here:

1. **Dual-path exposure.** Credentials can exist *today* that reach the S3 backend (e.g. Ceph
   RGW) without traversing any gateway. The exposure list is an artifact an operator must
   **create**, not a datum the gateway reads at decision time: there is no `native_principals`
   bundle field, and native backend users are recognized purely at request time by the
   `<tenant>$<user>` identity shape their requests carry. A native **tenant-owner** credential
   is authorized across the **entire tenant** — every bucket, with no per-user/object/prefix
   scope.

2. **Rego drift.** More than one policy codebase may evaluate the same organization's access
   intent: the in-backend defense-in-depth policy (external), an external analytics-engine PEP
   policy, and the gateway policy (the authz/audit path). Multiple policy codebases over one
   grants source means divergence *is* a bypass. Either generate them from one source, or run a
   shared conformance suite over all. This ADR decides which.

### What is implemented vs planned (as relevant to this ADR)

**Implemented (this repo):**

- The gateway policy `policy/gateway/authz.rego` — deny-by-default, membership necessary but
  not sufficient, grant × (action, bucket, object|prefix) matching, list-narrowing obligations;
  its header documents the grant data contract it consumes. In production the platform pushes
  the policy (rego module + data) as a bundle; the in-repo module is the **compiled-in default**,
  the **local-dev policy**, and the **dual-engine parity oracle** (below) — not the sole source
  of truth.
- The OPA input contract `src/authz/input.rs`. `object_tags` is documented there as gated —
  never populated until the direct-path question resolves — so the code already treats this ADR
  as a blocker for tag ABAC (see ADR-003).
- The audit record `src/audit/record.rs` — one OPA-decision-log-shaped record per request,
  `requested_by` = end-user `sub`, with a trusted org label for fail-closed attribution (see
  ADR-002).
- The golden decision corpus `policy/testdata/corpus.json` and its runner
  `tests/policy_corpus.rs`, which replays it through the embedded regorus PDP. The corpus is
  engine-agnostic and seeds the shared conformance corpus.

**External / planned (the platform):**

- The data-plane grant projection (`s3_grants` / `group_grants`) the gateway rego consumes —
  the "one grants source" that must project S3 grants into the bundle.
- Per-user gateway credentials for humans and CLIs, and per-query sub-bearing engine
  credentials — the replacements that make closure possible.
- Ingestion of the gateway's decision-log record type, without which gateway audit records are
  dropped and closure is unobservable (see ADR-002).

---

## Decision

Three decisions: close the direct paths, fix what the gateway may consume, and control drift.

### D1 — Direct-credential exposure is a maintained, owned artifact; every entry is closed or verifiably isolated

The exposure inventory is **created and owned operationally** (it is not a bundle field, and the
gateway consumes nothing from it at decision time). It is a living artifact with an owner, a
review cadence, and one governing rule:

> Under a per-user audit requirement, "accept in writing that it's outside the model" is **not**
> an available disposition for any credential that can reach user-attributable data — such a
> credential is, by definition, an unaudited direct path.

Every entry gets exactly one of two dispositions:

- **(a) Close** — revoke, and move the consumer onto the gateway with a per-user,
  gateway-issued credential. This is the **only** disposition available to any credential that
  can touch user-attributable data. Two canonical data-touching cases are the tenant-owner
  static credential vended to end users for CLI/rclone use, and the same tenant-owner credential
  configured into an analytics query engine and its catalog. Because these commonly **share one
  underlying secret**, revoking an endpoint is not closure — copies already live in user configs
  and in the engine catalog. Closure means **rotating the tenant-owner key at the backend**,
  which kills every outstanding copy at once, and must therefore be sequenced *after* both
  consumers have migrated (users onto gateway per-user creds; engines onto per-query sub-bearing
  creds), or every CLI user and every query breaks simultaneously.
- **(b) Isolate + bound** — available **only** to a pure infrastructure/control-plane credential
  that never touches tenant object data (e.g. a storage-operator admin credential), and only
  while **all** of the following hold, flipping to (a) the moment any fails:
  1. A written justification exists: purpose, and why this is not a data path.
  2. The binding is **technically verified**, not asserted: enumerate the credential's backend
     capabilities; it must have no S3 object read/write capability — admin/ops scope only. Where
     the backend can express a narrower bound (caps, prefix, IAM), apply the narrowest. This
     backend-native scoping is **blast-radius defense-in-depth on a non-data path, never an
     authorization mechanism** — which is exactly why (b) is unavailable for anything
     data-touching.
  3. Isolation: the secret exists only in the operator's secret store; its network path is
     restricted to backend admin endpoints; it is never exposed on any tenant or user surface.
  4. Detection: any object-data operation observed under the principal alerts and is handled as
     an incident.
  5. Rotation and a periodic review are scheduled.

If verification in step 2 shows the credential *can* read or write tenant objects and that
capability cannot be removed, it is by definition data-touching, (b) is unavailable, and the
infrastructure function must be re-plumbed so its data-plane capability is gone — option (a).

**Exhaustiveness is a process, not a snapshot.** A verified set of known direct credentials is a
*seed*, not a proof of completeness. The inventory therefore ships with (i) an initial
enumeration sweep of all backend users and keys per tenant, reconciled against the seed;
(ii) continuous detection — any principal observed on the direct path that is not in the
inventory is an incident; and (iii) migration of any identity-preserving but unaudited
convenience path (for example a per-user backend STS broker) onto the gateway, after which the
direct mint stops.

### D2 — What the gateway consumes, and what it must never consume

The gateway's runtime contract is deliberately ignorant of the inventory:

- It consumes the per-org bundle (`user_attributes`, `bucket_attributes`,
  `org_settings.freeze_writes`, and the planned `s3_grants` / `group_grants`) in exactly the
  shape documented in the header of `policy/gateway/authz.rego`. It does **not** read an exposure
  list, and no rego rule may branch on "is this principal also a native backend user."
- It authorizes with its **own per-tenant/per-backend credential** on the forward path, and never
  depends on backend IAM/STS/hooks for enforcement or audit.
- It emits one decision record per request in the `src/audit/record.rs` shape, which is what
  makes "closed" *observable* once the platform ingests that record type.

### D3 — Drift control: a shared conformance suite over one grants source (chosen), not code generation

Of the two options, we choose **a shared conformance suite over all policy codebases**, anchored
on a single grants source of truth — not generating the policies from one source.

**What "one grants source" already means here.** The *data* is generated from one source: the
grants store projects into per-org bundles, and no layer hand-maintains grant data. With the
bundle design, the platform pushes both the policy module and that data. What is hand-written,
and therefore what drifts, is the *policy code*. The suite pins the combined behavior of the
hand-written policies over that one data source.

**The layers under drift control:**

| Layer | Policy | Input domain | Role |
|---|---|---|---|
| In-backend hook | the in-backend defense-in-depth policy (external) | Backend request: identity shape, bucket. No request body — structurally cannot see copy-source, multi-delete keys, or the POST form key | Defense-in-depth, backend-only; membership + denylist |
| Analytics-engine PEP | an external analytics-engine PEP policy | SQL-logical: `catalog.schema.table[.column]`; never an S3 key | Defense-in-depth: row/column masking |
| Gateway | `s0.gateway` — `policy/gateway/authz.rego` (this repo) | Full parsed input superset (`src/authz/input.rs`) | **The** object-authz and audit path, for all backends |

**Suite architecture:**

1. **Shared golden corpus.** The corpus is a **shared conformance asset**, owned alongside the
   policy bundle rather than living only in this repo. This repo's `policy/testdata/corpus.json`
   **seeds** it: engine-agnostic cases covering grant/prefix/action matching,
   denylist-beats-membership, `freeze_writes`, list narrowing (`narrow_prefix` /
   `allowed_prefixes`), and the blind-spot decompositions (copy source-read/dest-write halves;
   per-key multi-delete). The shared corpus extends the seed with cases for the external
   defense-in-depth and analytics-PEP policies, plus the cross-layer invariants below.

2. **Gate A — dual-engine parity (this repo; partially implemented).** Every gateway policy or
   bundle revision replays the corpus through **both** engines: the **OPA sidecar** (the shipping
   default) and **embedded regorus** (the gated fast path). Identical decisions are required in
   CI before regorus may serve traffic. Implemented today: the regorus leg
   (`tests/policy_corpus.rs` replays the corpus through the embedded PDP, comparing
   `allowed_prefixes` order-insensitively — the rego normalizes list-obligation ordering for
   exactly this reason). Remaining: the OPA-sidecar leg of the same runner. The standing
   constraint that makes Gate A meaningful is that all gateway rego stays inside regorus's
   supported builtins — no `crypto.*`, no `io.jwt.*`.

3. **Gate B — cross-layer conformance (control-plane integration, out of scope for this
   repository).** Runs on every change to any policy codebase, the bundle/projection builder, or
   the corpus. Each layer is evaluated through its own input adapter, because the input domains
   differ by design. Gate B asserts *relations*, not equality, because the layers are
   intentionally non-identical:
   - **I1 — kill-switch dominance:** `freeze_writes = true` ⇒ every write-class decision denies
     in the gateway **and** in the in-backend defense-in-depth policy.
   - **I2 — denylist dominance:** a denylisted `(sub, bucket)` denies in the gateway and in the
     in-backend policy for that sub. (On the forward path the gateway's request carries the
     gateway's backend credential, not the sub — the in-backend half guards the residual direct
     path only.)
   - **I3 — blast radius:** the gateway's per-tenant backend credential is accepted by the
     in-backend policy only within its own tenant; cross-tenant attempts deny.
   - **I4 — availability non-drift:** every gateway-allow, re-issued with the gateway's backend
     credential, is allowed by the in-backend policy. A defense-in-depth layer that blocks the
     single legitimate path is also drift.
   - **I5 — engine-plane read consistency:** for a table whose storage is prefix `P`, a
     read-allow in the analytics-engine PEP for sub `S` implies a gateway `read_objects`-allow
     for `S` under `P`, or every governed query breaks at the object layer. The converse — an
     SQL grant projected without its object-prefix grant — is a projection lint, not a policy
     assertion.
   - **I6 — deny-by-default floor:** unknown action, unknown tenant, or missing grant data
     evaluates to deny at the gateway; corpus negative cases pin this.

**Why the conformance suite is the right branch** (and generation is not): the policies answer
different questions over different input contracts at different semantic levels, and two of them
are *intentionally coarser* than the gateway's. The invariant worth enforcing is
dominance/consistency, which a test suite states directly and a generator cannot express without
inventing equivalences that do not hold. A generator would itself need a conformance suite to be
trusted — the suite is mandatory on both branches, so generation adds a fourth policy-bearing
codebase without removing any work.

---

## Alternatives considered

1. **Risk-register the existing direct creds ("accept in writing") and ship.** Rejected: this is
   not an available disposition for any credential that can reach user-attributable data — the
   whole guarantee holds only if no consumer can reach a backend directly. A tracked bypass is
   still a bypass, and the tenant-owner paths are precisely user-attributable data paths.

2. **Keep vended credentials but scope them with backend IAM / prefix-bounded keys.** Rejected as
   an authorization mechanism: any design that depends on a backend-native capability for
   authorization or audit is disqualified (a plain S3 backend may not support scoping at all).
   Independently fatal: a scoped direct credential still produces **zero per-request decision
   records** and acts under a shared identity. Scoping survives only inside disposition (b), on
   verified non-data paths.

3. **Vend per-user credentials that authenticate directly to the backend.** Rejected: this audits
   only the vend, not each object op, so it fails the per-request bar, and it re-couples identity
   to the backend's STS, which enforcement must not depend on.

4. **Treat engines as a trusted tier with a broad credential.** Rejected: an analytics PEP never
   sees an S3 object key, performs no file-level authorization, and emits no per-object decision —
   so a broad engine credential fails per-user audit at the object layer.

5. **Generate all policies from one source.** Rejected for drift control:
   - The input contracts and semantic levels are disjoint: the in-backend hook input (no request
     body — it structurally cannot see the copy-source/multi-delete/POST-form blind spots),
     SQL-logical input (no object keys), and the parsed request superset. A generator spanning
     them must embed three enforcement semantics — it becomes a fourth policy codebase whose
     output still needs a conformance suite to trust.
   - The layers are *deliberately* non-equivalent: the in-backend policy stays membership +
     denylist on purpose, and there is nothing in it to "port" for prefix/op matching — that
     logic is net-new in the gateway. No generator output can be "coarser on purpose" without
     hand-written per-layer semantics, at which point it is not generation.
   - There is no function from object-prefix grants to the analytics PEP's row/column filters;
     the SQL plane's value-add is not derivable from the S3 grant model.
   - A generator adds a new way to emit rego outside the regorus builtin subset, which Gate A
     exists to forbid.

   What we *do* keep from this branch: the **data** stays generated from the one grants source —
   the rejection covers policy code only.

6. **One shared rego package with three entrypoints, imported by all layers.** A softer
   generation variant. Deferred: the external policies live in their own repos with their own
   deployment trains; a cross-repo rego library couples releases for a semantic overlap that is
   small (`freeze_writes`, denylist, membership). Gate B asserts that overlap behaviorally
   without the coupling. Revisit only if the shared surface grows.

---

## Consequences

**The security claim, stated as its preconditions.** "The gateway is the enforcement boundary
and every object access is per-user authorized and audited" holds iff:

1. Every data-touching direct credential is closed: consumers migrated, and the shared
   tenant-owner key **rotated at the backend and verified dead** — not merely un-vended.
2. Every isolated infra credential holds all five (b)-conditions, re-verified on cadence; any
   failure flips it to (a).
3. The enumeration sweep found no additional data-touching direct credential, and continuous
   detection is alerting (unknown direct principal ⇒ incident).
4. Any identity-preserving but unaudited convenience path (e.g. a backend STS broker) is retired
   behind the gateway.
5. Gates A and B are green for the deployed (policy, bundle, projection) triple.
6. Gateway audit records are actually ingested by the platform; otherwise the audit half of the
   claim is unobservable.

**Risks:**

- **User-facing breakage.** CLI/rclone users hold the static cred today; closure invalidates it.
  Mitigation: the replacement (gateway per-user creds) ships first, a dated deprecation window is
  announced, and rotation is a scheduled, verified event — no indefinite grace.
- **Rotation sequencing.** When users and engines share a secret, rotating before the engine
  migrates breaks every catalog; the order is engine migration → user migration → rotation →
  canary verification.
- **Engine bandwidth (proxy mode).** Gateway instances carry analytics scan bandwidth
  until/unless remote signing is verified for the pinned connector; this is the accepted trade —
  pick by bandwidth, not by whether the gateway is involved.
- **Isolated creds may prove data-capable.** The (b)→(a) flip is the mitigation; the cost of
  re-plumbing infra creds is accepted rather than weakening the rule.
- **Inventory staleness.** A snapshot decays; that is why D1 makes it a process (sweep +
  detection + owner + cadence), not a document.
- **Corpus governance.** If the corpus stays repo-local it silently stops being the shared
  contract. Promotion to a shared asset, with this repo consuming it read-only or contributing by
  PR, is control-plane integration (out of scope for this repository).
- **Gate B false confidence.** Adapters that mis-model a layer's real input make the suite green
  and worthless; each adapter must be reviewed by that layer's owner.

**Follow-ups inside this repo:**

- Tag ABAC stays blocked until these closures complete — already enforced in code (`object_tags`
  is never populated until the direct-path question resolves; the stale-tag-cache hazard is
  *caused by* direct-path writes the gateway never sees). See ADR-003.
- Add the OPA-sidecar leg to `tests/policy_corpus.rs` to complete Gate A.
- Keep every new rego rule inside the regorus builtin subset; Gate A is the enforcement.

---

## Control-plane integration (out of scope for this repository)

This ADR's closures and drift-control suite depend on work the platform owns, not this repo:
execute the direct-credential dispositions (close data-touching creds, isolate residual
infrastructure creds on verified non-data paths) and stand up the exposure inventory with an
owner, an enumeration sweep, and continuous unknown-direct-principal detection; emit the
`s3_grants` / `group_grants` projection over the existing bundle delivery — the "one grants
source" Gate B stands on; ingest the gateway's decision-log record type so closure is observable;
and promote `policy/testdata/corpus.json` to the shared conformance corpus with Gate B
(cross-layer invariants I1–I6) wired into its CI, triggered by changes to any policy codebase,
the projection, or the corpus.
