# Architecture Decision Records — hyperfluid S3 gateway

This set records the load-bearing design decisions for the gateway (`hyperfluid-s3-gateway`):
an S3 API re-issuer with a policy gate in the middle, whose product claim is that **every S3
object access — human, external app, or engine — is authorized as the end-user identity and
emits exactly one OPA decision record per request** (PROMPT §2, §6.6). The six ADRs resolve
the brief's open questions without reopening its settled invariants (§6) or the
engines-through-gateway posture (§6.5): they disposition the direct-to-backend credential
exposure and fix cross-policy drift control (ADR-001), freeze the audit record and its console
extractor contract (ADR-002), gate object-tag ABAC behind §7.1 (ADR-003), settle list
narrowing and pagination (ADR-004), operationalize the PDP engine posture and cache
correctness (ADR-005), and freeze the two platform contracts the gateway consumes — grant
projection and STS identity (ADR-006). Each ADR separates what EXISTS from what is
NOT-YET-BUILT and ends with a companion checklist; the security claim is **conditional** on
the blockers below, and every ADR is written to keep the gateway fail-closed until they clear.

## The ADRs

| ID | Title | Status | Decision (one sentence) |
|---|---|---|---|
| [ADR-001](ADR-001-dual-path-exposure-and-drift-control.md) | Dual-path direct-credential exposure and Rego drift control | Proposed | The direct-credential inventory is a maintained platform artifact seeded with the four verified §3.7 credentials — tenant-owner vend and its Trino/Lakekeeper copy must be **closed** (one coordinated rotation), Rook/OrgStorage admin creds get conditional **isolate + bound** with a flip-to-close rule — and drift across the three policy codebases is controlled by a shared conformance suite (Gate A dual-engine parity, Gate B cross-layer invariants I1–I6) over the single grants source, not by generation. |
| [ADR-002](ADR-002-decision-log-record-shape.md) | Decision-log record shape and the console Ceph/S3 extractor contract | Proposed | The gateway emits exactly one OPA-native decision-log record per S3 request (`decision_id`/`path`/`input`/`result`/`requested_by`/`timestamp`/`labels`/`gateway{}` per `src/audit/record.rs`), discriminated by label `data-dock-type == "s3-gateway"` with a trusted org-id label (never `input.resource.*`), with copy and multi-delete folded into single records and a new console extractor + stored variant as companion work. |
| [ADR-003](ADR-003-object-tag-abac-toctou-and-cache.md) | Object-tag ABAC — TOCTOU window, tag-cache invalidation, and the §7.1 ship-gate | Proposed | Object-tag ABAC ships only after §7.1 resolves to "no direct path" (§5.2 option iii — the interim hard-wiring already exists: `object_tags` never populated, tag-bearing decisions never cached); the eventual design makes tags restrict-only, gates tag mutation behind a new `manage_tags` action, forbids tag-decision caching without a gateway-minted tag-version in the key, and classifies deny classes R/I/N by tolerance of the irreducible TOCTOU window. |
| [ADR-004](ADR-004-list-multiprefix-handling.md) | ListObjects narrowing — single-prefix rewrite and bounded multi-prefix fan-out with a gateway-owned cursor | Proposed | Single-prefix listings rewrite `input.prefix` in the `&mut` typed hook; multi-prefix listings use bounded fan-out-and-merge (default 16, fail-closed above and for any unimplemented tier) with a sealed, stateless gateway-owned cursor (`{version, scope_hash, resume_key}`, resumed via plain `start_after`/`marker`, re-decided per page) and delimiter synthesis — response filtering is rejected on the §5.1 ContinuationToken/IsTruncated/MaxKeys analysis. |
| [ADR-005](ADR-005-pdp-engine-posture-and-parity-gate.md) | PDP engine posture — sidecar OPA by default, embedded regorus only behind a dual-engine parity gate | Proposed | A gateway-owned, gateway-fed sidecar OPA on loopback is the only ungated engine (both engines run the byte-identical embedded `GATEWAY_REGO`); embedded regorus may serve traffic only after the dual-engine parity gate is green — Mode A repo-CI replay of the corpus through pinned OPA + regorus with canonical `Decision` equality, Mode B bundle-release replay, six go/no-go criteria — and the §4.3.2 revision-keyed cache's four load-bearing correctness conditions are pinned. |
| [ADR-006](ADR-006-companion-grant-projection-and-identity.md) | Companion platform work — data-plane grant projection and STS identity | Proposed | Freezes the two contracts the gateway consumes but does not build: the grant projection (`tenants[t].s3_grants[sub]` / `group_grants[group]`, arrays of `{bucket, actions[], prefixes[]}`, an additive superset of the existing per-Org ceph-bundle with content-revision semantics) and STS identity (gateway-minted `HFST` sessions with HMAC-derived secrets, keyed by the bare OIDC `sub`, with the console fronting the gateway mint instead of RGW STS). |

All decisions assume the settled invariants: deny-by-default with membership necessary but
not sufficient (§6.2), live revocation via bundle revisions (§6.1), backend-agnostic
enforcement that never depends on a backend-native capability (§6.7), and per-request,
per-end-user audit (§6.6).

## Blockers before the security claim holds

The claim — "the gateway is the enforcement boundary and every object access is per-user
authorized and audited" — is **conditional** (§2, §6.5): it holds only when no consumer can
reach a backend directly. §7.1 makes this "a blocker, not a footnote", and rules that
**"accept in writing that they're outside the model" is NOT an available disposition** for
any credential that can reach user-attributable data. Until every item below is done, the
gateway is a proxy with a policy engine, not an enforcement boundary (ADR-001 Consequences;
ADR-006 D5 adds: no production enforcement claim before the grant projection lands — on
today's real bundles the gateway is fail-closed deny-everything, safe but not enforcing).

1. **Close the tenant-owner credential paths (§3.7 rows 1–2 — one shared secret).**
   The credentials-endpoint vend to end users and the Trino/Lakekeeper catalog copy are
   user-attributable data paths; only disposition (a) close is available. Closure = migrate
   both consumers (users onto gateway per-user creds; engines onto the §6.5 gateway path),
   **then** rotate the tenant-owner key at RGW and verify the old key dead (canary must
   fail). Rotating early breaks Trino and every CLI user at once. (ADR-001 D1; ADR-003
   G1/C1–C2.)
2. **Verify and bound the infra creds (§3.7 rows 3–4).** Rook admin ops and per-OrgStorage
   admin get isolate + bound only while all five (b)-conditions hold — written
   justification, technically verified no-object-data capability, isolation, detection,
   rotation + quarterly review — and flip to close the moment any fails. (ADR-001 D1;
   ADR-003 G2/C3.)
3. **Exhaustiveness as a process, not a snapshot.** Initial RGW enumeration sweep reconciled
   against the seed inventory; continuous detection where an unknown direct principal is an
   incident; a named owner and cadence. The sweep must fold in the console broker's per-user
   RGW-STS sessions. (ADR-001 D1; ADR-003 G3/C4.)
4. **Retire the console broker's direct RGW-STS object path** behind the gateway
   (`resolve_user_s3_context` repointed at the gateway mint; RGW-STS leg decommissioned) —
   §6.7 marks the broker as superseded. (ADR-001; ADR-006 D5 Phase 2 / C6, R7.)
5. **Gates A and B green** for the deployed (policy, bundle, projection) triple: dual-engine
   parity in repo CI plus cross-layer conformance (invariants I1–I6 over `ceph.authz` /
   `datadock.authz` / `hyperfluid.gateway`) in platform CI — divergence *is* a bypass.
   (ADR-001 D3; ADR-005 D5.)
6. **Gateway audit records actually ingested.** Today the console sink drops them (no S3/Ceph
   extractor exists, §3.6), so closure would be unobservable and the day-one §6.6 audit
   requirement is unmet — the extractor, stored variant, and authenticated idempotent ingest
   must ship. (ADR-001; ADR-002 R1/C1–C4/C8.)

Downstream gates that stay shut until the above clear: object-tag ABAC (ADR-003 D1/D7 — G1–G3
are exactly items 1–3), and any production enforcement claim at all before the ADR-006 grant
projection lands (Phase 1 acceptance gate). Embedded regorus additionally stays NO-GO in
production until ADR-005's Mode B exists, independent of §7.1.

## Companion (platform-side) work — consolidated checklist

Deduplicated across the six ADRs; source items in parentheses. Same-team follow-ups inside
this repo (Gate A OPA leg, `tag-abac` feature gate, mint endpoint, bundle poller, etc.) live
in each ADR's Follow-ups section and are not repeated here.

### 1. §7.1 credential closure (platform security)

- [ ] Replace `GET /harbors/{id}/buckets/{name}/credentials`: stop vending the tenant-owner
      static credential; return a gateway-issued per-user credential + gateway endpoint;
      publish a dated deprecation window (ADR-001; ADR-003 C1).
- [ ] Migrate Trino/Iceberg (Lakekeeper) onto per-query, `sub`-bearing credentials minted
      under an OPA decision, S3 endpoint = the gateway, proxy mode first (ADR-001; ADR-003 C2).
- [ ] Verify remote-signing support in the pinned Trino Iceberg connector; if unavailable,
      engines stay on proxy mode — no third option (ADR-001).
- [ ] Rotate the tenant-owner RGW key **after** both migrations; canary-verify the old key
      is dead — one event closes inventory rows 1–2 (ADR-001).
- [ ] Rows 3–4 (Rook admin ops; per-OrgStorage admin): caps audit, strip or bound object-data
      capability, namespace + network isolation, alert on any object-data op, written §7.1(b)
      justification, quarterly review; any failed condition ⇒ disposition (a) (ADR-001; ADR-003 C3).
- [ ] Operationalize the exposure inventory: enumeration sweep, continuous
      unknown-direct-principal detection + alert per bay, named owner, cadence; fold in and
      retire the console-broker STS sessions (ADR-001; ADR-003 C4).
- [ ] Post-closure hardening review: alert on — and consider narrowing — the `ceph.authz`
      native-tenant-owner passthrough and admin allows once rows 1–2 close (ADR-001).

### 2. Grant projection and bundle delivery (console)

- [ ] Extend the permission catalog with the object-op family
      (`read_objects | list_objects | write_objects | delete_objects | manage_lifecycle`)
      and an object-prefix grant scope (ADR-006 C1).
- [ ] Build the projection emitting exactly the ADR-006 D1 shape
      (`s3_grants[sub]` / `group_grants[group]` of `{bucket, actions[], prefixes[]}`), with
      build-time validation: closed action set or `["*"]`; prefixes bare, `/`-terminated
      unless a stem is intended, never `""`; `manage_lifecycle` ⇒ `prefixes: []`; every
      granted sub present in `user_attributes` (ADR-006 C2; ADR-001; ADR-004 C1).
- [ ] Grow the bundle additively on the same endpoint/builder/gzip document; regression test
      proving `ceph.authz` decisions unchanged on the superset bundle (ADR-006 C3).
- [ ] Endpoint semantics: byte-stable serialization for unchanged data; every grant mutation
      changes the served bytes; publish + monitor the build/propagation freshness SLO — this
      is the §6.1 revocation-latency bound (ADR-006 C4; ADR-005 C1 revision contract).
- [ ] Keep `user_attributes[sub].groups` authoritative and fresh — membership source and
      target of the group-intersection tightening (ADR-006 C5).
- [ ] Later, tag-ABAC enablers (post-gate): add `manage_tags` to the grant vocabulary and the
      D3 fetch-predicate key to `bucket_attributes` (ADR-003 C5–C6).
- [ ] Grant-authoring lint: warn/require-override above `list_fanout_max_prefixes`
      (default 16) effective prefixes per (subject∪groups, bucket, action); surface the
      deployed bound in the console (ADR-004 C2).

### 3. Decision-log ingest (console)

- [ ] New S3/Ceph extractor matching exclusively on
      `data-dock-type == "s3-gateway"`; org from the org-id label, fail-closed; principal
      from `requested_by` (validated against `input.principal.sub`); unknown fields ignored
      (ADR-002 C1; ADR-001).
- [ ] New stored decision variant carrying the S3 fields (`action`, `bucket`, `object`,
      `prefix`, `copy_source`, `delete_keys`, `denied_keys`, `outcome`, `backend_*`, …) —
      not shoehorned into the console or Trino variants (ADR-002 C2).
- [ ] Keep drop-with-warning for non-matching records + a drop-rate metric/alert; console
      test that a gateway record is claimed only by the new extractor (ADR-002 C3, C5).
- [ ] Idempotent ingest keyed on `decision_id` (at-least-once delivery from spill replay)
      and authenticated ingest for the gateway sender (ADR-002 C4, C8).
- [ ] Confirm ingest capacity vs the worst-case batch (multi-delete records ~2 MB); define
      retention + access policy for the stored variant — records contain object keys
      (ADR-002 C6, C7).

### 4. Golden corpus and conformance gates (platform CI)

- [ ] Adopt `policy/testdata/corpus.json` as the seed of the **platform-owned** golden corpus
      (§6.5: "a platform asset, not a repo asset") (ADR-001; ADR-005 C4).
- [ ] Wire Gate B — cross-layer conformance over `ceph.authz` / `datadock.authz` / gateway
      rego with per-layer input adapters, asserting invariants I1–I6; triggered by changes to
      any rego, the projection, or the corpus (ADR-001 D3).
- [ ] Mode B release gate: replay corpus inputs + synthesized per-grant probes through pinned
      OPA and regorus over every released bundle's data; divergence blocks release while any
      embedded-engine gateway is live (ADR-005 C2).
- [ ] Contribute console-emitted bundle fixtures + expected decisions to the corpus so the
      ADR-006 D5 acceptance gate and the dual-engine parity gate run on real projection
      output (ADR-006 C8).
- [ ] Extend the corpus with multi-prefix/delimiter-synthesis obligation cases (ADR-004 C3)
      and, post-gate, object-tag cases (ADR-003 C7).

### 5. Identity / STS cutover (console)

- [ ] Repoint the console STS flow (`resolve_user_s3_context` and object browse/upload/delete
      routes) at the gateway mint and the gateway S3 endpoint — humans and AI agents alike;
      schedule the RGW-STS leg for decommission with ADR-001 (ADR-006 C6).
- [ ] Publish per-Org OIDC verification parameters (issuer, JWKS, audience/token-exchange
      conventions) and agree the `AssumeRoleWithWebIdentity`-shaped mint API (ADR-006 C7).
- [ ] Explicit non-goal sign-off: guardrails-on-S3 and `sensitivity` enforcement stay out of
      the grant contract until productized through the same corpus gate (ADR-006 C9).

### 6. Deployment / ops (platform ops)

- [ ] Pin the sidecar OPA image version and publish it to this repo (`.opa-version`); OPA
      bumps require a green Mode A run before rollout (ADR-005 C3).
- [ ] Sidecar deployment shape: one OPA per gateway pod, loopback only, no external listener,
      no independent console polling — the gateway feeds policy at boot and data on install;
      sidecar health gates pod readiness (ADR-005 C5).
- [ ] Client-facing docs: listings are scope-narrowed; continuation tokens are opaque and may
      exceed AWS-typical size; policy change mid-listing means "restart the listing";
      above-bound listings return an actionable deny (ADR-004 C5).
