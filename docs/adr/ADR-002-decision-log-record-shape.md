# ADR-002: Decision-log record shape

- **Status**: Proposed
- **Date**: 2026-07-15
- **Owners**: gateway team (this repo)
- **Related**: `src/audit/record.rs`, `src/audit/sink.rs`, `src/authz/input.rs`, `src/authz/decision.rs`, `policy/gateway/authz.rego`; ADR-001, ADR-003

## Context

s0 exists to guarantee, for regulated (e.g. hospital) deployments, that every S3 object access —
by a human, an external app, or an analytics engine — is authorized as the **end-user identity**
and emits **exactly one OPA decision record per request**, attributed to that end-user identity.
Coarser-grained audit (per-grant, per-session, per-table) does **not** satisfy it.

What the platform's decision-log sink provides today:

- **(implemented)** An ingest endpoint (`POST /api/v1/decision-logs`) that accepts **OPA's native
  decision-log format**, batched: the body is a JSON array of decision records
  (`{ decision_id, path, input, result, labels, requested_by, timestamp, … }`).
- **(implemented)** The sink routes each record to a typed consumer by a discriminator label (a
  `record type`), and reads org attribution only from a **trusted** field. A record matching no
  consumer is **dropped with a warning**; org attribution is **fail-closed** — if the org cannot
  be read from a trusted field, the record is discarded, never guessed.
- **(planned / external)** There is **no** S3 record type yet. A control-plane consumer must add
  one to route and store gateway records. This ADR fixes that record shape *first*, so both sides
  build against one agreed schema. The required content is: principal, action, backend, tenant,
  bucket, object/prefix, copy-source, decision + reason, status, and org in a trusted field (a
  label, or an input field).

What is implemented in this repo:

- The record shape in `src/audit/record.rs` (`AuditRecord`, `GatewayMeta`, label constants,
  `DECISION_PATH`).
- Async, batched, non-blocking delivery with disk spill in `src/audit/sink.rs` (audit-emit
  failure never fails the request).
- The `input` and `result` payloads are the live authorization types: `src/authz/input.rs` (the
  OPA input contract) and `src/authz/decision.rs` (the verdict deserialized from
  `data.s0.gateway.decision` in `policy/gateway/authz.rego`).

This ADR freezes that record shape as the wire contract and specifies what a control-plane
consumer must do, so both sides build against one agreed schema and no existing consumer
mis-claims gateway records.

## Decision

### D1. Envelope: OPA native decision-log shape, one extra `gateway` block

The gateway emits records in the shape the sink already ingests, implemented verbatim in
`src/audit/record.rs`. Serialized field order and optionality follow that file.

| Field | Type | Value / semantics |
|---|---|---|
| `decision_id` | string | Gateway-generated UUID, unique per record. **Idempotency key** for ingest (see D5). |
| `path` | string | Constant `"s0/gateway/decision"` (`DECISION_PATH`) — the slash form of the single rego rule the PDP evaluates, `data.s0.gateway.decision` (`policy/gateway/authz.rego`, package `s0.gateway`). OPA decision-log convention. |
| `input` | object | The **full OPA input** (`src/authz/input.rs::OpaInput`) in *request-level* form (see D4): `principal{sub,type,attributes}`, `backend{id,kind}`, `tenant`, `organization_id`, `action`, `bucket`, `object?`, `prefix?`, `copy_source?`, `delete_keys?`, `object_tags?`, `request{method,params?,headers_subset?}`. |
| `result` | object | The aggregate PDP verdict (`src/authz/decision.rs::Decision`): `allow: bool`, `reason: string` (always present — deny reasons are first-class), `obligations{narrow_prefix?, allowed_prefixes?}`. Obligations expose any list-narrowing rewrite the PEP applied, so the audit trail shows *what was actually enumerated*, not just that a list was allowed. |
| `requested_by` | string | `input.principal.sub` — the **end-user** OIDC `sub` (never a shared/service identity, engines included). Denormalized copy of `input.principal.sub`; `AuditRecord::new` sets it from the input by construction. In stock OPA this field carries the PDP client address; for the `s3-gateway` record type this ADR fixes its meaning as the principal, mirroring how each record type defines its own principal source. |
| `timestamp` | string | RFC3339 UTC, decision time. |
| `labels` | map | Exactly the two routing/attribution labels of D2. |
| `gateway` | object | S3-specific fields beyond the OPA envelope (`GatewayMeta`): `backend_id: string`, `backend_kind: "ceph"\|"remote_s3"`, `outcome: "allowed"\|"denied"\|"error"`, `denied_keys: [string]` (omitted when empty), `backend_status: u16` (omitted unless a backend HTTP response was received). |

`result.allow` and `gateway.outcome` are deliberately distinct: `allow` is the **policy
verdict**, `outcome` is the **final disposition**. Normatively:

- `outcome = "denied"` — policy refused; nothing was forwarded; `backend_status` absent.
- `outcome = "allowed"` — authorized and forwarded; `backend_status` carries whatever the
  backend returned, **including backend 4xx/5xx** (an authz-allowed request that the backend
  rejects is still `allowed` for audit purposes — the authorization question and the storage
  outcome are separate facts, both recorded).
- `outcome = "error"` — authorized but the forward failed before any backend response
  (dispatch/transport failure), or an internal gateway failure; `backend_status` absent.

Every required content element maps onto a concrete field:

| Required content | Record field |
|---|---|
| principal | `requested_by`, `input.principal` |
| action | `input.action` |
| backend | `gateway.backend_id` / `gateway.backend_kind` (mirror of `input.backend`) |
| tenant | `input.tenant` |
| bucket | `input.bucket` |
| object / prefix | `input.object` / `input.prefix` / `input.delete_keys` |
| copy-source | `input.copy_source` |
| decision + reason | `result.allow` + `result.reason` |
| status | `gateway.outcome` + `gateway.backend_status` |
| org in a trusted field | `labels["s0.dev/organization-id"]` (D2) |

### D2. Discriminator and trusted org attribution: labels

Constants in `src/audit/record.rs`:

- `labels["s0.dev/record-type"] = "s3-gateway"` — the discriminator a consumer routes on, the
  same mechanism the sink already uses for its other record types.
- `labels["s0.dev/organization-id"] = <org-id>` — the trusted org attribution the fail-closed
  rule reads.

The trusted org can be carried either in a label or in an input field. We choose the **label**,
and the reasoning is load-bearing:

1. **No collision with consumers keyed on the input body.** Some decision consumers match on a
   trusted `input.resource.organization_id`. A gateway record carrying that field could be
   claimed by such a consumer and stored as the wrong variant, silently corrupting the audit
   stream. The input contract has no `resource` envelope (`src/authz/input.rs` carries
   `organization_id` at the top level), and the gateway **MUST never emit `input.resource.*`** —
   with that invariant, plus a distinct `path` (`s0/gateway/decision`) and a distinct record-type
   label, gateway records match **no** other consumer. Until the S3 consumer lands they are
   dropped-with-a-warning (safe, fail-closed, no misattribution); once it lands, routing order is
   immaterial because the match sets are disjoint.
2. **Trust is a property of the producer, not the JSON.** The org value is populated by the
   gateway from its own deployment configuration — the per-org bundle subscription
   (`/organizations/{organization_id}/ceph-bundle`) and the backend/tenant registry — never from
   anything the client sent. `AuditRecord::new` copies `input.organization_id` (a PEP-populated
   field documented as "trusted org attribution", `src/authz/input.rs`) into the label. This is
   what makes fail-closed attribution sound.

`input.principal.sub` is the bare OIDC `sub` (subjects are the OIDC `sub`), the same key the
bundle uses (`data.tenants[t].user_attributes[sub]`, consumed by
`policy/gateway/authz.rego::member`) — not the backend-decorated `$oidc$<sub>` form, which is a
backend identity artifact the gateway supersedes.

### D3. `input` and `result` are the live authorization values — no parallel audit schema

The record embeds the exact `OpaInput` the PDP decided on and the exact `Decision` it returned.
There is no second, hand-maintained audit DTO to drift from the authz path; decision and audit
derive from the same parsed request object. Field names in `src/authz/input.rs` are documented as
a **stable wire schema**; this ADR extends that stability guarantee to the whole record. Evolution
is **additive-only**, and consumers MUST ignore unknown fields.

### D4. Exactly one record per S3 request — and how blind-spot ops fold into it

**The gateway emits exactly one record per S3 request**, at the typed per-op seam where the
authoritative decision is made. One S3 request is one object operation, even when the PEP
decomposes it into several PDP questions internally (per-key / per-half sub-decisions): the
request-level `input` carries the full detail and `result` is the aggregate verdict. Per-request
granularity is the floor — multipart uploads, for example, emit one record per part request.

| Op | PDP questions | The one record |
|---|---|---|
| GetObject / HeadObject / PutObject / DeleteObject / PostObject | 1 | `input.object` = key; `result` = the verdict as returned by rego. |
| ListObjectsV2 / ListObjects | 1 | `input.prefix` = requested prefix; `result.obligations` records any narrowing applied. |
| **CopyObject** (blind spot #1) | 2 — source read (`read_objects` on source bucket/key) and dest write (`write_objects` on dest) | Request-level input: `action = "write_objects"`, `bucket`/`object` = destination, `copy_source = {bucket, key}` = source (`src/authz/input.rs`). `result.allow = true` iff **both** halves allowed. On deny, the source half is evaluated first and the aggregate reason is the denying half's rego reason prefixed with the half: `"copy source: <reason>"` or `"copy dest: <reason>"`. |
| **DeleteObjects** (blind spot #2) | N — one per key (`input.object` = key, `action = "delete_objects"`), N ≤ 1,000 by the semantic cap enforced before PDP fan-out | Request-level input: `delete_keys` = the full requested key list, `object` omitted. The PEP strips unauthorized keys (per-key filtering) and lists them in `gateway.denied_keys`. `result.allow = true` iff at least one key survived and the filtered request was forwarded (`outcome = "allowed"`, `denied_keys` non-empty on partial denial; aggregate reason `"allow: partial (k of n keys granted)"`). `result.allow = false` iff **every** key was denied (`outcome = "denied"`, `denied_keys` = all requested keys, nothing forwarded; reason = the per-key rego deny reason, uniform across the fixed reason set in `policy/gateway/authz.rego`). |

Aggregate reason strings for decomposed ops (`"copy source: …"`, `"allow: partial …"`) are
**PEP-composed** via `Decision::allow/deny` (`src/authz/decision.rs`), normative as of this ADR;
they are not rego outputs and do not affect the dual-engine parity gate, which compares raw
per-question engine outputs.

Two independence guarantees:

- **Emission is independent of the PDP engine and of cache hits.** A cache hit never reaches OPA,
  so any OPA-side logging would silently lose those records; only the PEP sees every request. The
  PEP emits the record in all cases (see also Alternative A6).
- **Emission is per end-user for every consumer class.** Engines route through the gateway
  presenting the querying user's `sub`, so engine reads produce these same records with the
  end-user identity — no engine-specific record variant exists, by design
  (`src/model.rs::PrincipalType` deliberately has no engine type).

### D5. Delivery semantics

Implemented in `src/audit/sink.rs`, held as contract:

- **Transport**: `POST` to the ingest endpoint (`…/api/v1/decision-logs`), body = JSON **array**
  of records (batched; `batch_max` 256, flush interval 2s by default). Any 2xx is success;
  anything else, or a transport error, triggers local NDJSON disk spill with periodic replay.
- **Never blocks the data path**: the request path only `try_send`s onto a bounded queue;
  overflow drops the record with a loud alert and a `dropped_total` counter. Audit loss and authz
  loss are different failures — a platform outage must not become a storage outage.
- **At-least-once, therefore idempotent ingest**: spill replay can re-POST a batch the platform
  partially processed before failing to respond. The consumer MUST deduplicate on `decision_id`.

### Example — allowed GetObject

```json
{
  "decision_id": "018f3c84-5b1e-7c2a-9d4f-6e8a0b1c2d3e",
  "path": "s0/gateway/decision",
  "input": {
    "principal": {
      "sub": "8d6a3f2e-1b4c-4a5d-9e8f-0c7b6a5d4e3f",
      "type": "user",
      "attributes": { "groups": ["radiology"] }
    },
    "backend": { "id": "backend-eu-central-1", "kind": "ceph" },
    "tenant": "acme",
    "organization_id": "3f8e2c1a-9d4b-4f6e-8a2d-7c5b9e0f1a2b",
    "action": "read_objects",
    "bucket": "imaging",
    "object": "dicom/2026/07/study-4711/series-1/img-0001.dcm",
    "request": { "method": "GET" }
  },
  "result": { "allow": true, "reason": "allow: grant matched", "obligations": {} },
  "requested_by": "8d6a3f2e-1b4c-4a5d-9e8f-0c7b6a5d4e3f",
  "timestamp": "2026-07-15T14:03:22.481Z",
  "labels": {
    "s0.dev/record-type": "s3-gateway",
    "s0.dev/organization-id": "3f8e2c1a-9d4b-4f6e-8a2d-7c5b9e0f1a2b"
  },
  "gateway": {
    "backend_id": "backend-eu-central-1",
    "backend_kind": "ceph",
    "outcome": "allowed",
    "backend_status": 200
  }
}
```

### Example — fully denied multi-delete (blind spot #2)

```json
{
  "decision_id": "018f3c84-9a2b-7e4d-8c1f-2b3a4d5e6f70",
  "path": "s0/gateway/decision",
  "input": {
    "principal": {
      "sub": "8d6a3f2e-1b4c-4a5d-9e8f-0c7b6a5d4e3f",
      "type": "user",
      "attributes": { "groups": ["radiology"] }
    },
    "backend": { "id": "backend-eu-central-1", "kind": "ceph" },
    "tenant": "acme",
    "organization_id": "3f8e2c1a-9d4b-4f6e-8a2d-7c5b9e0f1a2b",
    "action": "delete_objects",
    "bucket": "imaging",
    "delete_keys": [
      "dicom/2026/07/study-4711/series-1/img-0001.dcm",
      "lab/2026/07/report-2209.pdf"
    ],
    "request": { "method": "POST", "params": "delete" }
  },
  "result": {
    "allow": false,
    "reason": "deny: no grant matches action/scope",
    "obligations": {}
  },
  "requested_by": "8d6a3f2e-1b4c-4a5d-9e8f-0c7b6a5d4e3f",
  "timestamp": "2026-07-15T14:04:10.912Z",
  "labels": {
    "s0.dev/record-type": "s3-gateway",
    "s0.dev/organization-id": "3f8e2c1a-9d4b-4f6e-8a2d-7c5b9e0f1a2b"
  },
  "gateway": {
    "backend_id": "backend-eu-central-1",
    "backend_kind": "ceph",
    "outcome": "denied",
    "denied_keys": [
      "dicom/2026/07/study-4711/series-1/img-0001.dcm",
      "lab/2026/07/report-2209.pdf"
    ]
  }
}
```

Note the deny case: `object` is absent (the per-key detail lives in `delete_keys`), `denied_keys`
enumerates every refused key, `backend_status` is absent because nothing was forwarded, and the
reason is one of the fixed audit-facing strings from `policy/gateway/authz.rego` — deny reasons
matter as much as allow.

## Alternatives considered

- **A1 — Ride a consumer keyed on `input.resource.organization_id`.** Rejected. The S3 record
  needs its own stored variant. A consumer keyed on the input body reads its principal from a
  field that does not exist in the S3 input; records would be stored as control-plane decisions
  with none of the S3 fields (`action`, `object`, `copy_source`, `denied_keys`), destroying the
  object-level audit the gateway exists for. It would also warp the input contract by nesting a
  `resource` envelope that `src/authz/input.rs` does not have.
- **A2 — Reuse another record type's discriminator (e.g. the analytics engine's).** Rejected.
  Another consumer takes its principal from a differently-shaped field, absent from the S3 input —
  records would fail extraction or misattribute. It would also conflate two streams that must stay
  distinct: the analytics SQL-PEP records remain a separate, complementary defense-in-depth
  stream; the gateway stream is the object-level authz/audit path.
- **A3 — One record per PDP sub-decision (per multi-delete key, per copy half).** Rejected by
  "exactly one OPA decision record per object operation" and by volume: a 1,000-key delete would
  emit 1,000 records for one request while conveying no more information than one record's
  `delete_keys`/`denied_keys` arrays. Per-key auditability is preserved *inside* the single
  record.
- **A4 — Coarser records (per-session, per-grant, per-table).** Rejected: coarser-grained audit
  does **not** satisfy the per-request guarantee.
- **A5 — A gateway-owned audit store or new ingest endpoint.** Rejected. The sink already exists
  and the whole point is unified, live, reasoned audit in one place; rebuilding control-plane
  surfaces is out of scope. Reuse the delivery mechanism, extend via a new record type.
- **A6 — Let the sidecar OPA's native decision-log plugin upload records.** Rejected for three
  structural reasons: (a) the PDP is trait-abstracted with an embedded `regorus` fast path that
  has no decision-log plugin — audit must not depend on which engine served the decision;
  (b) cache hits never reach OPA, so OPA-side logging would silently drop exactly the high-volume
  records (Head/List storms) the cache exists for; (c) OPA sees per-sub-decision questions and
  none of the post-decision facts (`outcome`, `backend_status`, `denied_keys` after PEP
  filtering) — it cannot produce the one-record-per-request aggregate. Only the PEP can.
- **A7 — Synchronous audit emit (fail the request if the record can't be shipped).** Rejected:
  audit-emit failure **does not fail the request** (data path proceeds, loud alert). Mitigations
  instead: bounded queue, disk spill + replay, `dropped_total` alerting (D5, R3).

## Consequences

**What must hold for the guarantee** (it is only as strong as these):

- **I1** — The org label value comes exclusively from gateway deployment configuration (the
  per-org bundle identity), never from client-supplied data.
- **I2** — Exactly one record per S3 request, emitted at the typed seam by the PEP, regardless of
  PDP engine, cache hit, or outcome (allowed / denied / error).
- **I3** — `requested_by == input.principal.sub` == the end-user OIDC `sub`, for every consumer
  class including engines. No record is ever attributed to a shared or service identity for
  user-attributable data.
- **I4** — Label keys, the `"s3-gateway"` value, and `path` are frozen constants
  (`src/audit/record.rs`); changing any of them breaks consumer routing and is a breaking
  contract change requiring a coordinated release.
- **I5** — The gateway never emits `input.resource.*`, keeping the match sets disjoint (D2).
- **I6** — Schema evolution is additive-only; consumers ignore unknown fields.
- **I7** — Ingest is authenticated/trusted (R2) and idempotent on `decision_id`.

**Risks and follow-ups:**

- **R1 — Audit is not live until the S3 record type is ingested.** Today every gateway record is
  dropped-with-a-warning (fail-closed and safe), but the per-request requirement is unmet until a
  control-plane consumer ships. The gateway cannot be declared a production enforcement point for
  regulated deployments before then. Sequencing: agree the record shape (this ADR), then land the
  consumer.
- **R2 — A "trusted field" requires a trusted sender.** The fail-closed org rule reads a label
  anyone could forge if the ingest endpoint is open. `src/audit/sink.rs` currently POSTs with no
  client credential. Follow-up in this repo and the platform: define gateway→platform ingest
  authentication (service credential or mTLS, plus network policy).
- **R3 — Bounded record loss is possible and must be observable.** Queue overflow and spill-write
  failure drop records with an error log and counter (`dropped_total`). For hospital deployments,
  alerting on `dropped_total > 0` must page; operations must treat sustained drops as an incident
  even though the data path is healthy.
- **R4 — Consumers must understand `result.allow` vs `gateway.outcome`.** An authz-allowed
  request with a backend 5xx is `allow: true, outcome: "allowed", backend_status: 5xx`; a
  transport failure is `outcome: "error"`. Dashboards that count "denials" must read
  `outcome`/`result.allow`, not backend status.
- **R5 — Record and batch size.** `delete_keys` + `denied_keys` can carry up to 1,000 keys ×
  ≤ 1,024 bytes, so a worst-case record is ~2 MB and a 256-record batch far more. If the ingest
  body limit is lower, the gateway adds size-aware batch splitting (repo follow-up).
- **R6 — `check()`-backstop rejections have no record mapping yet.** Requests refused before the
  typed seam (non-allowlisted op, anonymous, coarse `freeze_writes` fast-reject) never produce an
  input, and `src/model.rs::Action` has no "unknown" variant to describe an unsupported op. This
  ADR's one-record guarantee covers every request reaching the authoritative typed seam. A
  follow-up ADR must decide whether backstop denials emit a record with a synthesized minimal
  input (requires a small, additive `Action`/input extension) or are captured as structured
  gateway logs outside the decision stream; for the regulated bar, the recommendation is to emit.
- **R7 — Decision logs are themselves sensitive.** Object keys in hospital deployments may embed
  identifiers (see the examples), and the record mandates keys. Retention and access control for
  the stored variant are control-plane policy; no redaction is performed gateway-side because the
  fields are exactly what the audit requires.

## Control-plane integration (out of scope for this repository)

A control-plane consumer of the S3 record type must: match **exclusively** on
`labels["s0.dev/record-type"] == "s3-gateway"`; read org from
`labels["s0.dev/organization-id"]`, fail-closed exactly like the existing consumers (unreadable
org ⇒ discard, never guess); take the principal from `requested_by` and validate
`requested_by == input.principal.sub`, discarding on mismatch; ignore unknown fields (I6); store a
new decision variant carrying the full S3 detail (`allow`, `reason`, `obligations`, `action`,
`tenant`, `bucket`, `object`, `prefix`, `copy_source`, `delete_keys`, `denied_keys`, `outcome`,
`backend_id`, `backend_kind`, `backend_status`, plus the envelope) rather than shoehorning into an
existing variant (A1/A2); deduplicate on `decision_id` (at-least-once delivery from spill replay,
D5); keep drop-with-warning plus a drop-rate metric/alert so schema drift is detected instead of
silently losing audit; and authenticate the gateway sender (R2), since org attribution trusts the
label only because it trusts the sender. Retention and access policy for the new variant (records
contain object keys, R7) and confirmation of ingest body/volume capacity against R5's worst case
are control-plane concerns.
