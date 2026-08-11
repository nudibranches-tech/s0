# ADR-002: Decision-log record shape

- **Status**: Accepted — implemented (src/audit/record.rs)
- **Date**: 2026-07-15
- **Owners**: gateway team (this repo)
- **Related**: `src/audit/record.rs`, `src/audit/sink.rs`, `src/authz/input.rs`, `src/authz/decision.rs`, `policy/gateway/authz.rego`; ADR-001, ADR-003

## Context

s0 exists to guarantee, for regulated (e.g. hospital) deployments, that every S3 object access —
by a human, an external app, or an analytics engine — is authorized as the **end-user identity**
and emits **exactly one decision record per request**, attributed to that identity. Coarser-grained
audit (per-grant, per-session, per-table) does not satisfy that.

Records are shipped to an external decision-log consumer that ingests **OPA's native decision-log
format**, batched as a JSON array of `{ decision_id, path, input, result, labels, requested_by,
timestamp, … }`. Such consumers typically route each record to a typed handler by a label, read org
attribution only from a trusted field, and drop unroutable records with a warning.

This ADR freezes the record shape as a wire contract so the gateway and any consumer build against
one schema and no existing consumer mis-claims gateway records.

## Decision

### D1. Envelope: OPA native decision-log shape, one extra `gateway` block

Implemented verbatim in `src/audit/record.rs`; serialized field order and optionality follow that
file.

| Field | Type | Value / semantics |
|---|---|---|
| `decision_id` | string | Gateway-generated UUID, unique per record. **Idempotency key** for ingest (see D5). |
| `path` | string | Constant `"s3/authz/decision"` (`DECISION_PATH`) — the slash form of the single rego rule the PDP evaluates, `data.s3.authz.decision` (`policy/gateway/authz.rego`, package `s3.authz`). OPA decision-log convention. |
| `input` | object | The **full OPA input** (`src/authz/input.rs::OpaInput`) in *request-level* form (see D4): `principal{sub,type,attributes}`, `backend{id,kind}`, `tenant`, `organization_id`, `action`, `bucket`, `object?`, `prefix?`, `copy_source?`, `delete_keys?`, `object_tags?`, `request{method,params?,headers_subset?}`. |
| `result` | object | The aggregate PDP verdict (`src/authz/decision.rs::Decision`): `allow: bool`, `reason: string` (always present — deny reasons are first-class), `obligations{narrow_prefix?, allowed_prefixes?}`. Obligations expose any list-narrowing rewrite the PEP applied, so the audit trail shows *what was actually enumerated*, not just that a list was allowed. |
| `requested_by` | string | `input.principal.sub` — the **end-user** OIDC `sub` (never a shared/service identity, engines included). `AuditRecord::new` sets it from the input by construction. In stock OPA this field carries the PDP client address; for the S3 record type this ADR fixes its meaning as the principal. |
| `timestamp` | string | RFC3339 UTC, decision time. |
| `labels` | map | Attribution and routing labels (D2). |
| `gateway` | object | S3-specific fields beyond the OPA envelope (`GatewayMeta`): `backend_id: string`, `backend_kind: "ceph"\|"remote_s3"`, `outcome: "allowed"\|"denied"\|"error"`, `denied_keys: [string]` (omitted when empty), `backend_status: u16` (omitted unless a backend HTTP response was received). |

`result.allow` and `gateway.outcome` are deliberately distinct: `allow` is the **policy
verdict**, `outcome` is the **final disposition**. Normatively:

- `outcome = "denied"` — policy refused; nothing was forwarded; `backend_status` absent.
- `outcome = "allowed"` — authorized and forwarded; `backend_status` carries whatever the
  backend returned, **including backend 4xx/5xx** (the authorization question and the storage
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
| org in a trusted field | the org label (D2) |

### D2. Discriminator and trusted org attribution: labels

Labelling is a deployment concern, carried by `LabelPolicy` (`src/audit/record.rs`): an
**organization-id label key** (default `s0/organization-id`, `DEFAULT_ORG_LABEL_KEY`) plus any
static labels the operator configures for the consumer's routing. The consumer dispatches on those
label keys literally, so a record that spells them any other way is discarded on its side.

The trusted org can be carried either in a label or in an input field. We choose the **label**:

1. **No collision with consumers keyed on the input body.** Some decision consumers match on a
   trusted `input.resource.organization_id`. A gateway record carrying that field could be claimed
   by such a consumer and stored as the wrong variant, silently corrupting the audit stream. The
   input contract has no `resource` envelope (`src/authz/input.rs` carries `organization_id` at the
   top level), and the gateway **MUST never emit `input.resource.*`** — with that invariant plus a
   distinct `path`, gateway records match no other consumer.
2. **Trust is a property of the producer, not the JSON.** The org value is populated by the gateway
   from its own deployment configuration — the per-org bundle subscription and the backend/tenant
   registry — never from anything the client sent. `AuditRecord::new` copies
   `input.organization_id` into the label. That is what makes fail-closed attribution sound.

`input.principal.sub` is the bare OIDC `sub`, the same key the bundle uses
(`data.tenants[t].user_attributes[sub]`, consumed by `policy/gateway/authz.rego::member`) — not a
backend-decorated `$oidc$<sub>` form, which is a backend identity artifact the gateway supersedes.

### D3. `input` and `result` are the live authorization values — no parallel audit schema

The record embeds the exact `OpaInput` the PDP decided on and the exact `Decision` it returned.
There is no second, hand-maintained audit DTO to drift from the authz path. Field names in
`src/authz/input.rs` are a **stable wire schema**; this ADR extends that stability guarantee to the
whole record. Evolution is **additive-only**, and consumers MUST ignore unknown fields.

### D4. Exactly one record per S3 request — and how blind-spot ops fold into it

**The gateway emits exactly one record per S3 request**, at the typed per-op seam where the
authoritative decision is made. One S3 request is one object operation, even when the PEP
decomposes it into several PDP questions internally: the request-level `input` carries the full
detail and `result` is the aggregate verdict. Per-request granularity is the floor — multipart
uploads emit one record per part request.

| Op | PDP questions | The one record |
|---|---|---|
| GetObject / HeadObject / PutObject / DeleteObject / PostObject | 1 | `input.object` = key; `result` = the verdict as returned by rego. |
| ListObjectsV2 / ListObjects | 1 | `input.prefix` = requested prefix; `result.obligations` records any narrowing applied. |
| **CopyObject** (blind spot #1) | 2 — source read (`read_objects` on source bucket/key) and dest write (`write_objects` on dest) | Request-level input: `action = "write_objects"`, `bucket`/`object` = destination, `copy_source = {bucket, key}` = source. `result.allow = true` iff **both** halves allowed. On deny, the source half is evaluated first and the aggregate reason is the denying half's rego reason prefixed with the half: `"copy source: <reason>"` or `"copy dest: <reason>"`. |
| **DeleteObjects** (blind spot #2) | N — one per key (`input.object` = key, `action = "delete_objects"`), N ≤ 1,000 by the semantic cap enforced before PDP fan-out | Request-level input: `delete_keys` = the full requested key list, `object` omitted. The PEP strips unauthorized keys and lists them in `gateway.denied_keys`. `result.allow = true` iff at least one key survived and the filtered request was forwarded (`outcome = "allowed"`; aggregate reason `"allow: partial (k of n keys granted)"`). `result.allow = false` iff **every** key was denied (`outcome = "denied"`, `denied_keys` = all requested keys, nothing forwarded; reason = the per-key rego deny reason). |

Aggregate reason strings for decomposed ops (`"copy source: …"`, `"allow: partial …"`) are
**PEP-composed** via `Decision::allow/deny` (`src/authz/decision.rs`); they are not rego outputs and
do not affect the dual-engine parity gate, which compares raw per-question engine outputs.

Two independence guarantees:

- **Emission is independent of the PDP engine and of cache hits.** A cache hit never reaches OPA,
  so any OPA-side logging would silently lose those records; only the PEP sees every request (see
  also Alternative A6).
- **Emission is per end-user for every consumer class.** Engines route through the gateway
  presenting the querying user's `sub`, so engine reads produce these same records with the
  end-user identity — no engine-specific record variant exists, by design
  (`src/model.rs::PrincipalType` deliberately has no engine type).

### D5. Delivery semantics

Implemented in `src/audit/sink.rs`, held as contract:

- **Transport**: `POST` to the ingest endpoint, body = JSON **array** of records (batched;
  `batch_max` 256, flush interval 2s by default). Any 2xx is success; anything else, or a transport
  error, triggers local NDJSON disk spill with periodic replay.
- **Never blocks the data path**: the request path only `try_send`s onto a bounded queue; overflow
  drops the record with a loud alert and a `dropped_total` counter. Audit loss and authz loss are
  different failures — a consumer outage must not become a storage outage.
- **At-least-once, therefore idempotent ingest**: spill replay can re-POST a batch the consumer
  partially processed before failing to respond. The consumer MUST deduplicate on `decision_id`.

### Example — allowed GetObject

```json
{
  "decision_id": "018f3c84-5b1e-7c2a-9d4f-6e8a0b1c2d3e",
  "path": "s3/authz/decision",
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
    "example/log-type": "s3-gateway",
    "s0/organization-id": "3f8e2c1a-9d4b-4f6e-8a2d-7c5b9e0f1a2b"
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
  "path": "s3/authz/decision",
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
    "example/log-type": "s3-gateway",
    "s0/organization-id": "3f8e2c1a-9d4b-4f6e-8a2d-7c5b9e0f1a2b"
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

In the deny case `object` is absent (the per-key detail lives in `delete_keys`), `denied_keys`
enumerates every refused key, and `backend_status` is absent because nothing was forwarded.

## Alternatives considered

- **A1 — Ride a consumer keyed on `input.resource.organization_id`.** Rejected. Such a consumer
  reads its principal from a field the S3 input does not have; records would be stored as
  control-plane decisions with none of the S3 fields (`action`, `object`, `copy_source`,
  `denied_keys`), destroying the object-level audit the gateway exists for.
- **A2 — Reuse another record type's discriminator (e.g. the analytics engine's).** Rejected: it
  takes its principal from a differently-shaped field, and it would conflate two streams that must
  stay distinct — a SQL-PEP stream is complementary defense in depth; this one is the object-level
  authz path.
- **A3 — One record per PDP sub-decision (per multi-delete key, per copy half).** Rejected by the
  one-record-per-object-operation requirement and by volume: a 1,000-key delete would emit 1,000
  records conveying no more than one record's `delete_keys`/`denied_keys` arrays.
- **A4 — Coarser records (per-session, per-grant, per-table).** Rejected: does not satisfy the
  per-request guarantee.
- **A5 — A gateway-owned audit store or new ingest endpoint.** Rejected: reuse the delivery
  mechanism, extend via a new record type.
- **A6 — Let the sidecar OPA's native decision-log plugin upload records.** Rejected for three
  structural reasons: (a) the PDP is trait-abstracted with an embedded `regorus` fast path that has
  no decision-log plugin — audit must not depend on which engine served the decision; (b) cache hits
  never reach OPA, so OPA-side logging would silently drop exactly the high-volume records
  (Head/List storms) the cache exists for; (c) OPA sees per-sub-decision questions and none of the
  post-decision facts (`outcome`, `backend_status`, `denied_keys` after PEP filtering). Only the PEP
  can produce the aggregate.
- **A7 — Synchronous audit emit (fail the request if the record can't be shipped).** Rejected:
  audit-emit failure does not fail the request. Mitigations instead: bounded queue, disk spill +
  replay, `dropped_total` alerting (D5, R3).

## Consequences

**What must hold for the guarantee** (it is only as strong as these):

- **I1** — The org label value comes exclusively from gateway deployment configuration, never from
  client-supplied data.
- **I2** — Exactly one record per S3 request, emitted at the typed seam by the PEP, regardless of
  PDP engine, cache hit, or outcome.
- **I3** — `requested_by == input.principal.sub` == the end-user OIDC `sub`, for every consumer
  class including engines. No record is attributed to a shared or service identity for
  user-attributable data.
- **I4** — Label keys, their configured values, and `path` are frozen for a given deployment;
  changing any of them breaks consumer routing and is a breaking contract change.
- **I5** — The gateway never emits `input.resource.*`, keeping consumer match sets disjoint (D2).
- **I6** — Schema evolution is additive-only; consumers ignore unknown fields.
- **I7** — Ingest is authenticated/trusted (R2) and idempotent on `decision_id`.

**Risks and follow-ups:**

- **R1 — Audit is not live until a consumer ingests the S3 record type.** Until then every gateway
  record is dropped-with-a-warning (fail-closed and safe), and the per-request requirement is unmet.
- **R2 — A "trusted field" requires a trusted sender.** The fail-closed org rule reads a label
  anyone could forge if the ingest endpoint is open. `src/audit/sink.rs` POSTs with no client
  credential; ingest authentication (service credential or mTLS, plus network policy) is a
  follow-up.
- **R3 — Bounded record loss is possible and must be observable.** Queue overflow and spill-write
  failure drop records with an error log and counter (`dropped_total`). Alerting on
  `dropped_total > 0` must page; sustained drops are an incident even though the data path is
  healthy.
- **R4 — Consumers must understand `result.allow` vs `gateway.outcome`.** Dashboards that count
  "denials" must read `outcome`/`result.allow`, not backend status.
- **R5 — Record and batch size.** `delete_keys` + `denied_keys` can carry up to 1,000 keys ×
  ≤ 1,024 bytes, so a worst-case record is ~2 MB and a 256-record batch far more. If the ingest body
  limit is lower, the gateway needs size-aware batch splitting.
- **R6 — `check()`-backstop rejections have no record mapping yet.** Requests refused before the
  typed seam (non-allowlisted op, anonymous, coarse `freeze_writes` fast-reject) never produce an
  input, and `src/model.rs::Action` has no "unknown" variant. The one-record guarantee covers every
  request reaching the authoritative typed seam; a follow-up ADR must decide whether backstop
  denials emit a synthesized minimal input or are captured as structured logs outside the decision
  stream. For the regulated bar, the recommendation is to emit.
- **R7 — Decision logs are themselves sensitive.** Object keys may embed identifiers and the record
  mandates keys. Retention and access control for the stored variant belong to the consumer; no
  redaction is performed gateway-side because the fields are exactly what the audit requires.

## Consumer integration (out of scope for this repository)

A consumer of the S3 record type must: match **exclusively** on the configured routing label; read
org from the configured org label, fail-closed (unreadable org ⇒ discard, never guess); take the
principal from `requested_by` and validate `requested_by == input.principal.sub`, discarding on
mismatch; ignore unknown fields (I6); store a decision variant carrying the full S3 detail (`allow`,
`reason`, `obligations`, `action`, `tenant`, `bucket`, `object`, `prefix`, `copy_source`,
`delete_keys`, `denied_keys`, `outcome`, `backend_id`, `backend_kind`, `backend_status`, plus the
envelope) rather than shoehorning into an existing variant (A1/A2); deduplicate on `decision_id`
(D5); keep drop-with-warning plus a drop-rate metric so schema drift is detected instead of silently
losing audit; and authenticate the gateway sender (R2), since org attribution trusts the label only
because it trusts the sender. Retention and access policy for the new variant (R7) and ingest
body/volume capacity against R5's worst case are consumer-side concerns.
