# ADR-011: Delegated operations — bucket configuration answered by a control backend

- **Status**: Proposed — implemented: D1 to D5 and D7 (`src/access/optable.rs`,
  `src/access/delegation.rs`, `src/proxy/control.rs`, `src/config.rs`, `src/audit/record.rs`)
  and D6, read-your-writes (`src/bundle_refresh.rs` for `BundleRefresher` and `PlacementWait`,
  `src/access/mod.rs` for the refresh on miss in `check`, `src/proxy/mod.rs` for
  `delegate_then`, `src/cors/lookup.rs` for `CorsState::invalidate`)
- **Date**: 2026-11-02
- **Owners**: gateway team (this repo); the control backend is the console of the platform that
  deploys s0
- **Related**: `src/access/optable.rs` (`Coverage`, `gate_op`), `src/access/proof.rs`
  (`AuthzProof`), `src/access/mod.rs` (`check`), `src/proxy/mod.rs` (`forward`, `build_proxy`),
  `src/audit/record.rs`, `src/gateway.rs`, `src/config.rs`; amends ADR-002 (a third record
  shape) and ADR-008 (rider screening of a delegated `CreateBucket`); relies on ADR-001, ADR-006 and ADR-009. Platform side: ADR-0056 of the Hyperfluid
  repository (bucket creation and configuration over S3, delegated by s0).

## Context

s0 sorts the S3 operations into two classes (`src/access/optable.rs`): **enforced**, where the
request is parsed, decided by the policy engine and re-issued to the storage backend from the
same typed value, and **denied**, refused with `403 AccessDenied` before any hook runs. The
README states it plainly: there is no third category.

Bucket creation and bucket configuration (CORS, lifecycle, tags, versioning, default
encryption) sit in the denied class. They are not enforced because the answer does not live in
the storage backend. On a platform that owns its buckets through a control plane, a bucket is a
declared resource: creating or reconfiguring it through the storage backend would bypass the
control plane's model, its quotas, its protections and its audit. A client that speaks S3
nevertheless expects `aws s3api put-bucket-cors` to work.

The platform therefore wants s0 to hand these operations to a **control backend** — an S3
endpoint served by the control plane that implements only these operations — and to return its
answer. s0 must stay fail-closed while doing so. Three layers hold today and must keep holding:

1. `check` refuses an operation the table does not enforce, before any hook;
2. an enforced dispatch arm demands an `AuthzProof` (`proof::require`, before any backend client
   is resolved) that only the enforce path inside the typed hook can mint, on the allow side of
   an audited policy decision (`src/access/proof.rs`);
3. a policy engine error is a deny.

A new class must not weaken any of them, and must not let an operation reach the storage backend
without the policy engine, nor reach the control backend with the policy engine's authority
presumed.

The rule that decides which side authorizes: **whatever s0 forwards to the storage backend, s0
authorizes**, because the backend only sees s0's credential. **Whatever s0 delegates, the control
backend authorizes.** Object data (keys, contents, versions) is never delegated.

## Decision

### D1. The class: `Delegable`, a static fact; `Delegated`, a runtime verdict

`Coverage` gains a third value, `Delegable`. It is a property of the operation table, which
cannot know the configuration. Exactly **15** rows qualify:

| Operations |
|---|
| `CreateBucket` |
| `GetBucketCors`, `PutBucketCors`, `DeleteBucketCors` |
| `GetBucketLifecycleConfiguration`, `PutBucketLifecycleConfiguration`, `DeleteBucketLifecycle` |
| `GetBucketTagging`, `PutBucketTagging`, `DeleteBucketTagging` |
| `GetBucketVersioning`, `PutBucketVersioning` |
| `GetBucketEncryption`, `PutBucketEncryption`, `DeleteBucketEncryption` |

`GetBucketPolicy` and `PutBucketPolicy` are never delegable. `DeleteBucket` is not delegable
under this ADR either: ADR-0056 leaves it open ("Not decided here").

Coverage drives behaviour only together with configuration. The gate returns:

- `Gate::Enforced` for an enforced row;
- `Gate::Delegated` for a `Delegable` row that `control_backend.operations` lists;
- the same `GateDenial` as today for everything else (`Unknown`, `Unauthorizable`,
  `NotEnforced`); a `Delegable` row the configuration does not list gets `NotEnforced`,
  byte-identical to today's: same message, same gate record. A
  gateway with no `control_backend` behaves exactly as it did before this ADR.

No row classed `DangerTier::NeverImplement` can be `Delegable`, and the tier is checked before
coverage. `CreateSession` and `WriteGetObjectResponse` are table rows built by `unauthorizable()`;
they are refused by tier, ahead of coverage, and configuration validation (D2) refuses them
independently. Two tests enforce the rule:

- `exactly_the_fifteen_adr_0056_operations_are_delegable`;
- `no_never_implement_operation_is_delegable`.

### D2. Configuration and startup validation

`gateway.control_backend` is optional, and its struct is `deny_unknown_fields`, so a mistyped key
fails to load instead of silently delegating nothing. Its fields: `endpoint_url`, `region`,
`access_key_id`, `secret_access_key` (a `Secret<String>`, never printed), `operations`,
`connect_timeout_secs`, `call_timeout_secs`, `create_bucket_placement_wait_secs`.

s0 **refuses to load** the configuration when any of these holds:

- `operations` is empty or has a duplicate;
- an operation is unknown, enforced, denied or `NeverImplement`;
- a timeout is 0;
- `call_timeout_secs + create_bucket_placement_wait_secs >= 60` — the client's read timeout is
  60 s by default in the AWS CLI and boto3, and the delegated call must finish inside it;
- the tenants span more than one organization or more than one backend: one control credential
  is bound to one (organization, backend), so a gateway serving several has no single identity to
  present;
- the endpoint is unparseable, equals a storage backend's endpoint, or equals the bundle URL;
- the credential is empty.

The control backend is restart-only, like the STS ring: a config reload that changes it logs a
warning and keeps the running one.

### D3. What `check` does for a delegated operation

For `Gate::Delegated`, `check`:

1. authenticates the caller and resolves the principal and the route through the same stages as
   an enforced operation, so an anonymous or unrouted caller is refused as today;
2. never calls the policy engine, and checks no placement, quota, `freeze_writes` or rider: those
   questions belong to the control backend, which sees the whole request. In particular the
   control backend owns the `CreateBucket` ACL, grant, ownership and object-lock refusal that
   ADR-008 places in the gate for a denied `CreateBucket`;
3. mints a `DelegationProof` bound to the operation name and returns.

`check` mints the `DelegationProof`. A delegated hook and its dispatch arm (`delegate()`, which
calls `delegation::require` before it touches the control client) both demand that proof; the
enforced dispatch arm demands an `AuthzProof`, which only the enforce path mints. **Neither proof
opens the other's arm**, and the s3s default hook, which would answer `Ok`, is overridden for
every delegated operation to refuse when the proof is absent. This is the second fail-closed
layer's mirror image: a delegated operation cannot be dispatched without `check` having admitted
it as delegated.

### D4. The wire contract with the control backend

The request goes to the control backend as it goes to a storage backend: the parsed, typed
request, re-issued through the `s3s-aws` `Proxy`, signed with s0's control credential.

**Identity headers.** Added before signing, so all of them are signed:

| Header | Value |
|---|---|
| `x-s0-caller-subject` | `user:<sub>` or `sa:<client id>`, from the principal's subject key |
| `x-s0-caller-tenant` | the harbor slug of the caller's tenant |
| `x-s0-caller-organization` | the organization, taken from the route, never from the credential |
| `x-s0-backend-id` | the backend this s0 serves |
| `x-s0-request-id` | the decision id of the delegated audit record (D5) |

The `aws-sigv4` signer excludes only `authorization`, `user-agent`, `x-amzn-trace-id` and
`transfer-encoding` from the canonical headers, so these five appear in `SignedHeaders`.

**Trust condition.** The control backend uses these headers only when all of the following
hold; otherwise it answers `403` and ignores them:

- (a) the SigV4 signature verifies under the credential dedicated to this (organization,
  backend);
- (b) every `x-s0-*` header is listed in `SignedHeaders`;
- (c) the organization and backend headers equal that credential's binding;
- (d) each header appears exactly once.

A header an s0 instance may not forge is one it signs; a header it may not choose (organization,
backend) is one the credential pins.

**Transport.** No automatic retry: a delegated write is not known to be idempotent. A separate
connect timeout and call timeout, the call timeout exceeding the control backend's own wait and
staying below the client's read timeout (D2).

**Errors.** The control backend returns S3 errors and XML itself. s0 passes its code, message and
status through unchanged and skips the backend-error rewriting that enforced operations get,
because that rewriting exists to remove ARNs and account ids from an upstream body and these
bodies carry neither. s0 replaces the request id with its own decision id, so the client's error
joins the audit record. A transport failure or a timeout has no body to pass: s0 answers
`503 ServiceUnavailable` itself.

**Accepted risk.** A signed request can be replayed within SigV4's 15-minute window. The
mitigation is the network path (a NetworkPolicy admitting only s0 pods, in-cluster traffic); TLS
is recommended. A compromised s0 can impersonate any caller of its own organization towards the
control backend, and has no reach across organizations, because the credential pins one.

### D5. The audit record: a third shape (amends ADR-002)

ADR-002 fixes two shapes sharing one envelope, exactly one half present: a **decision** record
(`input`) and a **gate** record (`gate`). A delegated request has neither a policy question nor
an `Action`: the decision half's `OpaInput.action` is an `Action`, and none exists for these 15
operations. Inventing one would put a claim in a regulated record that was never made, the same
reason ADR-002 gave for the gate record.

A **delegated** record is a third half, `delegated`, under its own path:

| Field | Value |
|---|---|
| `path` | constant `"s3/authz/delegated"` (`DELEGATED_PATH`); not the decision path, because no policy ran |
| `input`, `gate` | absent |
| `delegated.operation` | the S3 operation name |
| `delegated.bucket` | the bucket named by the request path |
| `delegated.tenant` | the caller's tenant |
| `delegated.subject` | the caller's subject key, as sent in `x-s0-caller-subject` |
| `delegated.control_status` | the HTTP status the control backend answered; omitted when none was received |
| `delegated.control_error` | the error code the control backend answered; omitted on success |
| `delegated.placement_wait` | the outcome of the `CreateBucket` placement wait (D6); omitted otherwise |
| `requested_by` | the end-user subject, as for every other shape |
| `labels` | the same trusted organization label as every other shape |
| `gateway.outcome` | `allowed` for a 2xx; `denied` for `403 AccessDenied`; `error` otherwise (any other answered status, or no answer) |
| `gateway.backend` | `not_attempted`: the storage backend was never contacted |
| `result` | `allow` is the control backend's authorization answer, not an s0 verdict: `true` for a 2xx, `false` only for `403 AccessDenied`. For any other answered status, `allow` is `true` and the reason names the control backend and its error code, with `control_status` / `control_error` set; with no answer, `outcome` is `error` and `control_status` is absent: the reason is "control backend unreachable" when the call was made and nothing came back, or "request ended before the control backend was called" (with `allow` `false`, since nothing was observed) when the request failed after authorization and before dispatch, as a malformed body does, or "request ended before the control backend answered" (also `allow` `false`, `control_status` absent) when the request ended while the call was in flight, as a client disconnect does. A 2xx whose body then failed is `error` too, and the control backend's `403` about the gateway's own credential is answered `503` and recorded as `error`, never as a denial |

One record per delegated request, emitted when the request finishes (through `PendingAudit`, as a
decision record is), and never rate-limited: it is a decision about a caller, not
noise from an unauthenticated one. A consumer that dispatches on the presence of `input` or
`gate` and files everything else as a decision would file a delegated record as a decision with
an empty action and bucket. Consumers therefore dispatch on `path` first. The shape the first
implementation ships, committed as a captured fixture, is the contract; this table is its
description.

ADR-002's status line records the amendment. Its body is unchanged.

### D6. Read-your-writes

Three things make a delegated write visible to the next request, each bounded:

- **`CreateBucket` placement wait.** The control backend answers when the bucket is declared; the
  placement bundle that lets s0 enforce object operations on it (ADR-009) arrives separately. s0
  refreshes its bundle at once and waits up to `create_bucket_placement_wait_secs` for the bucket
  to be placed before answering the client. The outcome is recorded in `delegated.placement_wait`.
  A timeout is not an error: the bucket exists, and the next request refreshes on a miss.
- **Refresh on miss.** An enforced request refused because the pinned bundle does not place the
  path bucket on this backend triggers, in `check` and before any hook, at most one bundle
  refresh, and only after authentication and route resolution. The refresh happens only when a
  `control_backend` is configured. The decision is made on a fetch that started after the
  request arrived, never on one already running. Fetches triggered by a miss start at most once
  per second per replica: a miss arriving inside that interval waits for it to pass and shares
  the fetch of the misses waiting with it. The caller waits at most 2 s, then decides with
  whatever placement is current. The hook then decides once against the re-pinned
  placement, so the request has one decision and one audit record. The `CreateBucket` placement
  wait's fetches go through the same single-flight gate as every other fetch and are shared
  with any fetch that starts after the wait began; they use their own 250 ms to 1 s backoff and
  are not subject to the one-per-second miss interval, so one `CreateBucket` costs about 1 to 12
  fetches. They are counted under `trigger="placement_wait"`.
- **CORS cache drop.** A delegated CORS write or delete drops the replica's cached CORS
  configuration for the bucket. Other replicas follow within the cache TTL (60 s); "at once"
  holds only for the replica that served the write.

### D7. The two invariants, as tests

- `a_delegated_operation_never_reaches_the_policy_engine`: all 15 operations, under a bundle that
  places the bucket under another tenant with `freeze_writes` on, never call the policy engine
  and write no decision record, and each reaches the control backend.
- `an_enforced_operation_never_reaches_the_control_backend`: every enforced operation through its
  hook and dispatch arm, plus a sample over real HTTP, leaves the control backend's request count at zero.

Neither is satisfied by inspection of the code; both are black-box assertions that must stay in
the suite for as long as the class exists.

## Consequences

- **The README's "no third category" is no longer true** and is rewritten with the
  implementation. The six operations listed in the 2026-08-08 conformance test as refused for
  good are re-split: three stay non-delegable (`GetBucketPolicy`, `PutBucketPolicy` never; `DeleteBucket` under this ADR), the rest are `Delegable`.
- **The control backend becomes a dependency of bucket configuration.** If it is down, these
  operations answer `503`; object operations are unaffected.
- **s0 stops checking `freeze_writes`, quotas, placement and request riders for delegated
  operations.** The control backend must apply its own equivalents, including the `CreateBucket`
  ACL, grant, ownership and object-lock refusal; that is its half of the contract. ADR-009's
  placement and backend-id refusals sit in `decide()` and do not cover delegated operations.
- **The 15 new dispatch arms remove the "no arm, s3s `NotImplemented`" backstop** for these
  operations (`src/access/optable.rs`); the `DelegationProof` on hook and arm replaces it.
- **A delegated request has no policy-engine decision to replay.** The conformance corpus covers
  enforced operations only; delegated behaviour is covered by the delegation test suite.
- **CORS lag across replicas**, bounded by the cache TTL.
- **A compromised s0 can act as any caller of its organization** towards the control backend. The
  blast radius is one organization.

## Alternatives considered

- **A bare SDK client with per-operation `customize()`.** Viable, and the fallback if the
  client-level interceptor cannot carry the caller headers. It loses the `Proxy`'s error
  conversion and request building, which would need small local copies.
- **A client per request built from a shared config.** Correct but allocates a client for every
  delegated call, for no isolation the task-scoped caller does not already give.
- **A JSON webhook to the control plane.** Rejected in ADR-0056: it would re-invent S3 request
  parsing and error mapping in a second place, and the client-visible semantics would drift from
  S3's.
- **Enforcing these operations in s0 against the storage backend.** Rejected: it bypasses the
  control plane's model of the bucket, which is the reason they are refused today.
