# Architecture Decision Records — s0

**s0** is an OPA/ABAC-enforcing, S3-compatible authorization gateway: an S3 API re-issuer
with a policy gate in the middle. Its product claim is that **every S3 object access — human,
external app, or engine — is authorized as the end-user identity and emits exactly one policy
decision record per request**.

An **Architecture Decision Record (ADR)** captures a single significant design decision: the
context that forced it, the decision itself, the alternatives weighed, and the consequences
accepted. Each record is self-contained and dated. Records are immutable once accepted — a
later decision supersedes an earlier one with a new ADR rather than being edited in place.
Together they form the design history of the gateway.

## The ADRs

| ID | Title | Status | Summary |
|---|---|---|---|
| [ADR-001](ADR-001-dual-path-exposure-and-drift-control.md) | Dual-path direct-credential exposure and Rego drift control | Proposed | Direct-to-backend credentials that bypass the gateway are tracked in a maintained inventory — user-attributable credential paths must be closed by migration and key rotation, infrastructure credentials may be conditionally isolated and bounded under a flip-to-close rule — and drift across the separate policy codebases is controlled by a shared conformance suite over the single grants source rather than by code generation. |
| [ADR-002](ADR-002-decision-log-record-shape.md) | Decision-log record shape and the extractor contract | Proposed | The gateway emits exactly one policy-native decision-log record per S3 request (`decision_id`/`path`/`input`/`result`/`requested_by`/`timestamp`/`labels`/`gateway{}`), discriminated by a record-type label alongside a trusted org-id label (never derived from request input), with copy and multi-delete folded into single records; the log extractor and stored record variant are control-plane integration out of scope for this repository. |
| [ADR-003](ADR-003-object-tag-abac-toctou-and-cache.md) | Object-tag ABAC — TOCTOU window, tag-cache invalidation, and the ship-gate | Proposed | Object-tag ABAC ships only after the direct-path exposure is closed (the interim hard-wiring already exists: object tags are never populated and tag-bearing decisions are never cached); the eventual design makes tags restrict-only, gates tag mutation behind a new `manage_tags` action, forbids caching tag-based decisions without a gateway-minted tag-version in the cache key, and classifies deny classes by their tolerance of the irreducible TOCTOU window. |
| [ADR-004](ADR-004-list-multiprefix-handling.md) | ListObjects narrowing — single-prefix rewrite and bounded multi-prefix fan-out with a gateway-owned cursor | Proposed | Single-prefix listings rewrite `input.prefix` in the `&mut` typed hook; multi-prefix listings use bounded fan-out-and-merge (default 16, fail-closed above the bound and for any unimplemented tier) with a sealed, stateless gateway-owned cursor (`{version, scope_hash, resume_key}`, resumed via plain `start_after`/`marker`, re-decided per page) and delimiter synthesis — response filtering is rejected on the ContinuationToken/IsTruncated/MaxKeys correctness analysis. |
| [ADR-005](ADR-005-pdp-engine-posture-and-parity-gate.md) | PDP engine posture — sidecar OPA by default, embedded regorus only behind a dual-engine parity gate | Proposed | A gateway-owned, gateway-fed sidecar OPA on loopback is the shipping default engine; embedded regorus is the gated fast path that may serve traffic only after the dual-engine parity gate is green — Mode A repo-CI replay of the corpus through pinned OPA and regorus with canonical `Decision` equality, Mode B bundle-release replay, six go/no-go criteria — and the revision-keyed decision cache's four load-bearing correctness conditions are pinned. |
| [ADR-006](ADR-006-grant-projection-and-identity.md) | Grant projection contract and STS identity | Proposed | Freezes the two contracts the gateway consumes but does not build: the grant projection (`tenants[t].s3_grants[sub]` / `group_grants[group]`, arrays of `{bucket, actions[], prefixes[]}`, an additive superset of the existing per-tenant bundle with content-revision semantics) and STS identity (gateway-minted `HFST` sessions with HMAC-derived secrets, keyed by the bare OIDC `sub`, with the control plane fronting the gateway mint instead of a backend STS). |

## Settled invariants

Every decision above assumes the same invariants, which the ADRs resolve open questions
around without reopening:

- **Deny-by-default**, with tenant membership necessary but never sufficient — access
  requires an explicit matching grant.
- **Live revocation via bundle revisions**: policy and grant data arrive as versioned
  bundles, so a revocation lands as a new revision and takes effect without invalidation
  logic.
- **Backend-agnostic enforcement** that never depends on a backend-native capability, so the
  same policy holds across any S3-compatible backend (for example Ceph RGW, MinIO, OVH, or
  Hetzner).
- **Per-request, per-end-user audit**: one decision record per S3 request, attributed to the
  end-user identity.
