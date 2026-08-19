# Architecture Decision Records

An ADR captures one significant design decision: the context that forced it, the decision,
the alternatives weighed, and the consequences accepted. Each is self-contained and dated.
The body is immutable once accepted — a later decision supersedes an earlier one with a new
ADR rather than editing it in place — but the **Status** line tracks reality.

| ID | Decision | Status |
|---|---|---|
| [ADR-001](ADR-001-dual-path-exposure-and-drift-control.md) | s0's enforcement claim is conditional on no consumer reaching the backend directly — and s0 is deliberately ignorant of the exposure inventory, so no rule can branch on "is this principal also a native backend user". Closing the direct paths is an operator obligation; drift across policy codebases is controlled by a shared conformance corpus, not code generation. | Accepted (gateway half) |
| [ADR-002](ADR-002-decision-log-record-shape.md) | Exactly one policy-native decision-log record per S3 request, discriminated by a record-type label alongside a trusted org label that is never derived from request input. Copy and multi-delete fold into single records. | Accepted |
| [ADR-003](ADR-003-object-tag-abac-toctou-and-cache.md) | Object-tag ABAC ships only after the direct-path exposure is closed. Until then it is hard-wired off: object tags are never populated and tag-bearing decisions are never cached. The eventual design is restrict-only, gated behind a new verb, and never cached without a gateway-minted tag version in the key. | Proposed |
| [ADR-004](ADR-004-list-multiprefix-handling.md) | Single-prefix listings rewrite `input.prefix` in the `&mut` typed hook; multi-prefix listings use bounded fan-out-and-merge (default 16, fail-closed above the bound) with a sealed, stateless gateway-owned cursor, re-decided per page. Response filtering was rejected on pagination-correctness grounds. | Accepted |
| [ADR-005](ADR-005-pdp-engine-posture-and-parity-gate.md) | Sidecar OPA on loopback is the shipping default engine. Embedded regorus may serve traffic only behind a dual-engine parity gate that replays the golden corpus through both with canonical decision equality. Pins the decision cache's correctness conditions. | Accepted |
| [ADR-006](ADR-006-grant-projection-and-identity.md) | Freezes the two contracts the gateway consumes but does not build: the grant projection shape, and STS identity — gateway-minted sessions with HMAC-derived secrets keyed by the bare OIDC `sub`, with the control plane fronting the mint instead of a backend STS. | Accepted |
| [ADR-007](ADR-007-response-obligations-and-bucket-visibility.md) | Introduces the channel by which a decision restricts a **response** rather than a request. Settles `ListBuckets` with a gateway-owned sort and cursor, a `must_understand` list that denies rather than skipping an obligation an old binary cannot apply, and an empty listing — never a 403 — for both "may not enumerate" and "has nothing". | Accepted |
| [ADR-008](ADR-008-request-riders-acl-tagging-and-retention.md) | Closes the ACL / grant-header / inline-tagging / governance-bypass blind spots on write operations. The answer is **deny, never strip**: a strip answers 200 to a request whose intent was not honoured. Conferring ACLs and governance bypass are refused in code, ahead of the PDP, so no pushed policy can confer them. | Accepted |

## Settled invariants

Every decision above assumes these, and resolves open questions without reopening them:

- **Deny by default**, with tenant membership necessary but never sufficient — access
  requires an explicit matching grant.
- **Live revocation via bundle revisions**: policy and grant data arrive as versioned
  bundles, so a revocation lands as a new revision with no invalidation logic.
- **Backend-agnostic enforcement** that never depends on a backend-native capability, so
  the same policy holds across any S3-compatible backend.
- **Per-request, per-end-user audit**: one decision record per S3 request, attributed to
  the end-user identity.
