# ADR-001: The enforcement claim is conditional on closing direct backend paths

- **Status**: Accepted — the gateway-side half is implemented; the deployment-side half is an operator obligation
- **Date**: 2026-07-15
- **Scope**: What s0's security claim actually depends on, and what s0 therefore refuses to
  consume. The operational programme for closing direct paths is named here but belongs to
  whoever deploys s0, not to this repository.

---

## Context

s0's security claim is **conditional**:

> Enforcement and per-user audit hold **only if no consumer can reach the backend directly.**

This is an invariant, not a migration detail. A gateway that authorizes every request it sees
proves nothing if a credential exists that bypasses it. Until the direct paths are closed, s0 is
a proxy with a policy engine, not an enforcement boundary.

Two things follow, and only the second is s0's to decide.

**Direct-path exposure is real in any existing deployment.** Credentials that reach the backend
without traversing a gateway generally exist already — a tenant-owner key vended to end users
for CLI use, the same key configured into a query engine, an operator's admin credential. They
are frequently *the same secret*, so revoking one endpoint is not closure: closure means
rotating the underlying backend key, which kills every outstanding copy at once and must
therefore be sequenced after every consumer has migrated.

**Policy drift is possible whenever more than one policy codebase evaluates the same access
intent.** A backend-side defence-in-depth policy, an analytics-engine PEP, and the gateway
policy can disagree, and divergence between them *is* a bypass.

## Decision

### D1 — s0 is deliberately ignorant of the exposure inventory

The inventory of direct-path credentials is an operational artifact with an owner and a review
cadence. It is **not** a bundle field, and s0 reads nothing from it at decision time.

That ignorance is the decision. If s0 consumed an exposure list, a rego rule could branch on
"is this principal also a native backend user", and the gateway's verdict would then depend on a
document maintained outside the trust boundary it is enforcing.

The governing rule for the inventory itself, stated here because s0's claim rests on it:

> Under a per-user audit requirement, "accept in writing that it is outside the model" is not an
> available disposition for any credential that can reach user-attributable data. Such a
> credential is, by definition, an unaudited direct path.

Every entry is either **closed** (revoked, with the consumer moved onto a per-user
gateway-issued credential) or, only for a credential that provably cannot touch tenant object
data, **isolated and bounded** — verified capability-by-capability rather than asserted, secret
held only in the operator's store, network path restricted to backend admin endpoints, any
object operation under that principal alerting as an incident. If verification shows the
credential *can* read or write tenant objects and that cannot be removed, it is data-touching
and only closure is available.

A verified set of known credentials is a *seed*, not a proof of completeness: the inventory needs
an enumeration sweep reconciled against it, and continuous detection treating any uninventoried
principal on the direct path as an incident.

### D2 — What s0 consumes, and what it must never consume

This is the part the code enforces:

- s0 consumes the per-org bundle — `user_attributes`, `bucket_attributes`, `org_settings`,
  `s3_grants` / `group_grants` — in exactly the shape documented at the head of
  [`policy/gateway/authz.rego`](../../policy/gateway/authz.rego), **and nothing else**.
- It authorizes the forward path with its **own per-tenant, per-backend credential**, and never
  depends on backend IAM, backend STS, or a backend hook for enforcement or audit.
- It emits one decision record per request ([`src/audit/record.rs`](../../src/audit/record.rs)),
  which is what makes "closed" *observable* rather than merely asserted.

### D3 — Drift is controlled by a shared conformance corpus, not by code generation

Where more than one policy codebase exists, they are held together by a shared conformance suite
replaying one corpus, anchored on a single grants source of truth — not by generating the
policies from a common source.

Generation was rejected because it makes the generator a single point of silent failure and
couples release cycles across systems that ship independently. A corpus, by contrast, fails
loudly and per-case, and each codebase stays free to express its own concerns.

In this repository the corpus is [`policy/testdata/corpus.json`](../../policy/testdata/corpus.json),
replayed by [`tests/policy_corpus.rs`](../../tests/policy_corpus.rs) and — through both engines,
which must agree byte-for-byte — by [`tests/parity.rs`](../../tests/parity.rs). It is
engine-agnostic on purpose, so it can seed the same suite elsewhere.

## Consequences

- s0 cannot verify its own precondition. Nothing in this repository can prove no direct path
  exists; that proof is deployment-side, and this ADR exists so the dependency is written down
  rather than assumed.
- Refusing to consume the inventory means s0 cannot "compensate" for a known-open direct path.
  That is intended: a gateway that special-cases the principals bypassing it is not an
  enforcement boundary.
- Object-tag ABAC is gated on this ADR — see
  [ADR-003](ADR-003-object-tag-abac-toctou-and-cache.md), which hard-wires tags off until the
  direct-path question resolves.
