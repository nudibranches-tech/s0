# ADR-009: Bundle v3 — bucket placement, enforced by the gateway

- **Status**: Accepted — implemented (src/pdp/bundle.rs, src/access/mod.rs, src/proxy/mod.rs,
  policy/gateway/authz.rego)
- **Date**: 2026-10-02
- **Owners**: gateway team (this repo); the per-backend projection is control-plane integration
- **Related**: `src/pdp/bundle.rs` (`BucketPlacement`), `src/access/mod.rs` (`check`, `decide`),
  `src/proxy/obligations.rs` (`BucketSource`), `src/proxy/mod.rs` (`list_buckets`),
  `src/audit/record.rs` (`object_name`), `tests/bundle_v3.rs`, `tests/fixture_drift.rs`;
  amends ADR-007 (where a `ListBuckets` answer comes from) and ADR-002 (two optional
  `gateway` fields)

## Context

Until now every tenant of a gateway was re-signed with **its own** upstream credential, so
the backend itself kept tenants apart: a tenant's credential could not reach another
tenant's bucket whatever the gateway allowed. That stops holding on a backend whose upstream
identity is shared by every tenant of an organization (one identity per organization, scoped
to its bucket prefix): the backend would serve any of that organization's buckets to any of
its tenants. The isolation has to move into the gateway.

Two related facts come with such a backend. The upstream identity is usually not allowed to
list buckets at all, so `ListBuckets` cannot be forwarded. And one gateway fronts exactly one
backend, so a bundle describing another backend's buckets describes buckets that are not
there.

## Decision

From `grant_schema_version` **3** the control plane's bundle **places** buckets:

- `data.backend = { "id", "kind" }` names the backend the bundle was projected for;
- `data.tenants[<tenant>].bucket_attributes` is keyed by **S3 name** and lists every bucket
  of that backend under exactly one tenant, its owner; each entry may carry `object_name`
  (the control plane's own name for the bucket) and `created_at` (RFC 3339).

Below version 3 nothing changes: no index is built and every path is the one it was. That
holds for a numeric version below 3 and for a document with no version at all. A version
that is present but not a number (`"3"`, `null`) is a projection defect: no version was
ever anything but a number, so it is read as an unusable placing document, never as an old
one.

**The index.** `Bundle::new` builds a `BucketPlacement` once per revision: `S3 name → owning
tenant`, each tenant's bucket list, and the backend id. `check` pins it in the request's
extensions beside the route, so every sub-decision of one request is screened against one
revision.

**The gate, ahead of the PDP.** `GatewayAccess::decide` — the single funnel every policy
question passes through — refuses before asking any engine:

| Condition | Reason recorded and returned |
|---|---|
| the bucket is placed under another tenant | `deny (gateway): bucket belongs to another tenant` |
| no tenant has the bucket on this backend | `deny (gateway): bucket not on this backend` |
| the bucket is placed under several tenants | the first reason, naming the defect |
| `data.backend.id` is not the backend the request routes to | every request refused, naming both ids |
| a placing document that cannot be read | every request refused, naming the defect |
| below v3, the tenant shares its upstream identity with another tenant | every request of that tenant refused |

**Tenants sharing an upstream identity need a placing bundle.** Below v3 the pre-v3 path is
only safe because each tenant has its own credential, which the backend keeps apart by
itself. When two or more tenants of the gateway config are re-signed with the same
`(backend_id, owner_access_key)`, the placement is the only barrier between them, so for
those tenants an unplaced bundle (v2, the seed, an unversioned document) is not "today's
behaviour": every request of theirs is refused, `ListBuckets` lists nothing, and nothing is
forwarded. The sharing is derived from the config on load and on every config apply, carried
on the request's route snapshot as a flag (never the key), and a forward refuses to cross a
config change that flipped it. Tenants with their own credential keep the v2 path unchanged.

**What the client is told.** The three per-bucket refusals answer `AccessDenied` with the
reason above, verbatim. The bundle-wide ones (another backend, an unreadable placing
document, a shared identity below v3) answer one fixed sentence, `deny (gateway): the policy
bundle in force cannot be used for this request; …`: their detail can name another tenant
(`data.tenants.<tenant>.bucket_attributes is not an object`), both backend ids, or the
fact that the tenant shares an upstream identity. The detail stays on the audit record and
in the error log.

A copy's source bucket is screened on the same terms as its destination. The hooks whose
single record summarizes several decisions (copy, multi-delete, a write with riders) screen
up front, so the record names the placement rather than the summary. A refusal is an
ordinary decision record — attributed, carrying the full input, not rate-limited — because
the caller is authenticated and its tenant is known.

**The default policy agrees.** The compiled-in `policy/gateway/authz.rego` refuses the
same cases from v3 on — a bucket-scoped decision (or a copy's source) whose bucket is not
placed under `input.tenant` alone, and any decision when `data.backend.id` is not
`input.backend.id` — with its own `deny: …` reasons, and leaves the account scope's
visibility as it was. The corpus (`policy/testdata/corpus.json`) pins the cases on both
engines, and `tests/policy_corpus.rs` checks that over every case the module refuses on
placement exactly when the gateway's screen does. A module the control plane pushes is
expected to carry the same rule; the gate does not depend on it.

**`ListBuckets` from the bundle.** The hook picks the listing's source (`BucketSource`) from
the pinned placement: at v3, the requester's tenant's buckets from the bundle, `created_at`
as `CreationDate`; the backend is never asked. The policy's visibility obligation and the
gateway's sort, cursor and page cap (ADR-007) apply to it unchanged, and the authorization
proof is still required. At v2 the drained backend listing is used exactly as before.

**Audit.** A record names the bundle's `object_name` for `input.bucket` and for a copy's
source (`gateway.object_name`, `gateway.copy_source_object_name`), so a consumer can join
it to the bucket without re-deriving one name from the other. Both are omitted when the
bundle publishes none.

## Alternatives considered

- **Leave isolation to the pushed policy alone.** A policy can require
  `bucket_attributes[input.tenant][input.bucket]` to exist, and the control plane's module
  should. But the gateway would then enforce tenant isolation only as long as every module
  ever pushed carries that rule; the gate makes it a property of the binary.
- **Gate records from `check` instead of decision records.** `check` sees the path's bucket,
  but not a copy's source without re-parsing a raw header, and a gate record carries no
  action, no bucket and no organization — the facts an auditor needs about an authenticated
  tenant reaching across.
- **Treat an unreadable placing bundle as unplaced.** That switches the gate off for exactly
  the bundles that need it.
- **Let tenants sharing an upstream identity fall back to the v2 path.** A rollout that puts
  a shared-identity config live before the placing bundle, a control-plane rollback or the
  boot seed would then remove the only cross-tenant barrier, and a wildcard grant of one
  tenant would match the other's buckets. It is the same hole as the previous alternative.

## Consequences

- At v3, a bucket that is not placed under the requester's tenant answers `403`, where a
  forwarded request could have answered `404`. Distinguishing "another tenant's" from "not
  here" discloses that the name is taken on this backend, which the control plane's
  bucket-creation refusal discloses anyway.
- A bundle served to the wrong instance is a total outage of that instance, logged at
  `error` once per revision and recorded on every refused request. Failing open would serve
  buckets the bundle was never about.
- `ListBuckets` at v3 costs no backend round trip and no drain bound.
- A config whose tenants share an upstream identity must not go live before their placing
  bundle does. If it does, those tenants are refused until it arrives; nothing is served
  across tenants in the meantime.
- Bucket names in a v3 bundle are S3 names; grants must be projected to them, or they match
  nothing the gate lets through.
