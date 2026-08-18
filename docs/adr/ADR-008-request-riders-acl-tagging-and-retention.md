# ADR-008 — Request riders: ACL grants, inline tagging, and governance bypass

- **Status:** Accepted — implemented
- **Date:** 2026-07-28
- **Scope:** `src/access/headers.rs`, `src/access/tagging.rs`, `src/access/mod.rs`
  (`screen_riders`, `authorize_riders`, `enforce_object_write`),
  `src/authz/input.rs` (`acl_grants`, `bypass_governance`), `tests/request_riders.rs`

## Context

The gateway authorized a write on `(bucket, key)` and nothing else. Everything else the
request carried rode through to the backend unread:

| field | effect at the backend | ops |
|---|---|---|
| `x-amz-acl` (canned) | **makes the object world-readable** with `public-read` | PutObject, PostObject, CopyObject, CreateMultipartUpload, CreateBucket |
| `x-amz-grant-{read,write,read-acp,write-acp,full-control}` | the same, one grantee at a time | same (`grant-write` on CreateBucket only) |
| `x-amz-tagging` | installs a caller-chosen tag set | PutObject, PostObject, CopyObject (with `tagging-directive: REPLACE`), CreateMultipartUpload |
| `x-amz-bypass-governance-retention` | **destroys an object under WORM retention** | DeleteObject, DeleteObjects |

The decision record for such a request said *allowed write*, with no evidence anywhere
that an ACL had been requested, let alone applied. For a private cloud sold into
hospitals and governments, a silent public-exposure path is the worst class of defect.

Three questions had to be answered, and they have different answers.

## Decision 1 — DENY, not strip

A `strip_request_fields` obligation does not exist. `Obligations` carries
`deny_unknown_fields`, so a policy emitting one denies every request it touches — pinned
by `no_strip_obligation_exists_and_a_policy_emitting_one_denies`.

1. **A strip makes the gateway lie.** The caller asked for an ACL, got `200 OK`, and does
   not have one. The failure surfaces months later as "the partner integration lost
   access", with no error to correlate against — the same shape as the defect being
   fixed, merely inverted.
2. **A deny is discoverable in one round trip.** 403, a reason naming the header, and a
   decision record. The operator's next move is legible from the response.
3. **A strip switch is the switch that gets flipped.** The first thing a frustrated
   operator does when `aws s3 cp --acl private` 403s is turn stripping on — for every
   principal and every request. An authorization boundary must not be a config value.
4. **`PostObject` cannot be stripped correctly at all.** Its ACL is a *form field* covered
   by the signed POST policy document. Removing the field while forwarding the policy
   produces a policy/field mismatch — an opaque 403 from the backend instead of an honest
   one from the gateway.
5. **The compatibility case that motivates stripping is `private`, and `private` is not a
   grant** (decision 2). Handling it costs one const array, not a switch.

## Decision 2 — three tiers, and only the first one passes

| tier | membership | outcome |
|---|---|---|
| **no-op** | canned `private` — and only `private` | carries no grant. Emitted in `acl_grants` and on the audit record, but requires nothing |
| **public** | `public-read`, `public-read-write`, `authenticated-read`; any grantee expression containing `AllUsers`/`AuthenticatedUsers`; **any canned name this build does not recognize**; and any bucket ACL on `CreateBucket` | **refused in code** (`AclDisposition::RefusedPublic`), ahead of and independent of the PDP |
| **conferring** | everything else — `bucket-owner-read`, `bucket-owner-full-control`, `aws-exec-read`, `id=`/`emailAddress=` grantees | **refused in code** (`AclDisposition::RefusedConferring`) on all four write paths |

- **Why this is code and not policy.** `action_matches(g) if "*" in g.actions` means a
  wildcard grant confers anything, and the default access model seeds exactly that for
  every org Owner. A policy-only guard would leave every Owner one `--acl public-read`
  away from publishing a patient record. `tests/request_riders.rs` re-runs every refusal
  against an `actions: ["*"]` bundle for that reason.
- **Why conferring is refused rather than gated on a verb.** An object ACL is a second,
  backend-side access-control list the control plane does not project, cannot display and
  cannot revoke, so granting through it is granting outside the managed access model. The
  two refusals stay distinguishable because the operator needs to know which one they hit.
- **Why `private` is a no-op and `bucket-owner-full-control` is not.** `private` is *the
  default ACL*: on a create it asks for the state the object would have anyway, and on an
  overwrite it narrows. There is no third party it can name. `bucket-owner-full-control`
  is a no-op only *because* every forward is re-signed as the tenant-owner credential — a
  property of the current topology, not of the request. `s3cmd` and `rclone` send
  `private` by default, which is the entire compatibility exposure.
- **Why an unrecognized canned name is refused.** The gateway cannot prove a name it has
  never heard of is not a public grant; the backend will expand it regardless. Guessing
  permissively is how a closed set silently reopens on the next S3 API addition.
- **Why `CreateBucket` needs no special case.** It is `Coverage::Denied`, so its
  create-time bucket ACL is refused a step earlier, by the gate.

An inline `x-amz-tagging` is decomposed the same way: it is a `PutObjectTagging` wearing a
`PutObject`'s clothes, so it takes a `write_object_tags` decision on the same object.
This mirrors AWS's own model (`s3:PutObject` + `s3:PutObjectAcl` + `s3:PutObjectTagging`)
and is what keeps the ordinary case free — a write with no riders costs one decision.

## Decision 3 — `x-amz-bypass-governance-retention` is refused unconditionally

AWS gates it on its own IAM action, `s3:BypassGovernanceRetention`. The gateway's grant
vocabulary has **no equivalent**, so no grant could express "may destroy a retained
object" — the refusal therefore cannot be a policy decision, and inventing an extra verb
here would be a contract change made unilaterally by a PEP.

So: refused in code, on `DeleteObject` and `DeleteObjects`, and on the batch op the
*whole* request is refused before any key is decided (a partially-honoured WORM bypass is
not something this gateway should be able to produce). `bypass_governance: true` still
reaches the PDP input and therefore the audit record, because in a regulated deployment
"who tried to defeat retention" is a question the trail has to answer.

Making retention overrides possible is a vocabulary revision on the control-plane side,
not a patch here.

## Decision 4 — `reserved_tag_keys`: absence denies

`OpaInput.object_tags` exists so a policy can key grants on object tags. The moment any
policy does, a principal holding `write_objects` + `write_object_tags` can grant itself
whatever the policy keys on. Two things close that:

1. the decision is made against the **proposed** tag set (`requested_tags`), never the
   object's current one, so the policy sees the state the object is *entering*;
2. the key space a policy may depend on is reserved, published by the control plane at
   `data.org_settings.reserved_tag_keys` and enforced **PEP-side** — deliberately not in
   the rego, so a pushed policy module cannot forget it.

**An absent list denies every tag write** (`PutObjectTagging`, `DeleteObjectTagging` and
inline `x-amz-tagging` all refused). A malformed list is treated as absent for the same
reason. The alternative default is indistinguishable from a correctly-configured
deployment right up to the moment someone writes the first ABAC condition, at which point
every tag-writing principal silently gains the ability to satisfy it. A missing
security-relevant input must not read as "no restriction" — the same argument that
produced `deny_unknown_fields` on `Obligations` and `must_understand` in ADR-007.

In practice the control plane publishes a list on every bundle: its own reserved
namespace (the analogue of AWS's `aws:` prefix) unioned with every `tag:<key>` a grant in
the same document conditions on. Deriving the list from the grants being published turns
"no policy depends on a tag" from a claim into an invariant the producer cannot violate.

`DeleteObjectTagging` is included on purpose: removing a tag changes the ABAC facts about
an object exactly as setting one does, and a deployment that has not said which keys
matter cannot tell which removals do.

## Consequences

- **`acl_grants` and `bypass_governance` are always-serialized `OpaInput` fields.** `[]`
  and `false` are assertions, not absences: a rego reference to an undefined field is the
  silent deny-all this project exists to avoid. They enter the decision-cache key by
  construction (`resource_key` is a digest of the document), which matters concretely —
  otherwise a plain `PutObject` and an ACL-bearing one to the same key would share a cache
  entry, and the first would cache an allow for the second. Pinned by
  `the_acl_retrofit_fields_enter_the_decision_cache_key_by_construction`.
- **The captured corpus carries two new always-present keys** and was regenerated. One
  capture carries a real `acl_grants` and a header-derived `requested_tags`, so the wire
  form of an ACL grant is on the record for policy authors.
- **A tag key a policy conditions on but which the published list omits is still
  writable.** The failure mode is a list that is present and incomplete, not a missing
  one. A key some projected grant conditions on cannot be omitted, because the list is
  derived from those grants; the residual is a key read by a policy from outside the
  grant projection.
- **Residuals kept, not closed.** Object-lock headers (`mode`, `retain-until-date`,
  `legal-hold`) are uninspected — a write grant can make an object *undeletable*, the
  opposite direction from the bypass. A `CopyObject` under the default
  `tagging-directive: COPY` moves the source object's tags onto a new key with no
  tag-write decision. `object_ownership` on `CreateBucket` can re-enable ACLs on the new
  bucket (inert while every ACL-bearing request is refused, but a posture change nobody
  authorized). All three are on the relevant `OP_TABLE` blind-spot lists.
- **A tagging header containing a literal `+` is refused**, because query-string encoding
  reads it as a space and RFC 3986 reads it as a plus, and the gateway cannot know which
  the backend will pick. Same parser-differential argument that refuses a duplicate key in
  a `TagSet` body.
- **Public-grantee matching over-matches.** `AllUsers`/`AuthenticatedUsers` are matched
  case-insensitively as substrings of the whole grantee expression, so a canonical user id
  containing that literal text is refused. A false refusal is a support ticket; a false
  acceptance is a public bucket.

## Alternatives rejected

- **Ship the strip obligation behind a config flag.** The flag is the failure mode, not
  the mitigation.
- **Refuse every ACL, including `private`.** Breaks `s3cmd` and `rclone` on every upload
  for zero security gain, because `private` cannot grant anyone anything.
- **Add a `bypass_governance_retention` verb.** The vocabulary is the contract the
  control-plane projection emits; a PEP does not get to extend it unilaterally.
- **Put the reserved-key guard in the rego.** The control plane pushes the policy module,
  so a module that forgot the guard would reopen the hole with nothing failing.
- **Parse grantee expressions properly.** A partial parse the gateway and the backend
  disagree about is worse than none. The one classification that matters (does this reach
  a public audience?) is made on the raw text, in the over-matching direction.
