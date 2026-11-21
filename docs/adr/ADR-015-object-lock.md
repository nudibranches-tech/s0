# ADR-015: Object Lock — delegated configuration, two verbs for retention and legal hold

- **Status**: Accepted — implemented in 0.6.1 (`src/model.rs`, `src/access/optable.rs`,
  `src/access/headers.rs`, `src/access/mod.rs`, `src/authz/input.rs`, `src/proxy/mod.rs`,
  `policy/gateway/authz.rego`, `docs/verbs.json`); amends ADR-006 (the closed verb set),
  ADR-008 (the object-lock residual is closed; Decision 3 is kept), ADR-012 (the delegable set
  grows from sixteen to eighteen) and ADR-013 (D5 applies to the new verbs)
- **Date**: 2026-11-20 (revised the same day after the platform's second red-team round;
  accepted with the implementation the same day)
- **Owners**: gateway team (this repo); the projection that emits the new verb and the control
  backend that answers the delegated operations are the control plane of the platform that deploys
  s0
- **Related**: `src/access/optable.rs` (`GATEWAY_VERBS`, the six object-lock rows), `src/model.rs`
  (`Action`), `src/access/headers.rs` (`RequestRiders`), `src/access/mod.rs` (`screen_riders`,
  `authorize_riders`, the write hooks), `src/proxy/mod.rs`, `policy/gateway/authz.rego`
  (`write_actions`); relies on ADR-006, ADR-008, ADR-012 and ADR-013. Platform side: ADR-0056 of
  the Hyperfluid repository, amendment "Object Lock".

## Context

s0 refuses every Object Lock operation. The six rows (`Get/PutObjectLockConfiguration`,
`Get/PutObjectRetention`, `Get/PutObjectLegalHold`) are `Denied`. `CreateBucket` is delegated
(ADR-012), and its typed input already carries `object_lock_enabled_for_bucket`; the control
backend refuses it today.

The platform that deploys s0 has decided to offer Object Lock at bucket creation, as AWS, OVHcloud
and Scaleway do. Three things in s0 stand in the way:

1. A tenant cannot read or change a locked bucket's default retention: the configuration ops are
   denied.
2. A tenant cannot set or read retention or a legal hold on one object.
3. The object-lock headers on `PutObject`, `CopyObject`, `CreateMultipartUpload` and `PostObject`
   are uninspected blind spots (ADR-008, Decision 4 residuals). While no bucket behind s0 was
   locked, the backend rejected those headers and the blind spot was inert. On a locked bucket it
   becomes live: any `write_objects` grant could make data undeletable for years in COMPLIANCE
   mode. That is the mirror image of the governance bypass that ADR-008 Decision 3 refuses.

s0 signs upstream requests with a credential that, on the reference deployment, holds `s3:*` on
the tenant's buckets. Whatever s0 forwards, the backend honours as the bucket owner. So every lock
power has to be decided in s0.

## Decisions

### D1 — the bucket lock configuration is delegated

`GetObjectLockConfiguration` and `PutObjectLockConfiguration` become `Delegable`. They keep their
classification labels (`read_bucket_config`, `write_bucket_config`) and tiers (`Routine`,
`PostureAltering`). They are delegated only when listed in `control_backend.operations` (ADR-012
D1, D2). An unlisted one answers `AccessDenied`, like every unlisted delegable row; it no longer
answers 501.

- **Why delegate.** A bucket's lock configuration is bucket posture owned by the control plane, in
  the same way as versioning. The control backend knows whether the bucket was created locked, the
  platform's retention limits and the owner's permission. s0 knows none of these.
- **`CreateBucket` needs no change.** `object_lock_enabled_for_bucket` is part of the typed input
  that is forwarded. The control backend decides whether to honour it, which ADR-012 D3.2 already
  gives it.
- A test asserts that the control stub receives the field. That test is the proof the s3s-aws
  forwarding keeps it.

The delegable set grows from sixteen to eighteen.

- **Rollout constraint.** An s0 older than 0.6.1 refuses to load a configuration that lists
  either operation (ADR-012 D2). So a control plane must render them only for a 0.6.1 image.

### D2 — two verbs, `write_object_retention` and `write_object_legal_hold`

`Action::WriteObjectRetention` / `"write_object_retention"` and `Action::WriteObjectLegalHold` /
`"write_object_legal_hold"` join the closed grant vocabulary, which grows to ten verbs (ADR-014
added the ninth, `create_objects`). This amends ADR-006 and follows ADR-013 D3.

- **Why two.** AWS splits `s3:PutObjectRetention` from `s3:PutObjectLegalHold`, and so must the
  grants. With one verb, an application key granted retention so that it can stamp new uploads
  could also lift a legal hold an owner placed for litigation.
- **Scope.** Both are object-scoped and prefix-scoped.
- **Freeze.** Both are writes, so `freeze_writes` covers them on both sides.
  `the_write_set_matches_the_shipped_rego` holds the Rust and the compiled-in rego sets equal. A
  deployment that pushes its own module (the reference platform does) must guard its own copy, so
  s0 publishes the vocabulary as `docs/verbs.json` (each verb with its `is_write`), pinned by
  `verbs_json_matches_action_all`, for the control plane to vendor and test against.
- **Covers.** `PutObjectRetention` is `Enforced` under `write_object_retention`,
  `PutObjectLegalHold` under `write_object_legal_hold`, both with tier `PostureAltering`. They also
  cover the inline riders of D3.
- **Independent of `write_objects`.** Neither implies `write_objects`, and `write_objects` does not
  imply them. A principal that may set retention or a hold cannot write data. The converse holds
  only where the bucket has no default retention: on a bucket with one, the backend stamps every
  plain write, so every `write_objects` holder creates retained versions (see "No implicit grant").
- **Deny.** An applicable deny on `write_objects` also denies both verbs, as a deny on
  `delete_objects` denies `delete_object_versions` (ADR-013). A principal shut out of a prefix must
  not keep the power to make its objects permanent or to release them.
- **Reads.** `GetObjectRetention` and `GetObjectLegalHold` become `Enforced` under `read_objects`
  (`Routine`). Retention is metadata of an object the principal may already read.
- **Blind spot.** The four retention and legal-hold ops have one blind spot: `version_id`. A
  retention on an older version is decided under the current key's grant, as `GetObjectTagging`
  already is.
- **No implicit grant.** A bucket's default retention, set through D1, applies to plain writes
  inside the backend. It needs no verb because the bucket's owner chose it. The owner's choice is
  what makes every writer a retention creator on that bucket; bounding that (a finite bucket quota)
  is the control plane's job.

### D3 — inline lock headers are a rider

A `PutObject`, `CopyObject`, `CreateMultipartUpload` or `PostObject` that carries any of the
following is decided a second time, under `write_object_retention` on the same object:

- `x-amz-object-lock-mode`
- `x-amz-object-lock-retain-until-date`
- `x-amz-object-lock-legal-hold`
- the POST form fields of the same names

This is ADR-008's decomposition, applied the way inline `x-amz-tagging` is decided under
`write_object_tags`.

- **Create-only writes.** The riders are decided before, and independently of, the primary
  decision. A write that cannot overwrite (`If-None-Match: *`), decided under `create_objects`
  when `write_objects` is denied (ADR-014 F1), takes the same lock decisions: the drop-box verb
  does not stamp a retention or a hold.
- **Cost.** A write without lock headers still costs one decision.
- **Audit.** One request still produces one audit record, against the primary input.
- **Malformed pairs are refused.** A mode without a retain-until date, or a date without a mode,
  is refused before any decision. The backend could read such a pair differently from s0, so it is
  a parser differential.
- **Blind spots removed.** The object-lock blind spots are removed from the four rows.
  `tests/op_coverage.rs` stops requiring the `PutObject` one.

Mode and retain-until riders are decided under `write_object_retention`; a legal-hold rider under
`write_object_legal_hold`. A request carrying both takes both decisions.

`OpaInput` gains an optional `requested_retention` (`{mode, retain_until, retain_days, legal_hold}`),
for the policy and the audit trail. It is filled on the inline riders **and** on the primary
`PutObjectRetention` and `PutObjectLegalHold` inputs, so a policy can cap a period whichever way it
is asked for. `retain_days` is the whole number of days from the request time to `retain_until`,
rounded up, computed by s0 so that a policy needs no clock. The field is omitted when absent, so
captured inputs that have no lock field stay unchanged. It enters the decision-cache key.

- **D2 and D3 ship in one commit.** No build of this release has the verbs without the riders: a
  control plane that opens the lock on a build whose riders are missing would leave every
  `write_objects` holder able to set COMPLIANCE retention inline.

### D4 — the governance bypass stays refused in code

ADR-008 Decision 3 is kept unchanged. `x-amz-bypass-governance-retention` is refused ahead of the
PDP on `DeleteObject` and `DeleteObjects`. It is now also refused on `PutObjectRetention`, where
it is the way to shorten or lift a GOVERNANCE retention.

- **Not a new verb.** The new verb does not express bypass. Making bypass possible stays a separate
  vocabulary revision on the control-plane side.
- **Audit.** The attempt is still recorded in the input.
- **Backend rules stand.** Extending a retention or switching GOVERNANCE to COMPLIANCE needs no
  bypass, so it is decided under the verb. The backend still refuses shortening a COMPLIANCE
  retention and refuses a delete of a retained version. s0 forwards those refusals.

### D5 — wildcard grants gain the verbs

`"*"` in a grant's `actions` now confers both new verbs (ADR-013 D5). The platform's own
projection emits no action wildcard.

## Rollout

| Change | Effect on a client | When it is safe |
|---|---|---|
| Lock configuration delegated | `get/put-object-lock-configuration` reach the control backend | When the control plane lists them, only for a 0.6.1 image |
| Retention ops enforced under the new verbs | A principal holding a verb can set retention or a legal hold; any principal with `read_objects` can read them | After the control plane has listed the buckets its backend already reports as locked. A deployment that once handed tenants the backend owner credential cannot assume no bucket was locked before 0.6.1 |
| Inline lock headers decided under the verbs | A write carrying lock headers is refused without the matching verb | Immediately. On an unlocked bucket the backend refused those headers anyway; on a bucket locked earlier this closes a live blind spot |
| `"*"` gains the verbs | A wildcard grant may set retention and legal holds | The platform emits no wildcard |
| Pre-release builds | A `0.6.1-dev.*` or `0.6.1-rc.*` image lists the eighteen operations | A control plane should open the lock only on a final release; the platform's gate refuses pre-releases |

A control plane that does not project the verb yet loses nothing it had. No retention operation
worked before.

## Consequences

- **Ten grant verbs.** These move together: `GATEWAY_VERBS`, `Action::ALL`, the rego vocabulary,
  `write_actions` and the platform's projection, permission catalog and pushed rego.
- **Counts.** Twenty-eight operations are enforced and seventy-one are not. Eighteen are delegable.
- **Tests that change:**
  - `tests/op_coverage.rs`: counts, the delegable list, ten verbs, and the inverted object-lock
    residual.
  - `tests/gate_invariants.rs`: hooks and arms.
  - `tests/delegation.rs`: eighteen calls, plus the `CreateBucket` lock-field test.
  - `tests/request_riders.rs`: the two lock riders, the bypass on `PutObjectRetention`, and
    `requested_retention` (with `retain_days`) on both primary ops.
  - `policy/gateway/authz.rego` and its tests: the deny implication from `write_objects`.
  - new `docs/verbs.json` and `verbs_json_matches_action_all`.
  - `tests/common/{ops,control_stub}.rs`.
  - `tests/readme_optable.rs`, through the README.
- **Remaining residuals:**
  - s0 itself does not cap a retain-until date. It hands the period to the policy
    (`requested_retention.retain_days`), and the deploying platform's pushed module caps it (the
    reference platform at 3 650 days, denying when the field is missing).
  - A frozen organization cannot lift a legal hold: freeze is decided by verb, and lifting a hold
    is a write. The control plane unfreezes to let it.
  - Whether the backend copies retention on `CopyObject` (AWS does not) is unverified; a copy
    without lock headers is decided under `write_objects` only.
  - Deleting a retained version is decided under `delete_object_versions` and refused by the
    backend. s0 has no lock-aware logic and needs none.
  - A downgrade below 0.6.1 after a locked bucket exists reopens the inline-header blind spot.
    The control plane must refuse it (the reference platform's operator does).
- **Release.** This ships as 0.6.1, by the deploying platform's decision. It is a contract change
  at feature level, released in a patch number.

## Implementation notes

Settled while implementing, without changing a decision above:

- **Wire values.** `requested_retention.mode` is `GOVERNANCE` or `COMPLIANCE`,
  `legal_hold` is `ON` or `OFF`, as S3 spells them; `retain_until` is RFC 3339 in UTC with
  millisecond precision. A mode or hold state outside those lists is refused before any
  decision, like a half-specified retention: the backend could read it differently.
- **No double decision.** A rider whose verb is the primary decision's is not asked again:
  `PutObjectRetention` takes one decision under `write_object_retention`, not two.
- **Empty bodies.** A `PutObjectRetention` whose `Retention` names neither a mode nor a date
  carries `requested_retention: {}` (no `retain_days`, so a module that denies on a missing
  period denies it). A `PutObjectLegalHold` naming no status is refused: the gateway cannot
  see which direction the hold moves.
- **The deny implication lives in the pushed module.** The compiled-in default module has
  no action-scoped deny grants, only the per-bucket denylist, which already covers every
  verb (the corpus pins it for both lock verbs). "A deny on `write_objects` also denies both
  verbs" (D2) is therefore a rule for a deploying platform's pushed module, which has deny
  grants; the default module's header states it.
- **Captured inputs.** The golden-capture probe for `PutObjectRetention` sends an empty
  `Retention`, because `retain_days` counts from the request time and a dated probe would
  record a different input every day. The dated shape is pinned in
  `tests/request_riders.rs`.

## Alternatives considered

**A1 — keep retention ops and inline headers under `write_objects`.** This was the table's
original label. Rejected: every writer could make data undeletable. That power is as destructive
as the bypass ADR-008 refuses, and AWS keeps it under its own action.

**A2 — enforce the lock configuration under a bucket-scoped verb instead of delegating it.**
Rejected: ADR-012 already settles that bucket posture (versioning, encryption) belongs to the
control backend. A bucket verb would split the authority over one setting between the policy and
the control plane.

**A3 — strip lock headers from writes that lack the verb.** Rejected on ADR-008's ground ("deny,
never strip"): a strip answers 200 to a request whose intent was not honoured.

**A4 — add a `bypass_governance_retention` verb now.** Rejected: no consumer asked for it. A
platform that must release locked data at contract end does it with its own backend credential,
outside s0. A grantable bypass stays the vocabulary revision ADR-008 describes.

**A5 — one verb for retention and legal hold.** The first draft. Rejected: an application that may
stamp retention could lift an owner's legal hold.

**A6 — a hard-coded maximum retain-until in s0.** Rejected: the right ceiling is the deploying
platform's policy, which it already ships in the bundle. s0 supplies the number the policy needs.
