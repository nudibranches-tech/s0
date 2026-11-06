# ADR-012: Versioned listing and the versioned-delete verb

- **Status**: Proposed — amends ADR-002 (the decision record), ADR-004 (D6.4) and ADR-006 (the closed verb set); implemented
  (`src/access/optable.rs`, `src/access/mod.rs`, `src/proxy/mod.rs`, `src/proxy/obligations.rs`,
  `src/audit/record.rs`, `policy/gateway/authz.rego`)
- **Date**: 2026-11-04
- **Owners**: gateway team (this repo); the grant projection that emits the new verb is the control
  plane of the platform that deploys s0
- **Related**: `src/access/optable.rs` (`OpSpec.versioned`, `GATEWAY_VERBS`), `src/model.rs`
  (`Action`), `src/access/mod.rs` (`delete_object`, `delete_objects`, `list_object_versions`),
  `src/proxy/mod.rs` (`restrict_versions`), `policy/gateway/authz.rego` (`write_actions`); relies
  on ADR-004, ADR-006, ADR-007 (response obligations) and ADR-008 (rider screening); companion to
  ADR-011. Platform side: ADR-0056 of the Hyperfluid repository.

## Context

Until now s0 ignored object versions. `ListObjectVersions` was refused. `DeleteObject` and every
`DeleteObjects` entry were decided under `delete_objects` whether or not they carried a
`versionId`, and the table listed that as a blind spot: "a versioned delete is not distinguished
from a delete marker".

That was harmless while no bucket behind s0 was versioned. ADR-011 delegates `PutBucketVersioning`
to the control backend, so a versioned bucket is now reachable through s0, and the blind spot
becomes a real escalation. On an Enabled versioned bucket `DeleteObject` without a `versionId` writes a
delete marker and destroys nothing (on a Suspended bucket it removes the null version, as
`s3:DeleteObject` does on AWS, so a `delete_objects` grant keeps that residual power there). With a `versionId` it **permanently destroys one version**.
A grant that lets a principal "delete objects" would silently let it destroy history. AWS keeps
the two apart: `s3:DeleteObject` and `s3:DeleteObjectVersion`.

Clients also need the other half. `aws s3api list-object-versions`, `mc ls --versions`, boto3's
`bucket.object_versions` and rclone with `--s3-versions` all call `ListObjectVersions`, which s0
answered `AccessDenied` or `501`.

## Decisions

### D1 — `ListObjectVersions` is a single-prefix `list_objects` decision

`ListObjectVersions` joins `list_objects`, with the shape and the refusals of `ListObjects`
(ADR-004 D2): the request prefix is narrowed to the granted one, an unbounded listing needs a
whole-bucket grant, and **a multi-prefix grant is refused with the existing reason**. It is not
fanned out. The cursor of a version listing is two-part (`key_marker`, `version_id_marker`) and
ADR-004's resume-by-key rule does not cover it, which is exactly why D6.4 kept the operation off
the allowlist. Refusing the multi-prefix case is the narrowing of that clause; fan-out for
versions stays unspecified.

The hook runs the same `enforce_list` as `ListObjects` with `Fanout::Unsupported`, so a refusal is
the audited verdict and no proof is minted for it.

### D2 — the response is re-filtered to the decided prefix, owners are withheld

ADR-004 rejected response filtering as the *mechanism* of narrowing, on pagination grounds, and
that still holds: the request is narrowed first. Here the filter is a second line, not the
mechanism. The forward is re-signed with the tenant-owner credential, "the backend honored the
narrowing" is not observable, and a version listing carries two row types (versions and delete
markers) plus common prefixes, each of which names a key.

The access hook installs `ResponseObligations::version_listing(prefix)` (ADR-007's channel). The
dispatcher refuses to forward a version listing that has no such obligation (`InternalError`,
before any backend is contacted) and, on the answer:

- keeps the `versions`, `delete_markers` and `common_prefixes` whose key starts with the decided
  prefix, comparing percent-decoded keys when the answer says `encoding-type=url` (the request
  prefix is the raw string);
- drops a row with no key;
- withholds `owner` from both row types, for the reason on `ListParts`: it names the shared
  tenant-owner credential.

Markers and `is_truncated` are left as the backend set them, so a page may come back short.
Version ids, sizes, ETags and delete markers ride through as the backend reported them.

### D3 — a seventh verb, `delete_object_versions`

`Action::DeleteObjectVersions` / `"delete_object_versions"` is added to the closed grant
vocabulary (it amends ADR-006, which froze six). It is object-scoped, prefix-scoped like
`delete_objects`, and a write: `freeze_writes` covers it on both sides, and
`the_write_set_matches_the_shipped_rego` holds the Rust and rego sets equal.

- **Covers** `DeleteObject` with any `versionId`, `"null"` included, and each `DeleteObjects`
  entry carrying one. An entry with no `versionId` stays on `delete_objects`.
- **Is independent.** A grant of `delete_object_versions` does not imply `delete_objects`, and the
  reverse does not hold (AWS parity). A principal that may only add delete markers cannot destroy
  history; one that may destroy a version may not thereby create markers.
- **Does not cover** `Put/DeleteObjectTagging` with a `versionId` (tags on a version destroy no
  data, and s0 never reads object tags, ADR-003), nor `Get/HeadObject`, `GetObjectAttributes`,
  `GetObjectTagging` and copy sources naming a version. Those stay blind spots of `read_objects`
  and `write_object_tags`.

The table records it as `OpSpec.versioned: Option<VersionedPath { verb, tier }>`, set on
`DeleteObject` and `DeleteObjects` to `{ delete_object_versions, PostureAltering }`: "what is
retained or deleted" is posture. The unversioned path keeps `Mutating`.

### D4 — a batch is decided per entry, and recorded under the stronger verb

`DeleteObjects` decides each entry under its own verb. The filter that drops refused entries is
**index-based**: a batch may name the same key twice, once with a version and once without, under
different verbs, and a filter keyed on the key would forward both or neither.

The batch's audit record carries `input.action = delete_object_versions` when any entry carries a
version, else `delete_objects`, and `gateway.versions` lists the `(key, version_id)` pairs of the
batch (omitted when empty); `gateway.denied_versions` lists the versioned entries policy refused
and stripped, so a key named twice is still readable. A single `DeleteObject` naming a version
records its one pair in `gateway.versions`. Both are audit only and never a policy input. A batch whose
every entry is refused is `AccessDenied`, as before.

`x-amz-bypass-governance-retention` remains refused in code on both paths (ADR-008): the new verb
is not a way around the retention screen, whatever the grant.

### D5 — wildcard grants gain the verb

`"*"` in a grant's `actions` matches every verb, so it now confers `delete_object_versions`. This
is the one behaviour change a wildcard grant sees. The platform's own projection emits no action
wildcard.

## Rollout

| Change | Effect on a client | When it is safe |
|---|---|---|
| `delete_object_versions` added | A client that sends `versionId` (boto3 `object_versions.delete()`, `mc rm --versions`, rclone `--s3-versions`) is refused with only `delete_objects` granted | Before any bucket is versioned; the platform ships the projection of the verb in the same release line |
| `ListObjectVersions` enforced | A principal holding `list_objects` on a single prefix or a whole bucket can list versions; one holding several prefixes is refused | Immediately |

A control plane that does not yet project the verb loses nothing it had: no versioned delete
worked before, since no bucket was versioned.

## Consequences

- Seven grant verbs. `GATEWAY_VERBS`, `Action::ALL`, the rego's documented vocabulary, ADR-006's
  table and the platform's projection move together; `the_gateway_vocabulary_and_the_action_enum_agree`
  and `op_coverage.rs` fail otherwise.
- Twenty-four enforced operations, seventy-five not enforced.
- Tagging and reads that name a `version_id` remain blind spots, stated in the table.
- Versioned multi-prefix listings stay refused until a cursor for them is designed.

## Alternatives considered

**A1 — keep versioned deletes under `delete_objects`.** Rejected: it is the escalation described
in the context, and the one AWS closed with a separate action.

**A2 — fan out a multi-prefix version listing.** Rejected for now: the merge would need a
resume rule over `(key, version_id)` pairs, newest first within a key, across prefixes. Refusing
is fail-closed and costs only the multi-prefix subject a listing it did not have before.

**A3 — filter only, without narrowing the request.** Rejected on ADR-004's grounds: it scans the
bucket to find the grant.
