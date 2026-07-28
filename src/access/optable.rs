//! `OP_TABLE` — the operation table. One entry per s3s operation, and the single
//! source of truth for what the gateway will let through.
//!
//! Why a table and not a `&[&str]` allowlist: **all 99 typed `S3Access` hooks default
//! to `Ok(())`**, so an operation that reaches its hook without an override is
//! *allowed*. The only thing standing between that default and the backend is the
//! deny-by-default backstop in `check`, and a bare string list gives a reviewer no way
//! to see whether a listed op actually has a hook, a dispatch arm, or a sane verb.
//! The table carries that classification explicitly, `check` reads it, and
//! `tests/op_coverage.rs` / `tests/gate_invariants.rs` hold it to the source.
//!
//! Adding an op is therefore a reviewed [`Coverage::Denied`] → [`Coverage::Enforced`]
//! diff that must land together with its hook and its dispatch arm, or the tests fail.
//! The compile- and test-time checks prove well-formedness and that the claimed hook
//! and dispatch arm exist; they cannot prove a [`DangerTier`] is right. Treat the diff
//! as the security-review artifact.

use crate::model::Action;

/// Whether the gateway authorizes an operation, or refuses it at the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    /// A typed `S3Access` hook authorizes the *parsed* request and a `GatewayS3` arm
    /// forwards it. Both must exist — `tests/gate_invariants.rs` probes for them.
    Enforced,
    /// `check` refuses it before deserialization. There is no dispatch arm, so even a
    /// bug in `check` leaves the s3s `NotImplemented` default in the way.
    Denied,
}

/// What the operation's input actually names — i.e. what there is to authorize.
/// Chosen so that "which enforce helper does this need?" is answerable from the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceShape {
    /// No bucket: scoped to the whole account/tenant (`ListBuckets`).
    Account,
    /// A bucket, and nothing finer.
    Bucket,
    /// A bucket plus a named sub-resource (`?id=`), e.g. an inventory configuration.
    /// The id is a second dimension the current `OpaInput` cannot express.
    BucketSubresource,
    /// A bucket and one object key.
    Object,
    /// A bucket and a list of object keys carried in the body — one sub-decision per
    /// key, or the body is a blind spot.
    ObjectBatch,
    /// A bucket and a prefix/marker: the response, not just the request, is in scope.
    Listing,
    /// A destination bucket+key *and* a source bucket+key — two sub-decisions.
    Copy,
    /// Nothing addressable at all. There is no resource to authorize.
    Unaddressable,
}

/// How much damage the operation can do if it is authorized wrongly. Drives review
/// attention, not runtime behaviour — except for [`DangerTier::NeverImplement`],
/// which `check` refuses outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DangerTier {
    /// Reads and lists. Exposure is bounded by what the policy granted.
    Routine,
    /// Changes object data, or a bucket's existence or benign configuration. Subject
    /// to the org-global `freeze_writes` kill switch.
    Mutating,
    /// Changes *who can reach what*, what is retained or deleted, or writes data to a
    /// caller-chosen destination off the gateway's request path — bucket/object ACLs
    /// and policy, public-access block, ownership controls, encryption, object lock,
    /// versioning, lifecycle, replication, logging, notification, inventory/analytics,
    /// and tag writes (which can drive ABAC grants). Default-deny in policy even once
    /// enforced.
    PostureAltering,
    /// Structurally unauthorizable — see [`unauthorizable`]. Refused in code, ahead of
    /// and independently of [`Coverage`], so no pushed policy and no table edit alone
    /// can enable it.
    NeverImplement,
}

/// The 13-verb grant vocabulary frozen in the master plan (§1.2).
///
/// Held as strings rather than [`Action`] on purpose: `Action` still carries the
/// original 5 verbs, and giving a *denied* op a typed verb it can never be decided
/// against would be unverifiable fiction. `S2-verbs` widens `Action` to these 13 and
/// this becomes a typed field; until then `op_table_verbs_are_from_the_frozen_set`
/// and `enforced_verbs_exist_in_todays_action_vocabulary` keep the two honest.
pub const FROZEN_VERBS: &[&str] = &[
    "read_objects",
    "list_objects",
    "write_objects",
    "delete_objects",
    "read_object_tags",
    "write_object_tags",
    "write_object_acl",
    "list_buckets",
    "read_bucket",
    "create_bucket",
    "delete_bucket",
    "read_bucket_config",
    "write_bucket_config",
];

/// One operation's security classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpSpec {
    /// The exact s3s operation name (`S3Operation::name()`), which is what `check`
    /// matches on and what rides in the audit record.
    pub name: &'static str,
    pub coverage: Coverage,
    /// The grant verb the decision is made against, from [`FROZEN_VERBS`]. `None`
    /// only for [`DangerTier::NeverImplement`]: those have no verb because they are
    /// never decided. Copy-shaped ops name their *destination* verb; the source read
    /// is a separate sub-decision.
    pub verb: Option<&'static str>,
    pub shape: ResourceShape,
    pub tier: DangerTier,
    /// What an enforced op's hook does **not** inspect. This is the honest half of the
    /// table: the gateway allows the request on the strength of bucket+key, and these
    /// are the parts of the request that ride along unauthorized. Empty for denied ops
    /// — a blind spot on an op nothing reaches is meaningless.
    pub blind_spots: &'static [&'static str],
}

/// An operation with a typed hook and a dispatch arm.
const fn enforced(
    name: &'static str,
    verb: &'static str,
    shape: ResourceShape,
    tier: DangerTier,
    blind_spots: &'static [&'static str],
) -> OpSpec {
    OpSpec {
        name,
        coverage: Coverage::Enforced,
        verb: Some(verb),
        shape,
        tier,
        blind_spots,
    }
}

/// An operation `check` refuses today. The verb and shape are the classification the
/// reviewer of a future `Denied → Enforced` flip starts from.
const fn denied(
    name: &'static str,
    verb: &'static str,
    shape: ResourceShape,
    tier: DangerTier,
) -> OpSpec {
    OpSpec {
        name,
        coverage: Coverage::Denied,
        verb: Some(verb),
        shape,
        tier,
        blind_spots: &[],
    }
}

/// An operation that is denied **in code**, not by policy, and that no table edit can
/// enable on its own — `check` refuses [`DangerTier::NeverImplement`] before it looks
/// at [`Coverage`]. This constructor is the only one that produces that tier and it
/// always produces [`Coverage::Denied`], so "hard-denied but enforced" is not a state
/// this table can be edited into by accident.
///
/// Exactly two operations qualify, both for structural reasons rather than product
/// ones:
///
/// - **`CreateSession`** returns `SessionCredentials` that the client then uses
///   *directly against the backend*. Authorizing it once would hand out a permanent,
///   total bypass of the gateway — every later request would never be seen here.
/// - **`WriteGetObjectResponse`** carries neither a bucket nor a key. There is no
///   resource to decide against, so any decision would be a fiction.
const fn unauthorizable(name: &'static str, shape: ResourceShape) -> OpSpec {
    OpSpec {
        name,
        coverage: Coverage::Denied,
        verb: None,
        shape,
        tier: DangerTier::NeverImplement,
        blind_spots: &[],
    }
}

/// Every operation `s3s` 0.14.1 can route, sorted by name (`spec` binary-searches it,
/// and `op_table_is_sorted_and_unique` holds the ordering).
///
/// Regenerate the reference list with:
/// ```text
/// grep -A1 "fn name(&self) -> &'static str {" \
///     ~/.cargo/registry/src/*/s3s-0.14.1/src/ops/generated.rs \
///   | grep -o '"[A-Za-z0-9]*"' | tr -d '"' | sort > tests/data/s3s-0.14.1-ops.txt
/// ```
pub const OP_TABLE: &[OpSpec] = &[
    enforced(
        "AbortMultipartUpload",
        "write_objects",
        ResourceShape::Object,
        DangerTier::Mutating,
        &["the upload id is not bound to the principal that created it"],
    ),
    enforced(
        "CompleteMultipartUpload",
        "write_objects",
        ResourceShape::Object,
        DangerTier::Mutating,
        &["the part list is not re-authorized against the parts actually uploaded"],
    ),
    enforced(
        "CopyObject",
        "write_objects",
        ResourceShape::Copy,
        DangerTier::Mutating,
        &[
            "x-amz-acl / x-amz-grant-* headers",
            "x-amz-tagging + x-amz-tagging-directive",
            "object-lock headers",
        ],
    ),
    denied(
        "CreateBucket",
        "create_bucket",
        ResourceShape::Bucket,
        DangerTier::Mutating,
    ),
    denied(
        "CreateBucketMetadataTableConfiguration",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    enforced(
        "CreateMultipartUpload",
        "write_objects",
        ResourceShape::Object,
        DangerTier::Mutating,
        &[
            "x-amz-acl / x-amz-grant-* headers",
            "x-amz-tagging",
            "object-lock headers",
        ],
    ),
    unauthorizable("CreateSession", ResourceShape::Bucket),
    denied(
        "DeleteBucket",
        "delete_bucket",
        ResourceShape::Bucket,
        DangerTier::Mutating,
    ),
    denied(
        "DeleteBucketAnalyticsConfiguration",
        "write_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::PostureAltering,
    ),
    denied(
        "DeleteBucketCors",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "DeleteBucketEncryption",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "DeleteBucketIntelligentTieringConfiguration",
        "write_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::Mutating,
    ),
    denied(
        "DeleteBucketInventoryConfiguration",
        "write_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::PostureAltering,
    ),
    denied(
        "DeleteBucketLifecycle",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "DeleteBucketMetadataTableConfiguration",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "DeleteBucketMetricsConfiguration",
        "write_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::Mutating,
    ),
    denied(
        "DeleteBucketOwnershipControls",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "DeleteBucketPolicy",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "DeleteBucketReplication",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "DeleteBucketTagging",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Mutating,
    ),
    denied(
        "DeleteBucketWebsite",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    enforced(
        "DeleteObject",
        "delete_objects",
        ResourceShape::Object,
        DangerTier::Mutating,
        &[
            "version_id (a versioned delete is not distinguished from a delete marker)",
            "x-amz-bypass-governance-retention",
        ],
    ),
    denied(
        "DeleteObjectTagging",
        "write_object_tags",
        ResourceShape::Object,
        DangerTier::PostureAltering,
    ),
    enforced(
        "DeleteObjects",
        "delete_objects",
        ResourceShape::ObjectBatch,
        DangerTier::Mutating,
        &["per-key version_id", "x-amz-bypass-governance-retention"],
    ),
    denied(
        "DeletePublicAccessBlock",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "GetBucketAccelerateConfiguration",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketAcl",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketAnalyticsConfiguration",
        "read_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketCors",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketEncryption",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketIntelligentTieringConfiguration",
        "read_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketInventoryConfiguration",
        "read_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketLifecycleConfiguration",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketLocation",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketLogging",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketMetadataTableConfiguration",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketMetricsConfiguration",
        "read_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketNotificationConfiguration",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketOwnershipControls",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketPolicy",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketPolicyStatus",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketReplication",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketRequestPayment",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketTagging",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketVersioning",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetBucketWebsite",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    enforced(
        "GetObject",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
        &["version_id (an old version reads under the current key's grant)"],
    ),
    denied(
        "GetObjectAcl",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
    ),
    denied(
        "GetObjectAttributes",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
    ),
    denied(
        "GetObjectLegalHold",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
    ),
    denied(
        "GetObjectLockConfiguration",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "GetObjectRetention",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
    ),
    denied(
        "GetObjectTagging",
        "read_object_tags",
        ResourceShape::Object,
        DangerTier::Routine,
    ),
    denied(
        "GetObjectTorrent",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
    ),
    denied(
        "GetPublicAccessBlock",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "HeadBucket",
        "read_bucket",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    enforced(
        "HeadObject",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
        &["version_id"],
    ),
    denied(
        "ListBucketAnalyticsConfigurations",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "ListBucketIntelligentTieringConfigurations",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "ListBucketInventoryConfigurations",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "ListBucketMetricsConfigurations",
        "read_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Routine,
    ),
    denied(
        "ListBuckets",
        "list_buckets",
        ResourceShape::Account,
        DangerTier::Routine,
    ),
    denied(
        "ListDirectoryBuckets",
        "list_buckets",
        ResourceShape::Account,
        DangerTier::Routine,
    ),
    enforced(
        "ListMultipartUploads",
        "list_objects",
        ResourceShape::Listing,
        DangerTier::Routine,
        &[
            "the response is not filtered; only the request prefix is narrowed, and a multi-prefix grant fails closed",
        ],
    ),
    denied(
        "ListObjectVersions",
        "list_objects",
        ResourceShape::Listing,
        DangerTier::Routine,
    ),
    enforced(
        "ListObjects",
        "list_objects",
        ResourceShape::Listing,
        DangerTier::Routine,
        &[
            "the response is not filtered; only the request prefix is narrowed, and a multi-prefix grant fails closed",
        ],
    ),
    enforced(
        "ListObjectsV2",
        "list_objects",
        ResourceShape::Listing,
        DangerTier::Routine,
        &[
            "the response is not filtered; the request prefix is narrowed or fanned out instead",
            "delimiter listing across several granted prefixes is refused, not merged",
        ],
    ),
    enforced(
        "ListParts",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
        &["the upload id is not bound to the principal that created it"],
    ),
    denied(
        "PostObject",
        "write_objects",
        ResourceShape::Object,
        DangerTier::Mutating,
    ),
    denied(
        "PutBucketAccelerateConfiguration",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Mutating,
    ),
    denied(
        "PutBucketAcl",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketAnalyticsConfiguration",
        "write_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketCors",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketEncryption",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketIntelligentTieringConfiguration",
        "write_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::Mutating,
    ),
    denied(
        "PutBucketInventoryConfiguration",
        "write_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketLifecycleConfiguration",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketLogging",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketMetricsConfiguration",
        "write_bucket_config",
        ResourceShape::BucketSubresource,
        DangerTier::Mutating,
    ),
    denied(
        "PutBucketNotificationConfiguration",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketOwnershipControls",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketPolicy",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketReplication",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketRequestPayment",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Mutating,
    ),
    denied(
        "PutBucketTagging",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::Mutating,
    ),
    denied(
        "PutBucketVersioning",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutBucketWebsite",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    enforced(
        "PutObject",
        "write_objects",
        ResourceShape::Object,
        DangerTier::Mutating,
        &[
            "x-amz-acl / x-amz-grant-* headers",
            "x-amz-tagging",
            "object-lock headers",
        ],
    ),
    denied(
        "PutObjectAcl",
        "write_object_acl",
        ResourceShape::Object,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutObjectLegalHold",
        "write_objects",
        ResourceShape::Object,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutObjectLockConfiguration",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutObjectRetention",
        "write_objects",
        ResourceShape::Object,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutObjectTagging",
        "write_object_tags",
        ResourceShape::Object,
        DangerTier::PostureAltering,
    ),
    denied(
        "PutPublicAccessBlock",
        "write_bucket_config",
        ResourceShape::Bucket,
        DangerTier::PostureAltering,
    ),
    denied(
        "RestoreObject",
        "write_objects",
        ResourceShape::Object,
        DangerTier::PostureAltering,
    ),
    denied(
        "SelectObjectContent",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
    ),
    enforced(
        "UploadPart",
        "write_objects",
        ResourceShape::Object,
        DangerTier::Mutating,
        &["the upload id is not bound to the principal that created it"],
    ),
    enforced(
        "UploadPartCopy",
        "write_objects",
        ResourceShape::Copy,
        DangerTier::Mutating,
        &[
            "the upload id is not bound to the principal that created it",
            "copy-source range and version id",
        ],
    ),
    unauthorizable("WriteGetObjectResponse", ResourceShape::Unaddressable),
];

/// Why the deny-by-default backstop refused an operation. Separate variants because
/// they are separate facts: an unknown op means s3s and this table disagree (a
/// dependency bump), while a not-enforced op is the ordinary, expected refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDenial {
    /// s3s routed an operation `OP_TABLE` does not know. Fails closed, and is a bug:
    /// `op_table_covers_every_s3s_operation` exists so a s3s bump surfaces at build
    /// time rather than as a request-time surprise.
    Unknown,
    /// Structurally unauthorizable ([`DangerTier::NeverImplement`]).
    Unauthorizable,
    /// In the table, but nothing enforces it yet.
    NotEnforced,
}

impl GateDenial {
    /// Short, non-leaking reason for the client-facing `AccessDenied` and the log.
    pub const fn as_str(self) -> &'static str {
        match self {
            GateDenial::Unknown => "unknown operation",
            GateDenial::Unauthorizable => "operation cannot be authorized by the gateway",
            GateDenial::NotEnforced => "operation is not permitted by the gateway",
        }
    }
}

/// The table entry for an s3s operation name, or `None` if there is none.
#[must_use]
pub fn spec(op: &str) -> Option<&'static OpSpec> {
    OP_TABLE
        .binary_search_by(|s| s.name.cmp(op))
        .ok()
        .map(|i| &OP_TABLE[i])
}

/// The op half of the deny-by-default backstop, and the *only* place the allowlist is
/// derived — there is no second list to drift from this one.
///
/// Factored out of `S3Access::check` so the full 99-op matrix is testable:
/// `s3s::access::S3AccessContext` has crate-private fields and cannot be constructed
/// outside s3s, so a table-driven test cannot go through `check` itself.
/// `tests/gate_blackbox.rs` closes that gap over real HTTP for a sample.
pub fn gate_op(op: &str) -> Result<&'static OpSpec, GateDenial> {
    let Some(spec) = spec(op) else {
        return Err(GateDenial::Unknown);
    };
    // Checked BEFORE `coverage`, and independently of it: these must stay impossible
    // to reach whatever a pushed policy says and whatever a future table edit does.
    if matches!(spec.tier, DangerTier::NeverImplement) {
        return Err(GateDenial::Unauthorizable);
    }
    if !matches!(spec.coverage, Coverage::Enforced) {
        return Err(GateDenial::NotEnforced);
    }
    Ok(spec)
}

/// The generated allowlist: every operation with a hook and a dispatch arm.
#[must_use]
pub fn enforced_ops() -> Vec<&'static str> {
    OP_TABLE
        .iter()
        .filter(|s| s.coverage == Coverage::Enforced)
        .map(|s| s.name)
        .collect()
}

/// The verbs today's [`Action`] can actually express. Used by the coverage test to
/// keep the table's `verb` column decidable for every enforced op; `S2-verbs` widens
/// this to all of [`FROZEN_VERBS`].
pub const TODAYS_ACTIONS: &[Action] = &[
    Action::ReadObjects,
    Action::ListObjects,
    Action::WriteObjects,
    Action::DeleteObjects,
    Action::ManageLifecycle,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_table_is_sorted_and_unique() {
        // `spec` binary-searches, so this is a correctness precondition, not tidiness.
        for w in OP_TABLE.windows(2) {
            assert!(
                w[0].name < w[1].name,
                "OP_TABLE is not sorted/unique at {} / {}",
                w[0].name,
                w[1].name
            );
        }
    }

    #[test]
    fn spec_finds_every_entry() {
        for s in OP_TABLE {
            assert_eq!(spec(s.name).map(|f| f.name), Some(s.name));
        }
        assert!(spec("NoSuchOperation").is_none());
    }

    #[test]
    fn hard_denied_ops_are_refused_ahead_of_coverage() {
        // The two structural denials. If someone flips one to `Enforced`, `gate_op`
        // still refuses it — the tier is checked first — and this test says so.
        for op in ["CreateSession", "WriteGetObjectResponse"] {
            assert_eq!(gate_op(op), Err(GateDenial::Unauthorizable), "{op}");
            assert_eq!(spec(op).unwrap().tier, DangerTier::NeverImplement);
            assert!(spec(op).unwrap().verb.is_none());
        }
    }

    #[test]
    fn an_operation_outside_the_table_fails_closed() {
        assert_eq!(gate_op("PutSomethingNewInS3s"), Err(GateDenial::Unknown));
    }
}
