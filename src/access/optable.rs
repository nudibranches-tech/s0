//! `OP_TABLE` — one entry per s3s operation, and the single source of truth for what the
//! gateway lets through.
//!
//! A table rather than a string allowlist because all 99 typed `S3Access` hooks default to
//! `Ok(())`: an op that reaches its hook without an override is *allowed*, and only the
//! deny-by-default backstop in `check` stands between that and the backend. The table
//! records whether a hook and a dispatch arm really exist; `tests/op_coverage.rs` and
//! `tests/gate_invariants.rs` hold it to the source. Flipping an entry to
//! [`Coverage::Enforced`] must land with its hook and arm or the tests fail — but no test
//! can check that a [`DangerTier`] is right, so treat such a diff as a security review.

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
    /// Changes *who can reach what*, what is retained or deleted, or writes data off the
    /// gateway's request path — ACLs and policy, public-access block, encryption, object
    /// lock, versioning, replication, logging, and tag writes (which can drive ABAC
    /// grants). Default-deny in policy even once enforced.
    PostureAltering,
    /// Structurally unauthorizable — see [`unauthorizable`]. Refused in code, ahead of
    /// and independently of [`Coverage`], so no pushed policy and no table edit alone
    /// can enable it.
    NeverImplement,
}

/// The grant vocabulary the gateway can actually decide against: the six verbs a control
/// plane's grant projection emits.
///
/// Held as strings rather than [`Action`] because the table classifies *denied* ops too;
/// `the_gateway_vocabulary_and_the_action_enum_agree` holds the two sets equal, so the
/// string form cannot drift into fiction.
pub const GATEWAY_VERBS: &[&str] = &[
    "read_objects",
    "list_objects",
    "write_objects",
    "delete_objects",
    "write_object_tags",
    "read",
];

/// Classification labels for denied operations whose authority is **not** the gateway's
/// to broker: acting on a bucket as a *managed resource* — its existence, its policy, its
/// CORS — bypasses the control plane that owns it, and conferring an object ACL is refused
/// in code ([`crate::access::headers`]).
///
/// They are the table's classification column and nothing else. Three tests hold that:
/// this set is disjoint from [`GATEWAY_VERBS`], no `Enforced` entry may name one, and
/// [`action_for`] returns `None` for each — so flipping such an op to `Enforced` fails the
/// suite rather than quietly compiling.
pub const NON_GATEWAY_VERBS: &[&str] = &[
    "create_bucket",
    "delete_bucket",
    "read_bucket_config",
    "write_bucket_config",
    "write_object_acl",
];

/// One operation's security classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpSpec {
    /// The exact s3s operation name (`S3Operation::name()`), which is what `check`
    /// matches on and what rides in the audit record.
    pub name: &'static str,
    pub coverage: Coverage,
    /// The verb the decision is (or would be) made against. `None` only for
    /// [`DangerTier::NeverImplement`]. Copy-shaped ops name their *destination* verb; the
    /// source read is a separate sub-decision.
    ///
    /// An `Enforced` entry always names one of [`GATEWAY_VERBS`], because a hook cannot
    /// build an `OpaInput` for a verb no [`Action`] expresses. A `Denied` entry may
    /// instead name a control-plane label from [`NON_GATEWAY_VERBS`].
    pub verb: Option<&'static str>,
    pub shape: ResourceShape,
    pub tier: DangerTier,
    /// What an enforced op's hook does **not** inspect: the parts of the request that ride
    /// along unauthorized once bucket+key have been allowed. Empty for denied ops.
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

/// An operation denied **in code**, not by policy: `check` refuses
/// [`DangerTier::NeverImplement`] ahead of [`Coverage`], and this is the only constructor
/// that produces that tier. Two operations qualify, both structurally:
///
/// - **`CreateSession`** returns `SessionCredentials` the client then uses *directly
///   against the backend* — a permanent, total bypass of the gateway.
/// - **`WriteGetObjectResponse`** carries neither bucket nor key: nothing to decide
///   against, so any decision would be a fiction.
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
            "under the default `x-amz-tagging-directive: COPY` the destination inherits \
             the SOURCE object's tags, which the gateway does not read — so a tag the \
             policy conditions on can be moved onto a new key without a write_object_tags \
             decision. Only a REPLACE directive (or an explicit x-amz-tagging) is \
             authorized as a tag write",
            "object-lock headers (mode, retain-until-date, legal-hold) are not inspected: \
             a write grant can make the new object undeletable",
        ],
    ),
    // A bucket created through the gateway is unmanaged and absent from
    // `bucket_attributes`, so the per-bucket denylist the policy reads has nothing to key
    // on. Bucket existence is control-plane. Compatibility cost: rclone issues CreateBucket
    // before every upload and aborts on a refusal, so it needs `--s3-no-check-bucket`.
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
            "object-lock headers (mode, retain-until-date, legal-hold) are not inspected: \
             a write grant can make the completed object undeletable",
        ],
    ),
    unauthorizable("CreateSession", ResourceShape::Bucket),
    // The more dangerous half of the pair: it destroys a bucket the control plane still
    // believes it manages.
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
        &["version_id (a versioned delete is not distinguished from a delete marker)"],
    ),
    enforced(
        "DeleteObjectTagging",
        "write_object_tags",
        ResourceShape::Object,
        DangerTier::PostureAltering,
        &[
            "version_id (tags are removed from whichever version the id names)",
            "the tags being removed are not read first, so a policy cannot condition on \
             what is being cleared",
        ],
    ),
    enforced(
        "DeleteObjects",
        "delete_objects",
        ResourceShape::ObjectBatch,
        DangerTier::Mutating,
        &["per-key version_id"],
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
    enforced(
        // The existence verb, not a configuration one: every S3 client probes this on
        // connect, so charging it to anything else would make ordinary use require a
        // grant nobody would know to give. Same verb as HeadBucket and ListBuckets.
        "GetBucketLocation",
        "read",
        ResourceShape::Bucket,
        DangerTier::Routine,
        &["the response names the backend region, which is not tenant-specific"],
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
    enforced(
        "GetObjectAttributes",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
        &[
            "ObjectParts reveals the multipart structure (part count, sizes, checksums) \
             to any read-granted principal; the requested attribute list is not \
             authorized separately — noted, not solved",
            "version_id (an old version's attributes read under the current key's grant)",
        ],
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
    enforced(
        // `read_objects`, not a tag-specific verb: reading an object's tags is strictly
        // less than reading the object itself. The WRITE direction is deliberately NOT
        // merged — see `Action::WriteObjectTags`.
        "GetObjectTagging",
        "read_objects",
        ResourceShape::Object,
        DangerTier::Routine,
        &["version_id"],
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
    enforced(
        "HeadBucket",
        "read",
        ResourceShape::Bucket,
        DangerTier::Routine,
        &[
            "a HEAD response carries no body, so a denial is a bare 403: the client \
             cannot distinguish 'no such bucket' from 'not yours'. That is the safe \
             direction, and it is also why the deny reason only reaches the audit record",
        ],
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
    enforced(
        // Same verb as HeadBucket, in the account shape (`input.bucket == ""`):
        // enumerate-vs-exists was two verbs for one question, and a principal whose
        // `aws s3 ls` came back empty while its next `head-bucket` succeeded is exactly
        // the two-answers-to-one-question defect that merge removes.
        "ListBuckets",
        "read",
        ResourceShape::Account,
        DangerTier::Routine,
        &[
            "the merged listing is GATEWAY-ordered, not backend-ordered: the response is \
             sorted by name gateway-side and paginated with a gateway-owned cursor, \
             because RGW promises no stable order across ListBuckets pages",
            "one request drains the tenant's entire bucket list from the backend, bounded \
             by limits.max_bucket_list_pages; a tenant over that bound is refused rather \
             than under-reported",
            "the Owner element is withheld wholesale rather than mapped to the caller — \
             the backend reports the shared tenant-owner identity, which is not the \
             requester's",
            "creation_date and bucket_region ride through as the backend reported them",
            "bucket_patterns is NOT implemented: a policy emitting it denies (there is no \
             settled pattern grammar, and an unvalidated glob in a visibility allowlist \
             widens rather than narrows)",
        ],
    ),
    denied(
        "ListDirectoryBuckets",
        "read",
        ResourceShape::Account,
        DangerTier::Routine,
    ),
    enforced(
        "ListMultipartUploads",
        "list_objects",
        ResourceShape::Listing,
        DangerTier::Routine,
        &[
            "the request prefix is narrowed and the response is re-filtered against it, but \
             a multi-prefix grant still fails closed rather than fanning out",
            "the upload id and initiation time of an in-scope upload are forwarded; only \
             owner/initiator (the shared tenant-owner identity) are stripped",
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
        &[
            "the upload id is not bound to the principal that created it",
            "part sizes, ETags and checksums are forwarded — they describe the object the \
             caller already holds read on; only owner/initiator (the shared tenant-owner \
             identity) are stripped",
        ],
    ),
    enforced(
        "PostObject",
        "write_objects",
        ResourceShape::Object,
        DangerTier::Mutating,
        &[
            "the file is aggregated into memory by s3s BEFORE check runs, so \
             limits.post_object_max_file_size — not the decision — is what bounds an \
             unauthorized allocation",
            "success_action_redirect is forwarded as given",
            "object-lock form fields are not inspected",
        ],
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
    // CORS decides which browser origins may reach a bucket's data — posture, not data —
    // and the gateway never inspected the rules it forwarded, so a write-config grant
    // permitted `AllowedOrigin: *`. Bucket configuration is control-plane.
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
    // A bucket policy is a SECOND, backend-side PDP that this gateway does not evaluate,
    // so an Allow statement written through here widens access to a principal no grant
    // named — a bypass of the managed access model, whatever verb guarded the write.
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
            "object-lock headers (mode, retain-until-date, legal-hold) are not inspected: \
             a write grant can make an object undeletable. Note the asymmetry — the \
             opposite direction, destroying a retained object, is refused in code",
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
    enforced(
        "PutObjectTagging",
        "write_object_tags",
        ResourceShape::Object,
        DangerTier::PostureAltering,
        &[
            "the reserved-key guard is only as good as the list the control plane \
             publishes: a key a policy conditions on but which is absent from \
             org_settings.reserved_tag_keys is writable by anyone holding \
             write_object_tags. (An absent list denies every tag write, so the failure \
             mode is a list that is present and incomplete, not a missing one.) \
             A control plane is expected to DERIVE the list from the grants it \
             publishes — the union of its own namespace and every `tag:<key>` a grant in \
             the same document conditions on — so a key a projected GRANT conditions on \
             cannot be omitted. What remains is a key some policy reads from outside the \
             grant projection.",
            "version_id",
        ],
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
/// derived.
///
/// Factored out of `S3Access::check` so the full 99-op matrix is testable:
/// `S3AccessContext` cannot be constructed outside s3s, so a table-driven test cannot go
/// through `check` itself. `tests/gate_blackbox.rs` covers a sample over real HTTP.
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

/// The typed verb for a table entry, or `None` when the entry names one [`Action`] cannot
/// express: the structurally unauthorizable ops and the ones labelled with a
/// [`NON_GATEWAY_VERBS`] control-plane authority.
///
/// A hook cannot build an `OpaInput` for a verb with no `Action`, so this is what keeps an
/// `Enforced` flip honest.
#[must_use]
pub fn action_for(spec: &OpSpec) -> Option<Action> {
    let verb = spec.verb?;
    Action::ALL.iter().copied().find(|a| a.as_str() == verb)
}

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
    fn the_gateway_vocabulary_and_the_action_enum_agree() {
        // Two spellings of one vocabulary: the table's string column and the typed verb a
        // hook decides against. If they could differ, an op could be flipped to Enforced
        // naming a verb no `Action` expresses — a hook that cannot be written.
        let mut typed: Vec<&str> = Action::ALL.iter().map(|a| a.as_str()).collect();
        let mut gateway: Vec<&str> = GATEWAY_VERBS.to_vec();
        typed.sort_unstable();
        gateway.sort_unstable();
        assert_eq!(typed, gateway);
        assert_eq!(
            gateway.len(),
            6,
            "the projected vocabulary is six verbs (settled 2026-08-08)"
        );
    }

    #[test]
    fn a_removed_verb_cannot_be_grantable_and_a_classification_label_at_once() {
        // The two sets separate "a grant can carry this" from "this is a label on a row
        // nothing reaches". An overlap would mean a control-plane authority had quietly
        // re-entered the grant vocabulary, so it is a hard failure, not a lint.
        for verb in NON_GATEWAY_VERBS {
            assert!(
                !GATEWAY_VERBS.contains(verb),
                "{verb} is both a grantable gateway verb and a control-plane label"
            );
            assert!(
                Action::ALL.iter().all(|a| a.as_str() != *verb),
                "{verb} was removed from the vocabulary but `Action` still expresses it"
            );
        }
        // …and each label still classifies at least one row: a label nothing uses is a
        // claim the table has stopped making.
        for verb in NON_GATEWAY_VERBS {
            assert!(
                OP_TABLE.iter().any(|s| s.verb == Some(verb)),
                "NON_GATEWAY_VERBS names {verb}, which no OP_TABLE row uses — delete it"
            );
        }
    }

    #[test]
    fn no_control_plane_operation_is_enforced() {
        // Stated where a reviewer editing this table will trip over it: the gateway is
        // DATA-PLANE ONLY. Making or unmaking a bucket, and writing its policy or CORS,
        // go through the control plane so that every bucket stays managed.
        for s in OP_TABLE {
            if let Some(v) = s.verb
                && NON_GATEWAY_VERBS.contains(&v)
            {
                assert_eq!(
                    s.coverage,
                    Coverage::Denied,
                    "{} is Enforced under the control-plane label {v}; the gateway does \
                     not broker that authority and there is no grant that carries it",
                    s.name
                );
                assert!(
                    action_for(s).is_none(),
                    "{} names {v}, which `Action` must not be able to express",
                    s.name
                );
            }
        }
    }

    #[test]
    fn the_six_ops_re_denied_on_2026_08_08_are_refused_at_the_gate() {
        // Named one by one rather than counted: a future edit could flip one back on and
        // rebalance the total by denying something else, and a count would still pass.
        for op in [
            "CreateBucket",
            "DeleteBucket",
            "GetBucketPolicy",
            "PutBucketPolicy",
            "GetBucketCors",
            "PutBucketCors",
        ] {
            assert_eq!(
                gate_op(op),
                Err(GateDenial::NotEnforced),
                "{op} must be refused before deserialization"
            );
            assert!(
                spec(op).unwrap().blind_spots.is_empty(),
                "{op} is denied but still claims blind spots"
            );
        }
    }

    #[test]
    fn bucket_existence_is_one_verb_in_both_request_shapes() {
        // Two PEPs answering one question differently is the defect being guarded here:
        // HeadBucket and ListBuckets asking about existence under two different verbs, so
        // a principal's `aws s3 ls` came back empty while its `head-bucket` succeeded.
        for op in ["HeadBucket", "GetBucketLocation", "ListBuckets"] {
            assert_eq!(spec(op).unwrap().verb, Some("read"), "{op}");
            assert_eq!(action_for(spec(op).unwrap()), Some(Action::Read), "{op}");
        }
        // …and the two shapes really are different, which is why the rego needs a gate
        // on each rule that reads the verb.
        assert_eq!(spec("HeadBucket").unwrap().shape, ResourceShape::Bucket);
        assert_eq!(spec("ListBuckets").unwrap().shape, ResourceShape::Account);
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
