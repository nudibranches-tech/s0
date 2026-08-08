//! Core domain vocabulary shared across the gateway.
//!
//! Domain shape: `Organization → Tenant (= one Ceph tenant) → Bucket`.
//! A tenant *slug* is the Ceph tenant. Object keys nest under a bucket.

use serde::{Deserialize, Serialize};

/// The grant vocabulary the gateway authorizes against — the **six projected verbs**.
///
/// Deliberately coarser than the 99 S3 ops: every enforced S3 op maps onto exactly one
/// of these (a `PutObject` to `write_objects`, a `HeadBucket` to `read`), and
/// `CopyObject` maps to two (source read + dest write). The set is not a local choice:
/// it is exactly what hyperfluid's grant projection emits
/// (`s3_gateway_projection::verbs`), so adding a verb is a cross-repo contract change.
/// `tests/cross_repo_contract.rs::the_gateway_vocabulary_is_what_hyperfluid_projects`
/// holds the two sides equal against the real checkout.
///
/// ## THE GATEWAY IS DATA-PLANE ONLY (settled 2026-08-08)
///
/// Seven verbs were **removed** on 2026-08-08, and the reason is one sentence: each was
/// a way to act on the bucket as a *managed resource* without going through the managed
/// path. A bucket made with `create_bucket` has no `HFBucket` CR — unmanaged, unquota'd,
/// invisible to the console, absent from `bucket_attributes`. So existence, policy,
/// CORS and quota are control-plane, through the console and the operator, and never
/// through S3:
///
/// | removed | where that authority lives now |
/// |---|---|
/// | `create_bucket`, `delete_bucket` | console `bucket:create` / `bucket:delete` |
/// | `read_bucket_config`, `write_bucket_config` | console `bucket:read` / `bucket:update` |
/// | `write_object_acl` | nowhere — conferring an ACL is refused in code ([`crate::access::headers`]) |
/// | `read_bucket`, `list_buckets` | merged into [`Action::Read`] |
/// | `read_object_tags` | merged into [`Action::ReadObjects`] |
///
/// The two merges are widenings of a surviving verb, not deletions of authority:
/// reading an object's tags is strictly less than reading the object, and
/// "this bucket exists, for me" is one question however it is asked.
///
/// `manage_lifecycle` was deleted earlier, and for the same family of reason: it was a
/// keyless verb whose rego branch granted the whole bucket ignoring prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    // object-scoped: the decision is made against a bucket + one key
    ReadObjects,
    WriteObjects,
    DeleteObjects,
    /// Kept **deliberately separate** from [`Action::WriteObjects`].
    /// `OpaInput::object_tags` exists so a policy can key on tags; the moment it does, a
    /// principal holding write_objects + tag-write could grant itself whatever the
    /// policy keys on. Merging the two plants a trap that springs when tag-driven ABAC
    /// is enabled.
    WriteObjectTags,
    // listing: bucket + prefix, and the *response* is in scope
    ListObjects,
    /// The existence verb — hyperfluid's `bucket:read`, and the ONE dual-plane
    /// permission in the family.
    ///
    /// It answers "does this bucket exist, for me?", which the console asks on its
    /// bucket list and detail routes and which S3 asks as `ListBuckets`, `HeadBucket`
    /// and `GetBucketLocation`. Those two PEPs must answer identically or a user is told
    /// yes by one and no by the other — the defect the 2026-08-08 vocabulary exists to
    /// remove — so it is one verb, and it is the only bucket-shaped verb left.
    ///
    /// It is bucket-scoped AND account-scoped: bucket-shaped for `HeadBucket` /
    /// `GetBucketLocation` (`input.bucket` names one) and account-shaped for
    /// `ListBuckets` (`input.bucket == ""`). The rego rules that read it are gated on
    /// which, and those gates are load-bearing — see the module note in
    /// `policy/gateway/authz.rego`.
    Read,
}

impl Action {
    /// Every verb, in declaration order. Exhaustively matched in [`Action::as_str`], so
    /// a new variant is a compile error there, and cross-checked against
    /// `optable::GATEWAY_VERBS` and the rego's own action sets by test.
    pub const ALL: &'static [Action] = &[
        Action::ReadObjects,
        Action::WriteObjects,
        Action::DeleteObjects,
        Action::WriteObjectTags,
        Action::ListObjects,
        Action::Read,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Action::ReadObjects => "read_objects",
            Action::WriteObjects => "write_objects",
            Action::DeleteObjects => "delete_objects",
            Action::WriteObjectTags => "write_object_tags",
            Action::ListObjects => "list_objects",
            Action::Read => "read",
        }
    }

    /// Writes are subject to the org-global `freeze_writes` kill-switch.
    ///
    /// This set MUST equal the rego's `write_actions`, or `freeze_writes` — the only
    /// kill switch the live bundle carries — stops covering a verb on one side while
    /// still claiming to on the other. `the_write_set_matches_the_shipped_rego` in
    /// `tests/op_coverage.rs` extracts the rego's set from the shipped module and
    /// compares it here, so a divergence fails the build rather than surfacing as a
    /// freeze that did not freeze.
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            Action::WriteObjects | Action::DeleteObjects | Action::WriteObjectTags
        )
    }

    /// True for a verb decided against a **named bucket with no object key**. Such a
    /// verb ignores grant prefixes by construction (there is no key to test a prefix
    /// against), which is why it must be its own verb rather than a keyless
    /// fall-through of the object verbs — a `read_objects` grant scoped to `2024/` must
    /// never confer `HeadBucket`.
    ///
    /// Exactly one verb qualifies now, and that is the point: the other four keyless
    /// verbs were the ones that bypassed the managed path.
    pub const fn is_bucket_scoped(self) -> bool {
        matches!(self, Action::Read)
    }

    /// True for a verb decided with **no bucket at all** (`input.bucket == ""`) — the
    /// account scope, which today is `ListBuckets` alone.
    ///
    /// [`Action::Read`] is in this set *and* in [`Action::is_bucket_scoped`], and the
    /// overlap is deliberate: one verb, two request shapes. Every rego rule that reads
    /// either set therefore has to carry the matching shape gate, or a permitted
    /// `HeadBucket` picks up a `visible_buckets` obligation it cannot apply — which
    /// `must_understand` turns into a hard deny.
    pub const fn is_account_scoped(self) -> bool {
        matches!(self, Action::Read)
    }
}

/// Which backend family a request is proxied to. Enforcement never depends on
/// backend-native features; this only selects the proxy client + re-signing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    Ceph,
    RemoteS3,
}

impl BackendKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            BackendKind::Ceph => "ceph",
            BackendKind::RemoteS3 => "remote_s3",
        }
    }
}

/// Principal classes. Analytics engines present a per-user identity like any other
/// client, so there is no dedicated engine principal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalType {
    User,
    ServiceAccount,
}

/// Identifies one physical backend (a Ceph RGW instance or a remote S3 endpoint).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BackendId(pub String);

/// A tenant slug == a Ceph tenant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Tenant(pub String);

/// The OIDC subject that owns a Ceph tenant, or a remote endpoint id.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OrgId(pub String);

impl std::fmt::Display for BackendId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::fmt::Display for Tenant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::fmt::Display for OrgId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Key into the per-`(backend, tenant)` proxy client pool. Backend
/// credentials are per-tenant/per-backend so an authz bug cannot cross tenants.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PoolKey {
    pub backend: BackendId,
    pub tenant: Tenant,
}
