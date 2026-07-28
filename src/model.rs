//! Core domain vocabulary shared across the gateway.
//!
//! Domain shape: `Organization → Tenant (= one Ceph tenant) → Bucket`.
//! A tenant *slug* is the Ceph tenant. Object keys nest under a bucket.

use serde::{Deserialize, Serialize};

/// The grant vocabulary the gateway authorizes against — the **13 frozen verbs**.
///
/// Deliberately coarser than the 99 S3 ops: every enforced S3 op maps onto exactly one
/// of these (a `PutObject` to `write_objects`, a `HeadBucket` to `read_bucket`), and
/// `CopyObject` maps to two (source read + dest write). The set is frozen: it is the
/// vocabulary the grant projection emits and the rego matches on, so adding a verb is a
/// cross-repo contract change, not a local edit.
///
/// `manage_lifecycle` was **deleted** rather than kept as a spare. It was the only
/// keyless verb, and its rego branch granted the whole bucket ignoring prefixes — a
/// latent whole-bucket allow that would start matching the moment any lifecycle op
/// landed. The bucket-scoped verbs below replace it explicitly.
///
/// Policy-vs-CORS is **not** split into separate verbs: both are
/// `read_bucket_config` / `write_bucket_config`, discriminated by
/// [`crate::authz::OpaInput::config_kind`]. A verb per sub-resource would multiply the
/// vocabulary without making any grant more expressive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    // object-scoped: the decision is made against a bucket + one key
    ReadObjects,
    WriteObjects,
    DeleteObjects,
    ReadObjectTags,
    WriteObjectTags,
    WriteObjectAcl,
    // listing: bucket + prefix, and the *response* is in scope
    ListObjects,
    // bucket-scoped: no key, so `prefixes` cannot narrow them
    ReadBucket,
    CreateBucket,
    DeleteBucket,
    ReadBucketConfig,
    WriteBucketConfig,
    // account-scoped
    ListBuckets,
}

impl Action {
    /// Every verb, in declaration order. Exhaustively matched in [`Action::as_str`], so
    /// a new variant is a compile error there, and cross-checked against
    /// `optable::FROZEN_VERBS` and the rego's own write set by test.
    pub const ALL: &'static [Action] = &[
        Action::ReadObjects,
        Action::WriteObjects,
        Action::DeleteObjects,
        Action::ReadObjectTags,
        Action::WriteObjectTags,
        Action::WriteObjectAcl,
        Action::ListObjects,
        Action::ReadBucket,
        Action::CreateBucket,
        Action::DeleteBucket,
        Action::ReadBucketConfig,
        Action::WriteBucketConfig,
        Action::ListBuckets,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Action::ReadObjects => "read_objects",
            Action::WriteObjects => "write_objects",
            Action::DeleteObjects => "delete_objects",
            Action::ReadObjectTags => "read_object_tags",
            Action::WriteObjectTags => "write_object_tags",
            Action::WriteObjectAcl => "write_object_acl",
            Action::ListObjects => "list_objects",
            Action::ReadBucket => "read_bucket",
            Action::CreateBucket => "create_bucket",
            Action::DeleteBucket => "delete_bucket",
            Action::ReadBucketConfig => "read_bucket_config",
            Action::WriteBucketConfig => "write_bucket_config",
            Action::ListBuckets => "list_buckets",
        }
    }

    /// Writes are subject to the org-global `freeze_writes` kill-switch.
    ///
    /// This set MUST equal the rego's `write_actions`, or `freeze_writes` — the only
    /// kill switch the live bundle carries — stops covering a verb on one side while
    /// still claiming to on the other. `write_set_matches_the_shipped_rego` in
    /// `tests/op_coverage.rs` extracts the rego's set from the shipped module and
    /// compares it here, so a divergence fails the build rather than surfacing as a
    /// freeze that did not freeze.
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            Action::WriteObjects
                | Action::DeleteObjects
                | Action::WriteObjectTags
                | Action::WriteObjectAcl
                | Action::CreateBucket
                | Action::DeleteBucket
                | Action::WriteBucketConfig
        )
    }

    /// True for the verbs decided against a bucket with **no object key**. They ignore
    /// grant prefixes by construction (there is no key to test a prefix against), which
    /// is why they are separate verbs rather than a keyless fall-through of the object
    /// verbs — a `read_objects` grant scoped to `2024/` must never confer `HeadBucket`.
    pub const fn is_bucket_scoped(self) -> bool {
        matches!(
            self,
            Action::ReadBucket
                | Action::CreateBucket
                | Action::DeleteBucket
                | Action::ReadBucketConfig
                | Action::WriteBucketConfig
        )
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
