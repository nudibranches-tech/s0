//! Core domain vocabulary shared across the gateway.
//!
//! Domain shape: `Organization → Tenant (= one Ceph tenant) → Bucket`.
//! A tenant *slug* is the Ceph tenant. Object keys nest under a bucket.

use serde::{Deserialize, Serialize};

/// The grant vocabulary the gateway authorizes against — the **six projected verbs**.
///
/// Deliberately coarser than the 99 S3 ops: every enforced op maps onto exactly one of
/// these (`PutObject` to `write_objects`, `HeadBucket` to `read`), except `CopyObject`,
/// which maps to two. The set is a contract with whatever control plane projects grants.
///
/// **The gateway is data-plane only**, so there is no verb for acting on a bucket as a
/// *managed resource*: existence, policy, CORS and quota are control-plane concerns, and
/// `write_object_acl` is refused in code ([`crate::access::headers`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    // object-scoped: the decision is made against a bucket + one key
    ReadObjects,
    WriteObjects,
    DeleteObjects,
    /// Kept **deliberately separate** from [`Action::WriteObjects`]. `OpaInput::object_tags`
    /// lets a policy key on tags; merging the two would let a principal holding both grant
    /// itself whatever the policy keys on, a trap that springs when tag-driven ABAC is on.
    WriteObjectTags,
    // listing: bucket + prefix, and the *response* is in scope
    ListObjects,
    /// The existence verb, and the ONE dual-plane permission in the family: it answers
    /// "does this bucket exist, for me?", which S3 asks as `ListBuckets`, `HeadBucket` and
    /// `GetBucketLocation` and a control plane asks on its own bucket routes. Two policy
    /// enforcement points answering that differently tell a user yes and no at once.
    ///
    /// It is bucket-scoped AND account-scoped: bucket-shaped for `HeadBucket` /
    /// `GetBucketLocation` (`input.bucket` names one), account-shaped for `ListBuckets`
    /// (`input.bucket == ""`). The rego rules reading it are gated on which, and those
    /// gates are load-bearing — see the module note in `policy/gateway/authz.rego`.
    Read,
}

impl Action {
    /// Every verb, in declaration order. Exhaustively matched in [`Action::as_str`], so a
    /// new variant is a compile error there, and cross-checked against
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
    /// This set MUST equal the rego's `write_actions`, or the switch stops covering a verb
    /// on one side while still claiming to on the other.
    /// `tests/op_coverage.rs::the_write_set_matches_the_shipped_rego` extracts the rego's
    /// set and compares it here, so a divergence fails the build rather than surfacing as a
    /// freeze that did not freeze.
    pub const fn is_write(self) -> bool {
        matches!(
            self,
            Action::WriteObjects | Action::DeleteObjects | Action::WriteObjectTags
        )
    }

    /// True for a verb decided against a **named bucket with no object key**. Such a verb
    /// ignores grant prefixes by construction (there is no key to test one against), which
    /// is why it must be its own verb rather than a keyless fall-through of the object
    /// verbs — a `read_objects` grant scoped to `2024/` must never confer `HeadBucket`.
    pub const fn is_bucket_scoped(self) -> bool {
        matches!(self, Action::Read)
    }

    /// True for a verb decided with **no bucket at all** (`input.bucket == ""`) — the
    /// account scope, which is `ListBuckets` alone.
    ///
    /// [`Action::Read`] is in this set *and* in [`Action::is_bucket_scoped`]: one verb, two
    /// request shapes. Every rego rule reading either set must therefore carry the matching
    /// shape gate, or a permitted `HeadBucket` picks up a `visible_buckets` obligation it
    /// cannot apply — which `must_understand` turns into a hard deny.
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
