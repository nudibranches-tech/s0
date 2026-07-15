//! The per-Org bundle: the projected policy *data* (tenants, grants, denylists,
//! `freeze_writes`) plus a revision. The gateway reuses the console's bundle
//! delivery mechanism (§3.4); the rego itself is net-new and ships embedded in the
//! binary, so a bundle here is data + revision only.
//!
//! The revision is the linchpin of cache correctness (§4.3.2): a revocation lands as
//! a new revision, so every decision cached under the old revision is unreachable by
//! construction — there is no invalidation logic to get wrong.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// The embedded gateway policy — single source of truth for both the shipped rule
/// and the tests, so what we test is what we enforce.
pub const GATEWAY_REGO: &str = include_str!("../../policy/gateway/authz.rego");

/// The rule the engines evaluate.
pub const DECISION_RULE: &str = "data.hyperfluid.gateway.decision";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Opaque monotonic revision from the console bundle builder (an etag/version).
    pub revision: String,
    /// The projected policy data (`tenants`, `org_settings`, …). Shape per §3.4 +
    /// the target grant superset (§3.3).
    pub data: serde_json::Value,
}

impl Bundle {
    pub fn new(revision: impl Into<String>, data: serde_json::Value) -> Self {
        Bundle {
            revision: revision.into(),
            data,
        }
    }
}

/// Hot-swappable current bundle, shared by every engine instance and the decision
/// cache. Swapping is lock-free; readers never block a decision.
pub struct BundleStore {
    current: ArcSwap<Bundle>,
}

impl BundleStore {
    pub fn new(initial: Bundle) -> Self {
        BundleStore {
            current: ArcSwap::from_pointee(initial),
        }
    }

    pub fn current(&self) -> arc_swap::Guard<std::sync::Arc<Bundle>> {
        self.current.load()
    }

    pub fn revision(&self) -> String {
        self.current.load().revision.clone()
    }

    /// Install a newly-fetched bundle. Old cached decisions become unreachable
    /// because their cache keys embed the prior revision.
    pub fn store(&self, bundle: Bundle) {
        self.current.store(std::sync::Arc::new(bundle));
    }
}
