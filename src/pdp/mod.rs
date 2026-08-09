//! Policy Decision Point. The decision is abstracted behind [`Pdp`] from
//! day one so the engine — sidecar OPA (default) or embedded regorus (fast path) — is
//! a config swap, permitted only behind the dual-engine parity gate.
//!
//! [`CachingPdp`] wraps any engine with the revision-keyed cache.

mod bundle;
mod cache;
mod embedded;
mod sidecar;

pub use bundle::{
    Bundle, BundleStore, DECISION_RULE, GATEWAY_REGO, ParsedBundle, bundle_knows_service_account,
    content_revision, decision_rule_path, parse_bundle, service_account_subject_key,
};
pub use cache::CachingPdp;
pub use embedded::RegorusPdp;
pub use sidecar::SidecarPdp;

use async_trait::async_trait;

use crate::authz::{Decision, OpaInput};
use crate::error::Result;

/// The one seam every engine implements. Deny-by-default is the engine's
/// responsibility: any error or undefined result must surface as a deny, never an
/// allow.
#[async_trait]
pub trait Pdp: Send + Sync {
    async fn decide(&self, input: &OpaInput) -> Result<Decision>;

    /// Install a new pushed bundle (a new revision): live policy and live revocation.
    /// `policy` is the rego module when the platform pushed one, else `None` (keep the
    /// engine's current policy). Default no-op: the sidecar engine is fed the bundle
    /// out-of-band by OPA's own bundle plugin, so only the revision (in [`BundleStore`])
    /// changes for it.
    async fn reload(&self, _policy: Option<&str>, _data: &serde_json::Value) -> Result<()> {
        Ok(())
    }
}
