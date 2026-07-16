//! Policy Decision Point (§4.3.1). The decision is abstracted behind [`Pdp`] from
//! day one so the engine — sidecar OPA (default) or embedded regorus (fast path) — is
//! a config swap, permitted only behind the dual-engine parity gate (§4.3.1).
//!
//! [`CachingPdp`] wraps any engine with the revision-keyed cache (§4.3.2).

mod bundle;
mod cache;
mod embedded;
mod sidecar;

pub use bundle::{Bundle, BundleStore, DECISION_RULE, GATEWAY_REGO, content_revision};
pub use cache::CachingPdp;
pub use embedded::RegorusPdp;
pub use sidecar::SidecarPdp;

use async_trait::async_trait;

use crate::authz::{Decision, OpaInput};
use crate::error::Result;

/// The one seam every engine implements. Deny-by-default is the engine's
/// responsibility: any error or undefined result must surface as a deny, never an
/// allow (§6.2).
#[async_trait]
pub trait Pdp: Send + Sync {
    async fn decide(&self, input: &OpaInput) -> Result<Decision>;

    /// Install new projected policy data (a new bundle revision). Live policy /
    /// live revocation (§6.1). Default no-op: the sidecar engine is fed the bundle
    /// out-of-band by OPA's bundle plugin, so only the revision (in [`BundleStore`])
    /// changes for it.
    async fn reload(&self, _bundle: &serde_json::Value) -> Result<()> {
        Ok(())
    }
}
