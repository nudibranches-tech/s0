//! Decision cache.
//!
//! The key embeds the bundle revision, the full principal, and a digest of *every other
//! field* of the input ([`OpaInput::resource_key`] — derived, not enumerated, so a field
//! the policy can read is never outside the key). A revocation bumps the revision, so
//! stale entries are never looked up again: no TTL, no invalidation. Decisions whose
//! input carries on-demand data (object tags) are never cached — their freshness is not
//! bounded by the revision.

use std::sync::Arc;

use async_trait::async_trait;
use moka::future::Cache;

use crate::authz::{Decision, OpaInput};
use crate::error::Result;

use super::{Pdp, bundle::BundleStore};

pub struct CachingPdp {
    inner: Arc<dyn Pdp>,
    store: Arc<BundleStore>,
    cache: Cache<String, Decision>,
}

impl CachingPdp {
    pub fn new(inner: Arc<dyn Pdp>, store: Arc<BundleStore>, capacity: u64) -> Self {
        CachingPdp {
            inner,
            store,
            cache: Cache::new(capacity),
        }
    }

    fn key(revision: &str, input: &OpaInput) -> Result<String> {
        // Full principal in the key: two tokens for the same `sub` but different
        // groups must not share a verdict.
        let principal = serde_json::to_string(&input.principal)?;
        let resource = input.resource_key()?;
        Ok(format!("{revision}\u{1f}{principal}\u{1f}{resource}"))
    }
}

#[async_trait]
impl Pdp for CachingPdp {
    async fn decide(&self, input: &OpaInput) -> Result<Decision> {
        if input.has_on_demand_data() {
            return self.inner.decide(input).await;
        }
        let key = Self::key(&self.store.revision(), input)?;
        if let Some(hit) = self.cache.get(&key).await {
            return Ok(hit);
        }
        let decision = self.inner.decide(input).await?;
        self.cache.insert(key, decision.clone()).await;
        Ok(decision)
    }

    async fn reload(&self, policy: Option<&str>, data: &serde_json::Value) -> Result<()> {
        self.inner.reload(policy, data).await
    }
}
