//! The assembled gateway: the shared context the S3 front (auth / access / proxy)
//! draws on, plus its construction from config.

use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;

use crate::audit::{self, AuditConfig, AuditSink};
use crate::auth::{Identity, StaticCredential, StaticCredentialStore};
use crate::auth::sts::StsAuthority;
use crate::config::{GatewayConfig, LimitsConfig, PdpConfig};
use crate::error::{GatewayError, Result};
use crate::pdp::{Bundle, BundleStore, CachingPdp, GATEWAY_REGO, Pdp, RegorusPdp, SidecarPdp};
use crate::proxy::BackendRegistry;

/// Shared, cheaply-cloneable state. `Arc<Gateway>` is held by the auth, access, and
/// proxy layers.
pub struct Gateway {
    pub identity: Arc<Identity>,
    pub pdp: Arc<dyn Pdp>,
    pub audit: AuditSink,
    pub registry: Arc<BackendRegistry>,
    pub limits: LimitsConfig,
    /// Kept so a bundle-refresh loop can swap revisions (cache stays coherent, §4.3.2).
    pub bundles: Arc<BundleStore>,
}

impl Gateway {
    /// Build the full gateway from config. Must run inside a tokio runtime (spawns
    /// the audit worker).
    pub fn build(cfg: &GatewayConfig) -> Result<Arc<Gateway>> {
        let sts = Arc::new(build_sts(cfg)?);
        let creds = Arc::new(build_static_store(cfg));
        let identity = Arc::new(Identity::new(sts, creds));

        let (bundles, pdp) = build_pdp(cfg)?;
        let registry = Arc::new(BackendRegistry::from_config(cfg)?);

        let audit = audit::spawn(AuditConfig {
            sink_url: cfg.audit.sink_url.clone(),
            spill_path: cfg.audit.spill_path.clone(),
            ..AuditConfig::default()
        });

        Ok(Arc::new(Gateway {
            identity,
            pdp,
            audit,
            registry,
            limits: cfg.limits.clone(),
            bundles,
        }))
    }
}

fn build_sts(cfg: &GatewayConfig) -> Result<StsAuthority> {
    let master = hex::decode(&cfg.sts.master_key_hex)
        .map_err(|e| GatewayError::Config(format!("sts master_key_hex: {e}")))?;
    let signing = hex::decode(&cfg.sts.signing_key_hex)
        .map_err(|e| GatewayError::Config(format!("sts signing_key_hex: {e}")))?;
    StsAuthority::new(master, signing)
}

fn build_static_store(cfg: &GatewayConfig) -> StaticCredentialStore {
    let mut store = StaticCredentialStore::new();
    for c in &cfg.static_credentials {
        store.insert(
            c.access_key_id.clone(),
            StaticCredential {
                secret_access_key: c.secret_access_key.clone(),
                principal_sub: c.principal_sub.clone(),
                tenant: c.tenant.clone(),
                organization_id: c.organization_id.clone(),
                groups: c.groups.clone(),
            },
        );
    }
    store
}

fn build_pdp(cfg: &GatewayConfig) -> Result<(Arc<BundleStore>, Arc<dyn Pdp>)> {
    let raw = std::fs::read_to_string(&cfg.bundle_path)
        .map_err(|e| GatewayError::Bundle(format!("read {:?}: {e}", cfg.bundle_path)))?;
    let data: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| GatewayError::Bundle(format!("parse bundle: {e}")))?;
    let revision = content_revision(&raw);
    let bundles = Arc::new(BundleStore::new(Bundle::new(revision, data.clone())));

    let (inner, capacity): (Arc<dyn Pdp>, u64) = match &cfg.pdp {
        PdpConfig::Embedded { cache_capacity } => {
            (Arc::new(RegorusPdp::new(GATEWAY_REGO, &data)?), *cache_capacity)
        }
        PdpConfig::Sidecar {
            base_url,
            cache_capacity,
            timeout_ms,
        } => (
            Arc::new(SidecarPdp::new(base_url, Duration::from_millis(*timeout_ms))?),
            *cache_capacity,
        ),
    };
    let pdp: Arc<dyn Pdp> = Arc::new(CachingPdp::new(inner, bundles.clone(), capacity));
    Ok((bundles, pdp))
}

/// Stable revision derived from bundle content — a content change is a new revision,
/// which is exactly the cache-invalidation signal (§4.3.2).
fn content_revision(raw: &str) -> String {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    raw.hash(&mut h);
    format!("{:016x}", h.finish())
}
