//! The assembled gateway: the shared context the S3 front (auth / access / proxy)
//! draws on, plus its construction from config.

use std::sync::Arc;
use std::time::Duration;

use crate::audit::{self, AuditConfig, AuditHandle, AuditSink};
use crate::auth::sts::StsAuthority;
use crate::auth::{Identity, StaticCredential, StaticCredentialStore};
use crate::config::{GatewayConfig, LimitsConfig, PdpConfig};
use crate::error::{GatewayError, Result};
use crate::pdp::{
    Bundle, BundleStore, CachingPdp, GATEWAY_REGO, Pdp, RegorusPdp, SidecarPdp, content_revision,
    parse_bundle,
};
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
    /// the audit worker). Returns the shared gateway plus the audit drain handle, which
    /// the caller must `drain()` on shutdown so buffered records are not lost (§9.2).
    pub fn build(cfg: &GatewayConfig) -> Result<(Arc<Gateway>, AuditHandle)> {
        let sts = Arc::new(build_sts(cfg)?);
        let creds = Arc::new(build_static_store(cfg));
        let identity = Arc::new(Identity::new(sts, creds));

        let (bundles, pdp) = build_pdp(cfg)?;
        let registry = Arc::new(BackendRegistry::from_config(cfg)?);

        let (audit, audit_handle) = audit::spawn(AuditConfig {
            sink_url: cfg.audit.sink_url.clone(),
            spill_path: cfg.audit.spill_path.clone(),
            ..AuditConfig::default()
        });

        let gateway = Arc::new(Gateway {
            identity,
            pdp,
            audit,
            registry,
            limits: cfg.limits.clone(),
            bundles,
        });
        Ok((gateway, audit_handle))
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
    let parsed = parse_bundle(&raw).map_err(GatewayError::Bundle)?;
    let revision = content_revision(&raw);
    let bundles = Arc::new(BundleStore::new(Bundle::new(revision, parsed.data.clone())));

    let pdp: Arc<dyn Pdp> = match &cfg.pdp {
        PdpConfig::Embedded { cache_capacity } => {
            // Cache is sound for the embedded engine: the gateway reloads the engine
            // and bumps the revision atomically, so a stale entry misses by
            // construction (§4.3.2).
            // The platform's pushed module is authoritative; the compiled-in default is
            // the fallback when the bundle carries data only.
            let policy = parsed.policy.as_deref().unwrap_or(GATEWAY_REGO);
            let engine: Arc<dyn Pdp> = Arc::new(RegorusPdp::new(policy, &parsed.data)?);
            Arc::new(CachingPdp::new(engine, bundles.clone(), *cache_capacity))
        }
        PdpConfig::Sidecar {
            base_url,
            timeout_ms,
            ..
        } => {
            // NO decision cache for the sidecar: OPA polls its own bundle
            // independently, so the gateway's BundleStore revision is not bound to the
            // data OPA actually evaluates. A revision-keyed cache would serve stale
            // allows across the skew window (a live-revocation bypass, §6.1). Every
            // request hits OPA, which holds the current bundle. Caching returns once
            // the gateway is authoritative for OPA's revision (ADR-005 follow-up).
            Arc::new(SidecarPdp::new(
                base_url,
                Duration::from_millis(*timeout_ms),
            )?)
        }
    };
    Ok((bundles, pdp))
}
