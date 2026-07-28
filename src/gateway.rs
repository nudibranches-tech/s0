//! The assembled gateway: the shared context the S3 front (auth / access / proxy)
//! draws on, plus its construction from config.

use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;

use crate::audit::{self, AuditConfig, AuditHandle, AuditSink};
use crate::auth::sts::StsAuthority;
use crate::auth::{Identity, StaticCredentialStore};
use crate::authz::CaptureSink;
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
    /// The concrete static credential store, kept alongside the `Arc<dyn
    /// CredentialStore>` inside `identity` so a config apply can reach it (plan defect
    /// A-8: `Identity::new` erases the handle immediately).
    pub credentials: Arc<StaticCredentialStore>,
    /// Behind an [`ArcSwap`] so the gateway's own semantic caps can be re-applied
    /// without a restart. `Arc<ArcSwap<_>>` rather than a bare `ArcSwap<_>` so the
    /// *handle* can be shared with layers that must not hold the whole `Gateway` —
    /// `crate::proxy::S3GatewayState` is the one that does. Load it at the point of
    /// use; a reader that clones the `LimitsConfig` out into a long-lived field has
    /// silently opted out of the reload.
    pub limits: Arc<ArcSwap<LimitsConfig>>,
    /// Kept so a bundle-refresh loop can swap revisions (cache stays coherent).
    pub bundles: Arc<BundleStore>,
    /// Golden-capture tap. `None` in every deployed binary: [`Gateway::build`] is the
    /// only production construction path and it hard-codes `None`, there is no setter
    /// and no config knob. Enabling capture therefore requires building a `Gateway`
    /// literally — which only tests do. See [`crate::authz::capture`].
    pub capture: Option<Arc<CaptureSink>>,
}

impl Gateway {
    /// Build the full gateway from config. Must run inside a tokio runtime (spawns
    /// the audit worker). Returns the shared gateway plus the audit drain handle, which
    /// the caller must `drain()` on shutdown so buffered records are not lost (§9.2).
    pub fn build(cfg: &GatewayConfig) -> Result<(Arc<Gateway>, AuditHandle)> {
        let sts = Arc::new(build_sts(cfg)?);
        let credentials = Arc::new(StaticCredentialStore::from_config(cfg));
        let identity = Arc::new(Identity::new(sts, credentials.clone()));

        let (bundles, pdp) = build_pdp(cfg)?;
        let registry = Arc::new(BackendRegistry::from_config(cfg)?);

        let (audit, audit_handle) = audit::spawn(AuditConfig {
            sink_url: cfg.audit.sink_url.clone(),
            spill_path: cfg.audit.spill_path.clone(),
            backend: cfg.audit.backend,
            ..AuditConfig::default()
        });

        let gateway = Arc::new(Gateway {
            identity,
            pdp,
            audit,
            registry,
            credentials,
            limits: Arc::new(ArcSwap::from_pointee(cfg.limits.clone())),
            bundles,
            // Never enabled from config: a capture sink retains principal identifiers
            // and object keys in memory, and nothing an operator can set should be able
            // to turn that on.
            capture: None,
        });
        Ok((gateway, audit_handle))
    }

    /// The hardening limits in force right now.
    pub fn limits(&self) -> arc_swap::Guard<Arc<LimitsConfig>> {
        self.limits.load()
    }

    /// Re-apply an operator-rendered config to the running gateway (plan task 10).
    ///
    /// There is deliberately **no producer for this in-tree**. Plan §1.1 cut the polled
    /// `/gateway-config` document: configuration comes from a ConfigMap + Secret, and
    /// E-6's `checksum/credentials` annotation rolls the pods when either changes. This
    /// exists so that swapping *is possible* — the mechanism, not a channel — and so
    /// that the state it swaps is provably reachable rather than erased into a trait
    /// object at construction.
    ///
    /// ## What this does and does not reload
    ///
    /// Applied: the backend routing table (and with it every tenant→Org binding and
    /// owner credential), the static credential list, and the gateway's own semantic
    /// caps (`max_delete_keys`, `max_list_fanout`, the backend timeouts consulted on
    /// the next pool build).
    ///
    /// **Not** applied, because they are consumed once at assembly and re-reading them
    /// would report a change that did not happen: the listen addresses, the s3s
    /// protocol limits and connection cap (baked into the `S3Service` and the accept
    /// loop by `crate::server`), the STS key ring, the PDP mode, and the audit backend.
    /// Changing any of those still needs a restart, which is what a pod roll does.
    ///
    /// ## Ordering
    ///
    /// Each half is built before anything is stored, so an unusable config leaves the
    /// running one entirely intact. The three stores are then swapped in sequence, so a
    /// request in flight can observe new routes with old limits — deliberate and
    /// harmless: limits are resource bounds, not authorization inputs, and no decision
    /// reads both. What must *not* tear is a single request's view of its own route,
    /// and that is guaranteed one level up by the `RouteSnapshot` in
    /// `req.extensions` rather than by anything here.
    pub fn apply_config(&self, cfg: &GatewayConfig) -> Result<()> {
        let credentials = crate::auth::credentials_from_config(cfg);
        self.registry.apply_config(cfg)?;
        self.credentials.replace(credentials);
        self.limits.store(Arc::new(cfg.limits.clone()));
        tracing::info!(
            tenants = cfg.tenants.len(),
            static_credentials = cfg.static_credentials.len(),
            "gateway configuration re-applied"
        );
        Ok(())
    }
}

fn build_sts(cfg: &GatewayConfig) -> Result<StsAuthority> {
    // The ring's shape (exactly one of the two forms, `current_kid` present and
    // resolvable) is settled by `GatewayConfig::validate`; what is left here is hex.
    let (ring, current_kid) = cfg.sts.key_ring();
    let mut master_keys = std::collections::BTreeMap::new();
    for (kid, hex_key) in &ring {
        let key = hex::decode(hex_key.expose())
            .map_err(|e| GatewayError::Config(format!("sts master key {kid}: {e}")))?;
        master_keys.insert(kid.clone(), key);
    }
    let signing = hex::decode(cfg.sts.signing_key_hex.expose())
        .map_err(|e| GatewayError::Config(format!("sts signing_key_hex: {e}")))?;
    let authority = StsAuthority::with_key_ring(master_keys, &current_kid, signing)?;
    tracing::info!(
        current_kid = %authority.current_kid(),
        key_ids = ?authority.key_ids(),
        "sts key ring loaded"
    );
    Ok(authority)
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
            // construction.
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
            // allows across the skew window (a live-revocation bypass). Every
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{CredentialStore, StaticCredential, StaticCredentials};

    fn cfg_with(static_credentials: serde_json::Value, max_delete_keys: u64) -> GatewayConfig {
        GatewayConfig::from_json(
            &serde_json::json!({
                "listen": "127.0.0.1:0",
                "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
                "pdp": { "mode": "embedded" },
                "audit": { "sink_url": "http://127.0.0.1:59999/none",
                           "spill_path": std::env::temp_dir()
                               .join(format!("s0-gwcfg-{}.ndjson", uuid::Uuid::new_v4())) },
                "limits": {
                    "xml_max_body_size": 20971520,
                    "presigned_url_max_skew_time_secs": 900,
                    "max_delete_keys": max_delete_keys,
                    "max_list_fanout": 16,
                    "max_connections": 1024,
                    "header_read_timeout_secs": 15
                },
                "backends": [
                    { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:7480" },
                    { "id": "bay-2", "kind": "remote_s3", "endpoint_url": "http://127.0.0.1:7481" }
                ],
                "tenants": [
                    { "tenant": "acme", "organization_id": "org-acme", "backend_id": "bay-1",
                      "owner_access_key": "OWNER", "owner_secret_key": "OWNERSECRET" }
                ],
                "static_credentials": static_credentials,
                "bundle_path": "/dev/null"
            })
            .to_string(),
        )
        .expect("config")
    }

    fn cred(key: &str, sub: &str, secret: &str) -> serde_json::Value {
        serde_json::json!({
            "access_key_id": key, "secret_access_key": secret,
            "principal_sub": sub, "tenant": "acme", "organization_id": "org-acme"
        })
    }

    /// A gateway assembled the way `build` does. Returns the audit handle so the
    /// worker outlives the test rather than every `emit` logging an error.
    fn gateway(cfg: &GatewayConfig) -> (Gateway, AuditHandle) {
        let credentials = Arc::new(StaticCredentialStore::from_config(cfg));
        let (audit, handle) = audit::spawn(AuditConfig {
            sink_url: cfg.audit.sink_url.clone(),
            spill_path: cfg.audit.spill_path.clone(),
            ..AuditConfig::default()
        });
        let gw = Gateway {
            identity: Arc::new(Identity::new(
                Arc::new(build_sts(cfg).expect("sts")),
                credentials.clone(),
            )),
            pdp: Arc::new(RegorusPdp::new(GATEWAY_REGO, &serde_json::json!({})).expect("regorus")),
            audit,
            registry: Arc::new(BackendRegistry::from_config(cfg).expect("registry")),
            credentials,
            limits: Arc::new(ArcSwap::from_pointee(cfg.limits.clone())),
            bundles: Arc::new(BundleStore::new(Bundle::new(
                "rev-1",
                serde_json::json!({}),
            ))),
            capture: None,
        };
        (gw, handle)
    }

    /// Plan defect A-8, as a runtime property rather than a claim.
    ///
    /// `Identity::new` erases the store into `Arc<dyn CredentialStore>` at
    /// construction. If the swap lived *around* the store — an `ArcSwap` the caller
    /// holds — replacing it would leave `Identity` reading the original forever, and
    /// every test that checked the concrete handle instead of the erased one would
    /// still pass. So this asserts through `Identity::resolve`, which is the path a
    /// real request takes.
    #[tokio::test]
    async fn a_credential_swap_reaches_the_handle_identity_erased_at_construction() {
        let (gw, _audit) = gateway(&cfg_with(
            serde_json::json!([cred("AKIAOLD", "alice", "old-secret")]),
            1000,
        ));
        assert_eq!(gw.identity.resolve("AKIAOLD", None).unwrap().sub, "alice");

        gw.apply_config(&cfg_with(
            serde_json::json!([cred("AKIANEW", "bob", "new-secret")]),
            1000,
        ))
        .expect("apply");

        // The revocation direction: a credential removed from the config stops
        // resolving, through the same erased handle.
        assert!(
            gw.identity.resolve("AKIAOLD", None).is_err(),
            "a credential removed from the config still resolves"
        );
        assert_eq!(gw.identity.resolve("AKIANEW", None).unwrap().sub, "bob");
    }

    #[tokio::test]
    async fn a_secret_rotation_reaches_the_sigv4_path() {
        // `secret_key` is what s3s asks for to verify a signature, and it is a
        // different method from `resolve` — a swap that reached one and not the other
        // would authenticate with the old secret and attribute with the new principal.
        let (gw, _audit) = gateway(&cfg_with(
            serde_json::json!([cred("AKIASAME", "alice", "old-secret")]),
            1000,
        ));
        let store: &dyn CredentialStore = gw.credentials.as_ref();
        assert_eq!(store.secret("AKIASAME").as_deref(), Some("old-secret"));

        gw.apply_config(&cfg_with(
            serde_json::json!([cred("AKIASAME", "alice", "rotated")]),
            1000,
        ))
        .expect("apply");
        assert_eq!(store.secret("AKIASAME").as_deref(), Some("rotated"));
    }

    #[tokio::test]
    async fn applying_a_config_moves_the_semantic_caps() {
        let (gw, _audit) = gateway(&cfg_with(serde_json::json!([]), 1000));
        assert_eq!(gw.limits().max_delete_keys, 1000);
        gw.apply_config(&cfg_with(serde_json::json!([]), 50))
            .expect("apply");
        assert_eq!(gw.limits().max_delete_keys, 50);
    }

    #[tokio::test]
    async fn the_sts_key_ring_is_deliberately_not_hot_reloaded() {
        // Not an oversight, and worth a test so it stays a decision: the mint holds a
        // SECOND `Arc<StsAuthority>` clone (`Identity::sts()`, handed to `Mint::new` in
        // `main` and captured into a detached task), so swapping the authority behind
        // `Identity` would leave the badge desk minting under the old ring. Rotation is
        // therefore a config edit plus a pod roll — which is what the key ring's `kid`
        // exists to make survivable (see `crate::auth::sts`). Making it live requires
        // the swap to live INSIDE `StsAuthority`, not around it.
        let (gw, _audit) = gateway(&cfg_with(serde_json::json!([]), 1000));
        let held_by_the_mint = gw.identity.sts();
        gw.apply_config(&cfg_with(serde_json::json!([]), 1000))
            .expect("apply");
        assert!(
            Arc::ptr_eq(&held_by_the_mint, &gw.identity.sts()),
            "the STS authority was swapped; the mint's detached clone would not see it"
        );
    }

    #[tokio::test]
    async fn a_config_that_does_not_apply_changes_nothing() {
        let (gw, _audit) = gateway(&cfg_with(
            serde_json::json!([cred("AKIAOLD", "alice", "old-secret")]),
            1000,
        ));
        let mut broken = cfg_with(serde_json::json!([cred("AKIANEW", "bob", "s")]), 7);
        broken.tenants[0].backend_id = "nope".into();

        assert!(gw.apply_config(&broken).is_err());
        // Every half stays as it was — including the two that are swapped *after* the
        // routing table, which is what makes "build before store" load-bearing rather
        // than incidental.
        assert_eq!(gw.limits().max_delete_keys, 1000);
        assert!(gw.identity.resolve("AKIANEW", None).is_err());
        assert_eq!(gw.identity.resolve("AKIAOLD", None).unwrap().sub, "alice");
        assert!(gw.registry.route_snapshot("acme").is_some());
    }

    #[test]
    fn the_credential_store_swaps_wholesale_not_by_merge() {
        // `replace` is not `extend`: an operator who deletes a credential from the
        // ConfigMap has revoked it, and a merge would keep it alive forever.
        let store = StaticCredentialStore::new();
        store.insert(
            "AKIA1",
            StaticCredential {
                secret_access_key: "s1".into(),
                principal_sub: "alice".into(),
                tenant: "acme".into(),
                organization_id: "org-acme".into(),
                groups: vec![],
            },
        );
        assert_eq!(store.len(), 1);
        store.replace(StaticCredentials::new());
        assert!(store.is_empty());
        assert_eq!(store.secret("AKIA1"), None);
    }
}
