//! Gateway configuration. Secrets (STS keys, per-tenant backend credentials) are
//! expected from a secret store in production; here they load from a JSON file
//! referenced by `$GATEWAY_CONFIG` so the binary is runnable end-to-end.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{GatewayError, Result};
use crate::model::BackendKind;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub listen: SocketAddr,
    pub sts: StsConfig,
    pub pdp: PdpConfig,
    #[serde(default)]
    pub audit: AuditFileConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    pub backends: Vec<BackendConfig>,
    pub tenants: Vec<TenantConfig>,
    /// Long-lived static credentials (external apps / service accounts). Each is its
    /// own principal — never a shared bay key (§6.5).
    #[serde(default)]
    pub static_credentials: Vec<StaticCredentialConfig>,
    /// Path to the initial per-Org bundle JSON (the projected policy data). In
    /// production this is polled from the console bundle endpoint (§3.4).
    pub bundle_path: PathBuf,
    /// Optional console bundle endpoint to poll for live updates (§3.4, §6.1). When
    /// unset, the refresher re-reads `bundle_path` (dev/local).
    #[serde(default)]
    pub bundle_url: Option<String>,
    #[serde(default = "default_bundle_poll_secs")]
    pub bundle_poll_secs: u64,
    /// Optional STS mint (the badge desk, §4.2). When present, a control-plane server
    /// runs on its own listener and issues gateway session creds from OIDC tokens.
    #[serde(default)]
    pub sts_mint: Option<StsMintConfig>,
}

/// OIDC → gateway-credentials mint. Backend-agnostic: verifies a Keycloak token and
/// mints the gateway's own session (never a backend STS).
#[derive(Debug, Clone, Deserialize)]
pub struct StsMintConfig {
    pub listen: SocketAddr,
    pub issuer: String,
    pub audience: String,
    /// JWKS endpoint (production; keys rotate). Exactly one of jwks_uri / public_key_pem.
    #[serde(default)]
    pub jwks_uri: Option<String>,
    /// Static RS256 public key PEM (simpler deployments / tests).
    #[serde(default)]
    pub public_key_pem: Option<String>,
    #[serde(default = "default_sub_claim")]
    pub sub_claim: String,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    /// Claim carrying the Harbor/tenant slug.
    pub tenant_claim: String,
    /// Claim carrying the organization id.
    pub org_claim: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StaticCredentialConfig {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub principal_sub: String,
    pub tenant: String,
    pub organization_id: String,
    #[serde(default)]
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StsConfig {
    /// Hex-encoded master key (≥32 bytes) deriving session secrets.
    pub master_key_hex: String,
    /// Hex-encoded signing key (≥32 bytes) authenticating session tokens.
    pub signing_key_hex: String,
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PdpConfig {
    /// Embedded regorus (fast path). Permitted only behind the parity gate (§4.3.1).
    Embedded {
        #[serde(default = "default_cache_capacity")]
        cache_capacity: u64,
    },
    /// Sidecar OPA over loopback (shipping default, §4.3.1).
    Sidecar {
        base_url: String,
        #[serde(default = "default_cache_capacity")]
        cache_capacity: u64,
        #[serde(default = "default_pdp_timeout_ms")]
        timeout_ms: u64,
    },
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuditFileConfig {
    pub sink_url: String,
    pub spill_path: PathBuf,
}

impl Default for AuditFileConfig {
    fn default() -> Self {
        AuditFileConfig {
            sink_url: "http://127.0.0.1:9000/api/v1/decision-logs".into(),
            spill_path: PathBuf::from("/var/lib/hyperfluid-gateway/audit-spill.ndjson"),
        }
    }
}

/// Request-shape + hardening limits (§9.1). Mapped onto `s3s::S3Config` plus the
/// gateway's own semantic caps enforced before the PDP fan-out.
#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    pub xml_max_body_size: usize,
    pub post_object_max_file_size: u64,
    pub presigned_url_max_skew_time_secs: u32,
    /// AWS semantic cap: `DeleteObjects` ≤ 1000 keys (enforced before OPA, §9.1).
    pub max_delete_keys: usize,
    /// Multi-prefix list fan-out bound; above it the list fails closed (§5.1).
    pub max_list_fanout: usize,
    /// Max concurrent connections (slowloris / resource-exhaustion guard, §9.1).
    pub max_connections: usize,
    /// Header read timeout (slowloris, §9.1).
    pub header_read_timeout_secs: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            xml_max_body_size: 20 * 1024 * 1024,
            post_object_max_file_size: 5 * 1024 * 1024 * 1024,
            presigned_url_max_skew_time_secs: 900,
            max_delete_keys: 1000,
            max_list_fanout: 16,
            max_connections: 1024,
            header_read_timeout_secs: 15,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct BackendConfig {
    pub id: String,
    pub kind: BackendKind,
    pub endpoint_url: String,
    #[serde(default = "default_region")]
    pub region: String,
    #[serde(default = "default_true")]
    pub force_path_style: bool,
}

/// Maps a Harbor tenant to its Org, its backend, and the per-tenant backend
/// credential the proxy re-signs with (never the caller's, §4.4/§6.4).
#[derive(Debug, Clone, Deserialize)]
pub struct TenantConfig {
    pub tenant: String,
    pub organization_id: String,
    pub backend_id: String,
    pub owner_access_key: String,
    pub owner_secret_key: String,
}

impl GatewayConfig {
    pub fn load() -> Result<Self> {
        let path = std::env::var("GATEWAY_CONFIG").unwrap_or_else(|_| "gateway.json".into());
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| GatewayError::Config(format!("read {path}: {e}")))?;
        Self::from_json(&raw)
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        let cfg: GatewayConfig =
            serde_json::from_str(raw).map_err(|e| GatewayError::Config(format!("parse: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        let ids: HashMap<&str, &BackendConfig> =
            self.backends.iter().map(|b| (b.id.as_str(), b)).collect();
        for t in &self.tenants {
            if !ids.contains_key(t.backend_id.as_str()) {
                return Err(GatewayError::Config(format!(
                    "tenant {} references unknown backend {}",
                    t.tenant, t.backend_id
                )));
            }
        }
        // A static credential's org must match its tenant's authoritative org, or
        // audit attribution would drift from the tenant->org binding (§6.6).
        let tenant_org: HashMap<&str, &str> = self
            .tenants
            .iter()
            .map(|t| (t.tenant.as_str(), t.organization_id.as_str()))
            .collect();
        for c in &self.static_credentials {
            if c.access_key_id.starts_with(crate::auth::sts::STS_PREFIX) {
                return Err(GatewayError::Config(format!(
                    "static credential {} collides with the STS access-key prefix {:?}; \
                     it would be shadowed by STS secret derivation",
                    c.access_key_id,
                    crate::auth::sts::STS_PREFIX
                )));
            }
            match tenant_org.get(c.tenant.as_str()) {
                None => {
                    return Err(GatewayError::Config(format!(
                        "static credential {} references unknown tenant {}",
                        c.access_key_id, c.tenant
                    )));
                }
                Some(org) if *org != c.organization_id => {
                    return Err(GatewayError::Config(format!(
                        "static credential {} org {} disagrees with tenant {} org {}",
                        c.access_key_id, c.organization_id, c.tenant, org
                    )));
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.sts.session_ttl_secs)
    }
}

fn default_session_ttl_secs() -> u64 {
    3600
}
fn default_bundle_poll_secs() -> u64 {
    30
}
fn default_sub_claim() -> String {
    "sub".into()
}
fn default_groups_claim() -> String {
    "groups".into()
}
fn default_cache_capacity() -> u64 {
    100_000
}
fn default_pdp_timeout_ms() -> u64 {
    2000
}
fn default_region() -> String {
    "us-east-1".into()
}
fn default_true() -> bool {
    true
}
