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
    /// Liveness / readiness / metrics listener. Always on: the runtime image is
    /// distroless, so a probe cannot `exec` anything, and a TCP probe on the S3 port
    /// succeeds on a pod that has never reached the control plane. Unauthenticated by
    /// design (a probe cannot sign SigV4) — keep it off the ingress.
    #[serde(default = "default_admin_listen")]
    pub admin_listen: SocketAddr,
    pub sts: StsConfig,
    pub pdp: PdpConfig,
    #[serde(default)]
    pub audit: AuditFileConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    pub backends: Vec<BackendConfig>,
    pub tenants: Vec<TenantConfig>,
    /// Long-lived static credentials (external apps / service accounts). Each is its
    /// own principal — never a shared backend key.
    #[serde(default)]
    pub static_credentials: Vec<StaticCredentialConfig>,
    /// Path to the initial per-Org bundle JSON (the projected policy data). In
    /// production this is polled from the control-plane bundle endpoint.
    pub bundle_path: PathBuf,
    /// Optional control-plane bundle endpoint to poll for live updates. When
    /// unset, the refresher re-reads `bundle_path` (dev/local).
    #[serde(default)]
    pub bundle_url: Option<String>,
    #[serde(default = "default_bundle_poll_secs")]
    pub bundle_poll_secs: u64,
    /// Whole-request timeout for one bundle fetch. Without it a control plane that
    /// accepts the connection and never answers stalls the refresh loop *forever*:
    /// the poller is a single task, so one hung fetch stops all later polls and
    /// revocation silently stops landing. Must be < `bundle_poll_secs` × a small
    /// factor or polls queue up behind each other.
    #[serde(default = "default_bundle_timeout_secs")]
    pub bundle_timeout_secs: u64,
    /// Optional STS mint (the badge desk). When present, a control-plane server
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
    /// Claim carrying the tenant slug.
    pub tenant_claim: String,
    /// Claim carrying the organization id.
    pub org_claim: String,
    /// Whole-request timeout for a JWKS fetch. A JWKS fetch happens *inline* in a
    /// mint request on a `kid` miss, so an IdP that hangs would hang every mint
    /// request behind it — the fleet's entire credential-issuing path.
    #[serde(default = "default_jwks_timeout_secs")]
    pub jwks_timeout_secs: u64,
    /// Background JWKS refresh interval. Refresh-on-`kid`-miss alone means the very
    /// first request after a key rotation pays the fetch (and fails if the IdP is
    /// briefly unreachable); a warm cache makes rotation a non-event. `0` disables
    /// the background refresh, leaving miss-driven fetching only.
    #[serde(default = "default_jwks_refresh_secs")]
    pub jwks_refresh_secs: u64,
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
    /// Hex-encoded master key (≥32 bytes) deriving session secrets. Sugar for a
    /// one-entry `master_keys` ring under `auth::sts::DEFAULT_KID`; mutually
    /// exclusive with it.
    #[serde(default)]
    pub master_key_hex: Option<String>,
    /// The master-key **ring**: `kid -> hex key`. The `kid` lands in every access-key
    /// id this gateway mints (`HFST<kid>.<sid>`), which is what lets a key be retired
    /// without invalidating the sessions it already minted. See the rotation procedure
    /// in [`crate::auth::sts`].
    #[serde(default)]
    pub master_keys: std::collections::BTreeMap<String, String>,
    /// Which ring entry mints new sessions. Required with `master_keys`, and never
    /// inferred: "whichever key sorts first" is not a decision an operator made.
    #[serde(default)]
    pub current_kid: Option<String>,
    /// Hex-encoded signing key (≥32 bytes) authenticating session tokens.
    pub signing_key_hex: String,
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
}

impl StsConfig {
    /// The configured ring as `(kid -> hex key, current kid)`, normalizing the
    /// single-key form. Shape errors are raised at load by
    /// [`GatewayConfig::validate`], so this cannot be reached with an invalid pair.
    pub fn key_ring(&self) -> (std::collections::BTreeMap<String, String>, String) {
        match &self.master_key_hex {
            Some(hex) if self.master_keys.is_empty() => (
                std::collections::BTreeMap::from([(
                    crate::auth::sts::DEFAULT_KID.to_string(),
                    hex.clone(),
                )]),
                crate::auth::sts::DEFAULT_KID.to_string(),
            ),
            _ => (
                self.master_keys.clone(),
                self.current_kid.clone().unwrap_or_default(),
            ),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum PdpConfig {
    /// Embedded regorus (fast path). Permitted only behind the parity gate.
    Embedded {
        #[serde(default = "default_cache_capacity")]
        cache_capacity: u64,
    },
    /// Sidecar OPA over loopback (shipping default).
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
    /// Where records go. `control_plane` (default) POSTs batches to `sink_url`;
    /// `stdout_ndjson` prints one flat JSON line per record for the log agent already
    /// tailing the pod, and ignores `sink_url`.
    #[serde(default)]
    pub backend: crate::audit::AuditBackendKind,
}

impl Default for AuditFileConfig {
    fn default() -> Self {
        AuditFileConfig {
            sink_url: "http://127.0.0.1:9000/api/v1/decision-logs".into(),
            spill_path: PathBuf::from("/var/lib/s0/audit-spill.ndjson"),
            backend: crate::audit::AuditBackendKind::default(),
        }
    }
}

/// Request-shape + hardening limits. Mapped onto `s3s::S3Config` plus the
/// gateway's own semantic caps enforced before the PDP fan-out.
#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    pub xml_max_body_size: usize,
    pub post_object_max_file_size: u64,
    pub presigned_url_max_skew_time_secs: u32,
    /// AWS semantic cap: `DeleteObjects` ≤ 1000 keys (enforced before OPA).
    pub max_delete_keys: usize,
    /// Multi-prefix list fan-out bound; above it the list fails closed.
    pub max_list_fanout: usize,
    /// Max concurrent connections (slowloris / resource-exhaustion guard).
    pub max_connections: usize,
    /// Header read timeout (slowloris).
    pub header_read_timeout_secs: u64,
    /// Socket-establishment bound for the backend client. A blackholed backend IP
    /// (a repointed Service, a dead RGW pod) otherwise parks the request — and its
    /// connection slot — until the kernel gives up, minutes later.
    #[serde(default = "default_backend_connect_timeout_secs")]
    pub backend_connect_timeout_secs: u64,
    /// Time-to-first-response-byte bound for the backend client. `0` (the default)
    /// disables it, deliberately: the SDK measures this from *request initiation*,
    /// so on a bulk `PutObject`/`UploadPart` it includes the whole upload — any
    /// finite value would cap the size of an object that can be written over a slow
    /// link. Set it only on a deployment whose backends are known-local and whose
    /// objects are known-small.
    #[serde(default)]
    pub backend_read_timeout_secs: u64,
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
            backend_connect_timeout_secs: 5,
            backend_read_timeout_secs: 0,
        }
    }
}

impl LimitsConfig {
    /// `None` ⇒ the SDK default (no bound). See the field docs for why the read
    /// timeout defaults to disabled.
    pub fn backend_read_timeout(&self) -> Option<Duration> {
        (self.backend_read_timeout_secs > 0)
            .then(|| Duration::from_secs(self.backend_read_timeout_secs))
    }

    pub fn backend_connect_timeout(&self) -> Duration {
        Duration::from_secs(self.backend_connect_timeout_secs)
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

/// Maps a tenant to its Org, its backend, and the per-tenant backend
/// credential the proxy re-signs with (never the caller's).
#[derive(Debug, Clone, Deserialize)]
pub struct TenantConfig {
    pub tenant: String,
    pub organization_id: String,
    pub backend_id: String,
    pub owner_access_key: String,
    pub owner_secret_key: String,
}

/// This process's identity, for anything that must not be shared between replicas.
///
/// `POD_NAME` (the downward API) first, then `HOSTNAME` (which kubernetes sets to the
/// pod name anyway, and which is the container id under plain docker), then the pid —
/// never a constant, because the whole point is that two replicas differ.
pub fn instance_id() -> String {
    instance_id_from(|k| std::env::var(k).ok())
}

/// The [`instance_id`] rule, with the environment injected so it is testable without
/// mutating the process environment out from under other threads.
fn instance_id_from(lookup: impl Fn(&str) -> Option<String>) -> String {
    for var in ["POD_NAME", "HOSTNAME"] {
        if let Some(v) = lookup(var) {
            let v = v.trim();
            if !v.is_empty() {
                return v.to_string();
            }
        }
    }
    format!("pid-{}", std::process::id())
}

impl GatewayConfig {
    /// Load, interpolating `${VAR}` / `${VAR:-default}` from the environment first.
    ///
    /// The interpolation exists so a single ConfigMap can render per-pod values —
    /// specifically the audit spill path, which **must** be pod-unique
    /// (`"/var/lib/s0/audit-spill-${POD_NAME}.ndjson"`); two replicas sharing one
    /// destroy each other's records. An unset variable with no default is a hard
    /// error: a spill path that silently collapsed to `audit-spill-.ndjson` on every
    /// pod would reintroduce exactly the bug this fixes.
    pub fn load() -> Result<Self> {
        let path = std::env::var("GATEWAY_CONFIG").unwrap_or_else(|_| "gateway.json".into());
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| GatewayError::Config(format!("read {path}: {e}")))?;
        let expanded = expand_env(&raw)?;
        Self::from_json(&expanded)
    }

    pub fn from_json(raw: &str) -> Result<Self> {
        let cfg: GatewayConfig =
            serde_json::from_str(raw).map_err(|e| GatewayError::Config(format!("parse: {e}")))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        self.validate_sts_key_ring()?;
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
        // audit attribution would drift from the tenant->org binding.
        let tenant_org: HashMap<&str, &str> = self
            .tenants
            .iter()
            .map(|t| (t.tenant.as_str(), t.organization_id.as_str()))
            .collect();
        for c in &self.static_credentials {
            // The STS namespace is `HFST*` in its entirety — not just the well-formed
            // `HFST<kid>.<sid>` shape. `Identity` answers every key in it from the STS
            // authority alone, so a static entry here is not "shadowed by derivation",
            // it is simply never reachable: an operator would provision a credential
            // that silently does not work. Both halves of the reason are worth saying,
            // because the near-miss shapes (a bare prefix, the pre-key-ring
            // `HFST<sid>` form) are exactly what a migration produces.
            if crate::auth::sts::StsAuthority::is_sts_access_key(&c.access_key_id) {
                return Err(GatewayError::Config(format!(
                    "static credential {} is inside the STS access-key namespace {:?}*; \
                     STS keys are minted as {}<kid>{}<sid> and every key carrying the \
                     prefix is answered by the STS authority, so this credential would \
                     never resolve",
                    c.access_key_id,
                    crate::auth::sts::STS_PREFIX,
                    crate::auth::sts::STS_PREFIX,
                    crate::auth::sts::KID_SEP,
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
        // A zero timeout is not "no timeout" anywhere in this file — it is either an
        // instant failure or, historically, the unbounded wait we are fixing. Reject
        // it at load rather than have an operator discover which one it meant.
        if self.bundle_timeout_secs == 0 {
            return Err(GatewayError::Config(
                "bundle_timeout_secs must be > 0; an unbounded bundle fetch stalls revocation"
                    .into(),
            ));
        }
        if self.limits.backend_connect_timeout_secs == 0 {
            return Err(GatewayError::Config(
                "limits.backend_connect_timeout_secs must be > 0".into(),
            ));
        }
        if let Some(m) = &self.sts_mint
            && m.jwks_timeout_secs == 0
        {
            return Err(GatewayError::Config(
                "sts_mint.jwks_timeout_secs must be > 0; an unbounded JWKS fetch hangs mint requests"
                    .into(),
            ));
        }
        Ok(())
    }

    /// The STS key ring must be unambiguous *at load*, not at first mint.
    ///
    /// Every failure here is one where the gateway would otherwise come up and issue
    /// credentials under a key nobody chose, or come up unable to mint at all — and
    /// the mint is a control-plane endpoint, so the second failure is only discovered
    /// by the first user who tries to get a credential.
    fn validate_sts_key_ring(&self) -> Result<()> {
        let s = &self.sts;
        match (&s.master_key_hex, s.master_keys.is_empty()) {
            (None, true) => {
                return Err(GatewayError::Config(
                    "sts needs either master_key_hex or a non-empty master_keys ring".into(),
                ));
            }
            (Some(_), false) => {
                return Err(GatewayError::Config(
                    "sts.master_key_hex and sts.master_keys are mutually exclusive; \
                     master_key_hex is shorthand for a one-entry ring"
                        .into(),
                ));
            }
            (Some(_), true) => {
                if s.current_kid.is_some() {
                    return Err(GatewayError::Config(
                        "sts.current_kid is meaningless without sts.master_keys".into(),
                    ));
                }
            }
            (None, false) => {
                let Some(kid) = &s.current_kid else {
                    return Err(GatewayError::Config(
                        "sts.current_kid is required with sts.master_keys: which key mints \
                         new sessions is an operator decision, never inferred"
                            .into(),
                    ));
                };
                if !s.master_keys.contains_key(kid) {
                    return Err(GatewayError::Config(format!(
                        "sts.current_kid {kid:?} is not one of sts.master_keys {:?}",
                        s.master_keys.keys().collect::<Vec<_>>()
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(self.sts.session_ttl_secs)
    }
}

/// Substitute `${VAR}` and `${VAR:-fallback}` from the environment.
///
/// Runs on the raw text *before* JSON parsing, so it works in any position. Values are
/// JSON-string-escaped on the way in: interpolating an unescaped `"` would otherwise
/// let an environment variable rewrite the document — and this document decides who may
/// read what.
fn expand_env(raw: &str) -> Result<String> {
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after.find('}').ok_or_else(|| {
            GatewayError::Config("unterminated `${` in config; expected a closing `}`".into())
        })?;
        let (name, fallback) = match after[..end].split_once(":-") {
            Some((n, f)) => (n, Some(f)),
            None => (&after[..end], None),
        };
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return Err(GatewayError::Config(format!(
                "invalid environment variable name in config: ${{{}}}",
                &after[..end]
            )));
        }
        let value = match std::env::var(name) {
            Ok(v) => v,
            Err(_) => fallback.map(str::to_string).ok_or_else(|| {
                GatewayError::Config(format!(
                    "config references ${{{name}}} but {name} is not set \
                     (use ${{{name}:-fallback}} to allow a default)"
                ))
            })?,
        };
        out.push_str(&json_escape(&value));
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

/// JSON string escaping, without the surrounding quotes.
fn json_escape(value: &str) -> String {
    let quoted = serde_json::Value::String(value.to_string()).to_string();
    quoted[1..quoted.len() - 1].to_string()
}

fn default_session_ttl_secs() -> u64 {
    3600
}
fn default_admin_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8016))
}
fn default_bundle_poll_secs() -> u64 {
    30
}
fn default_bundle_timeout_secs() -> u64 {
    10
}
fn default_jwks_timeout_secs() -> u64 {
    5
}
fn default_jwks_refresh_secs() -> u64 {
    300
}
fn default_backend_connect_timeout_secs() -> u64 {
    5
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `expand_env` is what makes a single ConfigMap render a per-pod spill path.
    /// These run in one process, so each case uses a variable name of its own rather
    /// than relying on test ordering.
    #[test]
    fn interpolates_pod_identity_into_the_spill_path() {
        unsafe { std::env::set_var("S0_TEST_POD", "s0-7d9f-abcde") };
        let out = expand_env(r#"{"spill_path":"/var/lib/s0/audit-spill-${S0_TEST_POD}.ndjson"}"#)
            .expect("expands");
        assert_eq!(
            out,
            r#"{"spill_path":"/var/lib/s0/audit-spill-s0-7d9f-abcde.ndjson"}"#
        );
    }

    #[test]
    fn a_missing_variable_is_a_hard_error_not_an_empty_string() {
        // The failure this prevents: every replica silently resolving to the SAME
        // `audit-spill-.ndjson`, which is exactly the shared-file bug the
        // interpolation exists to avoid.
        let err = expand_env(r#"{"p":"${S0_TEST_DEFINITELY_UNSET}"}"#).unwrap_err();
        assert!(
            err.to_string().contains("S0_TEST_DEFINITELY_UNSET"),
            "{err}"
        );
    }

    #[test]
    fn a_fallback_is_honoured_and_a_set_value_wins_over_it() {
        assert_eq!(
            expand_env(r#"{"p":"${S0_TEST_UNSET_WITH_FALLBACK:-local}"}"#).unwrap(),
            r#"{"p":"local"}"#
        );
        unsafe { std::env::set_var("S0_TEST_SET_WITH_FALLBACK", "from-env") };
        assert_eq!(
            expand_env(r#"{"p":"${S0_TEST_SET_WITH_FALLBACK:-local}"}"#).unwrap(),
            r#"{"p":"from-env"}"#
        );
    }

    #[test]
    fn an_interpolated_value_cannot_rewrite_the_document() {
        // This document decides who may read what. An environment variable is not
        // allowed to close a string and add fields to it.
        unsafe { std::env::set_var("S0_TEST_INJECT", r#"x","listen":"0.0.0.0:1"#) };
        let out = expand_env(r#"{"tenant":"${S0_TEST_INJECT}"}"#).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&out).expect("still valid json");
        assert_eq!(
            parsed.as_object().unwrap().len(),
            1,
            "no field was injected"
        );
        assert_eq!(parsed["tenant"], r#"x","listen":"0.0.0.0:1"#);
    }

    #[test]
    fn malformed_interpolations_are_rejected() {
        assert!(expand_env(r#"{"p":"${UNTERMINATED"}"#).is_err());
        assert!(expand_env(r#"{"p":"${bad name}"}"#).is_err());
        assert!(expand_env(r#"{"p":"${}"}"#).is_err());
        // A bare `$` is not an interpolation and must survive untouched (secrets and
        // regexes contain them).
        assert_eq!(expand_env(r#"{"p":"a$b"}"#).unwrap(), r#"{"p":"a$b"}"#);
    }

    #[test]
    fn instance_id_prefers_pod_name_and_is_never_constant() {
        let env = |k: &str| match k {
            "POD_NAME" => Some("s0-abcde-12345".to_string()),
            "HOSTNAME" => Some("node-7".to_string()),
            _ => None,
        };
        assert_eq!(instance_id_from(env), "s0-abcde-12345");
        // HOSTNAME is the fallback (kubernetes sets it to the pod name anyway).
        assert_eq!(
            instance_id_from(|k| (k == "HOSTNAME").then(|| "node-7".to_string())),
            "node-7"
        );
        // An empty value is not an identity — it would collapse two replicas onto one
        // spill path, which is the bug this whole mechanism exists to prevent.
        assert!(
            instance_id_from(|_| Some(String::new())).starts_with("pid-"),
            "an empty POD_NAME must not become a shared constant"
        );
        assert!(instance_id_from(|_| None).starts_with("pid-"));
    }

    #[test]
    fn a_zero_timeout_is_rejected_at_load() {
        let base: serde_json::Value =
            serde_json::from_str(include_str!("../docs/gateway.example.json")).unwrap();
        let mut cfg = base.clone();
        cfg["bundle_timeout_secs"] = serde_json::json!(0);
        let err = GatewayConfig::from_json(&cfg.to_string()).unwrap_err();
        assert!(err.to_string().contains("bundle_timeout_secs"), "{err}");

        let mut cfg = base.clone();
        cfg["sts_mint"]["jwks_timeout_secs"] = serde_json::json!(0);
        let err = GatewayConfig::from_json(&cfg.to_string()).unwrap_err();
        assert!(err.to_string().contains("jwks_timeout_secs"), "{err}");

        // The shipped example must itself be loadable, or the docs are a trap.
        assert!(GatewayConfig::from_json(&base.to_string()).is_ok());
    }

    fn example() -> serde_json::Value {
        serde_json::from_str(include_str!("../docs/gateway.example.json")).unwrap()
    }

    #[test]
    fn the_sts_key_ring_shape_is_settled_at_load_not_at_first_mint() {
        // The shipped example is the ring form and must load.
        let base = example();
        assert!(GatewayConfig::from_json(&base.to_string()).is_ok());
        let loaded = GatewayConfig::from_json(&base.to_string()).unwrap();
        let (ring, current) = loaded.sts.key_ring();
        assert_eq!(current, "k0");
        assert_eq!(ring.keys().collect::<Vec<_>>(), vec!["k0"]);

        let reject = |mutate: &dyn Fn(&mut serde_json::Value)| -> String {
            let mut cfg = example();
            mutate(&mut cfg);
            GatewayConfig::from_json(&cfg.to_string())
                .expect_err("must not load")
                .to_string()
        };

        // No key material at all.
        assert!(
            reject(&|c| {
                c["sts"].as_object_mut().unwrap().remove("master_keys");
                c["sts"].as_object_mut().unwrap().remove("current_kid");
            })
            .contains("master_key_hex or a non-empty master_keys")
        );
        // Both forms at once: which one mints is then a coin flip.
        assert!(
            reject(&|c| c["sts"]["master_key_hex"] = serde_json::json!("aa"))
                .contains("mutually exclusive")
        );
        // A ring with nobody nominated to mint.
        assert!(
            reject(&|c| {
                c["sts"].as_object_mut().unwrap().remove("current_kid");
            })
            .contains("current_kid is required")
        );
        // A current_kid naming a key that is not there — the shape a botched step 4 of
        // the rotation produces (delete the old entry while still pointing at it).
        assert!(reject(&|c| c["sts"]["current_kid"] = serde_json::json!("k9")).contains("k9"));
        // current_kid without a ring is a no-op that reads as if it did something.
        assert!(
            reject(&|c| {
                let s = c["sts"].as_object_mut().unwrap();
                s.remove("master_keys");
                s.insert("master_key_hex".into(), serde_json::json!("aa"));
            })
            .contains("meaningless")
        );

        // The single-key form still works and normalizes onto the default kid.
        let mut cfg = example();
        let s = cfg["sts"].as_object_mut().unwrap();
        s.remove("master_keys");
        s.remove("current_kid");
        s.insert("master_key_hex".into(), serde_json::json!("aa"));
        let (ring, current) = GatewayConfig::from_json(&cfg.to_string())
            .unwrap()
            .sts
            .key_ring();
        assert_eq!(current, crate::auth::sts::DEFAULT_KID);
        assert_eq!(ring[crate::auth::sts::DEFAULT_KID], "aa");
    }

    #[test]
    fn a_static_credential_inside_the_sts_namespace_is_refused() {
        // Every one of these carries the STS prefix, so `Identity` answers it from the
        // STS authority and never consults the store — a credential provisioned here
        // would silently never work. The near-miss shapes matter as much as the exact
        // one: the middle two are what a pre-key-ring config and a half-done migration
        // look like.
        for key in [
            "HFSTk0.sid-1",
            "HFSTsid-1",
            "HFST",
            "HFSTanything-at-all",
            crate::auth::sts::STS_PREFIX,
        ] {
            let mut cfg = example();
            cfg["static_credentials"] = serde_json::json!([{
                "access_key_id": key,
                "secret_access_key": "s",
                "principal_sub": "alice",
                "tenant": "acme",
                "organization_id": "org-acme",
            }]);
            let err = GatewayConfig::from_json(&cfg.to_string())
                .expect_err(&format!("{key} must be refused"))
                .to_string();
            assert!(err.contains("STS access-key namespace"), "{key}: {err}");
        }

        // Positive control: an ordinary key in the same position loads.
        let mut cfg = example();
        cfg["static_credentials"] = serde_json::json!([{
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "s",
            "principal_sub": "alice",
            "tenant": "acme",
            "organization_id": "org-acme",
        }]);
        assert!(GatewayConfig::from_json(&cfg.to_string()).is_ok());
    }

    #[test]
    fn the_admin_listener_is_on_by_default() {
        // Probes are not opt-in: a config that forgets them would deploy a pod
        // kubernetes cannot health-check, on a distroless image with no shell.
        let mut cfg: serde_json::Value =
            serde_json::from_str(include_str!("../docs/gateway.example.json")).unwrap();
        cfg.as_object_mut().unwrap().remove("admin_listen");
        let loaded = GatewayConfig::from_json(&cfg.to_string()).unwrap();
        assert_eq!(loaded.admin_listen.port(), 8016);
    }
}
