//! Gateway configuration. Secrets (STS keys, per-tenant backend credentials) are
//! expected from a secret store in production; here they load from a JSON file
//! referenced by `$GATEWAY_CONFIG` so the binary is runnable end-to-end.
//!
//! **Every plaintext credential in this file is a [`Secret<String>`]**, not a `String`.
//! These structs `derive(Debug)` and are reachable from a `tracing` call, a panic
//! payload, or any error type that wraps them. `Secret` makes redaction a property of
//! the type rather than of whoever writes the next log line, so a *new* secret field is
//! safe by default. See `src/secret.rs`.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{GatewayError, Result};
use crate::model::BackendKind;
use crate::secret::Secret;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    /// The S3 data-plane listener, at its historical top-level place. Equivalent to
    /// `frontends.s3.listen`; setting both is refused. Required iff the S3 front is enabled
    /// (ADR-009 D1): an SFTP-only process binds no S3 port. Read it through
    /// [`Self::s3_listen`].
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    /// The data-plane fronts, each enabled in its own section. Absent ⇒ the S3 front alone,
    /// so every config written before the SFTP front keeps its behaviour.
    #[serde(default)]
    pub frontends: FrontendsConfig,
    /// Top-level `s3` / `sftp` are refused rather than ignored: this struct tolerates
    /// unknown keys (the `_note` fields), so a section in the wrong place would otherwise
    /// load cleanly and switch nothing — an SFTP pod that serves no SFTP.
    #[serde(default, rename = "s3")]
    misplaced_s3: Option<serde_json::Value>,
    #[serde(default, rename = "sftp")]
    misplaced_sftp: Option<serde_json::Value>,
    /// Liveness / readiness / metrics listener. Always on: the runtime image is
    /// distroless, so a probe cannot `exec` anything, and a TCP probe on the S3 port
    /// succeeds on a pod that has never reached the control plane. Unauthenticated by
    /// design (a probe cannot sign SigV4) — keep it off the ingress.
    #[serde(default = "default_admin_listen")]
    pub admin_listen: SocketAddr,
    /// The STS key material. Required iff something in this process mints or verifies
    /// STS sessions: the S3 front, the mint, or the internal API. An SFTP-only process
    /// carries none (ADR-009 D1). Read it through [`Self::sts`].
    #[serde(default)]
    pub sts: Option<StsConfig>,
    /// Optional key ring for **derived long-lived per-principal keys**. Absent ⇒ the
    /// gateway mints and honours none — but the namespace is not free: `HFSA*` is
    /// refused for static credentials either way (see [`GatewayConfig::validate`]) and
    /// answered by nothing at runtime, so enabling this later cannot silently activate a
    /// credential someone parked in the namespace.
    #[serde(default)]
    pub derived_keys: Option<DerivedKeysConfig>,
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
    /// Whole-request timeout for one bundle fetch. The poller is a single task, so a
    /// control plane that accepts the connection and never answers stalls every later
    /// poll and revocation silently stops landing. Must stay well below
    /// `bundle_poll_secs` or polls queue up behind each other.
    #[serde(default = "default_bundle_timeout_secs")]
    pub bundle_timeout_secs: u64,
    /// Credential presented on every bundle fetch, when the bundle is polled from the
    /// control plane. Optional: a plain file or an unauthenticated URL needs none. When
    /// set it is sent on every request, never on the first one only and never
    /// conditionally ([`crate::bundle_refresh`]). Rejected at load when `bundle_url` is
    /// unset, because a credential that is never sent reads exactly like one that is.
    #[serde(default)]
    pub bundle_shared_secret: Option<Secret<String>>,
    /// Optional STS mint. When present, a server runs on its own listener and issues
    /// gateway session credentials from OIDC tokens.
    #[serde(default)]
    pub sts_mint: Option<StsMintConfig>,
    /// Optional **authenticated** internal surface: the control-plane-mediated session
    /// endpoint. Absent by default — no listener is bound, nothing is served.
    #[serde(default)]
    pub internal: Option<InternalApiConfig>,
}

/// The data-plane fronts (ADR-009 D1). Each is switched on in its own section, next to
/// the settings it switches.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrontendsConfig {
    /// **Absent ⇒ the S3 front is enabled.** See [`S3FrontConfig`].
    #[serde(default)]
    pub s3: Option<S3FrontConfig>,
    /// **Absent ⇒ no SFTP listener** — exactly as with `sts_mint` and `internal`. See
    /// [`SftpConfig`].
    #[serde(default)]
    pub sftp: Option<SftpConfig>,
}

/// The S3 front's section.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3FrontConfig {
    /// Required when the section is present: an operator writes `true` or `false`.
    pub enabled: bool,
    /// The S3 listener. May instead be given as the top-level `listen` (the historical
    /// place); setting both is refused.
    #[serde(default)]
    pub listen: Option<SocketAddr>,
}

/// How a backend closes the create-only check-then-write race (ADR-009 D8).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConditionalCreate {
    /// The commit carries `If-None-Match: *`. An operator **assertion** that the backend
    /// honours it — s0 never assumes support.
    Native,
    /// Re-issue `HeadObject` just before the commit, plus a per-process registry of
    /// in-flight keys. Leaves a one-round-trip cross-replica race.
    #[default]
    CheckThenWrite,
}

/// PROXY protocol v2 reception (ADR-009 D12).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyProtocolConfig {
    /// Peers that MUST send a PROXY v2 header. A trusted peer that does not is
    /// disconnected; an untrusted peer that does is disconnected.
    pub trusted_cidrs: Vec<String>,
}

/// The SFTP front's listener (ADR-009 D1, D3). Only `listen`, `host_keys` and
/// `proxy_protocol` need a restart; the limits are in [`LimitsConfig::sftp`].
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SftpConfig {
    /// Required, no default: whether this process serves SFTP. A section kept with
    /// `enabled: false` binds nothing.
    pub enabled: bool,
    pub listen: SocketAddr,
    /// Paths to mounted host private keys (OpenSSH format, unencrypted). An ed25519 key is
    /// required; an ECDSA P-256 key is optional. Never generated: a missing, unreadable,
    /// world-readable, encrypted, RSA or duplicate key refuses startup.
    pub host_keys: Vec<PathBuf>,
    #[serde(default)]
    pub proxy_protocol: Option<ProxyProtocolConfig>,
    /// On SIGTERM, how long open sessions get to finish in-flight commands before every
    /// open transfer is aborted.
    #[serde(default = "default_sftp_drain_secs")]
    pub drain_secs: u64,
}

fn default_sftp_drain_secs() -> u64 {
    20
}

/// The SFTP front's hot-reloadable limits (ADR-009 D12). Defaults are the ADR's.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SftpLimits {
    pub max_connections: usize,
    /// Per IPv4 /32 or IPv6 /64.
    pub max_connections_per_ip: usize,
    pub max_sessions_per_subject: usize,
    /// Pre-authentication connections per IP per minute (token bucket refill rate).
    pub preauth_rate_per_ip_per_min: u32,
    pub preauth_burst_per_ip: u32,
    /// From TCP accept to authentication success, PROXY header included.
    pub handshake_timeout_secs: u64,
    /// 1–10.
    pub max_auth_attempts: usize,
    /// Public keys offered without a signature, per connection.
    pub max_key_probes: usize,
    /// Failures within `auth_failure_window_secs` that trigger a ban.
    pub auth_failure_ban_threshold: u32,
    pub auth_failure_window_secs: u64,
    pub auth_failure_ban_secs: u64,
    /// LRU bound on the ban table.
    pub ban_table_size: usize,
    /// Session idle bound (no SFTP request).
    pub idle_timeout_secs: u64,
    /// Transfer idle bound (no WRITE).
    pub transfer_idle_timeout_secs: u64,
    pub max_file_size: u64,
    /// Per session, per direction. 0 ⇒ unlimited.
    pub bandwidth_bytes_per_sec: u64,
    /// 5–64 MiB.
    pub part_size: usize,
    /// 1–4.
    pub max_inflight_parts: usize,
    /// At most `part_size`.
    pub reorder_window: usize,
    pub max_write_handles: usize,
    pub max_transfer_memory: usize,
    pub max_sftp_packet_len: usize,
    /// Bytes a download prefetches from the backend ahead of the client's READs, per
    /// open read handle. Bounded: a slow client stops the prefetch, never grows it.
    pub read_ahead: usize,
}

impl Default for SftpLimits {
    fn default() -> Self {
        SftpLimits {
            max_connections: 256,
            max_connections_per_ip: 16,
            max_sessions_per_subject: 8,
            preauth_rate_per_ip_per_min: 10,
            preauth_burst_per_ip: 20,
            handshake_timeout_secs: 30,
            max_auth_attempts: 6,
            max_key_probes: 10,
            auth_failure_ban_threshold: 10,
            auth_failure_window_secs: 300,
            auth_failure_ban_secs: 900,
            ban_table_size: 65_536,
            idle_timeout_secs: 300,
            transfer_idle_timeout_secs: 120,
            max_file_size: 50 * 1024 * 1024 * 1024,
            bandwidth_bytes_per_sec: 0,
            part_size: 8 * 1024 * 1024,
            max_inflight_parts: 2,
            reorder_window: 2 * 1024 * 1024,
            max_write_handles: 2,
            max_transfer_memory: 1024 * 1024 * 1024,
            max_sftp_packet_len: 262_144,
            read_ahead: 1024 * 1024,
        }
    }
}

impl SftpLimits {
    /// The worst-case memory one upload transfer can hold, reserved up front at OPEN.
    pub fn transfer_reservation(&self) -> usize {
        self.part_size * (1 + self.max_inflight_parts) + self.reorder_window
    }

    fn validate(&self) -> std::result::Result<(), String> {
        const MIB: usize = 1024 * 1024;
        let positive: [(&str, u64); 12] = [
            ("max_connections", self.max_connections as u64),
            ("max_connections_per_ip", self.max_connections_per_ip as u64),
            (
                "max_sessions_per_subject",
                self.max_sessions_per_subject as u64,
            ),
            (
                "preauth_rate_per_ip_per_min",
                u64::from(self.preauth_rate_per_ip_per_min),
            ),
            ("preauth_burst_per_ip", u64::from(self.preauth_burst_per_ip)),
            ("handshake_timeout_secs", self.handshake_timeout_secs),
            ("max_key_probes", self.max_key_probes as u64),
            ("idle_timeout_secs", self.idle_timeout_secs),
            (
                "transfer_idle_timeout_secs",
                self.transfer_idle_timeout_secs,
            ),
            ("max_write_handles", self.max_write_handles as u64),
            ("ban_table_size", self.ban_table_size as u64),
            (
                "auth_failure_ban_threshold",
                u64::from(self.auth_failure_ban_threshold),
            ),
        ];
        for (name, v) in positive {
            if v == 0 {
                return Err(format!(
                    "limits.sftp.{name} must be > 0; zero is not 'unbounded' here"
                ));
            }
        }
        if !(1..=10).contains(&self.max_auth_attempts) {
            return Err("limits.sftp.max_auth_attempts must be within 1..=10".into());
        }
        if !(5 * MIB..=64 * MIB).contains(&self.part_size) {
            return Err("limits.sftp.part_size must be within 5 MiB..=64 MiB".into());
        }
        if !(1..=4).contains(&self.max_inflight_parts) {
            return Err("limits.sftp.max_inflight_parts must be within 1..=4".into());
        }
        if self.reorder_window > self.part_size {
            return Err("limits.sftp.reorder_window must not exceed part_size".into());
        }
        if self.max_file_size > (self.part_size as u64) * 10_000 {
            return Err(format!(
                "limits.sftp.max_file_size {} exceeds part_size × 10,000 = {}; a multipart \
                 upload has at most 10,000 parts",
                self.max_file_size,
                (self.part_size as u64) * 10_000
            ));
        }
        if self.max_transfer_memory < self.transfer_reservation() {
            return Err(format!(
                "limits.sftp.max_transfer_memory {} is below one transfer's reservation {}; \
                 no upload could ever start",
                self.max_transfer_memory,
                self.transfer_reservation()
            ));
        }
        if self.max_sftp_packet_len < 34_000 {
            return Err(
                "limits.sftp.max_sftp_packet_len must be ≥ 34000 (RFC: servers must accept \
                 32768-byte data plus headers)"
                    .into(),
            );
        }
        if self.read_ahead == 0 {
            return Err("limits.sftp.read_ahead must be > 0".into());
        }
        Ok(())
    }
}

/// The authenticated internal control-plane surface (`POST /internal/v1/sts/sessions`).
///
/// Deliberately **its own listener**: the admin listener is unauthenticated by
/// construction (probes cannot carry a secret), and a credential-minting route sharing
/// that port would make "is this request authenticated?" a routing question — which is
/// how fail-open surfaces are built. See [`crate::internal`].
#[derive(Debug, Clone, Deserialize)]
pub struct InternalApiConfig {
    #[serde(default = "default_internal_listen")]
    pub listen: SocketAddr,
    /// The caller's `X-Shared-Secret`. **Optional in the schema, mandatory in effect**:
    /// absent, empty or whitespace-only, every request to this listener is refused. Not
    /// a load-time error, because crash-looping a pod whose *data plane* is healthy is
    /// the larger failure; the refusal is loud (an `error!` at startup, a 401 per
    /// request) rather than silent, and is never a reason to allow.
    #[serde(default)]
    pub shared_secret: Option<Secret<String>>,
    /// Ceiling on a minted session's lifetime, in seconds. The caller asks for a
    /// duration; anything above this is **clamped down** to it (never refused — see
    /// [`crate::internal`] for why) and logged.
    #[serde(default = "default_max_session_ttl_secs")]
    pub max_session_ttl_secs: u64,
}

/// OIDC → gateway-credentials mint. Backend-agnostic: verifies an identity-provider
/// token and mints the gateway's own session (never a backend STS). Neither door takes
/// a separate credential, correctly: the OIDC token **is** the credential.
///
/// * bearer-token JSON exchange: needs `tenant_claim`/`org_claim`, mints *user* sessions;
/// * `Action=AssumeRoleWithWebIdentity` ([`crate::webidentity`]): the AWS STS query
///   protocol stock SDKs speak, tenant from the `RoleArn`, service accounts included.
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

    // ── the AssumeRoleWithWebIdentity surface ──────────────────────────────────
    /// Serve `Action=AssumeRoleWithWebIdentity` on this listener.
    ///
    /// Defaults **on**: an operator who has gone to the trouble of pointing s0 at an IdP
    /// wants clients to be able to get a credential, and this is the door stock SDKs
    /// speak. Set it to `false` to run the bearer door alone.
    #[serde(default = "default_true")]
    pub web_identity_enabled: bool,

    /// Audiences accepted on the web-identity door. Empty ⇒ `[audience]`.
    ///
    /// Separate from the strictly-checked `audience` because a `client_credentials`
    /// service-account token typically carries `aud: "account"` and names the client in
    /// **`azp`**; this door matches either, as Ceph RGW and MinIO do. Never skipped — an
    /// empty list falls back to `[audience]`.
    #[serde(default)]
    pub web_identity_audiences: Vec<String>,

    /// Expected role name, with `{tenant}` substituted from the presented `RoleArn`.
    /// Absent ⇒ any non-empty role name is accepted; set, it turns a mistyped ARN into a
    /// clear refusal instead of a session in a tenant the caller did not mean. A
    /// **diagnostic**, never an authorization input — authority comes from the bundle.
    #[serde(default)]
    pub role_name_template: Option<String>,

    /// Ceiling on `DurationSeconds`. Above it, **clamped down** and logged — never
    /// refused; see [`crate::webidentity::WebIdentitySts::clamp_duration`] for why the
    /// deviation from AWS (which returns `ValidationError`) is the safer direction for a
    /// credential-acquisition call.
    #[serde(default = "default_max_session_ttl_secs")]
    pub max_duration_secs: u64,

    // ── the listener's own hardening bounds ──────────────────────────────
    /// Max concurrent connections on the mint listener.
    ///
    /// The one socket that is both internet-facing and unauthenticated by design, with
    /// no rate limiting in front of it. It is a **queue, not a refusal**: the accept
    /// loop takes its permit *before* it accepts, so excess connections wait in the
    /// kernel backlog instead of getting an error, and saturation is only counted
    /// (`s0_mint_connection_limit_saturated_total`). `0` is refused at load.
    #[serde(default = "default_mint_max_connections")]
    pub max_connections: usize,

    /// Hard ceiling on the lifetime of one accepted mint connection, in seconds.
    ///
    /// Without it the connection bound above makes slowloris *easier*: an attacker
    /// dribbling bytes on `max_connections` sockets holds every permit forever. A plain
    /// `tokio::time::timeout` rather than hyper's `header_read_timeout`, whose timer does
    /// not survive `into_owned()`. `0` is refused at load, not read as "no bound".
    #[serde(default = "default_mint_connection_timeout_secs")]
    pub connection_timeout_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StaticCredentialConfig {
    pub access_key_id: String,
    pub secret_access_key: Secret<String>,
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
    pub master_key_hex: Option<Secret<String>>,
    /// The master-key **ring**: `kid -> hex key`. The `kid` lands in every access-key
    /// id this gateway mints (`HFST<kid>.<sid>`), which is what lets a key be retired
    /// without invalidating the sessions it already minted. See the rotation procedure
    /// in [`crate::auth::sts`].
    #[serde(default)]
    pub master_keys: std::collections::BTreeMap<String, Secret<String>>,
    /// Which ring entry mints new sessions. Required with `master_keys`, and never
    /// inferred: "whichever key sorts first" is not a decision an operator made.
    #[serde(default)]
    pub current_kid: Option<String>,
    /// Hex-encoded signing key (≥32 bytes) authenticating session tokens.
    pub signing_key_hex: Secret<String>,
    #[serde(default = "default_session_ttl_secs")]
    pub session_ttl_secs: u64,
}

impl StsConfig {
    /// The configured ring as `(kid -> hex key, current kid)`, normalizing the
    /// single-key form. Shape errors are raised at load by
    /// [`GatewayConfig::validate`], so this cannot be reached with an invalid pair.
    pub fn key_ring(&self) -> (std::collections::BTreeMap<String, Secret<String>>, String) {
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

/// The master-key ring for derived long-lived per-principal keys.
///
/// Mirrors [`StsConfig`]'s ring exactly, so an operator learns one convention. There is
/// **no signing key**: a derived key has no session token to sign; the MAC inside the
/// access-key id is what proves it, and it is derived from this ring.
#[derive(Debug, Clone, Deserialize)]
pub struct DerivedKeysConfig {
    /// Hex-encoded master key (≥32 bytes). Sugar for a one-entry `master_keys` ring
    /// under `auth::derived::DEFAULT_KID`; mutually exclusive with it.
    #[serde(default)]
    pub master_key_hex: Option<Secret<String>>,
    /// The master-key **ring**: `kid -> hex key`. The `kid` lands in every access-key id
    /// minted from it (`HFSA<kid>.<payload>.<mac>`), which is what lets a key be rotated
    /// without invalidating every outstanding one. Unlike the STS ring there is **no TTL
    /// after which stragglers are gone**: retiring an entry here permanently revokes
    /// every long-lived key minted under it, so it must be paired with reissuing them.
    #[serde(default)]
    pub master_keys: std::collections::BTreeMap<String, Secret<String>>,
    /// Which ring entry mints new keys. Required with `master_keys`, never inferred.
    #[serde(default)]
    pub current_kid: Option<String>,
}

impl DerivedKeysConfig {
    /// The configured ring as `(kid -> hex key, current kid)`, normalizing the single-key
    /// form. Shape errors are raised at load by [`GatewayConfig::validate`].
    pub fn key_ring(&self) -> (std::collections::BTreeMap<String, Secret<String>>, String) {
        match &self.master_key_hex {
            Some(hex) if self.master_keys.is_empty() => (
                std::collections::BTreeMap::from([(
                    crate::auth::derived::DEFAULT_KID.to_string(),
                    hex.clone(),
                )]),
                crate::auth::derived::DEFAULT_KID.to_string(),
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
    /// The label key carrying org attribution. Its *value* is always the request's
    /// `organization_id`, resolved from the routing table and never from a claim.
    ///
    /// Configurable because a decision-log consumer routes on the key it already uses;
    /// a consumer that reads a different one drops every record while still answering
    /// `201`, so the producer never learns.
    #[serde(default = "default_org_label_key")]
    pub organization_label_key: String,
    /// Static labels stamped on every record, decision and gate alike. Empty by default.
    ///
    /// This is the deployment's own routing vocabulary — a consumer that dispatches on
    /// `{"acme.example/log-type": "s3-gateway"}` sets it here rather than having s0 ship
    /// somebody else's domain as a constant.
    #[serde(default)]
    pub extra_labels: BTreeMap<String, String>,
}

fn default_org_label_key() -> String {
    crate::audit::DEFAULT_ORG_LABEL_KEY.to_string()
}

impl Default for AuditFileConfig {
    fn default() -> Self {
        AuditFileConfig {
            sink_url: "http://127.0.0.1:9000/api/v1/decision-logs".into(),
            spill_path: PathBuf::from("/var/lib/s0/audit-spill.ndjson"),
            backend: crate::audit::AuditBackendKind::default(),
            organization_label_key: default_org_label_key(),
            extra_labels: BTreeMap::new(),
        }
    }
}

/// Request-shape + hardening limits. Mapped onto `s3s::S3Config` plus the
/// gateway's own semantic caps enforced before the PDP fan-out.
#[derive(Debug, Clone, Deserialize)]
pub struct LimitsConfig {
    pub xml_max_body_size: usize,
    /// Ceiling on the file part of a browser form upload (`PostObject`).
    ///
    /// **Not** an ordinary request cap: s3s aggregates the whole file into memory before
    /// any authorization happens, so this bounds what an *unauthorized* caller can make
    /// the process allocate, times `max_connections`. s3s's own default is 5 GiB.
    /// Defaulted, unlike its neighbours, so a `limits` block that omits it is still safe.
    #[serde(default = "default_post_object_max_file_size")]
    pub post_object_max_file_size: u64,
    pub presigned_url_max_skew_time_secs: u32,
    /// AWS semantic cap: `DeleteObjects` ≤ 1000 keys (enforced before OPA).
    pub max_delete_keys: usize,
    /// AWS semantic cap: ≤ 10 tags per object (`PutObjectTagging`).
    ///
    /// A **resource bound**, never a deny mechanism: exceeding it produces a real
    /// `write_object_tags` Deny sub-decision that is audited, not a bare
    /// `InvalidRequest` that short-circuits ahead of the audit call. Set it to 0 and
    /// every tag write is refused *and recorded*.
    #[serde(default = "default_max_tag_count")]
    pub max_tag_count: usize,
    /// Multi-prefix list fan-out bound; above it the list fails closed.
    pub max_list_fanout: usize,
    /// Page size ceiling for a **filtered** `ListBuckets`.
    ///
    /// The gateway owns this pagination outright — filtering the backend's answer makes
    /// its `max-buckets` and `continuation-token` meaningless to the client — so a
    /// caller-supplied `max-buckets` is clamped to this rather than honored.
    #[serde(default = "default_max_buckets_per_page")]
    pub max_buckets_per_page: usize,
    /// How many backend `ListBuckets` pages one client request may drain.
    ///
    /// A filtered listing cannot be produced incrementally: the gateway sorts the whole
    /// visible set before it can cut a stable page (see `proxy::bucketfilter`), so it
    /// reads the tenant's bucket list to the end. A tenant with more buckets than this
    /// is **refused**, loudly — an under-reported bucket list is indistinguishable from
    /// a revoked grant.
    #[serde(default = "default_max_bucket_list_pages")]
    pub max_bucket_list_pages: usize,
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
    /// disables it, deliberately: the SDK measures this from *request initiation*, so on
    /// a bulk `PutObject`/`UploadPart` any finite value caps the size of an object that
    /// can be written over a slow link. Set it only where backends are known-local and
    /// objects known-small.
    #[serde(default)]
    pub backend_read_timeout_secs: u64,
    /// The SFTP front's limits (ADR-009 D12). Defaulted as a block, so a `limits` section
    /// written before the SFTP front stays valid.
    #[serde(default)]
    pub sftp: SftpLimits,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        LimitsConfig {
            xml_max_body_size: 20 * 1024 * 1024,
            post_object_max_file_size: default_post_object_max_file_size(),
            presigned_url_max_skew_time_secs: 900,
            max_delete_keys: 1000,
            max_tag_count: default_max_tag_count(),
            max_list_fanout: 16,
            max_buckets_per_page: default_max_buckets_per_page(),
            max_bucket_list_pages: default_max_bucket_list_pages(),
            max_connections: 1024,
            header_read_timeout_secs: 15,
            backend_connect_timeout_secs: 5,
            backend_read_timeout_secs: 0,
            sftp: SftpLimits::default(),
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
    /// How a create-only write (`create_objects`) is kept from overwriting on this
    /// backend (ADR-009 D8). `native` asserts that the backend honours `If-None-Match: *`
    /// on `PutObject` and `CompleteMultipartUpload`; s0 never assumes it. Absent ⇒
    /// `check_then_write`. Read by both fronts: the S3 front authorizes a conditional
    /// write as `create_objects` only on a `native` backend.
    #[serde(default)]
    pub conditional_create: ConditionalCreate,
}

/// Maps a tenant to its Org, its backend, and the per-tenant backend
/// credential the proxy re-signs with (never the caller's).
#[derive(Debug, Clone, Deserialize)]
pub struct TenantConfig {
    pub tenant: String,
    pub organization_id: String,
    pub backend_id: String,
    pub owner_access_key: String,
    pub owner_secret_key: Secret<String>,
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
    /// The interpolation lets a single ConfigMap render per-pod values — above all the
    /// audit spill path, which **must** be pod-unique
    /// (`"/var/lib/s0/audit-spill-${POD_NAME}.ndjson"`); two replicas sharing one
    /// destroy each other's records. An unset variable with no default is a hard error,
    /// because a path collapsing to `audit-spill-.ndjson` on every pod is that same bug.
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
        self.validate_fronts()?;
        self.validate_sts_key_ring()?;
        self.validate_derived_key_ring()?;
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
            // The STS namespace is `HFST*` in its entirety, not just the well-formed
            // `HFST<kid>.<sid>` shape: `Identity` answers every key in it from the STS
            // authority alone, so a static entry here is simply never reachable and an
            // operator would provision a credential that silently does not work. The
            // near-miss shapes (a bare prefix, an `HFST<sid>` form) are what a migration
            // produces.
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
            // The same rule for the derived long-lived namespace. `HFSA` differs from
            // `HFST` in one character, and `Identity::secret_key` answers every key with
            // this prefix from the derived-key half alone, INCLUDING when derived keys
            // are off, where the answer is "no". Without this check the credential
            // silently never resolves — and starts resolving the day the feature is on.
            if crate::auth::derived::DerivedKeyAuthority::is_derived_access_key(&c.access_key_id) {
                return Err(GatewayError::Config(format!(
                    "static credential {} is inside the DERIVED long-lived access-key \
                     namespace {:?}*; derived keys are minted as {}<kid>{}<payload>{}<mac> \
                     and every key carrying the prefix is answered by the derived-key \
                     authority (or by nothing at all, when `derived_keys` is unset), so \
                     this credential would never resolve",
                    c.access_key_id,
                    crate::auth::derived::DERIVED_PREFIX,
                    crate::auth::derived::DERIVED_PREFIX,
                    crate::auth::derived::FIELD_SEP,
                    crate::auth::derived::FIELD_SEP,
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
        // A zero timeout is not "no timeout" anywhere in this file: it is an instant
        // failure. Reject it at load rather than let an operator discover that at
        // runtime.
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
        // A bundle credential with no remote source is never sent. Left to run, it is
        // indistinguishable from an authenticated poll — an operator would believe the
        // bundle endpoint is being called with a credential when it is not being called
        // at all.
        if self.bundle_shared_secret.is_some() && self.bundle_url.is_none() {
            return Err(GatewayError::Config(
                "bundle_shared_secret is set but bundle_url is not; the credential would \
                 never be sent (the bundle is being re-read from bundle_path)"
                    .into(),
            ));
        }
        self.validate_internal_listener()?;
        self.validate_mint_listener()?;
        self.validate_sftp()?;
        Ok(())
    }

    /// Whether this process serves the S3 data plane. An absent `s3` section means yes.
    pub fn s3_enabled(&self) -> bool {
        self.frontends.s3.as_ref().is_none_or(|s| s.enabled)
    }

    /// The SFTP section, when it is present **and** enabled.
    pub fn sftp_enabled(&self) -> Option<&SftpConfig> {
        self.frontends.sftp.as_ref().filter(|s| s.enabled)
    }

    /// Wherever the S3 listener was written: `frontends.s3.listen` or top-level `listen`.
    fn s3_listen_configured(&self) -> Option<SocketAddr> {
        self.frontends
            .s3
            .as_ref()
            .and_then(|s| s.listen)
            .or(self.listen)
    }

    /// The S3 listener. `None` exactly when the S3 front is disabled — validated at load.
    pub fn s3_listen(&self) -> Option<SocketAddr> {
        if self.s3_enabled() {
            self.s3_listen_configured()
        } else {
            None
        }
    }

    /// The STS key material, when this process needs it. Validated at load: present
    /// whenever the S3 front, the mint or the internal API is on.
    pub fn sts(&self) -> Option<&StsConfig> {
        self.sts.as_ref()
    }

    /// True when something in this process mints or verifies STS sessions.
    pub fn needs_sts(&self) -> bool {
        self.s3_enabled() || self.sts_mint.is_some() || self.internal.is_some()
    }

    /// Every listener this process binds, by name, for the uniqueness check.
    fn listeners(&self) -> Vec<(&'static str, SocketAddr)> {
        let mut v = vec![("admin_listen", self.admin_listen)];
        if let Some(l) = self.s3_listen() {
            v.push(("listen", l));
        }
        if let Some(m) = &self.sts_mint {
            v.push(("sts_mint.listen", m.listen));
        }
        if let Some(i) = &self.internal {
            v.push(("internal.listen", i.listen));
        }
        if let Some(s) = self.sftp_enabled() {
            v.push(("frontends.sftp.listen", s.listen));
        }
        v
    }

    /// The per-front `enabled` switches (ADR-009 D1), and the fields that became
    /// conditional on them.
    fn validate_fronts(&self) -> Result<()> {
        for (name, present) in [
            ("s3", self.misplaced_s3.is_some()),
            ("sftp", self.misplaced_sftp.is_some()),
        ] {
            if present {
                return Err(GatewayError::Config(format!(
                    "`{name}` must be under `frontends` (frontends.{name}); at the top level \
                     it would switch nothing"
                )));
            }
        }
        let s3 = self.s3_enabled();
        let sftp = self.sftp_enabled().is_some();
        if !s3 && !sftp {
            return Err(GatewayError::Config(
                "both data-plane fronts are disabled (frontends.s3.enabled is false and no \
                 enabled frontends.sftp section); this process would serve nothing"
                    .into(),
            ));
        }
        if self.listen.is_some()
            && self
                .frontends
                .s3
                .as_ref()
                .is_some_and(|s| s.listen.is_some())
        {
            return Err(GatewayError::Config(
                "the S3 listener is set twice (top-level listen and frontends.s3.listen); \
                 keep one"
                    .into(),
            ));
        }
        if s3 && self.s3_listen_configured().is_none() {
            return Err(GatewayError::Config(
                "listen (or frontends.s3.listen) is required while the S3 front is enabled \
                 (set frontends.s3.enabled=false for an SFTP-only process)"
                    .into(),
            ));
        }
        if !s3 && self.s3_listen_configured().is_some() {
            return Err(GatewayError::Config(
                "listen is set but frontends.s3.enabled is false; a listener that is never bound reads \
                 exactly like one that is — remove it or enable the S3 front"
                    .into(),
            ));
        }
        if self.needs_sts() && self.sts.is_none() {
            return Err(GatewayError::Config(
                "sts is required: the S3 front, sts_mint and internal all mint or verify STS \
                 sessions"
                    .into(),
            ));
        }
        if s3 && sftp {
            tracing::warn!(
                "both the S3 and the SFTP fronts are enabled in one process; this is for \
                 development — production runs SFTP as its own Deployment (ADR-009 D1)"
            );
        }
        Ok(())
    }

    /// The SFTP section's own rules. Shape is validated even when `enabled` is false, so
    /// flipping the switch later cannot be the moment a typo is discovered.
    fn validate_sftp(&self) -> Result<()> {
        self.limits.sftp.validate().map_err(GatewayError::Config)?;
        let Some(s) = &self.frontends.sftp else {
            return Ok(());
        };
        if s.host_keys.is_empty() {
            return Err(GatewayError::Config(
                "frontends.sftp.host_keys is empty; host keys are mounted, never generated".into(),
            ));
        }
        let mut seen = std::collections::HashSet::new();
        for k in &s.host_keys {
            if !seen.insert(k) {
                return Err(GatewayError::Config(format!(
                    "frontends.sftp.host_keys lists {k:?} twice"
                )));
            }
        }
        if let Some(p) = &s.proxy_protocol {
            for c in &p.trusted_cidrs {
                crate::sftp::limits::Cidr::parse(c).map_err(|e| {
                    GatewayError::Config(format!(
                        "frontends.sftp.proxy_protocol.trusted_cidrs: {e}"
                    ))
                })?;
            }
        }
        if s.drain_secs == 0 {
            return Err(GatewayError::Config(
                "frontends.sftp.drain_secs must be > 0".into(),
            ));
        }
        // Every bound listener on its own port: whichever binds second loses, and the
        // loser finds out at runtime.
        let listeners = self.listeners();
        for (i, (a, x)) in listeners.iter().enumerate() {
            for (b, y) in &listeners[i + 1..] {
                if x.port() == y.port()
                    && (*a == "frontends.sftp.listen" || *b == "frontends.sftp.listen")
                {
                    return Err(GatewayError::Config(format!(
                        "{a} {x} shares a port with {b} {y}"
                    )));
                }
            }
        }
        Ok(())
    }

    /// The mint listener may not share a port with the data plane or with the probes.
    ///
    /// It is deliberately unauthenticated and published through an Ingress. Sharing
    /// **`listen`** stops the S3 data plane coming up (whichever binds second loses);
    /// sharing **`admin_listen`** puts credential minting on the probe/scrape port. The
    /// `internal` collision is checked in [`Self::validate_internal_listener`].
    fn validate_mint_listener(&self) -> Result<()> {
        let Some(m) = &self.sts_mint else {
            return Ok(());
        };
        if let Some(listen) = self.s3_listen()
            && m.listen.port() == listen.port()
        {
            return Err(GatewayError::Config(format!(
                "sts_mint.listen {} shares a port with the S3 data-plane listener {}; \
                 the mint is a separate, deliberately unauthenticated socket and must \
                 not be a route inside the SigV4-authenticated data plane",
                m.listen, listen
            )));
        }
        if m.listen.port() == self.admin_listen.port() {
            return Err(GatewayError::Config(format!(
                "sts_mint.listen {} shares a port with admin_listen {}; the admin \
                 listener is published for probes and scraping and must never also \
                 mint credentials",
                m.listen, self.admin_listen
            )));
        }
        if m.max_duration_secs == 0 {
            return Err(GatewayError::Config(
                "sts_mint.max_duration_secs must be > 0; a zero ceiling clamps every \
                 minted session to nothing and is not a way to disable the surface \
                 (set sts_mint.web_identity_enabled=false for that)"
                    .into(),
            ));
        }
        // Both of these read like "no limit" and mean the opposite. A zero-permit
        // semaphore parks the accept loop forever while the port stays bound and still
        // passes a TCP probe; a zero timeout closes every connection before its first
        // byte. Both are silent, total outages of the credential path.
        if m.max_connections == 0 {
            return Err(GatewayError::Config(
                "sts_mint.max_connections must be > 0; zero is not 'unbounded', it is a \
                 listener that accepts no connection at all while still binding the port \
                 and still passing a TCP probe"
                    .into(),
            ));
        }
        if m.connection_timeout_secs == 0 {
            return Err(GatewayError::Config(
                "sts_mint.connection_timeout_secs must be > 0; zero is not 'no timeout', \
                 it closes every connection before it can be answered. Raise it if the \
                 default of 30 s is too short for your IdP"
                    .into(),
            ));
        }
        Ok(())
    }

    /// The credential-minting listener may not share a port with anything else this
    /// process serves.
    ///
    /// The **admin listener** is unauthenticated (a probe cannot present a secret) and
    /// published for scraping; the **S3 listener** is Ingress-fronted. Either collision
    /// puts a credential-issuing endpoint somewhere it must never be. Refused at load,
    /// not at bind time, where only the loser of the race finds out.
    fn validate_internal_listener(&self) -> Result<()> {
        let Some(i) = &self.internal else {
            return Ok(());
        };
        if i.listen.port() == self.admin_listen.port() {
            return Err(GatewayError::Config(format!(
                "internal.listen {} shares a port with admin_listen {}; the admin \
                 listener is UNAUTHENTICATED by design (a probe cannot present a \
                 secret) and a credential-minting endpoint must never share it",
                i.listen, self.admin_listen
            )));
        }
        if let Some(listen) = self.s3_listen()
            && i.listen.port() == listen.port()
        {
            return Err(GatewayError::Config(format!(
                "internal.listen {} shares a port with the S3 data-plane listener {}; \
                 the data plane is fronted by an Ingress and a credential-minting \
                 endpoint must never be reachable from it",
                i.listen, listen
            )));
        }
        if let Some(m) = &self.sts_mint
            && i.listen.port() == m.listen.port()
        {
            return Err(GatewayError::Config(format!(
                "internal.listen {} shares a port with sts_mint.listen {}",
                i.listen, m.listen
            )));
        }
        if i.max_session_ttl_secs == 0 {
            return Err(GatewayError::Config(
                "internal.max_session_ttl_secs must be > 0; a zero ceiling clamps every \
                 minted session to nothing and is not a way to disable the endpoint \
                 (omit the `internal` section for that)"
                    .into(),
            ));
        }
        Ok(())
    }

    /// The STS key ring must be unambiguous *at load*, not at first mint.
    ///
    /// Otherwise the gateway comes up issuing credentials under a key nobody chose, or
    /// comes up unable to mint at all — and the second is only discovered by the first
    /// user who tries to get a credential.
    fn validate_sts_key_ring(&self) -> Result<()> {
        let Some(s) = &self.sts else {
            return Ok(());
        };
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

    /// The derived-key ring's shape, plus the one rule that is not a copy of the STS
    /// ring's: **no key may be shared between the two credential classes.**
    ///
    /// The classes have different lifetimes and revocation stories; sharing material
    /// collapses them into one blast radius — retiring a `kid` to revoke a long-lived
    /// key would silently 403 every live session. The STS signing key is covered too.
    fn validate_derived_key_ring(&self) -> Result<()> {
        let Some(d) = &self.derived_keys else {
            return Ok(());
        };
        match (&d.master_key_hex, d.master_keys.is_empty()) {
            (None, true) => {
                return Err(GatewayError::Config(
                    "derived_keys needs either master_key_hex or a non-empty master_keys ring; \
                     omit the whole `derived_keys` section to switch the feature off"
                        .into(),
                ));
            }
            (Some(_), false) => {
                return Err(GatewayError::Config(
                    "derived_keys.master_key_hex and derived_keys.master_keys are mutually \
                     exclusive; master_key_hex is shorthand for a one-entry ring"
                        .into(),
                ));
            }
            (Some(_), true) => {
                if d.current_kid.is_some() {
                    return Err(GatewayError::Config(
                        "derived_keys.current_kid is meaningless without \
                         derived_keys.master_keys"
                            .into(),
                    ));
                }
            }
            (None, false) => {
                let Some(kid) = &d.current_kid else {
                    return Err(GatewayError::Config(
                        "derived_keys.current_kid is required with derived_keys.master_keys: \
                         which key mints new credentials is an operator decision, never \
                         inferred"
                            .into(),
                    ));
                };
                if !d.master_keys.contains_key(kid) {
                    return Err(GatewayError::Config(format!(
                        "derived_keys.current_kid {kid:?} is not one of \
                         derived_keys.master_keys {:?}",
                        d.master_keys.keys().collect::<Vec<_>>()
                    )));
                }
            }
        }
        let (derived_ring, _) = d.key_ring();
        let Some(sts) = &self.sts else {
            return Ok(());
        };
        let (sts_ring, _) = sts.key_ring();
        for (kid, key) in &derived_ring {
            if key.expose() == sts.signing_key_hex.expose() {
                return Err(GatewayError::Config(format!(
                    "derived_keys master key {kid} is the same material as sts.signing_key_hex; \
                     the two credential classes must not share a key"
                )));
            }
            if let Some(sts_kid) = sts_ring
                .iter()
                .find(|(_, k)| k.expose() == key.expose())
                .map(|(k, _)| k)
            {
                return Err(GatewayError::Config(format!(
                    "derived_keys master key {kid} is the same material as sts master key \
                     {sts_kid}; the two credential classes must not share a key — retiring a \
                     kid to revoke long-lived credentials would then 403 every live session"
                )));
            }
        }
        Ok(())
    }

    /// The STS session lifetime. Only meaningful where [`Self::needs_sts`]; an SFTP-only
    /// process falls back to the default and mints nothing with it.
    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(
            self.sts
                .as_ref()
                .map_or_else(default_session_ttl_secs, |s| s.session_ttl_secs),
        )
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
/// 8017: next to the admin port and deliberately *not* it. `0.0.0.0` because the caller
/// runs in a different pod — loopback would make the endpoint unreachable. Reachability
/// is fenced by the network policy and by authentication, never by the bind address.
fn default_internal_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8017))
}
/// One hour, matching `default_session_ttl_secs`.
fn default_max_session_ttl_secs() -> u64 {
    3600
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
/// 256 concurrent connections on the mint.
///
/// Sized against the largest legitimate burst: a deployment rolling many pods at once,
/// each minting on startup, which the kubernetes default `maxSurge: 25%` already caps at
/// a few dozen. A quarter of the data plane's 1024, because a client mints once and then
/// uses the credential for an hour.
fn default_mint_max_connections() -> usize {
    256
}
/// 30 s of connection lifetime.
///
/// An order of magnitude above the worst legitimate request (a `kid`-miss mint pays one
/// JWKS fetch, bounded by `jwks_timeout_secs`). A *lifetime*, not an idle timeout, so the
/// only client it inconveniences is one reusing a pooled connection more than 30 s after
/// opening it — which every HTTP client already retries.
fn default_mint_connection_timeout_secs() -> u64 {
    30
}
fn default_backend_connect_timeout_secs() -> u64 {
    5
}
/// 64 MiB. See the field docs: s3s buffers this entire body in memory *before* the
/// gateway authorizes anything, so it is an unauthenticated allocation bound.
fn default_post_object_max_file_size() -> u64 {
    64 * 1024 * 1024
}
/// AWS: 10 tags per object.
fn default_max_tag_count() -> usize {
    10
}
/// One `ListBuckets` page, gateway-owned (the filtering makes the backend's own
/// pagination meaningless to the client).
fn default_max_buckets_per_page() -> usize {
    1000
}

fn default_max_bucket_list_pages() -> usize {
    64
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

    /// A complete config, with `patch` merged over the top level. `null` removes a key.
    fn fronts(patch: serde_json::Value) -> Result<GatewayConfig> {
        let mut v = serde_json::json!({
            "listen": "127.0.0.1:8014",
            "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
            "pdp": { "mode": "embedded" },
            "backends": [ { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:7480" } ],
            "tenants": [ { "tenant": "acme", "organization_id": "org-acme", "backend_id": "bay-1",
                           "owner_access_key": "O", "owner_secret_key": "S" } ],
            "bundle_path": "/dev/null"
        });
        for (k, val) in patch.as_object().expect("object patch") {
            if val.is_null() {
                v.as_object_mut().unwrap().remove(k);
            } else {
                v[k] = val.clone();
            }
        }
        GatewayConfig::from_json(&v.to_string())
    }

    fn sftp(enabled: bool) -> serde_json::Value {
        serde_json::json!({
            "enabled": enabled,
            "listen": "127.0.0.1:2222",
            "host_keys": ["/etc/s0/sftp/ssh_host_ed25519_key"]
        })
    }

    #[test]
    fn an_absent_frontends_key_means_the_s3_front_alone_as_before() {
        let c = fronts(serde_json::json!({})).expect("every pre-SFTP config still loads");
        assert!(c.s3_enabled());
        assert_eq!(c.s3_listen(), Some("127.0.0.1:8014".parse().unwrap()));
        assert!(c.sftp_enabled().is_none());
        let e = fronts(serde_json::json!({ "listen": null })).unwrap_err();
        assert!(e.to_string().contains("is required"), "{e}");
        // `frontends` present without `s3`: still on.
        let c = fronts(serde_json::json!({ "frontends": { "sftp": sftp(false) } })).unwrap();
        assert!(c.s3_enabled());
    }

    #[test]
    fn each_front_is_switched_in_its_own_section_under_frontends() {
        // SFTP-only: no S3 listener, no STS key material.
        let c = fronts(serde_json::json!({
            "frontends": { "s3": { "enabled": false }, "sftp": sftp(true) },
            "listen": null, "sts": null
        }))
        .expect("an SFTP-only process");
        assert!(!c.s3_enabled());
        assert_eq!(c.s3_listen(), None);
        assert!(c.sts().is_none());
        assert_eq!(c.sftp_enabled().unwrap().listen.port(), 2222);

        // A section kept with `enabled: false` binds nothing.
        let c = fronts(serde_json::json!({ "frontends": { "sftp": sftp(false) } })).unwrap();
        assert!(c.sftp_enabled().is_none());

        // Both on is allowed (development).
        let c = fronts(serde_json::json!({ "frontends": { "sftp": sftp(true) } })).unwrap();
        assert!(c.s3_enabled() && c.sftp_enabled().is_some());

        // The S3 listener may live in its section instead of at the top level…
        let c = fronts(serde_json::json!({
            "listen": null,
            "frontends": { "s3": { "enabled": true, "listen": "127.0.0.1:9014" } }
        }))
        .unwrap();
        assert_eq!(c.s3_listen(), Some("127.0.0.1:9014".parse().unwrap()));
        // …but not in both places.
        let e = fronts(serde_json::json!({
            "frontends": { "s3": { "enabled": true, "listen": "127.0.0.1:9014" } }
        }))
        .unwrap_err();
        assert!(e.to_string().contains("set twice"), "{e}");
        // The old top-level sections are not silently accepted.
        assert!(fronts(serde_json::json!({ "sftp": sftp(true) })).is_err());
        assert!(fronts(serde_json::json!({ "frontends": { "ftp": {} } })).is_err());
    }

    #[test]
    fn the_enabled_flag_is_required_and_never_defaulted() {
        let mut no_flag = sftp(true);
        no_flag.as_object_mut().unwrap().remove("enabled");
        let e = fronts(serde_json::json!({ "frontends": { "sftp": no_flag } })).unwrap_err();
        assert!(e.to_string().contains("enabled"), "{e}");
        let e = fronts(serde_json::json!({ "frontends": { "s3": {} } })).unwrap_err();
        assert!(e.to_string().contains("enabled"), "{e}");
    }

    #[test]
    fn degenerate_front_combinations_are_refused_at_load() {
        let e = fronts(serde_json::json!({
            "frontends": { "s3": { "enabled": false } }, "listen": null
        }))
        .unwrap_err();
        assert!(
            e.to_string()
                .contains("both data-plane fronts are disabled"),
            "{e}"
        );
        let e = fronts(serde_json::json!({
            "frontends": { "s3": { "enabled": false }, "sftp": sftp(false) }, "listen": null
        }))
        .unwrap_err();
        assert!(
            e.to_string()
                .contains("both data-plane fronts are disabled"),
            "{e}"
        );
        let e = fronts(serde_json::json!({
            "frontends": { "s3": { "enabled": false }, "sftp": sftp(true) }
        }))
        .unwrap_err();
        assert!(
            e.to_string().contains("s3.enabled is false"),
            "a listen nobody binds: {e}"
        );
        let e = fronts(serde_json::json!({ "sts": null })).unwrap_err();
        assert!(e.to_string().contains("sts is required"), "{e}");
    }

    #[test]
    fn conditional_create_is_a_backend_property_and_defaults_to_check_then_write() {
        let c = fronts(serde_json::json!({})).unwrap();
        assert_eq!(
            c.backends[0].conditional_create,
            ConditionalCreate::CheckThenWrite
        );
        let c = fronts(serde_json::json!({ "backends": [
            { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:7480",
              "conditional_create": "native" } ] }))
        .unwrap();
        assert_eq!(c.backends[0].conditional_create, ConditionalCreate::Native);
        assert!(
            fronts(serde_json::json!({ "backends": [
            { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:7480",
              "conditional_create": "maybe" } ] }))
            .is_err()
        );
    }

    #[test]
    fn sftp_shape_is_validated_even_when_disabled() {
        let with = |sftp: serde_json::Value, extra: serde_json::Value| {
            let mut patch = serde_json::json!({ "frontends": { "sftp": sftp } });
            for (k, v) in extra.as_object().unwrap() {
                patch[k] = v.clone();
            }
            fronts(patch)
        };
        let mut bad = sftp(false);
        bad["listen"] = serde_json::json!("127.0.0.1:9090");
        assert!(
            with(bad, serde_json::json!({ "admin_listen": "127.0.0.1:9090" })).is_ok(),
            "a disabled section binds nothing, so it collides with nothing"
        );
        let mut bad = sftp(true);
        bad["listen"] = serde_json::json!("127.0.0.1:9090");
        let e = with(bad, serde_json::json!({ "admin_listen": "127.0.0.1:9090" })).unwrap_err();
        assert!(e.to_string().contains("shares a port"), "{e}");
        let mut bad = sftp(false);
        bad["host_keys"] = serde_json::json!([]);
        assert!(with(bad, serde_json::json!({})).is_err());
        let mut bad = sftp(false);
        bad["proxy_protocol"] = serde_json::json!({ "trusted_cidrs": ["not-a-cidr"] });
        assert!(with(bad, serde_json::json!({})).is_err());
        let mut bad = sftp(false);
        bad["conditional_create"] = serde_json::json!({ "bay-1": "native" });
        assert!(
            with(bad, serde_json::json!({})).is_err(),
            "conditional_create moved to the backend; the old place is refused, not ignored"
        );
    }

    #[test]
    fn sftp_limits_default_to_the_adr_and_are_bounded() {
        let l = SftpLimits::default();
        assert_eq!(
            l.transfer_reservation(),
            26 * 1024 * 1024,
            "26 MiB per transfer at the defaults"
        );
        assert!(l.validate().is_ok());
        for (field, value) in [
            ("part_size", serde_json::json!(1024)),
            ("max_inflight_parts", serde_json::json!(9)),
            ("max_auth_attempts", serde_json::json!(0)),
            ("reorder_window", serde_json::json!(64 * 1024 * 1024)),
            ("max_file_size", serde_json::json!(1u64 << 50)),
            ("max_connections", serde_json::json!(0)),
        ] {
            let l: SftpLimits =
                serde_json::from_value(serde_json::json!({ field: value })).unwrap();
            assert!(l.validate().is_err(), "{field}={value}");
        }
    }

    #[test]
    fn the_form_upload_buffer_is_bounded_well_below_the_substrate_default() {
        // s3s aggregates a PostObject file into memory before any authorization, so this
        // number times `max_connections` is what an *unauthenticated* caller can make
        // this process allocate. s3s's own default is 5 GiB.
        let limits = LimitsConfig::default();
        assert_eq!(limits.post_object_max_file_size, 64 * 1024 * 1024);
        assert!(
            limits.post_object_max_file_size < 5 * 1024 * 1024 * 1024,
            "the s3s default must not be inherited"
        );
        // And it applies even to a config that spells out `limits` without naming it,
        // which is how the dangerous value would otherwise creep back in.
        let cfg: LimitsConfig = serde_json::from_str(
            r#"{"xml_max_body_size":20971520,"presigned_url_max_skew_time_secs":900,
                "max_delete_keys":1000,"max_list_fanout":16,"max_connections":1024,
                "header_read_timeout_secs":15}"#,
        )
        .expect("limits without the field");
        assert_eq!(cfg.post_object_max_file_size, 64 * 1024 * 1024);
        // The control-plane body caps: AWS's own semantics, four orders of magnitude
        // below `xml_max_body_size`.
        assert_eq!(cfg.max_tag_count, 10);
    }

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
        let (ring, current) = loaded.sts().unwrap().key_ring();
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
        // A current_kid naming a key that is not there — the shape a botched rotation
        // produces (delete the old entry while still pointing at it).
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
            .sts()
            .unwrap()
            .key_ring();
        assert_eq!(current, crate::auth::sts::DEFAULT_KID);
        assert_eq!(ring[crate::auth::sts::DEFAULT_KID].expose(), "aa");
    }

    #[test]
    fn a_static_credential_inside_the_sts_namespace_is_refused() {
        // Every one of these carries the STS prefix, so `Identity` answers it from the
        // STS authority and never consults the store — a credential provisioned here
        // would silently never work. The near-miss shapes matter as much as the exact
        // one: they are what a half-done migration looks like.
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

    /// **The prefix-collision guard for the DERIVED namespace.**
    ///
    /// `HFSA` differs from `HFST` in one character, so it is one keystroke away. The
    /// guard must fire whether or not `derived_keys` is configured: with the feature off
    /// the credential silently never resolves, and with it on it resolves to a
    /// *different* principal than the operator wrote down.
    #[test]
    fn a_static_credential_inside_the_derived_namespace_is_refused_switched_on_or_off() {
        let derived_section = serde_json::json!({ "master_key_hex": "cc".repeat(32) });
        for key in [
            "HFSAk0.AQEAAAABBGFjbWU.AAAAAAAAAAAAAAAAAAAAAA", // a well-formed one
            "HFSAk0.payload",                                // half-formed
            "HFSAsomething",                                 // prefix only
            "HFSA",
            crate::auth::derived::DERIVED_PREFIX,
        ] {
            for with_feature in [false, true] {
                let mut cfg = example();
                if with_feature {
                    cfg["derived_keys"] = derived_section.clone();
                }
                cfg["static_credentials"] = serde_json::json!([{
                    "access_key_id": key,
                    "secret_access_key": "s",
                    "principal_sub": "alice",
                    "tenant": "acme",
                    "organization_id": "org-acme",
                }]);
                let err = GatewayConfig::from_json(&cfg.to_string())
                    .expect_err(&format!("{key} must be refused (feature={with_feature})"))
                    .to_string();
                assert!(
                    err.contains("DERIVED long-lived access-key namespace"),
                    "{key} (feature={with_feature}): {err}"
                );
            }
        }

        // Positive controls, both directions: an ordinary key still loads with the
        // feature on, and a key that merely *starts* like the prefix but is not it is
        // not caught by an over-eager check.
        let mut cfg = example();
        cfg["derived_keys"] = derived_section;
        cfg["static_credentials"] = serde_json::json!([
            { "access_key_id": "AKIAEXAMPLE", "secret_access_key": "s",
              "principal_sub": "alice", "tenant": "acme", "organization_id": "org-acme" },
            { "access_key_id": "HFS", "secret_access_key": "s",
              "principal_sub": "bob", "tenant": "acme", "organization_id": "org-acme" },
            { "access_key_id": "HFSB-not-ours", "secret_access_key": "s",
              "principal_sub": "carol", "tenant": "acme", "organization_id": "org-acme" },
        ]);
        assert!(GatewayConfig::from_json(&cfg.to_string()).is_ok());
    }

    #[test]
    fn the_derived_key_ring_shape_is_settled_at_load_and_shares_no_key_with_sts() {
        // The shipped example declares the section, so it must load, and load as a ring.
        let shipped = GatewayConfig::from_json(&example().to_string()).unwrap();
        let derived = shipped
            .derived_keys
            .as_ref()
            .expect("the shipped example declares derived_keys");
        assert_eq!(derived.key_ring().1, "k0");

        // And absent is still not an error: the feature is simply off, which is
        // what a deployment that has not opted in looks like.
        let mut without = example();
        without.as_object_mut().unwrap().remove("derived_keys");
        assert!(
            GatewayConfig::from_json(&without.to_string())
                .unwrap()
                .derived_keys
                .is_none()
        );

        let with = |section: serde_json::Value| -> Result<GatewayConfig> {
            let mut cfg = example();
            cfg["derived_keys"] = section;
            GatewayConfig::from_json(&cfg.to_string())
        };
        let reject = |section: serde_json::Value| -> String {
            with(section).expect_err("must not load").to_string()
        };

        // The single-key form normalizes onto the default kid.
        let loaded = with(serde_json::json!({ "master_key_hex": "cc".repeat(32) })).unwrap();
        let (ring, current) = loaded.derived_keys.as_ref().unwrap().key_ring();
        assert_eq!(current, crate::auth::derived::DEFAULT_KID);
        assert_eq!(
            ring[crate::auth::derived::DEFAULT_KID].expose(),
            &"cc".repeat(32)
        );

        // The ring form.
        assert!(
            with(serde_json::json!({
                "master_keys": { "k0": "cc".repeat(32), "k1": "dd".repeat(32) },
                "current_kid": "k1"
            }))
            .is_ok()
        );

        assert!(
            reject(serde_json::json!({})).contains("master_key_hex or a non-empty master_keys")
        );
        assert!(
            reject(serde_json::json!({
                "master_key_hex": "cc".repeat(32),
                "master_keys": { "k0": "cc".repeat(32) }
            }))
            .contains("mutually exclusive")
        );
        assert!(
            reject(serde_json::json!({ "master_keys": { "k0": "cc".repeat(32) } }))
                .contains("current_kid is required")
        );
        assert!(
            reject(serde_json::json!({
                "master_keys": { "k0": "cc".repeat(32) }, "current_kid": "k9"
            }))
            .contains("k9")
        );
        assert!(
            reject(serde_json::json!({ "master_key_hex": "cc".repeat(32), "current_kid": "k0" }))
                .contains("meaningless")
        );

        // **The rule that is not a copy of the STS ring's.** The example's STS section
        // holds master key `k0` and a signing key; reusing either here is refused,
        // because retiring a derived kid would then 403 every live session and material
        // recovered from one class would forge the other.
        let sts = &example()["sts"];
        let sts_master = sts["master_keys"]["k0"].as_str().unwrap().to_string();
        let sts_signing = sts["signing_key_hex"].as_str().unwrap().to_string();
        assert!(
            reject(serde_json::json!({ "master_key_hex": sts_master.clone() }))
                .contains("same material as sts master key")
        );
        assert!(
            reject(serde_json::json!({
                "master_keys": { "d0": "cc".repeat(32), "d1": sts_master },
                "current_kid": "d0"
            }))
            .contains("same material as sts master key"),
            "the check must cover every ring entry, not just the first"
        );
        assert!(
            reject(serde_json::json!({ "master_key_hex": sts_signing }))
                .contains("same material as sts.signing_key_hex")
        );
    }

    /// Plaintext secrets must not be reachable via `{:?}`.
    ///
    /// A loaded `GatewayConfig` is one `tracing::debug!(?cfg)` — or one panic whose
    /// payload includes it — away from a log pipeline. This asserts on the whole rendered
    /// config rather than field by field, so a secret field added later is covered
    /// without anyone remembering to extend this test.
    #[test]
    fn no_debug_rendering_of_the_config_contains_a_secret() {
        const MASTER: &str = "d0d0caca0000000000000000000000000000000000000000000000000000beef";
        const SIGNING: &str = "5ec2e7ba5e0000000000000000000000000000000000000000000000deadbeef";
        const OWNER: &str = "OWNER-SECRET-Wj4rXk9zQ2";
        const STATIC: &str = "STATIC-SECRET-Pq7mLt3v";
        // The two machine-to-machine credentials. Both are a shared secret reused across
        // the cluster, so a `{:?}` printing either would be worse than the four above.
        const BUNDLE: &str = "BUNDLE-SHARED-SECRET-Kx8nQ2";
        const INTERNAL: &str = "INTERNAL-SHARED-SECRET-Vb5tR9";

        let mut cfg = example();
        cfg["bundle_shared_secret"] = serde_json::json!(BUNDLE);
        cfg["internal"]["shared_secret"] = serde_json::json!(INTERNAL);
        cfg["sts"]["master_keys"] = serde_json::json!({ "k0": MASTER });
        cfg["sts"]["current_kid"] = serde_json::json!("k0");
        cfg["sts"]["signing_key_hex"] = serde_json::json!(SIGNING);
        for t in cfg["tenants"].as_array_mut().unwrap() {
            t["owner_secret_key"] = serde_json::json!(OWNER);
        }
        cfg["static_credentials"] = serde_json::json!([{
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": STATIC,
            "principal_sub": "alice",
            "tenant": "acme",
            "organization_id": "org-acme",
        }]);
        let loaded = GatewayConfig::from_json(&cfg.to_string()).expect("loads");

        // The values are really in there — otherwise this test proves nothing.
        assert_eq!(loaded.sts().unwrap().signing_key_hex.expose(), SIGNING);
        assert_eq!(loaded.tenants[0].owner_secret_key.expose(), OWNER);
        assert_eq!(
            loaded.static_credentials[0].secret_access_key.expose(),
            STATIC
        );
        assert_eq!(loaded.sts().unwrap().key_ring().0["k0"].expose(), MASTER);
        assert_eq!(
            loaded.bundle_shared_secret.as_ref().map(|s| s.expose()),
            Some(&BUNDLE.to_string())
        );
        assert_eq!(
            loaded
                .internal
                .as_ref()
                .and_then(|i| i.shared_secret.as_ref())
                .map(|s| s.expose()),
            Some(&INTERNAL.to_string())
        );

        // …and no rendering of the config, at any depth or in any format, shows them.
        let renderings = [
            format!("{loaded:?}"),
            format!("{loaded:#?}"),
            format!("{:?}", loaded.sts),
            format!("{:#?}", loaded.sts),
            format!("{:?}", loaded.tenants),
            format!("{:?}", loaded.static_credentials),
            format!("{:?}", loaded.sts().unwrap().key_ring()),
            format!("{:?}", loaded.internal),
            format!("{:?}", loaded.bundle_shared_secret),
            // The shape an error type that wraps a config produces.
            format!("{:?}", Some(&loaded)),
        ];
        for rendered in renderings {
            for secret in [MASTER, SIGNING, OWNER, STATIC, BUNDLE, INTERNAL] {
                assert!(
                    !rendered.contains(secret),
                    "a plaintext secret is reachable through Debug: {rendered}"
                );
            }
            assert!(
                rendered.contains("<redacted>"),
                "the redaction marker should be visible where a secret was: {rendered}"
            );
        }

        // The static-credential table built from the config carries the same property:
        // it derives `Debug` and is held for the process's lifetime.
        let creds = crate::auth::credentials_from_config(&loaded);
        let rendered = format!("{creds:?}");
        assert!(!rendered.contains(STATIC), "{rendered}");
    }

    /// The `AssumeRoleWithWebIdentity` knobs load off the shipped example.
    ///
    /// The example is the schema operators write their config against, and s0 **ignores
    /// unknown keys** — so a misspelled field is silent, and silent in the worst
    /// direction: a mistyped `web_identity_audiences` leaves the surface accepting only
    /// the bearer door's single `audience`, refusing every service account.
    #[test]
    fn the_web_identity_surface_loads_from_the_shipped_example() {
        let loaded = GatewayConfig::from_json(&example().to_string()).expect("the example loads");
        let mint = loaded.sts_mint.expect("the example declares sts_mint");
        assert_eq!(mint.listen.port(), 8015);
        assert!(mint.web_identity_enabled);
        assert_eq!(
            mint.web_identity_audiences,
            vec!["acme-storage", "hf-console", "control-plane-sa"]
        );
        assert_eq!(
            mint.role_name_template.as_deref(),
            Some("{tenant}-sts-role")
        );
        assert_eq!(mint.max_duration_secs, 3600);

        // …and a config that omits these fields still loads, with the surface ON by
        // default. Absence of the whole section is the only "off" that matters.
        let mut older = example();
        let m = older["sts_mint"].as_object_mut().expect("sts_mint");
        for k in [
            "web_identity_enabled",
            "web_identity_audiences",
            "role_name_template",
            "max_duration_secs",
        ] {
            m.remove(k);
        }
        let loaded = GatewayConfig::from_json(&older.to_string()).expect("an older config loads");
        let mint = loaded.sts_mint.expect("sts_mint");
        assert!(mint.web_identity_enabled, "the surface defaults ON");
        assert!(mint.web_identity_audiences.is_empty());
        assert_eq!(mint.role_name_template, None, "no template ⇒ any role name");
        assert_eq!(mint.max_duration_secs, 3600);
    }

    /// The mint listener may not land on the data plane or on the probe port either.
    ///
    /// Checked from this side as well as from `internal`'s, because the two sections are
    /// added independently and a rule enforced from only one of them is a rule that
    /// disappears when the other section is absent.
    #[test]
    fn the_mint_listener_may_not_share_a_port_with_anything_else() {
        let collide = |port: u16| -> String {
            let mut cfg = example();
            cfg["sts_mint"]["listen"] = serde_json::json!(format!("0.0.0.0:{port}"));
            GatewayConfig::from_json(&cfg.to_string())
                .expect_err("a port collision must not load")
                .to_string()
        };
        assert!(collide(8014).contains("data-plane"), "{}", collide(8014));
        assert!(collide(8016).contains("admin_listen"), "{}", collide(8016));
        // The internal listener's own check catches this one, from the other side.
        assert!(
            collide(8017).contains("internal.listen"),
            "{}",
            collide(8017)
        );

        // A zero ceiling would clamp every minted credential to nothing. Turning the
        // surface off is `web_identity_enabled: false`, not a zero.
        let mut cfg = example();
        cfg["sts_mint"]["max_duration_secs"] = serde_json::json!(0);
        let err = GatewayConfig::from_json(&cfg.to_string())
            .expect_err("a zero ceiling must not load")
            .to_string();
        assert!(err.contains("max_duration_secs"), "{err}");
        assert!(
            err.contains("web_identity_enabled"),
            "the message must say how: {err}"
        );

        // POSITIVE CONTROL: the example itself still loads on its own port.
        assert!(GatewayConfig::from_json(&example().to_string()).is_ok());
    }

    /// The mint listener's own hardening bounds: present in the shipped schema, defaulted
    /// when omitted, and never settable to a value that reads as "no limit" and means "no
    /// service". The defaulting matters most — this socket is internet-facing and
    /// unauthenticated by design, so a `gateway.json` naming neither field must still come
    /// up **bounded**.
    #[test]
    fn the_mint_listeners_bounds_are_defaulted_and_cannot_be_set_to_zero() {
        let loaded = GatewayConfig::from_json(&example().to_string()).expect("the example loads");
        let mint = loaded.sts_mint.expect("sts_mint");
        assert_eq!(mint.max_connections, 256);
        assert_eq!(mint.connection_timeout_secs, 30);

        // A config that omits both fields gets exactly the same numbers.
        let mut older = example();
        let m = older["sts_mint"].as_object_mut().expect("sts_mint");
        m.remove("max_connections");
        m.remove("connection_timeout_secs");
        let mint = GatewayConfig::from_json(&older.to_string())
            .expect("a config that predates the bounds still loads")
            .sts_mint
            .expect("sts_mint");
        assert_eq!(
            mint.max_connections, 256,
            "an unbounded mint must not be reachable by omission"
        );
        assert_eq!(mint.connection_timeout_secs, 30);

        // Zero reads like "no limit" and does the opposite in both cases: a
        // zero-permit semaphore accepts nothing, and a zero timeout closes every
        // connection before it can be answered. Both are silent total outages of the
        // credential path, so both are refused at load.
        let reject = |key: &str| -> String {
            let mut cfg = example();
            cfg["sts_mint"][key] = serde_json::json!(0);
            GatewayConfig::from_json(&cfg.to_string())
                .expect_err("zero must not load")
                .to_string()
        };
        let err = reject("max_connections");
        assert!(err.contains("max_connections"), "{err}");
        assert!(
            err.contains("unbounded"),
            "the message must say why zero is not what the operator meant: {err}"
        );
        let err = reject("connection_timeout_secs");
        assert!(err.contains("connection_timeout_secs"), "{err}");
        assert!(err.contains("no timeout"), "{err}");

        // POSITIVE CONTROL: a deliberately raised bound loads unchanged.
        let mut cfg = example();
        cfg["sts_mint"]["max_connections"] = serde_json::json!(2048);
        cfg["sts_mint"]["connection_timeout_secs"] = serde_json::json!(120);
        let mint = GatewayConfig::from_json(&cfg.to_string())
            .expect("a raised bound loads")
            .sts_mint
            .expect("sts_mint");
        assert_eq!(mint.max_connections, 2048);
        assert_eq!(mint.connection_timeout_secs, 120);
    }

    /// The credential mint may not land on the unauthenticated probe port, on the
    /// Ingress-fronted data plane, or on the OIDC mint.
    #[test]
    fn the_internal_listener_may_not_share_a_port_with_anything_else() {
        let collide = |port: u16| -> String {
            let mut cfg = example();
            cfg["internal"]["listen"] = serde_json::json!(format!("0.0.0.0:{port}"));
            GatewayConfig::from_json(&cfg.to_string())
                .expect_err("a port collision must not load")
                .to_string()
        };
        assert!(collide(8016).contains("admin_listen"), "{}", collide(8016));
        assert!(
            collide(8016).contains("UNAUTHENTICATED"),
            "the message must say WHY"
        );
        assert!(collide(8014).contains("data-plane"), "{}", collide(8014));
        assert!(collide(8015).contains("sts_mint"), "{}", collide(8015));

        // A zero ceiling is not a way to disable the endpoint; it would clamp every
        // session to nothing.
        let mut cfg = example();
        cfg["internal"]["max_session_ttl_secs"] = serde_json::json!(0);
        assert!(
            GatewayConfig::from_json(&cfg.to_string())
                .expect_err("zero ttl cap")
                .to_string()
                .contains("max_session_ttl_secs")
        );
    }

    /// Omitting the whole section is the "off" state: no listener, and a config that
    /// never mentions the field still loads.
    #[test]
    fn the_internal_listener_is_absent_unless_configured() {
        let mut cfg = example();
        cfg.as_object_mut().unwrap().remove("internal");
        cfg.as_object_mut().unwrap().remove("bundle_shared_secret");
        let loaded = GatewayConfig::from_json(&cfg.to_string()).expect("loads without them");
        assert!(loaded.internal.is_none());
        assert!(loaded.bundle_shared_secret.is_none());

        // And when it is present without a secret it still loads — refusing every
        // request is a *runtime* posture, not a crash loop that would take the healthy
        // data plane down with it.
        let mut cfg = example();
        cfg["internal"]
            .as_object_mut()
            .unwrap()
            .remove("shared_secret");
        let loaded = GatewayConfig::from_json(&cfg.to_string()).expect("loads without a secret");
        let internal = loaded.internal.expect("section present");
        assert!(internal.shared_secret.is_none());
        assert_eq!(internal.listen.port(), 8017);
        assert_eq!(internal.max_session_ttl_secs, 3600);
    }

    /// A bundle credential that is never sent reads exactly like one that is.
    #[test]
    fn a_bundle_credential_without_a_bundle_url_is_refused() {
        let mut cfg = example();
        cfg.as_object_mut().unwrap().remove("bundle_url");
        let err = GatewayConfig::from_json(&cfg.to_string())
            .expect_err("a credential with no remote source must not load")
            .to_string();
        assert!(err.contains("bundle_shared_secret"), "{err}");
        assert!(err.contains("never be sent"), "{err}");

        // Positive control: dropping both loads (the dev/file-source deployment).
        let mut cfg = example();
        cfg.as_object_mut().unwrap().remove("bundle_url");
        cfg.as_object_mut().unwrap().remove("bundle_shared_secret");
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
