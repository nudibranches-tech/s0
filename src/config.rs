//! Gateway configuration. Secrets (STS keys, per-tenant backend credentials) are
//! expected from a secret store in production; here they load from a JSON file
//! referenced by `$GATEWAY_CONFIG` so the binary is runnable end-to-end.
//!
//! **Every plaintext credential in this file is a [`Secret<String>`]**, not a `String`.
//! These structs `derive(Debug)` and are reachable from a `tracing` call, a panic
//! payload, or any error type that wraps them — and this deployment ships JSON logs
//! into a shared pipeline. `Secret` makes the redaction a property of the type rather
//! than of whoever writes the next log line, so a *new* secret field is safe by
//! default instead of safe by memory. See `src/secret.rs`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

use crate::error::{GatewayError, Result};
use crate::model::BackendKind;
use crate::secret::Secret;

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
    /// Optional: the key ring for **derived long-lived per-principal keys**
    /// (`FOLLOW-UPS.md` F17). Absent ⇒ the gateway mints and honours none, and behaves
    /// byte-identically to a build made before they existed.
    ///
    /// **Absent does not mean the namespace is free.** `HFSA*` is refused for static
    /// credentials either way (see [`GatewayConfig::validate`]) and answered by nothing
    /// at runtime, so enabling this later cannot silently activate a credential someone
    /// parked in the namespace in the meantime.
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
    /// Whole-request timeout for one bundle fetch. Without it a control plane that
    /// accepts the connection and never answers stalls the refresh loop *forever*:
    /// the poller is a single task, so one hung fetch stops all later polls and
    /// revocation silently stops landing. Must be < `bundle_poll_secs` × a small
    /// factor or polls queue up behind each other.
    #[serde(default = "default_bundle_timeout_secs")]
    pub bundle_timeout_secs: u64,
    /// Credential presented on every bundle fetch, when the bundle is polled from
    /// the control plane.
    ///
    /// **Optional on purpose.** s0 must stay runnable against a plain file or an
    /// unauthenticated URL (development, and any operator running it outside
    /// hyperfluid), so a missing value is not an error — it is "this source needs no
    /// credential". But when it *is* set it is sent on every request, never on the
    /// first one only and never conditionally: see [`crate::bundle_refresh`].
    ///
    /// Rejected at load when `bundle_url` is unset, because a credential that is
    /// never sent reads exactly like a credential that is.
    #[serde(default)]
    pub bundle_shared_secret: Option<Secret<String>>,
    /// Optional STS mint (the badge desk). When present, a control-plane server
    /// runs on its own listener and issues gateway session creds from OIDC tokens.
    #[serde(default)]
    pub sts_mint: Option<StsMintConfig>,
    /// Optional **authenticated** internal surface: the console-mediated session
    /// endpoint. Absent by default, so a gateway that does not carry this section
    /// behaves byte-identically to one built before it existed — no listener is
    /// bound, no port is opened, nothing is served.
    #[serde(default)]
    pub internal: Option<InternalApiConfig>,
}

/// The authenticated internal control-plane surface (`POST
/// /internal/v1/sts/sessions`).
///
/// Deliberately **its own listener**, not a route on the admin listener and not a
/// route on the S3 data plane. See [`crate::internal`] for the full argument; the
/// short form is that the admin listener is unauthenticated by construction (probes
/// cannot carry a secret) and mixing an authenticated credential-minting route onto
/// the same port makes "is this request authenticated?" a routing question — which is
/// how fail-open surfaces are built.
#[derive(Debug, Clone, Deserialize)]
pub struct InternalApiConfig {
    #[serde(default = "default_internal_listen")]
    pub listen: SocketAddr,
    /// The platform `X-Shared-Secret`. **Optional in the schema, mandatory in
    /// effect**: absent, empty or whitespace-only, every request to this listener is
    /// refused. It is not a load-time error because that would crash-loop a pod whose
    /// *data plane* is healthy and serving — refusing to mint is the smaller failure,
    /// and it is loud (an `error!` at startup and a 401 per request) rather than
    /// silent. It is never a reason to allow.
    #[serde(default)]
    pub shared_secret: Option<Secret<String>>,
    /// Ceiling on a minted session's lifetime, in seconds. The caller asks for a
    /// duration; anything above this is **clamped down** to it (never refused — see
    /// [`crate::internal`] for why) and logged.
    #[serde(default = "default_max_session_ttl_secs")]
    pub max_session_ttl_secs: u64,
}

/// OIDC → gateway-credentials mint. Backend-agnostic: verifies a Keycloak token and
/// mints the gateway's own session (never a backend STS).
///
/// This listener serves **two** doors, and the second one is the one clients use:
///
/// * the original bearer-token JSON exchange (`Authorization: Bearer <oidc>` ⇒ a JSON
///   credential document), which requires `tenant_claim`/`org_claim` to be present in
///   the token and can only ever mint a *user* session;
/// * `Action=AssumeRoleWithWebIdentity` — the AWS STS query protocol, form-encoded
///   request and XML response ([`crate::webidentity`]). This is what every S3 SDK can
///   speak with stock configuration, it carries the tenant in the `RoleArn` rather than
///   in a claim, and it can mint a service-account session. Configured by the
///   `web_identity_*` / `role_name_template` / `max_duration_secs` fields below.
///
/// Both are unauthenticated in the sense that no *platform* credential is required —
/// correctly, because the OIDC token **is** the credential. See
/// [`crate::webidentity`] for why that posture belongs on this socket and on no other.
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
    /// Defaults **on**: this door is the whole reason to configure `sts_mint` on this
    /// platform (the bearer door cannot serve hyperfluid — see [`crate::internal`]), and
    /// an operator who has gone to the trouble of pointing s0 at an IdP wants clients to
    /// be able to get a credential. Set it to `false` to run the bearer door alone.
    #[serde(default = "default_true")]
    pub web_identity_enabled: bool,

    /// Audiences accepted on the web-identity door. Empty ⇒ `[audience]`.
    ///
    /// A separate list from `audience` because the two doors have genuinely different
    /// requirements, and collapsing them would break one of them:
    ///
    /// * the **bearer door** validates `aud` strictly, through `jsonwebtoken`'s own
    ///   audience check, against this one configured value;
    /// * a **Keycloak service-account token** obtained with
    ///   `grant_type=client_credentials` carries `aud: "account"` and identifies the
    ///   client in **`azp`**. Requiring a matching `aud` would refuse every service
    ///   account on the platform — i.e. the primary consumer of the gateway.
    ///
    /// So the web-identity door accepts a match on `aud` **or** `azp`/`client_id`
    /// against this list. That is not a local invention: it is exactly what Ceph RGW
    /// does (`ensure_sts_role` is handed a list of client ids, not audiences) and what
    /// MinIO documents ("validates `aud` first, then falls back to `azp`"), and the
    /// operator renders the same list it already gives RGW. There is **no** setting in
    /// which the check is skipped: an empty list falls back to `[audience]`, so a token
    /// with no audience binding at all is always refused.
    #[serde(default)]
    pub web_identity_audiences: Vec<String>,

    /// Expected role name, with `{tenant}` substituted from the presented `RoleArn`.
    ///
    /// Absent ⇒ any non-empty role name is accepted (s0 must stay runnable outside
    /// hyperfluid). Set, it makes a mistyped ARN a clear refusal instead of a working
    /// session in a tenant the caller did not mean. It is a **diagnostic**, never an
    /// authorization input — s0 has no role objects and authority comes from the bundle.
    #[serde(default)]
    pub role_name_template: Option<String>,

    /// Ceiling on `DurationSeconds`. Above it, **clamped down** and logged — never
    /// refused; see [`crate::webidentity::WebIdentitySts::clamp_duration`] for why the
    /// deviation from AWS (which returns `ValidationError`) is the safer direction for a
    /// credential-acquisition call.
    #[serde(default = "default_max_session_ttl_secs")]
    pub max_duration_secs: u64,

    // ── the listener's own hardening bounds (F13) ──────────────────────────────
    /// Max concurrent connections on the mint listener.
    ///
    /// The same treatment `LimitsConfig::max_connections` gives the S3 data plane,
    /// with its own number, because this listener's exposure is different in both
    /// directions:
    ///
    /// * it is the **one socket that is both internet-facing and unauthenticated by
    ///   design** — the web identity token *is* the credential, exactly as at
    ///   `sts.amazonaws.com`, so there is nothing to present before being served, and
    ///   the Ingress in front of it applies no rate limiting (Cilium has no
    ///   rate-limit annotation, and an nginx-shaped key would be silently ignored).
    ///   Whatever bound exists has to exist here;
    /// * its natural concurrency is far *below* the data plane's. A client mints once
    ///   and then uses the credential for an hour, so the mint sees roughly one
    ///   request per client per session lifetime, against the data plane's one per
    ///   object operation.
    ///
    /// **It is a queue, not a refusal.** The accept loop takes a permit *before* it
    /// accepts, exactly as `server::serve_with_shutdown` does, so a connection beyond
    /// the bound waits in the kernel's accept backlog rather than being answered with
    /// an error. That is the point: a legitimate mint refused is worse than no bound
    /// at all, and every mint is a few hundred microseconds of RS256, so a queue
    /// drains as fast as it forms. Saturation is counted and logged rather than
    /// returned to the caller (`s0_mint_connection_limit_saturated_total`).
    ///
    /// `0` is refused at load: a zero-permit semaphore is not "unbounded", it is a
    /// listener that accepts nothing.
    #[serde(default = "default_mint_max_connections")]
    pub max_connections: usize,

    /// Hard ceiling on the lifetime of one accepted mint connection, in seconds.
    ///
    /// Without it the connection bound above makes slowloris *easier*, not harder: an
    /// attacker who dribbles bytes on `max_connections` sockets holds every permit
    /// forever and locks out the whole fleet's credential path with a few hundred
    /// connections. With it, a permit is always returned within this many seconds.
    ///
    /// **Deliberately not `hyper`'s `header_read_timeout`.** That knob needs a timer
    /// installed on the h1 builder that does not survive `into_owned()`, so it panics
    /// once per connection — this project already added it once and removed it (see
    /// the NOTE in `server::serve_with_shutdown`). This is a plain
    /// `tokio::time::timeout` around the already-`GracefulShutdown`-watched connection
    /// future: no timer in the builder, no shape to get subtly wrong, and it bounds
    /// the *whole* connection rather than only its header read.
    ///
    /// The default is far longer than any legitimate mint — a token verification plus,
    /// worst case on a `kid` miss, one JWKS fetch bounded by `jwks_timeout_secs` — and
    /// far shorter than "forever", which is what an unbounded socket grants. `0` is
    /// refused at load rather than read as "no bound".
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
/// Mirrors [`StsConfig`]'s ring exactly — the same two forms, the same `current_kid`
/// rule — because an operator should not have to learn a second convention for the second
/// derivation. There is **no signing key**: a derived key has no session token to sign;
/// the MAC inside the access-key id is what proves it, and it is derived from this ring.
#[derive(Debug, Clone, Deserialize)]
pub struct DerivedKeysConfig {
    /// Hex-encoded master key (≥32 bytes). Sugar for a one-entry `master_keys` ring
    /// under `auth::derived::DEFAULT_KID`; mutually exclusive with it.
    #[serde(default)]
    pub master_key_hex: Option<Secret<String>>,
    /// The master-key **ring**: `kid -> hex key`. The `kid` lands in every access-key id
    /// minted from it (`HFSA<kid>.<payload>.<mac>`), which is what lets a key be rotated
    /// without invalidating every outstanding one.
    ///
    /// Unlike the STS ring there is **no TTL after which stragglers are gone**: retiring
    /// an entry here revokes every long-lived key minted under it, permanently, so it
    /// must be paired with reissuing them.
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
    /// Ceiling on the file part of a browser form upload (`PostObject`).
    ///
    /// This one is **not** an ordinary request cap: s3s aggregates the whole file into
    /// memory during route resolution — before `check`, before the typed hook, before
    /// any authorization happens at all (`s3s-0.14.1/src/ops/mod.rs:539-551`). So it
    /// bounds what an *unauthorized* caller can make this process allocate, multiplied
    /// by `max_connections`. s3s's own default is 5 GiB, which at 1024 connections is
    /// not a bound at all; the default here is 64 MiB, on the grounds that the form-POST
    /// path exists for browser uploads and anything larger belongs on `PutObject` or a
    /// multipart upload, which stream.
    ///
    /// Defaulted (unlike its neighbours) so that a config which spells out `limits`
    /// without naming this field gets the safe bound rather than s3s's 5 GiB.
    #[serde(default = "default_post_object_max_file_size")]
    pub post_object_max_file_size: u64,
    pub presigned_url_max_skew_time_secs: u32,
    /// AWS semantic cap: `DeleteObjects` ≤ 1000 keys (enforced before OPA).
    pub max_delete_keys: usize,
    /// AWS semantic cap: ≤ 10 tags per object (`PutObjectTagging`, and the tag set a
    /// future `PutObject`/`PostObject` retrofit parses).
    ///
    /// A cap here is a **resource bound**, never a deny mechanism: exceeding it
    /// produces a real `write_object_tags` Deny sub-decision that is audited, not a
    /// bare `InvalidRequest` that short-circuits ahead of the audit call (plan defect
    /// B-1). Set it to 0 and every tag write is refused *and recorded*.
    #[serde(default = "default_max_tag_count")]
    pub max_tag_count: usize,
    // `max_bucket_policy_bytes` and `max_cors_rules` were removed on 2026-08-08 with the
    // ops they bounded: `PutBucketPolicy` and `PutBucketCors` are `Coverage::Denied`, so
    // neither body reaches this process. Both had `#[serde(default)]` and the operator
    // renders neither (`hf_bin_operator/src/s3_gateway/config.rs::LimitsSection`), so a
    // deployed `gateway.json` that still carries them keeps loading — they are simply
    // ignored. A knob that bounds nothing is a claim the binary no longer makes.
    /// Multi-prefix list fan-out bound; above it the list fails closed.
    pub max_list_fanout: usize,
    /// Page size ceiling for a **filtered** `ListBuckets`.
    ///
    /// The gateway owns this pagination outright — filtering the backend's answer makes
    /// its `max-buckets` and `continuation-token` meaningless to the client — so a
    /// caller-supplied `max-buckets` is clamped to this rather than honored. AWS's own
    /// default page is 10 000; 1 000 keeps one response bounded in the same order as a
    /// `ListObjectsV2` page.
    #[serde(default = "default_max_buckets_per_page")]
    pub max_buckets_per_page: usize,
    /// How many backend `ListBuckets` pages one client request may drain.
    ///
    /// A filtered listing cannot be produced incrementally: the gateway sorts the whole
    /// visible set before it can cut a stable page (see `proxy::bucketfilter`), so it
    /// reads the tenant's bucket list to the end. This bounds that read. A tenant with
    /// more buckets than this is **refused**, loudly — an under-reported bucket list is
    /// indistinguishable from a revoked grant, and silently omitting buckets from an
    /// authorization-filtered response is the failure mode this whole file exists to
    /// avoid.
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
            // The SAME rule for the derived long-lived namespace, and it is not a copy
            // for symmetry's sake. `HFSA` differs from `HFST` in the fourth character
            // only, so a hand-written credential list is one keystroke away from landing
            // in it — and `Identity::secret_key` answers every key carrying this prefix
            // from the derived-key half alone, INCLUDING when derived keys are switched
            // off, where the answer is "no". Without this check an operator provisions a
            // static credential that silently never resolves; worse, it would start
            // resolving differently the day the feature is enabled.
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
        Ok(())
    }

    /// The mint listener may not share a port with the data plane or with the probes.
    ///
    /// This used to be unchecked, and it used to be *nearly* harmless because nothing
    /// rendered a `sts_mint` section. That changed when the listener grew the
    /// [`crate::webidentity`] door: it now mints credentials for anyone holding a valid
    /// IdP token, it is deliberately unauthenticated, and the operator publishes it
    /// through an Ingress. Sharing a port with either of the other two would be a
    /// different failure in each direction:
    ///
    /// * with **`listen`**, the S3 data plane would never come up (whichever binds
    ///   second loses), so a copy-pasted port takes the *storage* down;
    /// * with **`admin_listen`**, the probe port would answer credential mints — and
    ///   the probe port is published on the Service for Prometheus, whose network
    ///   posture is nothing like a mint's.
    ///
    /// The `internal` collision is checked from the other side in
    /// [`Self::validate_internal_listener`]; both are kept so neither section can be
    /// added without the pair being enforced.
    fn validate_mint_listener(&self) -> Result<()> {
        let Some(m) = &self.sts_mint else {
            return Ok(());
        };
        if m.listen.port() == self.listen.port() {
            return Err(GatewayError::Config(format!(
                "sts_mint.listen {} shares a port with the S3 data-plane listener {}; \
                 the mint is a separate, deliberately unauthenticated socket and must \
                 not be a route inside the SigV4-authenticated data plane",
                m.listen, self.listen
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
        // semaphore never hands out a permit, so the accept loop would park forever and
        // the listener would answer nothing while still being bound and still passing a
        // TCP probe; a zero timeout closes every connection before its first byte. Both
        // are silent, total outages of the credential path, so they are refused at load
        // — the same reasoning as `max_duration_secs` above.
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
    /// Both collisions are real config mistakes with the same shape — a
    /// copy-pasted port — and both are catastrophic in the same direction:
    ///
    /// * **The admin listener** answers `/healthz`, `/readyz` and `/metrics` with no
    ///   authentication at all, because a kubernetes probe cannot present a secret.
    ///   Its port is published on the Service for scraping. Sharing it would put a
    ///   credential mint behind whatever the probe port's network posture happens to be.
    /// * **The S3 listener** is the data plane. It is fronted by an Ingress and is
    ///   reachable from the public internet on `<org>.s3-gw.<domain>`. A minting route
    ///   there is a credential-issuing endpoint on the open internet.
    ///
    /// Refusing at load rather than at bind time: `TcpListener::bind` would fail on a
    /// real collision anyway, but only *after* the data plane is already serving, and
    /// only for the loser of the race.
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
        if i.listen.port() == self.listen.port() {
            return Err(GatewayError::Config(format!(
                "internal.listen {} shares a port with the S3 data-plane listener {}; \
                 the data plane is fronted by an Ingress and a credential-minting \
                 endpoint must never be reachable from it",
                i.listen, self.listen
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

    /// The derived-key ring's shape, plus the one rule that is not a copy of the STS
    /// ring's: **no key may be shared between the two credential classes.**
    ///
    /// The classes have different lifetimes (one hour against indefinite) and different
    /// revocation stories, and sharing material would collapse them into one blast
    /// radius: retiring a `kid` to revoke a long-lived key would silently 403 every live
    /// session, and material recovered from either would forge both. The check covers the
    /// STS signing key too — it is a second, differently-handled secret in the same
    /// section, and "the operator pasted the wrong hex" is the failure being caught.
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
        let (sts_ring, _) = self.sts.key_ring();
        for (kid, key) in &derived_ring {
            if key.expose() == self.sts.signing_key_hex.expose() {
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
/// 8017: next to the admin port and deliberately *not* it. `0.0.0.0` because the
/// caller is the console, in a different pod — loopback would make the endpoint
/// unreachable and the whole console-mediated path dead. Reachability is fenced by
/// the Service/NetworkPolicy (operator side) and by authentication (here), never by
/// the bind address.
fn default_internal_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 8017))
}
/// One hour, matching `default_session_ttl_secs` and the console's own
/// `DurationSeconds=3600` on the legacy RGW path.
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
/// Sized against the largest legitimate burst anyone could point at it, not against a
/// guess. The worst realistic case is a deployment rolling many pods at once, each
/// minting a credential on startup: a 200-pod Deployment at the kubernetes default
/// `maxSurge: 25%` brings up ~50 pods at a time, and even a whole-fleet restart is
/// serialised by image pulls and readiness gates long before it is serialised here.
/// 256 leaves that burst several times over, and one mint is a signature verification
/// against a *cached* JWKS plus an HMAC — a few hundred microseconds — so 256 in flight
/// is throughput this listener will never reach.
///
/// It is a quarter of the data plane's 1024, deliberately (F13: "the mint's natural
/// concurrency is far below the data plane's"), and it is two orders of magnitude
/// below what the unbounded loop allowed, which was the process file-descriptor limit.
fn default_mint_max_connections() -> usize {
    256
}
/// 30 s of connection lifetime.
///
/// An order of magnitude above the worst legitimate request — a `kid`-miss mint pays
/// one JWKS fetch, bounded by `jwks_timeout_secs` (5 s), on top of a verification
/// measured in microseconds — and it is a *lifetime* rather than an idle timeout, so
/// the only client it can inconvenience is one reusing a pooled connection more than
/// 30 s after opening it. That client minted twice inside 30 s, which no SDK does
/// (a session lasts an hour), and every HTTP client already retries a connection the
/// server closed underneath it, because every HTTP server closes idle keep-alives.
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

    #[test]
    fn the_form_upload_buffer_is_bounded_well_below_the_substrate_default() {
        // s3s aggregates a PostObject file into memory during route resolution —
        // before `check`, before any authorization — so this number times
        // `max_connections` is what an *unauthenticated* caller can make this process
        // allocate. s3s's own default is 5 GiB, which at 1024 connections is not a
        // bound at all.
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
        assert_eq!(ring[crate::auth::sts::DEFAULT_KID].expose(), "aa");
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

    /// **The prefix-collision guard for the DERIVED namespace.**
    ///
    /// `HFSA` differs from `HFST` in one character, so this is the near-miss the existing
    /// STS guard's own comment warns about, one keystroke away. It must fire whether or
    /// not `derived_keys` is configured: with the feature off the credential silently
    /// never resolves, and with it on it resolves to a *different* principal than the
    /// operator wrote down.
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
        // Absent is the default and is not an error: the feature is simply off.
        assert!(
            GatewayConfig::from_json(&example().to_string())
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

    /// M0 issue 3: "plaintext secrets reachable via `{:?}`".
    ///
    /// A loaded `GatewayConfig` is one `tracing::debug!(?cfg)` — or one panic whose
    /// payload includes it — away from a JSON log pipeline. This asserts on the whole
    /// rendered config rather than field by field, so a secret field added later is
    /// covered without anyone remembering to extend this test.
    #[test]
    fn no_debug_rendering_of_the_config_contains_a_secret() {
        const MASTER: &str = "d0d0caca0000000000000000000000000000000000000000000000000000beef";
        const SIGNING: &str = "5ec2e7ba5e0000000000000000000000000000000000000000000000deadbeef";
        const OWNER: &str = "OWNER-SECRET-Wj4rXk9zQ2";
        const STATIC: &str = "STATIC-SECRET-Pq7mLt3v";
        // The two machine-to-machine credentials added for P2/P3. Both are the
        // platform shared secret — the single most reusable credential on the
        // cluster — so a `{:?}` that printed either of them would be worse than any
        // of the four above.
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
        assert_eq!(loaded.sts.signing_key_hex.expose(), SIGNING);
        assert_eq!(loaded.tenants[0].owner_secret_key.expose(), OWNER);
        assert_eq!(
            loaded.static_credentials[0].secret_access_key.expose(),
            STATIC
        );
        assert_eq!(loaded.sts.key_ring().0["k0"].expose(), MASTER);
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
            format!("{:?}", loaded.sts.key_ring()),
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

    /// The `AssumeRoleWithWebIdentity` knobs load off the shipped example, with the
    /// values the operator renders.
    ///
    /// The example is the schema the operator's own contract test
    /// (`every_key_the_operator_renders_exists_in_s0s_own_schema`) checks its writer
    /// against, and s0 **ignores unknown keys** — so a field misspelled on either side
    /// is silent. Here it is silent in the worst direction: a mistyped
    /// `web_identity_audiences` leaves the surface accepting only the bearer door's
    /// single `audience`, which refuses every service account on the platform, with no
    /// error anywhere.
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

        // …and a config that predates the surface still loads, with the surface ON by
        // default. Absence of the section is the only "off" that matters, and it is
        // still expressible; absence of these *fields* must not be.
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

    /// The mint listener's own hardening bounds (F13): present in the shipped schema,
    /// defaulted for every config that predates them, and never settable to a value
    /// that reads as "no limit" and means "no service".
    ///
    /// The defaulting half is the part that matters most. This socket is the one that
    /// is both internet-facing and unauthenticated by design, so a deployed
    /// `gateway.json` written before these fields existed — which is every one of them
    /// — must come up **bounded**. If absence meant "unbounded", the fix would land
    /// only on operators who edited their config, i.e. on nobody.
    #[test]
    fn the_mint_listeners_bounds_are_defaulted_and_cannot_be_set_to_zero() {
        let loaded = GatewayConfig::from_json(&example().to_string()).expect("the example loads");
        let mint = loaded.sts_mint.expect("sts_mint");
        assert_eq!(mint.max_connections, 256);
        assert_eq!(mint.connection_timeout_secs, 30);

        // A config written before F13 gets exactly the same numbers.
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

    /// Omitting the whole section is the "off" state: no listener, and the config that
    /// every gateway runs today (which has never heard of the field) still loads.
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
