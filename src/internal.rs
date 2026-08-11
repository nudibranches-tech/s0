//! The authenticated internal control-plane surface: the session mint
//! ([`SESSION_PATH`]) and the long-lived key mint ([`DERIVED_KEY_PATH`]).
//!
//! The OIDC badge desk next door ([`crate::mint`]) needs `tenant`/`org` claims and only
//! mints users. Where the tenant belongs to the resource being addressed rather than to
//! the user, and service accounts are first-class, only the control plane knows those
//! facts — so it states them here, authenticated with a shared secret. A session is an
//! identity assertion, not a grant: authority is read from the bundle at decision time,
//! so a revocation lands within one poll even for a session minted a moment earlier.
//!
//! Own listener, never the admin one: that port is unauthenticated by construction
//! (probes and metrics scrapes cannot present a secret), so authenticating it would make
//! "is this request authenticated" a *routing* question — one mis-written path prefix
//! from a fail-open mint. Reachability is fenced by the network, authorization by the
//! shared secret ([`SharedSecretAuth`]); neither is trusted to be the only one.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use hmac::{Hmac, KeyInit, Mac};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::HeaderMap;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use serde::Deserialize;
use sha2::Sha256;
use tokio::net::TcpListener;

use crate::auth::sts::{SessionClaims, StsAuthority};
use crate::auth::{DerivedKeys, DerivedMintRefusal};
use crate::config::InternalApiConfig;
use crate::error::Result;
use crate::mint::MintedCredentials;
use crate::model::PrincipalType;
use crate::proxy::BackendRegistry;
use crate::secret::Secret;

type HmacSha256 = Hmac<Sha256>;

/// The machine-to-machine auth header. Its exact name is part of the wire contract with
/// the control plane: a different one here is a 401 on every mint, with no fallback.
pub const SHARED_SECRET_HEADER: &str = "X-Shared-Secret";

/// The session endpoint's path. Part of the control-plane wire contract.
pub const SESSION_PATH: &str = "/internal/v1/sts/sessions";

/// The long-lived key endpoint's path.
///
/// Minting lives here, not in the control plane, because a derived key is an HMAC over a
/// byte layout with no version handshake: a second implementation kept in step by a
/// golden vector is a credential that silently stops authenticating after some future
/// refactor. One implementation, in the process that verifies — so the master ring never
/// leaves s0, and the epoch stamped into a key is read from the very bundle that will
/// revoke it (see [`crate::auth::DerivedKeys::mint`]).
pub const DERIVED_KEY_PATH: &str = "/internal/v1/derived-keys";

/// Ceiling on a request body. Applied *after* authentication, so it bounds an
/// authenticated caller — the unauthenticated one never reaches the body at all.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// In-flight budget on shutdown. A mint is an in-process HMAC; anything still running
/// past this is a stuck socket.
const INTERNAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

// ── authentication ─────────────────────────────────────────────────────────────

/// Constant-time shared-secret check, with "not configured" folded into the same
/// answer as "wrong".
///
/// A **double HMAC**: both the configured and the presented secret are MAC'd under a
/// per-process key, and the 32-byte tags compared with a fold that has no early exit.
/// Tags are always the same length, so neither the secret's length nor a matching prefix
/// is observable through timing. The plaintext is touched once, at construction, and is
/// not retained.
pub struct SharedSecretAuth {
    /// Blinding key, per process. Never leaves this struct.
    key: [u8; 32],
    /// `HMAC(key, configured_secret)`. **`None` ⇒ refuse everything.**
    tag: Option<[u8; 32]>,
}

impl std::fmt::Debug for SharedSecretAuth {
    /// Renders whether a secret is configured and nothing else: that fact is the
    /// difference between "minting" and "refusing everything", and is not itself secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecretAuth")
            .field("configured", &self.tag.is_some())
            .finish()
    }
}

impl SharedSecretAuth {
    /// Build from the configured value. Absent, empty, or whitespace-only all mean
    /// **no secret**: an empty string or a `"   "` left by a template is not a
    /// credential and must not be treated as one.
    pub fn new(configured: Option<&Secret<String>>) -> Self {
        let key = blinding_key();
        let tag = configured
            .map(Secret::expose)
            .filter(|s| !s.trim().is_empty())
            .map(|s| mac(&key, s.as_bytes()));
        SharedSecretAuth { key, tag }
    }

    /// True when a usable secret was configured. Used only for the startup log line;
    /// [`accepts`](Self::accepts) does not consult it.
    pub fn is_configured(&self) -> bool {
        self.tag.is_some()
    }

    /// Does this request carry the configured secret?
    ///
    /// `false` when nothing is configured — checked first, so there is no path through
    /// this function that allows a request against an absent secret.
    pub fn accepts(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = self.tag.as_ref() else {
            return false;
        };
        let Some(presented) = headers.get(SHARED_SECRET_HEADER) else {
            return false;
        };
        constant_time_eq(expected, &mac(&self.key, presented.as_bytes()))
    }
}

fn mac(key: &[u8; 32], message: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    m.update(message);
    m.finalize().into_bytes().into()
}

/// 32 bytes from the OS CSPRNG, via `uuid`'s getrandom-backed v4 generator (each UUID
/// fixes 6 bits for version/variant, so this is ~244 bits — far more than a blinding
/// key needs, and it avoids adding a dependency for one array).
fn blinding_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    key[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    key
}

/// No early exit, on equal-length inputs only (both are HMAC tags).
fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ── the wire contract ──────────────────────────────────────────────────────────

/// What the control plane asserts about a caller when asking for a session.
///
/// `deny_unknown_fields` is deliberate and has a cost: when the caller adds a field,
/// every mint fails until this binary is redeployed (deploy s0 first, then the thing
/// that uses the new field). It is chosen anyway because a field s0 silently dropped
/// could be a *restriction* the caller believed it had applied, and silently dropping a
/// restriction on a credential mint is the failure this component exists to prevent.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    /// The **raw** OIDC subject: the user id for a user, the client id for a service
    /// account. Never the prefixed subject key — the rego composes `user:<sub>` /
    /// `sa:<sub>` itself, so a pre-prefixed value here would look up `user:user:<sub>`
    /// and find no grants.
    pub sub: String,
    /// `user` | `service_account`. An **enum**, not a free string: serde refuses any
    /// other value, so an unrecognised principal class is a 400 at the door rather than
    /// a session in a key space with no grants — or a typo that silently lands in the
    /// other principal's key space.
    pub principal_type: PrincipalType,
    /// Storage tenant. Must be routable on this gateway.
    pub tenant: String,
    /// Control-plane organization id. Must agree with this gateway's own
    /// tenant→org binding.
    pub organization_id: String,
    /// Role names the control plane believed the caller held at mint time. **Advisory**:
    /// groups are read from the bundle, never from the session, because token claims are
    /// frozen at mint and a role change must be revocable inside one poll. Carried so an
    /// audit record shows what the caller believed.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Requested lifetime. Clamped to the configured maximum; see
    /// [`InternalApi::clamp_ttl`].
    pub duration_seconds: u64,
}

/// The body of `POST /internal/v1/derived-keys`.
///
/// The first four fields are [`SessionRequest`]'s, with the same meanings and the same
/// `deny_unknown_fields` reasoning. What is **absent** is the contract:
///
/// * no `duration_seconds` — the credential does not expire; it ends when the epoch
///   floor rises past it;
/// * no `groups`, not even advisory: a key outliving every group it was minted under
///   would make that record misleading, and groups are read live from the bundle;
/// * no scope, prefix or permission field, and deliberately nowhere to put one. Baking
///   scope into a long-lived credential breaks live revocation.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DerivedKeyRequest {
    /// The **raw** OIDC subject — the client id for a service account, the user id for a
    /// user. See [`SessionRequest::sub`]; the prefix is composed downstream.
    pub sub: String,
    /// `user` | `service_account`.
    pub principal_type: PrincipalType,
    /// Storage tenant. Must be routable on this gateway.
    pub tenant: String,
    /// Control-plane organization id. Must agree with this gateway's tenant→org binding.
    pub organization_id: String,
    /// Which epoch to stamp. Absent ⇒ the revocation floor in force, which is what a
    /// first issue wants. A rotation passes `floor + 1` so the new key and the one it
    /// replaces can both work until the old one is revoked — see
    /// [`crate::auth::DerivedKeys::mint`]. Below the floor is refused, not clamped.
    #[serde(default)]
    pub key_epoch: Option<u32>,
}

/// The response. **Both halves, once** — nothing is stored on this side, so a caller
/// that loses `secret_access_key` has to mint a new key rather than re-read this one.
///
/// `key_epoch` and `kid` are returned because a caller's issuance ledger cannot
/// recompute them: the epoch is what a later revocation must raise the floor past, and
/// the kid says which ring signed it, which makes a rotation's blast radius answerable.
#[derive(Debug, Clone, serde::Serialize)]
pub struct MintedDerivedKeyResponse {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub key_epoch: u32,
    pub kid: String,
}

/// Why a session was not minted. Every variant is a **refusal**, never a downgrade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionRefusal {
    /// No usable shared secret is configured, or the presented one did not match.
    Unauthenticated,
    /// The body was absent, too large, not JSON, carried an unknown field, or carried
    /// a `principal_type` outside the enum.
    Malformed(String),
    /// `sub` is empty. A session with no subject composes the key `sa:` / `user:`,
    /// which is a real key an accidental grant could match.
    EmptySubject,
    /// `duration_seconds` is 0. Not clamped up: a caller asking for a zero-length
    /// session has a configuration bug, and silently handing back a credential that
    /// expires in one second turns it into an intermittent one.
    ZeroDuration,
    /// The tenant is not in this gateway's routing table. s0 would deny every request
    /// under such a session anyway; refusing at mint makes the misconfiguration visible
    /// to the caller instead of as an unexplained 403 storm later.
    UnroutableTenant(String),
    /// The asserted organization disagrees with this gateway's authoritative
    /// tenant→org binding. Fails closed: the decision path attributes from the route,
    /// not from the claim, so such a session would evaluate against an org the caller
    /// did not name — an attribution drift that nothing downstream could detect.
    OrganizationMismatch,
    /// The STS authority refused (an empty sid, a ring problem).
    MintFailed(String),
}

impl SessionRefusal {
    pub fn status(&self) -> StatusCode {
        match self {
            SessionRefusal::Unauthenticated => StatusCode::UNAUTHORIZED,
            SessionRefusal::MintFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }

    /// The message returned to the caller. The caller is already authenticated, so
    /// naming the offending field is a diagnostic and not a leak — but nothing here
    /// ever interpolates a credential.
    pub fn message(&self) -> String {
        match self {
            SessionRefusal::Unauthenticated => "unauthenticated".into(),
            SessionRefusal::Malformed(why) => format!("malformed session request: {why}"),
            SessionRefusal::EmptySubject => "sub must be non-empty".into(),
            SessionRefusal::ZeroDuration => "duration_seconds must be > 0".into(),
            SessionRefusal::UnroutableTenant(t) => {
                format!("tenant {t:?} is not routable on this gateway")
            }
            SessionRefusal::OrganizationMismatch => {
                "organization_id disagrees with this gateway's tenant binding".into()
            }
            SessionRefusal::MintFailed(why) => format!("mint failed: {why}"),
        }
    }
}

// ── the endpoint ───────────────────────────────────────────────────────────────

/// The control-plane-mediated session mint.
///
/// Holds the **same** [`StsAuthority`] the S3 front verifies with, so a session minted
/// here is indistinguishable from any other: one key ring, one code path. A credential
/// this endpoint could mint that the data plane could not verify, or vice versa, would
/// be undetectable from either side alone.
pub struct InternalApi {
    auth: SharedSecretAuth,
    sts: Arc<StsAuthority>,
    /// The authoritative tenant→org binding, consulted to check that the named tenant is
    /// one this gateway can actually route.
    registry: Arc<BackendRegistry>,
    max_ttl_secs: u64,
    /// The **same** [`DerivedKeys`] the S3 front admits keys with, for the reason the
    /// same `StsAuthority` is shared: one ring, one epoch source, one encoding.
    /// `None` when the deployment configured no ring, which makes [`DERIVED_KEY_PATH`]
    /// answer 409 rather than 404 — the path exists, the feature is off, and those are
    /// different problems for whoever reads the response.
    derived: Option<Arc<DerivedKeys>>,
}

impl InternalApi {
    pub fn new(
        cfg: &InternalApiConfig,
        sts: Arc<StsAuthority>,
        registry: Arc<BackendRegistry>,
    ) -> Self {
        InternalApi {
            auth: SharedSecretAuth::new(cfg.shared_secret.as_ref()),
            sts,
            registry,
            max_ttl_secs: cfg.max_session_ttl_secs,
            derived: None,
        }
    }

    /// Switch on `POST /internal/v1/derived-keys`. Additive: a caller that does not
    /// supply this gets a binary whose derived-key path is off.
    pub fn with_derived_keys(mut self, derived: Option<Arc<DerivedKeys>>) -> Self {
        self.derived = derived;
        self
    }

    /// True when a usable shared secret is configured. Callers log this at startup;
    /// `false` means this listener will refuse every request it ever receives.
    pub fn is_authenticated(&self) -> bool {
        self.auth.is_configured()
    }

    /// **Clamp, not refuse.**
    ///
    /// The requested duration is control-plane configuration an operator edits, so
    /// refusing an over-cap value would turn one number there into a total credential
    /// outage for that organization. Clamping can only shorten a credential's life and
    /// is observable — the response's `Expiration` says exactly when it ends — and it is
    /// logged at `warn` with both numbers. Zero is *not* clamped up; see
    /// [`SessionRefusal::ZeroDuration`].
    fn clamp_ttl(&self, requested: u64) -> u64 {
        if requested > self.max_ttl_secs {
            tracing::warn!(
                requested,
                max = self.max_ttl_secs,
                "session ttl request exceeds the configured maximum; clamping"
            );
            return self.max_ttl_secs;
        }
        requested
    }

    /// Validate the asserted facts and mint. `sid` is caller-supplied (random at the
    /// endpoint, fixed in tests) so this stays deterministic.
    pub fn mint_session(
        &self,
        req: &SessionRequest,
        sid: &str,
    ) -> std::result::Result<MintedCredentials, SessionRefusal> {
        if req.sub.trim().is_empty() {
            return Err(SessionRefusal::EmptySubject);
        }
        if req.duration_seconds == 0 {
            return Err(SessionRefusal::ZeroDuration);
        }
        // The tenant must be routable *on this gateway*. This is the same table the
        // request pipeline resolves against, so "mintable" and "usable" cannot drift.
        let route = self
            .registry
            .route_snapshot(&req.tenant)
            .ok_or_else(|| SessionRefusal::UnroutableTenant(req.tenant.clone()))?;
        // …and the named org must be the one this gateway binds that tenant to. The
        // decision path attributes from the route, never from the claim, so a
        // disagreement here would produce a session that silently evaluates against a
        // different organization than the one it was minted for.
        if route.organization_id != req.organization_id {
            tracing::warn!(
                tenant = %req.tenant,
                asserted = %req.organization_id,
                bound = %route.organization_id,
                "refusing a session whose organization disagrees with the tenant binding"
            );
            return Err(SessionRefusal::OrganizationMismatch);
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SessionRefusal::MintFailed(format!("clock: {e}")))?
            .as_secs();
        let claims = SessionClaims {
            sub: req.sub.clone(),
            // The reason this endpoint exists: the principal class is stated by the
            // control plane and carried into the session, so a service-account session
            // evaluates in the `sa:` key space.
            principal_type: req.principal_type,
            groups: req.groups.clone(),
            tenant: req.tenant.clone(),
            org: req.organization_id.clone(),
            sid: sid.to_string(),
            exp: now + self.clamp_ttl(req.duration_seconds),
        };
        self.sts
            .mint(sid, claims)
            .map(MintedCredentials::from)
            .map_err(|e| SessionRefusal::MintFailed(e.to_string()))
    }

    /// Route one request. **Authentication first**, before the method check, the path
    /// match, or any read of the body.
    async fn route(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        if !self.auth.accepts(req.headers()) {
            // Deliberately uniform: no distinction between "no secret configured on
            // this gateway", "no header sent" and "wrong value", and no hint about
            // which paths exist. One `warn` line, no credential material in it.
            tracing::warn!(
                path = %req.uri().path(),
                configured = self.auth.is_configured(),
                "internal request refused: shared secret missing or wrong"
            );
            return refuse(&SessionRefusal::Unauthenticated);
        }
        if req.method() != Method::POST {
            return json_error(StatusCode::METHOD_NOT_ALLOWED, "use POST");
        }
        let path = req.uri().path().to_string();
        if path != SESSION_PATH && path != DERIVED_KEY_PATH {
            return json_error(StatusCode::NOT_FOUND, "not found");
        }

        let body = match Limited::new(req.into_body(), MAX_BODY_BYTES)
            .collect()
            .await
        {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return refuse(&SessionRefusal::Malformed(format!(
                    "body exceeds {MAX_BODY_BYTES} bytes or could not be read"
                )));
            }
        };
        if path == DERIVED_KEY_PATH {
            return self.route_derived_key(&body);
        }
        let parsed: SessionRequest = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(e) => return refuse(&SessionRefusal::Malformed(e.to_string())),
        };

        let sid = uuid::Uuid::new_v4().to_string();
        match self.mint_session(&parsed, &sid) {
            Ok(creds) => match serde_json::to_vec(&creds) {
                Ok(body) => json_ok(body),
                Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "encode failed"),
            },
            Err(refusal) => {
                // The refusal reason is logged; the credential is not, because there
                // is not one. `sub` and `tenant` are identifiers, not secrets, and
                // without them a refusal is undiagnosable.
                tracing::warn!(
                    sub = %parsed.sub,
                    tenant = %parsed.tenant,
                    reason = %refusal.message(),
                    "session mint refused"
                );
                refuse(&refusal)
            }
        }
    }

    /// `POST /internal/v1/derived-keys`, past authentication and the body read.
    ///
    /// Logs the tenant, subject and epoch — never the access-key id, which is half of a
    /// credential that does not expire and would otherwise sit in a log aggregator for
    /// as long as the key lives. Stricter than the STS path needs; the lifetime is what
    /// makes it necessary.
    fn route_derived_key(&self, body: &[u8]) -> Response<Full<Bytes>> {
        let Some(derived) = self.derived.as_ref() else {
            return json_error(
                StatusCode::CONFLICT,
                "long-lived keys are not configured on this gateway (no `derived_keys` \
                 section); the path exists but the feature is off",
            );
        };
        let parsed: DerivedKeyRequest = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(e) => {
                return refuse(&SessionRefusal::Malformed(format!(
                    "malformed derived key request: {e}"
                )));
            }
        };
        match derived.mint(
            &parsed.tenant,
            &parsed.organization_id,
            parsed.principal_type,
            &parsed.sub,
            parsed.key_epoch,
        ) {
            Ok(minted) => {
                tracing::info!(
                    sub = %parsed.sub,
                    tenant = %parsed.tenant,
                    key_epoch = minted.key_epoch,
                    kid = %minted.kid,
                    "minted a long-lived key"
                );
                let response = MintedDerivedKeyResponse {
                    access_key_id: minted.credential.access_key_id,
                    secret_access_key: minted.credential.secret_access_key,
                    key_epoch: minted.key_epoch,
                    kid: minted.kid,
                };
                match serde_json::to_vec(&response) {
                    Ok(body) => json_ok(body),
                    Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "encode failed"),
                }
            }
            Err(refusal) => {
                tracing::warn!(
                    sub = %parsed.sub,
                    tenant = %parsed.tenant,
                    reason = %refusal.message(),
                    "long-lived key mint refused"
                );
                json_error(derived_mint_status(&refusal), &refusal.message())
            }
        }
    }
}

/// A tenant that has not opted in, and a tenant that does not exist here, are different
/// answers on purpose: the first is one control-plane action away from working (publish
/// the epoch), the second is a routing mistake.
fn derived_mint_status(refusal: &DerivedMintRefusal) -> StatusCode {
    match refusal {
        // Both are "the state moved under you", not "your request is malformed": a
        // caller that retries after re-reading the floor succeeds.
        DerivedMintRefusal::NotEnabledForTenant(_) | DerivedMintRefusal::EpochBelowFloor { .. } => {
            StatusCode::CONFLICT
        }
        DerivedMintRefusal::MintFailed(_) => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::BAD_REQUEST,
    }
}

fn refuse(refusal: &SessionRefusal) -> Response<Full<Bytes>> {
    json_error(refusal.status(), &refusal.message())
}

fn json_ok(body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .expect("response")
}

fn json_error(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({ "error": msg }).to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .expect("response")
}

/// Serve the internal API until the caller triggers shutdown.
///
/// Same drain discipline as the S3 front and the mint: accept inside the `select`, so an
/// idle listener still observes the signal, and a bounded graceful drain rather than an
/// abort mid-request — a mint the runtime aborts looks to the caller like an unexplained
/// credential failure on every deploy.
pub async fn serve_with_shutdown(
    api: Arc<InternalApi>,
    listen: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    serve_on(api, TcpListener::bind(listen).await?, shutdown).await
}

/// As [`serve_with_shutdown`], on an already-bound listener.
///
/// Split out so a caller that must know the bound address — the integration suite, which
/// binds `127.0.0.1:0` and reads the port back — exercises **this** serving path rather
/// than a substitute. This endpoint's safety argument is about the order things happen
/// in on the way through, so a test driving a different loop would test the wrong loop.
pub async fn serve_on(
    api: Arc<InternalApi>,
    listener: TcpListener,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    let listen = listener.local_addr()?;
    if api.is_authenticated() {
        tracing::info!(%listen, path = SESSION_PATH, "internal api listening (shared-secret authenticated)");
    } else {
        // Loud, at error level, once per process: this listener is up and will refuse
        // every request it ever receives. An operator who rendered no secret must not
        // have to infer that from a wall of 401s.
        tracing::error!(
            %listen,
            "internal api listening but NO shared secret is configured: every request \
             will be refused. Set internal.shared_secret, or remove the `internal` \
             section to not bind this port at all."
        );
    }
    let http = ConnBuilder::new(TokioExecutor::new());
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);

    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = &mut shutdown => {
                tracing::info!("shutdown signal; draining internal api connections");
                break;
            }
        };
        let (stream, _) = match accepted {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%e, "internal api accept failed; backing off");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let api = api.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let api = api.clone();
            async move { Ok::<_, std::convert::Infallible>(api.route(req).await) }
        });
        let conn = http
            .serve_connection(TokioIo::new(stream), svc)
            .into_owned();
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }

    tokio::select! {
        _ = graceful.shutdown() => tracing::info!("internal api connections drained"),
        _ = tokio::time::sleep(INTERNAL_DRAIN_TIMEOUT) => {
            tracing::warn!(timeout = ?INTERNAL_DRAIN_TIMEOUT, "internal api drain timed out");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: Option<&str>) -> HeaderMap {
        let mut h = HeaderMap::new();
        if let Some(v) = value {
            h.insert(SHARED_SECRET_HEADER, v.parse().expect("header value"));
        }
        h
    }

    #[test]
    fn an_absent_or_empty_secret_refuses_everything() {
        // The failure a reviewer must never find: a gateway that was deployed without
        // the secret rendered and kept minting. All four of these are the same answer.
        for configured in [None, Some(Secret::from("")), Some(Secret::from("   "))] {
            let auth = SharedSecretAuth::new(configured.as_ref());
            assert!(!auth.is_configured());
            assert!(!auth.accepts(&headers(None)), "no header must not pass");
            assert!(
                !auth.accepts(&headers(Some(""))),
                "empty header must not pass"
            );
            assert!(!auth.accepts(&headers(Some("   "))));
            assert!(!auth.accepts(&headers(Some("anything"))));
            // Not even the literal the operator failed to configure.
            assert!(!auth.accepts(&headers(Some("null"))));
        }
    }

    #[test]
    fn only_the_configured_secret_is_accepted() {
        let auth = SharedSecretAuth::new(Some(&Secret::from("s3cr3t-value")));
        assert!(auth.is_configured());
        assert!(auth.accepts(&headers(Some("s3cr3t-value"))));
        for wrong in [
            "",
            "s3cr3t-valu",   // one short
            "s3cr3t-values", // one long
            "s3cr3t-valuE",  // one bit
            "S3CR3T-VALUE",
            " s3cr3t-value",
        ] {
            assert!(
                !auth.accepts(&headers(Some(wrong))),
                "{wrong:?} must not authenticate"
            );
        }
    }

    #[test]
    fn the_shared_secret_is_not_reachable_through_debug() {
        let auth = SharedSecretAuth::new(Some(&Secret::from("PLAINTEXT-SHARED-SECRET")));
        let rendered = format!("{auth:?}");
        assert!(!rendered.contains("PLAINTEXT"), "{rendered}");
        assert!(rendered.contains("configured: true"), "{rendered}");
    }

    #[test]
    fn the_principal_type_is_an_enum_not_a_free_string() {
        let body = |t: &str| {
            format!(
                r#"{{"sub":"x","principal_type":"{t}","tenant":"acme",
                     "organization_id":"org-acme","groups":[],"duration_seconds":900}}"#
            )
        };
        assert_eq!(
            serde_json::from_str::<SessionRequest>(&body("service_account"))
                .expect("service_account parses")
                .principal_type,
            PrincipalType::ServiceAccount
        );
        assert_eq!(
            serde_json::from_str::<SessionRequest>(&body("user"))
                .expect("user parses")
                .principal_type,
            PrincipalType::User
        );
        // Anything else is a parse failure — a 400 at the door, not a session in a key
        // space with no grants.
        for bad in ["admin", "User", "serviceaccount", "sa", ""] {
            assert!(
                serde_json::from_str::<SessionRequest>(&body(bad)).is_err(),
                "principal_type {bad:?} must not deserialize"
            );
        }
    }

    #[test]
    fn an_unknown_field_is_refused_rather_than_dropped() {
        // A field the caller added and this binary does not implement could be a
        // restriction. Dropping it silently is the failure mode; refusing is loud and
        // is fixed by the documented rollout order (s0 image first).
        let err = serde_json::from_str::<SessionRequest>(
            r#"{"sub":"x","principal_type":"user","tenant":"acme","organization_id":"org-acme",
                "groups":[],"duration_seconds":900,"require_mfa":true}"#,
        )
        .expect_err("an unknown field must not be dropped");
        assert!(err.to_string().contains("require_mfa"), "{err}");
    }
}
