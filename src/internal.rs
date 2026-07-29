//! The **authenticated** internal control-plane surface: `POST
//! /internal/v1/sts/sessions`, the console-mediated session mint.
//!
//! # Why this exists at all — the mint next door cannot serve hyperfluid
//!
//! s0 already has a badge desk ([`crate::mint`]): present a Keycloak OIDC token, get a
//! gateway session. It cannot be the path hyperfluid uses, for two reasons that are
//! properties of *token-mediated* minting rather than bugs to be fixed in it:
//!
//! 1. `StandardVerifier::extract` resolves `tenant` and `org` through `str_claim`,
//!    which **errors when the claim is absent**. Hyperfluid's Keycloak tokens carry
//!    neither. The organization is derived from the issuer path or a control-plane
//!    lookup, and there is no tenant claim at all — the Ceph tenant is a property of
//!    the *harbor being addressed*, not of the *user*, so a user with access to three
//!    harbors would need three values of a claim that is minted once per login.
//! 2. `Mint::mint` hard-codes `principal_type: PrincipalType::User`, and
//!    `VerifiedIdentity` has no field to override it with. **Service accounts are the
//!    primary consumer of object storage here**, and the bundle keys their grants
//!    under `sa:<client id>` while a user's live under `user:<oidc sub>`. Every SA
//!    session minted through that door would look up the wrong key space and evaluate
//!    against no grants at all.
//!
//! The IdP would have to learn facts only the control plane knows. So the console —
//! which has already authenticated the caller, already resolved their organization,
//! already resolved the harbor's Ceph tenant, and already knows whether it is looking
//! at a user or a service account — *states* those facts to s0 over the internal
//! network, authenticated with the platform shared secret.
//!
//! # A session is an identity assertion, not a grant of authority
//!
//! This endpoint mints a credential that says "this is `sa:pipeline-runner`, in tenant
//! `acme-prod`, in org X". It confers **nothing**. Everything that decides whether a
//! request is allowed is read from the bundle at decision time, which is what makes
//! console-mediated minting safe: a revoked grant takes effect within one bundle poll
//! even for a session minted a moment earlier. The claims cannot over-grant because no
//! rule reads authority out of them.
//!
//! # Why its own listener, and not the admin listener
//!
//! The constraint is narrow and absolute: **a credential-minting endpoint must never
//! be reachable from the S3 data-plane listener or from an Ingress.** The data plane
//! is out immediately — it is fronted by an Ingress on `<org>.s3-gw.<domain>` and is
//! reachable from the public internet. That leaves two candidates.
//!
//! *Authenticate the existing admin listener* was rejected:
//!
//! - The admin listener is unauthenticated **by construction, not by omission**. A
//!   kubelet `httpGet` probe cannot present a secret, and neither can a Prometheus
//!   scrape without provisioning the platform's machine credential into the scrape
//!   config. Authenticating the port therefore means *exempting* `/healthz`,
//!   `/readyz` and `/metrics` — i.e. a port where whether a request is authenticated
//!   is a **routing** question. That is precisely the shape of every fail-open
//!   surface: one added route, one path-prefix match written slightly wrong, and the
//!   mint is answering unauthenticated. Keeping the two on different sockets makes
//!   "unauthenticated" a property of the listener, and the property is checked once,
//!   at accept, for everything it serves.
//! - The admin port is **published on the Service for scraping** and is deliberately
//!   the target of the probes. Its network posture is "whatever can reach a metrics
//!   port", which is not the posture a credential mint should inherit.
//! - Two ports are two NetworkPolicy targets. An operator can allow the monitoring
//!   namespace to 8016 and only the console to 8017. One port cannot express that.
//!
//! What the separate listener does **not** buy is confidentiality of the bind
//! address: like the admin listener it binds `0.0.0.0`, because the caller is the
//! console in a different pod. Reachability is fenced by the Service and by a
//! NetworkPolicy; *authorization* is fenced here, by the shared secret. Neither is
//! trusted to be the only one.
//!
//! # Authentication
//!
//! The platform idiom, matched exactly: the `X-Shared-Secret` header
//! ([`SHARED_SECRET_HEADER`], the same literal as hyperfluid's
//! `hf_lib_config::SHARED_SECRET_HEADER`), compared in constant time.
//!
//! **A missing or empty configured secret refuses every request.** There is no
//! "unauthenticated mode", no dev bypass and no `allow_anonymous` flag: the failure a
//! reviewer must never find is a deployment where the secret was not rendered and the
//! endpoint quietly kept minting. [`SharedSecretAuth::accepts`] returns `false` before
//! it looks at the request when there is nothing to compare against.
//!
//! Authentication happens **before** the method check, before the path match and
//! before the body is read. An unauthenticated caller learns nothing from this
//! listener — not which paths exist, not which methods they take, and it can make this
//! process allocate nothing beyond one set of request headers.

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
use crate::config::InternalApiConfig;
use crate::error::Result;
use crate::mint::MintedCredentials;
use crate::model::PrincipalType;
use crate::proxy::BackendRegistry;
use crate::secret::Secret;

type HmacSha256 = Hmac<Sha256>;

/// The platform-wide machine-to-machine auth header.
///
/// Held equal to hyperfluid's `hf_lib_config::SHARED_SECRET_HEADER` by
/// `tests/cross_repo_contract.rs`. Matching it is not cosmetic: the console sends this
/// header and nothing else, so a different name here is a 401 on every mint — an org
/// that has opted in gets no credentials at all, with no fallback, because
/// `decide_issuance_path` never falls back to the legacy path once the flag is on.
pub const SHARED_SECRET_HEADER: &str = "X-Shared-Secret";

/// The session endpoint's path. Held equal to hyperfluid's
/// `s3_gateway_sts::GATEWAY_SESSION_PATH` by `tests/cross_repo_contract.rs`.
pub const SESSION_PATH: &str = "/internal/v1/sts/sessions";

/// Ceiling on a session request body. The document is six small fields; anything
/// larger is a mistake or an attempt to make this process allocate. Applied *after*
/// authentication, so it bounds an authenticated caller — the unauthenticated one
/// never reaches the body at all.
const MAX_BODY_BYTES: usize = 16 * 1024;

/// In-flight budget on shutdown. A mint is an in-process HMAC; anything still running
/// past this is a stuck socket.
const INTERNAL_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

// ── authentication ─────────────────────────────────────────────────────────────

/// Constant-time shared-secret check, with "not configured" folded into the same
/// answer as "wrong".
///
/// The comparison is a **double HMAC**: both the configured secret and the presented
/// one are MAC'd under a key generated once per process, and the two 32-byte tags are
/// compared with a fold that has no early exit. This is stronger than a hand-rolled
/// byte compare in the way that matters here — a length check that returns early
/// leaks the secret's length, and a naive `==` on the raw values leaks a prefix
/// through timing. Tags are always the same length, so neither is observable.
///
/// The plaintext secret is touched exactly once, at construction, and is not retained.
pub struct SharedSecretAuth {
    /// Blinding key, per process. Never leaves this struct.
    key: [u8; 32],
    /// `HMAC(key, configured_secret)`. **`None` ⇒ refuse everything.**
    tag: Option<[u8; 32]>,
}

impl std::fmt::Debug for SharedSecretAuth {
    /// Renders whether a secret is configured and nothing else — that fact is
    /// operationally essential (it is the difference between "minting" and "refusing
    /// every request") and is not itself secret.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecretAuth")
            .field("configured", &self.tag.is_some())
            .finish()
    }
}

impl SharedSecretAuth {
    /// Build from the configured value. Absent, empty, or whitespace-only all mean
    /// **no secret**: a kubernetes Secret that rendered an empty string, or a
    /// `"   "` left by a template, is not a credential and must not be treated as one.
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

/// What the console asserts about a caller when asking for a session.
///
/// This shape is hyperfluid's `GatewaySessionRequest`, field for field, and is pinned
/// from both sides by `tests/cross_repo_contract.rs` — including by replaying the
/// exact JSON the console's own contract test asserts.
///
/// `deny_unknown_fields` is deliberate and has a cost worth stating: if the console
/// ever adds a field, every mint fails until this binary is redeployed. That is the
/// same rollout-ordering rule the obligations already impose (*deploy the s0 image
/// first, then the thing that uses the new field*), and it is chosen over the
/// alternative for the usual reason — a field s0 silently drops could be a
/// *restriction* the console believed it had applied, and silently dropping a
/// restriction on a credential mint is the failure this whole component exists to
/// prevent. The contract test reddens before such a change can ship.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionRequest {
    /// The **raw** OIDC subject: the Keycloak user id for a user, the Keycloak
    /// `clientId` for a service account. Never the prefixed subject key — the rego
    /// composes `user:<sub>` / `sa:<sub>` itself, so a pre-prefixed value here would
    /// look up `user:user:<sub>` and find no grants.
    pub sub: String,
    /// `user` | `service_account`. An **enum**, not a free string: serde refuses any
    /// other value at deserialization, so an unrecognised principal class is a 400 at
    /// the door rather than a session in a key space that has no grants (or, worse,
    /// a typo that silently lands in the other principal's key space).
    pub principal_type: PrincipalType,
    /// Ceph tenant == harbor slug. Must be routable on this gateway.
    pub tenant: String,
    /// Control-plane organization id. Must agree with this gateway's own
    /// tenant→org binding.
    pub organization_id: String,
    /// Role names the console believed the caller held at mint time. **Advisory**:
    /// the module reads groups from the bundle, never from the session, because token
    /// claims are frozen at mint and a role change must be revocable inside one poll.
    /// Carried so an audit record shows what the console believed.
    #[serde(default)]
    pub groups: Vec<String>,
    /// Requested lifetime. Clamped to the configured maximum; see
    /// [`InternalApi::clamp_ttl`].
    pub duration_seconds: u64,
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
    /// The tenant is not in this gateway's routing table. The bundle's tenant table
    /// is built from the same bindings, so s0 would deny every request under such a
    /// session anyway — refusing at mint makes the misconfiguration visible at the
    /// console instead of as an unexplained 403 storm later.
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

    /// The message returned to the caller. The caller is the console, holding the
    /// platform credential, so naming the field is a diagnostic and not a leak — but
    /// nothing here ever interpolates a credential.
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

/// The console-mediated session mint.
///
/// Holds the **same** [`StsAuthority`] the S3 front verifies with (handed over from
/// `Identity::sts()`), so a session minted here is indistinguishable from any other:
/// same key ring, same `HFST<kid>.<sid>` access-key shape, same derived secret, same
/// signed claims, same retirement semantics on a rotation. There is deliberately no
/// second authority and no second code path — a credential this endpoint could mint
/// that the data plane could not verify, or vice versa, would be undetectable from
/// either side alone.
pub struct InternalApi {
    auth: SharedSecretAuth,
    sts: Arc<StsAuthority>,
    /// The authoritative tenant→org binding, consulted to check that the tenant the
    /// console names is one this gateway can actually route.
    registry: Arc<BackendRegistry>,
    max_ttl_secs: u64,
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
        }
    }

    /// True when a usable shared secret is configured. Callers log this at startup;
    /// `false` means this listener will refuse every request it ever receives.
    pub fn is_authenticated(&self) -> bool {
        self.auth.is_configured()
    }

    /// **Clamp, not refuse.**
    ///
    /// The requested duration comes from `OrgStorage.spec.s3Gateway.sessionTtlSecs`,
    /// which lives in the *other* repository and is edited by an operator patching a
    /// CR. Refusing an over-cap request would turn one number in a CR into a total
    /// credential outage for that organization — and there is no fallback, because
    /// `decide_issuance_path` deliberately never returns to the legacy path once the
    /// flag is on. Clamping is strictly the safer direction (it can only shorten a
    /// credential's life), the answer is observable (the response's `Expiration` says
    /// exactly when it ends), and it is what the console already documents s0 as
    /// doing: *"s0 clamps it to its own maximum; this is a request, not a
    /// guarantee."* Matching the contract the other side already shipped beats
    /// inventing a stricter one.
    ///
    /// A clamp is logged at `warn` with both numbers, so a persistently over-cap CR is
    /// visible rather than merely survivable. Zero is *not* clamped up — see
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

    /// Validate the console's assertions and mint. `sid` is caller-supplied (random at
    /// the endpoint, fixed in tests) so this stays deterministic.
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
        // …and the org the console names must be the org this gateway binds that
        // tenant to. The decision path attributes from the route (`RouteSnapshot`),
        // never from the claim, so a disagreement here would produce a session that
        // silently evaluates against a different organization than the one it was
        // minted for.
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
            // The whole reason this endpoint exists: the principal class is stated by
            // the control plane and carried into the session, so a service-account
            // session evaluates in the `sa:` key space.
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
        if req.uri().path() != SESSION_PATH {
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
/// Same drain discipline as the S3 front and the mint: accept inside the `select`, so
/// an idle listener still observes the signal, and a bounded graceful drain rather
/// than an abort mid-request (a mint aborted by the runtime looks to the console like
/// an unexplained credential failure on every deploy).
pub async fn serve_with_shutdown(
    api: Arc<InternalApi>,
    listen: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    serve_on(api, TcpListener::bind(listen).await?, shutdown).await
}

/// As [`serve_with_shutdown`], on an already-bound listener.
///
/// Split out so a caller that must know the bound address — the integration suite,
/// which binds `127.0.0.1:0` and reads the port back — exercises **this** serving
/// path rather than a hand-rolled substitute. A test that drives a different loop than
/// production is a test of the wrong loop, and this endpoint's whole safety argument
/// is about the order things happen in on the way through it.
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
        // A field the console added and this binary does not implement could be a
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
