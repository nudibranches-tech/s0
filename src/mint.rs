//! STS mint — the "badge desk". A backend-agnostic control-plane endpoint:
//! it verifies a Keycloak OIDC token and issues short-lived **gateway** credentials
//! that the gateway itself later verifies (derived secrets, [`crate::auth::sts`]).
//!
//! No backend (Ceph/RGW/RustFS/…) is ever involved — this supersedes RGW's STS
//! and works identically regardless of what object store sits behind the gateway.
//!
//! # Two doors, one socket
//!
//! This listener serves two protocols, and which one a request gets is decided by the
//! request itself — not by a path:
//!
//! * **`Action=AssumeRoleWithWebIdentity`** (a form-encoded body carrying an `Action`
//!   parameter) ⇒ the AWS STS query protocol, XML in and out. This is the door every S3
//!   SDK can use with stock configuration, and it is the only one that can mint a
//!   *service-account* session. It lives in [`crate::webidentity`], which carries the
//!   design argument.
//! * **anything else** ⇒ the original bearer-token JSON exchange below.
//!
//! Discriminating on the presence of `Action` rather than on a URL path is what the AWS
//! query protocol *is* — an SDK POSTs to `/` and puts the action in the body — so there
//! is no path to get subtly wrong, and a request that carries no `Action` cannot reach
//! the STS surface at all.
//!
//! Both doors are unauthenticated in the sense that no *platform* credential is
//! presented, and that is correct rather than tolerated: the OIDC token **is** the
//! credential, exactly as at `sts.amazonaws.com`. It is why this socket is not, and must
//! never become, the socket [`crate::internal`] serves on.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde::Serialize;
use serde_json::Value;
use tokio::net::TcpListener;

use crate::auth::sts::{SessionClaims, StsAuthority};
use crate::config::StsMintConfig;
use crate::error::{GatewayError, Result};
use crate::model::PrincipalType;
use crate::webidentity::{
    Params, StsRefusal, WebIdentitySts, WebIdentityVerifier, render_assume_role_response,
    render_error_response,
};

/// Identity verified from an OIDC token, to be minted into a gateway session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub sub: String,
    pub groups: Vec<String>,
    pub tenant: String,
    pub org: String,
}

/// Which claims carry tenant/org/groups (Keycloak custom claims are deployment-named).
#[derive(Debug, Clone)]
pub struct ClaimNames {
    pub sub: String,
    pub groups: String,
    pub tenant: String,
    pub org: String,
}

#[async_trait::async_trait]
pub trait OidcVerifier: Send + Sync {
    async fn verify(&self, token: &str) -> Result<VerifiedIdentity>;
}

/// Where the token-signing public key comes from.
enum KeySource {
    /// Static RS256 public key (PEM).
    Pem(DecodingKey),
    /// JWKS endpoint; keys cached, refreshed periodically in the background and on a
    /// `kid` miss (rotation).
    Jwks {
        uri: String,
        client: reqwest::Client,
        cache: ArcSwap<JwkSet>,
        refresh_interval: Duration,
    },
}

/// Production OIDC verifier: RS256, issuer + audience + expiry validated, claims
/// extracted by configured name.
pub struct StandardVerifier {
    key_source: KeySource,
    issuer: String,
    audience: String,
    claims: ClaimNames,
    /// Audiences the [`crate::webidentity`] door accepts, matched against `aud` **or**
    /// `azp`/`client_id`. Empty ⇒ `[audience]`. See
    /// [`StsMintConfig::web_identity_audiences`] for why the two doors differ.
    web_identity_audiences: Vec<String>,
}

impl StandardVerifier {
    pub fn from_config(cfg: &StsMintConfig) -> Result<Self> {
        let key_source = match (&cfg.public_key_pem, &cfg.jwks_uri) {
            (Some(pem), _) => KeySource::Pem(
                DecodingKey::from_rsa_pem(pem.as_bytes())
                    .map_err(|e| GatewayError::Config(format!("oidc public_key_pem: {e}")))?,
            ),
            (None, Some(uri)) => KeySource::Jwks {
                uri: uri.clone(),
                // A JWKS fetch can happen inline in a mint request (kid miss), so an
                // unbounded client lets one hung IdP hang every credential request
                // behind it. Bounded here, at the only construction site.
                client: reqwest::Client::builder()
                    .timeout(Duration::from_secs(cfg.jwks_timeout_secs))
                    .connect_timeout(
                        Duration::from_secs(cfg.jwks_timeout_secs).min(Duration::from_secs(3)),
                    )
                    .build()
                    .map_err(|e| GatewayError::Config(format!("jwks http client: {e}")))?,
                cache: ArcSwap::from_pointee(empty_jwks()),
                refresh_interval: Duration::from_secs(cfg.jwks_refresh_secs),
            },
            (None, None) => {
                return Err(GatewayError::Config(
                    "sts_mint needs public_key_pem or jwks_uri".into(),
                ));
            }
        };
        Ok(StandardVerifier {
            key_source,
            issuer: cfg.issuer.clone(),
            audience: cfg.audience.clone(),
            claims: ClaimNames {
                sub: cfg.sub_claim.clone(),
                groups: cfg.groups_claim.clone(),
                tenant: cfg.tenant_claim.clone(),
                org: cfg.org_claim.clone(),
            },
            web_identity_audiences: cfg.web_identity_audiences.clone(),
        })
    }

    /// The audiences the web-identity door will accept. Never empty: an empty
    /// configured list falls back to the single `audience`, so there is no configuration
    /// in which a token's audience binding goes unchecked.
    fn accepted_audiences(&self) -> Vec<&str> {
        if self.web_identity_audiences.is_empty() {
            return vec![self.audience.as_str()];
        }
        self.web_identity_audiences
            .iter()
            .map(String::as_str)
            .collect()
    }

    /// Keep the JWKS cache warm in the background.
    ///
    /// Refresh-on-`kid`-miss alone is a cold cache: the first request after a key
    /// rotation pays an inline IdP fetch and *fails* if the IdP is briefly
    /// unreachable — for every replica independently, which is exactly when a
    /// rotation looks like a fleet-wide mint outage. A no-op for a PEM key source or
    /// a zero interval. Returns the task handle so the caller can abort it on
    /// shutdown; dropping it detaches the task.
    pub fn spawn_jwks_refresh(self: &Arc<Self>) -> Option<tokio::task::JoinHandle<()>> {
        let KeySource::Jwks {
            refresh_interval, ..
        } = &self.key_source
        else {
            return None;
        };
        let interval = *refresh_interval;
        if interval.is_zero() {
            return None;
        }
        let verifier = self.clone();
        Some(tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                // The first tick completes immediately, so the cache is warm before
                // the first mint request rather than one interval later.
                ticker.tick().await;
                match verifier.refresh_jwks().await {
                    Ok(n) => tracing::debug!(keys = n, "jwks refreshed"),
                    // Never fatal: the miss-driven path still works, and the previous
                    // key set stays in force.
                    Err(e) => tracing::warn!(%e, "jwks refresh failed; keeping cached keys"),
                }
            }
        }))
    }

    /// Fetch and install the current key set. Returns the number of keys installed.
    async fn refresh_jwks(&self) -> Result<usize> {
        let KeySource::Jwks {
            uri, client, cache, ..
        } = &self.key_source
        else {
            return Ok(0);
        };
        let fresh = fetch_jwks(client, uri).await?;
        // An empty key set would revoke every token this replica can verify. That is
        // never a legitimate rotation state, so treat it as a bad answer and keep what
        // we have (the kid-miss path still refreshes on a real rotation).
        if fresh.keys.is_empty() && !cache.load().keys.is_empty() {
            return Err(GatewayError::Sts(
                "jwks endpoint returned an empty key set; keeping cached keys".into(),
            ));
        }
        let n = fresh.keys.len();
        cache.store(Arc::new(fresh));
        Ok(n)
    }

    async fn decoding_key(&self, token: &str) -> Result<DecodingKey> {
        match &self.key_source {
            KeySource::Pem(k) => Ok(k.clone()),
            KeySource::Jwks {
                uri, client, cache, ..
            } => {
                let kid = decode_header(token)
                    .map_err(|e| GatewayError::Sts(format!("oidc header: {e}")))?
                    .kid
                    .ok_or_else(|| GatewayError::Sts("oidc token missing kid".into()))?;
                if let Some(jwk) = cache.load().find(&kid).cloned() {
                    return DecodingKey::from_jwk(&jwk)
                        .map_err(|e| GatewayError::Sts(format!("jwk: {e}")));
                }
                // kid miss ⇒ refresh (key rotation).
                let fresh = fetch_jwks(client, uri).await?;
                let jwk = fresh
                    .find(&kid)
                    .cloned()
                    .ok_or_else(|| GatewayError::Sts(format!("no jwk for kid {kid}")))?;
                cache.store(Arc::new(fresh));
                DecodingKey::from_jwk(&jwk).map_err(|e| GatewayError::Sts(format!("jwk: {e}")))
            }
        }
    }

    fn extract(&self, claims: &Value) -> Result<VerifiedIdentity> {
        let str_claim = |name: &str| -> Result<String> {
            claims
                .get(name)
                .and_then(Value::as_str)
                .map(str::to_string)
                .ok_or_else(|| GatewayError::Sts(format!("oidc token missing claim {name}")))
        };
        let groups = claims
            .get(&self.claims.groups)
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(String::from)
                    .collect()
            })
            .unwrap_or_default();
        Ok(VerifiedIdentity {
            sub: str_claim(&self.claims.sub)?,
            groups,
            tenant: str_claim(&self.claims.tenant)?,
            org: str_claim(&self.claims.org)?,
        })
    }
}

#[async_trait::async_trait]
impl OidcVerifier for StandardVerifier {
    async fn verify(&self, token: &str) -> Result<VerifiedIdentity> {
        let key = self.decoding_key(token).await?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        validation.set_audience(&[&self.audience]);
        // Require these, not just check-when-present: a token omitting aud/iss must be
        // rejected, or the audience binding is void.
        validation.set_required_spec_claims(&["exp", "iss", "aud"]);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        let data = decode::<Value>(token, &key, &validation)
            .map_err(|e| GatewayError::Sts(format!("oidc token invalid: {e}")))?;
        self.extract(&data.claims)
    }
}

/// The web-identity door's verification, which is deliberately **not** `verify()`.
///
/// Same signing key, same issuer, same expiry enforcement — three differences, each one
/// a thing the bearer door gets right for itself and wrong for this one:
///
/// 1. it returns the **raw claims**, because the tenant and organization are resolved
///    from the `RoleArn` and the routing table rather than from claims that hyperfluid's
///    Keycloak does not mint;
/// 2. the audience check is the `aud`-or-`azp` rule ([`Self::audience_is_accepted`])
///    rather than `jsonwebtoken`'s strict `aud`, so a service-account token is usable —
///    and it is applied by [`crate::webidentity::WebIdentitySts::addressed_to_this_gateway`]
///    rather than here, because since the bundle route it also needs the tenant out of
///    the `RoleArn`, which this trait never sees;
/// 3. an **expired** token is reported as `ExpiredTokenException` rather than folded
///    into a generic invalid-token error, because an SDK treats the two differently: an
///    expiry means "re-read the projected token file and retry", and any other invalid
///    token means "stop".
///
/// `verify()` is untouched by all of this. Two doors with two threat models sharing one
/// verification function is how one of them silently acquires the other's leniency.
#[async_trait::async_trait]
impl WebIdentityVerifier for StandardVerifier {
    async fn verify_token(&self, token: &str) -> std::result::Result<Value, StsRefusal> {
        let key = self
            .decoding_key(token)
            .await
            .map_err(|e| StsRefusal::InvalidIdentityToken(e.to_string()))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[&self.issuer]);
        // `iss` and `exp` are required outright — a token that omits either is not a
        // token this gateway can reason about. `aud` is checked below instead of here,
        // so `validate_aud` is off and `aud` is not in the required set.
        validation.set_required_spec_claims(&["exp", "iss"]);
        validation.validate_aud = false;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        let data = decode::<Value>(token, &key, &validation).map_err(|e| match e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => StsRefusal::ExpiredToken,
            _ => StsRefusal::InvalidIdentityToken(e.to_string()),
        })?;
        Ok(data.claims)
    }

    /// Does this token name one of the audiences this gateway serves?
    ///
    /// Accepts a match on `aud` (string **or** array — a JWT `aud` is legally either)
    /// or on `azp`/`client_id`. The `azp` fallback is what makes a Keycloak
    /// service-account token usable at all: `grant_type=client_credentials` produces
    /// `aud: "account"` and names the client only in `azp`. Ceph RGW and MinIO both do
    /// exactly this, and the operator renders the same client-id list it already gives
    /// RGW's role, so a token that works against one works against the other.
    ///
    /// **Unchanged by the bundle route.** This is still the whole of the configured
    /// answer; the bundle is consulted only where this returns `false`, and only for the
    /// tenant the `RoleArn` named.
    fn audience_is_accepted(&self, claims: &Value) -> bool {
        let accepted = self.accepted_audiences();
        let matches = |v: &str| accepted.contains(&v);
        let aud_ok = match claims.get("aud") {
            Some(Value::String(s)) => matches(s),
            Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).any(matches),
            _ => false,
        };
        aud_ok
            || ["azp", "client_id"].iter().any(|name| {
                claims
                    .get(*name)
                    .and_then(Value::as_str)
                    .is_some_and(matches)
            })
    }

    fn configured_audiences(&self) -> Vec<String> {
        self.accepted_audiences()
            .into_iter()
            .map(str::to_string)
            .collect()
    }
}

async fn fetch_jwks(client: &reqwest::Client, uri: &str) -> Result<JwkSet> {
    let resp = client
        .get(uri)
        .send()
        .await
        .map_err(|e| GatewayError::Sts(format!("jwks fetch: {e}")))?;
    resp.json::<JwkSet>()
        .await
        .map_err(|e| GatewayError::Sts(format!("jwks decode: {e}")))
}

fn empty_jwks() -> JwkSet {
    serde_json::from_str(r#"{"keys":[]}"#).expect("empty jwks")
}

/// The mint: verify an OIDC token, issue a gateway session.
pub struct Mint {
    verifier: Arc<dyn OidcVerifier>,
    sts: Arc<StsAuthority>,
    ttl: Duration,
    /// The AWS STS door. `None` ⇒ this listener serves the bearer exchange alone and a
    /// request carrying an `Action` gets the same answer as any other unrecognised one,
    /// so turning the surface off really does remove it rather than hiding it behind a
    /// different error.
    web_identity: Option<Arc<WebIdentitySts>>,
}

/// AssumeRoleWithWebIdentity-shaped response.
///
/// Public and shared with [`crate::internal`] on purpose: the console-mediated
/// session endpoint answers with **this** type rather than a second credential shape,
/// so a session minted through either door is indistinguishable on the wire as well
/// as in the key ring. hyperfluid's `MintedSession` deserializes exactly these four
/// field names; they are pinned from both sides by `tests/cross_repo_contract.rs`.
///
/// No `Debug`: three of its four fields are a live credential, and the strongest
/// available guarantee that they never reach a log line is that `{:?}` on this type
/// does not compile. (Its hyperfluid counterpart makes the same choice, for the same
/// stated reason.)
#[derive(Serialize)]
pub struct MintedCredentials {
    #[serde(rename = "AccessKeyId")]
    pub access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    pub secret_access_key: String,
    #[serde(rename = "SessionToken")]
    pub session_token: String,
    #[serde(rename = "Expiration")]
    pub expiration: u64,
}

impl From<crate::auth::sts::SessionCredentials> for MintedCredentials {
    fn from(creds: crate::auth::sts::SessionCredentials) -> Self {
        MintedCredentials {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            expiration: creds.expires_at,
        }
    }
}

/// Ceiling on a mint request body.
///
/// A web identity token is the body's whole bulk, and a Keycloak access token carrying a
/// realm's worth of role claims is routinely 4–8 KiB, so this is generous where the
/// internal endpoint's 16 KiB is not. It is still a bound, and it is the *only* one on
/// this socket: the listener is unauthenticated by design, so what an anonymous caller
/// can make this process allocate is decided here and nowhere else.
const MAX_MINT_BODY_BYTES: usize = 64 * 1024;

impl Mint {
    pub fn new(verifier: Arc<dyn OidcVerifier>, sts: Arc<StsAuthority>, ttl: Duration) -> Self {
        Mint {
            verifier,
            sts,
            ttl,
            web_identity: None,
        }
    }

    /// Attach the [`crate::webidentity`] door. Absent ⇒ bearer exchange only.
    #[must_use]
    pub fn with_web_identity(mut self, sts: Arc<WebIdentitySts>) -> Self {
        self.web_identity = Some(sts);
        self
    }

    /// Verify an OIDC token and mint session credentials. `sid` is caller-supplied
    /// (random at the endpoint; fixed in tests) so this stays deterministic.
    async fn mint(&self, oidc_token: &str, sid: &str) -> Result<MintedCredentials> {
        let id = self.verifier.verify(oidc_token).await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| GatewayError::Sts(format!("clock: {e}")))?
            .as_secs();
        let claims = SessionClaims {
            sub: id.sub,
            principal_type: PrincipalType::User,
            groups: id.groups,
            tenant: id.tenant,
            org: id.org,
            sid: sid.to_string(),
            exp: now + self.ttl.as_secs(),
        };
        Ok(self.sts.mint(sid, claims)?.into())
    }

    async fn route(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        if req.method() != Method::POST {
            // Both doors are POST-only. The AWS query protocol does define a GET form,
            // but no SDK uses it for a call that carries a bearer token in a parameter,
            // and putting a web identity token in a URL puts it in every access log
            // between here and the client. Refused rather than supported.
            return json_error(StatusCode::METHOD_NOT_ALLOWED, "use POST");
        }
        // The bearer door ignores the body and the STS door *is* the body, so it is read
        // once, bounded, before the two are told apart.
        let query = req.uri().query().unwrap_or_default().to_string();
        let bearer_token = bearer(&req);
        let body = match Limited::new(req.into_body(), MAX_MINT_BODY_BYTES)
            .collect()
            .await
        {
            Ok(b) => b.to_bytes(),
            Err(_) => {
                return json_error(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "request body exceeds the mint's limit",
                );
            }
        };

        // The AWS query protocol puts the action in the body of a POST to `/`. A
        // request that carries one is an STS request and gets STS answers — including
        // STS-shaped *errors*, which is the half that matters: an SDK that receives a
        // JSON body where it expects an `ErrorResponse` reports "unknown error" and the
        // operator never learns what was actually wrong.
        let mut params = Params::parse(&String::from_utf8_lossy(&body));
        if params.get("Action").is_none() && !query.is_empty() {
            // Some clients (and every hand-written `curl` example) put the parameters
            // in the query string instead. Accepted, but only as a fallback: a body
            // that names an Action is never overridden by a query string that names
            // another.
            params = Params::parse(&query);
        }
        if let Some(action) = params.get("Action") {
            let Some(sts) = &self.web_identity else {
                tracing::warn!(
                    %action,
                    "an AWS STS request arrived but the web-identity surface is disabled"
                );
                return sts_error(&StsRefusal::InvalidAction(action.to_string()));
            };
            return self.route_sts(sts, &params).await;
        }

        let Some(token) = bearer_token else {
            return json_error(StatusCode::UNAUTHORIZED, "missing bearer OIDC token");
        };
        let sid = uuid::Uuid::new_v4().to_string();
        match self.mint(&token, &sid).await {
            Ok(creds) => match serde_json::to_vec(&creds) {
                Ok(body) => json_ok(body),
                Err(_) => json_error(StatusCode::INTERNAL_SERVER_ERROR, "encode failed"),
            },
            Err(e) => {
                tracing::warn!(%e, "sts mint denied");
                json_error(StatusCode::UNAUTHORIZED, "mint denied")
            }
        }
    }

    /// One `AssumeRoleWithWebIdentity` call, rendered as XML either way.
    async fn route_sts(&self, sts: &WebIdentitySts, params: &Params) -> Response<Full<Bytes>> {
        // The request id is minted here rather than inside the surface so it can be
        // logged alongside a refusal and quoted back by a client. It is not the session
        // id: correlating a support ticket to a log line must not hand out the identifier
        // the credential is MAC-bound to.
        let request_id = uuid::Uuid::new_v4().to_string();
        let sid = uuid::Uuid::new_v4().to_string();
        match sts.assume_role_from_params(params, &sid).await {
            Ok(session) => {
                tracing::info!(
                    %request_id,
                    sub = %session.principal.sub,
                    principal_type = ?session.principal.principal_type,
                    tenant = %session.role.tenant,
                    expires_at = session.expires_at,
                    "AssumeRoleWithWebIdentity minted a gateway session"
                );
                xml_ok(render_assume_role_response(&session, &request_id))
            }
            Err(refusal) => {
                tracing::warn!(
                    %request_id,
                    code = refusal.code(),
                    // The internal detail goes here and not into the response body.
                    detail = ?refusal,
                    "AssumeRoleWithWebIdentity refused"
                );
                xml_error(
                    refusal.status(),
                    render_error_response(&refusal, &request_id),
                )
            }
        }
    }
}

fn xml_ok(body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/xml")
        // A credential must never be cached by anything between here and the client.
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .expect("response")
}

fn xml_error(status: u16, body: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::from_u16(status).unwrap_or(StatusCode::BAD_REQUEST))
        .header("content-type", "text/xml")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .expect("response")
}

fn sts_error(refusal: &StsRefusal) -> Response<Full<Bytes>> {
    let request_id = uuid::Uuid::new_v4().to_string();
    xml_error(
        refusal.status(),
        render_error_response(refusal, &request_id),
    )
}

fn bearer(req: &Request<Incoming>) -> Option<String> {
    req.headers()
        .get(hyper::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::to_string)
}

fn json_ok(body: Vec<u8>) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/json")
        // A credential must not be cached by anything on the way to the client. The
        // internal endpoint has always said so; this one did not, and the body is the
        // same kind of thing.
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body)))
        .expect("response")
}

fn json_error(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({ "error": msg }).to_string();
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .expect("response")
}

/// How long in-flight mint requests get to finish after the shutdown signal. Minting
/// is a token verification plus an HMAC — anything still running past this is stuck.
const MINT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve the mint on its own listener (control plane, separate from the S3 data
/// plane) until SIGTERM/Ctrl-C, then drain.
pub async fn serve(mint: Arc<Mint>, listen: SocketAddr) -> Result<()> {
    serve_with_shutdown(mint, listen, crate::shutdown::signal()).await
}

/// As [`serve`], with a caller-supplied shutdown trigger.
///
/// The mint gets the same treatment as the S3 listener, and for the same reason: it
/// used to be an infinite accept loop with no signal handling, so on every rolling
/// update its task was aborted mid-request when the runtime dropped. The visible
/// symptom is sporadic credential-issuing failures on each deploy — indistinguishable
/// from an IdP problem, and retried by clients into a thundering herd.
pub async fn serve_with_shutdown(
    mint: Arc<Mint>,
    listen: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, "sts mint listening");
    let http = ConnBuilder::new(TokioExecutor::new());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    tokio::pin!(shutdown);

    loop {
        // Accept inside the select, or an idle mint never observes the signal.
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = &mut shutdown => {
                tracing::info!("shutdown signal; draining mint connections");
                break;
            }
        };
        let (stream, _) = match accepted {
            Ok(v) => v,
            Err(e) => {
                // Back off rather than busy-spin on a persistent accept error.
                tracing::warn!(%e, "mint accept failed; backing off");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let mint = mint.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let mint = mint.clone();
            async move { Ok::<_, std::convert::Infallible>(mint.route(req).await) }
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
        _ = graceful.shutdown() => tracing::info!("mint connections drained"),
        _ = tokio::time::sleep(MINT_DRAIN_TIMEOUT) => {
            tracing::warn!(timeout = ?MINT_DRAIN_TIMEOUT, "mint drain timed out");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockVerifier(VerifiedIdentity);
    #[async_trait::async_trait]
    impl OidcVerifier for MockVerifier {
        async fn verify(&self, _token: &str) -> Result<VerifiedIdentity> {
            Ok(self.0.clone())
        }
    }

    fn sts() -> Arc<StsAuthority> {
        Arc::new(StsAuthority::new(vec![4u8; 32], vec![8u8; 32]).unwrap())
    }

    #[tokio::test]
    async fn mint_produces_creds_the_gateway_can_verify() {
        let id = VerifiedIdentity {
            sub: "alice".into(),
            groups: vec!["analysts".into()],
            tenant: "acme".into(),
            org: "org-acme".into(),
        };
        let sts = sts();
        let mint = Mint::new(
            Arc::new(MockVerifier(id)),
            sts.clone(),
            Duration::from_secs(900),
        );
        let creds = mint.mint("ignored", "sid-1").await.unwrap();

        // The minted access key derives the same secret, and the session token verifies
        // back to the same identity — exactly what S3Auth + check() will do.
        assert_eq!(
            sts.secret_for_access_key(&creds.access_key_id).as_deref(),
            Some(creds.secret_access_key.as_str())
        );
        let session = sts
            .verify_session(&creds.access_key_id, &creds.session_token)
            .unwrap();
        assert_eq!(session.sub, "alice");
        assert_eq!(session.tenant, "acme");
        assert_eq!(session.groups, vec!["analysts".to_string()]);
    }

    fn claim_names() -> ClaimNames {
        ClaimNames {
            sub: "sub".into(),
            groups: "groups".into(),
            tenant: "tenant".into(),
            org: "org".into(),
        }
    }

    fn verifier_with_web_identity_audiences(audiences: Vec<String>) -> StandardVerifier {
        StandardVerifier {
            key_source: KeySource::Pem(DecodingKey::from_secret(b"x")),
            issuer: "i".into(),
            audience: "a".into(),
            claims: claim_names(),
            web_identity_audiences: audiences,
        }
    }

    #[test]
    fn extract_pulls_named_claims() {
        let v = verifier_with_web_identity_audiences(Vec::new());
        let claims = serde_json::json!({
            "sub": "alice", "tenant": "acme", "org": "org-acme",
            "groups": ["analysts", "radiology"]
        });
        let id = v.extract(&claims).unwrap();
        assert_eq!(id.sub, "alice");
        assert_eq!(id.tenant, "acme");
        assert_eq!(id.org, "org-acme");
        assert_eq!(
            id.groups,
            vec!["analysts".to_string(), "radiology".to_string()]
        );

        // Missing required tenant claim ⇒ error.
        let bad = serde_json::json!({ "sub": "alice", "org": "o" });
        assert!(v.extract(&bad).is_err());
    }

    /// **The check that decides whether a service account can use this gateway.**
    ///
    /// A Keycloak `grant_type=client_credentials` token carries `aud: "account"` and
    /// names its client only in `azp`. A strict `aud` check — which is exactly what the
    /// bearer door does, correctly, for itself — refuses every one of them, i.e. the
    /// primary consumer of the whole product.
    #[test]
    fn the_web_identity_door_accepts_a_service_account_token_on_azp() {
        let v = verifier_with_web_identity_audiences(vec![
            "acme-storage".into(),
            "control-plane-sa".into(),
        ]);
        // The real shape Keycloak issues for a service account.
        assert!(v.audience_is_accepted(&serde_json::json!({
            "aud": "account", "azp": "acme-storage"
        })));
        // `client_id` is the same fact under the other spelling some IdPs use.
        assert!(v.audience_is_accepted(&serde_json::json!({
            "aud": "account", "client_id": "control-plane-sa"
        })));
        // A plain `aud` still works, string or array — a JWT `aud` is legally either.
        assert!(v.audience_is_accepted(&serde_json::json!({ "aud": "acme-storage" })));
        assert!(v.audience_is_accepted(&serde_json::json!({ "aud": ["x", "acme-storage"] })));
    }

    /// …and there is no configuration in which the audience binding is skipped.
    #[test]
    fn a_token_naming_no_accepted_audience_is_refused() {
        let v = verifier_with_web_identity_audiences(vec!["acme-storage".into()]);
        for claims in [
            serde_json::json!({}),
            serde_json::json!({ "aud": "account" }),
            serde_json::json!({ "aud": "account", "azp": "some-other-client" }),
            serde_json::json!({ "aud": ["account", "realm-management"] }),
            // Not a substring match, not a prefix match.
            serde_json::json!({ "azp": "acme-storage-2" }),
            serde_json::json!({ "azp": "acme" }),
            // Not case-insensitive: a client id is an exact identifier.
            serde_json::json!({ "azp": "ACME-STORAGE" }),
        ] {
            assert!(
                !v.audience_is_accepted(&claims),
                "{claims} must not pass the audience check"
            );
        }
    }

    /// An empty configured list is not "accept anything" — it falls back to the single
    /// `audience` the bearer door uses, so the two doors cannot end up with one of them
    /// unchecked because a field was left out of a config.
    #[test]
    fn an_empty_audience_list_falls_back_to_the_configured_audience() {
        let v = verifier_with_web_identity_audiences(Vec::new());
        assert_eq!(v.accepted_audiences(), vec!["a"]);
        assert!(v.audience_is_accepted(&serde_json::json!({ "aud": "a" })));
        assert!(!v.audience_is_accepted(&serde_json::json!({ "aud": "anything-else" })));
        assert!(!v.audience_is_accepted(&serde_json::json!({})));
    }
}
