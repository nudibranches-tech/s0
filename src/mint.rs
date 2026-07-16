//! STS mint — the "badge desk". A backend-agnostic control-plane endpoint:
//! it verifies a Keycloak OIDC token and issues short-lived **gateway** credentials
//! that the gateway itself later verifies (derived secrets, [`crate::auth::sts`]).
//!
//! No backend (Ceph/RGW/RustFS/…) is ever involved — this supersedes RGW's STS
//! and works identically regardless of what object store sits behind the gateway.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::Full;
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
    /// JWKS endpoint; keys cached, refreshed on a `kid` miss (rotation).
    Jwks {
        uri: String,
        client: reqwest::Client,
        cache: ArcSwap<JwkSet>,
    },
}

/// Production OIDC verifier: RS256, issuer + audience + expiry validated, claims
/// extracted by configured name.
pub struct StandardVerifier {
    key_source: KeySource,
    issuer: String,
    audience: String,
    claims: ClaimNames,
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
                client: reqwest::Client::new(),
                cache: ArcSwap::from_pointee(empty_jwks()),
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
        })
    }

    async fn decoding_key(&self, token: &str) -> Result<DecodingKey> {
        match &self.key_source {
            KeySource::Pem(k) => Ok(k.clone()),
            KeySource::Jwks { uri, client, cache } => {
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
}

/// AssumeRoleWithWebIdentity-shaped response.
#[derive(Debug, Serialize)]
struct MintedCredentials {
    #[serde(rename = "AccessKeyId")]
    access_key_id: String,
    #[serde(rename = "SecretAccessKey")]
    secret_access_key: String,
    #[serde(rename = "SessionToken")]
    session_token: String,
    #[serde(rename = "Expiration")]
    expiration: u64,
}

impl Mint {
    pub fn new(verifier: Arc<dyn OidcVerifier>, sts: Arc<StsAuthority>, ttl: Duration) -> Self {
        Mint { verifier, sts, ttl }
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
        let creds = self.sts.mint(sid, claims)?;
        Ok(MintedCredentials {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            expiration: creds.expires_at,
        })
    }

    async fn route(&self, req: Request<Incoming>) -> Response<Full<Bytes>> {
        if req.method() != Method::POST {
            return json_error(StatusCode::METHOD_NOT_ALLOWED, "use POST");
        }
        let Some(token) = bearer(&req) else {
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

/// Serve the mint on its own listener (control plane, separate from the S3 data plane).
pub async fn serve(mint: Arc<Mint>, listen: SocketAddr) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, "sts mint listening");
    let http = ConnBuilder::new(TokioExecutor::new());
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%e, "mint accept failed");
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
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }
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

    #[test]
    fn extract_pulls_named_claims() {
        let v = StandardVerifier {
            key_source: KeySource::Pem(DecodingKey::from_secret(b"x")),
            issuer: "i".into(),
            audience: "a".into(),
            claims: claim_names(),
        };
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
}
