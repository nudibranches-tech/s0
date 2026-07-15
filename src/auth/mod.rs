//! Identity / credential authority (§4.2). The gateway owns identity: it verifies
//! inbound SigV4 signatures itself and never depends on a backend's STS (§6.7).
//!
//! Two credential kinds share the `S3Auth` path:
//! - **STS sessions** — derived secrets, no store, claims in a signed token ([`sts`]).
//! - **Long-lived static keys** — issued to external apps / service accounts, each
//!   its own principal ([`CredentialStore`]).

pub mod sts;

use std::collections::HashMap;
use std::sync::Arc;

use s3s::auth::{S3Auth, SecretKey};
use s3s::{S3Result, s3_error};

use crate::error::{GatewayError, Result};
use crate::identity::ResolvedPrincipal;
use crate::model::PrincipalType;
use sts::StsAuthority;

/// SigV4 verification recomputes an HMAC, so the plaintext secret must be
/// retrievable per principal — a hash cannot be stored (§4.2).
pub trait CredentialStore: Send + Sync {
    fn secret(&self, access_key_id: &str) -> Option<String>;
    /// The full end-user identity bound to a static access-key id (its own identity,
    /// never a shared bay key — §6.5).
    fn resolve(&self, access_key_id: &str) -> Option<ResolvedPrincipal>;
}

#[derive(Debug, Clone)]
pub struct StaticCredential {
    pub secret_access_key: String,
    pub principal_sub: String,
    pub tenant: String,
    pub organization_id: String,
    pub groups: Vec<String>,
}

#[derive(Debug, Default)]
pub struct StaticCredentialStore {
    by_access_key: HashMap<String, StaticCredential>,
}

impl StaticCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, access_key_id: impl Into<String>, cred: StaticCredential) {
        self.by_access_key.insert(access_key_id.into(), cred);
    }
}

impl CredentialStore for StaticCredentialStore {
    fn secret(&self, access_key_id: &str) -> Option<String> {
        self.by_access_key
            .get(access_key_id)
            .map(|c| c.secret_access_key.clone())
    }

    fn resolve(&self, access_key_id: &str) -> Option<ResolvedPrincipal> {
        self.by_access_key.get(access_key_id).map(|c| ResolvedPrincipal {
            sub: c.principal_sub.clone(),
            principal_type: PrincipalType::ServiceAccount,
            groups: c.groups.clone(),
            tenant: c.tenant.clone(),
            organization_id: c.organization_id.clone(),
        })
    }
}

/// Ties the STS authority and the static store together. Answers both the
/// `S3Auth::get_secret_key` question and the "who is this principal" question the
/// access layer asks in `check`.
pub struct Identity {
    sts: Arc<StsAuthority>,
    creds: Arc<dyn CredentialStore>,
}

/// Header carrying the STS session token (standard SigV4 session credential).
pub const SECURITY_TOKEN_HEADER: &str = "x-amz-security-token";

impl Identity {
    pub fn new(sts: Arc<StsAuthority>, creds: Arc<dyn CredentialStore>) -> Self {
        Identity { sts, creds }
    }

    fn secret_key(&self, access_key_id: &str) -> Option<String> {
        self.sts
            .secret_for_access_key(access_key_id)
            .or_else(|| self.creds.secret(access_key_id))
    }

    /// Resolve the end-user identity from the presented credential + optional session
    /// token. STS keys must present a valid, unexpired, sid-bound token; static keys
    /// resolve from the store.
    pub fn resolve(
        &self,
        access_key_id: &str,
        security_token: Option<&str>,
    ) -> Result<ResolvedPrincipal> {
        if StsAuthority::sid_from_access_key(access_key_id).is_some() {
            let token = security_token.ok_or_else(|| {
                GatewayError::Sts("sts credential without session token".into())
            })?;
            let claims = self.sts.verify_session(access_key_id, token)?;
            return Ok(ResolvedPrincipal {
                sub: claims.sub,
                principal_type: claims.principal_type,
                groups: claims.groups,
                tenant: claims.tenant,
                organization_id: claims.org,
            });
        }
        self.creds
            .resolve(access_key_id)
            .ok_or_else(|| GatewayError::Credentials(format!("unknown access key {access_key_id}")))
    }
}

/// The `s3s::S3Auth` impl. Pure `access_key -> SecretKey`; principal resolution
/// happens later in `S3Access::check` (which also sees the session-token header).
pub struct GatewayAuth {
    identity: Arc<Identity>,
}

impl GatewayAuth {
    pub fn new(identity: Arc<Identity>) -> Self {
        GatewayAuth { identity }
    }
}

#[async_trait::async_trait]
impl S3Auth for GatewayAuth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        match self.identity.secret_key(access_key) {
            Some(secret) => Ok(SecretKey::from(secret)),
            None => Err(s3_error!(InvalidAccessKeyId, "unknown access key")),
        }
    }
}
