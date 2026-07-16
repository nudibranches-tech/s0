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
        self.by_access_key
            .get(access_key_id)
            .map(|c| ResolvedPrincipal {
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

    /// The STS authority, shared with the mint (the badge desk) so minted sessions and
    /// inbound verification use the same keys.
    pub fn sts(&self) -> Arc<StsAuthority> {
        self.sts.clone()
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
            let token = security_token
                .ok_or_else(|| GatewayError::Sts("sts credential without session token".into()))?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use sts::SessionClaims;

    fn far_future() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    fn identity() -> (Identity, StsAuthority) {
        let sts = StsAuthority::new(vec![3u8; 32], vec![5u8; 32]).unwrap();
        let mut store = StaticCredentialStore::new();
        store.insert(
            "AKIASTATIC",
            StaticCredential {
                secret_access_key: "shhh".into(),
                principal_sub: "svc-reporter".into(),
                tenant: "acme".into(),
                organization_id: "org-acme".into(),
                groups: vec!["reporters".into()],
            },
        );
        (Identity::new(Arc::new(sts.clone()), Arc::new(store)), sts)
    }

    #[test]
    fn resolves_static_credential() {
        let (id, _) = identity();
        let p = id.resolve("AKIASTATIC", None).unwrap();
        assert_eq!(p.sub, "svc-reporter");
        assert_eq!(p.tenant, "acme");
        assert_eq!(p.principal_type, PrincipalType::ServiceAccount);
    }

    #[test]
    fn resolves_sts_session_with_token() {
        let (id, sts) = identity();
        let claims = SessionClaims {
            sub: "alice".into(),
            principal_type: PrincipalType::User,
            groups: vec!["analysts".into()],
            tenant: "acme".into(),
            org: "org-acme".into(),
            sid: "sid-1".into(),
            exp: far_future(),
        };
        let creds = sts.mint("sid-1", claims).unwrap();
        let p = id
            .resolve(&creds.access_key_id, Some(&creds.session_token))
            .unwrap();
        assert_eq!(p.sub, "alice");
        assert_eq!(p.groups, vec!["analysts".to_string()]);
    }

    #[test]
    fn sts_key_without_token_is_rejected() {
        let (id, _) = identity();
        let ak = StsAuthority::access_key_id("sid-1");
        assert!(id.resolve(&ak, None).is_err());
    }

    #[test]
    fn unknown_static_key_is_rejected() {
        let (id, _) = identity();
        assert!(id.resolve("AKIANOPE", None).is_err());
    }

    #[test]
    fn secret_key_path_covers_both_kinds() {
        let (id, sts) = identity();
        assert_eq!(id.secret_key("AKIASTATIC").as_deref(), Some("shhh"));
        let ak = StsAuthority::access_key_id("sid-9");
        assert_eq!(
            id.secret_key(&ak).as_deref(),
            Some(sts.derive_secret("sid-9").as_str())
        );
    }
}
