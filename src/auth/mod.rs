//! Identity / credential authority. The gateway owns identity: it verifies
//! inbound SigV4 signatures itself and never depends on a backend's STS.
//!
//! Two credential kinds share the `S3Auth` path:
//! - **STS sessions** — derived secrets, no store, claims in a signed token ([`sts`]).
//! - **Long-lived static keys** — issued to external apps / service accounts, each
//!   its own principal ([`CredentialStore`]).

pub mod sts;

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use s3s::auth::{S3Auth, SecretKey};
use s3s::{S3Result, s3_error};

use crate::error::{GatewayError, Result};
use crate::identity::ResolvedPrincipal;
use crate::model::PrincipalType;
use sts::StsAuthority;

/// SigV4 verification recomputes an HMAC, so the plaintext secret must be
/// retrievable per principal — a hash cannot be stored.
pub trait CredentialStore: Send + Sync {
    fn secret(&self, access_key_id: &str) -> Option<String>;
    /// The full end-user identity bound to a static access-key id (its own identity,
    /// never a shared backend key).
    fn resolve(&self, access_key_id: &str) -> Option<ResolvedPrincipal>;
}

#[derive(Debug, Clone)]
pub struct StaticCredential {
    /// A [`Secret`](crate::secret::Secret) rather than a `String` for the same reason
    /// the config field is: this struct derives `Debug` and lives in a map that is
    /// trivially reachable from a log line.
    pub secret_access_key: crate::secret::Secret<String>,
    pub principal_sub: String,
    pub tenant: String,
    pub organization_id: String,
    pub groups: Vec<String>,
}

/// The static credential table: one immutable snapshot, swapped wholesale.
pub type StaticCredentials = HashMap<String, StaticCredential>;

/// The long-lived static keys, behind an [`ArcSwap`] so a rotated credential list can
/// be applied without restarting (plan task 10).
///
/// The swap lives **inside** the store rather than around it because
/// `Identity::new` erases the concrete handle into `Arc<dyn CredentialStore>`
/// immediately (plan defect A-8): an `ArcSwap<Arc<dyn CredentialStore>>` held by the
/// caller would not reach the copy `Identity` is holding. Callers keep an
/// `Arc<StaticCredentialStore>` and call [`replace`](Self::replace); every reader,
/// including the one behind the trait object, sees the new table on its next lookup.
#[derive(Debug, Default)]
pub struct StaticCredentialStore {
    by_access_key: ArcSwap<StaticCredentials>,
}

impl StaticCredentialStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build from config. Rejects nothing: `GatewayConfig::validate` has already
    /// refused STS-namespace collisions and org/tenant disagreements, and duplicating
    /// that here would let the two drift.
    pub fn from_config(cfg: &crate::config::GatewayConfig) -> Self {
        let store = Self::new();
        store.replace(credentials_from_config(cfg));
        store
    }

    /// Install a new credential table. Readers in flight finish against the table they
    /// started with; the next lookup sees this one.
    pub fn replace(&self, creds: StaticCredentials) {
        self.by_access_key.store(Arc::new(creds));
    }

    /// How many credentials are currently installed.
    pub fn len(&self) -> usize {
        self.by_access_key.load().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copy-on-write single insert. For construction and tests; `replace` is the
    /// hot-reload path.
    pub fn insert(&self, access_key_id: impl Into<String>, cred: StaticCredential) {
        let key = access_key_id.into();
        self.by_access_key.rcu(|current| {
            let mut next = StaticCredentials::clone(current);
            next.insert(key.clone(), cred.clone());
            next
        });
    }
}

/// The credential table a config describes.
pub fn credentials_from_config(cfg: &crate::config::GatewayConfig) -> StaticCredentials {
    cfg.static_credentials
        .iter()
        .map(|c| {
            (
                c.access_key_id.clone(),
                StaticCredential {
                    secret_access_key: c.secret_access_key.clone(),
                    principal_sub: c.principal_sub.clone(),
                    tenant: c.tenant.clone(),
                    organization_id: c.organization_id.clone(),
                    groups: c.groups.clone(),
                },
            )
        })
        .collect()
}

impl CredentialStore for StaticCredentialStore {
    fn secret(&self, access_key_id: &str) -> Option<String> {
        self.by_access_key
            .load()
            .get(access_key_id)
            .map(|c| c.secret_access_key.expose().clone())
    }

    fn resolve(&self, access_key_id: &str) -> Option<ResolvedPrincipal> {
        self.by_access_key
            .load()
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

    /// The two credential namespaces are disjoint **by construction**, not by
    /// configuration: anything carrying the STS prefix is answered by the STS
    /// authority alone, even when it is malformed or names a retired key id.
    ///
    /// `GatewayConfig::validate` also rejects a static credential in the STS
    /// namespace, but that guard protects one config-loading path; this one holds for
    /// every store a `CredentialStore` impl could ever be.
    fn secret_key(&self, access_key_id: &str) -> Option<String> {
        if StsAuthority::is_sts_access_key(access_key_id) {
            return self.sts.secret_for_access_key(access_key_id);
        }
        self.creds.secret(access_key_id)
    }

    /// Resolve the end-user identity from the presented credential + optional session
    /// token. STS keys must present a valid, unexpired, sid-bound token; static keys
    /// resolve from the store.
    pub fn resolve(
        &self,
        access_key_id: &str,
        security_token: Option<&str>,
    ) -> Result<ResolvedPrincipal> {
        if StsAuthority::is_sts_access_key(access_key_id) {
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
        let store = StaticCredentialStore::new();
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
        let (id, sts) = identity();
        let ak = sts.access_key_id("sid-1");
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
        let ak = sts.access_key_id("sid-9");
        assert_eq!(
            id.secret_key(&ak).as_deref(),
            sts.derive_secret(sts.current_kid(), "sid-9").as_deref()
        );
    }

    #[test]
    fn a_static_credential_cannot_shadow_the_sts_namespace() {
        // The config loader rejects this at startup; here the store is built by hand,
        // which is exactly the case the loader does not cover. An access key in the
        // STS namespace must be answered by the STS authority even when it is
        // malformed — falling through to the store would let whoever can write the
        // credential list hand out a credential the gateway then treats as a session.
        let sts = StsAuthority::new(vec![3u8; 32], vec![5u8; 32]).unwrap();
        let squatted = format!("{}sid-1", sts::STS_PREFIX); // the pre-key-ring shape
        let store = StaticCredentialStore::new();
        store.insert(
            squatted.clone(),
            StaticCredential {
                secret_access_key: "attacker-chosen".into(),
                principal_sub: "root".into(),
                tenant: "acme".into(),
                organization_id: "org-acme".into(),
                groups: vec![],
            },
        );
        let id = Identity::new(Arc::new(sts), Arc::new(store));
        assert_eq!(id.secret_key(&squatted), None);
        assert!(id.resolve(&squatted, None).is_err());
        assert!(id.resolve(&squatted, Some("any-token")).is_err());
    }
}
