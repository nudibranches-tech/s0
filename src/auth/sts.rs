//! Own STS (§4.2). Mints short-lived S3 credentials from an OIDC token and verifies
//! them on the hot path **without any per-session secret at rest and without a
//! hot-path store lookup**:
//!
//! - The session **secret** is derived deterministically: `secret = HMAC(master, sid)`.
//!   `get_secret_key` re-derives it from the access-key id alone.
//! - The session **claims** (sub, groups, tenant, org, expiry) ride in a signed
//!   session token (`X-Amz-Security-Token`), MAC-bound to the same `sid`. No store.
//! - **Revocation stays live** because policy lives in OPA/grants, not in the token
//!   (§6.1): a revoked grant denies at the PDP even while the token is unexpired.
//!
//! This mints the platform's identity shape — `principal.sub` is the OIDC `sub`
//! (§3.1) — so gateway decisions and audit line up with the rest of the platform.

use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::error::{GatewayError, Result};
use crate::model::PrincipalType;

type HmacSha256 = Hmac<Sha256>;

/// Access-key ids the gateway mints for STS sessions carry this prefix so
/// `get_secret_key` can distinguish them from long-lived static keys.
pub const STS_PREFIX: &str = "HFST";

/// Signed session claims. `sid` binds the token to the access-key id / secret; `exp`
/// is standard JWT expiry (seconds since epoch).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionClaims {
    pub sub: String,
    #[serde(rename = "typ")]
    pub principal_type: PrincipalType,
    #[serde(default)]
    pub groups: Vec<String>,
    pub tenant: String,
    pub org: String,
    pub sid: String,
    pub exp: u64,
}

/// What a mint returns to the client (AssumeRoleWithWebIdentity-shaped).
#[derive(Debug, Clone)]
pub struct SessionCredentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expires_at: u64,
}

/// Holds the two long-term secrets: the `master` key that derives session secrets
/// and the `signing` key that authenticates session tokens. Keep them distinct so a
/// token-forgery bug cannot yield a usable signing secret.
#[derive(Clone)]
pub struct StsAuthority {
    master_key: Vec<u8>,
    signing_key: Vec<u8>,
}

impl StsAuthority {
    pub fn new(master_key: Vec<u8>, signing_key: Vec<u8>) -> Result<Self> {
        if master_key.len() < 32 || signing_key.len() < 32 {
            return Err(GatewayError::Sts("sts keys must be >= 32 bytes".into()));
        }
        Ok(StsAuthority {
            master_key,
            signing_key,
        })
    }

    /// `secret = hex(HMAC-SHA256(master, sid))`. Deterministic, store-free.
    pub fn derive_secret(&self, sid: &str) -> String {
        let mut mac = HmacSha256::new_from_slice(&self.master_key)
            .expect("hmac accepts any key length");
        mac.update(sid.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn access_key_id(sid: &str) -> String {
        format!("{STS_PREFIX}{sid}")
    }

    /// Recover the `sid` from an access-key id, if it is one of ours.
    pub fn sid_from_access_key(access_key_id: &str) -> Option<&str> {
        access_key_id.strip_prefix(STS_PREFIX)
    }

    /// The [`crate::auth`] `S3Auth` path: derive the secret for an STS access key.
    /// Returns `None` for non-STS keys (a static credential store handles those).
    pub fn secret_for_access_key(&self, access_key_id: &str) -> Option<String> {
        Self::sid_from_access_key(access_key_id).map(|sid| self.derive_secret(sid))
    }

    /// Mint a session. `sid` is supplied by the caller (random at the endpoint;
    /// fixed in tests) so this stays deterministic.
    pub fn mint(&self, sid: &str, claims: SessionClaims) -> Result<SessionCredentials> {
        if claims.sid != sid {
            return Err(GatewayError::Sts("sid mismatch in claims".into()));
        }
        let token = jsonwebtoken::encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(&self.signing_key),
        )
        .map_err(|e| GatewayError::Sts(format!("encode session token: {e}")))?;
        Ok(SessionCredentials {
            access_key_id: Self::access_key_id(sid),
            secret_access_key: self.derive_secret(sid),
            session_token: token,
            expires_at: claims.exp,
        })
    }

    /// Verify a session token: signature, expiry, and `sid`-binding to the presented
    /// access-key id. Any failure is an auth failure (caller denies).
    pub fn verify_session(
        &self,
        access_key_id: &str,
        session_token: &str,
    ) -> Result<SessionClaims> {
        let sid = Self::sid_from_access_key(access_key_id)
            .ok_or_else(|| GatewayError::Sts("not an sts access key".into()))?;
        let mut validation = Validation::new(Algorithm::HS256);
        validation.set_required_spec_claims(&["exp"]);
        validation.validate_aud = false;
        let data = jsonwebtoken::decode::<SessionClaims>(
            session_token,
            &DecodingKey::from_secret(&self.signing_key),
            &validation,
        )
        .map_err(|e| GatewayError::Sts(format!("session token invalid: {e}")))?;
        if data.claims.sid != sid {
            return Err(GatewayError::Sts("session token not bound to access key".into()));
        }
        Ok(data.claims)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> StsAuthority {
        StsAuthority::new(vec![7u8; 32], vec![9u8; 32]).unwrap()
    }

    fn claims(sid: &str, exp: u64) -> SessionClaims {
        SessionClaims {
            sub: "alice".into(),
            principal_type: PrincipalType::User,
            groups: vec!["analysts".into()],
            tenant: "acme".into(),
            org: "org-acme".into(),
            sid: sid.into(),
            exp,
        }
    }

    fn far_future() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600
    }

    #[test]
    fn secret_derivation_is_deterministic_and_unique() {
        let a = authority();
        assert_eq!(a.derive_secret("sid-1"), a.derive_secret("sid-1"));
        assert_ne!(a.derive_secret("sid-1"), a.derive_secret("sid-2"));
    }

    #[test]
    fn access_key_id_round_trips() {
        let ak = StsAuthority::access_key_id("sid-xyz");
        assert!(ak.starts_with(STS_PREFIX));
        assert_eq!(StsAuthority::sid_from_access_key(&ak), Some("sid-xyz"));
        assert_eq!(StsAuthority::sid_from_access_key("AKIAstatic"), None);
    }

    #[test]
    fn secret_for_access_key_matches_mint() {
        let a = authority();
        let creds = a.mint("sid-1", claims("sid-1", far_future())).unwrap();
        assert_eq!(
            a.secret_for_access_key(&creds.access_key_id).as_deref(),
            Some(creds.secret_access_key.as_str())
        );
    }

    #[test]
    fn mint_then_verify_round_trips() {
        let a = authority();
        let creds = a.mint("sid-1", claims("sid-1", far_future())).unwrap();
        let recovered = a
            .verify_session(&creds.access_key_id, &creds.session_token)
            .unwrap();
        assert_eq!(recovered.sub, "alice");
        assert_eq!(recovered.tenant, "acme");
    }

    #[test]
    fn wrong_signing_key_is_rejected() {
        let a = authority();
        let creds = a.mint("sid-1", claims("sid-1", far_future())).unwrap();
        let attacker = StsAuthority::new(vec![7u8; 32], vec![0u8; 32]).unwrap();
        assert!(
            attacker
                .verify_session(&creds.access_key_id, &creds.session_token)
                .is_err()
        );
    }

    #[test]
    fn expired_token_is_rejected() {
        let a = authority();
        let creds = a.mint("sid-1", claims("sid-1", 1_000_000_000)).unwrap();
        assert!(
            a.verify_session(&creds.access_key_id, &creds.session_token)
                .is_err()
        );
    }

    #[test]
    fn token_not_bound_to_other_access_key() {
        let a = authority();
        let creds = a.mint("sid-1", claims("sid-1", far_future())).unwrap();
        let other = StsAuthority::access_key_id("sid-2");
        assert!(a.verify_session(&other, &creds.session_token).is_err());
    }
}
