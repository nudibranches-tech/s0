//! Own STS. Mints short-lived S3 credentials from an OIDC token and verifies
//! them on the hot path **without any per-session secret at rest and without a
//! hot-path store lookup**:
//!
//! - The session **secret** is derived deterministically:
//!   `secret = HMAC(master_keys[kid], kid ‖ 0x00 ‖ sid)`. `get_secret_key` re-derives it
//!   from the access-key id alone, which carries both `kid` and `sid`.
//! - The session **claims** (sub, groups, tenant, org, expiry) ride in a signed
//!   session token (`X-Amz-Security-Token`), MAC-bound to the same `sid`. No store.
//! - **Revocation stays live** because policy lives in OPA/grants, not in the token:
//!   a revoked grant denies at the PDP even while the token is unexpired.
//!
//! This mints the platform's identity shape — `principal.sub` is the OIDC `sub` — so
//! gateway decisions and audit line up with the rest of the platform.
//!
//! ## Master-key rotation (plan task 11)
//!
//! Because the secret is *derived* rather than stored, replacing the master key
//! silently invalidates every live session: the client keeps presenting a secret the
//! gateway can no longer reproduce, and every request 403s until the session expires.
//! There is no signal that says "your credential was rotated out from under you", so a
//! rotation would look to an operator exactly like a fleet-wide auth outage.
//!
//! The key **ring** removes the coupling. The access-key id names the key that derived
//! it (`HFST<kid>.<sid>`), so a retired key stays usable for verification while a new
//! one mints:
//!
//! 1. add the new key to `sts.master_keys` under a fresh `kid`; deploy;
//! 2. point `sts.current_kid` at it; deploy. New sessions mint under the new key, live
//!    ones keep verifying under the old;
//! 3. wait one full `session_ttl_secs` (every session minted under the old key has now
//!    expired);
//! 4. delete the old entry. Any straggler fails closed — an unknown `kid` derives
//!    nothing, so the credential is simply not honoured.
//!
//! The **signing** key is deliberately NOT a ring here. It authenticates the session
//! token rather than the credential, so rotating it does invalidate live sessions; the
//! JWT `kid` header is the mechanism for that and it is a separate change. Rotate the
//! master key with the procedure above; rotate the signing key during a maintenance
//! window, or accept re-minting.

use std::collections::BTreeMap;

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

/// Separates the key id from the session id: `HFST<kid>.<sid>`.
///
/// A `kid` may not contain it (enforced in [`StsAuthority::with_key_ring`]) and a
/// `sid` may, because the split is on the **first** occurrence — so the decomposition
/// is unambiguous no matter what the mint chooses for a session id.
pub const KID_SEP: char = '.';

/// The `kid` a single-key configuration is filed under. An operator who never asked
/// for a ring still gets one, so turning on rotation later is a config edit rather
/// than a credential-format migration.
pub const DEFAULT_KID: &str = "k0";

/// The two halves of an STS access-key id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StsKeyId<'a> {
    /// Which master key derived this session's secret.
    pub kid: &'a str,
    /// The session id, which the session token is MAC-bound to.
    pub sid: &'a str,
}

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

/// Holds the long-term secrets: the ring of `master` keys that derive session secrets
/// (see the module docs for the rotation procedure) and the `signing` key that
/// authenticates session tokens. Keep them distinct so a token-forgery bug cannot
/// yield a usable signing secret.
#[derive(Clone)]
pub struct StsAuthority {
    /// `kid -> master key`. Every entry can *verify*; only `current_kid` mints.
    master_keys: BTreeMap<String, Vec<u8>>,
    current_kid: String,
    signing_key: Vec<u8>,
}

impl StsAuthority {
    /// Single-key convenience: a one-entry ring under [`DEFAULT_KID`].
    pub fn new(master_key: Vec<u8>, signing_key: Vec<u8>) -> Result<Self> {
        Self::with_key_ring(
            BTreeMap::from([(DEFAULT_KID.to_string(), master_key)]),
            DEFAULT_KID,
            signing_key,
        )
    }

    /// Build from a full key ring. `current_kid` must name an entry — the alternative
    /// (falling back to some other key) would mint credentials under a key the
    /// operator did not choose.
    pub fn with_key_ring(
        master_keys: BTreeMap<String, Vec<u8>>,
        current_kid: &str,
        signing_key: Vec<u8>,
    ) -> Result<Self> {
        if master_keys.is_empty() {
            return Err(GatewayError::Sts("sts master key ring is empty".into()));
        }
        if signing_key.len() < 32 {
            return Err(GatewayError::Sts("sts keys must be >= 32 bytes".into()));
        }
        for (kid, key) in &master_keys {
            validate_kid(kid)?;
            if key.len() < 32 {
                return Err(GatewayError::Sts(format!(
                    "sts keys must be >= 32 bytes (master key {kid} is {})",
                    key.len()
                )));
            }
            // The secret-derivation and token-signing keys must be distinct, or the
            // two-key separation the design relies on collapses to one. Checked per
            // ring entry: one reused key is enough to collapse it.
            if key == &signing_key {
                return Err(GatewayError::Sts(format!(
                    "sts master key {kid} and signing_key must differ"
                )));
            }
        }
        if !master_keys.contains_key(current_kid) {
            return Err(GatewayError::Sts(format!(
                "sts current_kid {current_kid:?} is not in the master key ring"
            )));
        }
        Ok(StsAuthority {
            master_keys,
            current_kid: current_kid.to_string(),
            signing_key,
        })
    }

    /// The `kid` new sessions are minted under.
    pub fn current_kid(&self) -> &str {
        &self.current_kid
    }

    /// The key ids this authority can still verify, oldest-named first. Exposed so an
    /// operator (and a test) can see what a rotation has actually retired.
    pub fn key_ids(&self) -> Vec<&str> {
        self.master_keys.keys().map(String::as_str).collect()
    }

    /// `secret = hex(HMAC-SHA256(master_keys[kid], kid ‖ 0x00 ‖ sid))`. Deterministic,
    /// store-free. `None` when `kid` is not (or is no longer) in the ring.
    ///
    /// The `kid` is inside the MAC message as well as selecting the key: an operator
    /// who files the same key bytes under two ids then gets two distinct secrets
    /// rather than one credential that verifies under either, which keeps "retire the
    /// old kid" a real revocation. The `0x00` separator keeps `kid ‖ sid` unambiguous.
    pub fn derive_secret(&self, kid: &str, sid: &str) -> Option<String> {
        let key = self.master_keys.get(kid)?;
        let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
        mac.update(kid.as_bytes());
        mac.update(&[0u8]);
        mac.update(sid.as_bytes());
        Some(hex::encode(mac.finalize().into_bytes()))
    }

    /// The access-key id for a session minted under the current key.
    pub fn access_key_id(&self, sid: &str) -> String {
        Self::access_key_id_for(&self.current_kid, sid)
    }

    /// The access-key id a given `(kid, sid)` produces.
    pub fn access_key_id_for(kid: &str, sid: &str) -> String {
        format!("{STS_PREFIX}{kid}{KID_SEP}{sid}")
    }

    /// Does this access-key id claim to be one of ours?
    ///
    /// Deliberately separate from [`parse_access_key`](Self::parse_access_key): a key
    /// that carries the prefix but does not decompose is a *malformed STS credential*,
    /// not a static one, and callers must not let it fall through to the static store
    /// (where a colliding entry would shadow the STS namespace). `GatewayConfig`
    /// rejects such entries at load; this makes the property hold without that.
    pub fn is_sts_access_key(access_key_id: &str) -> bool {
        access_key_id.starts_with(STS_PREFIX)
    }

    /// Split an access-key id into `(kid, sid)`, if it is one of ours and well formed.
    /// A bare prefix, a missing separator, or an empty half is rejected.
    pub fn parse_access_key(access_key_id: &str) -> Option<StsKeyId<'_>> {
        let rest = access_key_id.strip_prefix(STS_PREFIX)?;
        // Split on the FIRST separator: the kid cannot contain one, the sid may.
        let (kid, sid) = rest.split_once(KID_SEP)?;
        (!kid.is_empty() && !sid.is_empty()).then_some(StsKeyId { kid, sid })
    }

    /// Recover the `sid` from an access-key id, if it is one of ours.
    pub fn sid_from_access_key(access_key_id: &str) -> Option<&str> {
        Self::parse_access_key(access_key_id).map(|k| k.sid)
    }

    /// The [`crate::auth`] `S3Auth` path: derive the secret for an STS access key.
    /// Returns `None` for non-STS keys (a static credential store handles those), for
    /// malformed ones, and for a `kid` that has been retired from the ring.
    pub fn secret_for_access_key(&self, access_key_id: &str) -> Option<String> {
        let k = Self::parse_access_key(access_key_id)?;
        self.derive_secret(k.kid, k.sid)
    }

    /// Mint a session under the current key. `sid` is supplied by the caller (random
    /// at the endpoint; fixed in tests) so this stays deterministic.
    pub fn mint(&self, sid: &str, claims: SessionClaims) -> Result<SessionCredentials> {
        if sid.is_empty() {
            return Err(GatewayError::Sts("sid must be non-empty".into()));
        }
        if claims.sid != sid {
            return Err(GatewayError::Sts("sid mismatch in claims".into()));
        }
        let secret = self
            .derive_secret(&self.current_kid, sid)
            .ok_or_else(|| GatewayError::Sts("current_kid is not in the key ring".into()))?;
        // The minting `kid` goes in the JWS header — the registered place for it, and
        // covered by the signature, so it cannot be edited in flight. `verify_session`
        // requires it to match the `kid` in the presented access-key id: without that,
        // the two halves of the credential name keys independently, and anyone holding
        // a leaked *retired* master key could re-label a current session's access-key
        // id onto it, derive the secret themselves, and ride an otherwise valid token.
        let mut header = Header::new(Algorithm::HS256);
        header.kid = Some(self.current_kid.clone());
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &EncodingKey::from_secret(&self.signing_key),
        )
        .map_err(|e| GatewayError::Sts(format!("encode session token: {e}")))?;
        Ok(SessionCredentials {
            access_key_id: self.access_key_id(sid),
            secret_access_key: secret,
            session_token: token,
            expires_at: claims.exp,
        })
    }

    /// Verify a session token: signature, expiry, and `sid`-binding to the presented
    /// access-key id. Any failure is an auth failure (caller denies).
    ///
    /// The `kid` must still be in the ring. A session minted under a key that has
    /// since been retired is refused here as well as at secret derivation, so a
    /// retirement is a revocation on both halves of the credential.
    pub fn verify_session(
        &self,
        access_key_id: &str,
        session_token: &str,
    ) -> Result<SessionClaims> {
        let key = Self::parse_access_key(access_key_id)
            .ok_or_else(|| GatewayError::Sts("not an sts access key".into()))?;
        if !self.master_keys.contains_key(key.kid) {
            return Err(GatewayError::Sts(format!(
                "sts key id {:?} is not in the key ring (retired?)",
                key.kid
            )));
        }
        let sid = key.sid;
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
            return Err(GatewayError::Sts(
                "session token not bound to access key".into(),
            ));
        }
        // Both halves of the credential must name the same master key. See `mint`.
        if data.header.kid.as_deref() != Some(key.kid) {
            return Err(GatewayError::Sts(
                "session token was minted under a different sts key id".into(),
            ));
        }
        Ok(data.claims)
    }
}

/// A `kid` becomes part of an access-key id, so it must keep that id decomposable and
/// printable. Rejecting the separator is the load-bearing rule: a `kid` containing one
/// would make `HFST<kid>.<sid>` split at the wrong place and derive a secret for a
/// different key — the classic delimiter-injection shape, on a credential.
fn validate_kid(kid: &str) -> Result<()> {
    if kid.is_empty() {
        return Err(GatewayError::Sts("sts key id must be non-empty".into()));
    }
    if !kid
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(GatewayError::Sts(format!(
            "sts key id {kid:?} must be ASCII alphanumeric, '-' or '_' \
             (it becomes part of the access-key id {STS_PREFIX}<kid>{KID_SEP}<sid>)"
        )));
    }
    Ok(())
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

    /// A two-key ring: `old` still verifies, `new` mints.
    fn rotating_authority() -> StsAuthority {
        StsAuthority::with_key_ring(
            BTreeMap::from([
                ("old".to_string(), vec![7u8; 32]),
                ("new".to_string(), vec![8u8; 32]),
            ]),
            "new",
            vec![9u8; 32],
        )
        .unwrap()
    }

    #[test]
    fn secret_derivation_is_deterministic_and_unique() {
        let a = authority();
        assert_eq!(
            a.derive_secret(DEFAULT_KID, "sid-1"),
            a.derive_secret(DEFAULT_KID, "sid-1")
        );
        assert_ne!(
            a.derive_secret(DEFAULT_KID, "sid-1"),
            a.derive_secret(DEFAULT_KID, "sid-2")
        );
        // A kid outside the ring derives nothing at all — the retirement case.
        assert_eq!(a.derive_secret("no-such-kid", "sid-1"), None);
    }

    #[test]
    fn access_key_id_round_trips() {
        let a = authority();
        let ak = a.access_key_id("sid-xyz");
        assert_eq!(ak, format!("{STS_PREFIX}{DEFAULT_KID}{KID_SEP}sid-xyz"));
        assert_eq!(
            StsAuthority::parse_access_key(&ak),
            Some(StsKeyId {
                kid: DEFAULT_KID,
                sid: "sid-xyz"
            })
        );
        assert_eq!(StsAuthority::sid_from_access_key(&ak), Some("sid-xyz"));
        assert_eq!(StsAuthority::sid_from_access_key("AKIAstatic"), None);
    }

    #[test]
    fn a_malformed_sts_access_key_is_not_silently_a_static_one() {
        // Every one of these carries the STS prefix, so `is_sts_access_key` claims
        // them — and none of them decomposes, so they derive no secret. The pair of
        // answers is what stops `Identity` from falling through to the static store,
        // where a colliding entry would shadow the whole STS namespace.
        for ak in [
            STS_PREFIX,                                     // bare prefix
            &format!("{STS_PREFIX}sid-1"),                  // pre-key-ring format
            &format!("{STS_PREFIX}{KID_SEP}sid-1"),         // empty kid
            &format!("{STS_PREFIX}{DEFAULT_KID}{KID_SEP}"), // empty sid
        ] {
            assert!(StsAuthority::is_sts_access_key(ak), "{ak}");
            assert_eq!(StsAuthority::parse_access_key(ak), None, "{ak}");
            assert_eq!(authority().secret_for_access_key(ak), None, "{ak}");
        }
        assert!(!StsAuthority::is_sts_access_key("AKIAstatic"));
    }

    #[test]
    fn a_sid_may_contain_the_separator_and_still_decomposes() {
        // The split is on the FIRST separator, so the mint is free to choose any sid
        // shape without the kid becoming ambiguous.
        let ak = StsAuthority::access_key_id_for("k1", "sid.with.dots");
        assert_eq!(
            StsAuthority::parse_access_key(&ak),
            Some(StsKeyId {
                kid: "k1",
                sid: "sid.with.dots"
            })
        );
    }

    // ── rotation (plan task 11) ─────────────────────────────────────────────────

    #[test]
    fn a_session_minted_under_the_previous_key_survives_the_rotation() {
        // The whole reason the ring exists: step 2 of the rotation procedure must not
        // 403 every live session.
        let before = StsAuthority::with_key_ring(
            BTreeMap::from([("old".to_string(), vec![7u8; 32])]),
            "old",
            vec![9u8; 32],
        )
        .unwrap();
        let live = before.mint("sid-1", claims("sid-1", far_future())).unwrap();

        let after = rotating_authority();
        assert_eq!(after.current_kid(), "new");
        // The live credential still verifies, byte for byte.
        assert_eq!(
            after.secret_for_access_key(&live.access_key_id).as_deref(),
            Some(live.secret_access_key.as_str())
        );
        assert!(
            after
                .verify_session(&live.access_key_id, &live.session_token)
                .is_ok()
        );
        // And a session minted now is filed under the new key.
        let fresh = after.mint("sid-2", claims("sid-2", far_future())).unwrap();
        assert_eq!(
            StsAuthority::parse_access_key(&fresh.access_key_id)
                .unwrap()
                .kid,
            "new"
        );
    }

    #[test]
    fn retiring_a_key_revokes_both_halves_of_its_credentials() {
        // Step 4: after one session TTL the old entry is deleted, and any straggler
        // must fail closed on the secret AND on the token.
        let before = rotating_authority();
        let stale = before.mint("sid-1", claims("sid-1", far_future())).unwrap();
        let stale_old_key = StsAuthority::access_key_id_for("old", "sid-1");

        let retired = StsAuthority::with_key_ring(
            BTreeMap::from([("new".to_string(), vec![8u8; 32])]),
            "new",
            vec![9u8; 32],
        )
        .unwrap();
        assert_eq!(retired.key_ids(), vec!["new"]);
        assert_eq!(retired.secret_for_access_key(&stale_old_key), None);
        assert!(
            retired
                .verify_session(&stale_old_key, &stale.session_token)
                .is_err()
        );
        // Positive control: the surviving key is unaffected.
        assert!(
            retired
                .verify_session(&stale.access_key_id, &stale.session_token)
                .is_ok()
        );
    }

    #[test]
    fn the_same_key_bytes_under_two_ids_do_not_share_a_secret() {
        // Otherwise "retire the old kid" would not be a revocation for an operator who
        // rotated by re-filing the same material.
        let a = StsAuthority::with_key_ring(
            BTreeMap::from([
                ("k1".to_string(), vec![7u8; 32]),
                ("k2".to_string(), vec![7u8; 32]),
            ]),
            "k1",
            vec![9u8; 32],
        )
        .unwrap();
        assert_ne!(
            a.derive_secret("k1", "sid-1"),
            a.derive_secret("k2", "sid-1")
        );
    }

    #[test]
    fn a_key_ring_that_cannot_be_trusted_is_refused_at_construction() {
        let signing = vec![9u8; 32];
        let ok = || BTreeMap::from([("k1".to_string(), vec![7u8; 32])]);

        // A kid carrying the separator would split the access-key id at the wrong
        // place and select a different key.
        assert!(
            StsAuthority::with_key_ring(
                BTreeMap::from([("k.1".to_string(), vec![7u8; 32])]),
                "k.1",
                signing.clone()
            )
            .is_err()
        );
        // current_kid must name a real entry: minting under an unchosen key is worse
        // than refusing to start.
        assert!(StsAuthority::with_key_ring(ok(), "k2", signing.clone()).is_err());
        assert!(StsAuthority::with_key_ring(BTreeMap::new(), "k1", signing.clone()).is_err());
        // Short keys and master/signing reuse are rejected per entry, not just for the
        // first one.
        assert!(
            StsAuthority::with_key_ring(
                BTreeMap::from([
                    ("k1".to_string(), vec![7u8; 32]),
                    ("k2".to_string(), vec![7u8; 8])
                ]),
                "k1",
                signing.clone()
            )
            .is_err()
        );
        assert!(
            StsAuthority::with_key_ring(
                BTreeMap::from([
                    ("k1".to_string(), vec![7u8; 32]),
                    ("k2".to_string(), signing.clone())
                ]),
                "k1",
                signing.clone()
            )
            .is_err()
        );
        // Positive control.
        assert!(StsAuthority::with_key_ring(ok(), "k1", signing).is_ok());
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
        let other = a.access_key_id("sid-2");
        assert!(a.verify_session(&other, &creds.session_token).is_err());
    }

    #[test]
    fn a_session_token_cannot_be_walked_onto_a_different_key_id() {
        // The attack the JWS `kid` header closes: an adversary who has recovered a
        // *retired-but-still-ringed* master key takes a live session's token, re-labels
        // its access-key id onto that key, derives the secret themselves (they have
        // the key), and signs. Everything else about the credential is genuine — same
        // sid, same signing key, unexpired.
        let a = rotating_authority();
        let live = a.mint("sid-1", claims("sid-1", far_future())).unwrap();
        assert!(live.access_key_id.contains("new"));

        let relabelled = StsAuthority::access_key_id_for("old", "sid-1");
        // The two halves of the credential are internally consistent as far as the
        // ring is concerned: "old" is present, and the secret derives.
        assert!(a.secret_for_access_key(&relabelled).is_some());
        let err = a
            .verify_session(&relabelled, &live.session_token)
            .expect_err("a relabelled access key must not verify");
        assert!(format!("{err}").contains("different sts key id"), "{err}");

        // Positive control: the credential as minted still verifies.
        assert!(
            a.verify_session(&live.access_key_id, &live.session_token)
                .is_ok()
        );
    }
}
