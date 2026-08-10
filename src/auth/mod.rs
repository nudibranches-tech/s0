//! Identity / credential authority. The gateway owns identity: it verifies
//! inbound SigV4 signatures itself and never depends on a backend's STS.
//!
//! Three credential kinds share the `S3Auth` path:
//! - **STS sessions** — derived secrets, no store, claims in a signed token ([`sts`]).
//! - **Derived long-lived per-principal keys** — derived secrets, no store, identity in
//!   the access-key id itself ([`derived`]). The migration path for consumers that hold
//!   a static key and cannot refresh (`FOLLOW-UPS.md` F17).
//! - **Long-lived static keys** — issued to external apps / service accounts, each
//!   its own principal ([`CredentialStore`]).
//!
//! The three namespaces are disjoint **by prefix**, and the dispatch below is what makes
//! that a property of the code rather than of the configuration.

pub mod derived;
pub mod sts;

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use s3s::auth::{S3Auth, SecretKey};
use s3s::{S3Result, s3_error};

use crate::error::{GatewayError, Result};
use crate::identity::ResolvedPrincipal;
use crate::model::PrincipalType;
use derived::{DerivedKeyAuthority, DerivedPrincipal};
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

/// The gateway's own **tenant → organization** table.
///
/// Implemented by [`crate::proxy::BackendRegistry`], which builds it from the operator's
/// rendered config. It exists as a trait so [`DerivedKeys`] can state, in its own
/// signature, that the organization is something it *asks for* rather than something it
/// reads out of a credential.
///
/// This is the settled rule for every credential class in this gateway: a static
/// credential's `organization_id` is cross-checked against the tenant's authoritative org
/// at config load (`GatewayConfig::validate`), an STS session's org comes from the route
/// the internal mint resolved, and every S3 decision is attributed from the
/// `RouteSnapshot` `access::check` looks up. A long-lived key is the credential class
/// most likely to outlive the binding it was minted against, so it is the last place the
/// rule may be weakened.
pub trait TenantDirectory: Send + Sync {
    /// The organization a tenant belongs to, or `None` when the tenant is not routable
    /// by this gateway.
    fn organization_of(&self, tenant: &str) -> Option<String>;
}

/// **How a derived key is revoked.** Read from the policy bundle in force, so a
/// revocation lands at exactly the latency every other revocation in this system lands
/// at, through exactly the same channel.
///
/// ## Why an epoch floor and not a revoked-key list
///
/// A derived key cannot be deleted — there is no row to delete, which is the property
/// that makes it multi-replica-correct — so the bundle has to be able to *invalidate*
/// one. Both shapes were considered:
///
/// * **A revoked-key list** fails in the wrong direction. Its absence means "nothing is
///   revoked", so a bundle that lost the field, or a tenant the projection has not
///   learned about yet, silently un-revokes every key ever revoked. It also grows without
///   bound (a long-lived credential's revocation can never be aged out, unlike an STS
///   session's) and it puts credential identifiers into a document every gateway pod
///   holds in memory.
/// * **An epoch floor** fails closed by construction. The key carries the epoch it was
///   minted at; the bundle publishes the lowest epoch it still honours; a key below the
///   floor is refused. **Absence of the floor denies**, so an empty bundle, a tenant the
///   bundle does not carry, the operator's `seed_bundle`, and a field of the wrong type
///   all mean "no derived key works here" rather than "every derived key works here".
///   Publishing the floor is therefore the platform's explicit opt-in to the whole
///   credential class, and one number revokes a whole tenant's keys at once.
///
/// The floor is composed from **two** published values so revocation is not all-or-
/// nothing: a per-tenant epoch (the blunt instrument — rotate everybody) and an optional
/// per-subject epoch (the surgical one — cut off one compromised consumer without
/// touching the other four). The effective floor is the **greater** of the two, so a
/// subject entry can only ever tighten, never loosen, what the tenant published.
///
/// The epoch carries **no scope and no permissions**. It is a revocation counter, and
/// that distinction is what keeps `FOLLOW-UPS.md` **F21** / **ADR-0016** closed: the
/// credential stays an identity, and everything about what it may do is still read live
/// from the bundle at decision time.
pub trait KeyEpochFloor: Send + Sync {
    /// The lowest `key_epoch` a derived key for this `(tenant, subject_key)` may carry.
    ///
    /// `None` means the bundle in force publishes no floor for this tenant, which
    /// **denies** — see the trait docs. `subject_key` is the bundle's own key space
    /// (`sa:<client id>` / `user:<sub>`), composed by
    /// [`crate::pdp::principal_subject_key`].
    fn key_epoch_floor(&self, tenant: &str, subject_key: &str) -> Option<u32>;
}

/// The derived-key half of [`Identity`]: the ring that verifies, the tenant→org table
/// that attributes, and the bundle that revokes.
///
/// Held as a unit because all three are required to admit a key, and a construction that
/// let one be omitted would be a construction in which a key is admitted without being
/// revocable, or attributed from its own payload.
pub struct DerivedKeys {
    authority: Arc<DerivedKeyAuthority>,
    tenants: Arc<dyn TenantDirectory>,
    epochs: Arc<dyn KeyEpochFloor>,
}

impl DerivedKeys {
    pub fn new(
        authority: Arc<DerivedKeyAuthority>,
        tenants: Arc<dyn TenantDirectory>,
        epochs: Arc<dyn KeyEpochFloor>,
    ) -> Self {
        DerivedKeys {
            authority,
            tenants,
            epochs,
        }
    }

    /// The ring, for the operator-facing startup log and for tests.
    pub fn authority(&self) -> &DerivedKeyAuthority {
        &self.authority
    }

    /// **The single admission path.** Verify, then revoke-check, then attribute — in that
    /// order, and every failure answers the same `None`.
    ///
    /// 1. the MAC is checked before any field inside the id is read
    ///    ([`DerivedKeyAuthority::verify`]);
    /// 2. the key's epoch is checked against the floor the **bundle in force** publishes,
    ///    which is where revocation happens and where the absence of data denies;
    /// 3. the organization is resolved from the gateway's own tenant→org table. A tenant
    ///    this gateway does not route is refused here, which is also what refuses a key
    ///    minted for another deployment's tenant.
    ///
    /// The organization inside the credential is not consulted, because there is none:
    /// [`DerivedPrincipal`] has no such field, by design.
    fn admit(&self, access_key_id: &str) -> Option<(DerivedPrincipal, String)> {
        let principal = self.authority.verify(access_key_id)?;
        let subject_key =
            crate::pdp::principal_subject_key(principal.principal_type, &principal.sub);
        let Some(floor) = self.epochs.key_epoch_floor(&principal.tenant, &subject_key) else {
            tracing::warn!(
                tenant = %principal.tenant,
                subject = %subject_key,
                "derived key refused: the bundle in force publishes no key epoch for this \
                 tenant, so no derived key can be honoured for it (this is the fail-closed \
                 direction; publish `tenants.<tenant>.s3_key_epoch` to enable them)"
            );
            return None;
        };
        if principal.key_epoch < floor {
            tracing::warn!(
                tenant = %principal.tenant,
                subject = %subject_key,
                key_epoch = principal.key_epoch,
                floor,
                "derived key refused: REVOKED by key epoch"
            );
            return None;
        }
        let organization_id = self.tenants.organization_of(&principal.tenant)?;
        Some((principal, organization_id))
    }

    /// The SigV4 secret for an admitted key. A key that is forged, revoked, or names a
    /// tenant this gateway does not route derives nothing — so all four are one answer.
    fn secret(&self, access_key_id: &str) -> Option<String> {
        self.admit(access_key_id)?;
        self.authority.secret_for_access_key(access_key_id)
    }

    /// The full identity for an admitted key.
    ///
    /// **`groups` is empty, deliberately.** Group membership is read live from the bundle
    /// by the policy (`data.tenants[t].user_attributes[sub].groups`), never from the
    /// credential — which is the same reason an STS session's groups are advisory and a
    /// web-identity session carries none at all (AWS-PARITY D27). A long-lived key that
    /// froze its groups at mint time would be a permanent grant of whatever those groups
    /// confer, which is the scope-in-the-credential mistake this design exists to avoid.
    fn resolve(&self, access_key_id: &str) -> Option<ResolvedPrincipal> {
        let (principal, organization_id) = self.admit(access_key_id)?;
        Some(ResolvedPrincipal {
            sub: principal.sub,
            principal_type: principal.principal_type,
            groups: Vec::new(),
            tenant: principal.tenant,
            organization_id,
        })
    }
}

/// Ties the STS authority, the derived-key authority and the static store together.
/// Answers both the `S3Auth::get_secret_key` question and the "who is this principal"
/// question the access layer asks in `check`.
pub struct Identity {
    sts: Arc<StsAuthority>,
    creds: Arc<dyn CredentialStore>,
    /// `None` when the deployment has not configured derived keys. **The namespace is
    /// still reserved** — see [`Identity::secret_key`].
    derived: Option<Arc<DerivedKeys>>,
}

/// Header carrying the STS session token (standard SigV4 session credential).
pub const SECURITY_TOKEN_HEADER: &str = "x-amz-security-token";

impl Identity {
    pub fn new(sts: Arc<StsAuthority>, creds: Arc<dyn CredentialStore>) -> Self {
        Identity {
            sts,
            creds,
            derived: None,
        }
    }

    /// Switch on derived long-lived keys (F17).
    ///
    /// **Additive by construction, and the signature is where that is stated:** every
    /// existing call site keeps the two-argument [`Identity::new`], gets `derived: None`,
    /// and behaves byte-identically to a build made before this existed. Nothing about
    /// the STS path, the static path or the web-identity door changes here or below.
    pub fn with_derived_keys(mut self, derived: Arc<DerivedKeys>) -> Self {
        self.derived = Some(derived);
        self
    }

    /// The STS authority, shared with the mint (the badge desk) so minted sessions and
    /// inbound verification use the same keys.
    pub fn sts(&self) -> Arc<StsAuthority> {
        self.sts.clone()
    }

    /// The three credential namespaces are disjoint **by construction**, not by
    /// configuration: anything carrying the STS prefix is answered by the STS
    /// authority alone, and anything carrying the derived-key prefix by the derived-key
    /// half alone, even when it is malformed or names a retired key id.
    ///
    /// **The `HFSA` namespace is reserved even when derived keys are switched off**, and
    /// that `None` is not an oversight. If an unconfigured deployment fell through to the
    /// static store, whoever can write the credential list could provision a credential
    /// there and have it start working the day derived keys are enabled — or, worse, keep
    /// working under a principal the derived path would have resolved differently. So an
    /// id in this namespace is answered here or not at all.
    ///
    /// `GatewayConfig::validate` also rejects a static credential in either namespace,
    /// but that guard protects one config-loading path; this one holds for every store a
    /// `CredentialStore` impl could ever be.
    fn secret_key(&self, access_key_id: &str) -> Option<String> {
        if StsAuthority::is_sts_access_key(access_key_id) {
            return self.sts.secret_for_access_key(access_key_id);
        }
        if DerivedKeyAuthority::is_derived_access_key(access_key_id) {
            return self.derived.as_ref()?.secret(access_key_id);
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
        if DerivedKeyAuthority::is_derived_access_key(access_key_id) {
            // A derived key presents no session token; a caller that sends one is not
            // making it more authoritative, and it is ignored rather than trusted.
            return self
                .derived
                .as_ref()
                .and_then(|d| d.resolve(access_key_id))
                .ok_or_else(|| {
                    // One message for forged, revoked, unknown-kid and unroutable-tenant
                    // alike: an id that failed here must not tell its holder which.
                    GatewayError::Credentials(format!("unknown access key {access_key_id}"))
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

    // ── derived long-lived per-principal keys (F17) ──────────────────────────────

    mod derived_keys {
        use super::*;
        use crate::auth::derived::{DERIVED_PREFIX, DerivedKeyAuthority, DerivedPrincipal};
        use std::sync::Mutex;

        /// A tenant→org table with exactly one routable tenant, so "a key for an unknown
        /// tenant" is a real state and not an absence of setup.
        struct OneTenant;
        impl TenantDirectory for OneTenant {
            fn organization_of(&self, tenant: &str) -> Option<String> {
                (tenant == "acme").then(|| "org-acme".to_string())
            }
        }

        /// A stand-in for the bundle, swappable mid-test — which is what "within one
        /// bundle refresh" means when the bundle is not a file.
        #[derive(Default)]
        struct Epochs(Mutex<Option<u32>>);
        impl Epochs {
            fn at(floor: u32) -> Arc<Self> {
                Arc::new(Epochs(Mutex::new(Some(floor))))
            }
            fn publish(&self, floor: Option<u32>) {
                *self.0.lock().unwrap() = floor;
            }
        }
        impl KeyEpochFloor for Epochs {
            fn key_epoch_floor(&self, _tenant: &str, _subject: &str) -> Option<u32> {
                *self.0.lock().unwrap()
            }
        }

        fn principal(tenant: &str, epoch: u32) -> DerivedPrincipal {
            DerivedPrincipal {
                tenant: tenant.into(),
                sub: "trino-background".into(),
                principal_type: PrincipalType::ServiceAccount,
                key_epoch: epoch,
            }
        }

        /// The full identity, with all three credential classes live at once.
        fn identity_with(
            epochs: Arc<Epochs>,
        ) -> (Identity, Arc<DerivedKeyAuthority>, StsAuthority) {
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
            let authority = Arc::new(DerivedKeyAuthority::new(vec![9u8; 32]).unwrap());
            let id =
                Identity::new(Arc::new(sts.clone()), Arc::new(store)).with_derived_keys(Arc::new(
                    DerivedKeys::new(authority.clone(), Arc::new(OneTenant), epochs),
                ));
            (id, authority, sts)
        }

        /// The headline: a derived key authenticates and resolves to the right principal,
        /// tenant and organization — and the organization is the **table's**, not one the
        /// credential could have named.
        #[test]
        fn a_derived_key_authenticates_and_resolves_to_its_principal_tenant_and_org() {
            let (id, authority, _) = identity_with(Epochs::at(1));
            let creds = authority.mint(&principal("acme", 1)).unwrap();

            assert_eq!(
                id.secret_key(&creds.access_key_id).as_deref(),
                Some(creds.secret_access_key.as_str()),
                "the SigV4 path does not reproduce the secret the mint handed out"
            );
            let p = id.resolve(&creds.access_key_id, None).unwrap();
            assert_eq!(p.sub, "trino-background");
            assert_eq!(p.principal_type, PrincipalType::ServiceAccount);
            assert_eq!(p.tenant, "acme");
            assert_eq!(p.organization_id, "org-acme");
            // Groups come from the bundle at decision time, never from the credential.
            assert!(p.groups.is_empty());
            // A key ABOVE the floor is fine too: the floor is a floor, not an equality.
            let newer = authority.mint(&principal("acme", 7)).unwrap();
            assert!(id.resolve(&newer.access_key_id, None).is_ok());
        }

        /// The one place the organization could leak in from the credential is the
        /// payload, so this asserts the payload has nowhere to put it: two gateways with
        /// different tables read the same key as different organizations, and neither
        /// reads it as anything the minter chose.
        #[test]
        fn the_organization_comes_from_the_table_and_the_credential_cannot_name_one() {
            struct OtherOrg;
            impl TenantDirectory for OtherOrg {
                fn organization_of(&self, _tenant: &str) -> Option<String> {
                    Some("org-somewhere-else".into())
                }
            }
            let (id, authority, _) = identity_with(Epochs::at(0));
            let creds = authority.mint(&principal("acme", 0)).unwrap();
            assert_eq!(
                id.resolve(&creds.access_key_id, None)
                    .unwrap()
                    .organization_id,
                "org-acme"
            );

            let relabelled = Identity::new(
                Arc::new(StsAuthority::new(vec![3u8; 32], vec![5u8; 32]).unwrap()),
                Arc::new(StaticCredentialStore::new()),
            )
            .with_derived_keys(Arc::new(DerivedKeys::new(
                authority.clone(),
                Arc::new(OtherOrg),
                Epochs::at(0),
            )));
            assert_eq!(
                relabelled
                    .resolve(&creds.access_key_id, None)
                    .unwrap()
                    .organization_id,
                "org-somewhere-else",
                "the same credential resolved to the same org under a different table, so \
                 the org is coming from the credential"
            );
        }

        #[test]
        fn a_forged_mac_is_indistinguishable_from_an_unknown_key() {
            let (id, authority, _) = identity_with(Epochs::at(0));
            let good = authority.mint(&principal("acme", 0)).unwrap().access_key_id;
            let (head, mac) = good.rsplit_once('.').unwrap();
            let forged = format!(
                "{head}.{}{}",
                if mac.starts_with('A') { 'B' } else { 'A' },
                &mac[1..]
            );
            let never_minted =
                format!("{DERIVED_PREFIX}k0.AQEAAAAABGFjbWV4.AAAAAAAAAAAAAAAAAAAAAA");

            for bad in [&forged, &never_minted] {
                assert_eq!(id.secret_key(bad), None, "{bad}");
                let err = id.resolve(bad, None).expect_err("must refuse");
                assert!(
                    format!("{err}").starts_with("credential store error: unknown access key"),
                    "a forged key produced a distinguishable error: {err}"
                );
            }
            // The two refusals are the SAME message, so nothing separates "your MAC is
            // wrong" from "no such key".
            assert_eq!(
                format!("{}", id.resolve(&forged, None).unwrap_err()).replace(&forged, "<id>"),
                format!("{}", id.resolve(&never_minted, None).unwrap_err())
                    .replace(&never_minted, "<id>")
            );
            assert!(id.resolve(&good, None).is_ok());
        }

        #[test]
        fn a_key_for_an_unknown_tenant_is_refused() {
            let (id, authority, _) = identity_with(Epochs::at(0));
            // Genuinely minted, MAC intact, epoch fine — and naming a tenant this
            // gateway does not route. That is a key from another deployment, or from
            // before a tenant was removed.
            let creds = authority.mint(&principal("not-ours", 0)).unwrap();
            assert!(authority.verify(&creds.access_key_id).is_some());
            assert_eq!(id.secret_key(&creds.access_key_id), None);
            assert!(id.resolve(&creds.access_key_id, None).is_err());
        }

        /// **Revocation, and the direction absence fails in.**
        #[test]
        fn a_revoked_key_stops_working_at_the_next_bundle_refresh() {
            let epochs = Epochs::at(1);
            let (id, authority, _) = identity_with(epochs.clone());
            let creds = authority.mint(&principal("acme", 1)).unwrap();
            assert!(id.resolve(&creds.access_key_id, None).is_ok());
            assert!(id.secret_key(&creds.access_key_id).is_some());

            // One bundle poll raises the floor. Nothing else happens: no restart, no
            // config change, no store to edit.
            epochs.publish(Some(2));
            assert_eq!(
                id.secret_key(&creds.access_key_id),
                None,
                "a revoked key still derives a secret, so SigV4 still succeeds"
            );
            assert!(id.resolve(&creds.access_key_id, None).is_err());

            // A key minted AFTER the bump works, which is what makes this a revocation
            // rather than a kill switch.
            let reissued = authority.mint(&principal("acme", 2)).unwrap();
            assert!(id.resolve(&reissued.access_key_id, None).is_ok());

            // And the floor going ABSENT — an empty bundle, a tenant the projection
            // dropped, the operator's seed bundle — denies rather than admits.
            epochs.publish(None);
            assert_eq!(id.secret_key(&reissued.access_key_id), None);
            assert!(id.resolve(&reissued.access_key_id, None).is_err());
        }

        /// The multi-replica property (F8) at the identity layer: a key minted on one
        /// pod, verified on a second process that has only the key material — no shared
        /// store, nothing carried across the restart.
        #[test]
        fn a_key_survives_a_pod_restart_and_works_on_a_second_instance() {
            let (pod_a, authority, _) = identity_with(Epochs::at(1));
            let creds = authority.mint(&principal("acme", 1)).unwrap();
            let expected = pod_a.resolve(&creds.access_key_id, None).unwrap();
            drop(pod_a);
            drop(authority);

            // A second process, built from config alone.
            let (pod_b, _, _) = identity_with(Epochs::at(1));
            assert_eq!(
                pod_b.secret_key(&creds.access_key_id).as_deref(),
                Some(creds.secret_access_key.as_str())
            );
            let there = pod_b.resolve(&creds.access_key_id, None).unwrap();
            assert_eq!(
                (there.sub, there.tenant, there.organization_id),
                (expected.sub, expected.tenant, expected.organization_id)
            );
        }

        /// **The additive guarantee.** With derived keys switched on, the two existing
        /// credential classes behave exactly as they did — same secrets, same principals,
        /// same refusals.
        #[test]
        fn sts_and_static_credentials_are_untouched_by_the_new_class() {
            let (with_derived, _, sts) = identity_with(Epochs::at(0));
            let plain = {
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
                Identity::new(Arc::new(sts.clone()), Arc::new(store))
            };

            let session = sts
                .mint(
                    "sid-1",
                    SessionClaims {
                        sub: "alice".into(),
                        principal_type: PrincipalType::User,
                        groups: vec!["analysts".into()],
                        tenant: "acme".into(),
                        org: "org-acme".into(),
                        sid: "sid-1".into(),
                        exp: far_future(),
                    },
                )
                .unwrap();

            for (label, key, token) in [
                ("static", "AKIASTATIC".to_string(), None),
                (
                    "sts",
                    session.access_key_id.clone(),
                    Some(session.session_token.as_str()),
                ),
                ("unknown", "AKIANOPE".to_string(), None),
                ("malformed sts", format!("{}sid-1", sts::STS_PREFIX), None),
            ] {
                assert_eq!(
                    with_derived.secret_key(&key),
                    plain.secret_key(&key),
                    "{label}: secret_key diverged"
                );
                let (a, b) = (
                    with_derived.resolve(&key, token),
                    plain.resolve(&key, token),
                );
                match (a, b) {
                    (Ok(a), Ok(b)) => assert_eq!(
                        (a.sub, a.tenant, a.organization_id, a.groups),
                        (b.sub, b.tenant, b.organization_id, b.groups),
                        "{label}: resolve diverged"
                    ),
                    (Err(a), Err(b)) => assert_eq!(format!("{a}"), format!("{b}"), "{label}"),
                    (a, b) => {
                        panic!("{label}: one path resolved and the other did not: {a:?} {b:?}")
                    }
                }
            }
        }

        /// The namespace is answered here or not at all, **including when the feature is
        /// off** — otherwise a static entry parked in `HFSA*` would start resolving the
        /// day an operator enables derived keys.
        #[test]
        fn a_static_credential_cannot_shadow_the_derived_namespace_switched_on_or_off() {
            let authority = DerivedKeyAuthority::new(vec![9u8; 32]).unwrap();
            let squatted = authority.mint(&principal("acme", 0)).unwrap().access_key_id;
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
            let store = Arc::new(store);
            let sts = Arc::new(StsAuthority::new(vec![3u8; 32], vec![5u8; 32]).unwrap());

            // Feature OFF: the namespace answers nothing.
            let off = Identity::new(sts.clone(), store.clone());
            assert_eq!(off.secret_key(&squatted), None);
            assert!(off.resolve(&squatted, None).is_err());
            // A malformed id in the namespace, likewise.
            let malformed = format!("{DERIVED_PREFIX}whatever");
            assert_eq!(off.secret_key(&malformed), None);
            assert!(off.resolve(&malformed, None).is_err());

            // Feature ON: still not the static entry — the derived authority answers,
            // and it hands back the DERIVED secret, not "attacker-chosen".
            let on = Identity::new(sts, store).with_derived_keys(Arc::new(DerivedKeys::new(
                Arc::new(authority),
                Arc::new(OneTenant),
                Epochs::at(0),
            )));
            assert_ne!(on.secret_key(&squatted).as_deref(), Some("attacker-chosen"));
            assert_eq!(on.resolve(&squatted, None).unwrap().sub, "trino-background");
            assert_eq!(on.secret_key(&malformed), None);
        }
    }
}
