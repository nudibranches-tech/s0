//! Bundle-driven SFTP authentication (ADR-009 D5).
//!
//! An SFTP principal is an **existing bundle subject**. What the `data.sftp` section adds is
//! a way to *reach* a subject over SSH: an account keyed by login, naming its tenant, its
//! subject and its home, plus the key fingerprints and user CAs that may authenticate it.
//! An account **confers nothing** — authority still comes only from grants, decided by the
//! PDP on every operation.
//!
//! Every degenerate input fails closed ([`Directory::gate`]): no section, a wrong
//! `sftp.version`, a `grant_schema_version` below 3, a malformed account. The one
//! "absent means unrestricted" field is `allowed_source_cidrs`, because it restricts on top
//! of key possession rather than granting anything.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use russh::keys::ssh_key::certificate::CertType;
use russh::keys::ssh_key::public::KeyData;
use russh::keys::{Algorithm, Certificate, EcdsaCurve, HashAlg};

use super::limits::{Cidr, any_contains};
use super::paths::Home;
use crate::model::PrincipalType;
use crate::pdp::{Bundle, split_subject_key, subject_lookup_key};

/// The `data.sftp.version` this binary understands.
pub const SFTP_SECTION_VERSION: u64 = 1;
/// The lowest `grant_schema_version` that defines `create_objects` and `data.sftp`.
pub const MIN_GRANT_SCHEMA_VERSION: u64 = 3;

/// `^[a-z0-9][a-z0-9._-]{0,63}$` — excludes `@` and `:`, the separators clients and the
/// subject-key space already use.
pub fn login_is_valid(login: &str) -> bool {
    let b = login.as_bytes();
    !b.is_empty()
        && b.len() <= 64
        && (b[0].is_ascii_lowercase() || b[0].is_ascii_digit())
        && b.iter().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-')
        })
}

/// The client-key algorithms D3 accepts: ed25519 and the three ECDSA curves. No RSA (its
/// SHA-1 signature cannot be excluded on the pinned russh, E6), no DSA, no security keys.
pub fn client_key_allowed(key: &KeyData) -> bool {
    matches!(
        key.algorithm(),
        Algorithm::Ed25519
            | Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256 | EcdsaCurve::NistP384 | EcdsaCurve::NistP521
            }
    )
}

/// `SHA256:<base64, no padding>`, exactly as OpenSSH prints it.
pub fn fingerprint(key: &KeyData) -> String {
    key.fingerprint(HashAlg::Sha256).to_string()
}

/// The algorithm name as the bundle spells `key_type`.
pub fn key_type(key: &KeyData) -> String {
    key.algorithm().as_str().to_string()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyRef {
    key_type: String,
    fingerprint: String,
}

/// One `data.sftp.user_cas` entry.
#[derive(Debug, Clone)]
pub struct UserCa {
    pub id: String,
    key: KeyRef,
    /// `None` ⇒ `["*"]`: every tenant.
    tenants: Option<HashSet<String>>,
    revoked_serials: HashSet<u64>,
    revoked_key_ids: HashSet<String>,
}

/// One `data.sftp.accounts` entry, validated.
#[derive(Debug, Clone)]
pub struct Account {
    pub login: String,
    pub tenant: String,
    /// Identity-contract form, always prefixed (`sa:` / `user:`).
    pub subject_key: String,
    pub principal_type: PrincipalType,
    /// The raw subject (`input.principal.sub`).
    pub sub: String,
    pub home: Home,
    authorized_keys: Vec<KeyRef>,
    certificate_authorities: Vec<String>,
    /// `None` ⇒ no restriction; `Some([])` ⇒ nothing allowed.
    allowed_source_cidrs: Option<Vec<Cidr>>,
}

/// The `data.sftp` section of one bundle revision, parsed once and memoized.
#[derive(Debug)]
pub struct Directory {
    pub revision: String,
    /// `Err(reason)` ⇒ every login is rejected for this revision.
    gate: Result<(), String>,
    accounts: HashMap<String, Account>,
    cas: HashMap<String, UserCa>,
    denied_source_cidrs: Vec<Cidr>,
    /// Membership lookups follow the module in force (see [`subject_lookup_key`]).
    policy_module: bool,
    /// `tenants[t].user_attributes`, kept for the membership and groups check.
    user_attributes: HashMap<String, serde_json::Map<String, serde_json::Value>>,
}

/// How a session authenticated, re-checkable against any later directory.
#[derive(Debug, Clone)]
pub enum Credential {
    PublicKey { key: KeyData },
    Certificate { cert: Box<Certificate> },
}

impl Credential {
    pub fn method(&self) -> &'static str {
        match self {
            Credential::PublicKey { .. } => "publickey",
            Credential::Certificate { .. } => "openssh-cert",
        }
    }

    pub fn key(&self) -> &KeyData {
        match self {
            Credential::PublicKey { key } => key,
            Credential::Certificate { cert } => cert.public_key(),
        }
    }
}

/// What the audit record says about how the session authenticated.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct AuthInfo {
    pub method: String,
    pub key_type: String,
    pub key_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cert: Option<CertInfo>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct CertInfo {
    pub key_id: String,
    pub serial: u64,
    pub ca: String,
    pub ca_fingerprint: String,
}

/// A successful authentication: the account and the subject it reaches.
#[derive(Debug, Clone)]
pub struct Authenticated {
    pub account: Account,
    pub groups: Vec<String>,
    pub auth: AuthInfo,
}

impl Directory {
    /// Parse `data.sftp` out of one bundle.
    pub fn from_bundle(bundle: &Bundle) -> Self {
        let data = &bundle.data;
        let mut dir = Directory {
            revision: bundle.revision.clone(),
            gate: Ok(()),
            accounts: HashMap::new(),
            cas: HashMap::new(),
            denied_source_cidrs: Vec::new(),
            policy_module: bundle.policy_module,
            user_attributes: HashMap::new(),
        };
        let Some(section) = data.get("sftp") else {
            dir.gate = Err("the bundle carries no sftp section".into());
            return dir;
        };
        match section.get("version").and_then(serde_json::Value::as_u64) {
            Some(SFTP_SECTION_VERSION) => {}
            other => {
                dir.gate = Err(format!(
                    "data.sftp.version is {other:?}; this gateway understands {SFTP_SECTION_VERSION}"
                ));
                tracing::error!(revision = %bundle.revision, reason = ?dir.gate, "sftp section refused; every login is rejected");
                return dir;
            }
        }
        // Absent ⇒ a hand-written bundle on the compiled-in module: governed by
        // `sftp.version` alone. Present and below 3 ⇒ a module that predates
        // `create_objects`.
        if let Some(v) = data.get("grant_schema_version") {
            match v.as_u64() {
                Some(v) if v >= MIN_GRANT_SCHEMA_VERSION => {}
                _ => {
                    dir.gate = Err(format!(
                        "grant_schema_version {v} is below {MIN_GRANT_SCHEMA_VERSION}; a \
                         module that predates create_objects cannot serve SFTP"
                    ));
                    tracing::error!(revision = %bundle.revision, reason = ?dir.gate, "sftp refused for this bundle");
                    return dir;
                }
            }
        }
        if let Some(tenants) = data.get("tenants").and_then(|t| t.as_object()) {
            for (t, body) in tenants {
                if let Some(ua) = body.get("user_attributes").and_then(|u| u.as_object()) {
                    dir.user_attributes.insert(t.clone(), ua.clone());
                }
            }
        }
        if let Some(cidrs) = section
            .get("denied_source_cidrs")
            .and_then(|c| c.as_array())
        {
            for c in cidrs {
                match c.as_str().map(Cidr::parse) {
                    Some(Ok(c)) => dir.denied_source_cidrs.push(c),
                    _ => {
                        // A denylist entry that does not parse cannot be enforced, and an
                        // unenforced block is an allow nobody chose. Refuse the section.
                        dir.gate = Err(format!(
                            "data.sftp.denied_source_cidrs has an invalid entry {c}"
                        ));
                        tracing::error!(revision = %bundle.revision, reason = ?dir.gate, "sftp refused for this bundle");
                        return dir;
                    }
                }
            }
        }
        if let Some(cas) = section.get("user_cas").and_then(|c| c.as_object()) {
            for (id, body) in cas {
                match parse_ca(id, body) {
                    Ok(ca) => {
                        dir.cas.insert(id.clone(), ca);
                    }
                    Err(e) => tracing::error!(ca = %id, error = %e, "sftp user CA ignored"),
                }
            }
        }
        if let Some(accounts) = section.get("accounts").and_then(|a| a.as_object()) {
            for (login, body) in accounts {
                match parse_account(login, body) {
                    Ok(a) => {
                        dir.accounts.insert(login.clone(), a);
                    }
                    Err(e) => {
                        tracing::error!(%login, error = %e, "sftp account rejected; others unaffected")
                    }
                }
            }
        }
        dir
    }

    pub fn gate(&self) -> Result<(), &str> {
        self.gate.as_ref().map(|_| ()).map_err(String::as_str)
    }

    /// The bundle-distributed fleet-wide block, enforced at accept time.
    pub fn is_source_denied(&self, ip: IpAddr) -> bool {
        any_contains(&self.denied_source_cidrs, ip)
    }

    /// Check a credential for `login` from `client_ip`. Errors are audit reasons, and are
    /// never shown to the client (every failure looks the same from outside).
    pub fn authenticate(
        &self,
        login: &str,
        credential: &Credential,
        client_ip: IpAddr,
        now_unix: u64,
    ) -> Result<Authenticated, String> {
        self.gate().map_err(str::to_string)?;
        if self.is_source_denied(client_ip) {
            return Err("source address is on the bundle denylist".into());
        }
        let account = self
            .accounts
            .get(login)
            .ok_or_else(|| "unknown login".to_string())?;
        if let Some(allowed) = &account.allowed_source_cidrs
            && !any_contains(allowed, client_ip)
        {
            return Err("source address not allowed for this account".into());
        }
        if !client_key_allowed(credential.key()) {
            return Err(format!(
                "client key type {} is not accepted (ed25519 and ECDSA only)",
                key_type(credential.key())
            ));
        }
        let auth = match credential {
            Credential::PublicKey { key } => {
                let want = KeyRef {
                    key_type: key_type(key),
                    fingerprint: fingerprint(key),
                };
                if !account.authorized_keys.contains(&want) {
                    return Err("key not authorized for login".into());
                }
                AuthInfo {
                    method: "publickey".into(),
                    key_type: want.key_type,
                    key_fingerprint: want.fingerprint,
                    cert: None,
                }
            }
            Credential::Certificate { cert } => {
                self.check_certificate(account, cert, client_ip, now_unix)?
            }
        };
        let groups = self.membership(account)?;
        Ok(Authenticated {
            account: account.clone(),
            groups,
            auth,
        })
    }

    /// The subject's membership, read under the key the module in force reads.
    fn membership(&self, account: &Account) -> Result<Vec<String>, String> {
        let key = subject_lookup_key(self.policy_module, &account.subject_key)
            .ok_or_else(|| "account subject_key has no recognized prefix".to_string())?;
        let attrs = self
            .user_attributes
            .get(&account.tenant)
            .and_then(|ua| ua.get(&key))
            .and_then(|v| v.as_object())
            .ok_or_else(|| format!("subject {key} is not a member of tenant {}", account.tenant))?;
        Ok(attrs
            .get("groups")
            .and_then(|g| g.as_array())
            .map(|g| {
                g.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default())
    }

    /// The D5 certificate mapping, rules 1–8. russh has already checked the validity
    /// window and the CA signature (E6); both are re-checked here with the same clock, so
    /// a re-authorization after a bundle swap does not depend on russh having run.
    fn check_certificate(
        &self,
        account: &Account,
        cert: &Certificate,
        client_ip: IpAddr,
        now_unix: u64,
    ) -> Result<AuthInfo, String> {
        // 1
        if account.certificate_authorities.is_empty() {
            return Err("account accepts no certificates".into());
        }
        // 2
        if cert.cert_type() != CertType::User {
            return Err("not a user certificate".into());
        }
        // 3 + 8 (CA key type)
        let ca_key = cert.signature_key();
        if !client_key_allowed(ca_key) {
            return Err("certificate CA key type is not accepted".into());
        }
        let ca_ref = KeyRef {
            key_type: key_type(ca_key),
            fingerprint: fingerprint(ca_key),
        };
        let ca = account
            .certificate_authorities
            .iter()
            .filter_map(|id| self.cas.get(id))
            .find(|ca| ca.key == ca_ref)
            .ok_or_else(|| "certificate CA is not trusted for this login".to_string())?;
        if let Some(tenants) = &ca.tenants
            && !tenants.contains(&account.tenant)
        {
            return Err(format!(
                "CA {} is not scoped to tenant {}",
                ca.id, account.tenant
            ));
        }
        // 4: literal principal; an empty list means "any" in OpenSSH and is refused.
        if cert.valid_principals().is_empty() {
            return Err("certificate has an empty principals list".into());
        }
        if !cert.valid_principals().iter().any(|p| p == &account.login) {
            return Err("certificate does not name this login as a principal".into());
        }
        // 5
        if now_unix < cert.valid_after() || now_unix >= cert.valid_before() {
            return Err("certificate is outside its validity window".into());
        }
        cert.verify_signature()
            .map_err(|_| "certificate signature does not verify".to_string())?;
        // 6
        if ca.revoked_serials.contains(&cert.serial()) {
            return Err(format!("certificate serial {} is revoked", cert.serial()));
        }
        if ca.revoked_key_ids.contains(cert.key_id()) {
            return Err(format!("certificate key id {:?} is revoked", cert.key_id()));
        }
        // 7: critical options; extensions are ignored.
        for (name, value) in cert.critical_options().iter() {
            match name.as_str() {
                "source-address" => {
                    let allowed: Result<Vec<Cidr>, _> =
                        value.split(',').map(|c| Cidr::parse(c.trim())).collect();
                    let allowed = allowed
                        .map_err(|_| "certificate source-address does not parse".to_string())?;
                    if !any_contains(&allowed, client_ip) {
                        return Err("certificate source-address excludes the client".into());
                    }
                }
                "force-command" if value == "internal-sftp" => {}
                other => {
                    return Err(format!(
                        "certificate carries critical option {other:?}, which this gateway does \
                         not understand"
                    ));
                }
            }
        }
        // 8 (certified key type) is checked by the caller on `credential.key()`.
        let key = cert.public_key();
        Ok(AuthInfo {
            method: "openssh-cert".into(),
            key_type: key_type(key),
            key_fingerprint: fingerprint(key),
            cert: Some(CertInfo {
                key_id: cert.key_id().to_string(),
                serial: cert.serial(),
                ca: ca.id.clone(),
                ca_fingerprint: ca.key.fingerprint.clone(),
            }),
        })
    }
}

fn str_field<'a>(v: &'a serde_json::Value, k: &str) -> Result<&'a str, String> {
    v.get(k)
        .and_then(|x| x.as_str())
        .ok_or_else(|| format!("missing or non-string {k}"))
}

fn parse_key_ref(v: &serde_json::Value) -> Result<KeyRef, String> {
    let key_type = str_field(v, "key_type")?.to_string();
    let fingerprint = str_field(v, "fingerprint")?.to_string();
    if !fingerprint.starts_with("SHA256:") {
        return Err(format!(
            "fingerprint {fingerprint:?} is not SHA256:<base64>"
        ));
    }
    Ok(KeyRef {
        key_type,
        fingerprint,
    })
}

fn parse_ca(id: &str, v: &serde_json::Value) -> Result<UserCa, String> {
    let key = parse_key_ref(v)?;
    let tenants = v
        .get("tenants")
        .and_then(|t| t.as_array())
        .ok_or("missing tenants (CA scopes must be explicit)")?;
    let tenants: Vec<String> = tenants
        .iter()
        .map(|t| t.as_str().map(str::to_string).ok_or("non-string tenant"))
        .collect::<Result<_, _>>()?;
    if tenants.is_empty() {
        return Err("empty tenants: a CA scoped to nothing vouches for nothing".into());
    }
    let tenants = if tenants == ["*"] {
        None
    } else if tenants.iter().any(|t| t == "*") {
        return Err("\"*\" must be the only tenant entry".into());
    } else {
        Some(tenants.into_iter().collect())
    };
    let revoked_serials = v
        .get("revoked_serials")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .map(|x| x.as_u64().ok_or("non-integer serial"))
                .collect()
        })
        .transpose()?
        .unwrap_or_default();
    let revoked_key_ids = v
        .get("revoked_key_ids")
        .and_then(|s| s.as_array())
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().map(str::to_string).ok_or("non-string key id"))
                .collect()
        })
        .transpose()?
        .unwrap_or_default();
    Ok(UserCa {
        id: id.to_string(),
        key,
        tenants,
        revoked_serials,
        revoked_key_ids,
    })
}

fn parse_account(login: &str, v: &serde_json::Value) -> Result<Account, String> {
    if !login_is_valid(login) {
        return Err("login does not match ^[a-z0-9][a-z0-9._-]{0,63}$".into());
    }
    let tenant = str_field(v, "tenant")?.to_string();
    if tenant.is_empty() {
        return Err("empty tenant".into());
    }
    let subject_key = str_field(v, "subject_key")?.to_string();
    let (principal_type, sub) = split_subject_key(&subject_key)
        .ok_or_else(|| format!("subject_key {subject_key:?} is not sa:<id> or user:<sub>"))?;
    let sub = sub.to_string();
    let home = v.get("home").ok_or("missing home")?;
    let bucket = str_field(home, "bucket")?.to_string();
    if bucket.is_empty() || bucket.contains('/') {
        return Err("home.bucket must be a bucket name".into());
    }
    let prefix = home
        .get("prefix")
        .and_then(|p| p.as_str())
        .unwrap_or("")
        .to_string();
    if !prefix.is_empty() && !prefix.ends_with('/') {
        // ADR-006 R3's stem pitfall: `partner-x` would also match `partner-x-old/`.
        return Err(format!(
            "home.prefix {prefix:?} must be empty or /-terminated"
        ));
    }
    if prefix.starts_with('/')
        || prefix.contains("//")
        || prefix.split('/').any(|c| c == "." || c == "..")
    {
        return Err(format!(
            "home.prefix {prefix:?} is not a canonical key prefix"
        ));
    }
    let authorized_keys = v
        .get("authorized_keys")
        .and_then(|k| k.as_array())
        .map(|a| a.iter().map(parse_key_ref).collect::<Result<Vec<_>, _>>())
        .transpose()?
        .unwrap_or_default();
    let certificate_authorities = v
        .get("certificate_authorities")
        .and_then(|k| k.as_array())
        .map(|a| {
            a.iter()
                .map(|x| x.as_str().map(str::to_string).ok_or("non-string CA id"))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?
        .unwrap_or_default();
    let allowed_source_cidrs = match v.get("allowed_source_cidrs") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::Array(a)) => Some(
            a.iter()
                .map(|c| {
                    c.as_str()
                        .ok_or_else(|| "non-string CIDR".to_string())
                        .and_then(Cidr::parse)
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Some(_) => return Err("allowed_source_cidrs must be an array".into()),
    };
    Ok(Account {
        login: login.to_string(),
        tenant,
        subject_key,
        principal_type,
        sub,
        home: Home { bucket, prefix },
        authorized_keys,
        certificate_authorities,
        allowed_source_cidrs,
    })
}

/// Memoizes the parsed [`Directory`] per bundle revision, so a steady-state operation's
/// credential re-check costs one string compare.
#[derive(Default)]
pub struct DirectoryCache {
    current: Mutex<Option<Arc<Directory>>>,
}

impl DirectoryCache {
    pub fn get(&self, bundle: &Bundle) -> Arc<Directory> {
        let mut g = self.current.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(d) = g.as_ref()
            && d.revision == bundle.revision
        {
            return d.clone();
        }
        let d = Arc::new(Directory::from_bundle(bundle));
        *g = Some(d.clone());
        d
    }
}

/// `BTreeMap` for deterministic iteration in tests.
#[allow(dead_code)]
type Ordered<K, V> = BTreeMap<K, V>;

#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::PrivateKey;
    use russh::keys::ssh_key;
    use ssh_key::certificate::Builder;

    fn ed25519() -> PrivateKey {
        PrivateKey::random(&mut rand_core(), Algorithm::Ed25519).unwrap()
    }

    /// A deterministic-enough RNG for key generation in tests.
    fn rand_core() -> impl ssh_key::rand_core::CryptoRng {
        TestRng(uuid::Uuid::new_v4().as_u128())
    }

    struct TestRng(u128);
    impl ssh_key::rand_core::TryRng for TestRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.try_next_u64()? as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            self.0 = self
                .0
                .wrapping_mul(0x2360_ed05_1fc6_5da4_4385_df64_9fcc_f645)
                .wrapping_add(0x5851_f42d_4c95_7f2d_1405_7b7e_f767_814f);
            Ok((self.0 >> 64) as u64 ^ uuid::Uuid::new_v4().as_u128() as u64)
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for c in dst.chunks_mut(8) {
                let v = self.try_next_u64()?.to_le_bytes();
                c.copy_from_slice(&v[..c.len()]);
            }
            Ok(())
        }
    }
    impl ssh_key::rand_core::TryCryptoRng for TestRng {}

    fn bundle(sftp: serde_json::Value, module: bool) -> Bundle {
        let key = if module {
            "sa:partner-drop"
        } else {
            "partner-drop"
        };
        Bundle::new(
            "rev-1",
            serde_json::json!({
                "sftp": sftp,
                "tenants": { "acme": { "user_attributes": { key: { "groups": ["drops"], "attributes": {} } } } }
            }),
        )
        .with_policy_module(module)
    }

    fn section(fp: &str, extra: serde_json::Value) -> serde_json::Value {
        let mut acct = serde_json::json!({
            "tenant": "acme",
            "subject_key": "sa:partner-drop",
            "home": { "bucket": "inbound", "prefix": "partner-x/" },
            "authorized_keys": [ { "key_type": "ssh-ed25519", "fingerprint": fp } ]
        });
        if let (Some(a), Some(e)) = (acct.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                a.insert(k.clone(), v.clone());
            }
        }
        serde_json::json!({ "version": 1, "accounts": { "acme-partner-drop": acct } })
    }

    fn ip() -> IpAddr {
        "203.0.113.10".parse().unwrap()
    }

    #[test]
    fn logins_follow_the_grammar() {
        assert!(login_is_valid("acme-partner-drop"));
        assert!(login_is_valid("a.b_c-1"));
        for bad in ["", "Acme", "-a", "a@b", "a:b", &"a".repeat(65)] {
            assert!(!login_is_valid(bad), "{bad}");
        }
    }

    #[test]
    fn a_listed_key_authenticates_in_both_key_spaces() {
        let k = ed25519();
        let fp = fingerprint(k.public_key().key_data());
        for module in [true, false] {
            let dir = Directory::from_bundle(&bundle(section(&fp, serde_json::json!({})), module));
            let a = dir
                .authenticate(
                    "acme-partner-drop",
                    &Credential::PublicKey {
                        key: k.public_key().key_data().clone(),
                    },
                    ip(),
                    0,
                )
                .unwrap_or_else(|e| panic!("module={module}: {e}"));
            assert_eq!(a.account.sub, "partner-drop");
            assert_eq!(a.account.principal_type, PrincipalType::ServiceAccount);
            assert_eq!(a.groups, ["drops"]);
        }
    }

    #[test]
    fn every_degenerate_bundle_rejects_every_login() {
        let k = ed25519();
        let fp = fingerprint(k.public_key().key_data());
        let cred = Credential::PublicKey {
            key: k.public_key().key_data().clone(),
        };
        let none = Bundle::new("r", serde_json::json!({}));
        assert!(
            Directory::from_bundle(&none)
                .authenticate("acme-partner-drop", &cred, ip(), 0)
                .is_err()
        );
        let mut wrong = section(&fp, serde_json::json!({}));
        wrong["version"] = serde_json::json!(2);
        assert!(
            Directory::from_bundle(&bundle(wrong, true))
                .authenticate("acme-partner-drop", &cred, ip(), 0)
                .is_err()
        );
        let mut old = bundle(section(&fp, serde_json::json!({})), true);
        old.data["grant_schema_version"] = serde_json::json!(2);
        assert!(
            Directory::from_bundle(&old)
                .authenticate("acme-partner-drop", &cred, ip(), 0)
                .is_err()
        );
        let mut v3 = bundle(section(&fp, serde_json::json!({})), true);
        v3.data["grant_schema_version"] = serde_json::json!(3);
        assert!(
            Directory::from_bundle(&v3)
                .authenticate("acme-partner-drop", &cred, ip(), 0)
                .is_ok()
        );
    }

    #[test]
    fn a_non_terminated_prefix_rejects_that_account_only() {
        let k = ed25519();
        let fp = fingerprint(k.public_key().key_data());
        let s = section(
            &fp,
            serde_json::json!({ "home": { "bucket": "inbound", "prefix": "partner-x" } }),
        );
        let dir = Directory::from_bundle(&bundle(s, true));
        assert!(dir.gate().is_ok());
        assert!(dir.accounts.is_empty());
    }

    #[test]
    fn source_cidrs_absent_means_unrestricted_and_empty_means_nothing() {
        let k = ed25519();
        let fp = fingerprint(k.public_key().key_data());
        let cred = Credential::PublicKey {
            key: k.public_key().key_data().clone(),
        };
        let only = Directory::from_bundle(&bundle(
            section(
                &fp,
                serde_json::json!({ "allowed_source_cidrs": ["198.51.100.0/24"] }),
            ),
            true,
        ));
        assert!(
            only.authenticate("acme-partner-drop", &cred, ip(), 0)
                .is_err()
        );
        let empty = Directory::from_bundle(&bundle(
            section(&fp, serde_json::json!({ "allowed_source_cidrs": [] })),
            true,
        ));
        assert!(
            empty
                .authenticate("acme-partner-drop", &cred, ip(), 0)
                .is_err()
        );
    }

    #[test]
    fn a_non_member_subject_cannot_log_in() {
        let k = ed25519();
        let fp = fingerprint(k.public_key().key_data());
        let mut b = bundle(section(&fp, serde_json::json!({})), true);
        b.data["tenants"]["acme"]["user_attributes"] = serde_json::json!({});
        let dir = Directory::from_bundle(&b);
        let e = dir
            .authenticate(
                "acme-partner-drop",
                &Credential::PublicKey {
                    key: k.public_key().key_data().clone(),
                },
                ip(),
                0,
            )
            .unwrap_err();
        assert!(e.contains("not a member"), "{e}");
    }

    fn cert(
        ca: &PrivateKey,
        user: &PrivateKey,
        principals: &[&str],
        serial: u64,
        key_id: &str,
        options: &[(&str, &str)],
    ) -> Certificate {
        let mut b = Builder::new_with_random_nonce(
            &mut rand_core(),
            user.public_key().key_data().clone(),
            0,
            u64::MAX - 1,
        )
        .unwrap();
        b.serial(serial).unwrap();
        b.key_id(key_id).unwrap();
        b.cert_type(CertType::User).unwrap();
        if principals.is_empty() {
            b.all_principals_valid().unwrap();
        }
        for p in principals {
            b.valid_principal(*p).unwrap();
        }
        for (k, v) in options {
            b.critical_option(*k, *v).unwrap();
        }
        b.sign(ca).unwrap()
    }

    fn ca_bundle(ca: &PrivateKey, tenants: serde_json::Value) -> Bundle {
        let mut s = section(
            "SHA256:none",
            serde_json::json!({ "certificate_authorities": ["partner-ca"] }),
        );
        s["user_cas"] = serde_json::json!({
            "partner-ca": {
                "key_type": "ssh-ed25519",
                "fingerprint": fingerprint(ca.public_key().key_data()),
                "tenants": tenants,
                "revoked_serials": [17],
                "revoked_key_ids": ["mallory@example.org"]
            }
        });
        bundle(s, true)
    }

    #[test]
    fn the_certificate_mapping_holds_rule_by_rule() {
        let ca = ed25519();
        let user = ed25519();
        let dir = Directory::from_bundle(&ca_bundle(&ca, serde_json::json!(["acme"])));
        let try_cert = |c: Certificate| {
            dir.authenticate(
                "acme-partner-drop",
                &Credential::Certificate { cert: Box::new(c) },
                ip(),
                1_000,
            )
        };
        let ok = try_cert(cert(
            &ca,
            &user,
            &["acme-partner-drop"],
            42,
            "alice@example.org",
            &[],
        ))
        .unwrap();
        let info = ok.auth.cert.unwrap();
        assert_eq!(
            (info.key_id.as_str(), info.serial, info.ca.as_str()),
            ("alice@example.org", 42, "partner-ca")
        );

        assert!(
            try_cert(cert(&ca, &user, &[], 1, "a", &[]))
                .unwrap_err()
                .contains("empty principals")
        );
        assert!(try_cert(cert(&ca, &user, &["someone-else"], 1, "a", &[])).is_err());
        assert!(
            try_cert(cert(&ca, &user, &["acme-partner-drop"], 17, "a", &[]))
                .unwrap_err()
                .contains("revoked")
        );
        assert!(
            try_cert(cert(
                &ca,
                &user,
                &["acme-partner-drop"],
                1,
                "mallory@example.org",
                &[]
            ))
            .unwrap_err()
            .contains("revoked")
        );
        assert!(
            try_cert(cert(
                &ca,
                &user,
                &["acme-partner-drop"],
                1,
                "a",
                &[("permit-pty", "")]
            ))
            .unwrap_err()
            .contains("critical option")
        );
        assert!(
            try_cert(cert(
                &ca,
                &user,
                &["acme-partner-drop"],
                1,
                "a",
                &[("force-command", "/bin/sh")]
            ))
            .is_err()
        );
        assert!(
            try_cert(cert(
                &ca,
                &user,
                &["acme-partner-drop"],
                1,
                "a",
                &[("force-command", "internal-sftp")]
            ))
            .is_ok()
        );
        assert!(
            try_cert(cert(
                &ca,
                &user,
                &["acme-partner-drop"],
                1,
                "a",
                &[("source-address", "198.51.100.0/24")]
            ))
            .is_err()
        );
        assert!(
            try_cert(cert(
                &ca,
                &user,
                &["acme-partner-drop"],
                1,
                "a",
                &[("source-address", "203.0.113.0/24")]
            ))
            .is_ok()
        );

        let other_ca = ed25519();
        assert!(
            try_cert(cert(&other_ca, &user, &["acme-partner-drop"], 1, "a", &[]))
                .unwrap_err()
                .contains("not trusted")
        );
    }

    #[test]
    fn a_foreign_tenant_ca_cannot_vouch() {
        let ca = ed25519();
        let user = ed25519();
        let dir = Directory::from_bundle(&ca_bundle(&ca, serde_json::json!(["globex"])));
        let e = dir
            .authenticate(
                "acme-partner-drop",
                &Credential::Certificate {
                    cert: Box::new(cert(&ca, &user, &["acme-partner-drop"], 1, "a", &[])),
                },
                ip(),
                1_000,
            )
            .unwrap_err();
        assert!(e.contains("not scoped"), "{e}");
        let wildcard = Directory::from_bundle(&ca_bundle(&ca, serde_json::json!(["*"])));
        assert!(
            wildcard
                .authenticate(
                    "acme-partner-drop",
                    &Credential::Certificate {
                        cert: Box::new(cert(&ca, &user, &["acme-partner-drop"], 1, "a", &[])),
                    },
                    ip(),
                    1_000,
                )
                .is_ok()
        );
    }
}
