//! Long-lived **per-principal** S3 keys — the migration path for
//! the five consumers that hold the per-harbor tenant-owner credential today.
//!
//! This is **not a new credential type**. It is the shape the platform already runs on —
//! two fields in a Secret, no refresh loop — with the blast radius cut from "every bucket
//! in the tenant" to "one principal's grants". The analogue is a **GCP HMAC key** or an
//! **AWS IAM user access key**: a long-lived S3 credential that is an *identity*, whose
//! permissions live outside it and are evaluated per request.
//!
//! ## The property that makes it safe
//!
//! **The key carries identity, never scope.** Groups and grants stay in the policy
//! bundle, so a grant change lands at normal bundle latency without reissuing anything,
//! and live revocation — invariant #1 of this project — is preserved. Baking permissions
//! into the credential was rejected once already: RGW session policies were killed
//! for exactly this reason, and F21 records the decision.
//!
//! ## The property that makes it multi-replica-correct
//!
//! Nothing is stored. Both halves are **derived** from the access-key id, exactly as
//! [`crate::auth::sts`] derives a session secret, so a key minted against one pod
//! verifies on any other and a pod restart changes nothing.
//!
//! ```text
//! access_key_id = HFSA<kid>.<payload>.<mac>
//!         payload = base64url_nopad( ver ‖ typ ‖ epoch ‖ len(tenant) ‖ tenant ‖ sub )
//!         mac     = base64url_nopad( HMAC-SHA256(k[kid], DOMAIN_ID ‖ 0 ‖ kid ‖ 0 ‖ payload)[..16] )
//!   secret_access_key = hex( HMAC-SHA256(k[kid], DOMAIN_SECRET ‖ 0 ‖ kid ‖ 0 ‖ access_key_id) )
//! ```
//!
//! ## THE CROSS-REPO CONTRACT — read this before changing a single byte above
//!
//! hyperfluid mints these keys (F17b); s0 verifies them. The two repos must agree on the
//! encoding **byte for byte**, and there is no negotiation and no version handshake on
//! the wire — a mismatch is a credential that simply does not authenticate. That failure
//! already happened once on this project, on the OPA entrypoint, and it cost 35 green
//! tests over a deny-all production policy. So:
//!
//! * [`DerivedKeyAuthority::mint`] is the **only** sanctioned constructor. The platform
//!   half must produce byte-identical output; the test
//!   `the_wire_format_is_pinned_byte_for_byte` holds a golden vector (fixed key, fixed
//!   inputs, exact strings) that either repo can replay to prove agreement.
//! * The field order, the version byte, the domain-separation tags, the MAC truncation
//!   length and the base64url alphabet are all part of the contract. Changing any of them
//!   is a new `ver` byte, never an edit of version 1.
//! * The MAC is computed over the **encoded payload text**, not over the decoded bytes.
//!   That makes the minted string the only string that verifies: there is no re-encoding
//!   a peer could do that would still check out.
//!
//! **`sub` is the RAW subject, never the bundle's prefixed spelling.** For a service
//! account it is the client id (`trino-background`), for a user the OIDC sub — *not*
//! `sa:trino-background` and not `user:<sub>`. The `sa:` / `user:` prefix is composed on
//! the way out by [`crate::pdp::principal_subject_key`], and a minter that bakes it in
//! produces a key that authenticates and is then denied everything, because every
//! bundle lookup goes looking for `sa:sa:trino-background`. This is the easiest mistake
//! for the platform half to make and the hardest to read off a 403, so the golden vector
//! below deliberately carries the raw spelling.
//!
//! **The golden vector, reproduced here so it can be read without running the test.**
//! Master key = 32 bytes of `0x07`, `kid = "k0"`, `tenant = "acme"`,
//! `sub = "trino-background"`, service account, `epoch = 1`:
//!
//! ```text
//! access_key_id     HFSAk0.AQEAAAABBGFjbWV0cmluby1iYWNrZ3JvdW5k.5WcSnIJ99Oc244wElX2Mag
//! secret_access_key 5b7b3cae116417cefaa08d94c85ee7285678bfaded3405183a908fe996e63d5f
//! ```
//!
//! Note what the payload decodes to, field by field:
//! `01` (ver) `01` (typ = service account) `00000001` (epoch, BE u32) `04` (len tenant)
//! `61636d65` (`acme`) `7472...` (`trino-background`, to the end).
//!
//! ## The alphabet, which is load-bearing outside this file
//!
//! Every character of a minted id is in `[A-Za-z0-9-_.]`:
//!
//! * `/` is **structurally excluded** — it delimits the SigV4 credential scope, so an id
//!   containing one is refused by s3s before it reaches us (and AWS would refuse it too).
//! * `'` and `\` are excluded, and that one is not cosmetic: hyperfluid's operator
//!   interpolates `s3.aws-access-key` into a Trino `CREATE CATALOG … WITH (k = '<value>')`
//!   SQL literal escaping only the single quote
//!   (`hf_bin_operator/src/infrastructure/catalog/mod.rs:160`). base64url plus `.` is
//!   safe; one alphabet change away it would not be.
//!
//! Pinned by `a_minted_id_stays_inside_the_alphabet_every_consumer_tolerates`.
//!
//! ## Revocation — see [`crate::auth::DerivedKeys`]
//!
//! A derived key cannot be deleted, because there is nothing to delete. The `epoch` field
//! above is where revocation lives: the bundle publishes a floor and a key naming a lower
//! one stops working at the next bundle refresh. The check is not in this file — this file
//! is arithmetic on a string — it is in [`crate::auth::DerivedKeys::admit`], which is the
//! only path the gateway calls.
//!
//! ## Rotation
//!
//! The `kid` works exactly as it does for STS: add a key, point `current_kid` at it, and
//! outstanding keys keep verifying under the old entry until it is deleted. Unlike an STS
//! session there is no TTL after which stragglers are gone, so retiring a `kid` is a
//! **fleet-wide revocation** of everything minted under it and must be paired with
//! reissuing those keys.

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::error::{GatewayError, Result};
use crate::model::PrincipalType;

type HmacSha256 = Hmac<Sha256>;

/// Access-key ids for derived long-lived keys carry this prefix.
///
/// **It differs from [`crate::auth::sts::STS_PREFIX`] (`HFST`) in the fourth character
/// only**, which is deliberate (both are "HF S3 …") and is exactly why the namespace
/// guard is enforced in two places rather than one — see
/// [`DerivedKeyAuthority::is_derived_access_key`].
pub const DERIVED_PREFIX: &str = "HFSA";

/// Separates the three fields of a derived access-key id: `HFSA<kid>.<payload>.<mac>`.
///
/// Neither the `kid` (rejected in [`validate_derived_kid`]) nor the payload nor the MAC
/// (base64url) can contain it, so the decomposition is unambiguous. Parsing splits on the
/// **last** occurrence for the MAC and the **first** for the kid, so it stays robust even
/// if a future payload alphabet widened.
pub const FIELD_SEP: char = '.';

/// The `kid` a single-key configuration is filed under — the same spelling
/// [`crate::auth::sts::DEFAULT_KID`] uses, so an operator reading two config sections
/// does not have to learn two conventions.
pub const DEFAULT_KID: &str = "k0";

/// Payload format version. A change to the field order, the widths or the meaning of any
/// field is a **new version**, never an edit of this one: the platform mints and s0
/// verifies out of two separate repos, and a silently redefined field is a credential
/// that resolves to the wrong principal rather than one that fails.
pub const PAYLOAD_VERSION: u8 = 1;

/// Bytes of HMAC-SHA256 kept as the id's MAC. 128 bits, base64url'd to 22 characters.
///
/// Truncation is the standard construction (RFC 2104 §5); 128 bits is far beyond what an
/// online forgery attempt against a gateway can reach, and the alternative — a full
/// 256-bit tag — costs 22 more characters on every access-key id, which is 22 more bytes
/// on every audit record (see the length note below).
pub const MAC_LEN: usize = 16;

/// Hard cap on the whole access-key id.
///
/// No client-side ceiling was found: ten SDK stacks (boto3, aws-cli v2, mc, rclone,
/// aws-sdk-go v1/v2, aws-sdk-s3 Rust, AWS SDK for Java v1/v2 and Trino's own
/// `trino-filesystem-s3`) all returned 200 on ids up to 16 KiB. So the cap is not an
/// interoperability limit; it bounds what an **unauthenticated** caller can write into
/// the audit stream.
///
/// `audit::GateContext` copies the presented access-key id into every
/// gate record, and a gate record is written precisely when a request is *refused*
/// before it becomes a policy question — which anyone who can reach the socket can
/// trigger, with an id they chose. Measured here: a real `identity_rejected` record
/// carrying a 66-character id is 549 bytes. Gate denials are already rate-limited
/// (`suppressed_since_last`), so this is a second bound rather than the only one.
///
/// Note for the register: an **allowed** request records no access-key id at all — the
/// decision record identifies the principal, not the credential — so the cap is not
/// about steady-state audit volume on the happy path.
pub const MAX_ACCESS_KEY_ID_LEN: usize = 1024;

/// The tenant is length-prefixed with a single byte, so it cannot exceed this. The mint
/// **refuses**, naming the field; it never truncates — two principals sharing a truncated
/// id would share a credential.
pub const MAX_TENANT_LEN: usize = 255;

/// Domain-separation tag for the id's MAC.
///
/// The two derivations below use the **same** ring entry, so they must be separated by
/// construction rather than by the improbability of a collision: without a tag, a message
/// crafted for one could be a message for the other, and the MAC that proves an identity
/// would be a secret that authenticates it. Distinct lengths plus a `0x00` terminator make
/// the two message spaces disjoint.
const DOMAIN_ID: &[u8] = b"s0-derived-key-id-v1";

/// Domain-separation tag for the secret. See [`DOMAIN_ID`].
const DOMAIN_SECRET: &[u8] = b"s0-derived-key-secret-v1";

/// `typ` byte for a human principal.
const TYP_USER: u8 = 0;
/// `typ` byte for a service account — which is what F18's five consumers are.
const TYP_SERVICE_ACCOUNT: u8 = 1;

/// The three fields of a derived access-key id, before anything inside them is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DerivedKeyId<'a> {
    /// Which master key minted this id.
    pub kid: &'a str,
    /// The encoded identity payload — **opaque until the MAC verifies**.
    pub payload: &'a str,
    /// The truncated MAC over `DOMAIN_ID ‖ 0 ‖ kid ‖ 0 ‖ payload`.
    pub mac: &'a str,
}

/// What a verified derived key asserts about its holder.
///
/// Note what is **not** here: no organization (that comes from the gateway's own
/// tenant→org table, never from the credential — see [`crate::auth::DerivedKeys`]), no
/// groups and no grants (both live in the bundle and are read live), no scope and no
/// expiry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedPrincipal {
    pub tenant: String,
    pub sub: String,
    pub principal_type: PrincipalType,
    /// The key-epoch this key was minted at. Revocation compares it against the floor the
    /// bundle publishes; see [`crate::auth::DerivedKeys`].
    pub key_epoch: u32,
}

/// The two fields a consumer puts in its Secret. Both halves, once, at mint time —
/// nothing is stored, so there is no second chance to read the secret.
#[derive(Debug, Clone)]
pub struct DerivedKeyCredential {
    pub access_key_id: String,
    /// Hex-encoded HMAC-SHA256, like an STS session secret.
    pub secret_access_key: String,
}

/// Holds the ring that mints and verifies derived keys.
///
/// **A ring of its own, not the STS ring.** The two credential classes have different
/// lifetimes (one hour vs. indefinite) and different revocation stories, and
/// `GatewayConfig::validate` refuses a configuration that files the same key bytes under
/// both — so compromise of one class's material cannot forge the other's.
#[derive(Clone)]
pub struct DerivedKeyAuthority {
    /// `kid -> key`. Every entry can *verify*; only `current_kid` mints.
    master_keys: BTreeMap<String, Vec<u8>>,
    current_kid: String,
}

impl DerivedKeyAuthority {
    /// Single-key convenience: a one-entry ring under [`DEFAULT_KID`].
    pub fn new(master_key: Vec<u8>) -> Result<Self> {
        Self::with_key_ring(
            BTreeMap::from([(DEFAULT_KID.to_string(), master_key)]),
            DEFAULT_KID,
        )
    }

    /// Build from a full key ring. `current_kid` must name an entry — minting under a key
    /// the operator did not choose is worse than refusing to start.
    pub fn with_key_ring(
        master_keys: BTreeMap<String, Vec<u8>>,
        current_kid: &str,
    ) -> Result<Self> {
        if master_keys.is_empty() {
            return Err(GatewayError::Credentials(
                "derived-key master key ring is empty".into(),
            ));
        }
        for (kid, key) in &master_keys {
            validate_derived_kid(kid)?;
            if key.len() < 32 {
                return Err(GatewayError::Credentials(format!(
                    "derived-key master keys must be >= 32 bytes (key {kid} is {})",
                    key.len()
                )));
            }
        }
        if !master_keys.contains_key(current_kid) {
            return Err(GatewayError::Credentials(format!(
                "derived_keys current_kid {current_kid:?} is not in the master key ring"
            )));
        }
        Ok(DerivedKeyAuthority {
            master_keys,
            current_kid: current_kid.to_string(),
        })
    }

    /// The `kid` new keys are minted under.
    pub fn current_kid(&self) -> &str {
        &self.current_kid
    }

    /// The key ids this authority can still verify. Exposed so an operator (and a test)
    /// can see what a rotation has actually retired.
    pub fn key_ids(&self) -> Vec<&str> {
        self.master_keys.keys().map(String::as_str).collect()
    }

    /// Does this access-key id claim to be a derived long-lived key?
    ///
    /// **Deliberately a prefix test and deliberately separate from
    /// [`Self::parse_access_key`]**, for the same reason
    /// [`crate::auth::sts::StsAuthority::is_sts_access_key`] is: an id carrying the prefix
    /// but not decomposing is a *malformed derived credential*, not a static one, and it
    /// must never fall through to the static credential store — where a colliding entry
    /// would shadow the whole namespace. `GatewayConfig::validate` refuses such entries at
    /// load; this makes the property hold even for a store built some other way.
    pub fn is_derived_access_key(access_key_id: &str) -> bool {
        access_key_id.starts_with(DERIVED_PREFIX)
    }

    /// Split an id into its three fields, if it is one of ours and well formed. Trusts
    /// **nothing** inside them — this is string surgery, not verification.
    pub fn parse_access_key(access_key_id: &str) -> Option<DerivedKeyId<'_>> {
        // Length first: an oversized id is refused before any work is done on it.
        if access_key_id.len() > MAX_ACCESS_KEY_ID_LEN {
            return None;
        }
        let rest = access_key_id.strip_prefix(DERIVED_PREFIX)?;
        // The MAC is taken from the LAST separator and the kid from the FIRST, so the
        // decomposition survives a payload alphabet that ever grew a `.`.
        let (head, mac) = rest.rsplit_once(FIELD_SEP)?;
        let (kid, payload) = head.split_once(FIELD_SEP)?;
        (!kid.is_empty() && !payload.is_empty() && !mac.is_empty()).then_some(DerivedKeyId {
            kid,
            payload,
            mac,
        })
    }

    /// **The verification gate.** Check the MAC, and only then decode the payload.
    ///
    /// Every failure — unknown prefix shape, retired `kid`, bad MAC, malformed payload,
    /// unknown version — answers the same `None`, so a forged id is indistinguishable
    /// from an unknown one to the caller.
    ///
    /// The ordering is the whole point: nothing inside the payload is looked at, let
    /// alone believed, until the MAC over the payload has checked out against the key the
    /// `kid` selects. A caller that decoded first would be reading attacker-chosen tenant
    /// and subject strings.
    pub fn verify(&self, access_key_id: &str) -> Option<DerivedPrincipal> {
        let id = Self::parse_access_key(access_key_id)?;
        let key = self.master_keys.get(id.kid)?;
        let tag = B64.decode(id.mac).ok()?;
        if tag.len() != MAC_LEN {
            return None;
        }
        // Constant-time, and length-checked above so a truncated tag cannot verify a
        // prefix of the real one.
        id_mac(key, id.kid, id.payload)
            .verify_truncated_left(&tag)
            .ok()?;
        decode_payload(id.payload)
    }

    /// `secret = hex(HMAC-SHA256(k[kid], DOMAIN_SECRET ‖ 0 ‖ kid ‖ 0 ‖ access_key_id))`.
    ///
    /// **Verifies the MAC first.** Deriving a secret for an unverified id would be
    /// harmless in itself (the holder could not know it), but it would answer
    /// `SignatureDoesNotMatch` where an unknown key answers `InvalidAccessKeyId` — and
    /// that difference is an oracle telling a prober which of their forgeries was
    /// structurally right.
    ///
    /// **Hot-path cost, stated because this runs per S3 request:** re-verifying rather
    /// than trusting an earlier `verify` in the same request costs one extra
    /// HMAC-SHA256 over ~100 bytes, against the four HMACs SigV4 itself performs plus a
    /// SHA-256 of the payload. Not worth a `_unchecked` variant that a future caller
    /// could reach for by mistake.
    pub fn secret_for_access_key(&self, access_key_id: &str) -> Option<String> {
        let id = Self::parse_access_key(access_key_id)?;
        self.verify(access_key_id)?;
        let key = self.master_keys.get(id.kid)?;
        Some(hex::encode(
            secret_mac(key, id.kid, access_key_id)
                .finalize()
                .into_bytes(),
        ))
    }

    /// **The helper the platform half (F17b) needs, and the contract it must match.**
    ///
    /// Mints under `current_kid`. `epoch` is the tenant's current key epoch, which the
    /// minter reads from the same place the gateway reads its floor — see
    /// [`crate::auth::DerivedKeys`]. Returns both halves once; nothing is stored.
    ///
    /// Every refusal names the field, and nothing is ever truncated: two principals
    /// sharing a truncated id would share a credential.
    pub fn mint(&self, principal: &DerivedPrincipal) -> Result<DerivedKeyCredential> {
        let payload = encode_payload(principal)?;
        let key = self
            .master_keys
            .get(&self.current_kid)
            .ok_or_else(|| GatewayError::Credentials("current_kid is not in the ring".into()))?;
        let mac = id_mac(key, &self.current_kid, &payload)
            .finalize()
            .into_bytes();
        let access_key_id = format!(
            "{DERIVED_PREFIX}{}{FIELD_SEP}{payload}{FIELD_SEP}{}",
            self.current_kid,
            B64.encode(&mac[..MAC_LEN]),
        );
        if access_key_id.len() > MAX_ACCESS_KEY_ID_LEN {
            return Err(GatewayError::Credentials(format!(
                "derived access-key id would be {} characters, over the {MAX_ACCESS_KEY_ID_LEN} \
                 cap; shorten `sub` (currently {} bytes) — it is never truncated, because two \
                 principals sharing a truncated id would share a credential",
                access_key_id.len(),
                principal.sub.len()
            )));
        }
        let secret_access_key = hex::encode(
            secret_mac(key, &self.current_kid, &access_key_id)
                .finalize()
                .into_bytes(),
        );
        Ok(DerivedKeyCredential {
            access_key_id,
            secret_access_key,
        })
    }
}

/// `HMAC(k, DOMAIN_ID ‖ 0 ‖ kid ‖ 0 ‖ payload)`, returned unfinalized so the caller can
/// either finalize it (minting) or verify against it in constant time (the hot path).
///
/// The `kid` is inside the message as well as selecting the key, for the reason
/// `sts::derive_secret` gives: an operator who files the same bytes under two ids then
/// gets two distinct MAC spaces, which keeps "retire the old kid" a real revocation.
fn id_mac(key: &[u8], kid: &str, payload: &str) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(DOMAIN_ID);
    mac.update(&[0u8]);
    mac.update(kid.as_bytes());
    mac.update(&[0u8]);
    mac.update(payload.as_bytes());
    mac
}

/// `HMAC(k, DOMAIN_SECRET ‖ 0 ‖ kid ‖ 0 ‖ access_key_id)`. See [`id_mac`].
fn secret_mac(key: &[u8], kid: &str, access_key_id: &str) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(DOMAIN_SECRET);
    mac.update(&[0u8]);
    mac.update(kid.as_bytes());
    mac.update(&[0u8]);
    mac.update(access_key_id.as_bytes());
    mac
}

/// `ver ‖ typ ‖ epoch(BE u32) ‖ len(tenant) ‖ tenant ‖ sub`, base64url without padding.
///
/// The tenant is length-prefixed and the subject takes the remainder, so neither needs an
/// escape and neither can be confused for the other — the delimiter-injection shape, on a
/// credential, is what this avoids.
fn encode_payload(p: &DerivedPrincipal) -> Result<String> {
    if p.tenant.is_empty() {
        return Err(GatewayError::Credentials(
            "derived key: `tenant` must be non-empty".into(),
        ));
    }
    if p.tenant.len() > MAX_TENANT_LEN {
        return Err(GatewayError::Credentials(format!(
            "derived key: `tenant` is {} bytes, over the {MAX_TENANT_LEN}-byte cap the \
             one-byte length prefix allows",
            p.tenant.len()
        )));
    }
    if p.sub.is_empty() {
        return Err(GatewayError::Credentials(
            "derived key: `sub` must be non-empty".into(),
        ));
    }
    let mut buf = Vec::with_capacity(7 + p.tenant.len() + p.sub.len());
    buf.push(PAYLOAD_VERSION);
    buf.push(match p.principal_type {
        PrincipalType::User => TYP_USER,
        PrincipalType::ServiceAccount => TYP_SERVICE_ACCOUNT,
    });
    buf.extend_from_slice(&p.key_epoch.to_be_bytes());
    buf.push(p.tenant.len() as u8);
    buf.extend_from_slice(p.tenant.as_bytes());
    buf.extend_from_slice(p.sub.as_bytes());
    Ok(B64.encode(&buf))
}

/// The inverse of [`encode_payload`]. **Only ever called after the MAC has verified.**
///
/// Every malformed shape answers `None` rather than a default: an unknown version, a
/// truncated buffer, a length prefix that overruns, a tenant or subject that is not UTF-8,
/// an empty subject. A credential is not a place to be lenient.
fn decode_payload(payload: &str) -> Option<DerivedPrincipal> {
    let bytes = B64.decode(payload).ok()?;
    // ver + typ + epoch(4) + tenant_len
    if bytes.len() < 7 {
        return None;
    }
    if bytes[0] != PAYLOAD_VERSION {
        return None;
    }
    let principal_type = match bytes[1] {
        TYP_USER => PrincipalType::User,
        TYP_SERVICE_ACCOUNT => PrincipalType::ServiceAccount,
        _ => return None,
    };
    let key_epoch = u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
    let tenant_len = bytes[6] as usize;
    let tenant_end = 7usize.checked_add(tenant_len)?;
    if bytes.len() <= tenant_end {
        // `<=`, not `<`: a zero-length subject is as malformed as a truncated buffer.
        return None;
    }
    let tenant = std::str::from_utf8(&bytes[7..tenant_end]).ok()?;
    let sub = std::str::from_utf8(&bytes[tenant_end..]).ok()?;
    if tenant.is_empty() || sub.is_empty() {
        return None;
    }
    Some(DerivedPrincipal {
        tenant: tenant.to_string(),
        sub: sub.to_string(),
        principal_type,
        key_epoch,
    })
}

/// A `kid` becomes part of an access-key id, so it must keep that id decomposable and
/// keep the id inside the alphabet every consumer tolerates. The rule is
/// [`crate::auth::sts::kid_is_well_formed`] — the same one the STS ring uses, shared
/// rather than restated so the two namespaces cannot drift apart.
pub fn validate_derived_kid(kid: &str) -> Result<()> {
    if crate::auth::sts::kid_is_well_formed(kid) {
        return Ok(());
    }
    Err(GatewayError::Credentials(format!(
        "derived-key id {kid:?} must be non-empty ASCII alphanumeric, '-' or '_' \
         (it becomes part of the access-key id {DERIVED_PREFIX}<kid>{FIELD_SEP}<payload>\
         {FIELD_SEP}<mac>)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authority() -> DerivedKeyAuthority {
        DerivedKeyAuthority::new(vec![7u8; 32]).unwrap()
    }

    fn principal() -> DerivedPrincipal {
        DerivedPrincipal {
            tenant: "acme".into(),
            // The RAW client id. `sa:` is composed by `pdp::principal_subject_key` on the
            // way out — baking it in here would teach the platform half (F17b) to
            // double-prefix, and the vector is the thing it will copy.
            sub: "trino-background".into(),
            principal_type: PrincipalType::ServiceAccount,
            key_epoch: 1,
        }
    }

    /// **THE CROSS-REPO CONTRACT, as bytes rather than as prose.**
    ///
    /// hyperfluid's minter (F17b) must reproduce these two strings exactly from the same
    /// inputs. If this test is ever edited to match new output, the platform half has to
    /// be edited in the same breath — which is precisely the coupling the OPA-entrypoint
    /// incident showed we cannot leave to memory.
    const GOLDEN_SECRET: &str = "5b7b3cae116417cefaa08d94c85ee7285678bfaded3405183a908fe996e63d5f";

    #[test]
    fn the_wire_format_is_pinned_byte_for_byte() {
        // Key: 32 bytes of 0x07. kid: "k0". tenant "acme", sub "trino-background" (RAW,
        // unprefixed — see the module header), service account, epoch 1.
        //
        // Reproduced independently from the module documentation alone by a Python
        // implementation that never saw this code, which is the evidence that F17b can
        // be written from the spec rather than from a port of this file.
        let creds = authority().mint(&principal()).unwrap();
        assert_eq!(
            creds.access_key_id,
            "HFSAk0.AQEAAAABBGFjbWV0cmluby1iYWNrZ3JvdW5k.5WcSnIJ99Oc244wElX2Mag"
        );
        assert_eq!(creds.secret_access_key, GOLDEN_SECRET);
        // …and the gateway reads back exactly what was minted.
        assert_eq!(authority().verify(&creds.access_key_id), Some(principal()));
    }

    #[test]
    fn a_minted_key_round_trips_through_verification() {
        let a = authority();
        for p in [
            principal(),
            DerivedPrincipal {
                tenant: "default".into(),
                sub: "user:8bf0f2a2-0000-4000-8000-000000000000".into(),
                principal_type: PrincipalType::User,
                key_epoch: 0,
            },
            DerivedPrincipal {
                tenant: "t".repeat(MAX_TENANT_LEN),
                sub: "s".repeat(258), // iam_sa_client_id's VARCHAR(255) worst case
                principal_type: PrincipalType::ServiceAccount,
                key_epoch: u32::MAX,
            },
        ] {
            let creds = a.mint(&p).unwrap();
            assert_eq!(a.verify(&creds.access_key_id).as_ref(), Some(&p));
            assert_eq!(
                a.secret_for_access_key(&creds.access_key_id).as_deref(),
                Some(creds.secret_access_key.as_str()),
                "the hot-path derivation disagrees with the mint"
            );
            assert!(creds.access_key_id.len() <= MAX_ACCESS_KEY_ID_LEN);
        }
    }

    /// The property the whole design rests on: no store, so a second process holding the
    /// same key material answers identically. This is `F8`'s multi-replica question for
    /// the new credential class, answered by construction.
    #[test]
    fn a_second_instance_verifies_a_key_it_never_minted() {
        let minted = authority().mint(&principal()).unwrap();
        let other_pod = DerivedKeyAuthority::new(vec![7u8; 32]).unwrap();
        assert_eq!(other_pod.verify(&minted.access_key_id), Some(principal()));
        assert_eq!(
            other_pod
                .secret_for_access_key(&minted.access_key_id)
                .as_deref(),
            Some(minted.secret_access_key.as_str())
        );
    }

    #[test]
    fn a_forged_mac_is_refused_and_so_is_every_other_malformation() {
        let a = authority();
        let good = a.mint(&principal()).unwrap().access_key_id;
        let (head, mac) = good.rsplit_once(FIELD_SEP).unwrap();

        // Flip one character of the MAC.
        let flipped = format!(
            "{head}.{}{}",
            if mac.starts_with('A') { 'B' } else { 'A' },
            &mac[1..]
        );
        assert_ne!(flipped, good);
        assert_eq!(a.verify(&flipped), None);
        assert_eq!(a.secret_for_access_key(&flipped), None);

        // A payload edited to name another tenant, with the original MAC.
        let other = a
            .mint(&DerivedPrincipal {
                tenant: "victim".into(),
                ..principal()
            })
            .unwrap()
            .access_key_id;
        let other_payload = other.split(FIELD_SEP).nth(1).unwrap();
        let swapped = format!("HFSAk0.{other_payload}.{mac}");
        assert_eq!(
            a.verify(&swapped),
            None,
            "a payload swapped under someone else's MAC verified"
        );

        for bad in [
            DERIVED_PREFIX.to_string(),                     // bare prefix
            format!("{DERIVED_PREFIX}k0"),                  // no separators
            format!("{DERIVED_PREFIX}k0.payload"),          // one separator
            format!("{DERIVED_PREFIX}.payload.{mac}"),      // empty kid
            format!("{DERIVED_PREFIX}k0..{mac}"),           // empty payload
            format!("{head}."),                             // empty mac
            format!("{head}.{}", B64.encode([0u8; 16])),    // a valid-length wrong MAC
            format!("{head}.{}", B64.encode([0u8; 32])),    // right MAC, wrong length
            format!("{head}.not-base64!!"),                 // not decodable
            format!("{DERIVED_PREFIX}nokey.{}.{mac}", "x"), // a kid outside the ring
            format!(
                "{DERIVED_PREFIX}k0.{}.{mac}",
                "A".repeat(MAX_ACCESS_KEY_ID_LEN)
            ),
        ] {
            assert!(
                DerivedKeyAuthority::is_derived_access_key(&bad),
                "{bad} must still be claimed by the namespace"
            );
            assert_eq!(a.verify(&bad), None, "{bad}");
            assert_eq!(a.secret_for_access_key(&bad), None, "{bad}");
        }
        // Positive control.
        assert!(a.verify(&good).is_some());
    }

    /// A payload that decodes but does not mean what it says must be refused, and the
    /// MAC does not protect against this — the *minter* could be the one that is wrong,
    /// or the version could have moved on. So every field is re-checked after decoding.
    #[test]
    fn a_correctly_maced_but_malformed_payload_is_still_refused() {
        let a = authority();
        let sign = |bytes: &[u8]| {
            let payload = B64.encode(bytes);
            let mac = id_mac(&[7u8; 32], "k0", &payload).finalize().into_bytes();
            format!(
                "{DERIVED_PREFIX}k0{FIELD_SEP}{payload}{FIELD_SEP}{}",
                B64.encode(&mac[..MAC_LEN])
            )
        };
        for bytes in [
            vec![],                              // empty
            vec![1, 1, 0, 0, 0, 1],              // one byte short of a header
            vec![2, 1, 0, 0, 0, 1, 4, b'a'],     // unknown version
            vec![1, 9, 0, 0, 0, 1, 4, b'a'],     // unknown principal type
            vec![1, 1, 0, 0, 0, 1, 4, b'a'],     // tenant_len overruns the buffer
            vec![1, 1, 0, 0, 0, 1, 0, b'a'],     // zero-length tenant
            vec![1, 1, 0, 0, 0, 1, 1, b'a'],     // no subject at all
            vec![1, 1, 0, 0, 0, 1, 1, 0xff, 65], // tenant is not UTF-8
        ] {
            let id = sign(&bytes);
            assert_eq!(a.verify(&id), None, "{bytes:?}");
            assert_eq!(a.secret_for_access_key(&id), None, "{bytes:?}");
        }
    }

    /// Stage 1's alphabet finding, enforced rather than remembered. `/` breaks SigV4's
    /// credential scope; `'` and `\` break the operator's Trino `CREATE CATALOG` SQL
    /// literal, which escapes only the single quote.
    #[test]
    fn a_minted_id_stays_inside_the_alphabet_every_consumer_tolerates() {
        let a = authority();
        for p in [
            principal(),
            DerivedPrincipal {
                // A subject full of characters that would be trouble unencoded.
                sub: "sa:o'brien\\backslash/slash \"quote\"".into(),
                ..principal()
            },
        ] {
            let id = a.mint(&p).unwrap().access_key_id;
            assert!(
                id.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.'),
                "{id} left the [A-Za-z0-9-_.] alphabet"
            );
            // …and it still round-trips, so the encoding is what keeps it safe rather
            // than a restriction on who may hold a key.
            assert_eq!(a.verify(&id).as_ref(), Some(&p));
        }
    }

    #[test]
    fn the_mint_refuses_rather_than_truncates() {
        let a = authority();
        for (p, needle) in [
            (
                DerivedPrincipal {
                    tenant: String::new(),
                    ..principal()
                },
                "`tenant` must be non-empty",
            ),
            (
                DerivedPrincipal {
                    tenant: "t".repeat(MAX_TENANT_LEN + 1),
                    ..principal()
                },
                "over the 255-byte cap",
            ),
            (
                DerivedPrincipal {
                    sub: String::new(),
                    ..principal()
                },
                "`sub` must be non-empty",
            ),
            (
                DerivedPrincipal {
                    sub: "s".repeat(2000),
                    ..principal()
                },
                "over the 1024 cap",
            ),
        ] {
            let err = a.mint(&p).expect_err("must refuse");
            assert!(format!("{err}").contains(needle), "{err}");
        }
    }

    // ── rotation ────────────────────────────────────────────────────────────────

    #[test]
    fn a_key_minted_under_the_previous_kid_survives_the_rotation() {
        let before = DerivedKeyAuthority::with_key_ring(
            BTreeMap::from([("old".to_string(), vec![7u8; 32])]),
            "old",
        )
        .unwrap();
        let live = before.mint(&principal()).unwrap();

        let after = DerivedKeyAuthority::with_key_ring(
            BTreeMap::from([
                ("old".to_string(), vec![7u8; 32]),
                ("new".to_string(), vec![8u8; 32]),
            ]),
            "new",
        )
        .unwrap();
        assert_eq!(after.current_kid(), "new");
        assert_eq!(after.verify(&live.access_key_id), Some(principal()));
        assert_eq!(
            after.secret_for_access_key(&live.access_key_id).as_deref(),
            Some(live.secret_access_key.as_str())
        );
        assert!(
            after
                .mint(&principal())
                .unwrap()
                .access_key_id
                .starts_with("HFSAnew.")
        );

        // Retiring the entry is a revocation, on both halves.
        let retired = DerivedKeyAuthority::with_key_ring(
            BTreeMap::from([("new".to_string(), vec![8u8; 32])]),
            "new",
        )
        .unwrap();
        assert_eq!(retired.verify(&live.access_key_id), None);
        assert_eq!(retired.secret_for_access_key(&live.access_key_id), None);
    }

    #[test]
    fn the_same_key_bytes_under_two_ids_do_not_share_a_credential() {
        let a = DerivedKeyAuthority::with_key_ring(
            BTreeMap::from([
                ("k1".to_string(), vec![7u8; 32]),
                ("k2".to_string(), vec![7u8; 32]),
            ]),
            "k1",
        )
        .unwrap();
        let minted = a.mint(&principal()).unwrap();
        // Relabel the id onto the other ring entry, keeping payload and MAC.
        let relabelled = minted.access_key_id.replacen("HFSAk1.", "HFSAk2.", 1);
        assert_eq!(
            a.verify(&relabelled),
            None,
            "the kid is not inside the MAC message"
        );
    }

    #[test]
    fn a_ring_that_cannot_be_trusted_is_refused_at_construction() {
        let ok = || BTreeMap::from([("k1".to_string(), vec![7u8; 32])]);
        assert!(DerivedKeyAuthority::with_key_ring(BTreeMap::new(), "k1").is_err());
        assert!(DerivedKeyAuthority::with_key_ring(ok(), "k2").is_err());
        // A kid carrying the separator would split the id at the wrong place and select
        // a different key.
        assert!(
            DerivedKeyAuthority::with_key_ring(
                BTreeMap::from([("k.1".to_string(), vec![7u8; 32])]),
                "k.1"
            )
            .is_err()
        );
        assert!(
            DerivedKeyAuthority::with_key_ring(
                BTreeMap::from([
                    ("k1".to_string(), vec![7u8; 32]),
                    ("k2".to_string(), vec![7u8; 8])
                ]),
                "k1"
            )
            .is_err()
        );
        assert!(DerivedKeyAuthority::with_key_ring(ok(), "k1").is_ok());
    }

    /// The two namespaces differ in one character, so this is asserted rather than
    /// assumed: no id can be claimed by both authorities.
    #[test]
    fn the_derived_and_sts_namespaces_are_disjoint() {
        use crate::auth::sts::{STS_PREFIX, StsAuthority};
        assert_ne!(DERIVED_PREFIX, STS_PREFIX);
        assert_eq!(DERIVED_PREFIX.len(), STS_PREFIX.len());
        let derived = authority().mint(&principal()).unwrap().access_key_id;
        assert!(DerivedKeyAuthority::is_derived_access_key(&derived));
        assert!(!StsAuthority::is_sts_access_key(&derived));
        let sts = StsAuthority::access_key_id_for("k0", "sid-1");
        assert!(StsAuthority::is_sts_access_key(&sts));
        assert!(!DerivedKeyAuthority::is_derived_access_key(&sts));
    }
}
