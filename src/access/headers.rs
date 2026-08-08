//! The **riders**: the parts of an already-authorized write that confer access, install
//! ABAC-visible metadata, or defeat retention — and that the bucket+key hooks did not
//! look at until this module existed.
//!
//! ## The defect this closes
//!
//! `PutObject` was authorized on `(bucket, key)`. A request carrying
//! `x-amz-acl: public-read` passed that hook unchanged and the header rode through to
//! RGW, which made the object **world-readable**. The gateway's decision log recorded an
//! ordinary allowed write. The same hole existed on `CopyObject`,
//! `CreateMultipartUpload`, `PostObject` and (until 2026-08-08 re-denied it)
//! `CreateBucket`, plus three siblings nobody had looked at either: the five
//! `x-amz-grant-*` headers, `x-amz-tagging` on write, and
//! `x-amz-bypass-governance-retention` on the delete ops.
//!
//! For a product sold into hospitals and governments a silent public-exposure path is the
//! worst class of defect there is, so the handling here is deliberately blunter than the
//! rest of the gateway.
//!
//! ## DENY, not strip — and why
//!
//! The master plan offers a `strip_request_fields` obligation as an escape hatch (§2.3,
//! open question 6). **It is not implemented, and that is the recommendation, not an
//! omission.** `Obligations` carries `deny_unknown_fields`, so a policy that emits
//! `strip_request_fields` denies every request it touches — the correct behaviour for an
//! obligation this PEP will not apply.
//!
//! 1. **A strip makes the gateway lie.** The caller asked for an ACL, got `200 OK`, and
//!    does not have one. Nothing in the response says so. The failure surfaces months
//!    later as "the shared bucket stopped working", with no error anywhere to correlate
//!    against — which is the same shape as the bug being fixed, only inverted.
//! 2. **A deny is discoverable in one round trip.** 403 + a reason naming the header,
//!    plus a decision record. The operator's next step (grant the principal access in the
//!    console, or stop sending the header) is legible from the response.
//! 3. **A strip switch is the switch that gets flipped.** Open question 6 makes the
//!    argument itself: the first thing a frustrated operator does when `--acl private`
//!    403s is turn stripping on, and it then applies to every principal and every
//!    request, with the closed field set as the only remaining guard. An authorization
//!    boundary must not be a config value.
//! 4. **`PostObject` cannot be stripped correctly at all.** Its ACL is a *form field*
//!    covered by the signed POST policy document. Removing the field while forwarding
//!    the policy produces a policy/field mismatch at the backend — an opaque 403 from
//!    RGW instead of an honest one from the gateway.
//! 5. **The compatibility case that motivates stripping is `private`, and `private` is
//!    not a grant.** It is handled as [`NO_OP_CANNED_ACLS`] below: one const array, no
//!    switch, no obligation, no request rewriting.
//!
//! ## The three tiers
//!
//! | tier | what | outcome |
//! |---|---|---|
//! | no-op | canned `private` | carries no grant; contributes nothing to `acl_grants` |
//! | public | `public-read`, `public-read-write`, `authenticated-read`, any grantee naming `AllUsers`/`AuthenticatedUsers`, **and any canned name this build does not recognize** | refused **in code**, ahead of and independent of the policy |
//! | conferring | everything else (`bucket-owner-*`, `aws-exec-read`, `id=`/`emailAddress=` grantees) | refused **in code** — see below |
//!
//! The middle tier is the one that answered the original brief. A wildcard grant
//! (`"actions": ["*"]`) used to confer `write_object_acl`, and the DEFAULT ACCESS MODEL
//! seeds exactly that for Owners — so a policy-only guard would have left every org
//! Owner one `--acl public-read` away from publishing a patient record. Public exposure
//! is not a capability this gateway brokers, so it is refused where no bundle can reach
//! it.
//!
//! ## 2026-08-08: the conferring tier is refused in code too
//!
//! M4 shipped the conferring tier as a **second decision** on `write_object_acl`: a
//! request carrying `x-amz-acl: bucket-owner-full-control` was a write *and* an ACL
//! change, and AWS models it the same way (`s3:PutObject` + `s3:PutObjectAcl`).
//!
//! That verb no longer exists. It was removed with the rest of the control-plane
//! vocabulary because an object ACL is a **second, backend-side access-control list that
//! hyperfluid does not project, does not display and cannot revoke** — a grant of access
//! to a principal named in no `grants` row, invisible to the console and to every audit
//! query that reads the grants model. That is a bypass of managed access whatever verb
//! guards it, which is the governing principle of the 2026-08-08 settlement.
//!
//! So conferring ACLs are now refused in code as well, and the two refusals are kept as
//! distinct dispositions on purpose: the reasons differ, and an operator reading a 403
//! needs to know whether they asked to publish to the world or merely to hand the object
//! to one named principal. Neither is a bare 400 — both go through
//! `GatewayAccess::refuse`, which writes a real `Deny` audit record against the write's
//! own verb before answering `AccessDenied` (defect B-1: a refusal with no record is not
//! a refusal anyone can review).
//!
//! **`private` is untouched**, and that matters more than it looks: `s3cmd` and `rclone`
//! send `x-amz-acl: private` on every upload by default, so folding it into the
//! conferring tier would 403 the two most common clients on ordinary writes. It confers
//! nothing on anyone — see [`NO_OP_CANNED_ACLS`].

use std::collections::BTreeMap;

use crate::authz::AclGrant;

/// Canned ACLs that grant nothing to anyone who did not already have it.
///
/// Exactly one entry, and the reasoning has to hold for each: `private` is *the default
/// ACL*. On a create it asks for the state the object would have anyway; on an overwrite
/// it resets the ACL to owner-only, which is a narrowing. There is no third party it can
/// name. Treating it as "no grant requested" is therefore not a relaxation — it is the
/// truth about the request — and it is what keeps `s3cmd` and `rclone`, which send
/// `x-amz-acl: private` on every upload by default, from needing a grant nobody would
/// know to give them.
///
/// `bucket-owner-full-control` is deliberately **not** here even though under this
/// gateway the bucket owner is the tenant-owner credential every forward is re-signed as.
/// That equivalence is a property of the current deployment topology, not of the request,
/// and an ACL entry that is a no-op only because of how the proxy happens to be wired is
/// not a no-op — the day the gateway forwards as anything else, it would start conferring
/// on a third party. It falls to the conferring tier, which is now a refusal.
pub const NO_OP_CANNED_ACLS: &[&str] = &["private"];

/// Canned ACLs that publish. Refused in code.
///
/// `authenticated-read` is in the list and belongs there: it grants read to the
/// `AuthenticatedUsers` group, which on a shared RGW is *every credential the object
/// store issues* — every other tenant of the same self-hosted cloud. "Authenticated" is
/// not "authorized", and in a multi-tenant regulated deployment the two are very far
/// apart.
pub const PUBLIC_CANNED_ACLS: &[&str] = &["public-read", "public-read-write", "authenticated-read"];

/// Canned ACLs that name a specific, non-public grantee. Refused in code since
/// 2026-08-08 (they required `write_object_acl` until that verb was removed).
///
/// They are still enumerated separately rather than folded into [`PUBLIC_CANNED_ACLS`],
/// because the *reason* differs and the reason is what reaches the client and the audit
/// record: `bucket-owner-full-control` does not publish anything, it hands the object to
/// one named principal outside the grants model. Collapsing the two would tell an
/// operator their `bucket-owner-full-control` upload was a public-exposure attempt,
/// which is both false and the kind of false that makes people stop reading 403s.
///
/// The list is CLOSED, and that closure is load-bearing: a canned name outside all three
/// of these arrays is treated as **public** (see [`classify`]). The gateway does not know
/// what a name it has never heard of expands to, the backend does, and guessing in the
/// permissive direction is how an ACL retrofit gets quietly reopened by a future S3 API
/// addition.
pub const CONFERRING_CANNED_ACLS: &[&str] = &[
    "bucket-owner-read",
    "bucket-owner-full-control",
    "aws-exec-read",
];

/// Grantee tokens that mean "everybody" or "every credential this store issues".
///
/// Matched case-insensitively as a *substring* of the whole grantee expression, which
/// over-matches (a canonical user id containing the literal text `allusers` would be
/// refused). That is the intended direction: the alternative is parsing a
/// comma-separated list of `id=`/`uri=`/`emailAddress=` pairs and disagreeing with the
/// backend about the result, and a false refusal is a support ticket while a false
/// acceptance is a public bucket.
const PUBLIC_GRANTEE_TOKENS: &[&str] = &["allusers", "authenticatedusers"];

/// The raw ACL-bearing fields of one request, borrowed from the parsed s3s input.
///
/// A struct rather than five arguments so that a hook cannot silently forget one: adding
/// a field here is a compile error at every construction site.
#[derive(Debug, Default, Clone, Copy)]
pub struct AclFields<'a> {
    /// `x-amz-acl` (header) or the `acl` form field on a browser POST.
    pub canned: Option<&'a str>,
    pub full_control: Option<&'a str>,
    pub read: Option<&'a str>,
    /// Only bucket ACLs have a WRITE grant, so this is `None` at every construction site
    /// in the gateway today — `CreateBucket` was the last op that could carry one and it
    /// is `Coverage::Denied` since 2026-08-08. Kept rather than deleted because it is
    /// what makes this struct a complete model of the S3 ACL headers: an op that CAN
    /// carry `x-amz-grant-write` is screened the day it is enforced, instead of the day
    /// someone notices the field was missing.
    pub write: Option<&'a str>,
    pub read_acp: Option<&'a str>,
    pub write_acp: Option<&'a str>,
}

impl AclFields<'_> {
    /// Normalize into the wire form the PDP and the audit record see.
    ///
    /// Sorted, so two spellings of the same request produce the same `resource_key` and
    /// the same capture id.
    #[must_use]
    pub fn grants(&self) -> Vec<AclGrant> {
        let mut out = Vec::new();
        let mut push = |source: &str, value: Option<&str>| {
            if let Some(v) = value {
                out.push(AclGrant {
                    source: source.to_string(),
                    value: v.to_string(),
                });
            }
        };
        push("acl", self.canned);
        push("grant-full-control", self.full_control);
        push("grant-read", self.read);
        push("grant-write", self.write);
        push("grant-read-acp", self.read_acp);
        push("grant-write-acp", self.write_acp);
        out.sort();
        out
    }
}

/// What the gateway will do about the ACL grants on a request.
///
/// Two of the three variants are refusals, and they are kept apart because they are
/// different facts about the request — the client-facing reason and the audit record
/// both say which.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AclDisposition {
    /// Nothing was asked for, or only a no-op canned ACL was. Proceed as an ordinary
    /// write.
    NoGrant,
    /// The request would expose the object to every caller of this object store, or
    /// names a canned ACL this build cannot prove is not that. Refused in code.
    RefusedPublic(String),
    /// The request confers access on a named principal outside the grants model.
    /// Refused in code since 2026-08-08 — there is no verb that authorizes it, and an
    /// ACL hyperfluid did not project is access it cannot display or revoke.
    RefusedConferring(String),
}

impl AclDisposition {
    /// The client-facing reason, or `None` when the request may proceed.
    ///
    /// Callers screen on this rather than matching the variants, so a *third* refusal
    /// tier added later is refused by every write path the day it is added, instead of
    /// falling through whichever `match` arm nobody updated.
    #[must_use]
    pub fn refusal(&self) -> Option<&str> {
        match self {
            AclDisposition::NoGrant => None,
            AclDisposition::RefusedPublic(why) | AclDisposition::RefusedConferring(why) => {
                Some(why)
            }
        }
    }
}

/// Classify the grants a request carries.
///
/// Order matters: **any** public grant refuses the whole request, even alongside
/// otherwise-fine ones, and it is reported as the public one — that is the more serious
/// of the two and the one an operator must see first. A request is one unit and the
/// gateway does not part-apply it; part-applying is stripping under another name.
#[must_use]
pub fn classify(grants: &[AclGrant]) -> AclDisposition {
    let mut conferring: Option<&AclGrant> = None;
    for g in grants {
        if let Some(reason) = public_grant_reason(g) {
            return AclDisposition::RefusedPublic(reason);
        }
        if g.source == "acl" && NO_OP_CANNED_ACLS.contains(&g.value.as_str()) {
            continue;
        }
        conferring = conferring.or(Some(g));
    }
    match conferring {
        None => AclDisposition::NoGrant,
        Some(g) => AclDisposition::RefusedConferring(format!(
            "the request carries x-amz-{} = {:?}, which confers access on a principal \
             this gateway did not grant it to. There is no verb that authorizes that: an \
             object ACL is a second, backend-side access-control list that hyperfluid \
             does not project, cannot display and cannot revoke, so writing one through \
             the gateway is a bypass of the managed access model. Refused in code, not \
             by policy. Grant the principal access in the console instead",
            g.source, g.value
        )),
    }
}

/// `Some(reason)` when this single grant reaches a public audience, or names a canned
/// ACL this build cannot classify.
fn public_grant_reason(g: &AclGrant) -> Option<String> {
    if g.source == "acl" {
        let v = g.value.as_str();
        if NO_OP_CANNED_ACLS.contains(&v) || CONFERRING_CANNED_ACLS.contains(&v) {
            return None;
        }
        if PUBLIC_CANNED_ACLS.contains(&v) {
            return Some(format!(
                "the request carries the canned ACL {v:?}, which would grant access to \
                 every caller of this object store; public exposure is not brokered by \
                 this gateway and is refused in code, not by policy"
            ));
        }
        return Some(format!(
            "the request carries the canned ACL {v:?}, which this gateway does not \
             recognize and therefore cannot prove is not a public grant; refused"
        ));
    }
    let lowered = g.value.to_ascii_lowercase();
    if let Some(token) = PUBLIC_GRANTEE_TOKENS.iter().find(|t| lowered.contains(**t)) {
        return Some(format!(
            "the request carries x-amz-{} naming the {token} group, which would grant \
             access to every caller of this object store; public exposure is not brokered \
             by this gateway and is refused in code, not by policy",
            g.source
        ));
    }
    None
}

/// Everything a write carries besides its bytes that changes who can reach the object or
/// whether it can be destroyed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestRiders {
    /// Normalized ACL grants — [`AclFields::grants`].
    pub acl: Vec<AclGrant>,
    /// The tag set an `x-amz-tagging` header (or a POST form `tagging` field) asks to
    /// install. `None` means the request named no tags at all, which is different from
    /// `Some({})` — the latter asks to install an empty set, i.e. to clear.
    pub tags: Option<BTreeMap<String, String>>,
    /// `x-amz-bypass-governance-retention`.
    pub bypass_governance: bool,
}

impl RequestRiders {
    /// Extract and normalize the riders of one request.
    ///
    /// Fails on a tag set the gateway cannot resolve the same way the backend will —
    /// see [`parse_tagging_header`]. The caller turns that into an audited refusal, never
    /// a bare `InvalidRequest` (plan defect B-1).
    pub fn parse(
        acl: AclFields<'_>,
        tagging: Option<&str>,
        bypass_governance: bool,
        max_tags: usize,
    ) -> Result<Self, String> {
        let tags = tagging
            .map(|t| parse_tagging_header(t, max_tags))
            .transpose()?;
        Ok(RequestRiders {
            acl: acl.grants(),
            tags,
            bypass_governance,
        })
    }

    /// True when this request carries nothing the retrofit cares about — the common case,
    /// and the one that must stay free of extra decisions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.acl.is_empty() && self.tags.is_none() && !self.bypass_governance
    }
}

/// The `x-amz-tagging` header: a URL-encoded query string, `k1=v1&k2=v2`.
///
/// Three refusals, all of them about the PDP and the backend agreeing on what the tag set
/// *is* — the same argument as the `TagSet` duplicate-key check in `access::mod`:
///
/// - **the cap** (`limits.max_tag_count`);
/// - **duplicate keys**, because folding them into a map keeps one and the backend keeps
///   whichever *it* prefers, so the PDP would authorize a tag set the object never gets;
/// - **a literal `+`**, because it is a genuine ambiguity: query-string encoding reads it
///   as a space, RFC 3986 percent-encoding reads it as a plus, and the gateway has no way
///   to know which the backend will pick. Refusing with an instruction to percent-encode
///   is a one-line fix for the caller and removes a parser differential on a value that
///   can drive an ABAC grant.
pub fn parse_tagging_header(
    header: &str,
    max_tags: usize,
) -> Result<BTreeMap<String, String>, String> {
    if header.contains('+') {
        return Err(
            "the x-amz-tagging header contains a literal '+', which the gateway and the \
             backend may decode differently (space vs plus); percent-encode it as %2B or \
             %20"
            .to_string(),
        );
    }
    let mut tags = BTreeMap::new();
    if header.is_empty() {
        return Ok(tags);
    }
    let mut count = 0usize;
    for pair in header.split('&') {
        count += 1;
        if count > max_tags {
            return Err(format!(
                "the x-amz-tagging header carries more than the {max_tags}-tag cap"
            ));
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            // A bare `k` is not a tag. Refused rather than read as `k=""`, which is a
            // guess the backend need not share.
            None => {
                return Err(format!(
                    "the x-amz-tagging header carries {pair:?}, which is not a key=value pair"
                ));
            }
        };
        let key = percent_decode(k);
        if key.is_empty() {
            return Err("the x-amz-tagging header carries a tag with an empty key".to_string());
        }
        if tags.insert(key.clone(), percent_decode(v)).is_some() {
            return Err(format!(
                "the x-amz-tagging header carries the key {key:?} twice; the gateway will \
                 not authorize a tag set it cannot resolve the same way the backend will"
            ));
        }
    }
    Ok(tags)
}

/// Percent-decoding for tag keys/values. Deliberately does **not** treat `+` as a space —
/// [`parse_tagging_header`] refuses the character outright rather than picking a reading.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn canned(v: &str) -> Vec<AclGrant> {
        vec![AclGrant {
            source: "acl".into(),
            value: v.into(),
        }]
    }

    fn grant(source: &str, v: &str) -> Vec<AclGrant> {
        vec![AclGrant {
            source: source.into(),
            value: v.into(),
        }]
    }

    #[test]
    fn a_public_canned_acl_is_refused_in_code() {
        for acl in PUBLIC_CANNED_ACLS {
            match classify(&canned(acl)) {
                AclDisposition::RefusedPublic(why) => {
                    assert!(why.contains(acl), "{why}");
                    assert!(
                        why.contains("refused in code, not by policy"),
                        "the reason must say the refusal is unconditional: {why}"
                    );
                }
                other => panic!("{acl} must be refused as public, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_canned_acl_this_build_does_not_recognize_is_refused() {
        // Fail-closed on the S3 API growing a name. The permissive alternative — treat
        // the unknown as "probably fine, ask the policy" — is how a closed set quietly
        // reopens.
        assert!(matches!(
            classify(&canned("log-delivery-write")),
            AclDisposition::RefusedPublic(_)
        ));
        assert!(matches!(
            classify(&canned("")),
            AclDisposition::RefusedPublic(_)
        ));
    }

    #[test]
    fn every_disposition_but_no_grant_refuses_and_says_why() {
        // `refusal()` is what every write path screens on, so "a new tier is refused by
        // construction" has to be true of the accessor, not of a `match` at each site.
        assert_eq!(classify(&[]).refusal(), None);
        for grants in [
            canned("public-read"),
            canned("log-delivery-write"),
            canned("bucket-owner-full-control"),
            grant("grant-read", "id=\"canonical-user-id\""),
        ] {
            let d = classify(&grants);
            let why = d
                .refusal()
                .unwrap_or_else(|| panic!("{grants:?} must be refused, got {d:?}"));
            assert!(!why.is_empty());
        }
    }

    #[test]
    fn private_is_the_one_canned_acl_that_confers_nothing() {
        assert_eq!(classify(&canned("private")), AclDisposition::NoGrant);
        // And it must stay the only one: an entry added here is a decision that some
        // other ACL name grants nobody anything, which is exactly the kind of claim that
        // is right until the deployment topology changes.
        assert_eq!(NO_OP_CANNED_ACLS, ["private"]);
    }

    #[test]
    fn a_non_public_canned_acl_is_refused_for_conferring_rather_than_for_publishing() {
        // Two claims, and the second is the one worth the test: these are refused, AND
        // they are refused with the conferring reason. An operator whose
        // `bucket-owner-full-control` upload is told it was a public-exposure attempt
        // stops believing the 403s.
        for acl in CONFERRING_CANNED_ACLS {
            match classify(&canned(acl)) {
                AclDisposition::RefusedConferring(why) => {
                    assert!(why.contains(acl), "{why}");
                    assert!(
                        why.contains("no verb that authorizes"),
                        "the reason must say WHY no grant can permit it: {why}"
                    );
                    assert!(
                        !why.contains("every caller of this object store"),
                        "a conferring ACL is not a public one: {why}"
                    );
                }
                other => panic!("{acl} must be refused as conferring, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_public_grant_outranks_a_conferring_one_in_the_same_request() {
        // Both refuse, so the request is safe either way — but the reason the client and
        // the audit record get must name the more serious of the two.
        let mut grants = canned("bucket-owner-full-control");
        grants.extend(grant(
            "grant-read",
            "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"",
        ));
        assert!(matches!(
            classify(&grants),
            AclDisposition::RefusedPublic(_)
        ));
    }

    #[test]
    fn a_grantee_naming_a_public_group_is_refused_however_it_is_spelled() {
        for value in [
            "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"",
            "uri=http://acs.amazonaws.com/groups/global/allusers",
            "URI=\"HTTP://ACS.AMAZONAWS.COM/GROUPS/GLOBAL/AUTHENTICATEDUSERS\"",
            // Mixed with a benign grantee: the request is one unit, so the whole thing
            // is refused rather than part-applied.
            "id=\"abc\", uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"",
        ] {
            for source in [
                "grant-read",
                "grant-write",
                "grant-read-acp",
                "grant-write-acp",
                "grant-full-control",
            ] {
                assert!(
                    matches!(
                        classify(&grant(source, value)),
                        AclDisposition::RefusedPublic(_)
                    ),
                    "{source}: {value}"
                );
            }
        }
    }

    #[test]
    fn a_named_grantee_is_refused_as_conferring_not_as_public() {
        // Until 2026-08-08 these went to the policy as a `write_object_acl` question.
        // The verb is gone: hyperfluid does not project object ACLs, so an ACL written
        // here is access the console cannot show and cannot take back.
        for value in [
            "id=\"canonical-user-id\"",
            "emailAddress=\"a@example.test\"",
        ] {
            for source in ["grant-read", "grant-full-control"] {
                assert!(
                    matches!(
                        classify(&grant(source, value)),
                        AclDisposition::RefusedConferring(_)
                    ),
                    "{source}: {value}"
                );
            }
        }
    }

    #[test]
    fn a_public_grant_alongside_a_no_op_still_refuses() {
        let mut grants = canned("private");
        grants.extend(grant(
            "grant-read",
            "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"",
        ));
        assert!(matches!(
            classify(&grants),
            AclDisposition::RefusedPublic(_)
        ));
    }

    #[test]
    fn no_acl_fields_is_no_grant() {
        assert_eq!(classify(&[]), AclDisposition::NoGrant);
        assert!(AclFields::default().grants().is_empty());
    }

    #[test]
    fn grants_are_normalized_and_sorted() {
        let fields = AclFields {
            canned: Some("private"),
            full_control: Some("id=\"x\""),
            read: None,
            write: Some("id=\"y\""),
            read_acp: None,
            write_acp: None,
        };
        let g = fields.grants();
        assert_eq!(
            g.iter().map(|g| g.source.as_str()).collect::<Vec<_>>(),
            ["acl", "grant-full-control", "grant-write"],
            "sorted, so two spellings of one request share a cache key and a capture id"
        );
    }

    #[test]
    fn the_tagging_header_parses_into_the_map_the_pdp_sees() {
        let t = parse_tagging_header("tier=internal&owner=team%2Da", 10).unwrap();
        assert_eq!(t["tier"], "internal");
        assert_eq!(t["owner"], "team-a");
        assert!(parse_tagging_header("", 10).unwrap().is_empty());
    }

    #[test]
    fn the_tagging_header_fails_closed_on_anything_ambiguous() {
        // Each of these is a case where the gateway and RGW could resolve the tag set
        // differently — which would mean the PDP authorized a tag set the object never
        // receives.
        assert!(
            parse_tagging_header("tier=a&tier=b", 10).is_err(),
            "dup key"
        );
        assert!(parse_tagging_header("tier", 10).is_err(), "not a pair");
        assert!(parse_tagging_header("=v", 10).is_err(), "empty key");
        assert!(parse_tagging_header("a=1&b=2&c=3", 2).is_err(), "over cap");
        let plus = parse_tagging_header("tier=a+b", 10).unwrap_err();
        assert!(plus.contains('+'), "{plus}");
    }

    #[test]
    fn riders_are_empty_only_when_the_request_carries_nothing() {
        assert!(RequestRiders::default().is_empty());
        let r = RequestRiders::parse(
            AclFields {
                canned: Some("private"),
                ..Default::default()
            },
            None,
            false,
            10,
        )
        .unwrap();
        // `private` is a no-op *grant*, but it is still a rider: `acl_grants` carries it
        // to the PDP and to the audit record, because "the caller asked for private" is a
        // fact about the request and the record should say so.
        assert!(!r.is_empty());
        assert_eq!(classify(&r.acl), AclDisposition::NoGrant);
    }
}
