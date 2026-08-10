//! `Action=AssumeRoleWithWebIdentity` — the AWS STS wire protocol, so that every S3
//! SDK can obtain a gateway credential with **stock configuration**.
//!
//! # Why this exists: nothing outside the console could get a credential
//!
//! s0 has had two mints for a while and neither one can be used by an S3 client:
//!
//! * [`crate::internal`] is authenticated with the *platform* shared secret and is
//!   reachable only from the console's pod. It is not a client-facing surface and must
//!   never become one.
//! * [`crate::mint`]'s bearer-token door speaks a bespoke JSON protocol. No SDK knows
//!   it, so using it means bespoke client code, bespoke refresh logic, and a bespoke
//!   answer to "what happens when the credential expires mid-upload".
//!
//! So `aws-cli`, `rclone`, Trino, Spark and every backup tool had **no way at all** to
//! use the gateway. This module is the missing door, and its shape is not a local
//! invention: it is the AWS `AssumeRoleWithWebIdentity` call, form-encoded request and
//! XML response, exactly as `sts.amazonaws.com`, Ceph RGW and MinIO all serve it.
//!
//! With this, the client configuration is the same one an EKS pod already uses:
//!
//! ```text
//! AWS_ROLE_ARN=arn:aws:iam::<tenant>:role/<tenant>-sts-role
//! AWS_WEB_IDENTITY_TOKEN_FILE=/var/run/secrets/…/token
//! AWS_ENDPOINT_URL_STS=https://<org>.s3-gw-sts.<domain>
//! AWS_ENDPOINT_URL_S3=https://<org>.s3-gw.<domain>
//! ```
//!
//! The SDK's own web-identity provider then mints, reads `Expiration` off the XML, and
//! re-mints before it lapses. No bespoke client code, and expiry handling is the SDK's.
//!
//! # What the RoleArn is for — and what it is not
//!
//! The hard problem the bearer mint could never solve is that hyperfluid's Keycloak
//! tokens carry **no tenant claim and no organization claim**, and cannot: the Ceph
//! tenant is a property of the *harbor being addressed*, not of the *user*, so a user
//! with three harbors would need three values of a claim minted once per login
//! ([`crate::internal`] documents this at length).
//!
//! `AssumeRoleWithWebIdentity` dissolves it, because in AWS the tenant travels in the
//! **RoleArn — a request parameter, not a token claim**:
//!
//! 1. the web identity token proves *who* the caller is;
//! 2. the `RoleArn` names *which* tenant they want to act in;
//! 3. the organization is resolved from s0's own authoritative tenant→org binding
//!    ([`crate::proxy::BackendRegistry`]) and **never** from a claim.
//!
//! Step 3 is the same rule [`crate::internal`] enforces for the console
//! (`OrganizationMismatch`), for the same reason: the decision path attributes from the
//! route, so an organization taken from anywhere else could silently disagree with it.
//! Here it is stronger — there is nothing to disagree *with*, because the caller never
//! gets to state an organization at all.
//!
//! **The role name confers nothing.** s0 has no IAM role objects, no trust policies and
//! no attached policies; authority comes from the bundle at decision time and from
//! nowhere else. The ARN is a tenant selector plus ceremony. When
//! [`WebIdentityConfig::role_name_template`] is configured the role name must match it,
//! which turns a typo into a clear refusal instead of a session in a tenant the caller
//! did not mean — but a matching role name still grants nothing on its own.
//!
//! # Why this listener, and why it is unauthenticated
//!
//! It rides [`crate::mint`]'s listener (`sts_mint.listen`, 8015 as the operator renders
//! it), which is **unauthenticated by design and correctly so: a valid web identity
//! token *is* the credential**, exactly as at `sts.amazonaws.com`, which is a public
//! endpoint. There is nothing to authenticate the caller *with* before they have a
//! credential; that is what the flow is for.
//!
//! What matters is that "unauthenticated" stays a property of a *socket*, never of a
//! path:
//!
//! * **Not the internal listener** (8017). That one is guarded by the platform shared
//!   secret, and an unauthenticated route sharing that socket would make "is this
//!   request authenticated?" a routing question on the port that mints credentials for
//!   the console. [`crate::config::GatewayConfig::validate`] refuses a config where the
//!   two share a port.
//! * **Not the admin listener** (8016). Probes and scrapes, unauthenticated by
//!   construction; its network posture is "whatever can reach a metrics port", which is
//!   not a posture to hand a credential mint.
//! * **Not the S3 data plane** (8014). Ceph RGW and MinIO *do* serve STS on the S3
//!   endpoint, and that is the one ecosystem convention deliberately not followed here:
//!   it would put an unauthenticated route inside the SigV4-authenticated data plane
//!   and make the discrimination a matter of parsing a POST body correctly, forever.
//!   AWS itself keeps `sts.amazonaws.com` and `s3.amazonaws.com` apart, so a separate
//!   endpoint is *also* the parity answer — at the cost of one extra client variable,
//!   `AWS_ENDPOINT_URL_STS`, which every current AWS SDK and the CLI honour.
//!
//! # Ordering: identity first, then the tenant
//!
//! [`WebIdentitySts::assume_role`] verifies the token **before** it looks at the
//! `RoleArn`. That ordering is deliberate and load-bearing: this endpoint is
//! internet-reachable, so resolving the tenant first would make it a tenant-existence
//! oracle for an anonymous caller. After the reordering, probing requires a token the
//! IdP actually issued, and the refusal is a deliberately unspecific `AccessDenied`
//! while the detail goes to the log.
//!
//! # Two ways a token can be addressed to this gateway
//!
//! The configured audience list, **or** the policy bundle — see
//! [`WebIdentitySts::addressed_to_this_gateway`], which carries the whole argument, and
//! the AWS-parity register (D31), which registers the deviation. The second route exists
//! because the first one cannot serve a *tenant's own* service accounts without an
//! operator re-render per service account, and those are the primary consumer of this
//! gateway. It is additive: no token the audience list accepts is affected by it, and
//! acceptance is not authorization in either case.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::Value;

use crate::auth::sts::{SessionClaims, StsAuthority};
use crate::config::StsMintConfig;
use crate::model::PrincipalType;
use crate::proxy::BackendRegistry;

/// The STS API version every AWS SDK sends and every response namespace carries.
pub const STS_API_VERSION: &str = "2011-06-15";
/// The XML namespace on both the result and the error document.
pub const STS_XMLNS: &str = "https://sts.amazonaws.com/doc/2011-06-15/";
/// The one action this surface implements.
pub const ACTION_ASSUME_ROLE_WITH_WEB_IDENTITY: &str = "AssumeRoleWithWebIdentity";

/// Keycloak's `preferred_username` for a service account is `service-account-<clientId>`.
/// This prefix is the only reliable in-token marker of the principal class.
pub const SERVICE_ACCOUNT_USERNAME_PREFIX: &str = "service-account-";

// ── errors ─────────────────────────────────────────────────────────────────────

/// A refusal, in AWS's vocabulary.
///
/// Every variant maps to a real STS error code, because an SDK *acts* on the code: it
/// retries `IDPCommunicationError`, it does not retry `InvalidIdentityToken`, and it
/// surfaces `ValidationError` to the user as a configuration mistake. Answering
/// everything with one code would make the failures indistinguishable to the only
/// consumer that reads them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StsRefusal {
    /// A malformed or missing request parameter. AWS: 400.
    Validation(String),
    /// An `Action` this surface does not implement. AWS: 400.
    InvalidAction(String),
    /// The web identity token did not verify: signature, issuer, audience, shape. AWS: 400.
    InvalidIdentityToken(String),
    /// The token verified but is past its expiry. AWS: 400.
    ExpiredToken,
    /// The token verified but its claims cannot be turned into a principal. AWS: 403.
    IdpRejectedClaim(String),
    /// The role cannot be assumed here: unroutable tenant, or a role name that is not
    /// the one this gateway serves. AWS: 403.
    ///
    /// The message is deliberately uniform and says nothing about *which* half failed —
    /// this endpoint is reachable from the internet and the detail is a tenant-existence
    /// oracle. The detail is logged.
    AccessDenied,
    /// The mint itself failed (a clock problem, a key-ring problem). AWS: 500.
    Internal(String),
}

impl StsRefusal {
    /// The HTTP status AWS answers with. SDK retry policy keys off 5xx, so an
    /// `Internal` must not be reported as a 400 or the client will not retry a
    /// transient failure.
    pub fn status(&self) -> u16 {
        match self {
            StsRefusal::AccessDenied | StsRefusal::IdpRejectedClaim(_) => 403,
            StsRefusal::Internal(_) => 500,
            _ => 400,
        }
    }

    /// The `<Code>` element. These are AWS's literals; an SDK matches on them.
    pub fn code(&self) -> &'static str {
        match self {
            StsRefusal::Validation(_) => "ValidationError",
            StsRefusal::InvalidAction(_) => "InvalidAction",
            StsRefusal::InvalidIdentityToken(_) => "InvalidIdentityToken",
            StsRefusal::ExpiredToken => "ExpiredTokenException",
            StsRefusal::IdpRejectedClaim(_) => "IDPRejectedClaim",
            StsRefusal::AccessDenied => "AccessDenied",
            StsRefusal::Internal(_) => "InternalFailure",
        }
    }

    /// `Sender` for anything the caller can fix, `Receiver` for anything it cannot —
    /// the AWS convention, and the signal a client uses to decide whether retrying the
    /// identical request could ever help.
    pub fn error_type(&self) -> &'static str {
        match self {
            StsRefusal::Internal(_) => "Receiver",
            _ => "Sender",
        }
    }

    /// The `<Message>`. Never interpolates a credential, and never names a tenant.
    pub fn message(&self) -> String {
        match self {
            StsRefusal::Validation(why) => why.clone(),
            StsRefusal::InvalidAction(action) => {
                format!(
                    "Action {action:?} is not supported by this endpoint; \
                     this gateway implements {ACTION_ASSUME_ROLE_WITH_WEB_IDENTITY} only"
                )
            }
            StsRefusal::InvalidIdentityToken(why) => {
                format!("The web identity token could not be validated: {why}")
            }
            StsRefusal::ExpiredToken => "The web identity token has expired".into(),
            StsRefusal::IdpRejectedClaim(why) => {
                format!("The web identity token's claims were rejected: {why}")
            }
            StsRefusal::AccessDenied => {
                "Not authorized to perform sts:AssumeRoleWithWebIdentity for the requested role"
                    .into()
            }
            StsRefusal::Internal(_) => "The request could not be completed".into(),
        }
    }
}

// ── the request ────────────────────────────────────────────────────────────────

/// The parameters of one `AssumeRoleWithWebIdentity` call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssumeRoleWithWebIdentityRequest {
    pub role_arn: String,
    pub role_session_name: String,
    pub web_identity_token: String,
    /// Absent ⇒ the configured default. AWS SDKs omit it by default and let the service
    /// decide, so absent must be a working request rather than a `ValidationError`.
    pub duration_seconds: Option<u64>,
}

impl AssumeRoleWithWebIdentityRequest {
    /// Pull the parameters out of a decoded form/query pair list.
    ///
    /// `Action` and `Version` are checked by the caller
    /// ([`WebIdentitySts::assume_role_from_params`]) so that an unknown `Action` is an
    /// `InvalidAction` rather than a complaint about a missing `RoleArn`.
    pub fn from_params(params: &Params) -> Result<Self, StsRefusal> {
        let required = |name: &str| -> Result<String, StsRefusal> {
            match params.get(name) {
                Some(v) if !v.trim().is_empty() => Ok(v.to_string()),
                _ => Err(StsRefusal::Validation(format!(
                    "{name} is required and must be non-empty"
                ))),
            }
        };
        let duration_seconds = match params.get("DurationSeconds") {
            None => None,
            Some(raw) if raw.trim().is_empty() => None,
            Some(raw) => Some(raw.trim().parse::<u64>().map_err(|_| {
                StsRefusal::Validation(format!(
                    "DurationSeconds must be a positive integer, got {raw:?}"
                ))
            })?),
        };
        // Zero is refused, not clamped up. It is the one duration no credential can
        // satisfy, so it is a malformed request rather than a request with a ceiling —
        // the same split `internal::SessionRefusal::ZeroDuration` makes.
        if duration_seconds == Some(0) {
            return Err(StsRefusal::Validation("DurationSeconds must be > 0".into()));
        }
        let role_session_name = required("RoleSessionName")?;
        validate_role_session_name(&role_session_name)?;
        Ok(AssumeRoleWithWebIdentityRequest {
            role_arn: required("RoleArn")?,
            role_session_name,
            web_identity_token: required("WebIdentityToken")?,
            duration_seconds,
        })
    }
}

/// AWS: 2–64 characters from `[\w+=,.@-]`.
///
/// Enforced because the value is **reflected into the response XML** as part of the
/// assumed-role ARN. Escaping it correctly is necessary and is done
/// ([`xml_escape`]) — but a charset check as well means the value can never carry
/// markup in the first place, which is the property worth having on a document a client
/// parses.
fn validate_role_session_name(name: &str) -> Result<(), StsRefusal> {
    let ok = (2..=64).contains(&name.chars().count())
        && name.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '=' | ',' | '.' | '@' | '-')
        });
    if ok {
        return Ok(());
    }
    Err(StsRefusal::Validation(
        "RoleSessionName must be 2-64 characters from [A-Za-z0-9_+=,.@-]".into(),
    ))
}

/// A decoded `application/x-www-form-urlencoded` document, order-preserving.
///
/// Hand-rolled rather than pulled from a crate: the decoder is 20 lines, it sits on the
/// unauthenticated edge of a credential-minting endpoint, and the alternative was a new
/// dependency in the process that decides who may read what. It is exercised directly
/// by the tests at the bottom of this file, including the shapes that matter (`+` as a
/// space, `%2B` as a plus, an empty value, a duplicated key).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Params(Vec<(String, String)>);

impl Params {
    /// Decode a form body or a query string. Never fails: an undecodable escape is left
    /// as written, because refusing the whole document over one stray `%` would turn a
    /// client quirk into an outage, and every value this surface reads is validated on
    /// its own terms anyway.
    pub fn parse(raw: &str) -> Self {
        let mut out = Vec::new();
        for pair in raw.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (k, v) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            out.push((form_decode(k), form_decode(v)));
        }
        Params(out)
    }

    /// The **first** value for `name`. First, not last: a caller that sends
    /// `WebIdentityToken` twice must not be able to make the value that is *verified*
    /// differ from the value a middlebox logged, and "first wins" is what the AWS query
    /// protocol specifies.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// `application/x-www-form-urlencoded` decoding: `+` is a space, `%XX` is a byte.
///
/// Invalid UTF-8 after decoding is replaced rather than rejected, for the same reason
/// [`Params::parse`] is infallible.
///
/// **Works on bytes throughout, and that is a fix rather than a style.** The first
/// version of this function read the two hex digits with `&input[i + 1..i + 3]`, which
/// panics whenever a `%` is followed by a multi-byte UTF-8 character: `i + 3` then lands
/// *inside* that character and `str` indexing refuses a non-boundary index. `%€` is
/// enough to do it. That is a remote panic reachable by an unauthenticated caller on the
/// credential mint — the one socket on this gateway where "anyone on the internet chooses
/// these bytes" is the design — so the decoder must not index a `str` by an offset it
/// computed itself. [`hex_digit`] reads the two bytes directly and simply declines to
/// decode anything that is not a pair of ASCII hex digits, which is the same answer the
/// old code gave for `%zz`.
fn form_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                match (hex_digit(bytes[i + 1]), hex_digit(bytes[i + 2])) {
                    (Some(hi), Some(lo)) => {
                        out.push(hi << 4 | lo);
                        i += 3;
                    }
                    _ => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One ASCII hex digit's value, or `None` for anything else — including any byte of a
/// multi-byte UTF-8 sequence, which is what keeps [`form_decode`] total.
fn hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ── the role ARN ───────────────────────────────────────────────────────────────

/// The two halves of a role ARN this gateway cares about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleArn {
    /// The ARN's *account* field. On this platform that is the **Ceph tenant**, which
    /// is exactly how the operator already provisions RGW's own roles
    /// (`harbor_binding_reconciler::ensure_harbor_sts` builds
    /// `arn:aws:iam::{tenant}:role/{tenant}-sts-role`). Reusing the same ARN means a
    /// client repointed from RGW STS to s0 changes its *endpoint* and nothing else.
    pub tenant: String,
    pub role_name: String,
}

impl RoleArn {
    /// Parse `arn:<partition>:iam::<tenant>:role/<name>`.
    ///
    /// Strict where AWS is strict and lenient only about the partition (`aws`,
    /// `aws-cn`, `aws-us-gov` are all real, and refusing an unfamiliar one buys
    /// nothing). The two rules that are enforced hard both protect the tenant:
    ///
    /// * the **region field must be empty**. IAM is global and every real IAM ARN has
    ///   an empty region, so a non-empty one means the caller is not sending what it
    ///   thinks it is — and the field it *has* filled might be the one we read as the
    ///   tenant.
    /// * the resource must be `role/<non-empty>`. `arn:aws:iam:::role/x` (the
    ///   untenanted form RGW emits when no tenant is set) parses to an **empty**
    ///   account and is refused here rather than silently selecting nothing.
    pub fn parse(arn: &str) -> Result<Self, StsRefusal> {
        let invalid = |why: &str| {
            StsRefusal::Validation(format!(
                "RoleArn must look like arn:aws:iam::<tenant>:role/<name> ({why})"
            ))
        };
        let parts: Vec<&str> = arn.splitn(6, ':').collect();
        if parts.len() != 6 {
            return Err(invalid("wrong number of ':'-separated fields"));
        }
        if parts[0] != "arn" {
            return Err(invalid("it must start with `arn:`"));
        }
        if parts[1].is_empty() {
            return Err(invalid("the partition field is empty"));
        }
        if parts[2] != "iam" {
            return Err(invalid("the service field must be `iam`"));
        }
        if !parts[3].is_empty() {
            return Err(invalid("the region field must be empty — IAM is global"));
        }
        let tenant = parts[4];
        if tenant.is_empty() {
            return Err(invalid(
                "the account field carries the tenant and must not be empty",
            ));
        }
        let Some(role_name) = parts[5].strip_prefix("role/") else {
            return Err(invalid("the resource must be `role/<name>`"));
        };
        if role_name.is_empty() {
            return Err(invalid("the role name is empty"));
        }
        Ok(RoleArn {
            tenant: tenant.to_string(),
            role_name: role_name.to_string(),
        })
    }
}

/// Normalize a role name for comparison: every non-alphanumeric character becomes `-`,
/// and case is folded.
///
/// **The looseness is the point, and it is not laziness.** The expected name is built by
/// substituting a *tenant* into a template, but the tenant and the role name are
/// sanitized by different rules on the way into the backend, so the two are not equal
/// even when everything is correct:
///
/// * a Ceph tenant may contain `_` (a harbor slug's `-` is mapped to `_` by
///   hyperfluid's `to_rgw_tenant`, and a sanitized slug gains a `_<hash8>` suffix);
/// * an RGW IAM **role** name may not contain `_` at all, so
///   `to_rgw_role_name("{tenant}-sts-role")` maps every `_` back to `-`.
///
/// So for a harbor whose slug is `data-lab`, the tenant is `data_lab_ab12cd34` and the
/// role the operator really provisions is `data-lab-ab12cd34-sts-role`, while the
/// template expands to `data_lab_ab12cd34-sts-role`. A byte comparison would refuse the
/// exact ARN the platform documents, for every harbor whose slug contains a hyphen —
/// which is most of them.
///
/// Folding both sides makes the check tolerant in the **only direction where a mistake
/// is harmful**. The role name is not an authorization input: accepting a spelling
/// variant grants nothing, because the tenant is validated separately and every request
/// is still authorized against the bundle. Refusing a legitimate spelling, by contrast,
/// is a total credential-vending outage for that harbor. The gate exists to catch a
/// typo; a typo does not survive this normalization, and a separator difference does.
fn role_name_key(name: &str) -> String {
    name.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect()
}

// ── principal resolution ───────────────────────────────────────────────────────

/// Who the token says the caller is, in the vocabulary the bundle is keyed by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WebIdentityPrincipal {
    /// The **raw** subject key. For a user, the OIDC `sub`; for a service account, the
    /// Keycloak **clientId**. Never prefixed — the rego composes `user:`/`sa:` itself.
    pub sub: String,
    pub principal_type: PrincipalType,
    /// The `sub` claim as presented, for the response's
    /// `SubjectFromWebIdentityToken` — which AWS defines as the token's subject, not as
    /// whatever the service decided to key on.
    pub token_subject: String,
}

/// Decide user vs service account from a Keycloak token's claims.
///
/// **Service accounts are the primary consumer of this gateway**, and the two classes
/// are two different key spaces in the bundle (`sa:<clientId>` vs `user:<oidc sub>`), so
/// getting this wrong is not a cosmetic error: an SA session minted as a user looks up a
/// key the projection never writes and evaluates against no grants at all. That failure
/// is exactly why [`crate::internal`] exists — the console *states* the class rather than
/// letting a token be guessed at — and it is the property this function has to reproduce
/// from the token alone.
///
/// The rule, and it is deliberately not a guess:
///
/// 1. `preferred_username` beginning `service-account-` is Keycloak's own marker for a
///    service-account user. Nothing else produces it.
/// 2. The clientId is then taken from **`azp`** (falling back to `client_id`), because
///    Keycloak lowercases `preferred_username` while `azp` carries the clientId as
///    registered — and `sa:<clientId>` in the bundle is keyed on the registered
///    spelling (`org_s3_gateway_bundle::service_account_subject`).
/// 3. If `azp` is present but does not case-insensitively match the username's suffix,
///    the token is **refused**. Two claims disagreeing about which client this is, is
///    not a case to resolve by preferring one; it is a case to refuse.
/// 4. Anything else is a user, keyed by `sub`.
///
/// A token with no usable subject at all is refused rather than minted with an empty
/// one: `sa:`/`user:` are real keys an accidental grant could match.
pub fn resolve_principal(claims: &Value) -> Result<WebIdentityPrincipal, StsRefusal> {
    let str_claim = |name: &str| claims.get(name).and_then(Value::as_str).map(str::trim);
    let token_subject = str_claim("sub").unwrap_or_default().to_string();

    let username = str_claim("preferred_username").unwrap_or_default();
    let azp = str_claim("azp")
        .filter(|s| !s.is_empty())
        .or_else(|| str_claim("client_id").filter(|s| !s.is_empty()));

    if let Some(from_username) = username.strip_prefix(SERVICE_ACCOUNT_USERNAME_PREFIX) {
        let from_username = from_username.trim();
        let client_id = match azp {
            Some(azp) if azp.eq_ignore_ascii_case(from_username) => azp,
            Some(azp) => {
                return Err(StsRefusal::IdpRejectedClaim(format!(
                    "azp {azp:?} and preferred_username service-account-{from_username:?} \
                     name different clients"
                )));
            }
            None => from_username,
        };
        if client_id.is_empty() {
            return Err(StsRefusal::IdpRejectedClaim(
                "the service account's client id is empty".into(),
            ));
        }
        return Ok(WebIdentityPrincipal {
            sub: client_id.to_string(),
            principal_type: PrincipalType::ServiceAccount,
            token_subject,
        });
    }

    if token_subject.is_empty() {
        return Err(StsRefusal::IdpRejectedClaim(
            "the token carries no `sub` claim".into(),
        ));
    }
    Ok(WebIdentityPrincipal {
        sub: token_subject.clone(),
        principal_type: PrincipalType::User,
        token_subject,
    })
}

// ── who this tenant's bundle already knows ─────────────────────────────────────

/// The subjects the **current** policy bundle knows for a tenant.
///
/// This is the second, purely **additive** route by which a token can be found to be
/// addressed to this gateway (see [`WebIdentitySts::addressed_to_this_gateway`], and
/// the AWS-parity register (D31) for the deviation it registers).
///
/// Implemented by [`crate::pdp::BundleStore`] — the same revision-swapped store the PDP
/// decides against. Every call reads whatever bundle is in force at that instant, so
/// this can never answer from a snapshot the poller has already replaced. A cache here
/// would be a *second* answer to "what does the control plane currently say", which is
/// exactly the failure class the revision swap exists to remove: a revocation would land
/// in the PDP and not here.
pub trait TenantSubjects: Send + Sync {
    /// Is `sa:<client_id>` a **member subject** of `tenant` in the bundle in force?
    ///
    /// "Member subject" is the policy's own word rather than a new concept: `s3.rego`'s
    /// membership rule is
    /// `member if is_object(data.tenants[input.tenant].user_attributes[subject_key])`,
    /// and this asks exactly that question, of exactly that map, under exactly that key.
    fn knows_service_account(&self, tenant: &str, client_id: &str) -> bool;
}

/// The client id a token names in `azp`, falling back to `client_id`.
///
/// **The only claim the bundle route reads.** Never `aud` — that is a list of
/// *audiences*, not a principal, and a token may carry an audience it does not speak
/// for. Never `sub` either: a user's `sub` is the other key space (`user:`), and no
/// claim a human's token carries may be allowed to select an `sa:` key.
fn azp_or_client_id(claims: &Value) -> Option<&str> {
    ["azp", "client_id"].into_iter().find_map(|name| {
        claims
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
    })
}

// ── the endpoint ───────────────────────────────────────────────────────────────

/// Verifies a web identity token and hands back its **raw** claims.
///
/// Separate from [`crate::mint::OidcVerifier`] on purpose. That trait's
/// `VerifiedIdentity` requires a tenant claim and an organization claim, which is
/// precisely the requirement this surface exists to remove — the tenant comes from the
/// `RoleArn` and the organization from the routing table.
#[async_trait::async_trait]
pub trait WebIdentityVerifier: Send + Sync {
    /// Verify the token's **signature, issuer and expiry** and return its raw claims.
    ///
    /// It deliberately does **not** decide whether the token is addressed to this
    /// gateway, because that decision now needs the tenant out of the `RoleArn` — which
    /// this trait never sees. [`WebIdentitySts::addressed_to_this_gateway`] takes it, on
    /// the one path that can reach a credential, so no implementation of this trait can
    /// skip it by omission.
    ///
    /// **The rename from `verify_claims` is the point of the rename.** The audience
    /// check used to live inside that method; moving it out while keeping the old name
    /// would leave any other implementation compiling and silently unchecked.
    async fn verify_token(&self, token: &str) -> Result<Value, StsRefusal>;

    /// Does the **configured** audience list accept this token? `aud` (string or array)
    /// or `azp`/`client_id`, exactly as before the bundle route existed. This answer is
    /// never narrowed by anything below — the bundle route is only ever consulted after
    /// it says no.
    fn audience_is_accepted(&self, claims: &Value) -> bool;

    /// The configured list, for a refusal **log line**. Never for a response body: this
    /// endpoint is internet-reachable and the list is the set of OIDC clients the
    /// platform provisions.
    fn configured_audiences(&self) -> Vec<String>;
}

/// Everything the surface needs that is not a secret.
#[derive(Debug, Clone)]
pub struct WebIdentityConfig {
    /// Ceiling on `DurationSeconds`. Requests above it are **clamped**, never refused —
    /// see [`WebIdentitySts::clamp_duration`].
    pub max_duration_secs: u64,
    /// Used when `DurationSeconds` is absent, which is what every AWS SDK's web-identity
    /// provider does by default.
    pub default_duration_secs: u64,
    /// When set, the role name must equal this with `{tenant}` substituted. See
    /// [`WebIdentitySts::check_role_name`].
    pub role_name_template: Option<String>,
}

impl WebIdentityConfig {
    /// Read the surface's knobs off the mint section.
    pub fn from_config(cfg: &StsMintConfig, session_ttl: Duration) -> Self {
        WebIdentityConfig {
            max_duration_secs: cfg.max_duration_secs,
            // The session TTL the rest of the gateway mints at, so a client that says
            // nothing gets the same lifetime the console-mediated path hands out.
            default_duration_secs: session_ttl.as_secs().min(cfg.max_duration_secs).max(1),
            role_name_template: cfg.role_name_template.clone(),
        }
    }
}

/// The `AssumeRoleWithWebIdentity` implementation.
///
/// Holds the **same** [`StsAuthority`] the S3 front verifies with, so a credential
/// minted here is byte-compatible with one minted by the console: same key ring, same
/// `HFST<kid>.<sid>` shape, same derived secret, same retirement semantics. There is
/// deliberately no second authority — a credential this door could mint that the data
/// plane could not honour would look healthy from both sides in isolation.
pub struct WebIdentitySts {
    verifier: Arc<dyn WebIdentityVerifier>,
    sts: Arc<StsAuthority>,
    registry: Arc<BackendRegistry>,
    config: WebIdentityConfig,
    /// The bundle-driven half of the audience decision. `None` ⇒ the configured
    /// audience list is the only route, byte-for-byte the behaviour of the build that
    /// predates it. See [`Self::with_bundle_subjects`].
    subjects: Option<Arc<dyn TenantSubjects>>,
}

/// A minted session, plus everything the response document echoes back.
pub struct AssumedRoleSession {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    /// Absolute expiry, seconds since the epoch. Rendered as **ISO-8601** in the XML —
    /// see [`render_assume_role_response`].
    pub expires_at: u64,
    pub role: RoleArn,
    pub role_session_name: String,
    pub principal: WebIdentityPrincipal,
    pub audience: String,
    pub issuer: String,
}

impl WebIdentitySts {
    pub fn new(
        verifier: Arc<dyn WebIdentityVerifier>,
        sts: Arc<StsAuthority>,
        registry: Arc<BackendRegistry>,
        config: WebIdentityConfig,
    ) -> Self {
        WebIdentitySts {
            verifier,
            sts,
            registry,
            config,
            subjects: None,
        }
    }

    /// Attach the policy bundle as a second, **additive** source of audience
    /// acceptance — see [`Self::addressed_to_this_gateway`] for the rule and the
    /// argument.
    ///
    /// A builder rather than a constructor parameter so that the absence of it is a
    /// real, reachable state: `main.rs` wires the gateway's own [`crate::pdp::BundleStore`],
    /// and anything that does not wire it gets precisely the pre-existing behaviour
    /// rather than a weaker version of the new one.
    #[must_use]
    pub fn with_bundle_subjects(mut self, subjects: Arc<dyn TenantSubjects>) -> Self {
        self.subjects = Some(subjects);
        self
    }

    /// **Clamp, not refuse** — the same choice [`crate::internal::InternalApi::clamp_ttl`]
    /// makes, and for a reason that is *stronger* here rather than merely consistent.
    ///
    /// AWS refuses: `DurationSeconds` above the role's `MaxSessionDuration` is a
    /// `ValidationError`. That is a deviation this file takes deliberately and registers
    ///, because of who the caller is. The AWS SDK web
    /// identity providers read `Expiration` off this response and schedule their own
    /// refresh from it, so a clamped credential simply works — the client re-mints
    /// sooner. A refusal, by contrast, is a hard failure at *credential acquisition*,
    /// i.e. the workload never starts, over a number that is only ever an upper bound
    /// request. Clamping can only ever shorten a credential's life, the answer is fully
    /// observable in the response, and it matches what the other mint on this gateway
    /// already does.
    ///
    /// Below AWS's 900 s floor is left alone rather than clamped up: a caller asking for
    /// a 60-second credential gets one, and shortening is never the unsafe direction.
    fn clamp_duration(&self, requested: u64) -> u64 {
        if requested > self.config.max_duration_secs {
            tracing::warn!(
                requested,
                max = self.config.max_duration_secs,
                "AssumeRoleWithWebIdentity DurationSeconds exceeds the configured maximum; clamping"
            );
            return self.config.max_duration_secs;
        }
        requested
    }

    /// **Is this token addressed to this gateway?** Two routes, and the second one only
    /// ever runs after the first has said no.
    ///
    /// 1. **The configured audience list** — `aud` or `azp`/`client_id` naming one of
    ///    `sts_mint.web_identity_audiences` (falling back to the bearer door's single
    ///    `audience`, so the list is never empty). Unchanged, and still authoritative:
    ///    every token accepted before this method existed is accepted by this arm alone.
    /// 2. **The policy bundle** — the token's `azp`/`client_id` `C` names a service
    ///    account that the *current* bundle already knows as a member subject
    ///    (`sa:C` ∈ `data.tenants[<tenant from the RoleArn>].user_attributes`).
    ///
    /// # Why route 2 exists
    ///
    /// Route 1 alone cannot serve a tenant's own service accounts, which are the primary
    /// consumer of this whole gateway. A Keycloak SA token from
    /// `grant_type=client_credentials` carries `aud: "account"` and `azp: <its clientId>`,
    /// and that clientId is in no list the operator rendered: the list is
    /// `[<org>-storage-sa] + PLATFORM_STS_AUDIENCES + spec.s3Gateway.stsAudiences`
    /// (`hf_bin_operator/src/s3_gateway/config.rs::audiences`). Naming each SA in
    /// `stsAudiences` works — it is what `naming_a_service_accounts_client_id_lets_it_present_an_unmapped_token`
    /// measures — but it costs an operator re-render per service account, so in practice
    /// every tenant-created SA is refused `InvalidIdentityToken`.
    ///
    /// # Why it is safe, in the three properties that make it so
    ///
    /// * **Acceptance is not authorization.** This decides only *"is this token
    ///   addressed to this gateway"*. Nothing here grants anything: the request is still
    ///   authorized against the bundle on every S3 call, and a subject the bundle knows
    ///   with no grant is still denied — pinned by
    ///   `web_identity_e2e::bundle_acceptance_is_not_authorization_a_grantless_subject_is_still_denied`.
    /// * **It fails closed.** The answer is drawn from the bundle in force. An empty,
    ///   seed, or stale bundle knows fewer subjects, so it accepts *fewer* tokens. There
    ///   is no bundle state that widens route 1.
    /// * **It is tenant-scoped, and the tenant is not the caller's to choose freely.**
    ///   The tenant comes from the `RoleArn`, and the lookup is against *that* tenant's
    ///   subject map, so a token cannot be accepted against a tenant whose bundle does
    ///   not name it. The honest limit: hyperfluid projects `user_attributes` org-wide
    ///   (`org_s3_gateway_bundle::assemble` clones one map into every tenant of the org),
    ///   so in practice this is "a service account of this organization, presented
    ///   against a harbor of this organization". It cannot cross an organization,
    ///   because a bundle is published per organization and the module hard-denies a
    ///   request whose `organization_id` is not the bundle's.
    ///
    /// # Why `user_attributes` and not `s3_grants`
    ///
    /// `user_attributes` is the map the policy's **own membership rule** reads
    /// (`s3.rego`: `member if is_object(data.tenants[t].user_attributes[subject_key])`),
    /// and a request from a non-member is denied `principal is not a tenant member`
    /// before any grant is consulted. So:
    ///
    /// * a subject in `user_attributes` with **no grant** is a real, ordinary state — the
    ///   projection writes an entry for every service account of the organization,
    ///   grants or not — and it is exactly the state a newly-created SA is in while
    ///   someone is still assigning its access. Keying on `s3_grants` would refuse it a
    ///   credential and report an *identity* failure for what is a missing grant;
    /// * a subject in `s3_grants` but **not** in `user_attributes` is authorized for
    ///   nothing at all, so accepting it would vend a credential that 403s on every
    ///   request — the same dud-credential outcome the mint already refuses to create
    ///   for an unroutable tenant.
    ///
    /// So the union buys nothing on the first count and costs a dud credential on the
    /// second. One map, and it is the one the decision itself is keyed on.
    ///
    /// # What it does NOT do
    ///
    /// It applies to this door only (the OIDC bearer mint's strict `aud` check in
    /// [`crate::mint::StandardVerifier::verify`] is untouched), it reads only
    /// `azp`/`client_id`, never `aud` and never `sub`, and it composes the `sa:` prefix
    /// itself — so no claim on a human's token can select a service account's key.
    fn addressed_to_this_gateway(&self, role: &RoleArn, claims: &Value) -> Result<(), StsRefusal> {
        if self.verifier.audience_is_accepted(claims) {
            return Ok(());
        }
        let client_id = azp_or_client_id(claims);
        if let (Some(subjects), Some(client_id)) = (&self.subjects, client_id)
            && subjects.knows_service_account(&role.tenant, client_id)
        {
            tracing::info!(
                tenant = %role.tenant,
                subject = %format!("sa:{client_id}"),
                "web identity token accepted by the POLICY BUNDLE rather than by the \
                 configured audience list: this client id is a service-account subject \
                 the tenant's current bundle knows. Acceptance is not authorization — \
                 every request is still authorized against the bundle"
            );
            return Ok(());
        }
        // Two different operator problems, and the log has to tell them apart: "I made a
        // new service account and it cannot get a credential" is a *bundle* question
        // (has the projection published it yet?), while "nothing from this client works"
        // is an *audience* question. The RESPONSE stays uniform — see below.
        match (&self.subjects, client_id) {
            (Some(_), Some(client_id)) => tracing::warn!(
                tenant = %role.tenant,
                subject = %format!("sa:{client_id}"),
                accepted = ?self.verifier.configured_audiences(),
                "web identity token refused: NO SUCH SUBJECT in this tenant's bundle — \
                 `sa:<client id>` is not in data.tenants[<tenant>].user_attributes for the \
                 tenant named by the RoleArn (and neither `aud` nor `azp` names a \
                 configured audience). If this service account is new, the control plane \
                 has not published it yet; if it belongs to another organization or \
                 another harbor, it never will"
            ),
            (Some(_), None) => tracing::warn!(
                tenant = %role.tenant,
                accepted = ?self.verifier.configured_audiences(),
                "web identity token refused: AUDIENCE NOT ACCEPTED — neither `aud` nor \
                 `azp` names a configured audience, and the token carries no \
                 `azp`/`client_id` at all, so the bundle route cannot apply to it"
            ),
            (None, _) => tracing::warn!(
                accepted = ?self.verifier.configured_audiences(),
                "web identity token refused: AUDIENCE NOT ACCEPTED — neither `aud` nor \
                 `azp` names a configured audience, and this instance has no bundle \
                 wired for the bundle-driven route"
            ),
        }
        // One message for every refusal above. Distinguishing them *here* would make an
        // internet-reachable, unauthenticated endpoint answer "that tenant's bundle does
        // not know you" differently from "wrong audience", which is the same
        // tenant-oracle D22 refuses to be. The accepted list is not echoed either.
        Err(StsRefusal::InvalidIdentityToken(
            "neither `aud` nor `azp` names an audience this gateway accepts, and `azp` \
             does not name a service account known to the requested tenant"
                .into(),
        ))
    }

    /// Is this the role name this gateway serves for that tenant?
    ///
    /// Nothing about authority rests on the answer — the bundle decides that — so this
    /// is a *diagnostic* gate: without it, `arn:aws:iam::acme:role/typo` mints a
    /// perfectly good `acme` session and the operator's mental model of "the role
    /// controls the access" is quietly false. With it, the ARN a client is told to use
    /// is the ARN that works.
    ///
    /// Unconfigured ⇒ any non-empty role name is accepted, because s0 must stay runnable
    /// outside hyperfluid where no such naming convention exists.
    ///
    /// See [`role_name_key`] for why the comparison is deliberately loose.
    fn check_role_name(&self, role: &RoleArn) -> Result<(), StsRefusal> {
        let Some(template) = &self.config.role_name_template else {
            return Ok(());
        };
        let expected = template.replace("{tenant}", &role.tenant);
        if role_name_key(&role.role_name) == role_name_key(&expected) {
            return Ok(());
        }
        tracing::warn!(
            tenant = %role.tenant,
            presented = %role.role_name,
            %expected,
            "AssumeRoleWithWebIdentity refused: the role name is not the one this gateway serves"
        );
        Err(StsRefusal::AccessDenied)
    }

    /// The full call: parse the action, verify the identity, resolve the principal,
    /// resolve the tenant, mint.
    ///
    /// `sid` is caller-supplied (random at the endpoint, fixed in tests) so this stays
    /// deterministic.
    pub async fn assume_role_from_params(
        &self,
        params: &Params,
        sid: &str,
    ) -> Result<AssumedRoleSession, StsRefusal> {
        let action = params.get("Action").unwrap_or_default();
        if action.is_empty() {
            return Err(StsRefusal::Validation(
                "Action is required; this endpoint speaks the AWS STS query protocol".into(),
            ));
        }
        if action != ACTION_ASSUME_ROLE_WITH_WEB_IDENTITY {
            return Err(StsRefusal::InvalidAction(action.to_string()));
        }
        // `Version` is echoed by every SDK. A *wrong* one is refused rather than
        // ignored: the response document's shape is versioned, and answering a client
        // that asked for a different contract with this one is how a silent
        // incompatibility ships.
        if let Some(v) = params.get("Version")
            && !v.is_empty()
            && v != STS_API_VERSION
        {
            return Err(StsRefusal::Validation(format!(
                "Version {v:?} is not supported; this endpoint implements {STS_API_VERSION}"
            )));
        }
        let request = AssumeRoleWithWebIdentityRequest::from_params(params)?;
        self.assume_role(&request, sid).await
    }

    /// As [`assume_role_from_params`](Self::assume_role_from_params), on already-parsed
    /// parameters.
    pub async fn assume_role(
        &self,
        request: &AssumeRoleWithWebIdentityRequest,
        sid: &str,
    ) -> Result<AssumedRoleSession, StsRefusal> {
        // The ARN is parsed first because it is a pure syntax check on a request
        // parameter — a malformed one is a client bug and deserves to say so. What is
        // NOT done before the token is verified is the *routing* lookup below: that one
        // is the tenant-existence oracle.
        let role = RoleArn::parse(&request.role_arn)?;

        // ── identity, before anything that could disclose a tenant ─────────────
        let claims = self
            .verifier
            .verify_token(&request.web_identity_token)
            .await?;
        // The audience decision sits exactly where it always did — immediately after
        // signature/issuer/expiry and before the principal is resolved — so no refusal
        // that was an `InvalidIdentityToken` becomes an `IDPRejectedClaim`, or the other
        // way round. What changed is only that it can now also be satisfied by the
        // bundle, which needs the tenant the RoleArn named.
        self.addressed_to_this_gateway(&role, &claims)?;
        let principal = resolve_principal(&claims)?;

        // ── now, and only now, the tenant ─────────────────────────────────────
        self.check_role_name(&role)?;
        let Some(route) = self.registry.route_snapshot(&role.tenant) else {
            // Same rule as `internal::SessionRefusal::UnroutableTenant`: refuse at the
            // mint rather than hand out a session every later request would 403 on.
            tracing::warn!(
                tenant = %role.tenant,
                sub = %principal.sub,
                "AssumeRoleWithWebIdentity refused: the RoleArn's tenant is not routable here"
            );
            return Err(StsRefusal::AccessDenied);
        };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| StsRefusal::Internal(format!("clock: {e}")))?
            .as_secs();
        let ttl = self.clamp_duration(
            request
                .duration_seconds
                .unwrap_or(self.config.default_duration_secs),
        );
        let claims_for_session = SessionClaims {
            sub: principal.sub.clone(),
            // The whole reason the bearer mint could not serve this platform: the
            // principal class is *resolved* rather than hard-coded, so a service
            // account evaluates in the `sa:` key space.
            principal_type: principal.principal_type,
            // Deliberately empty, and this is not an oversight. The module reads groups
            // from the bundle, never from the session — and unlike the console, which at
            // least states what it believed at mint time, a token's own role claims are
            // an *unvalidated* assertion by the IdP about authorization. Carrying them
            // into a session would put a caller-influenced value where an advisory
            // audit field is read.
            groups: Vec::new(),
            tenant: role.tenant.clone(),
            // From the gateway's own tenant→org binding. Never a claim, never a
            // parameter: the decision path attributes from the route, so anything else
            // could silently disagree with it.
            org: route.organization_id.clone(),
            sid: sid.to_string(),
            exp: now + ttl,
        };
        let creds = self
            .sts
            .mint(sid, claims_for_session)
            .map_err(|e| StsRefusal::Internal(e.to_string()))?;

        Ok(AssumedRoleSession {
            access_key_id: creds.access_key_id,
            secret_access_key: creds.secret_access_key,
            session_token: creds.session_token,
            expires_at: creds.expires_at,
            role,
            role_session_name: request.role_session_name.clone(),
            audience: primary_audience(&claims),
            issuer: claims
                .get("iss")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string(),
            principal,
        })
    }
}

/// The `aud` value to echo in `<Audience>`. A JWT `aud` may be a string or an array;
/// AWS reports one value, so the first is used.
fn primary_audience(claims: &Value) -> String {
    match claims.get("aud") {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(a)) => a
            .first()
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        _ => claims
            .get("azp")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }
}

// ── the wire documents ─────────────────────────────────────────────────────────

/// Render the success document.
///
/// **`Expiration` is ISO-8601**, which is the single most consequential detail in this
/// file. The existing JSON mint returns it as a Unix integer; the AWS SDKs parse this
/// field as an ISO-8601 date-time and a numeric value is a hard parse error, so a
/// numeric `Expiration` would make every SDK reject an otherwise perfect credential.
/// [`iso8601_utc`] has its own test for exactly that reason.
pub fn render_assume_role_response(session: &AssumedRoleSession, request_id: &str) -> String {
    let assumed_role_id = format!("{}:{}", session.role.role_name, session.role_session_name);
    let assumed_role_arn = format!(
        "arn:aws:sts::{}:assumed-role/{}/{}",
        session.role.tenant, session.role.role_name, session.role_session_name
    );
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="{ns}">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>{subject}</SubjectFromWebIdentityToken>
    <Audience>{audience}</Audience>
    <AssumedRoleUser>
      <Arn>{assumed_arn}</Arn>
      <AssumedRoleId>{assumed_id}</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>{access_key}</AccessKeyId>
      <SecretAccessKey>{secret_key}</SecretAccessKey>
      <SessionToken>{session_token}</SessionToken>
      <Expiration>{expiration}</Expiration>
    </Credentials>
    <Provider>{provider}</Provider>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>{request_id}</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>
"#,
        ns = STS_XMLNS,
        subject = xml_escape(&session.principal.token_subject),
        audience = xml_escape(&session.audience),
        assumed_arn = xml_escape(&assumed_role_arn),
        assumed_id = xml_escape(&assumed_role_id),
        access_key = xml_escape(&session.access_key_id),
        secret_key = xml_escape(&session.secret_access_key),
        session_token = xml_escape(&session.session_token),
        expiration = iso8601_utc(session.expires_at),
        provider = xml_escape(&session.issuer),
        request_id = xml_escape(request_id),
    )
}

/// Render the error document, in the shape AWS STS uses (an `ErrorResponse` envelope,
/// not S3's bare `Error` root). The difference is not cosmetic: an SDK's STS error
/// deserializer looks for this envelope, and without it every refusal — however precise
/// the code — surfaces to the user as an opaque "unknown error".
pub fn render_error_response(refusal: &StsRefusal, request_id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse xmlns="{ns}">
  <Error>
    <Type>{kind}</Type>
    <Code>{code}</Code>
    <Message>{message}</Message>
  </Error>
  <RequestId>{request_id}</RequestId>
</ErrorResponse>
"#,
        ns = STS_XMLNS,
        kind = refusal.error_type(),
        code = refusal.code(),
        message = xml_escape(&refusal.message()),
        request_id = xml_escape(request_id),
    )
}

/// `2026-08-09T12:34:56Z`.
///
/// Formatted from `chrono` rather than hand-rolled so leap years and month lengths are
/// not this file's problem. An out-of-range value degrades to the epoch rather than
/// panicking: a credential document is not a place to `unwrap`.
pub fn iso8601_utc(unix_seconds: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(unix_seconds as i64, 0)
        .unwrap_or(chrono::DateTime::<chrono::Utc>::UNIX_EPOCH)
        .format("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

/// Escape the five XML metacharacters.
///
/// Applied to **every** interpolated value without exception, including the ones whose
/// charset is already validated. A field that is safe today because of a check
/// somewhere else is a field that becomes unsafe when the check moves.
pub fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── form decoding ───────────────────────────────────────────────────────────

    #[test]
    fn a_form_body_decodes_the_way_an_sdk_encodes_one() {
        // The exact body shape `aws sts assume-role-with-web-identity` puts on the wire.
        let p = Params::parse(
            "Action=AssumeRoleWithWebIdentity&Version=2011-06-15\
             &RoleArn=arn%3Aaws%3Aiam%3A%3Aacme%3Arole%2Facme-sts-role\
             &RoleSessionName=my-session&WebIdentityToken=aaa.bbb.ccc&DurationSeconds=900",
        );
        assert_eq!(p.get("Action"), Some("AssumeRoleWithWebIdentity"));
        assert_eq!(
            p.get("RoleArn"),
            Some("arn:aws:iam::acme:role/acme-sts-role")
        );
        assert_eq!(p.get("RoleSessionName"), Some("my-session"));
        assert_eq!(p.get("WebIdentityToken"), Some("aaa.bbb.ccc"));
        assert_eq!(p.get("DurationSeconds"), Some("900"));
        assert_eq!(p.get("NotSent"), None);
    }

    #[test]
    fn form_decoding_handles_the_shapes_that_bite() {
        // `+` is a space in a form body, but `%2B` is a real plus — a JWT is base64url
        // so it has no `+`, but a RoleSessionName may.
        assert_eq!(Params::parse("a=one+two").get("a"), Some("one two"));
        assert_eq!(Params::parse("a=one%2Btwo").get("a"), Some("one+two"));
        // An empty value is present-and-empty, not absent.
        assert_eq!(Params::parse("a=&b=1").get("a"), Some(""));
        // A valueless key.
        assert_eq!(Params::parse("a&b=1").get("a"), Some(""));
        // FIRST wins on a duplicate, so the value that is verified is the value the
        // AWS query protocol says is in force.
        assert_eq!(Params::parse("a=first&a=second").get("a"), Some("first"));
        // A stray `%` is left alone rather than failing the whole document.
        assert_eq!(Params::parse("a=100%").get("a"), Some("100%"));
        assert_eq!(Params::parse("a=%zz").get("a"), Some("%zz"));
        assert!(Params::parse("").is_empty());
    }

    /// **A remote, unauthenticated panic, found in review on 2026-08-09 and fixed.**
    ///
    /// The decoder used to read its two hex digits with `&input[i + 1..i + 3]`. When a
    /// `%` is followed by a multi-byte UTF-8 character, `i + 3` lands inside that
    /// character and indexing a `str` at a non-boundary offset **panics** — so
    /// `RoleSessionName=%€` was enough to kill the connection task on the credential
    /// mint, which is unauthenticated by design and Ingress-fronted. Every byte in this
    /// test is one an anonymous caller chooses.
    ///
    /// The fix reads bytes rather than indexing the `str`; the assertions below are the
    /// behaviour, and the fact that this test returns at all is the regression guard.
    #[test]
    fn a_multibyte_character_after_a_percent_does_not_panic_the_decoder() {
        // 2-byte, 3-byte and 4-byte continuations, in the three positions where the
        // old slice could straddle one.
        assert_eq!(Params::parse("a=%\u{00E9}z").get("a"), Some("%\u{00E9}z"));
        assert_eq!(Params::parse("a=%\u{20AC}").get("a"), Some("%\u{20AC}"));
        assert_eq!(Params::parse("a=%\u{20AC}xx").get("a"), Some("%\u{20AC}xx"));
        assert_eq!(
            Params::parse("a=%\u{1F600}yy").get("a"),
            Some("%\u{1F600}yy")
        );
        assert_eq!(Params::parse("a=%4\u{20AC}").get("a"), Some("%4\u{20AC}"));
        // …and the whole document still parses, so one odd value does not cost the
        // rest of the request.
        let p = Params::parse("Action=AssumeRoleWithWebIdentity&RoleSessionName=%\u{20AC}");
        assert_eq!(p.get("Action"), Some("AssumeRoleWithWebIdentity"));
        // POSITIVE CONTROL: ordinary escapes still decode, so this did not pass by the
        // decoder giving up on `%` altogether.
        assert_eq!(Params::parse("a=%2F%2f%41").get("a"), Some("//A"));
    }

    // ── the role ARN ────────────────────────────────────────────────────────────

    #[test]
    fn the_tenant_comes_out_of_the_role_arn() {
        // The exact ARN `harbor_binding_reconciler::ensure_harbor_sts` provisions in RGW.
        let arn = RoleArn::parse("arn:aws:iam::acme-prod:role/acme-prod-sts-role").expect("parses");
        assert_eq!(arn.tenant, "acme-prod");
        assert_eq!(arn.role_name, "acme-prod-sts-role");
        // Other partitions are fine.
        assert_eq!(
            RoleArn::parse("arn:aws-us-gov:iam::t:role/r")
                .expect("parses")
                .tenant,
            "t"
        );
    }

    #[test]
    fn a_role_arn_that_names_no_tenant_is_refused() {
        // `arn:aws:iam:::role/x` is the UNTENANTED form RGW emits when no tenant is set
        // (`ceph_rgw_admin::client`). It selects nothing here, and must say so rather
        // than resolve to an empty tenant.
        for bad in [
            "arn:aws:iam:::role/acme-sts-role",
            "",
            "not-an-arn",
            "arn:aws:iam::acme:role/",
            "arn:aws:iam::acme:user/bob",
            "arn:aws:s3::acme:role/r",
            "arn:aws:iam:us-east-1:acme:role/r", // IAM is global; a region means confusion
            "arn::iam::acme:role/r",             // empty partition
            "xrn:aws:iam::acme:role/r",
            "arn:aws:iam::acme", // too few fields
        ] {
            assert!(
                RoleArn::parse(bad).is_err(),
                "{bad:?} must not parse to a tenant"
            );
        }
    }

    // ── role-name normalization ─────────────────────────────────────────────────

    /// **The mismatch this normalization exists for is real, not hypothetical.**
    ///
    /// For a harbor whose slug is `data-lab`, hyperfluid's `to_rgw_tenant` produces the
    /// Ceph tenant `data_lab_<hash8>` (a `-` becomes `_`, and a sanitized slug gains the
    /// hash suffix), while `to_rgw_role_name` refuses `_` in an IAM role name and maps
    /// it back to `-`. So the ARN the operator really provisions in RGW — and the one a
    /// client is told to use — is `data-lab-<hash8>-sts-role`, which is *not*
    /// `{tenant}-sts-role` byte for byte.
    ///
    /// A strict comparison would 403 that exact ARN for every harbor whose slug
    /// contains a hyphen. This test is the regression guard.
    #[test]
    fn the_role_name_the_operator_really_provisions_is_accepted() {
        let template = "{tenant}-sts-role";
        for (tenant, provisioned) in [
            // The no-sanitization case: slug is already a valid tenant.
            ("default", "default-sts-role"),
            // The common case: a hyphenated harbor slug.
            ("data_lab_ab12cd34", "data-lab-ab12cd34-sts-role"),
            ("acme_prod_deadbeef", "acme-prod-deadbeef-sts-role"),
        ] {
            let expected = template.replace("{tenant}", tenant);
            assert_eq!(
                role_name_key(provisioned),
                role_name_key(&expected),
                "the ARN the operator provisions for tenant {tenant:?} must be accepted"
            );
        }
    }

    /// …and a typo still does not survive it. The gate is loose about separators and
    /// case, and about nothing else.
    #[test]
    fn a_typo_does_not_survive_the_normalization() {
        let expected = "acme-sts-role";
        for typo in [
            "acme-sts-rol",
            "acme-sts-roles",
            "acme-sts",
            "sts-role",
            "acme2-sts-role",
            "",
        ] {
            assert_ne!(
                role_name_key(typo),
                role_name_key(expected),
                "{typo:?} must not be accepted as {expected:?}"
            );
        }
        // Separator and case differences DO fold, deliberately.
        assert_eq!(
            role_name_key("acme_sts_role"),
            role_name_key("acme-sts-role")
        );
        assert_eq!(
            role_name_key("ACME-STS-ROLE"),
            role_name_key("acme-sts-role")
        );
        assert_eq!(
            role_name_key("acme.sts.role"),
            role_name_key("acme-sts-role")
        );
    }

    // ── principal resolution ────────────────────────────────────────────────────

    fn sa_token(client_id: &str) -> Value {
        // Exactly what Keycloak issues for `grant_type=client_credentials`.
        serde_json::json!({
            "sub": "b6d2c1f0-0000-0000-0000-000000000000",
            "azp": client_id,
            "preferred_username": format!("service-account-{client_id}"),
            "aud": "account",
            "iss": "https://kc.example/realms/default"
        })
    }

    #[test]
    fn a_keycloak_service_account_token_resolves_to_the_client_id() {
        // THE case this whole surface exists for. The bundle keys an SA's grants under
        // `sa:<clientId>`; the token's `sub` is the Keycloak service-account *user* id,
        // which appears in no bundle and would find no grants at all.
        let p = resolve_principal(&sa_token("pipeline-runner")).expect("resolves");
        assert_eq!(p.principal_type, PrincipalType::ServiceAccount);
        assert_eq!(p.sub, "pipeline-runner");
        assert_ne!(
            p.sub, "b6d2c1f0-0000-0000-0000-000000000000",
            "keying an SA by its token sub finds no grants"
        );
        // …and the response still reports the token's own subject, per the AWS field
        // definition.
        assert_eq!(p.token_subject, "b6d2c1f0-0000-0000-0000-000000000000");
    }

    #[test]
    fn the_registered_client_id_spelling_wins_over_keycloaks_lowercased_username() {
        // Keycloak lowercases `preferred_username`; the bundle is keyed on the clientId
        // as registered. Taking the username's suffix would look up `sa:pipeline-runner`
        // for a client registered as `Pipeline-Runner`.
        let claims = serde_json::json!({
            "sub": "u", "azp": "Pipeline-Runner",
            "preferred_username": "service-account-pipeline-runner"
        });
        let p = resolve_principal(&claims).expect("resolves");
        assert_eq!(p.sub, "Pipeline-Runner");
        assert_eq!(p.principal_type, PrincipalType::ServiceAccount);
    }

    #[test]
    fn two_claims_naming_different_clients_are_refused_not_reconciled() {
        let claims = serde_json::json!({
            "sub": "u", "azp": "attacker-client",
            "preferred_username": "service-account-victim-client"
        });
        let err = resolve_principal(&claims).expect_err("must refuse");
        assert!(matches!(err, StsRefusal::IdpRejectedClaim(_)), "{err:?}");
        assert_eq!(err.status(), 403);
    }

    #[test]
    fn a_human_token_resolves_to_a_user_keyed_by_sub() {
        let claims = serde_json::json!({
            "sub": "oidc-sub-alice", "azp": "hf-console",
            "preferred_username": "alice", "aud": "account"
        });
        let p = resolve_principal(&claims).expect("resolves");
        assert_eq!(p.principal_type, PrincipalType::User);
        assert_eq!(p.sub, "oidc-sub-alice");
        // `azp` alone must NOT make a human look like a service account — every console
        // user's token carries one.
        assert_ne!(p.sub, "hf-console");
    }

    #[test]
    fn a_token_with_no_subject_at_all_is_refused() {
        // `user:` and `sa:` are real keys; a session with an empty subject is one an
        // accidental grant could match.
        assert!(resolve_principal(&serde_json::json!({ "azp": "x" })).is_err());
        assert!(resolve_principal(&serde_json::json!({ "sub": "  " })).is_err());
        assert!(
            resolve_principal(&serde_json::json!({
                "sub": "u", "preferred_username": "service-account-"
            }))
            .is_err()
        );
    }

    // ── request parsing ─────────────────────────────────────────────────────────

    #[test]
    fn an_absent_duration_is_a_valid_request() {
        // The AWS SDK web-identity providers omit `DurationSeconds` by default. Making
        // it required would break the default configuration of every SDK.
        let p = Params::parse(
            "RoleArn=arn%3Aaws%3Aiam%3A%3At%3Arole%2Fr&RoleSessionName=sess&WebIdentityToken=t",
        );
        let r = AssumeRoleWithWebIdentityRequest::from_params(&p).expect("parses");
        assert_eq!(r.duration_seconds, None);
    }

    #[test]
    fn a_zero_or_unparseable_duration_is_a_validation_error() {
        let base =
            "RoleArn=arn%3Aaws%3Aiam%3A%3At%3Arole%2Fr&RoleSessionName=sess&WebIdentityToken=t";
        for bad in ["0", "-1", "abc", "1.5"] {
            let p = Params::parse(&format!("{base}&DurationSeconds={bad}"));
            let err = AssumeRoleWithWebIdentityRequest::from_params(&p).expect_err("refused");
            assert_eq!(err.code(), "ValidationError", "{bad}");
            assert_eq!(err.status(), 400);
        }
        // An empty value is "not sent", which is what an SDK emitting an unset optional
        // produces.
        let p = Params::parse(&format!("{base}&DurationSeconds="));
        assert_eq!(
            AssumeRoleWithWebIdentityRequest::from_params(&p)
                .expect("parses")
                .duration_seconds,
            None
        );
    }

    #[test]
    fn the_required_parameters_are_required() {
        let full = [
            ("RoleArn", "arn%3Aaws%3Aiam%3A%3At%3Arole%2Fr"),
            ("RoleSessionName", "sess"),
            ("WebIdentityToken", "tok"),
        ];
        // Positive control first, or "everything fails" would pass this test.
        let all = full
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        assert!(AssumeRoleWithWebIdentityRequest::from_params(&Params::parse(&all)).is_ok());
        for skip in 0..full.len() {
            let partial = full
                .iter()
                .enumerate()
                .filter(|(i, _)| *i != skip)
                .map(|(_, (k, v))| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join("&");
            let err = AssumeRoleWithWebIdentityRequest::from_params(&Params::parse(&partial))
                .expect_err("a missing required parameter must be refused");
            assert_eq!(err.code(), "ValidationError");
            assert!(err.message().contains(full[skip].0), "{}", err.message());
        }
    }

    #[test]
    fn a_role_session_name_that_could_carry_markup_is_refused_at_the_door() {
        // The value is reflected into the response XML. It is escaped there as well —
        // both, because either alone is one edit away from not being true.
        for bad in ["", "x", "<script>", "a b", &"x".repeat(65)] {
            let p = Params::parse(&format!(
                "RoleArn=arn%3Aaws%3Aiam%3A%3At%3Arole%2Fr&WebIdentityToken=t&RoleSessionName={}",
                bad.replace('<', "%3C")
                    .replace('>', "%3E")
                    .replace(' ', "%20")
            ));
            assert!(
                AssumeRoleWithWebIdentityRequest::from_params(&p).is_err(),
                "RoleSessionName {bad:?} must be refused"
            );
        }
        for good in ["ok", "my-session_1", "pod@ns.cluster", "a+b=c,d.e"] {
            let p = Params::parse(&format!(
                "RoleArn=arn%3Aaws%3Aiam%3A%3At%3Arole%2Fr&WebIdentityToken=t&RoleSessionName={}",
                good.replace('+', "%2B")
            ));
            assert!(
                AssumeRoleWithWebIdentityRequest::from_params(&p).is_ok(),
                "RoleSessionName {good:?} must be accepted"
            );
        }
    }

    // ── addressing: the configured list, and the bundle route ───────────────────
    //
    // These drive the REAL `assume_role` — the same method the HTTP handler calls —
    // over a real `BackendRegistry` with TWO routable tenants and a real `StsAuthority`.
    // Two routable tenants is the load-bearing part of the setup: it is what makes
    // `the_same_service_account_is_refused_against_another_tenants_role_arn` a statement
    // about the bundle lookup rather than about the routing table, which would have
    // refused an unroutable tenant whatever this code did.

    /// A verifier that hands back fixed claims and holds a configured audience list.
    /// The signature/issuer/expiry half is `tests/web_identity_e2e.rs`'s job, with a
    /// real RS256 key; what these tests need to vary is the claims and the list.
    struct FixedVerifier {
        claims: Value,
        audiences: Vec<String>,
    }

    #[async_trait::async_trait]
    impl WebIdentityVerifier for FixedVerifier {
        async fn verify_token(&self, _token: &str) -> Result<Value, StsRefusal> {
            Ok(self.claims.clone())
        }
        fn audience_is_accepted(&self, claims: &Value) -> bool {
            // The same rule `StandardVerifier` applies: `aud` (string or array) or
            // `azp`/`client_id`, against the configured list.
            let matches = |v: &str| self.audiences.iter().any(|a| a == v);
            let aud = match claims.get("aud") {
                Some(Value::String(s)) => matches(s),
                Some(Value::Array(a)) => a.iter().filter_map(Value::as_str).any(matches),
                _ => false,
            };
            aud || ["azp", "client_id"]
                .iter()
                .any(|n| claims.get(*n).and_then(Value::as_str).is_some_and(matches))
        }
        fn configured_audiences(&self) -> Vec<String> {
            self.audiences.clone()
        }
    }

    /// The bundle, reduced to the one question the door asks it.
    struct KnownSubjects(Vec<(&'static str, &'static str)>);

    impl TenantSubjects for KnownSubjects {
        fn knows_service_account(&self, tenant: &str, client_id: &str) -> bool {
            self.0.iter().any(|(t, c)| *t == tenant && *c == client_id)
        }
    }

    /// `acme` and `warehouse`, both routable, both in the same organization.
    fn two_tenant_registry() -> Arc<BackendRegistry> {
        let cfg = crate::config::GatewayConfig::from_json(
            &serde_json::json!({
                "listen": "127.0.0.1:0",
                "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
                "pdp": { "mode": "embedded" },
                "audit": { "sink_url": "http://127.0.0.1:59999/none",
                           "spill_path": "/dev/null" },
                "backends": [
                    { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:1" }
                ],
                "tenants": [
                    { "tenant": "acme", "organization_id": "org-acme", "backend_id": "bay-1",
                      "owner_access_key": "OWNER", "owner_secret_key": "SECRET" },
                    { "tenant": "warehouse", "organization_id": "org-acme",
                      "backend_id": "bay-1",
                      "owner_access_key": "OWNER", "owner_secret_key": "SECRET" }
                ],
                "bundle_path": "/dev/null"
            })
            .to_string(),
        )
        .expect("config");
        Arc::new(BackendRegistry::from_config(&cfg).expect("registry"))
    }

    fn door(claims: Value, audiences: &[&str], known: Option<KnownSubjects>) -> WebIdentitySts {
        let sts = WebIdentitySts::new(
            Arc::new(FixedVerifier {
                claims,
                audiences: audiences.iter().map(|s| (*s).to_string()).collect(),
            }),
            Arc::new(StsAuthority::new(vec![4u8; 32], vec![8u8; 32]).expect("authority")),
            two_tenant_registry(),
            WebIdentityConfig {
                max_duration_secs: 3600,
                default_duration_secs: 900,
                role_name_template: Some("{tenant}-sts-role".into()),
            },
        );
        match known {
            Some(k) => sts.with_bundle_subjects(Arc::new(k)),
            None => sts,
        }
    }

    /// The refusal, or a panic naming what was minted instead.
    ///
    /// Written out rather than reached with `expect_err` because
    /// [`AssumedRoleSession`] deliberately does not implement `Debug` — three of its
    /// fields are a live credential, and the strongest guarantee that they never reach a
    /// panic message or a log line is that `{:?}` on it does not compile. That guarantee
    /// is worth more than the convenience, so the tests bend around it.
    fn refusal(outcome: Result<AssumedRoleSession, StsRefusal>, expectation: &str) -> StsRefusal {
        match outcome {
            Ok(_) => panic!("{expectation}: a credential was minted instead"),
            Err(e) => e,
        }
    }

    fn request_for(tenant: &str) -> AssumeRoleWithWebIdentityRequest {
        AssumeRoleWithWebIdentityRequest {
            role_arn: format!("arn:aws:iam::{tenant}:role/{tenant}-sts-role"),
            role_session_name: "unit-session".into(),
            web_identity_token: "verified-by-the-mock".into(),
            duration_seconds: None,
        }
    }

    /// A tenant's own service account, exactly as Keycloak issues it: `aud: "account"`,
    /// `azp: <clientId>`, and nothing in it that any configured audience names.
    fn tenant_sa_claims(client_id: &str) -> Value {
        serde_json::json!({
            "iss": "https://kc.example/realms/default",
            "aud": "account",
            "azp": client_id,
            "sub": "48794dea-0000-0000-0000-000000000000",
            "preferred_username": format!("service-account-{client_id}")
        })
    }

    /// **The case the whole change exists for.** `test-s0-before` is the real clientId
    /// measured against dev1: it is in no rendered audience list, its `aud` is
    /// Keycloak's `account`, and before the bundle route every token like it was refused
    /// `InvalidIdentityToken`.
    #[tokio::test]
    async fn a_tenant_service_account_the_bundle_knows_is_accepted_though_no_audience_names_it() {
        let sts = door(
            tenant_sa_claims("test-s0-before"),
            // The list the operator really renders: the org storage client and the two
            // platform clients. The SA is in none of them.
            &["acme-storage-sa", "hf-console", "control-plane-sa"],
            Some(KnownSubjects(vec![("acme", "test-s0-before")])),
        );
        let session = sts
            .assume_role(&request_for("acme"), "sid-1")
            .await
            .expect("the bundle knows this subject for this tenant");
        assert_eq!(session.principal.sub, "test-s0-before");
        assert_eq!(
            session.principal.principal_type,
            PrincipalType::ServiceAccount
        );
        assert_eq!(session.role.tenant, "acme");

        // NEGATIVE CONTROL, on the identical claims and the identical list: with no
        // bundle wired at all the token is refused, so the acceptance above came from
        // the bundle and from nothing else.
        let unwired = door(
            tenant_sa_claims("test-s0-before"),
            &["acme-storage-sa", "hf-console", "control-plane-sa"],
            None,
        );
        assert_eq!(
            unwired
                .assume_role(&request_for("acme"), "sid-1")
                .await
                .err(),
            Some(StsRefusal::InvalidIdentityToken(
                "neither `aud` nor `azp` names an audience this gateway accepts, and `azp` \
                 does not name a service account known to the requested tenant"
                    .into()
            ))
        );
    }

    /// **The tenant scoping, measured where it could actually fail.** `warehouse` is
    /// routable and its role name is right, so the ONLY thing standing between this
    /// token and a `warehouse` credential is that `warehouse`'s subject map does not
    /// name it.
    #[tokio::test]
    async fn the_same_service_account_is_refused_against_another_tenants_role_arn() {
        let known = || KnownSubjects(vec![("acme", "test-s0-before")]);
        let audiences = ["acme-storage-sa"];

        // POSITIVE CONTROL first: the tenant that does know it.
        assert!(
            door(
                tenant_sa_claims("test-s0-before"),
                &audiences,
                Some(known())
            )
            .assume_role(&request_for("acme"), "sid-1")
            .await
            .is_ok()
        );

        let err = refusal(
            door(
                tenant_sa_claims("test-s0-before"),
                &audiences,
                Some(known()),
            )
            .assume_role(&request_for("warehouse"), "sid-2")
            .await,
            "warehouse's bundle does not name this subject",
        );
        assert_eq!(err.code(), "InvalidIdentityToken");
        // The refusal names neither the tenant nor the subject: this endpoint is
        // internet-reachable (D22).
        assert!(!err.message().contains("warehouse"), "{}", err.message());
        assert!(
            !err.message().contains("test-s0-before"),
            "{}",
            err.message()
        );
    }

    /// A client id nothing knows is refused by both routes — the ordinary case, and the
    /// one that proves the bundle route is a *lookup* rather than a way in.
    #[tokio::test]
    async fn an_unknown_client_id_is_refused_by_both_routes() {
        let sts = door(
            tenant_sa_claims("attacker-client"),
            &["acme-storage-sa"],
            Some(KnownSubjects(vec![("acme", "test-s0-before")])),
        );
        let err = refusal(
            sts.assume_role(&request_for("acme"), "sid-1").await,
            "nothing names this client",
        );
        assert_eq!(err.code(), "InvalidIdentityToken");
        assert_eq!(err.status(), 400);
    }

    /// **Additivity, which is the constraint this change had to meet: nothing that is
    /// accepted today may become refused.**
    ///
    /// Every shape the configured list accepts — `aud` as a string, `aud` as an array,
    /// `azp`, `client_id`, and a human's console token — is driven through the door
    /// twice: once with **no bundle** (the build that predates this change) and once
    /// with a bundle that knows **nothing at all**. Both must mint. A bundle route that
    /// could ever narrow route 1 fails here.
    #[tokio::test]
    async fn every_token_the_configured_list_accepts_today_is_still_accepted() {
        let accepted_today = [
            serde_json::json!({ "aud": "acme-storage-sa", "sub": "u-1" }),
            serde_json::json!({ "aud": ["account", "acme-storage-sa"], "sub": "u-2" }),
            serde_json::json!({ "aud": "account", "azp": "hf-console", "sub": "u-3",
                                "preferred_username": "alice" }),
            serde_json::json!({ "aud": "account", "client_id": "control-plane-sa",
                                "sub": "u-4" }),
            // A service account whose clientId the operator DID name in stsAudiences:
            // route 1, and it must not start depending on the bundle.
            serde_json::json!({ "aud": "account", "azp": "control-plane-sa",
                                "sub": "u-5",
                                "preferred_username": "service-account-control-plane-sa" }),
        ];
        for claims in accepted_today {
            for (label, known) in [
                ("no bundle wired at all", None),
                (
                    "a bundle that knows nothing",
                    Some(KnownSubjects(Vec::new())),
                ),
            ] {
                let sts = door(
                    claims.clone(),
                    &["acme-storage-sa", "hf-console", "control-plane-sa"],
                    known,
                );
                assert!(
                    sts.assume_role(&request_for("acme"), "sid-1").await.is_ok(),
                    "{claims} was accepted before the bundle route and must still be \
                     accepted with {label}"
                );
            }
        }
    }

    /// An empty bundle is the seed bundle every pod boots on, and a stale one is what a
    /// broken poll leaves behind. Neither may widen anything, and neither may take route
    /// 1 away — the configured list is not sourced from the bundle at all.
    #[tokio::test]
    async fn an_empty_bundle_refuses_the_bundle_route_and_still_honours_the_configured_list() {
        // Route 2, against an empty bundle: refused.
        let empty = door(
            tenant_sa_claims("test-s0-before"),
            &["acme-storage-sa"],
            Some(KnownSubjects(Vec::new())),
        );
        assert_eq!(
            refusal(
                empty.assume_role(&request_for("acme"), "sid-1").await,
                "an empty bundle knows nobody",
            )
            .code(),
            "InvalidIdentityToken"
        );
        // Route 1, against the same empty bundle: unaffected.
        let configured = door(
            serde_json::json!({ "aud": "account", "azp": "acme-storage-sa", "sub": "u" }),
            &["acme-storage-sa"],
            Some(KnownSubjects(Vec::new())),
        );
        assert!(
            configured
                .assume_role(&request_for("acme"), "sid-1")
                .await
                .is_ok(),
            "an empty bundle must not be able to refuse a token the configured list accepts"
        );
    }

    /// The bundle route reads `azp`/`client_id` and composes the `sa:` prefix itself, so
    /// there is no claim a human's token can carry that reaches a service account's key
    /// space — and no `aud` value that reaches the bundle route at all.
    #[tokio::test]
    async fn the_bundle_route_reads_only_azp_and_never_aud_or_sub() {
        let known = || KnownSubjects(vec![("acme", "test-s0-before")]);
        for claims in [
            // `sub` naming the service account: the OTHER key space, ignored here.
            serde_json::json!({ "aud": "account", "sub": "test-s0-before" }),
            // `aud` naming it: an audience is not a principal.
            serde_json::json!({ "aud": "test-s0-before", "sub": "u" }),
            serde_json::json!({ "aud": ["account", "test-s0-before"], "sub": "u" }),
            // `preferred_username` naming it, with an azp that does not.
            serde_json::json!({ "aud": "account", "azp": "hf-console", "sub": "u",
                                "preferred_username": "service-account-test-s0-before" }),
            // No client id at all.
            serde_json::json!({ "aud": "account", "sub": "u" }),
        ] {
            let sts = door(claims.clone(), &["acme-storage-sa"], Some(known()));
            assert_eq!(
                refusal(
                    sts.assume_role(&request_for("acme"), "sid-1").await,
                    &format!("{claims} must not reach the bundle route"),
                )
                .code(),
                "InvalidIdentityToken",
                "{claims}"
            );
        }
    }

    /// Acceptance is decided **before** the role name and the routing table, exactly
    /// where it was before, so a token the bundle route accepts still gets the uniform
    /// `AccessDenied` for a wrong role name — and a token neither route accepts still
    /// answers the token error rather than the tenant one.
    #[tokio::test]
    async fn bundle_acceptance_does_not_reorder_the_role_and_tenant_checks() {
        let wrong_role = AssumeRoleWithWebIdentityRequest {
            role_arn: "arn:aws:iam::acme:role/not-the-role".into(),
            ..request_for("acme")
        };
        let sts = door(
            tenant_sa_claims("test-s0-before"),
            &["acme-storage-sa"],
            Some(KnownSubjects(vec![("acme", "test-s0-before")])),
        );
        assert_eq!(
            sts.assume_role(&wrong_role, "sid-1").await.err(),
            Some(StsRefusal::AccessDenied)
        );

        // …and a token the bundle does not know, against a tenant that does not exist,
        // still answers the *token* error: the tenant is not disclosed by ordering.
        let unknown = door(
            tenant_sa_claims("test-s0-before"),
            &["acme-storage-sa"],
            Some(KnownSubjects(vec![("acme", "test-s0-before")])),
        );
        assert_eq!(
            refusal(
                unknown
                    .assume_role(&request_for("no-such-tenant"), "sid-1")
                    .await,
                "a subject no tenant knows is refused",
            )
            .code(),
            "InvalidIdentityToken"
        );
    }

    // ── the wire documents ──────────────────────────────────────────────────────

    fn session() -> AssumedRoleSession {
        AssumedRoleSession {
            access_key_id: "HFSTk0.sid-1".into(),
            secret_access_key: "deadbeef".into(),
            session_token: "aaa.bbb.ccc".into(),
            expires_at: 1_800_000_000,
            role: RoleArn {
                tenant: "acme".into(),
                role_name: "acme-sts-role".into(),
            },
            role_session_name: "my-session".into(),
            principal: WebIdentityPrincipal {
                sub: "pipeline-runner".into(),
                principal_type: PrincipalType::ServiceAccount,
                token_subject: "b6d2c1f0".into(),
            },
            audience: "account".into(),
            issuer: "https://kc.example/realms/default".into(),
        }
    }

    /// **The detail that decides whether any SDK can use this at all.**
    ///
    /// The existing JSON mint returns `Expiration` as a Unix integer. Every AWS SDK
    /// parses this field as ISO-8601 and treats a bare number as a malformed response,
    /// so a numeric value here would reject a credential that is otherwise perfect.
    #[test]
    fn expiration_is_iso8601_and_never_a_unix_integer() {
        let xml = render_assume_role_response(&session(), "req-1");
        assert!(
            xml.contains("<Expiration>2027-01-15T08:00:00Z</Expiration>"),
            "{xml}"
        );
        assert!(
            !xml.contains("<Expiration>1800000000</Expiration>"),
            "a numeric Expiration is rejected by every AWS SDK"
        );
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn the_response_carries_every_element_an_sdk_reads() {
        let xml = render_assume_role_response(&session(), "req-1");
        for needle in [
            r#"<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">"#,
            "<AssumeRoleWithWebIdentityResult>",
            "<Credentials>",
            "<AccessKeyId>HFSTk0.sid-1</AccessKeyId>",
            "<SecretAccessKey>deadbeef</SecretAccessKey>",
            "<SessionToken>aaa.bbb.ccc</SessionToken>",
            "<SubjectFromWebIdentityToken>b6d2c1f0</SubjectFromWebIdentityToken>",
            "<Audience>account</Audience>",
            "<Arn>arn:aws:sts::acme:assumed-role/acme-sts-role/my-session</Arn>",
            "<AssumedRoleId>acme-sts-role:my-session</AssumedRoleId>",
            "<RequestId>req-1</RequestId>",
        ] {
            assert!(xml.contains(needle), "missing {needle}\nin {xml}");
        }
    }

    #[test]
    fn the_error_document_is_the_sts_envelope_not_the_s3_one() {
        let xml = render_error_response(&StsRefusal::AccessDenied, "req-2");
        assert!(xml.contains("<ErrorResponse"), "{xml}");
        assert!(xml.contains("<Type>Sender</Type>"), "{xml}");
        assert!(xml.contains("<Code>AccessDenied</Code>"), "{xml}");
        assert!(xml.contains("<RequestId>req-2</RequestId>"), "{xml}");
        // S3's shape (a bare <Error> root) would be parsed as "unknown error" by an
        // SDK's STS deserializer.
        assert!(!xml.starts_with("<Error>"), "{xml}");
    }

    #[test]
    fn every_error_code_and_status_is_the_aws_one() {
        // An SDK acts on these: it retries a 5xx and does not retry a 400, and a user
        // reads the code. Pinned as a table so a new variant cannot quietly answer
        // `InternalFailure` to a client mistake.
        let cases = [
            (StsRefusal::Validation("x".into()), 400, "ValidationError"),
            (
                StsRefusal::InvalidAction("Nope".into()),
                400,
                "InvalidAction",
            ),
            (
                StsRefusal::InvalidIdentityToken("x".into()),
                400,
                "InvalidIdentityToken",
            ),
            (StsRefusal::ExpiredToken, 400, "ExpiredTokenException"),
            (
                StsRefusal::IdpRejectedClaim("x".into()),
                403,
                "IDPRejectedClaim",
            ),
            (StsRefusal::AccessDenied, 403, "AccessDenied"),
            (StsRefusal::Internal("x".into()), 500, "InternalFailure"),
        ];
        for (refusal, status, code) in cases {
            assert_eq!(refusal.status(), status, "{refusal:?}");
            assert_eq!(refusal.code(), code, "{refusal:?}");
        }
    }

    /// A refusal must never let an internet-reachable caller learn whether a tenant
    /// exists, and must never carry an internal detail.
    #[test]
    fn a_refusal_discloses_neither_the_tenant_nor_the_internal_reason() {
        let denied = StsRefusal::AccessDenied.message();
        assert!(!denied.contains("acme"), "{denied}");
        assert!(!denied.to_lowercase().contains("routable"), "{denied}");
        let internal = StsRefusal::Internal("current_kid is not in the key ring".into());
        assert!(
            !internal.message().contains("key ring"),
            "{}",
            internal.message()
        );
    }

    #[test]
    fn every_interpolated_value_is_xml_escaped() {
        assert_eq!(
            xml_escape("a&b<c>d\"e'f"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
        // Reached through the real renderer, on the field an SDK would echo back.
        let mut s = session();
        s.audience = "a<b>&c".into();
        let xml = render_assume_role_response(&s, "r");
        assert!(
            xml.contains("<Audience>a&lt;b&gt;&amp;c</Audience>"),
            "{xml}"
        );
        assert!(!xml.contains("<Audience>a<b>"), "{xml}");
        // …and on an error message, which interpolates caller-supplied text.
        let xml = render_error_response(&StsRefusal::InvalidAction("<evil>".into()), "r");
        assert!(xml.contains("&lt;evil&gt;"), "{xml}");
        assert!(!xml.contains("<evil>"), "{xml}");
    }
}
