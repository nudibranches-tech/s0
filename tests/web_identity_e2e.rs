//! **An off-the-shelf S3 client can get a credential and use it**, proven by execution: an
//! RS256-signed service-account token posted form-encoded to the production
//! `mint::serve_with_shutdown` accept loop as `Action=AssumeRoleWithWebIdentity`, parsed
//! out of XML the way an SDK does, then used to SigV4-sign a real `GetObject` against the
//! production S3 front — with the decision document read out of the capture sink.
//!
//! The bundle keys a service account's grants under `sa:<clientId>` and a user's under
//! `user:<oidc sub>`; an SA token's `sub` is a user id in no bundle, so a surface that
//! resolves the principal wrongly mints a credential authorized against nothing. The two
//! principals here hold **different prefixes**, so neither direction passes on a constant.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::sigv4::RawRequest;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use s0::auth::SECURITY_TOKEN_HEADER;
use s0::config::StsMintConfig;
use s0::mint::{Mint, StandardVerifier};
use s0::webidentity::{WebIdentityConfig, WebIdentitySts};

const PRIVATE_PEM: &str = include_str!("testdata/oidc_test_rsa.pem");
const PUBLIC_PEM: &str = include_str!("testdata/oidc_test_rsa_pub.pem");

/// The realm URL the identity provider puts in `iss`.
const ISSUER: &str = "https://kc.example/realms/default";
/// The OIDC client the operator provisions for storage — the same value it already
/// hands RGW's role as an accepted client id.
const STORAGE_CLIENT: &str = "acme-storage";

/// The tenant and organization `tests/common` routes. The tenant is named by the
/// **RoleArn**; the organization is never named by the caller at all.
const TENANT: &str = "acme";
const ORG: &str = "org-acme";

/// `{tenant}-sts-role` — byte-identical to the role name the control plane provisions in
/// RGW, so a client repointed from RGW STS to s0 changes its endpoint and nothing else.
const ROLE_TEMPLATE: &str = "{tenant}-sts-role";
fn role_arn() -> String {
    format!("arn:aws:iam::{TENANT}:role/{TENANT}-sts-role")
}

/// The service account's OIDC **clientId** — the key the bundle uses.
const SA_CLIENT_ID: &str = "pipeline-runner";
/// The service-account *user* id the token carries in `sub`. In no bundle.
const SA_TOKEN_SUB: &str = "b6d2c1f0-0000-0000-0000-000000000000";
/// A human's OIDC subject.
const USER_SUB: &str = "oidc-sub-alice";

/// The configured session-duration ceiling.
const MAX_DURATION: u64 = 3600;

/// `sa:pipeline-runner` may read under `sa/`; `user:oidc-sub-alice` may read under
/// `human/`. Disjoint on purpose — see the module docs.
fn bundle() -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false, "reserved_tag_keys": ["acme/*"] },
        "tenants": { TENANT: {
            "user_attributes": {
                SA_CLIENT_ID: { "groups": ["editor"], "attributes": [] },
                USER_SUB: { "groups": ["viewer"], "attributes": [] }
            },
            "bucket_attributes": { "reports": { "denylist": {} } },
            "s3_grants": {
                SA_CLIENT_ID: [
                    { "bucket": "reports", "actions": ["read_objects"], "prefixes": ["sa/"] }
                ],
                USER_SUB: [
                    { "bucket": "reports", "actions": ["read_objects"], "prefixes": ["human/"] }
                ]
            },
            "group_grants": {}
        }}
    })
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// A service-account access token, field for field. Two details are load-bearing:
///
/// * **`aud` holds `account` *and* the storage client.** `account` alone means "issued for
///   nothing in particular"; the storage client is what an **audience mapper** adds, and
///   what makes the token say "issued for this gateway's STS".
/// * **`azp` is the SA's own clientId, not the audience** — the *subject* half, which the
///   bundle keys `sa:<clientId>` on.
fn service_account_token(client_id: &str) -> String {
    sign(serde_json::json!({
        "iss": ISSUER,
        "aud": ["account", STORAGE_CLIENT],
        "azp": client_id,
        "sub": SA_TOKEN_SUB,
        "preferred_username": format!("service-account-{client_id}"),
        "exp": now() + 3600,
        "iat": now(),
    }))
}

/// A human user's token: same realm and audience binding, but `preferred_username` is a
/// person and `azp` is an interactive client.
fn user_token() -> String {
    sign(serde_json::json!({
        "iss": ISSUER,
        "aud": ["account", STORAGE_CLIENT],
        "azp": "hf-console",
        "sub": USER_SUB,
        "preferred_username": "alice",
        "exp": now() + 3600,
        "iat": now(),
    }))
}

fn sign(claims: serde_json::Value) -> String {
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).expect("rsa key"),
    )
    .expect("sign")
}

fn mint_config() -> StsMintConfig {
    StsMintConfig {
        listen: "127.0.0.1:0".parse().expect("addr"),
        issuer: ISSUER.into(),
        // The bearer door's audience. Deliberately NOT one of the web-identity
        // audiences, so nothing here can pass because the two happen to coincide.
        audience: "s0-bearer-door".into(),
        jwks_uri: None,
        public_key_pem: Some(PUBLIC_PEM.to_string()),
        sub_claim: "sub".into(),
        groups_claim: "groups".into(),
        tenant_claim: "tenant".into(),
        org_claim: "org".into(),
        jwks_timeout_secs: 5,
        jwks_refresh_secs: 0,
        web_identity_enabled: true,
        // The same list the operator already hands RGW's role.
        web_identity_audiences: vec![
            STORAGE_CLIENT.into(),
            "hf-console".into(),
            "control-plane-sa".into(),
        ],
        role_name_template: Some(ROLE_TEMPLATE.into()),
        max_duration_secs: MAX_DURATION,
        // The listener's hardening bounds, left at the production defaults on purpose:
        // every test here drives one request at a time, so a test tripping a bound means
        // the bound is wrong for real traffic too. `tests/mint_hardening.rs` pushes them.
        max_connections: 256,
        connection_timeout_secs: 30,
    }
}

struct Harness {
    fx: common::Fixture,
    s3_base: String,
    sts_base: String,
}

/// Boot the **production** serving paths: `server::serve_with_shutdown` for the S3 data
/// plane and `mint::serve_with_shutdown` for the STS door, on two real sockets, over one
/// `StsAuthority` and one `BackendRegistry` — the same expressions `main.rs` uses. A
/// second authority would make the file measure a credential nothing else could honour.
async fn harness(tag: &str) -> Harness {
    harness_with(tag, mint_config()).await
}

async fn harness_with(tag: &str, cfg: StsMintConfig) -> Harness {
    harness_over(tag, cfg, bundle()).await
}

async fn harness_over(tag: &str, cfg: StsMintConfig, bundle: serde_json::Value) -> Harness {
    let fx = common::fixture(tag, bundle);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind s3");
    let s3_addr: SocketAddr = listener.local_addr().expect("addr");
    drop(listener);
    let gw = fx.gw.clone();
    tokio::spawn(async move {
        let _ = s0::server::serve_with_shutdown(gw, s3_addr, std::future::pending::<()>()).await;
    });

    let verifier = Arc::new(StandardVerifier::from_config(&cfg).expect("verifier"));
    let web_identity = Arc::new(
        WebIdentitySts::new(
            verifier.clone(),
            fx.gw.identity.sts(),
            fx.gw.registry.clone(),
            WebIdentityConfig::from_config(&cfg, Duration::from_secs(900)),
        )
        // The gateway's OWN BundleStore — the one the PDP decides against and the
        // poller swaps — exactly as `main.rs` wires it. A separate store here would
        // make every bundle-route test measure a document the data plane does not use.
        .with_bundle_subjects(fx.gw.bundles.clone()),
    );
    let mint = Arc::new(
        Mint::new(verifier, fx.gw.identity.sts(), Duration::from_secs(900))
            .with_web_identity(web_identity),
    );
    let sts_listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind sts");
    let sts_addr: SocketAddr = sts_listener.local_addr().expect("addr");
    drop(sts_listener);
    tokio::spawn(async move {
        let _ = s0::mint::serve_with_shutdown(mint, sts_addr, std::future::pending::<()>()).await;
    });

    for _ in 0..200 {
        let up = tokio::net::TcpStream::connect(s3_addr).await.is_ok()
            && tokio::net::TcpStream::connect(sts_addr).await.is_ok();
        if up {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    Harness {
        fx,
        s3_base: format!("http://{s3_addr}"),
        sts_base: format!("http://{sts_addr}"),
    }
}

/// One `AssumeRoleWithWebIdentity` call, exactly as an SDK issues it: `POST /`,
/// `application/x-www-form-urlencoded`, no `Authorization` header of any kind.
async fn assume_role(h: &Harness, form: &[(&str, &str)]) -> (u16, String) {
    let body = form
        .iter()
        .map(|(k, v)| format!("{}={}", url_encode(k), url_encode(v)))
        .collect::<Vec<_>>()
        .join("&");
    let resp = reqwest::Client::new()
        .post(&h.sts_base)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(body)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("the STS listener answered");
    (
        resp.status().as_u16(),
        resp.text().await.unwrap_or_default(),
    )
}

/// The default call: a service-account token assuming the tenant's role.
async fn assume_role_ok(h: &Harness, token: &str) -> Session {
    let (status, xml) = assume_role(
        h,
        &[
            ("Action", "AssumeRoleWithWebIdentity"),
            ("Version", "2011-06-15"),
            ("RoleArn", &role_arn()),
            ("RoleSessionName", "e2e-session"),
            ("WebIdentityToken", token),
        ],
    )
    .await;
    assert_eq!(status, 200, "AssumeRoleWithWebIdentity refused: {xml}");
    Session::parse(&xml)
}

fn url_encode(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    for b in v.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A credential as an SDK reads it off the XML.
struct Session {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
    expiration: String,
}

impl Session {
    fn parse(xml: &str) -> Self {
        Session {
            access_key_id: element(xml, "AccessKeyId"),
            secret_access_key: element(xml, "SecretAccessKey"),
            session_token: element(xml, "SessionToken"),
            expiration: element(xml, "Expiration"),
        }
    }
}

/// Pull one element's text out of the document. Hand-rolled and unforgiving on purpose:
/// the tag must be present and closed, so a renamed element panics here rather than
/// yielding an empty string a later assertion compares to something else empty.
fn element(xml: &str, name: &str) -> String {
    let open = format!("<{name}>");
    let close = format!("</{name}>");
    let start = xml
        .find(&open)
        .unwrap_or_else(|| panic!("<{name}> missing from the STS response:\n{xml}"))
        + open.len();
    let end = xml[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("</{name}> missing from the STS response:\n{xml}"))
        + start;
    xml[start..end].to_string()
}

/// `GET /reports/<key>`, SigV4-signed with the minted credentials and carrying the
/// session token — i.e. what any AWS SDK configured from this response puts on the wire.
async fn get_object(h: &Harness, session: &Session, key: &str) -> (u16, String) {
    let host = h.s3_base.trim_start_matches("http://").to_string();
    let req = RawRequest::new("GET", format!("/reports/{key}"))
        .header(SECURITY_TOKEN_HEADER, &session.session_token);
    let headers = req.sign(&host, &session.access_key_id, &session.secret_access_key);

    let mut builder = reqwest::Client::new()
        .request(reqwest::Method::GET, req.url(&h.s3_base))
        .timeout(Duration::from_secs(10));
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder.send().await.expect("the S3 front answered");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

/// The last `OpaInput` the enforce path handed the PDP, as the PDP saw it.
fn last_opa_input(h: &Harness) -> serde_json::Value {
    h.fx.capture
        .snapshot()
        .last()
        .expect("the enforce path asked for a decision")
        .raw
        .clone()
}

// ── the proof ──────────────────────────────────────────────────────────────────

/// **The headline.** A service-account token, through the real STS wire protocol, produces
/// a credential the S3 data plane accepts and evaluates as `sa:<clientId>` in the tenant
/// the RoleArn named.
#[tokio::test]
async fn a_service_account_token_mints_a_credential_that_works_against_s3() {
    let h = harness("webid-e2e-sa").await;
    let session = assume_role_ok(&h, &service_account_token(SA_CLIENT_ID)).await;

    // The credential shape the data plane recognises. A non-STS key would be answered
    // by the static store instead and the session token never consulted.
    assert!(
        session.access_key_id.starts_with("HFST"),
        "not an STS access key: {}",
        session.access_key_id
    );
    assert!(!session.secret_access_key.is_empty());
    assert!(!session.session_token.is_empty());

    // 1. SIGNATURE + IDENTITY. `sa/q1.csv` is inside the grant, so the request passes
    //    `check` (signature verified against the derived secret, identity resolved from
    //    the session token) AND the policy, and reaches the forward — where the
    //    fixture's backend (port 1) is not listening. Anything refused at the gate
    //    answers 403.
    let (status, body) = get_object(&h, &session, "sa/q1.csv").await;
    assert_ne!(
        status, 403,
        "a credential minted through AssumeRoleWithWebIdentity was refused by the S3 \
         data plane: {body}"
    );

    // 2. THE DECISION DOCUMENT, read from the tap inside `GatewayAccess::decide` — the
    //    document the PDP was handed, not a reconstruction of it.
    let input = last_opa_input(&h);
    assert_eq!(
        input["principal"]["type"],
        serde_json::json!("service_account"),
        "a Keycloak service-account token was evaluated as something else: {input}"
    );
    assert_eq!(
        input["principal"]["sub"],
        serde_json::json!(SA_CLIENT_ID),
        "an SA must be keyed by its clientId; keyed by the token's sub it finds no \
         grants at all: {input}"
    );
    assert_ne!(input["principal"]["sub"], serde_json::json!(SA_TOKEN_SUB));

    // 3. THE TENANT CAME FROM THE ROLE ARN, and the ORGANIZATION came from s0's own
    //    routing table — the caller never named one and there is no claim to take it
    //    from.
    assert_eq!(input["tenant"], serde_json::json!(TENANT));
    assert_eq!(input["organization_id"], serde_json::json!(ORG));
    assert_eq!(input["action"], serde_json::json!("read_objects"));
    assert_eq!(input["object"], serde_json::json!("sa/q1.csv"));

    // 4. …and the identity is load-bearing rather than decorative: the same credential
    //    on the *user's* prefix is denied by the same policy.
    let (status, _) = get_object(&h, &session, "human/private.csv").await;
    assert_eq!(
        status, 403,
        "the service account reached a prefix only the user is granted"
    );
}

/// **Two replicas behind one Service.** A credential minted by replica A is presented to
/// replica B, which has never seen the session — the ordinary case the moment the
/// deployment is scaled past one pod or a rolling update replaces the minting pod
/// mid-session.
///
/// The design makes this hold without shared state: the secret is
/// `HMAC(master_key, kid ‖ sid)` and the session is a signed token, so any replica
/// holding the configured key ring re-derives both. That is a *claim about a
/// deployment*, and it is the kind that stays true right up until someone adds a cache,
/// a nonce table or a per-process salt to the session path — at which point it fails
/// under load balancing and nowhere else. Asserted here rather than argued from the
/// design, because the failure is a 403 on a valid credential in production.
#[tokio::test]
async fn a_credential_minted_on_one_replica_is_honoured_by_another() {
    // Two independent gateways: separate sockets, PDP, bundle store, capture tap, audit
    // sink and spill directory. All they have in common is the config — including the
    // STS key ring, which is the only thing a real pair of replicas shares.
    let a = harness("ha-replica-a").await;
    let b = harness("ha-replica-b").await;

    let session = assume_role_ok(&a, &service_account_token(SA_CLIENT_ID)).await;

    // The credential crosses to the replica that did not mint it.
    let (status, body) = get_object(&b, &session, "sa/q1.csv").await;
    assert_ne!(
        status, 403,
        "replica B refused a credential replica A minted — with a shared key ring this \
         is the load-balanced request failing, not a policy denial: {body}"
    );

    // B resolved the principal from the token itself, to the same subject A would have.
    // A session that only works where it was minted is not visible as a signature
    // failure; it surfaces as an identity that resolves to nothing and a denial the
    // policy appears to have made.
    let input = last_opa_input(&b);
    assert_eq!(input["principal"]["sub"], serde_json::json!(SA_CLIENT_ID));
    assert_eq!(
        input["principal"]["type"],
        serde_json::json!("service_account")
    );
    assert_eq!(input["tenant"], serde_json::json!(TENANT));

    // And the minting replica was not in the path: no decision reached A, so B is not
    // quietly relying on state that only exists because A is still alive in this process.
    assert!(
        a.fx.capture.snapshot().is_empty(),
        "replica A evaluated a request that was sent to replica B"
    );

    // Control. Everything above would also hold on a data plane that accepted any
    // signature at all, which is the more alarming way to pass: the same request to the
    // same replica, signed with a secret one hex digit off, must be refused.
    let mut wrong: Vec<char> = session.secret_access_key.chars().collect();
    wrong[0] = if wrong[0] == '0' { '1' } else { '0' };
    let forged = Session {
        access_key_id: session.access_key_id.clone(),
        secret_access_key: wrong.into_iter().collect(),
        session_token: session.session_token.clone(),
        expiration: session.expiration.clone(),
    };
    let (status, _) = get_object(&b, &forged, "sa/q1.csv").await;
    assert_eq!(
        status, 403,
        "replica B accepted a request signed with the wrong secret, so its acceptance \
         of the real one proves nothing"
    );
}

/// The other half of the same claim: a human's token mints a **user** session, keyed by
/// `sub`, and is refused on the service account's prefix. Without this, the test above
/// would pass on a surface that hard-coded `ServiceAccount` — which is precisely the bug
/// the bearer mint has in the other direction.
#[tokio::test]
async fn a_user_token_mints_a_user_session_and_cannot_reach_the_service_accounts_prefix() {
    let h = harness("webid-e2e-user").await;
    let session = assume_role_ok(&h, &user_token()).await;

    let (status, body) = get_object(&h, &session, "human/notes.txt").await;
    assert_ne!(
        status, 403,
        "the user was refused on its own prefix: {body}"
    );

    let input = last_opa_input(&h);
    assert_eq!(input["principal"]["type"], serde_json::json!("user"));
    assert_eq!(input["principal"]["sub"], serde_json::json!(USER_SUB));
    // An `azp` is on this token too. If it were read as a client id, the subject would be
    // that client and every interactive user would share one key space.
    assert_ne!(input["principal"]["sub"], serde_json::json!("hf-console"));

    let (status, _) = get_object(&h, &session, "sa/q1.csv").await;
    assert_eq!(status, 403, "the user reached the service account's prefix");
}

/// **The detail that decides whether an SDK can use the response at all.**
///
/// The existing JSON mint returns `Expiration` as a Unix integer. Every AWS SDK parses
/// this field as ISO-8601 and treats a bare number as a malformed response, so a numeric
/// value would reject an otherwise perfect credential. Asserted here on the real wire
/// bytes, not on the renderer.
#[tokio::test]
async fn the_expiration_on_the_wire_is_iso8601_and_within_the_configured_ceiling() {
    let h = harness("webid-e2e-exp").await;
    let before = now();
    let session = assume_role_ok(&h, &service_account_token(SA_CLIENT_ID)).await;

    let parsed = chrono::DateTime::parse_from_rfc3339(&session.expiration)
        .unwrap_or_else(|e| panic!("Expiration {:?} is not ISO-8601: {e}", session.expiration));
    assert!(
        session.expiration.ends_with('Z'),
        "Expiration must be UTC: {}",
        session.expiration
    );
    assert!(
        session.expiration.parse::<u64>().is_err(),
        "a numeric Expiration is rejected by every AWS SDK: {}",
        session.expiration
    );
    let expires = parsed.timestamp() as u64;
    assert!(expires > before, "the credential is already expired");
    assert!(
        expires <= before + MAX_DURATION + 5,
        "expiry {expires} exceeds the configured ceiling"
    );
}

/// **Clamp, not refuse.** A `DurationSeconds` above the ceiling still yields a working
/// credential with a shorter life, because an SDK reads `Expiration` and schedules its own
/// refresh from it — whereas AWS's `ValidationError` fails credential acquisition outright
/// and the workload never starts. A deliberate deviation from AWS.
#[tokio::test]
async fn a_duration_above_the_ceiling_is_clamped_rather_than_refused() {
    let h = harness("webid-e2e-clamp").await;
    let before = now();
    let (status, xml) = assume_role(
        &h,
        &[
            ("Action", "AssumeRoleWithWebIdentity"),
            ("RoleArn", &role_arn()),
            ("RoleSessionName", "long-session"),
            ("WebIdentityToken", &service_account_token(SA_CLIENT_ID)),
            // 12 hours — RGW's own default ceiling, so a client migrating from the RGW
            // STS path really will ask for this.
            ("DurationSeconds", "43200"),
        ],
    )
    .await;
    assert_eq!(
        status, 200,
        "an over-cap duration must not be refused: {xml}"
    );
    let expires = chrono::DateTime::parse_from_rfc3339(&element(&xml, "Expiration"))
        .expect("iso8601")
        .timestamp() as u64;
    assert!(
        expires <= before + MAX_DURATION + 5,
        "the ceiling was not applied: expiry is {} s away",
        expires.saturating_sub(before)
    );
    // …and the clamped credential is a real one, not a stub.
    let session = Session::parse(&xml);
    let (status, body) = get_object(&h, &session, "sa/q1.csv").await;
    assert_ne!(status, 403, "the clamped credential does not work: {body}");
}

/// A zero duration is the one request no credential can satisfy, so it is refused
/// rather than clamped up — the same split `internal::SessionRefusal::ZeroDuration`
/// makes, and the reason the clamp above is not simply "we never say no".
#[tokio::test]
async fn a_zero_duration_is_refused_rather_than_silently_turned_into_a_credential() {
    let h = harness("webid-e2e-zero").await;
    let (status, xml) = assume_role(
        &h,
        &[
            ("Action", "AssumeRoleWithWebIdentity"),
            ("RoleArn", &role_arn()),
            ("RoleSessionName", "zero-session"),
            ("WebIdentityToken", &service_account_token(SA_CLIENT_ID)),
            ("DurationSeconds", "0"),
        ],
    )
    .await;
    assert_eq!(status, 400, "{xml}");
    assert!(xml.contains("<Code>ValidationError</Code>"), "{xml}");
    assert!(
        !xml.contains("<AccessKeyId>"),
        "a refusal must mint nothing: {xml}"
    );
}

// ── refusals ───────────────────────────────────────────────────────────────────

/// Every refusal is an STS `ErrorResponse` with an AWS code — never a JSON body, never
/// an S3 `<Error>` root. An SDK's STS deserializer looks for this envelope and reports
/// "unknown error" without it, so the precision of the code is wasted if the shape is
/// wrong.
#[tokio::test]
async fn every_refusal_is_an_sts_error_document_with_the_aws_code() {
    let h = harness("webid-e2e-errors").await;
    let good = service_account_token(SA_CLIENT_ID);

    // A token signed by an attacker's key.
    let forged = encode(
        &Header::new(Algorithm::HS256),
        &serde_json::json!({
            "iss": ISSUER, "aud": "account", "azp": STORAGE_CLIENT,
            "sub": "mallory", "preferred_username": "service-account-acme-storage",
            "exp": now() + 3600
        }),
        &EncodingKey::from_secret(b"attacker-secret"),
    )
    .expect("sign");
    // A token from another realm entirely.
    let wrong_issuer = sign(serde_json::json!({
        "iss": "https://evil.example/realms/default", "aud": "account",
        "azp": STORAGE_CLIENT, "sub": "x",
        "preferred_username": format!("service-account-{STORAGE_CLIENT}"),
        "exp": now() + 3600
    }));
    // A token whose audience names no client this gateway serves.
    let wrong_audience = sign(serde_json::json!({
        "iss": ISSUER, "aud": "account", "azp": "some-other-realm-client",
        "sub": "x", "preferred_username": "service-account-some-other-realm-client",
        "exp": now() + 3600
    }));
    let expired = sign(serde_json::json!({
        "iss": ISSUER, "aud": "account", "azp": STORAGE_CLIENT, "sub": "x",
        "preferred_username": format!("service-account-{STORAGE_CLIENT}"),
        "exp": 1_000_000_000u64
    }));

    /// One refusal case: why it is here, the form fields, the expected HTTP status, and
    /// the expected AWS `<Code>`.
    struct Case<'a> {
        why: &'a str,
        form: Vec<(&'a str, &'a str)>,
        status: u16,
        code: &'a str,
    }
    let case = |why, form, status, code| Case {
        why,
        form,
        status,
        code,
    };

    let cases = vec![
        case(
            "an action this endpoint does not implement",
            vec![("Action", "GetCallerIdentity")],
            400,
            "InvalidAction",
        ),
        case(
            "no RoleArn",
            vec![
                ("Action", "AssumeRoleWithWebIdentity"),
                ("RoleSessionName", "s1"),
                ("WebIdentityToken", &good),
            ],
            400,
            "ValidationError",
        ),
        case(
            "an untenanted RoleArn — the form RGW emits when no tenant is set",
            vec![
                ("Action", "AssumeRoleWithWebIdentity"),
                ("RoleArn", "arn:aws:iam:::role/acme-sts-role"),
                ("RoleSessionName", "s2"),
                ("WebIdentityToken", &good),
            ],
            400,
            "ValidationError",
        ),
        case(
            "a forged signature",
            vec![
                ("Action", "AssumeRoleWithWebIdentity"),
                ("RoleArn", "arn:aws:iam::acme:role/acme-sts-role"),
                ("RoleSessionName", "s3"),
                ("WebIdentityToken", &forged),
            ],
            400,
            "InvalidIdentityToken",
        ),
        case(
            "a token from another issuer",
            vec![
                ("Action", "AssumeRoleWithWebIdentity"),
                ("RoleArn", "arn:aws:iam::acme:role/acme-sts-role"),
                ("RoleSessionName", "s4"),
                ("WebIdentityToken", &wrong_issuer),
            ],
            400,
            "InvalidIdentityToken",
        ),
        case(
            "a token naming no accepted audience",
            vec![
                ("Action", "AssumeRoleWithWebIdentity"),
                ("RoleArn", "arn:aws:iam::acme:role/acme-sts-role"),
                ("RoleSessionName", "s5"),
                ("WebIdentityToken", &wrong_audience),
            ],
            400,
            "InvalidIdentityToken",
        ),
        case(
            "an expired token — distinct from any other invalid token, because an SDK \
             retries this one after re-reading its projected token file",
            vec![
                ("Action", "AssumeRoleWithWebIdentity"),
                ("RoleArn", "arn:aws:iam::acme:role/acme-sts-role"),
                ("RoleSessionName", "s6"),
                ("WebIdentityToken", &expired),
            ],
            400,
            "ExpiredTokenException",
        ),
        case(
            "a tenant this gateway does not route",
            vec![
                ("Action", "AssumeRoleWithWebIdentity"),
                ("RoleArn", "arn:aws:iam::globex:role/globex-sts-role"),
                ("RoleSessionName", "s7"),
                ("WebIdentityToken", &good),
            ],
            403,
            "AccessDenied",
        ),
        case(
            "a role name this gateway does not serve",
            vec![
                ("Action", "AssumeRoleWithWebIdentity"),
                ("RoleArn", "arn:aws:iam::acme:role/typo"),
                ("RoleSessionName", "s8"),
                ("WebIdentityToken", &good),
            ],
            403,
            "AccessDenied",
        ),
    ];

    for Case {
        why,
        form,
        status,
        code,
    } in cases
    {
        let (got, xml) = assume_role(&h, &form).await;
        assert_eq!(got, status, "{why}: {xml}");
        assert!(
            xml.contains("<ErrorResponse"),
            "{why}: not an STS envelope: {xml}"
        );
        assert!(
            xml.contains(&format!("<Code>{code}</Code>")),
            "{why}: expected {code}: {xml}"
        );
        assert!(
            !xml.contains("<AccessKeyId>"),
            "{why}: a refusal minted a credential: {xml}"
        );
    }

    // POSITIVE CONTROL: the same harness still mints for a well-formed call, so none of
    // the above passed because the surface is simply broken.
    let session = assume_role_ok(&h, &good).await;
    assert!(session.access_key_id.starts_with("HFST"));
}

/// **A realm token is not a gateway token.** The default `aud` for
/// `grant_type=client_credentials` is `account`, which rides on every token the realm
/// issues; accepting it would let any service in the realm exchange a token it holds for
/// storage credentials. So the token must carry a configured audience (`aud`) or a known
/// client (`azp`) — that audience mapper is the flow's one deployment prerequisite.
#[tokio::test]
async fn the_audience_binding_is_required_and_account_alone_is_not_one() {
    let h = harness("webid-e2e-aud").await;
    // Exactly what the IdP issues with no audience mapper configured.
    let unbound = sign(serde_json::json!({
        "iss": ISSUER,
        "aud": "account",
        "azp": SA_CLIENT_ID,
        "sub": SA_TOKEN_SUB,
        "preferred_username": format!("service-account-{SA_CLIENT_ID}"),
        "exp": now() + 3600
    }));
    let (status, xml) = assume_role(
        &h,
        &[
            ("Action", "AssumeRoleWithWebIdentity"),
            ("RoleArn", &role_arn()),
            ("RoleSessionName", "unbound"),
            ("WebIdentityToken", &unbound),
        ],
    )
    .await;
    assert_eq!(status, 400, "{xml}");
    assert!(xml.contains("<Code>InvalidIdentityToken</Code>"), "{xml}");
    assert!(!xml.contains("<AccessKeyId>"), "{xml}");
    // The refusal must not enumerate the accepted clients back to an anonymous caller.
    assert!(!xml.contains(STORAGE_CLIENT), "{xml}");

    // POSITIVE CONTROL: the same principal, the same everything, with the audience
    // mapper in place — so this test measures the binding and not the principal.
    let session = assume_role_ok(&h, &service_account_token(SA_CLIENT_ID)).await;
    assert!(session.access_key_id.starts_with("HFST"));
}

/// The escape hatch in the configured audience list: naming a service account's own
/// clientId lets it present its **unmapped** token. Same code path, different list — so an
/// operator can switch one SA on without an identity-provider change.
#[tokio::test]
async fn naming_a_service_accounts_client_id_lets_it_present_an_unmapped_token() {
    let cfg = StsMintConfig {
        web_identity_audiences: vec![STORAGE_CLIENT.into(), SA_CLIENT_ID.into()],
        ..mint_config()
    };
    let h = harness_with("webid-e2e-extra-aud", cfg).await;
    let unbound = sign(serde_json::json!({
        "iss": ISSUER, "aud": "account", "azp": SA_CLIENT_ID, "sub": SA_TOKEN_SUB,
        "preferred_username": format!("service-account-{SA_CLIENT_ID}"),
        "exp": now() + 3600
    }));
    let session = assume_role_ok(&h, &unbound).await;
    let (status, body) = get_object(&h, &session, "sa/q1.csv").await;
    assert_ne!(status, 403, "{body}");
    // …and it is still the SA's own key space, not the audience's.
    assert_eq!(
        last_opa_input(&h)["principal"]["sub"],
        serde_json::json!(SA_CLIENT_ID)
    );

    // NEGATIVE CONTROL: a *different* unmapped SA is still refused, so widening the
    // list for one principal did not widen it for the realm.
    let other = sign(serde_json::json!({
        "iss": ISSUER, "aud": "account", "azp": "some-other-sa", "sub": "x",
        "preferred_username": "service-account-some-other-sa", "exp": now() + 3600
    }));
    let (status, xml) = assume_role(
        &h,
        &[
            ("Action", "AssumeRoleWithWebIdentity"),
            ("RoleArn", &role_arn()),
            ("RoleSessionName", "other"),
            ("WebIdentityToken", &other),
        ],
    )
    .await;
    assert_eq!(status, 400, "{xml}");
    assert!(xml.contains("<Code>InvalidIdentityToken</Code>"), "{xml}");
}

// ── the bundle-driven route ────────────────────────────────────────────────────

/// A service account created by a **tenant**, not by the operator: its clientId is in no
/// configured audience list and never will be.
const TENANT_SA: &str = "test-s0-before";

/// [`bundle`] plus the membership entry the STS door's bundle route reads: `sa:<clientId>`
/// in `data.tenants[<tenant>].user_attributes`, which a control plane writes for every
/// service account of the organization.
///
/// **It carries no grant, deliberately**: that is the ordinary state of a freshly-created
/// SA, and it is what makes the 403 in
/// `bundle_acceptance_is_not_authorization_a_grantless_subject_is_still_denied` mean
/// something. The rest of the map keeps the raw keys `GATEWAY_REGO` reads, so the two key
/// spaces sit side by side here as they do in a mixed deployment.
fn bundle_with_a_tenant_service_account() -> serde_json::Value {
    let mut bundle = bundle();
    bundle["tenants"][TENANT]["user_attributes"]
        .as_object_mut()
        .expect("user_attributes")
        .insert(
            format!("sa:{TENANT_SA}"),
            serde_json::json!({ "groups": [], "attributes": [] }),
        );
    bundle
}

/// The token such an SA really presents: the `client_credentials` default, with no
/// audience mapper and no entry in the configured audience list.
fn unmapped_service_account_token(client_id: &str) -> String {
    sign(serde_json::json!({
        "iss": ISSUER,
        "aud": "account",
        "azp": client_id,
        "sub": SA_TOKEN_SUB,
        "preferred_username": format!("service-account-{client_id}"),
        "exp": now() + 3600,
    }))
}

/// **The case this route exists for, end to end.** A tenant's own service account —
/// unmapped token, `aud: "account"`, clientId in none of the configured audiences —
/// obtains a credential because the **policy bundle already knows it**, with no config
/// re-render and no identity-provider change.
///
/// The negative control is the same token and the same code path against a bundle that
/// does *not* name it: refused. So this measures the bundle lookup and not a hole in the
/// audience check.
#[tokio::test]
async fn a_tenant_service_account_the_bundle_knows_mints_a_credential_with_no_operator_re_render() {
    let h = harness_over(
        "webid-e2e-bundle-route",
        mint_config(),
        bundle_with_a_tenant_service_account(),
    )
    .await;
    let token = unmapped_service_account_token(TENANT_SA);

    let session = assume_role_ok(&h, &token).await;
    assert!(
        session.access_key_id.starts_with("HFST"),
        "not an STS access key: {}",
        session.access_key_id
    );
    assert!(!session.session_token.is_empty());

    // NEGATIVE CONTROL: the default fixture bundle knows no `sa:` subject at all, so the
    // identical token is refused there. Nothing about the configured list differs.
    let plain = harness("webid-e2e-bundle-route-neg").await;
    let (status, xml) = assume_role(
        &plain,
        &[
            ("Action", "AssumeRoleWithWebIdentity"),
            ("RoleArn", &role_arn()),
            ("RoleSessionName", "unknown-to-the-bundle"),
            ("WebIdentityToken", &token),
        ],
    )
    .await;
    assert_eq!(status, 400, "{xml}");
    assert!(xml.contains("<Code>InvalidIdentityToken</Code>"), "{xml}");
    assert!(!xml.contains("<AccessKeyId>"), "{xml}");
    // The refusal still enumerates nothing: not the accepted clients, not the subject,
    // not the tenant.
    assert!(!xml.contains(STORAGE_CLIENT), "{xml}");
    assert!(!xml.contains(TENANT_SA), "{xml}");
    assert!(!xml.contains(TENANT), "{xml}");
}

/// **Acceptance is not authorization**, measured on a real S3 request rather than argued.
///
/// The subject above is in the bundle and holds no grant. Its credential is perfectly
/// valid, and every S3 request it makes is still refused by the same policy as everyone
/// else. If the bundle route conferred anything, this is where it would show.
#[tokio::test]
async fn bundle_acceptance_is_not_authorization_a_grantless_subject_is_still_denied() {
    let h = harness_over(
        "webid-e2e-bundle-route-authz",
        mint_config(),
        bundle_with_a_tenant_service_account(),
    )
    .await;
    let session = assume_role_ok(&h, &unmapped_service_account_token(TENANT_SA)).await;

    for key in ["sa/q1.csv", "human/private.csv", "anything.txt"] {
        let (status, _) = get_object(&h, &session, key).await;
        assert_eq!(
            status, 403,
            "a subject the bundle merely KNOWS reached {key}: acceptance conferred access"
        );
    }
    // …and it was refused as itself, at the policy, not as a broken credential: the
    // decision document names the SA in the tenant the RoleArn selected.
    let input = last_opa_input(&h);
    assert_eq!(input["principal"]["sub"], serde_json::json!(TENANT_SA));
    assert_eq!(
        input["principal"]["type"],
        serde_json::json!("service_account")
    );
    assert_eq!(input["tenant"], serde_json::json!(TENANT));
    assert_eq!(input["organization_id"], serde_json::json!(ORG));

    // POSITIVE CONTROL, same gateway and same bundle: the SA that DOES hold a grant
    // still reaches its own prefix, so the 403s above are the absence of a grant rather
    // than a data plane that refuses every web-identity session.
    let granted = assume_role_ok(&h, &service_account_token(SA_CLIENT_ID)).await;
    let (status, body) = get_object(&h, &granted, "sa/q1.csv").await;
    assert_ne!(status, 403, "{body}");
}

/// A refusal must not tell an anonymous caller whether a tenant exists. The endpoint is
/// internet-reachable, so `AccessDenied` is uniform across "no such tenant" and "wrong
/// role name": the two answers are byte-identical apart from the request id.
#[tokio::test]
async fn an_unroutable_tenant_and_a_wrong_role_are_indistinguishable_to_the_caller() {
    let h = harness("webid-e2e-oracle").await;
    let good = service_account_token(SA_CLIENT_ID);
    let strip_request_id = |xml: String| {
        let start = xml.find("<RequestId>").expect("request id");
        let end = xml.find("</RequestId>").expect("request id");
        format!("{}{}", &xml[..start], &xml[end..])
    };

    let (_, unroutable) = assume_role(
        &h,
        &[
            ("Action", "AssumeRoleWithWebIdentity"),
            (
                "RoleArn",
                "arn:aws:iam::no-such-tenant:role/no-such-tenant-sts-role",
            ),
            ("RoleSessionName", "probe"),
            ("WebIdentityToken", &good),
        ],
    )
    .await;
    let (_, wrong_role) = assume_role(
        &h,
        &[
            ("Action", "AssumeRoleWithWebIdentity"),
            ("RoleArn", "arn:aws:iam::acme:role/not-the-role"),
            ("RoleSessionName", "probe"),
            ("WebIdentityToken", &good),
        ],
    )
    .await;
    assert_eq!(
        strip_request_id(unroutable.clone()),
        strip_request_id(wrong_role),
        "the two refusals differ, which makes this endpoint a tenant-existence oracle"
    );
    for leak in ["no-such-tenant", "acme", "routable", "routing"] {
        assert!(
            !unroutable.contains(leak),
            "the refusal discloses {leak:?}: {unroutable}"
        );
    }
}

/// **Identity is checked before the tenant.** An anonymous caller — one with no valid
/// IdP token at all — must not be able to learn anything about which tenants exist, so
/// a bad token and a bad tenant cannot be told apart by *ordering* either: a request
/// with both wrong answers the token error, never the tenant one.
#[tokio::test]
async fn a_caller_with_no_valid_token_cannot_probe_tenants_at_all() {
    let h = harness("webid-e2e-order").await;
    // Wrong tenant AND a garbage token. If the tenant were resolved first, the answer
    // would be AccessDenied and an anonymous caller could enumerate tenants by diffing
    // the code.
    let (status, xml) = assume_role(
        &h,
        &[
            ("Action", "AssumeRoleWithWebIdentity"),
            (
                "RoleArn",
                "arn:aws:iam::no-such-tenant:role/no-such-tenant-sts-role",
            ),
            ("RoleSessionName", "probe"),
            ("WebIdentityToken", "not-a-jwt"),
        ],
    )
    .await;
    assert_eq!(status, 400, "{xml}");
    assert!(
        xml.contains("<Code>InvalidIdentityToken</Code>"),
        "the tenant was evaluated before the identity: {xml}"
    );
}

// ── the two doors share one socket ─────────────────────────────────────────────

/// The bearer door is untouched: a POST with no `Action` is still the JSON exchange, and
/// still answers `401` with a JSON body when no bearer token is presented. Dispatch is on
/// the presence of `Action` in the body, so neither door can shadow the other.
#[tokio::test]
async fn the_bearer_door_still_answers_on_the_same_socket() {
    let h = harness("webid-e2e-both").await;

    let resp = reqwest::Client::new()
        .post(&h.sts_base)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("answered");
    assert_eq!(resp.status().as_u16(), 401);
    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let body = resp.text().await.unwrap_or_default();
    assert!(ct.contains("application/json"), "{ct}: {body}");
    assert!(body.contains("missing bearer OIDC token"), "{body}");
    assert!(
        !body.contains("ErrorResponse"),
        "a request with no Action must not get an STS document: {body}"
    );

    // …and the STS door still works on the very same socket.
    let session = assume_role_ok(&h, &service_account_token(SA_CLIENT_ID)).await;
    assert!(session.access_key_id.starts_with("HFST"));
}

/// With the surface switched off, an STS request gets an STS-shaped `InvalidAction`
/// rather than a JSON 401 — the refusal has to be legible to the client that sent it —
/// and no credential is minted.
#[tokio::test]
async fn the_surface_can_be_switched_off_and_then_mints_nothing() {
    let cfg = StsMintConfig {
        web_identity_enabled: false,
        ..mint_config()
    };
    // The harness builds the surface regardless of the flag (that decision lives in
    // `main.rs`), so switch it off the way `main.rs` does: by not attaching it.
    let fx = common::fixture("webid-e2e-off", bundle());
    let verifier = Arc::new(StandardVerifier::from_config(&cfg).expect("verifier"));
    let mint = Arc::new(Mint::new(
        verifier,
        fx.gw.identity.sts(),
        Duration::from_secs(900),
    ));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    drop(listener);
    tokio::spawn(async move {
        let _ = s0::mint::serve_with_shutdown(mint, addr, std::future::pending::<()>()).await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let h = Harness {
        fx,
        s3_base: String::new(),
        sts_base: format!("http://{addr}"),
    };
    let (status, xml) = assume_role(
        &h,
        &[
            ("Action", "AssumeRoleWithWebIdentity"),
            ("RoleArn", &role_arn()),
            ("RoleSessionName", "off-session"),
            ("WebIdentityToken", &service_account_token(SA_CLIENT_ID)),
        ],
    )
    .await;
    assert_eq!(status, 400, "{xml}");
    assert!(xml.contains("<Code>InvalidAction</Code>"), "{xml}");
    assert!(!xml.contains("<AccessKeyId>"), "{xml}");
}

/// A body larger than the mint's ceiling is refused rather than allocated. This socket
/// is unauthenticated by design, so it is the only place that bound exists.
#[tokio::test]
async fn an_oversized_body_is_refused_rather_than_buffered() {
    let h = harness("webid-e2e-big").await;
    let resp = reqwest::Client::new()
        .post(&h.sts_base)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(format!(
            "Action=AssumeRoleWithWebIdentity&WebIdentityToken={}",
            "A".repeat(128 * 1024)
        ))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("answered");
    assert_eq!(resp.status().as_u16(), 413);
}
