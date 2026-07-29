//! **P3, proven by execution end to end**: a session minted through the
//! console-mediated endpoint is a credential the S3 data plane accepts, and the
//! identity the console asserted is the identity the policy decision is made against.
//!
//! Every other test of this path stops one step short of the claim that matters.
//! `tests/internal_session.rs` mints over a real socket and resolves the credential
//! through `Identity::resolve` — the right call, but called by the test rather than by
//! the gateway. That leaves the load-bearing question open: **would a real S3 client,
//! signing SigV4 with what the console handed it, get through?** A credential that
//! resolves in isolation but fails signature verification, or that resolves to a
//! principal the enforce path never consults, looks identical from the console's side.
//!
//! So this file runs the whole thing:
//!
//! 1. the real `internal::serve_on` accept loop, on its own socket, holding the
//!    **same** `StsAuthority` the gateway verifies with (exactly how `main.rs` wires
//!    it: `gateway.identity.sts()`);
//! 2. a real `POST /internal/v1/sts/sessions` carrying the platform shared secret and
//!    the console's own request document;
//! 3. the real `server::serve_with_shutdown` S3 front on another socket;
//! 4. a **real SigV4-signed** `GetObject` over TCP, signed with the returned
//!    `AccessKeyId`/`SecretAccessKey` and carrying the returned `SessionToken` in
//!    `x-amz-security-token` — the same signer `tests/gate_blackbox.rs` uses;
//! 5. the `OpaInput` the enforce path actually handed the PDP, read out of the capture
//!    sink — not reconstructed, not re-derived.
//!
//! ## The service-account case is the point
//!
//! s0's own OIDC mint (`src/mint.rs`) hard-codes `PrincipalType::User` and has no field
//! to override it, so it **cannot express a service-account session at all** — and
//! service accounts are the primary consumer of this gateway. Both principal classes are
//! driven here, against grants keyed to *different prefixes*, so the test cannot pass on
//! a constant: the service account reaches its prefix and is refused on the user's, and
//! the user reaches its prefix and is refused on the service account's. A gateway that
//! ignored the asserted principal and evaluated everything as one subject would fail
//! four of those eight assertions.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use common::sigv4::RawRequest;
use s0::auth::SECURITY_TOKEN_HEADER;
use s0::config::InternalApiConfig;
use s0::internal::{InternalApi, SESSION_PATH, SHARED_SECRET_HEADER};
use s0::secret::Secret;

/// The platform shared secret, as the operator renders it into `internal.shared_secret`.
const SHARED_SECRET: &str = "PLATFORM-SHARED-SECRET-e2e";

/// The tenant and organization `tests/common` routes. The console asserts both, and s0
/// checks them against its own routing table before it mints.
const TENANT: &str = "acme";
const ORG: &str = "org-acme";

/// The two subjects, keyed to two different prefixes in the bundle below.
const SA_SUB: &str = "pipeline-runner";
const USER_SUB: &str = "alice-sub";

/// `pipeline-runner` (a service account) may read under `sa/`; `alice-sub` (a user) may
/// read under `human/`. Neither may read the other's prefix.
///
/// Two disjoint grants rather than one shared grant, deliberately: it makes "the
/// decision was made against the subject the console asserted" a *checkable* claim
/// rather than something inferred from the input document. A gateway that mixed the two
/// up — or that ignored the session entirely — cannot satisfy both directions.
fn bundle() -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false, "reserved_tag_keys": ["hyperfluid/*"] },
        "tenants": { TENANT: {
            "user_attributes": {
                SA_SUB: { "groups": ["editor"], "attributes": [] },
                USER_SUB: { "groups": ["viewer"], "attributes": [] }
            },
            "bucket_attributes": { "reports": { "denylist": {} } },
            "s3_grants": {
                SA_SUB: [
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

/// Everything a test needs: the gateway fixture, the S3 front's base URL, and the
/// internal API's base URL.
struct Harness {
    fx: common::Fixture,
    s3_base: String,
    internal_base: String,
}

/// Boot the **production** serving paths — `server::serve_with_shutdown` for the data
/// plane and `internal::serve_on` for the mint — over two real loopback sockets, with
/// one `StsAuthority` shared between them.
async fn harness(tag: &str) -> Harness {
    let fx = common::fixture(tag, bundle());

    // The S3 front, exactly as `tests/gate_blackbox.rs` boots it.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind s3");
    let s3_addr: SocketAddr = listener.local_addr().expect("addr");
    drop(listener);
    let gw = fx.gw.clone();
    tokio::spawn(async move {
        let _ = s0::server::serve_with_shutdown(gw, s3_addr, std::future::pending::<()>()).await;
    });

    // The internal API, on its own socket, over the SAME identity/STS the front
    // verifies with. `gateway.identity.sts()` and `gateway.registry` are the exact
    // expressions `main.rs` passes; a second authority here would make the whole file
    // measure a credential nothing else in the process could honour.
    let internal_cfg = InternalApiConfig {
        listen: "127.0.0.1:0".parse().expect("addr"),
        shared_secret: Some(Secret::from(SHARED_SECRET)),
        max_session_ttl_secs: 3600,
    };
    let api = Arc::new(InternalApi::new(
        &internal_cfg,
        fx.gw.identity.sts(),
        fx.gw.registry.clone(),
    ));
    let internal_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind internal");
    let internal_addr = internal_listener.local_addr().expect("addr");
    tokio::spawn(async move {
        let _ = s0::internal::serve_on(api, internal_listener, std::future::pending::<()>()).await;
    });

    for _ in 0..200 {
        let up = tokio::net::TcpStream::connect(s3_addr).await.is_ok()
            && tokio::net::TcpStream::connect(internal_addr).await.is_ok();
        if up {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    Harness {
        fx,
        s3_base: format!("http://{s3_addr}"),
        internal_base: format!("http://{internal_addr}"),
    }
}

/// A credential as the console receives it.
struct Session {
    access_key_id: String,
    secret_access_key: String,
    session_token: String,
}

/// The console's own request document, field for field
/// (`hf_console::outbound::s3_gateway_sts::GatewaySessionRequest`).
async fn mint(h: &Harness, sub: &str, principal_type: &str, groups: &[&str]) -> Session {
    let resp = reqwest::Client::new()
        .post(format!("{}{SESSION_PATH}", h.internal_base))
        .header(SHARED_SECRET_HEADER, SHARED_SECRET)
        .json(&serde_json::json!({
            "sub": sub,
            "principal_type": principal_type,
            "tenant": TENANT,
            "organization_id": ORG,
            "groups": groups,
            "duration_seconds": 900
        }))
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .expect("the console-mediated mint answered");
    assert_eq!(
        resp.status(),
        200,
        "the mint refused a well-formed console request: {}",
        resp.text().await.unwrap_or_default()
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    Session {
        access_key_id: body["AccessKeyId"].as_str().expect("AccessKeyId").into(),
        secret_access_key: body["SecretAccessKey"]
            .as_str()
            .expect("SecretAccessKey")
            .into(),
        session_token: body["SessionToken"].as_str().expect("SessionToken").into(),
    }
}

/// `GET /reports/<key>`, SigV4-signed with the session's own keys and carrying the
/// session token in the standard header — i.e. what any AWS SDK configured with these
/// three values puts on the wire.
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

/// **A service-account session minted by the console is honoured by SigV4 and is
/// evaluated as a service account.**
///
/// This is the case s0's own OIDC mint cannot produce, and it is the primary use case
/// for the whole project.
#[tokio::test]
async fn a_console_minted_service_account_session_is_accepted_by_sigv4_and_carries_its_identity() {
    let h = harness("console-e2e-sa").await;
    let session = mint(&h, SA_SUB, "service_account", &["editor"]).await;

    // The credential shape the data plane recognises. If this were not an STS key the
    // request below would be answered by the static store instead, and the session
    // token would never be consulted.
    assert!(
        session.access_key_id.starts_with("HFST"),
        "not an STS access key: {}",
        session.access_key_id
    );

    // 1. SIGNATURE + IDENTITY. `sa/q1.csv` is inside the service account's grant, so
    //    the request passes `check` (signature verified against the derived secret,
    //    identity resolved from the session token) AND the policy, and reaches the
    //    forward — where the fixture's backend (port 1) is not listening. Anything at
    //    the gate answers 403.
    let (status, body) = get_object(&h, &session, "sa/q1.csv").await;
    assert_ne!(
        status, 403,
        "a session the console minted was refused by the S3 data plane: {body}"
    );

    // 2. THE DECISION DOCUMENT. Read from the capture sink — the tap inside
    //    `GatewayAccess::decide`, so this is the document the PDP was handed, not a
    //    reconstruction of it.
    let input = last_opa_input(&h);
    assert_eq!(
        input["principal"]["type"],
        serde_json::json!("service_account"),
        "the console asserted a service account and the decision was made against \
         something else: {input}"
    );
    assert_eq!(input["principal"]["sub"], serde_json::json!(SA_SUB));
    assert_eq!(input["tenant"], serde_json::json!(TENANT));
    assert_eq!(input["organization_id"], serde_json::json!(ORG));
    assert_eq!(input["action"], serde_json::json!("read_objects"));
    assert_eq!(input["bucket"], serde_json::json!("reports"));
    assert_eq!(input["object"], serde_json::json!("sa/q1.csv"));

    // 3. …and the identity is load-bearing, not decorative: the same session on the
    //    *user's* prefix is denied by the same policy.
    let (status, _) = get_object(&h, &session, "human/private.csv").await;
    assert_eq!(
        status, 403,
        "the service account reached a prefix only the user is granted — the session's \
         subject is not driving the decision"
    );
    drop(h);
}

/// The user arm of the same path, so nothing above can pass on a constant.
#[tokio::test]
async fn a_console_minted_user_session_is_accepted_by_sigv4_and_carries_its_identity() {
    let h = harness("console-e2e-user").await;
    let session = mint(&h, USER_SUB, "user", &["viewer"]).await;

    let (status, body) = get_object(&h, &session, "human/notes.csv").await;
    assert_ne!(
        status, 403,
        "a user session the console minted was refused by the S3 data plane: {body}"
    );

    let input = last_opa_input(&h);
    assert_eq!(input["principal"]["type"], serde_json::json!("user"));
    assert_eq!(input["principal"]["sub"], serde_json::json!(USER_SUB));
    assert_eq!(input["tenant"], serde_json::json!(TENANT));
    assert_eq!(input["organization_id"], serde_json::json!(ORG));

    // The mirror of the service account's cross-check.
    let (status, _) = get_object(&h, &session, "sa/q1.csv").await;
    assert_eq!(
        status, 403,
        "the user reached a prefix only the service account is granted"
    );
    drop(h);
}

/// The negative control for the SigV4 half. Without it, "not 403" above would be
/// satisfied by a gateway that accepted everything.
///
/// Three separable ways to hold a console-minted session wrongly, each of which must
/// fail: the right access key with the wrong secret (signature), the right keys with no
/// session token (identity), and the right keys with another session's token (binding).
#[tokio::test]
async fn a_tampered_console_session_is_refused_by_the_data_plane() {
    let h = harness("console-e2e-negative").await;
    let session = mint(&h, SA_SUB, "service_account", &["editor"]).await;
    let other = mint(&h, USER_SUB, "user", &["viewer"]).await;
    let host = h.s3_base.trim_start_matches("http://").to_string();

    let send = |headers: Vec<(String, String)>, url: String| async move {
        let mut builder = reqwest::Client::new()
            .request(reqwest::Method::GET, url)
            .timeout(Duration::from_secs(10));
        for (k, v) in &headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        builder.send().await.expect("answered").status().as_u16()
    };

    // (a) The signature is real. A wrong secret must not pass.
    let req = RawRequest::new("GET", "/reports/sa/q1.csv")
        .header(SECURITY_TOKEN_HEADER, &session.session_token);
    let headers = req.sign(&host, &session.access_key_id, "not-the-derived-secret");
    assert_eq!(
        send(headers, req.url(&h.s3_base)).await,
        403,
        "a request signed with the wrong secret was accepted"
    );

    // (b) An STS access key with no session token resolves to nothing.
    let req = RawRequest::new("GET", "/reports/sa/q1.csv");
    let headers = req.sign(&host, &session.access_key_id, &session.secret_access_key);
    assert_eq!(
        send(headers, req.url(&h.s3_base)).await,
        403,
        "an STS credential with no session token was accepted"
    );

    // (c) The token is bound to its own access key: presenting another live session's
    //     token with this access key must not resolve.
    let req = RawRequest::new("GET", "/reports/sa/q1.csv")
        .header(SECURITY_TOKEN_HEADER, &other.session_token);
    let headers = req.sign(&host, &session.access_key_id, &session.secret_access_key);
    assert_eq!(
        send(headers, req.url(&h.s3_base)).await,
        403,
        "a session token from a different session was accepted for this access key"
    );
    drop(h);
}
