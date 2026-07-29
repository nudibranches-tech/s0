//! P3, end to end: the console-mediated session endpoint, driven over a real socket.
//!
//! Everything here goes through `internal::serve_on` — the production accept loop and
//! the production `route` — with a real `StsAuthority` and a real `BackendRegistry`.
//! The assertions that matter are not about status codes; they are:
//!
//! * **an unauthenticated caller gets nothing**, including nothing about which paths
//!   exist, and a gateway with no secret configured refuses *everything* rather than
//!   defaulting to open;
//! * **a service-account session reaches `OpaInput.principal.kind ==
//!   ServiceAccount`**, through `Identity::resolve` — the same call the S3 data plane
//!   makes on every request. This is the one property the existing OIDC mint cannot
//!   express at all (it hard-codes `PrincipalType::User`), and service accounts are
//!   the primary consumer of this gateway;
//! * **the credential the console receives is one the data plane accepts**, verified
//!   by re-deriving the secret from the access-key id and verifying the session token.
//!   A mint that produced credentials the gateway could not honour would look
//!   perfectly healthy from the console's side.

use std::sync::Arc;
use std::time::Duration;

use s0::auth::sts::StsAuthority;
use s0::auth::{Identity, StaticCredentialStore};
use s0::config::{GatewayConfig, InternalApiConfig};
use s0::internal::{
    InternalApi, SESSION_PATH, SHARED_SECRET_HEADER, SessionRefusal, SessionRequest,
};
use s0::model::PrincipalType;
use s0::proxy::BackendRegistry;
use s0::secret::Secret;

const SECRET: &str = "platform-shared-secret-value";

/// Two routable tenants on one gateway, so "unroutable" and "wrong org" are both
/// testable against a table that really has entries.
fn config() -> GatewayConfig {
    GatewayConfig::from_json(
        &serde_json::json!({
            "listen": "127.0.0.1:0",
            "admin_listen": "127.0.0.1:0",
            "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
            "pdp": { "mode": "embedded" },
            "audit": { "sink_url": "http://127.0.0.1:59999/none",
                       "spill_path": std::env::temp_dir()
                           .join(format!("s0-internal-{}.ndjson", uuid::Uuid::new_v4())) },
            "backends": [
                { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:7480" }
            ],
            "tenants": [
                { "tenant": "acme-prod", "organization_id": "11111111-1111-1111-1111-111111111111",
                  "backend_id": "bay-1", "owner_access_key": "OWNER", "owner_secret_key": "SECRET" },
                { "tenant": "globex", "organization_id": "22222222-2222-2222-2222-222222222222",
                  "backend_id": "bay-1", "owner_access_key": "OWNER2", "owner_secret_key": "SECRET2" }
            ],
            "bundle_path": "/dev/null"
        })
        .to_string(),
    )
    .expect("config")
}

fn sts() -> Arc<StsAuthority> {
    Arc::new(StsAuthority::new(vec![4u8; 32], vec![8u8; 32]).expect("sts"))
}

fn api_with(shared_secret: Option<&str>, max_ttl: u64, sts: Arc<StsAuthority>) -> Arc<InternalApi> {
    let cfg = InternalApiConfig {
        listen: "127.0.0.1:0".parse().expect("addr"),
        shared_secret: shared_secret.map(Secret::from),
        max_session_ttl_secs: max_ttl,
    };
    Arc::new(InternalApi::new(
        &cfg,
        sts,
        Arc::new(BackendRegistry::from_config(&config()).expect("registry")),
    ))
}

/// Start the real serving loop on an ephemeral port; returns its base URL and a
/// shutdown trigger.
async fn serve(api: Arc<InternalApi>) -> (String, tokio::sync::oneshot::Sender<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(async move {
        let _ = s0::internal::serve_on(api, listener, async {
            let _ = stopped.await;
        })
        .await;
    });
    (format!("http://{addr}"), stop)
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("client")
}

fn body(principal_type: &str, tenant: &str, org: &str, ttl: u64) -> serde_json::Value {
    serde_json::json!({
        "sub": "pipeline-runner",
        "principal_type": principal_type,
        "tenant": tenant,
        "organization_id": org,
        "groups": ["editor"],
        "duration_seconds": ttl
    })
}

const ORG: &str = "11111111-1111-1111-1111-111111111111";

// ── authentication ─────────────────────────────────────────────────────────────

/// The P2/P3 headline: this surface is not reachable without the platform credential.
#[tokio::test]
async fn an_unauthenticated_call_to_the_session_endpoint_is_refused() {
    let (base, _stop) = serve(api_with(Some(SECRET), 3600, sts())).await;
    let url = format!("{base}{SESSION_PATH}");

    let resp = client()
        .post(&url)
        .json(&body("service_account", "acme-prod", ORG, 900))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 401, "a call with no header must be refused");
    let text = resp.text().await.expect("body");
    assert!(
        !text.contains("AccessKeyId"),
        "no credential leaked: {text}"
    );

    // And the listener discloses nothing else either: an unauthenticated probe of an
    // unrelated path, or of a method the endpoint does not take, gets the same 401
    // rather than a 404/405 that would map the surface.
    for (method, path) in [
        (reqwest::Method::GET, SESSION_PATH),
        (reqwest::Method::POST, "/does-not-exist"),
        (reqwest::Method::GET, "/healthz"),
        (reqwest::Method::GET, "/metrics"),
    ] {
        let resp = client()
            .request(method.clone(), format!("{base}{path}"))
            .send()
            .await
            .expect("send");
        assert_eq!(
            resp.status(),
            401,
            "{method} {path} answered {} — an unauthenticated caller must not be able \
             to tell which paths or methods exist",
            resp.status()
        );
    }
}

#[tokio::test]
async fn a_wrong_secret_is_refused() {
    let (base, _stop) = serve(api_with(Some(SECRET), 3600, sts())).await;
    let url = format!("{base}{SESSION_PATH}");

    // Near misses in every direction. Note that a *leading* space is not testable
    // here: HTTP field values are OWS-trimmed by the parser (RFC 9110 §5.5), so
    // `" value"` arrives as `"value"` and would authenticate — correctly, because the
    // caller never sent the space as part of the value.
    for wrong in [
        "",
        "platform-shared-secret-valu",
        "platform-shared-secret-values",
        "Platform-Shared-Secret-Value",
        "platform-shared-secret-valuE",
        "platform shared-secret-value",
    ] {
        let resp = client()
            .post(&url)
            .header(SHARED_SECRET_HEADER, wrong)
            .json(&body("service_account", "acme-prod", ORG, 900))
            .send()
            .await
            .expect("send");
        assert_eq!(resp.status(), 401, "{wrong:?} authenticated");
    }

    // Positive control, so the four above are not passing because the endpoint is
    // broken for everyone.
    let resp = client()
        .post(&url)
        .header(SHARED_SECRET_HEADER, SECRET)
        .json(&body("service_account", "acme-prod", ORG, 900))
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 200);
}

/// The deployment mistake this must survive: the operator rendered the Secret key but
/// the value came out empty. There is no "no secret configured ⇒ allow" path.
#[tokio::test]
async fn an_empty_configured_secret_refuses_everything() {
    for configured in [None, Some(""), Some("   ")] {
        let (base, _stop) = serve(api_with(configured, 3600, sts())).await;
        let url = format!("{base}{SESSION_PATH}");
        for presented in [None, Some(""), Some("   "), Some(SECRET), Some("anything")] {
            let mut req = client()
                .post(&url)
                .json(&body("service_account", "acme-prod", ORG, 900));
            if let Some(v) = presented {
                req = req.header(SHARED_SECRET_HEADER, v);
            }
            let resp = req.send().await.expect("send");
            assert_eq!(
                resp.status(),
                401,
                "configured={configured:?} presented={presented:?} was not refused"
            );
        }
    }
}

// ── minting ────────────────────────────────────────────────────────────────────

/// The property the existing OIDC mint cannot express: a **service-account** session,
/// carried all the way to the OPA input the data plane builds.
#[tokio::test]
async fn a_service_account_session_carries_its_principal_type_to_the_opa_input() {
    let sts = sts();
    let (base, _stop) = serve(api_with(Some(SECRET), 3600, sts.clone())).await;

    let minted: serde_json::Value = client()
        .post(format!("{base}{SESSION_PATH}"))
        .header(SHARED_SECRET_HEADER, SECRET)
        .json(&body("service_account", "acme-prod", ORG, 900))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");

    let access_key_id = minted["AccessKeyId"].as_str().expect("AccessKeyId");
    let session_token = minted["SessionToken"].as_str().expect("SessionToken");
    let secret_access_key = minted["SecretAccessKey"].as_str().expect("SecretAccessKey");

    // 1. It is a credential the DATA PLANE honours — same key ring, same derived
    //    secret. `secret_for_access_key` is exactly what `S3Auth::get_secret_key`
    //    calls to verify an inbound SigV4 signature.
    assert!(
        StsAuthority::is_sts_access_key(access_key_id),
        "{access_key_id} is not in the STS namespace"
    );
    assert_eq!(
        sts.secret_for_access_key(access_key_id).as_deref(),
        Some(secret_access_key),
        "the gateway cannot re-derive the secret it just handed out"
    );

    // 2. …and it resolves, through the production identity path, to a service account.
    let identity = Identity::new(sts.clone(), Arc::new(StaticCredentialStore::new()));
    let principal = identity
        .resolve(access_key_id, Some(session_token))
        .expect("the data plane resolves the session it was handed");
    assert_eq!(principal.principal_type, PrincipalType::ServiceAccount);
    assert_eq!(principal.sub, "pipeline-runner");
    assert_eq!(principal.tenant, "acme-prod");
    assert_eq!(principal.organization_id, ORG);
    assert_eq!(principal.groups, vec!["editor".to_string()]);

    // 3. The OPA input the enforce path builds from it. `kind` is what the module
    //    turns into the `sa:` key space; `user` here would evaluate against grants
    //    that do not exist and fail closed on every request, invisibly.
    let opa = principal.to_opa_principal();
    assert_eq!(opa.kind, PrincipalType::ServiceAccount);
    assert_eq!(
        // `input.principal.type` — the path the module's `subject_key` sprintf reads.
        serde_json::to_value(&opa).expect("serialize")["type"],
        serde_json::json!("service_account"),
        "the wire form the rego's subject_key sprintf reads"
    );

    // 4. And the user direction still works, in the same key ring.
    let user: serde_json::Value = client()
        .post(format!("{base}{SESSION_PATH}"))
        .header(SHARED_SECRET_HEADER, SECRET)
        .json(&body("user", "acme-prod", ORG, 900))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let user_principal = identity
        .resolve(
            user["AccessKeyId"].as_str().expect("ak"),
            Some(user["SessionToken"].as_str().expect("token")),
        )
        .expect("resolve");
    assert_eq!(user_principal.principal_type, PrincipalType::User);
}

/// **Clamped, not refused** — and the answer says so.
///
/// The requested duration comes from a CR field in the other repository. Refusing an
/// over-cap value would turn one number in a `kubectl patch` into a total credential
/// outage for that organization, with no fallback (`decide_issuance_path` never
/// returns to the legacy path once the flag is on). Clamping can only ever *shorten* a
/// credential's life, and `Expiration` reports the truth.
#[tokio::test]
async fn a_ttl_over_the_cap_is_clamped_down_not_honoured() {
    let (base, _stop) = serve(api_with(Some(SECRET), 900, sts())).await;
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_secs();

    let minted: serde_json::Value = client()
        .post(format!("{base}{SESSION_PATH}"))
        .header(SHARED_SECRET_HEADER, SECRET)
        .json(&body("service_account", "acme-prod", ORG, 86_400))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");

    let expiration = minted["Expiration"].as_u64().expect("Expiration");
    let ttl = expiration - before;
    assert!(
        (890..=900).contains(&ttl),
        "a 86400 s request produced a {ttl} s session; the 900 s cap was not applied"
    );

    // Under the cap, the request is honoured exactly — the clamp is a ceiling, not a
    // fixed lifetime.
    let short: serde_json::Value = client()
        .post(format!("{base}{SESSION_PATH}"))
        .header(SHARED_SECRET_HEADER, SECRET)
        .json(&body("service_account", "acme-prod", ORG, 300))
        .send()
        .await
        .expect("send")
        .json()
        .await
        .expect("json");
    let short_ttl = short["Expiration"].as_u64().expect("Expiration") - before;
    assert!(
        (290..=300).contains(&short_ttl),
        "an under-cap request was not honoured: {short_ttl}"
    );
}

/// Everything the console can get wrong about the facts it asserts, refused rather
/// than minted. None of these is a downgrade to a weaker session.
#[tokio::test]
async fn the_asserted_facts_are_validated_against_this_gateways_own_tables() {
    let (base, _stop) = serve(api_with(Some(SECRET), 3600, sts())).await;
    let url = format!("{base}{SESSION_PATH}");
    let post = |b: serde_json::Value| {
        let url = url.clone();
        async move {
            client()
                .post(url)
                .header(SHARED_SECRET_HEADER, SECRET)
                .json(&b)
                .send()
                .await
                .expect("send")
        }
    };

    // A tenant this gateway cannot route. The bundle's tenant table is built from the
    // same bindings, so such a session would be denied on every request anyway.
    let resp = post(body("service_account", "not-a-tenant", ORG, 900)).await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.expect("body").contains("not routable"));

    // An org that disagrees with this gateway's tenant binding. The decision path
    // attributes from the route, not from the claim, so this would silently evaluate
    // against a different organization than the console named.
    let resp = post(body(
        "service_account",
        "acme-prod",
        "22222222-2222-2222-2222-222222222222",
        900,
    ))
    .await;
    assert_eq!(resp.status(), 400);
    assert!(resp.text().await.expect("body").contains("organization_id"));

    // A principal class outside the enum: refused at deserialization.
    let resp = post(body("admin", "acme-prod", ORG, 900)).await;
    assert_eq!(resp.status(), 400);

    // Zero duration: a configuration bug, not a clamp case. Handing back a one-second
    // credential would turn it into an intermittent failure instead of a loud one.
    let resp = post(body("service_account", "acme-prod", ORG, 0)).await;
    assert_eq!(resp.status(), 400);
    assert!(
        resp.text()
            .await
            .expect("body")
            .contains("duration_seconds"),
        "the refusal must name the field"
    );

    // An empty subject would compose the bundle key `sa:` — a real key an accidental
    // grant could match.
    let resp = post(serde_json::json!({
        "sub": "", "principal_type": "service_account", "tenant": "acme-prod",
        "organization_id": ORG, "groups": [], "duration_seconds": 900
    }))
    .await;
    assert_eq!(resp.status(), 400);

    // Not JSON at all.
    let resp = client()
        .post(&url)
        .header(SHARED_SECRET_HEADER, SECRET)
        .body("not json")
        .send()
        .await
        .expect("send");
    assert_eq!(resp.status(), 400);

    // Positive control.
    assert_eq!(
        post(body("service_account", "acme-prod", ORG, 900))
            .await
            .status(),
        200
    );
}

/// The refusal reasons are exercised directly too, so a change to the HTTP layer
/// cannot quietly turn one of them into an allow while the status codes still look
/// right.
#[test]
fn the_refusal_set_is_pinned_at_the_function_level() {
    let api = api_with(Some(SECRET), 900, sts());
    let req = |b: serde_json::Value| serde_json::from_value::<SessionRequest>(b).expect("shape");
    // `MintedCredentials` deliberately has no `Debug` — three of its four fields are a
    // live credential — so the success side is discarded before `expect_err` sees it.
    // That this is *necessary* is itself the guarantee.
    let refusal = |b: serde_json::Value, sid: &str| -> SessionRefusal {
        api.mint_session(&req(b), sid)
            .map(|_| ())
            .expect_err("must be refused")
    };

    assert_eq!(
        refusal(body("service_account", "nope", ORG, 900), "sid-1"),
        SessionRefusal::UnroutableTenant("nope".into())
    );
    assert_eq!(
        refusal(
            body(
                "user",
                "acme-prod",
                "22222222-2222-2222-2222-222222222222",
                900
            ),
            "sid-1"
        ),
        SessionRefusal::OrganizationMismatch
    );
    assert_eq!(
        refusal(body("user", "acme-prod", ORG, 0), "sid-1"),
        SessionRefusal::ZeroDuration
    );
    // A blank sid is the STS authority's own refusal, surfaced rather than swallowed.
    assert!(matches!(
        refusal(body("user", "acme-prod", ORG, 900), ""),
        SessionRefusal::MintFailed(_)
    ));
    assert!(
        api.mint_session(&req(body("user", "acme-prod", ORG, 900)), "sid-1")
            .is_ok()
    );
}
