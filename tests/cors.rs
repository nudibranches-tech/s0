//! CORS for browsers that reach s0 through a presigned URL, over real HTTP.
//!
//! The real `server::serve_with_shutdown` fronts a stub backend that holds a CORS
//! configuration per bucket and answers `PutObject` and `UploadPart` with an `ETag`. URLs
//! are presigned by the AWS SDK, the way the Hyperfluid console signs them, so the
//! preflight carries exactly what a browser would send: no `Authorization` header, and the
//! credential in the query string.
//!
//! What is pinned here, beyond the happy path:
//! - a preflight reaches neither the policy engine nor the audit trail;
//! - every refusal is the same response, whatever the reason;
//! - a bucket's configuration is read from the backend once per TTL, absence included;
//! - a request with no `Origin` is untouched and costs no backend read.

mod common;

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::presigning::PresigningConfig;
use bytes::Bytes;
use common::sigv4::RawRequest;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response};
use hyper_util::rt::TokioIo;
use reqwest::header::HeaderMap;
use s0::auth::derived::{DerivedKeyAuthority, DerivedPrincipal};
use s0::auth::sts::SessionClaims;
use s0::auth::{DerivedKeys, Identity};
use s0::cors::{CorsState, Denial};
use s0::model::PrincipalType;

const ORIGIN: &str = "https://app.proarchives360.fr";

/// The rule the Hyperfluid operator writes on every bucket.
const OPERATOR_RULE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <CORSRule>
    <AllowedOrigin>*</AllowedOrigin>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedHeader>content-type</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
    <MaxAgeSeconds>3000</MaxAgeSeconds>
  </CORSRule>
</CORSConfiguration>"#;

/// Two rules, so first-match is exercised through the real XML path: a read-only origin
/// first, then the origin that uploads.
const NAMED_RULES: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<CORSConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <CORSRule>
    <AllowedOrigin>https://reader.example.com</AllowedOrigin>
    <AllowedMethod>GET</AllowedMethod>
    <ExposeHeader>x-first</ExposeHeader>
  </CORSRule>
  <CORSRule>
    <AllowedOrigin>https://app.example.com</AllowedOrigin>
    <AllowedOrigin>https://*.partner.example.com</AllowedOrigin>
    <AllowedMethod>PUT</AllowedMethod>
    <AllowedMethod>GET</AllowedMethod>
    <AllowedHeader>*</AllowedHeader>
    <ExposeHeader>ETag</ExposeHeader>
    <ExposeHeader>x-amz-request-id</ExposeHeader>
    <MaxAgeSeconds>60</MaxAgeSeconds>
  </CORSRule>
</CORSConfiguration>"#;

// ── the backend ─────────────────────────────────────────────────────────────────────────

/// What the stub holds per bucket: `Some(xml)` is a CORS configuration, `None` is a
/// bucket with none, and a bucket that is not in the map does not exist.
#[derive(Default)]
struct StubState {
    buckets: Mutex<HashMap<String, Option<String>>>,
    cors_reads: Mutex<HashMap<String, usize>>,
}

impl StubState {
    fn set(&self, bucket: &str, cors: Option<&str>) {
        self.buckets
            .lock()
            .unwrap()
            .insert(bucket.to_string(), cors.map(str::to_string));
    }

    fn reads(&self, bucket: &str) -> usize {
        self.cors_reads
            .lock()
            .unwrap()
            .get(bucket)
            .copied()
            .unwrap_or(0)
    }

    fn total_reads(&self) -> usize {
        self.cors_reads.lock().unwrap().values().sum()
    }
}

fn xml(status: u16, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/xml")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

fn s3_error(status: u16, code: &str) -> Response<Full<Bytes>> {
    xml(
        status,
        &format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code>\
             <Message>stub</Message></Error>"
        ),
    )
}

async fn stub_backend(state: Arc<StubState>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((sock, _)) = listener.accept().await else {
                return;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let svc = service_fn(move |req: Request<Incoming>| {
                    let state = state.clone();
                    async move { Ok::<_, Infallible>(stub_answer(&state, req).await) }
                });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(sock), svc)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

async fn stub_answer(state: &StubState, req: Request<Incoming>) -> Response<Full<Bytes>> {
    let (parts, body) = req.into_parts();
    let _ = body.collect().await;
    let path = parts.uri.path().trim_start_matches('/').to_string();
    let query = parts.uri.query().unwrap_or("").to_string();
    let (bucket, key) = path.split_once('/').unwrap_or((path.as_str(), ""));
    let reads_cors = query
        .split('&')
        .any(|p| p == "cors" || p.starts_with("cors="));

    if parts.method == Method::GET && key.is_empty() && reads_cors {
        *state
            .cors_reads
            .lock()
            .unwrap()
            .entry(bucket.to_string())
            .or_default() += 1;
        return match state.buckets.lock().unwrap().get(bucket) {
            Some(Some(config)) => xml(200, config),
            Some(None) => s3_error(404, "NoSuchCORSConfiguration"),
            None => s3_error(404, "NoSuchBucket"),
        };
    }
    if parts.method == Method::PUT && !key.is_empty() {
        let etag = if query.contains("partNumber=") {
            "\"part-etag\""
        } else {
            "\"object-etag\""
        };
        return Response::builder()
            .status(200)
            .header("etag", etag)
            .body(Full::new(Bytes::new()))
            .unwrap();
    }
    s3_error(501, "NotImplemented")
}

// ── the gateway under test ──────────────────────────────────────────────────────────────

struct Harness {
    fx: common::Fixture,
    stub: Arc<StubState>,
    base: String,
}

async fn harness(tag: &str) -> Harness {
    harness_with(tag, common::alice_bundle(), |_| {}).await
}

/// `adjust` runs on the gateway before it is shared, which is the only time its parts can be
/// replaced.
async fn harness_with(
    tag: &str,
    bundle: serde_json::Value,
    adjust: impl FnOnce(&mut s0::gateway::Gateway),
) -> Harness {
    let stub = Arc::new(StubState::default());
    stub.set("reports", Some(OPERATOR_RULE));
    stub.set("named-origin", Some(NAMED_RULES));
    stub.set("bare-bucket", None);
    let backend = stub_backend(stub.clone()).await;

    let mut fx = common::fixture_with_backend(tag, bundle, &backend);
    adjust(Arc::get_mut(&mut fx.gw).expect("the fixture is the gateway's only owner"));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);
    let gw = fx.gw.clone();
    tokio::spawn(async move {
        let _ = s0::server::serve_with_shutdown(gw, addr, std::future::pending::<()>()).await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Harness {
        fx,
        stub,
        base: format!("http://{addr}"),
    }
}

impl Harness {
    fn sdk(&self, access_key: &str, secret: &str, token: Option<&str>) -> aws_sdk_s3::Client {
        let creds = Credentials::new(access_key, secret, token.map(str::to_string), None, "cors");
        let conf = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .endpoint_url(self.base.clone())
            .region(Region::new("us-east-1"))
            .credentials_provider(creds)
            .force_path_style(true)
            .build();
        aws_sdk_s3::Client::from_conf(conf)
    }

    fn static_sdk(&self) -> aws_sdk_s3::Client {
        self.sdk(common::ACCESS_KEY, common::SECRET_KEY, None)
    }

    fn metrics(&self) -> Arc<s0::cors::CorsMetrics> {
        self.fx.gw.cors.metrics()
    }

    /// Anything that is not a preflight the gateway answered must not have been decided
    /// by the policy engine or recorded as an access decision.
    async fn assert_no_decision_was_made(&self) {
        assert_eq!(
            self.fx.pdp_calls(),
            0,
            "a preflight reached the policy engine"
        );
        let records = self.fx.await_audit_records(0).await;
        assert!(records.is_empty(), "a preflight was audited: {records:?}");
    }
}

fn presign_cfg() -> PresigningConfig {
    PresigningConfig::expires_in(Duration::from_secs(900)).unwrap()
}

async fn presign_put(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> String {
    client
        .put_object()
        .bucket(bucket)
        .key(key)
        .presigned(presign_cfg())
        .await
        .unwrap()
        .uri()
        .to_string()
}

async fn presign_upload_part(client: &aws_sdk_s3::Client, bucket: &str, key: &str) -> String {
    client
        .upload_part()
        .bucket(bucket)
        .key(key)
        .upload_id("u-1")
        .part_number(1)
        .presigned(presign_cfg())
        .await
        .unwrap()
        .uri()
        .to_string()
}

struct Snap {
    status: u16,
    headers: HeaderMap,
    body: String,
}

impl Snap {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.headers
            .get_all(name)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect()
    }

    fn cors_headers(&self) -> Vec<String> {
        self.headers
            .keys()
            .map(|k| k.as_str().to_string())
            .filter(|k| k.starts_with("access-control-"))
            .collect()
    }
}

async fn send(req: reqwest::RequestBuilder) -> Snap {
    let resp = req.send().await.expect("the gateway answers");
    Snap {
        status: resp.status().as_u16(),
        headers: resp.headers().clone(),
        body: resp.text().await.unwrap_or_default(),
    }
}

/// What a browser sends before a cross-origin `PUT` with a `Content-Type`.
async fn preflight(url: &str, origin: &str, method: &str, headers: Option<&str>) -> Snap {
    let mut req = reqwest::Client::new()
        .request(Method::OPTIONS, url)
        .header("origin", origin)
        .header("access-control-request-method", method);
    if let Some(headers) = headers {
        req = req.header("access-control-request-headers", headers);
    }
    send(req).await
}

async fn browser_put(url: &str, origin: Option<&str>) -> Snap {
    let mut req = reqwest::Client::new()
        .put(url)
        .header("content-type", "application/pdf")
        .body("hello");
    if let Some(origin) = origin {
        req = req.header("origin", origin);
    }
    send(req).await
}

// ── the preflight, as the Hyperfluid console exercises it ───────────────────────────────

#[tokio::test]
async fn a_preflight_for_a_presigned_put_is_answered_from_the_buckets_rule() {
    let h = harness("cors-preflight").await;
    let url = presign_put(&h.static_sdk(), "reports", "2024/x.pdf").await;

    let resp = preflight(&url, ORIGIN, "PUT", Some("content-type")).await;

    assert_eq!(resp.status, 200, "{}", resp.body);
    assert_eq!(resp.header("access-control-allow-origin"), Some("*"));
    assert_eq!(resp.header("access-control-allow-methods"), Some("PUT"));
    assert_eq!(
        resp.header("access-control-allow-headers"),
        Some("content-type")
    );
    assert_eq!(resp.header("access-control-expose-headers"), Some("ETag"));
    assert_eq!(resp.header("access-control-max-age"), Some("3000"));
    let vary = resp.all("vary").join(",");
    assert!(vary.contains("Origin"), "{vary}");
    assert_eq!(h.stub.reads("reports"), 1);
    assert_eq!(h.metrics().preflight_allowed(), 1);
    assert_eq!(h.metrics().preflight_denied_total(), 0);
    h.assert_no_decision_was_made().await;
}

#[tokio::test]
async fn the_credential_may_be_an_sts_session_whose_token_is_in_the_query() {
    let h = harness("cors-sts").await;
    let sts = h.fx.gw.identity.sts();
    let session = |tenant: &str| {
        sts.mint(
            "sid-cors",
            SessionClaims {
                sub: "alice".into(),
                principal_type: PrincipalType::User,
                groups: vec![],
                tenant: tenant.into(),
                org: "org-acme".into(),
                sid: "sid-cors".into(),
                exp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    + 3600,
            },
        )
        .unwrap()
    };

    let s = session("acme");
    let client = h.sdk(
        &s.access_key_id,
        &s.secret_access_key,
        Some(&s.session_token),
    );
    let url = presign_put(&client, "reports", "2024/x.pdf").await;
    assert!(url.contains("X-Amz-Security-Token="), "{url}");
    assert_eq!(preflight(&url, ORIGIN, "PUT", None).await.status, 200);

    // The same session, its token altered: the identity is rejected, and nothing says why.
    let forged = url.replace("X-Amz-Security-Token=", "X-Amz-Security-Token=x");
    assert_eq!(preflight(&forged, ORIGIN, "PUT", None).await.status, 403);
    assert_eq!(h.metrics().preflight_denied(Denial::IdentityRejected), 1);

    // A genuine session for a tenant this gateway does not route.
    let s = session("nowhere");
    let client = h.sdk(
        &s.access_key_id,
        &s.secret_access_key,
        Some(&s.session_token),
    );
    let url = presign_put(&client, "reports", "2024/x.pdf").await;
    assert_eq!(preflight(&url, ORIGIN, "PUT", None).await.status, 403);
    assert_eq!(h.metrics().preflight_denied(Denial::TenantNotRoutable), 1);

    // Only the first read of `reports` reached the backend: the rejected ones never got
    // that far.
    assert_eq!(h.stub.reads("reports"), 1);
}

#[tokio::test]
async fn the_credential_may_be_a_derived_long_lived_key() {
    let authority = Arc::new(DerivedKeyAuthority::new(vec![9u8; 32]).unwrap());
    let mut bundle = common::alice_bundle();
    bundle["tenants"]["acme"]["s3_key_epoch"] = serde_json::json!(1);
    let h = harness_with("cors-derived", bundle, |gw| {
        let derived = DerivedKeys::new(authority.clone(), gw.registry.clone(), gw.bundles.clone());
        gw.identity = Arc::new(
            Identity::new(gw.identity.sts(), gw.credentials.clone())
                .with_derived_keys(Arc::new(derived)),
        );
    })
    .await;
    let key = authority
        .mint(&DerivedPrincipal {
            tenant: "acme".into(),
            sub: "alice".into(),
            principal_type: PrincipalType::User,
            key_epoch: 1,
        })
        .unwrap();
    let client = h.sdk(&key.access_key_id, &key.secret_access_key, None);
    let url = presign_put(&client, "reports", "2024/x.pdf").await;

    assert_eq!(preflight(&url, ORIGIN, "PUT", None).await.status, 200);

    // Revoked at the bundle, the key stops naming a tenant, so the preflight is refused.
    let mut revoked = common::alice_bundle();
    revoked["tenants"]["acme"]["s3_key_epoch"] = serde_json::json!(2);
    let raw = revoked.to_string();
    h.fx.gw.bundles.store(s0::pdp::Bundle::new(
        s0::pdp::content_revision(&raw),
        revoked,
    ));
    assert_eq!(preflight(&url, ORIGIN, "PUT", None).await.status, 403);
}

// ── what a rule allows ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_named_origin_is_echoed_and_the_first_matching_rule_wins() {
    let h = harness("cors-named").await;
    let url = presign_put(&h.static_sdk(), "named-origin", "x.pdf").await;

    // The second rule: origin, method and (via `*`) the requested header all match.
    let ok = preflight(
        &url,
        "https://app.example.com",
        "PUT",
        Some("content-type, x-custom"),
    )
    .await;
    assert_eq!(ok.status, 200, "{}", ok.body);
    assert_eq!(
        ok.header("access-control-allow-origin"),
        Some("https://app.example.com")
    );
    assert_eq!(ok.header("access-control-allow-methods"), Some("PUT, GET"));
    assert_eq!(
        ok.header("access-control-allow-headers"),
        Some("content-type, x-custom")
    );
    assert_eq!(
        ok.header("access-control-expose-headers"),
        Some("ETag, x-amz-request-id")
    );
    assert_eq!(ok.header("access-control-max-age"), Some("60"));
    assert!(ok.all("vary").join(",").contains("Origin"));

    // A wildcard origin pattern.
    let partner = preflight(&url, "https://eu.partner.example.com", "GET", None).await;
    assert_eq!(partner.status, 200);
    assert_eq!(
        partner.header("access-control-allow-origin"),
        Some("https://eu.partner.example.com")
    );

    // The first rule's origin, asking for a method only the second rule allows.
    assert_eq!(
        preflight(&url, "https://reader.example.com", "PUT", None)
            .await
            .status,
        403
    );
    // …and for the method it does allow.
    let read = preflight(&url, "https://reader.example.com", "GET", None).await;
    assert_eq!(read.status, 200);
    assert_eq!(
        read.header("access-control-expose-headers"),
        Some("x-first")
    );
}

#[tokio::test]
async fn every_refusal_is_the_same_response() {
    let h = harness("cors-refusals").await;
    let sdk = h.static_sdk();
    let good = presign_put(&sdk, "reports", "2024/x.pdf").await;
    let named = presign_put(&sdk, "named-origin", "x.pdf").await;
    let bare = presign_put(&sdk, "bare-bucket", "x.pdf").await;
    let ghost = presign_put(&sdk, "ghost-bucket", "x.pdf").await;
    let invalid = good.replace("/reports/", "/Not_A_Bucket/");
    let unknown_key = {
        let other = h.sdk("AKIANOSUCHKEY", "whatever", None);
        presign_put(&other, "reports", "2024/x.pdf").await
    };
    let no_credential = good.split('?').next().unwrap().to_string();

    let mut refusals: Vec<(&str, Snap)> = vec![
        (
            "origin not allowed by the rule",
            preflight(&named, "https://evil.example", "PUT", None).await,
        ),
        (
            "method not allowed",
            preflight(&good, ORIGIN, "DELETE", Some("content-type")).await,
        ),
        (
            "header not allowed",
            preflight(&good, ORIGIN, "PUT", Some("content-type, authorization")).await,
        ),
        (
            "no CORS configuration on the bucket",
            preflight(&bare, ORIGIN, "PUT", None).await,
        ),
        (
            "no such bucket",
            preflight(&ghost, ORIGIN, "PUT", None).await,
        ),
        (
            "invalid bucket name",
            preflight(&invalid, ORIGIN, "PUT", None).await,
        ),
        (
            "unknown access key",
            preflight(&unknown_key, ORIGIN, "PUT", None).await,
        ),
        (
            "no credential",
            preflight(&no_credential, ORIGIN, "PUT", None).await,
        ),
    ];
    let malformed = [
        (
            "no Access-Control-Request-Method",
            reqwest::Client::new()
                .request(Method::OPTIONS, &good)
                .header("origin", ORIGIN),
        ),
        (
            "no Origin",
            reqwest::Client::new()
                .request(Method::OPTIONS, &good)
                .header("access-control-request-method", "PUT"),
        ),
        (
            "neither",
            reqwest::Client::new().request(Method::OPTIONS, &good),
        ),
        (
            "not a bucket at all",
            reqwest::Client::new()
                .request(Method::OPTIONS, format!("{}/", h.base))
                .header("origin", ORIGIN)
                .header("access-control-request-method", "PUT"),
        ),
    ];
    for (what, req) in malformed {
        refusals.push((what, send(req).await));
    }

    let reference = &refusals[0].1;
    assert_eq!(reference.status, 403);
    let mut names: Vec<String> = reference
        .headers
        .keys()
        .map(|k| k.as_str().to_string())
        .collect();
    names.sort();
    for (what, snap) in &refusals {
        assert_eq!(snap.status, 403, "{what}");
        assert_eq!(snap.body, reference.body, "{what}: a distinguishable body");
        assert!(
            snap.cors_headers().is_empty(),
            "{what}: {:?}",
            snap.cors_headers()
        );
        let mut got: Vec<String> = snap
            .headers
            .keys()
            .map(|k| k.as_str().to_string())
            .collect();
        got.sort();
        assert_eq!(got, names, "{what}: a distinguishable header set");
        assert_eq!(
            snap.header("content-type"),
            reference.header("content-type"),
            "{what}"
        );
    }

    let m = h.metrics();
    assert_eq!(m.preflight_allowed(), 0);
    assert_eq!(m.preflight_denied_total(), refusals.len() as u64);
    assert_eq!(m.preflight_denied(Denial::NotAllowed), 3);
    assert_eq!(m.preflight_denied(Denial::NoConfiguration), 1);
    assert_eq!(m.preflight_denied(Denial::LookupFailed), 1);
    assert_eq!(m.preflight_denied(Denial::InvalidBucket), 1);
    assert_eq!(m.preflight_denied(Denial::IdentityRejected), 1);
    assert_eq!(m.preflight_denied(Denial::NoCredential), 2);
    assert_eq!(m.preflight_denied(Denial::Malformed), 3);
    h.assert_no_decision_was_made().await;
}

#[tokio::test]
async fn an_options_request_never_reaches_s3s() {
    let h = harness("cors-options").await;
    let resp = send(reqwest::Client::new().request(Method::OPTIONS, format!("{}/", h.base))).await;
    assert_eq!(resp.status, 403, "s3s would have answered 501");
    h.assert_no_decision_was_made().await;
}

// ── the real request ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_put_and_an_upload_part_expose_their_etag_to_the_browser() {
    let h = harness("cors-actual").await;
    let sdk = h.static_sdk();

    let put = browser_put(
        &presign_put(&sdk, "reports", "2024/x.pdf").await,
        Some(ORIGIN),
    )
    .await;
    assert_eq!(put.status, 200, "{}", put.body);
    assert_eq!(put.header("access-control-allow-origin"), Some("*"));
    assert_eq!(put.header("access-control-expose-headers"), Some("ETag"));
    assert_eq!(put.header("etag"), Some("\"object-etag\""));
    assert!(put.all("vary").join(",").contains("Origin"));

    let part_url = presign_upload_part(&sdk, "reports", "2024/big.bin").await;
    assert!(part_url.contains("partNumber=1") && part_url.contains("uploadId=u-1"));
    // The browser's preflight for the part carries the same query string as the part.
    assert_eq!(
        preflight(&part_url, ORIGIN, "PUT", Some("content-type"))
            .await
            .status,
        200
    );
    let part = browser_put(&part_url, Some(ORIGIN)).await;
    assert_eq!(part.status, 200, "{}", part.body);
    assert_eq!(part.header("access-control-allow-origin"), Some("*"));
    assert_eq!(part.header("access-control-expose-headers"), Some("ETag"));
    assert_eq!(part.header("etag"), Some("\"part-etag\""));

    assert_eq!(h.metrics().responses_decorated(), 2);
}

#[tokio::test]
async fn an_s3_error_response_is_decorated_like_a_success() {
    let h = harness("cors-error").await;
    // `alice` holds no grant on this bucket, so the gate answers 403 AccessDenied.
    let url = presign_put(&h.static_sdk(), "named-origin", "x.pdf").await;

    let allowed_origin = browser_put(&url, Some("https://app.example.com")).await;
    assert_eq!(allowed_origin.status, 403);
    assert!(
        allowed_origin.body.contains("AccessDenied"),
        "{}",
        allowed_origin.body
    );
    assert_eq!(
        allowed_origin.header("access-control-allow-origin"),
        Some("https://app.example.com")
    );
    assert!(allowed_origin.all("vary").join(",").contains("Origin"));

    let other_origin = browser_put(&url, Some("https://evil.example")).await;
    assert_eq!(other_origin.status, 403);
    assert!(other_origin.cors_headers().is_empty());
}

#[tokio::test]
async fn a_header_signed_request_names_its_credential_in_the_authorization_header() {
    let h = harness("cors-header-signed").await;
    let host = h.base.trim_start_matches("http://").to_string();
    let req = RawRequest::new("PUT", "/reports/2024/y.pdf")
        .header("origin", ORIGIN)
        .body(b"hello".to_vec());
    let signed = req.sign(&host, common::ACCESS_KEY, common::SECRET_KEY);
    let mut builder = reqwest::Client::new()
        .put(req.url(&h.base))
        .body(b"hello".to_vec());
    for (k, v) in signed {
        builder = builder.header(k, v);
    }

    let resp = send(builder).await;

    assert_eq!(resp.status, 200, "{}", resp.body);
    assert_eq!(resp.header("access-control-allow-origin"), Some("*"));
    assert_eq!(resp.header("access-control-expose-headers"), Some("ETag"));
}

#[tokio::test]
async fn a_request_without_an_origin_is_untouched_and_costs_no_backend_read() {
    let h = harness("cors-no-origin").await;
    let url = presign_put(&h.static_sdk(), "reports", "2024/x.pdf").await;

    let resp = browser_put(&url, None).await;

    assert_eq!(resp.status, 200, "{}", resp.body);
    assert!(resp.cors_headers().is_empty(), "{:?}", resp.cors_headers());
    assert!(resp.all("vary").is_empty());
    assert_eq!(resp.header("etag"), Some("\"object-etag\""));
    assert_eq!(
        h.stub.total_reads(),
        0,
        "a request with no Origin read bucket CORS"
    );
    assert_eq!(h.metrics().responses_decorated(), 0);
}

#[tokio::test]
async fn an_origin_no_rule_allows_gets_a_plain_response() {
    let h = harness("cors-not-allowed").await;
    // The operator's rule allows PUT. A browser GET matches nothing, so the response is
    // whatever s0 would have sent anyway.
    let url = h
        .static_sdk()
        .get_object()
        .bucket("reports")
        .key("2024/x.pdf")
        .presigned(presign_cfg())
        .await
        .unwrap()
        .uri()
        .to_string();

    let resp = send(reqwest::Client::new().get(url).header("origin", ORIGIN)).await;

    assert!(resp.cors_headers().is_empty(), "{:?}", resp.cors_headers());
    assert!(resp.all("vary").is_empty());
    assert_eq!(h.metrics().responses_decorated(), 0);
}

// ── the cache ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_burst_of_preflights_reads_the_configuration_once_and_absence_is_cached() {
    let h = harness("cors-cache").await;
    let sdk = h.static_sdk();
    let url = presign_put(&sdk, "reports", "2024/x.pdf").await;
    let bare = presign_put(&sdk, "bare-bucket", "x.pdf").await;
    let ghost = presign_put(&sdk, "ghost-bucket", "x.pdf").await;

    let burst: Vec<_> = (0..12)
        .map(|_| {
            let url = url.clone();
            tokio::spawn(async move { preflight(&url, ORIGIN, "PUT", Some("content-type")).await })
        })
        .collect();
    for task in burst {
        assert_eq!(task.await.unwrap().status, 200);
    }
    assert_eq!(
        h.stub.reads("reports"),
        1,
        "concurrent misses must share one read"
    );

    for _ in 0..3 {
        assert_eq!(preflight(&bare, ORIGIN, "PUT", None).await.status, 403);
        assert_eq!(preflight(&ghost, ORIGIN, "PUT", None).await.status, 403);
    }
    assert_eq!(
        h.stub.reads("bare-bucket"),
        1,
        "'no CORS configuration' is cached"
    );
    assert_eq!(
        h.stub.reads("ghost-bucket"),
        1,
        "a failed read is cached briefly"
    );
    assert_eq!(h.metrics().backend_lookups(), 3);
    assert_eq!(h.metrics().backend_lookup_failures(), 0);
}

#[tokio::test]
async fn a_rule_written_after_a_negative_answer_is_honoured_once_the_entry_expires() {
    let h = harness_with("cors-expiry", common::alice_bundle(), |gw| {
        gw.cors = Arc::new(CorsState::with_timings(
            Duration::from_millis(400),
            Duration::from_millis(100),
            Duration::from_secs(3),
        ));
    })
    .await;
    let url = presign_put(&h.static_sdk(), "late-rule", "x.pdf").await;

    // The bucket does not exist yet: refused, and the refusal is remembered briefly.
    assert_eq!(preflight(&url, ORIGIN, "PUT", None).await.status, 403);
    h.stub.set("late-rule", None);
    tokio::time::sleep(Duration::from_millis(250)).await;
    // The bucket exists with no rule: refused, and that is remembered for the longer TTL.
    assert_eq!(preflight(&url, ORIGIN, "PUT", None).await.status, 403);
    h.stub.set("late-rule", Some(OPERATOR_RULE));
    assert_eq!(
        preflight(&url, ORIGIN, "PUT", None).await.status,
        403,
        "the rule is not visible until the cached absence expires"
    );

    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(preflight(&url, ORIGIN, "PUT", None).await.status, 200);
    assert_eq!(h.stub.reads("late-rule"), 3);
}
