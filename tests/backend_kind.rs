//! S0.1: the `BackendKind::S3` vocabulary (B2) and region acceptance.
//!
//! Two properties, both already true of the underlying machinery and neither touched by
//! the B2 rename itself — these are regression tests pinning them down, not new
//! behavior:
//!
//! 1. **Inbound**: s3s verifies a SigV4 signature against the region carried in its OWN
//!    Authorization header, never against a value this gateway configures, so a client
//!    scoped to `default`, `us-east-1` or `local` must all verify so long as the
//!    signature itself is correct over that scope.
//! 2. **Outbound**: the proxy always re-signs the forwarded request with
//!    `BackendConfig.region` (`build_proxy`, `src/proxy/mod.rs`), never with whatever
//!    region the inbound client happened to sign with. An S3 backend refuses a SigV4
//!    scope whose region is not its own (AWS answers `AuthorizationHeaderMalformed`), so
//!    an `s3` backend with `region: "eu-west-3"` must re-sign in that scope even when
//!    nothing on the inbound side ever mentioned it.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::sigv4::RawRequest;
use http::Method;
use s0::access::GatewayAccess;
use s0::model::BackendKind;
use s0::proxy::{GatewayS3, S3GatewayState};
use s3s::access::S3Access;
use s3s::dto::PutObjectInput;
use s3s::{Body, S3};

/// Boot the real serving path on a loopback port — the only way to exercise s3s's own
/// SigV4 verification, which lives behind crate-private fields `S3AccessContext` cannot
/// be constructed around in-process.
async fn spawn_gateway(tag: &str, bundle: serde_json::Value) -> (String, common::Fixture) {
    let fx = common::fixture(tag, bundle);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);
    let gw = fx.gw.clone();
    tokio::spawn(async move {
        let _ = s0::server::serve_with_shutdown(gw, addr, std::future::pending::<()>()).await;
    });
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    (format!("http://{addr}"), fx)
}

/// Sign a `HeadBucket` on `reports` (alice holds the bucket-scoped `read` grant, §
/// `common::alice_bundle`) with the given credential-scope region, and return the status
/// and body. The backend endpoint is a closed port (`common::fixture`'s default), so a
/// request that clears the gate still fails — loudly, as a backend error — rather than
/// quietly succeeding against something real; the only question this answers is whether
/// the *signature* was accepted.
async fn head_bucket_scoped(base: &str, region: &str) -> (u16, String) {
    let host = base.trim_start_matches("http://").to_string();
    let r = RawRequest::new("HEAD", "/reports");
    let headers = r.sign_scoped(&host, common::ACCESS_KEY, common::SECRET_KEY, region);
    let mut builder = reqwest::Client::new()
        .request(Method::HEAD, r.url(base))
        .timeout(Duration::from_secs(10));
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder
        .send()
        .await
        .expect("the gateway must answer over HTTP");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

/// Every one of these regions is a client s0 must serve: `default` and `local` are what
/// the AWS CLI / SDKs fall back to against a non-AWS endpoint absent an explicit region,
/// and `us-east-1` is the universal SigV4 default.
#[tokio::test]
async fn sigv4_scoped_to_default_us_east_1_or_local_all_verify() {
    let (base, _fx) = spawn_gateway("bkr-scopes", common::alice_bundle()).await;

    for region in ["default", "us-east-1", "local"] {
        let (status, body) = head_bucket_scoped(&base, region).await;
        assert_ne!(
            status, 403,
            "region {region:?} must not be refused at the signature layer: {status} {body}"
        );
        assert!(
            !body.contains("SignatureDoesNotMatch")
                && !body.contains("AuthorizationHeaderMalformed"),
            "region {region:?} was rejected as a signature problem: {body}"
        );
    }
}

/// A scope s3s itself refuses for syntactic reasons (region must be `[a-z0-9-]+`) is the
/// control: without it, a gateway that accepted literally anything would pass the above
/// for the wrong reason.
#[tokio::test]
async fn a_syntactically_invalid_region_is_still_refused() {
    let (base, _fx) = spawn_gateway("bkr-bad-scope", common::alice_bundle()).await;
    // The malformed scope ("Not A Region!" has a space and `!`, neither legal in a
    // region or in a raw header value) is refused before an authorization decision is
    // ever reached — the status is whatever layer caught it first (a bare 400 from the
    // HTTP parser, or a 403 S3 error from s3s's own validation), never 200.
    let (status, body) = head_bucket_scoped(&base, "Not A Region!").await;
    assert_ne!(
        status, 200,
        "a malformed scope must never be accepted: {body}"
    );
}

/// A backend that keeps every request head it received, so the test can read the
/// Authorization header s0 actually put on the wire to the backend.
async fn recording_backend() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let seen = seen.clone();
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut head = Vec::new();
                let mut buf = [0u8; 4096];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                seen.lock()
                    .expect("heads")
                    .push(String::from_utf8_lossy(&head).to_string());
                let resp = "HTTP/1.1 200 OK\r\netag: \"abc\"\r\ncontent-length: 0\r\n\
                            connection: close\r\n\r\n";
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    (format!("http://{addr}"), heads)
}

fn gateway_s3(fx: &common::Fixture) -> GatewayS3 {
    GatewayS3::new(Arc::new(S3GatewayState::new(
        fx.gw.registry.clone(),
        fx.gw.limits.clone(),
    )))
}

/// The region a SigV4 `Authorization` header's credential scope carries
/// (`<key>/<date>/<region>/<service>/aws4_request`).
fn scope_region(head: &str) -> String {
    let auth = head
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
        .unwrap_or_else(|| panic!("no Authorization header reached the backend:\n{head}"));
    let credential = auth
        .split("Credential=")
        .nth(1)
        .unwrap_or_else(|| panic!("no Credential= in {auth}"));
    credential
        .split(',')
        .next()
        .unwrap_or(credential)
        .split('/')
        .nth(2)
        .unwrap_or_else(|| panic!("credential scope too short: {auth}"))
        .to_string()
}

/// s0 re-signs the forwarded request with the BACKEND's configured region, never the
/// inbound client's. Here the backend is `s3` with `region: "eu-west-3"` — the scope the
/// recording backend must see, even though nothing about the request as authorized (the
/// typed-hook path, which never carries an inbound SigV4 header at all) mentions
/// "eu-west-3" anywhere else.
#[tokio::test]
async fn upstream_resigning_uses_the_backend_region_not_the_clients() {
    let (url, heads) = recording_backend().await;
    let fx = common::fixture_with_backend_kind_region(
        "bkr-backend-scope",
        common::alice_bundle(),
        &url,
        BackendKind::S3,
        "eu-west-3",
    );
    let body = b"hello".to_vec();
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            content_length: Some(body.len() as i64),
            body: Some(s3s::dto::StreamingBlob::from(Body::from(body))),
            ..Default::default()
        },
        Method::PUT,
    );
    GatewayAccess::new(fx.gw.clone())
        .put_object(&mut req)
        .await
        .expect("alice may write under 2024/");
    gateway_s3(&fx)
        .put_object(req)
        .await
        .expect("the backend accepts the forward");

    let heads = heads.lock().expect("heads");
    assert_eq!(heads.len(), 1, "exactly one request must reach the backend");
    assert_eq!(
        scope_region(&heads[0]),
        "eu-west-3",
        "the upstream request must carry the backend's configured region, not the \
         gateway's default, in its SigV4 scope:\n{}",
        heads[0]
    );
}
