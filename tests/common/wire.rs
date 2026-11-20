//! Signed requests over real HTTP into an assembled gateway, for the suites that measure
//! what crosses the wire rather than what a hook returns.

use std::net::SocketAddr;
use std::time::Duration;

use super::routes;
use super::sigv4::RawRequest;
use super::{ACCESS_KEY, Fixture, SECRET_KEY};

/// Serve `fx`'s gateway on a loopback port through the real serving path and return its
/// base URL.
pub async fn serve(fx: &Fixture) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
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
    format!("http://{addr}")
}

pub struct Answer {
    pub status: u16,
    pub headers: http::HeaderMap,
    pub body: String,
}

impl Answer {
    pub fn request_id(&self) -> Option<&str> {
        self.headers
            .get("x-amz-request-id")
            .and_then(|v| v.to_str().ok())
    }
}

/// A minimal valid body for each delegable operation that carries one.
pub fn delegable_body(op: &str) -> Vec<u8> {
    match op {
        "PutBucketCors" => {
            "<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod>\
            <AllowedOrigin>https://app.example</AllowedOrigin></CORSRule></CORSConfiguration>"
        }
        "PutBucketLifecycleConfiguration" => {
            "<LifecycleConfiguration><Rule><ID>expire</ID>\
            <Status>Enabled</Status><Filter><Prefix>tmp/</Prefix></Filter>\
            <Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
        }
        "PutBucketTagging" => {
            "<Tagging><TagSet><Tag><Key>team</Key><Value>data</Value></Tag>\
            </TagSet></Tagging>"
        }
        "PutBucketVersioning" => {
            "<VersioningConfiguration><Status>Enabled</Status>\
            </VersioningConfiguration>"
        }
        "PutBucketEncryption" => {
            "<ServerSideEncryptionConfiguration><Rule>\
            <ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm>\
            </ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"
        }
        _ => "",
    }
    .as_bytes()
    .to_vec()
}

/// Send `op`'s smallest valid request for `bucket`, signed as the fixture's static
/// credential.
pub async fn send_op(base: &str, op: &str, bucket: &str) -> Answer {
    let route = routes::route(op);
    let host = base.trim_start_matches("http://").to_string();
    let mut req = RawRequest::new(route.method, format!("/{bucket}")).body(delegable_body(op));
    for (k, v) in &route.query {
        req = req.query(k, v);
    }
    for (k, v) in &route.headers {
        req = req.header(k, v);
    }
    send_raw(base, &host, req, ACCESS_KEY, SECRET_KEY).await
}

pub async fn send_raw(
    base: &str,
    host: &str,
    req: RawRequest,
    access_key: &str,
    secret_key: &str,
) -> Answer {
    let headers = req.sign(host, access_key, secret_key);
    let mut builder = reqwest::Client::new()
        .request(req.method.parse().expect("http method"), req.url(base))
        .timeout(Duration::from_secs(20))
        .body(req.body.clone());
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder.send().await.expect("the gateway answered");
    Answer {
        status: resp.status().as_u16(),
        headers: resp.headers().clone(),
        body: resp.text().await.unwrap_or_default(),
    }
}
