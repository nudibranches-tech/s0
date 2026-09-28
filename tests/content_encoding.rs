//! `Content-Encoding: aws-chunked` is how the *client* framed its request body; s3s has
//! already decoded it by the time a hook runs. Forwarded as object metadata, the backend
//! SDK appends its own `aws-chunked` for its own checksum trailer, and signs a request
//! carrying two `Content-Encoding` values that the backend canonicalizes as one — every
//! PutObject from an SDK with default flexible checksums then fails SigV4 upstream (#25).
//!
//! These tests drive the real hook and the real dispatch arm into a backend that records
//! the request head, so they observe what actually leaves the gateway.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http::Method;
use s0::access::GatewayAccess;
use s0::proxy::{GatewayS3, S3GatewayState};
use s3s::access::S3Access;
use s3s::dto::{CreateMultipartUploadInput, PutObjectInput, StreamingBlob};
use s3s::{Body, S3};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A backend that answers `PutObject` and `CreateMultipartUpload`, keeping every request
/// head it received.
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
                let head = String::from_utf8_lossy(&head).to_string();
                let body = if head.contains("?uploads") {
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <Bucket>reports</Bucket><Key>2024/x</Key><UploadId>u-1</UploadId>\
                     </InitiateMultipartUploadResult>"
                } else {
                    ""
                };
                seen.lock().expect("heads").push(head);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\netag: \"abc\"\r\ncontent-type: application/xml\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
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

/// Every `Content-Encoding` value in a request head, in order, split on commas.
fn content_encodings(head: &str) -> Vec<String> {
    head.lines()
        .filter_map(|l| l.split_once(':'))
        .filter(|(name, _)| name.trim().eq_ignore_ascii_case("content-encoding"))
        .flat_map(|(_, v)| v.split(',').map(|c| c.trim().to_string()))
        .filter(|c| !c.is_empty())
        .collect()
}

fn only_head(heads: &Mutex<Vec<String>>) -> String {
    let heads = heads.lock().expect("heads");
    assert_eq!(heads.len(), 1, "exactly one request must reach the backend");
    heads[0].clone()
}

async fn put_with_encoding(tag: &str, encoding: &str) -> String {
    let (url, heads) = recording_backend().await;
    let fx = common::fixture_with_backend(tag, common::alice_bundle(), &url);
    let body = b"hello".to_vec();
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            content_length: Some(body.len() as i64),
            content_encoding: Some(encoding.into()),
            body: Some(StreamingBlob::from(Body::from(body))),
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
    only_head(&heads)
}

#[tokio::test]
async fn an_aws_chunked_put_is_forwarded_with_one_content_encoding() {
    let head = put_with_encoding("ce-put-chunked", "aws-chunked").await;
    let encodings = content_encodings(&head);
    // The backend SDK frames its own body as aws-chunked for its checksum trailer, so one
    // `aws-chunked` is expected. Two is the bug: the client's was forwarded as metadata.
    assert!(
        encodings.iter().filter(|c| *c == "aws-chunked").count() <= 1,
        "the client's aws-chunked must not be forwarded next to the backend SDK's own: \
         {encodings:?}\n{head}"
    );
}

#[tokio::test]
async fn a_real_content_coding_survives_next_to_aws_chunked() {
    let head = put_with_encoding("ce-put-gzip", "gzip,aws-chunked").await;
    let encodings = content_encodings(&head);
    assert!(
        encodings.contains(&"gzip".to_string()),
        "gzip describes the object and must reach the backend: {encodings:?}"
    );
    assert!(
        encodings.iter().filter(|c| *c == "aws-chunked").count() <= 1,
        "only the backend SDK's own aws-chunked may remain: {encodings:?}"
    );
}

#[tokio::test]
async fn a_multipart_upload_does_not_store_aws_chunked_as_object_metadata() {
    let (url, heads) = recording_backend().await;
    let fx = common::fixture_with_backend("ce-mpu", common::alice_bundle(), &url);
    let mut req = fx.request(
        "CreateMultipartUpload",
        CreateMultipartUploadInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            content_encoding: Some("aws-chunked".into()),
            ..Default::default()
        },
        Method::POST,
    );
    GatewayAccess::new(fx.gw.clone())
        .create_multipart_upload(&mut req)
        .await
        .expect("alice may write under 2024/");
    gateway_s3(&fx)
        .create_multipart_upload(req)
        .await
        .expect("the backend accepts the forward");

    let head = only_head(&heads);
    assert!(
        content_encodings(&head).is_empty(),
        "CreateMultipartUpload carries no body, so any Content-Encoding it forwards is \
         stored on the object: {head}"
    );
}
