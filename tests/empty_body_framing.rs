//! A body-less `PUT`/`POST` must reach the backend with `Content-Length: 0`: Ceph RGW
//! refuses an unframed `UploadPartCopy` with `411 MissingContentLength`. These tests drive
//! the real hook and dispatch arm into a backend that refuses it the same way.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use http::Method;
use s0::access::GatewayAccess;
use s0::proxy::{GatewayS3, S3GatewayState};
use s3s::S3;
use s3s::access::S3Access;
use s3s::dto::CreateMultipartUploadInput;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A backend that answers `UploadPartCopy`, `CopyObject` and `CreateMultipartUpload`,
/// and answers `411 MissingContentLength` to a `PUT`/`POST` that declares no body framing.
async fn rgw_like_backend() -> (String, Arc<Mutex<Vec<String>>>) {
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
                let (status, body) = if (head.starts_with("PUT ") || head.starts_with("POST "))
                    && header(&head, "content-length").is_none()
                    && header(&head, "transfer-encoding").is_none()
                {
                    (
                        "411 Length Required",
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <Error><Code>MissingContentLength</Code><Message></Message></Error>",
                    )
                } else if head.contains("?uploads") {
                    (
                        "200 OK",
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                         <Bucket>reports</Bucket><Key>2024/dst.csv</Key><UploadId>u-1</UploadId>\
                         </InitiateMultipartUploadResult>",
                    )
                } else if head.contains("uploadId=") {
                    (
                        "200 OK",
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <CopyPartResult><ETag>\"abc\"</ETag></CopyPartResult>",
                    )
                } else {
                    (
                        "200 OK",
                        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                         <CopyObjectResult><ETag>\"abc\"</ETag></CopyObjectResult>",
                    )
                };
                seen.lock().expect("heads").push(head);
                let resp = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/xml\r\n\
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

/// The value of the one `name` header in a request head, if there is one.
fn header<'h>(head: &'h str, name: &str) -> Option<&'h str> {
    head.lines()
        .filter_map(|l| l.split_once(':'))
        .find(|(n, _)| n.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

fn gateway_s3(fx: &common::Fixture) -> GatewayS3 {
    GatewayS3::new(Arc::new(S3GatewayState::new(
        fx.gw.registry.clone(),
        fx.gw.limits.clone(),
    )))
}

fn only_head(heads: &Mutex<Vec<String>>) -> String {
    let heads = heads.lock().expect("heads");
    assert_eq!(heads.len(), 1, "exactly one request must reach the backend");
    heads[0].clone()
}

#[tokio::test]
async fn an_upload_part_copy_is_forwarded_with_an_explicit_zero_length() {
    let (url, heads) = rgw_like_backend().await;
    let fx = common::fixture_with_backend("ebf-upc", common::alice_bundle(), &url);
    let mut req = fx.request(
        "UploadPartCopy",
        common::ops::upload_part_copy_input(),
        Method::PUT,
    );
    GatewayAccess::new(fx.gw.clone())
        .upload_part_copy(&mut req)
        .await
        .expect("alice may copy within 2024/");
    gateway_s3(&fx)
        .upload_part_copy(req)
        .await
        .expect("a backend that requires body framing accepts the forward");
    assert_eq!(header(&only_head(&heads), "content-length"), Some("0"));
}

#[tokio::test]
async fn a_copy_object_is_forwarded_with_an_explicit_zero_length() {
    let (url, heads) = rgw_like_backend().await;
    let fx = common::fixture_with_backend("ebf-copy", common::alice_bundle(), &url);
    let mut req = fx.request("CopyObject", common::ops::copy_object_input(), Method::PUT);
    GatewayAccess::new(fx.gw.clone())
        .copy_object(&mut req)
        .await
        .expect("alice may copy within 2024/");
    gateway_s3(&fx)
        .copy_object(req)
        .await
        .expect("a backend that requires body framing accepts the forward");
    assert_eq!(header(&only_head(&heads), "content-length"), Some("0"));
}

#[tokio::test]
async fn a_create_multipart_upload_is_forwarded_with_an_explicit_zero_length() {
    let (url, heads) = rgw_like_backend().await;
    let fx = common::fixture_with_backend("ebf-mpu", common::alice_bundle(), &url);
    let mut req = fx.request(
        "CreateMultipartUpload",
        CreateMultipartUploadInput {
            bucket: "reports".into(),
            key: "2024/dst.csv".into(),
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
        .expect("a backend that requires body framing accepts the forward");
    assert_eq!(header(&only_head(&heads), "content-length"), Some("0"));
}
