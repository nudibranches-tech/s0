//! Byte quotas a v3 bundle states for a backend without native ones (ADR-010).
//!
//! A `quota` is `{ limit_bytes, used_bytes, collected_at }` on a bucket, a tenant or the
//! backend. A write the policy allowed is charged `used + counted since + its bytes`
//! against each, and refused with `QuotaExceeded` (403) before it reaches the backend when
//! one would pass its limit. These tests drive the real hooks and, where the backend's
//! answer matters, the real dispatch arm into a backend that records what it was asked.

mod common;

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use common::sigv4::RawRequest;
use http::Method;
use s0::access::{AuthzProof, GatewayAccess};
use s0::audit::{AuditRecord, Outcome};
use s0::config::GatewayConfig;
use s0::pdp::Bundle;
use s0::proxy::{GatewayS3, S3GatewayState};
use s0::quota::{QUOTA_EXCEEDED, QuotaReservation, QuotaScope};
use s3s::access::S3Access;
use s3s::dto::*;
use s3s::{Body, S3, S3Error, S3ErrorCode, S3Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The fixture config's only backend (`common::config_json`).
const BACKEND: &str = "bay-1";

/// The size the backend reports for any copy source it has.
const SOURCE_SIZE: u64 = 70;

fn quota(limit: u64, used: u64, collected_at: chrono::DateTime<chrono::Utc>) -> serde_json::Value {
    serde_json::json!({
        "limit_bytes": limit,
        "used_bytes": used,
        "collected_at": collected_at.to_rfc3339(),
    })
}

fn an_hour_ago() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() - chrono::Duration::hours(1)
}

/// `alice_bundle` at v3 on this backend, `reports` placed under `acme`, with whichever of
/// the three quotas the test states. `mallory` is a member of `acme` holding no grant.
fn quota_bundle(
    bucket: Option<serde_json::Value>,
    tenant: Option<serde_json::Value>,
    backend: Option<serde_json::Value>,
) -> serde_json::Value {
    let mut b = common::alice_bundle();
    b["grant_schema_version"] = serde_json::json!(3);
    b["backend"] = serde_json::json!({ "id": BACKEND, "kind": "s3" });
    let acme = &mut b["tenants"]["acme"];
    acme["user_attributes"]["mallory"] = serde_json::json!({ "groups": [], "attributes": [] });
    acme["bucket_attributes"] = serde_json::json!({
        "reports": { "denylist": {}, "object_name": "reports.bay-1",
                     "created_at": "2026-01-01T00:00:00Z" }
    });
    if let Some(q) = bucket {
        acme["bucket_attributes"]["reports"]["quota"] = q;
    }
    if let Some(q) = tenant {
        acme["quota"] = q;
    }
    if let Some(q) = backend {
        b["backend_quota"] = q;
    }
    b
}

fn bucket_limited(limit: u64, used: u64) -> serde_json::Value {
    quota_bundle(Some(quota(limit, used, an_hour_ago())), None, None)
}

fn reports() -> QuotaScope {
    QuotaScope::Bucket("reports".into())
}

// ── a backend that answers, and records ─────────────────────────────────────────

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    head: String,
}

struct Backend {
    url: String,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Backend {
    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().expect("seen").clone()
    }

    fn count(&self, method: &str) -> usize {
        self.seen().iter().filter(|s| s.method == method).count()
    }
}

/// What the backend answers. Keys ending in `refused` get a 403 and in `broken` a 500;
/// a `HEAD` reports [`SOURCE_SIZE`], except for a key ending in `missing`.
fn answer(method: &str, target: &str, head: &str) -> String {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let error = |status: &str, code: &str| {
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code>\
             <Message>backend says no</Message></Error>"
        );
        format!(
            "HTTP/1.1 {status}\r\ncontent-type: application/xml\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{body}",
            body.len()
        )
    };
    if method == "HEAD" {
        if path.ends_with("missing") {
            return "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                .to_string();
        }
        return format!(
            "HTTP/1.1 200 OK\r\ncontent-length: {SOURCE_SIZE}\r\netag: \"src\"\r\n\
             last-modified: Wed, 01 Oct 2026 12:00:00 GMT\r\nconnection: close\r\n\r\n"
        );
    }
    if path.ends_with("refused") {
        return error("403 Forbidden", "AccessDenied");
    }
    if path.ends_with("broken") {
        return error("500 Internal Server Error", "InternalError");
    }
    let copy = head.to_ascii_lowercase().contains("x-amz-copy-source:");
    let body = if method == "POST" && query.contains("uploads") {
        "<InitiateMultipartUploadResult><Bucket>reports</Bucket><Key>2024/x</Key>\
         <UploadId>u-1</UploadId></InitiateMultipartUploadResult>"
    } else if method == "POST" && query.contains("uploadId") {
        "<CompleteMultipartUploadResult><Bucket>reports</Bucket><Key>2024/x</Key>\
         <ETag>\"abc\"</ETag></CompleteMultipartUploadResult>"
    } else if copy && query.contains("uploadId") {
        "<CopyPartResult><ETag>\"abc\"</ETag>\
         <LastModified>2026-10-01T12:00:00.000Z</LastModified></CopyPartResult>"
    } else if copy {
        "<CopyObjectResult><ETag>\"abc\"</ETag>\
         <LastModified>2026-10-01T12:00:00.000Z</LastModified></CopyObjectResult>"
    } else {
        ""
    };
    let body = if body.is_empty() {
        String::new()
    } else {
        format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>{body}")
    };
    format!(
        "HTTP/1.1 200 OK\r\netag: \"abc\"\r\ncontent-type: application/xml\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

async fn backend() -> Backend {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let log = log.clone();
            tokio::spawn(async move {
                let mut raw = Vec::new();
                let mut buf = [0u8; 4096];
                let head_end = loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                    if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                };
                let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
                let length = head
                    .lines()
                    .filter_map(|l| l.split_once(':'))
                    .find(|(name, _)| name.trim().eq_ignore_ascii_case("content-length"))
                    .and_then(|(_, v)| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                // Drain the body, so the gateway's upload is complete before it is answered.
                while raw.len() < head_end + length {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => raw.extend_from_slice(&buf[..n]),
                    }
                }
                let mut line = head.lines().next().unwrap_or_default().split(' ');
                let method = line.next().unwrap_or_default().to_string();
                let target = line.next().unwrap_or_default().to_string();
                let resp = answer(&method, &target, &head);
                log.lock().expect("seen").push(Seen {
                    method,
                    target,
                    head,
                });
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    Backend {
        url: format!("http://{addr}"),
        seen,
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────────

fn gateway_s3(fx: &common::Fixture) -> GatewayS3 {
    GatewayS3::new(Arc::new(S3GatewayState::new(
        fx.gw.registry.clone(),
        fx.gw.limits.clone(),
    )))
}

fn put(key: &str, len: usize) -> PutObjectInput {
    PutObjectInput {
        bucket: "reports".into(),
        key: key.into(),
        content_length: Some(len as i64),
        body: Some(StreamingBlob::from(Body::from(vec![b'x'; len]))),
        ..Default::default()
    }
}

/// The hook alone: the reservation, if any, stays in flight with the returned request.
async fn admit_put(
    fx: &common::Fixture,
    sub: &str,
    input: PutObjectInput,
) -> Result<S3Request<PutObjectInput>, S3Error> {
    let mut req = fx.request_as(sub, "PutObject", input, Method::PUT);
    GatewayAccess::new(fx.gw.clone())
        .put_object(&mut req)
        .await
        .map(|()| req)
}

/// The hook, then the forward: what a client sees.
async fn put_through(
    fx: &common::Fixture,
    key: &str,
    len: usize,
) -> Result<PutObjectOutput, S3Error> {
    let req = admit_put(fx, "alice", put(key, len)).await?;
    gateway_s3(fx).put_object(req).await.map(|r| r.output)
}

fn assert_quota_exceeded<T: std::fmt::Debug>(
    label: &str,
    result: Result<T, S3Error>,
    message: &str,
) {
    let err = match result {
        Ok(v) => panic!("{label}: must be refused over quota, got {v:?}"),
        Err(e) => e,
    };
    assert_eq!(err.code().as_str(), QUOTA_EXCEEDED, "{label}: {err}");
    assert_eq!(
        err.status_code(),
        Some(http::StatusCode::FORBIDDEN),
        "{label}: RGW's convention for QuotaExceeded"
    );
    assert_eq!(err.message(), Some(message), "{label}");
}

const BUCKET_FULL: &str = "The storage quota for this bucket has been exceeded.";

fn denials(records: &[AuditRecord]) -> Vec<&AuditRecord> {
    records
        .iter()
        .filter(|r| r.input.is_some() && r.gateway.outcome == Outcome::Denied)
        .collect()
}

// ── the limit ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_put_within_the_limit_is_forwarded_and_one_over_it_never_reaches_the_backend() {
    let backend = backend().await;
    let fx = common::fixture_with_backend("quota-put", bucket_limited(100, 40), &backend.url);

    put_through(&fx, "2024/a", 60)
        .await
        .expect("40 used + 60 is exactly the limit");
    assert_eq!(backend.count("PUT"), 1);
    assert_eq!(fx.gw.quota.counted(&reports()), Some(60));

    let mut req = fx.request("PutObject", put("2024/b", 1), Method::PUT);
    assert_quota_exceeded(
        "one byte past the limit",
        GatewayAccess::new(fx.gw.clone()).put_object(&mut req).await,
        BUCKET_FULL,
    );
    assert!(
        req.extensions.get::<AuthzProof>().is_none(),
        "a refused write carries no proof, so no forward could reach the backend"
    );
    assert!(req.extensions.get::<Arc<QuotaReservation>>().is_none());
    assert_eq!(
        backend.count("PUT"),
        1,
        "the refused write was never forwarded"
    );

    // One decision record for the refusal, with the figures the client is not given.
    let records = fx.await_audit_records(2).await;
    let refused = denials(&records);
    assert_eq!(refused.len(), 1, "{records:?}");
    let rec = refused[0];
    assert_eq!(rec.requested_by, "alice");
    assert_eq!(
        rec.input.as_ref().map(|i| i.bucket.as_str()),
        Some("reports")
    );
    let reason = &rec.result.reason;
    assert!(
        reason.starts_with("deny (gateway): storage quota exceeded")
            && reason.contains("adds 1 bytes to bucket \"reports\"")
            && reason.contains("held 40 bytes")
            && reason.contains("accepted 60 bytes since")
            && reason.contains("limit of 100 bytes"),
        "{reason}"
    );
    assert_eq!(rec.gateway.object_name.as_deref(), Some("reports.bay-1"));
}

/// The policy is asked first. A caller with no grant is refused as before and learns
/// nothing about any quota, and charges nothing.
#[tokio::test]
async fn a_caller_without_a_grant_is_refused_by_the_policy_not_the_quota() {
    let fx = common::fixture("quota-policy-first", bucket_limited(0, 10));
    for (sub, key) in [("mallory", "2024/x"), ("alice", "2025/outside-her-prefix")] {
        let err = admit_put(&fx, sub, put(key, 1))
            .await
            .expect_err("no grant matches");
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied, "{sub}: {err}");
        assert!(
            err.message().is_some_and(|m| !m.contains("quota")),
            "{sub}: {err}"
        );
    }
    assert_eq!(fx.gw.quota.counted(&reports()), None);
    // …while alice, inside her grant, is refused by the quota.
    assert_quota_exceeded(
        "alice in her prefix",
        admit_put(&fx, "alice", put("2024/x", 1)).await,
        BUCKET_FULL,
    );
}

#[tokio::test]
async fn the_tenant_and_the_backend_ceilings_refuse_with_their_own_message() {
    let tenant = quota_bundle(
        Some(quota(1_000, 0, an_hour_ago())),
        Some(quota(100, 90, an_hour_ago())),
        None,
    );
    let fx = common::fixture("quota-tenant", tenant);
    // Held in flight: a write dropped before it was sent would give its bytes back.
    let _in_flight = admit_put(&fx, "alice", put("2024/a", 10))
        .await
        .expect("90 + 10 fits the tenant");
    assert_quota_exceeded(
        "tenant ceiling",
        admit_put(&fx, "alice", put("2024/b", 1)).await,
        "The storage quota for this tenant has been exceeded.",
    );

    let backend = quota_bundle(None, None, Some(quota(50, 50, an_hour_ago())));
    let fx = common::fixture("quota-backend", backend);
    // An empty object adds nothing, even at the limit.
    admit_put(&fx, "alice", put("2024/empty", 0))
        .await
        .expect("an empty write fits a full backend");
    assert_quota_exceeded(
        "backend ceiling",
        admit_put(&fx, "alice", put("2024/b", 1)).await,
        "The organization's storage quota on this backend has been exceeded.",
    );
}

// ── collections ─────────────────────────────────────────────────────────────────

/// A bundle with a newer `collected_at` replaces the count its collection covers: what
/// was written before it is in its `used_bytes` now, not in the counter.
#[tokio::test]
async fn a_newer_collection_resets_the_count_it_covers() {
    let backend = backend().await;
    let fx = common::fixture_with_backend("quota-reset", bucket_limited(100, 0), &backend.url);
    put_through(&fx, "2024/a", 60).await.expect("fits");
    assert_quota_exceeded(
        "60 counted + 50",
        put_through(&fx, "2024/b", 50).await,
        BUCKET_FULL,
    );

    // The collector saw the 60 bytes: a collection stamped after the write landed.
    let collected = chrono::Utc::now() + chrono::Duration::seconds(2);
    fx.gw.bundles.store(Bundle::new(
        "rev-2",
        quota_bundle(Some(quota(100, 60, collected)), None, None),
    ));
    assert_quota_exceeded(
        "60 used + 41",
        put_through(&fx, "2024/c", 41).await,
        BUCKET_FULL,
    );
    put_through(&fx, "2024/c", 40)
        .await
        .expect("60 used + 40 fits once the count is reset");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(40));

    // A request pinned to the older revision does not get the old basis back.
    fx.gw
        .bundles
        .store(Bundle::new("rev-old", bucket_limited(100, 0)));
    assert_quota_exceeded(
        "an older collection does not undo the newer one",
        put_through(&fx, "2024/d", 1).await,
        BUCKET_FULL,
    );
}

// ── what a write is charged ─────────────────────────────────────────────────────

/// A part is charged as it arrives; completing adds nothing, so it is refused only once
/// the bucket is already over its limit. Creating the upload is never charged.
#[tokio::test]
async fn multipart_parts_are_charged_and_completing_adds_nothing() {
    let fx = common::fixture("quota-mpu", bucket_limited(100, 0));
    let access = GatewayAccess::new(fx.gw.clone());
    let part = |n: i32, len: i64| UploadPartInput {
        bucket: "reports".into(),
        key: "2024/big".into(),
        part_number: n,
        upload_id: "u-1".into(),
        content_length: Some(len),
        ..Default::default()
    };
    let mut held = Vec::new();
    for (n, len, fits) in [(1, 60, true), (2, 50, false), (2, 40, true)] {
        let mut req = fx.request("UploadPart", part(n, len), Method::PUT);
        let result = access.upload_part(&mut req).await;
        if fits {
            result.unwrap_or_else(|e| panic!("part {n} of {len} bytes must fit: {e}"));
            held.push(req);
        } else {
            assert_quota_exceeded("a part past the limit", result, BUCKET_FULL);
        }
    }
    assert_eq!(fx.gw.quota.counted(&reports()), Some(100));

    let complete = || CompleteMultipartUploadInput {
        bucket: "reports".into(),
        key: "2024/big".into(),
        upload_id: "u-1".into(),
        ..Default::default()
    };
    let mut req = fx.request("CompleteMultipartUpload", complete(), Method::POST);
    access
        .complete_multipart_upload(&mut req)
        .await
        .expect("completing at the limit adds nothing");
    let mut req = fx.request(
        "CreateMultipartUpload",
        CreateMultipartUploadInput {
            bucket: "reports".into(),
            key: "2024/next".into(),
            ..Default::default()
        },
        Method::POST,
    );
    access
        .create_multipart_upload(&mut req)
        .await
        .expect("creating an upload writes no bytes");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(100));

    // Over the limit (the limit was lowered under it), completing is refused too.
    fx.gw
        .bundles
        .store(Bundle::new("rev-over", bucket_limited(100, 150)));
    let mut req = fx.request("CompleteMultipartUpload", complete(), Method::POST);
    assert_quota_exceeded(
        "completing over the limit",
        access.complete_multipart_upload(&mut req).await,
        BUCKET_FULL,
    );
    drop(held);
}

/// A copy adds its source's bytes, which the gateway reads from the backend: the copy is
/// charged that size, and refused before it is forwarded when it does not fit.
#[tokio::test]
async fn a_copy_is_charged_the_source_size_the_backend_reports() {
    let backend = backend().await;
    let fx = common::fixture_with_backend("quota-copy", bucket_limited(100, 0), &backend.url);
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request("CopyObject", common::ops::copy_object_input(), Method::PUT);
    access.copy_object(&mut req).await.expect("70 bytes fit");
    gateway_s3(&fx)
        .copy_object(req)
        .await
        .expect("the backend copies");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(SOURCE_SIZE));
    let heads: Vec<Seen> = backend
        .seen()
        .into_iter()
        .filter(|s| s.method == "HEAD")
        .collect();
    assert_eq!(heads.len(), 1, "{heads:?}");
    assert!(
        heads[0].target.contains("2024/src.csv"),
        "the source, not the destination, is sized: {heads:?}"
    );

    let mut req = fx.request("CopyObject", common::ops::copy_object_input(), Method::PUT);
    assert_quota_exceeded(
        "a second 70-byte copy",
        access.copy_object(&mut req).await,
        BUCKET_FULL,
    );
    assert!(req.extensions.get::<AuthzProof>().is_none());
    let copies: Vec<Seen> = backend
        .seen()
        .into_iter()
        .filter(|s| s.method == "PUT")
        .collect();
    assert_eq!(copies.len(), 1, "the refused copy was never forwarded");
    assert!(
        copies[0]
            .head
            .to_ascii_lowercase()
            .contains("x-amz-copy-source:"),
        "the one forward is the first copy: {copies:?}"
    );
}

/// A ranged part copy is charged its range, with no question to the backend.
#[tokio::test]
async fn a_ranged_part_copy_is_charged_its_range_without_a_head() {
    let backend = backend().await;
    let fx = common::fixture_with_backend("quota-part-copy", bucket_limited(100, 0), &backend.url);
    let access = GatewayAccess::new(fx.gw.clone());
    let mut input = common::ops::upload_part_copy_input();
    input.copy_source_range = Some("bytes=0-29".into());
    let mut req = fx.request("UploadPartCopy", input, Method::PUT);
    access
        .upload_part_copy(&mut req)
        .await
        .expect("30 bytes fit");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(30));
    assert_eq!(backend.count("HEAD"), 0);

    // Without a range, the whole source is charged: 30 + 70 fits, a second one does not.
    let whole = || {
        fx.request(
            "UploadPartCopy",
            common::ops::upload_part_copy_input(),
            Method::PUT,
        )
    };
    let mut req = whole();
    access
        .upload_part_copy(&mut req)
        .await
        .expect("30 + 70 fits");
    let mut again = whole();
    assert_quota_exceeded(
        "30 + 70 counted + another 70",
        access.upload_part_copy(&mut again).await,
        BUCKET_FULL,
    );
    assert_eq!(backend.count("HEAD"), 2);
}

/// A copy whose source cannot be sized is refused, and answered as the copy would have
/// been: a missing source is `NoSuchKey`, under the refusal record's decision id.
#[tokio::test]
async fn a_copy_of_a_missing_source_is_refused_as_the_copy_would_be() {
    let backend = backend().await;
    let fx = common::fixture_with_backend("quota-copy-404", bucket_limited(100, 0), &backend.url);
    let mut input = common::ops::copy_object_input();
    input.copy_source = CopySource::Bucket {
        bucket: "reports".into(),
        key: "2024/missing".into(),
        version_id: None,
    };
    let mut req = fx.request("CopyObject", input, Method::PUT);
    let err = GatewayAccess::new(fx.gw.clone())
        .copy_object(&mut req)
        .await
        .expect_err("an unsized copy is not charged as free");
    assert_eq!(*err.code(), S3ErrorCode::NoSuchKey, "{err}");
    assert_eq!(err.status_code(), Some(http::StatusCode::NOT_FOUND));
    assert_eq!(backend.count("PUT"), 0);

    let records = fx.await_audit_records(1).await;
    let refused = denials(&records);
    assert_eq!(refused.len(), 1, "{records:?}");
    assert!(
        refused[0]
            .result
            .reason
            .contains("the copy source's size could not be read"),
        "{}",
        refused[0].result.reason
    );
    assert_eq!(err.request_id(), Some(refused[0].decision_id.as_str()));
}

#[tokio::test]
async fn a_form_upload_is_charged_the_file_it_carries() {
    let fx = common::fixture("quota-post", bucket_limited(100, 90));
    let post = |len: i64| PostObjectInput {
        bucket: "reports".into(),
        key: "2024/form".into(),
        content_length: Some(len),
        ..Default::default()
    };
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request("PostObject", post(10), Method::POST);
    access.post_object(&mut req).await.expect("90 + 10 fits");
    let mut req = fx.request("PostObject", post(1), Method::POST);
    assert_quota_exceeded(
        "a form upload past the limit",
        access.post_object(&mut req).await,
        BUCKET_FULL,
    );
}

/// Where a quota applies, a write must say how big it is; elsewhere nothing changes.
#[tokio::test]
async fn a_write_of_unstated_size_is_refused_only_where_a_quota_applies() {
    let unsized_put = || PutObjectInput {
        bucket: "reports".into(),
        key: "2024/x".into(),
        content_length: None,
        ..Default::default()
    };
    let fx = common::fixture("quota-unsized", bucket_limited(100, 0));
    let err = admit_put(&fx, "alice", unsized_put())
        .await
        .expect_err("no length under a quota");
    assert_eq!(*err.code(), S3ErrorCode::MissingContentLength, "{err}");

    let fx = common::fixture("quota-unsized-free", quota_bundle(None, None, None));
    admit_put(&fx, "alice", unsized_put())
        .await
        .expect("no quota, no question");
}

// ── no quota, no change ─────────────────────────────────────────────────────────

/// A v3 bundle with no `quota` anywhere — a backend with native quotas — enforces and
/// counts nothing, and a copy costs no extra backend request. Below v3 a `quota` key is
/// not read at all.
#[tokio::test]
async fn without_a_stated_quota_nothing_is_counted_or_asked() {
    let backend = backend().await;
    let fx =
        common::fixture_with_backend("quota-none", quota_bundle(None, None, None), &backend.url);
    let req = admit_put(&fx, "alice", put("2024/a", 10))
        .await
        .expect("unlimited");
    assert!(req.extensions.get::<Arc<QuotaReservation>>().is_none());
    let mut req = fx.request("CopyObject", common::ops::copy_object_input(), Method::PUT);
    GatewayAccess::new(fx.gw.clone())
        .copy_object(&mut req)
        .await
        .expect("allowed");
    gateway_s3(&fx).copy_object(req).await.expect("copied");
    assert_eq!(backend.count("HEAD"), 0, "no quota, no sizing request");
    assert_eq!(fx.gw.quota.counted(&reports()), None);

    let mut v2 = bucket_limited(0, 1_000);
    v2["grant_schema_version"] = serde_json::json!(2);
    let fx = common::fixture("quota-v2", v2);
    let req = admit_put(&fx, "alice", put("2024/a", 10))
        .await
        .expect("a v2 bundle's quota means nothing");
    assert!(req.extensions.get::<Arc<QuotaReservation>>().is_none());
    assert_eq!(fx.gw.quota.counted(&reports()), None);
}

/// A quota the gateway cannot read refuses the writes it covers, never the reads.
#[tokio::test]
async fn an_unreadable_quota_refuses_writes_and_leaves_reads_alone() {
    let broken = quota_bundle(
        Some(serde_json::json!({ "limit_bytes": "lots", "used_bytes": 0,
                                 "collected_at": "2026-10-01T12:00:00Z" })),
        None,
        None,
    );
    let fx = common::fixture("quota-unreadable", broken);
    let err = admit_put(&fx, "alice", put("2024/x", 1))
        .await
        .expect_err("a limit half-read is not enforced by allowing");
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
    assert_eq!(err.message(), Some(s0::quota::QUOTA_UNREADABLE), "{err}");
    let records = fx.await_audit_records(1).await;
    assert!(
        records.iter().any(|r| r
            .result
            .reason
            .contains("storage quota for bucket \"reports\" cannot be read")),
        "the record keeps the detail: {records:?}"
    );
    let mut req = fx.request(
        "GetObject",
        GetObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            ..Default::default()
        },
        Method::GET,
    );
    GatewayAccess::new(fx.gw.clone())
        .get_object(&mut req)
        .await
        .expect("a read is never charged");
}

// ── the backend's answer settles the charge ─────────────────────────────────────

#[tokio::test]
async fn a_write_the_backend_refused_gives_its_bytes_back_and_an_unknown_outcome_does_not() {
    let backend = backend().await;
    let fx = common::fixture_with_backend("quota-settle", bucket_limited(100, 0), &backend.url);

    let err = put_through(&fx, "2024/refused", 60)
        .await
        .expect_err("the backend refuses");
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
    assert_eq!(
        fx.gw.quota.counted(&reports()),
        Some(0),
        "a 4xx means the write did not happen"
    );

    put_through(&fx, "2024/broken", 60)
        .await
        .expect_err("the backend fails");
    assert_eq!(
        fx.gw.quota.counted(&reports()),
        Some(60),
        "after a 5xx the write may have landed, so it stays counted"
    );

    // A write admitted and then dropped before any forward (s3s refusing it after the
    // access hook, a client gone before dispatch) stored nothing, and gives its bytes back.
    let req = admit_put(&fx, "alice", put("2024/lost", 30))
        .await
        .expect("fits");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(90));
    drop(req);
    assert_eq!(fx.gw.quota.counted(&reports()), Some(60));
}

/// A client that declares the remaining quota and then fails its body is charged nothing:
/// the backend cannot store an object without its whole body, so the failed upload must not
/// block the level until the next collection.
#[tokio::test]
async fn a_write_whose_client_body_failed_gives_its_bytes_back() {
    let backend = backend().await;
    let fx =
        common::fixture_with_backend("quota-body-failed", bucket_limited(100, 0), &backend.url);
    let input = PutObjectInput {
        body: Some(StreamingBlob::from(Body::http_body(HangUp { sent: false }))),
        ..put("2024/hangup", 100)
    };
    let req = admit_put(&fx, "alice", input).await.expect("100 bytes fit");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(100));
    gateway_s3(&fx)
        .put_object(req)
        .await
        .expect_err("the body never arrives");
    assert_eq!(
        fx.gw.quota.counted(&reports()),
        Some(0),
        "a body that failed stored nothing"
    );
    put_through(&fx, "2024/after", 100)
        .await
        .expect("the full quota is available again");
}

/// A body that declares 100 bytes, yields ten, then fails the way a client hanging up
/// mid-upload does.
struct HangUp {
    sent: bool,
}

impl hyper::body::Body for HangUp {
    type Data = bytes::Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<bytes::Bytes>, std::io::Error>>> {
        if self.sent {
            return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the client hung up",
            ))));
        }
        self.sent = true;
        std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(
            bytes::Bytes::from_static(b"0123456789"),
        ))))
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        hyper::body::SizeHint::with_exact(100)
    }
}

/// A write admitted and then refused before any backend call (here, its tenant was
/// re-routed in between) gives its bytes back.
#[tokio::test]
async fn a_write_refused_before_any_backend_call_gives_its_bytes_back() {
    let fx = common::fixture("quota-reroute", bucket_limited(100, 0));
    let req = admit_put(&fx, "alice", put("2024/a", 60))
        .await
        .expect("fits");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(60));

    let mut cfg: serde_json::Value =
        serde_json::from_str(&common::config_json(&fx.dir, "http://127.0.0.1:1"))
            .expect("config json");
    cfg["backends"]
        .as_array_mut()
        .expect("backends")
        .push(serde_json::json!({ "id": "bay-2", "kind": "s3",
                                  "endpoint_url": "http://127.0.0.1:1", "region": "us-east-1" }));
    cfg["tenants"][0]["backend_id"] = serde_json::json!("bay-2");
    fx.gw
        .registry
        .apply_config(&GatewayConfig::from_json(&cfg.to_string()).expect("config"))
        .expect("applied");

    let err = gateway_s3(&fx)
        .put_object(req)
        .await
        .expect_err("refused across a routing change");
    assert_eq!(*err.code(), S3ErrorCode::ServiceUnavailable, "{err}");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(0));
}

// ── concurrency ─────────────────────────────────────────────────────────────────

/// Many writers at once on one replica: exactly as many fit as the limit allows, never
/// one more.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_writers_on_one_replica_never_pass_the_limit() {
    let fx = common::fixture("quota-race", bucket_limited(100, 0));
    let tasks: Vec<_> = (0..48)
        .map(|i| {
            let req = fx.request("PutObject", put(&format!("2024/race-{i}"), 7), Method::PUT);
            let access = GatewayAccess::new(fx.gw.clone());
            tokio::spawn(async move {
                let mut req = req;
                access.put_object(&mut req).await.map(|()| req)
            })
        })
        .collect();
    let mut admitted = Vec::new();
    let mut refused = 0;
    for task in tasks {
        match task.await.expect("task") {
            Ok(req) => admitted.push(req),
            Err(e) => {
                assert_eq!(e.code().as_str(), QUOTA_EXCEEDED, "{e}");
                refused += 1;
            }
        }
    }
    // 100 / 7 = 14 writes, with the reservations still in flight.
    assert_eq!(admitted.len(), 14);
    assert_eq!(refused, 48 - 14);
    assert_eq!(fx.gw.quota.counted(&reports()), Some(98));
}

// ── aws-chunked bodies ──────────────────────────────────────────────────────────

/// CRC-32 (IEEE), for the checksum trailer a default-configured SDK sends.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= u32::from(b);
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

/// Boot the real serving path over `fx` on a loopback port; its `host:port`.
async fn serve(fx: &common::Fixture) -> String {
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
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    addr.to_string()
}

/// How the HTTP layer frames the aws-chunked body.
#[derive(Clone, Copy)]
enum Framing {
    /// boto3 ≥ 1.36: `Transfer-Encoding: chunked`, no `Content-Length` at all.
    TransferChunked,
    /// aws-cli / Java v2: `Content-Length` is the *encoded* length.
    EncodedLength,
}

/// A PutObject the way an SDK with default flexible checksums sends it — `aws-chunked`,
/// unsigned payload, CRC32 trailer — over real HTTP. Its status and body.
async fn put_aws_chunked(host: &str, key: &str, len: usize, framing: Framing) -> (u16, String) {
    put_aws_chunked_declaring(host, key, len, len, framing).await
}

/// [`put_aws_chunked`] carrying `len` bytes while declaring `declared`.
async fn put_aws_chunked_declaring(
    host: &str,
    key: &str,
    len: usize,
    declared: usize,
    framing: Framing,
) -> (u16, String) {
    let data = vec![b'x'; len];
    let checksum = common::sigv4::base64(&crc32(&data).to_be_bytes());
    let mut payload = Vec::new();
    if len > 0 {
        payload.extend_from_slice(format!("{len:x}\r\n").as_bytes());
        payload.extend_from_slice(&data);
        payload.extend_from_slice(b"\r\n");
    }
    payload.extend_from_slice(format!("0\r\nx-amz-checksum-crc32:{checksum}\r\n\r\n").as_bytes());

    let req = RawRequest::new("PUT", format!("/reports/{key}"))
        .header("content-encoding", "aws-chunked")
        .header("x-amz-decoded-content-length", &declared.to_string())
        .header("x-amz-trailer", "x-amz-checksum-crc32")
        .payload_hash("STREAMING-UNSIGNED-PAYLOAD-TRAILER");
    let mut wire = format!("PUT {} HTTP/1.1\r\n", req.url(""));
    for (k, v) in req.sign(host, common::ACCESS_KEY, common::SECRET_KEY) {
        wire.push_str(&format!("{k}: {v}\r\n"));
    }
    wire.push_str("connection: close\r\n");
    let mut wire = wire.into_bytes();
    match framing {
        Framing::TransferChunked => {
            wire.extend_from_slice(b"transfer-encoding: chunked\r\n\r\n");
            wire.extend_from_slice(format!("{:x}\r\n", payload.len()).as_bytes());
            wire.extend_from_slice(&payload);
            wire.extend_from_slice(b"\r\n0\r\n\r\n");
        }
        Framing::EncodedLength => {
            wire.extend_from_slice(format!("content-length: {}\r\n\r\n", payload.len()).as_bytes());
            wire.extend_from_slice(&payload);
        }
    }

    let mut sock = tokio::net::TcpStream::connect(host).await.expect("connect");
    sock.write_all(&wire).await.expect("send");
    let mut raw = Vec::new();
    let _ = sock.read_to_end(&mut raw).await;
    let text = String::from_utf8_lossy(&raw).to_string();
    let status = text
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| panic!("no HTTP status in {text:?}"));
    (status, text)
}

/// A default-configured boto3 / aws-cli / Java v2 PutObject states its size only in
/// `x-amz-decoded-content-length`. Under a quota it is admitted and charged that size —
/// not refused for lacking a `Content-Length`, nor charged its encoded length — and a write
/// past the limit is still refused before it reaches the backend.
#[tokio::test]
async fn an_aws_chunked_put_is_charged_its_decoded_length_over_real_http() {
    let backend = backend().await;
    let fx = common::fixture_with_backend("quota-chunked", bucket_limited(100, 0), &backend.url);
    let host = serve(&fx).await;

    let (status, body) = put_aws_chunked(&host, "2024/a", 60, Framing::TransferChunked).await;
    assert_eq!(status, 200, "boto3's framing, 60 of 100 bytes: {body}");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(60));

    // Encoded, these 40 bytes are ~100 on the wire: charged that, they would not fit.
    let (status, body) = put_aws_chunked(&host, "2024/b", 40, Framing::EncodedLength).await;
    assert_eq!(status, 200, "40 more bytes is exactly the limit: {body}");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(100));
    assert_eq!(backend.count("PUT"), 2);

    for framing in [Framing::TransferChunked, Framing::EncodedLength] {
        let (status, body) = put_aws_chunked(&host, "2024/c", 1, framing).await;
        assert_eq!(status, 403, "one byte past the limit: {body}");
        assert!(body.contains(QUOTA_EXCEEDED), "{body}");
    }
    assert_eq!(
        backend.count("PUT"),
        2,
        "the refused writes were never forwarded"
    );
    assert_eq!(fx.gw.quota.counted(&reports()), Some(100));
}

/// A multipart part from the same SDKs is aws-chunked too, and charged the same way.
#[tokio::test]
async fn an_aws_chunked_part_is_charged_its_decoded_length() {
    let fx = common::fixture("quota-chunked-part", bucket_limited(100, 0));
    let access = GatewayAccess::new(fx.gw.clone());
    let part = |n: i32, decoded: &str| {
        let mut req = fx.request(
            "UploadPart",
            UploadPartInput {
                bucket: "reports".into(),
                key: "2024/big".into(),
                part_number: n,
                upload_id: "u-1".into(),
                content_length: None,
                ..Default::default()
            },
            Method::PUT,
        );
        req.headers.insert(
            http::header::CONTENT_ENCODING,
            http::HeaderValue::from_static("aws-chunked"),
        );
        req.headers.insert(
            "x-amz-decoded-content-length",
            http::HeaderValue::from_str(decoded).expect("header value"),
        );
        req
    };

    let mut first = part(1, "70");
    access
        .upload_part(&mut first)
        .await
        .expect("70 of 100 bytes fits");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(70));

    let mut second = part(2, "31");
    assert_quota_exceeded(
        "a part past the limit",
        access.upload_part(&mut second).await,
        BUCKET_FULL,
    );

    let mut malformed = part(2, "30 bytes");
    let err = access
        .upload_part(&mut malformed)
        .await
        .expect_err("a decoded length that cannot be read states no size");
    assert_eq!(*err.code(), S3ErrorCode::MissingContentLength, "{err}");
    assert_eq!(fx.gw.quota.counted(&reports()), Some(70));
    drop(first);
}

/// The decoded length is the client's claim, and s3s's decoder does not hold the body to
/// it: a body carrying more than it declared fails, and is charged nothing, rather than
/// storing bytes the quota never counted.
#[tokio::test]
async fn an_aws_chunked_body_longer_than_it_declared_is_not_stored_or_charged() {
    let backend = backend().await;
    let fx =
        common::fixture_with_backend("quota-chunked-liar", bucket_limited(100, 0), &backend.url);
    let host = serve(&fx).await;

    let (status, body) =
        put_aws_chunked_declaring(&host, "2024/liar", 5_000, 10, Framing::TransferChunked).await;
    assert_ne!(
        status, 200,
        "5000 bytes declared as 10 must not succeed: {body}"
    );
    assert_eq!(fx.gw.quota.counted(&reports()), Some(0), "{body}");
}
