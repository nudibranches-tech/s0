//! Bundle v3: the bundle places buckets, and the gateway enforces the placement.
//!
//! From `grant_schema_version` 3 a bundle is filtered to one backend, names it in
//! `data.backend.id`, and lists every bucket of that backend under exactly one tenant. On a
//! backend whose upstream identity is shared by an organization's tenants, that placement
//! is the only thing keeping one tenant out of another's bucket, so the gateway enforces it
//! itself, ahead of any policy:
//!
//! 1. a bucket placed under another tenant is refused, and so is one no tenant has here;
//! 2. a bundle projected for another backend refuses everything;
//! 3. `ListBuckets` is answered from the bundle and never forwarded.
//!
//! Below version 3 none of this exists; the first test pins that.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::sigv4::RawRequest;
use http::Method;
use s0::access::GatewayAccess;
use s0::audit::{AuditRecord, Outcome};
use s0::pdp::{BUCKET_NOT_ON_THIS_BACKEND, BUCKET_OF_ANOTHER_TENANT, Bundle};
use s0::proxy::{GatewayS3, S3GatewayState};
use s3s::access::S3Access;
use s3s::dto::*;
use s3s::{S3, S3ErrorCode, S3Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// The fixture config's only backend (`common::config_json`).
const BACKEND: &str = "bay-1";

/// `alice_bundle`, placed: `acme` owns `reports`, `logs` and `zeta` on this backend, and
/// `globex` owns `ledger`.
///
/// `wild` holds every verb on every bucket of `acme`, so for anything it is refused the
/// *policy* would have said yes: what refuses it is the placement, not a missing grant.
fn placed_bundle(version: u64, backend_id: &str) -> serde_json::Value {
    let mut b = common::alice_bundle();
    b["grant_schema_version"] = serde_json::json!(version);
    b["backend"] = serde_json::json!({ "id": backend_id, "kind": "s3" });
    let acme = &mut b["tenants"]["acme"];
    acme["user_attributes"]["wild"] = serde_json::json!({ "groups": [], "attributes": [] });
    acme["s3_grants"]["wild"] = serde_json::json!([
        { "bucket": "*", "actions": ["*"], "prefixes": [] }
    ]);
    acme["bucket_attributes"] = serde_json::json!({
        "reports": { "denylist": {}, "object_name": "reports.bay-1",
                     "created_at": "2026-01-01T00:00:00Z" },
        "logs":    { "denylist": {}, "object_name": "logs.bay-1",
                     "created_at": "2026-01-02T00:00:00Z" },
        "zeta":    { "denylist": {}, "object_name": "zeta.bay-1",
                     "created_at": "2026-01-03T00:00:00Z" }
    });
    b["tenants"]["globex"] = serde_json::json!({
        "user_attributes": { "gail": { "groups": [], "attributes": [] } },
        "bucket_attributes": {
            "ledger": { "denylist": {}, "object_name": "ledger.bay-1",
                        "created_at": "2026-01-04T00:00:00Z" }
        },
        "s3_grants": { "gail": [ { "bucket": "*", "actions": ["*"], "prefixes": [] } ] },
        "group_grants": {}
    });
    b
}

fn v3() -> serde_json::Value {
    placed_bundle(3, BACKEND)
}

// ── a backend that answers, and counts ──────────────────────────────────────────

struct FakeBackend {
    url: String,
    requests: Arc<AtomicUsize>,
}

/// Answers every request with a `ListBuckets` body naming the tenant's buckets *and*
/// another tenant's, as an upstream identity shared across tenants would. Counted, so
/// "never forwarded" is a measurement.
async fn fake_backend() -> FakeBackend {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 2048];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                counter.fetch_add(1, Ordering::Relaxed);
                let rows: String = ["reports", "logs", "zeta", "ledger"]
                    .iter()
                    .map(|n| {
                        format!(
                            "<Bucket><Name>{n}</Name>\
                             <CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>"
                        )
                    })
                    .collect();
                let payload = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <Owner><ID>shared-upstream-identity</ID></Owner>\
                     <Buckets>{rows}</Buckets></ListAllMyBucketsResult>"
                );
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    FakeBackend {
        url: format!("http://{addr}"),
        requests,
    }
}

// ── helpers ─────────────────────────────────────────────────────────────────────

fn gateway_s3(fx: &common::Fixture) -> GatewayS3 {
    GatewayS3::new(Arc::new(S3GatewayState::new(
        fx.gw.registry.clone(),
        fx.gw.limits.clone(),
    )))
}

async fn list_buckets(
    fx: &common::Fixture,
    sub: &str,
    input: ListBucketsInput,
) -> Result<ListBucketsOutput, s3s::S3Error> {
    let mut req: S3Request<ListBucketsInput> =
        fx.request_as(sub, "ListBuckets", input, Method::GET);
    GatewayAccess::new(fx.gw.clone())
        .list_buckets(&mut req)
        .await
        .expect("the hook answers a refusal with an empty listing, never an error");
    gateway_s3(fx).list_buckets(req).await.map(|r| r.output)
}

fn names(out: &ListBucketsOutput) -> Vec<String> {
    out.buckets
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|b| b.name)
        .collect()
}

fn get(bucket: &str, key: &str) -> GetObjectInput {
    GetObjectInput {
        bucket: bucket.into(),
        key: key.into(),
        ..Default::default()
    }
}

/// Assert `result` is the gateway's `AccessDenied` carrying `reason`, verbatim.
fn assert_refused<T: std::fmt::Debug>(label: &str, result: Result<T, s3s::S3Error>, reason: &str) {
    let err = match result {
        Ok(v) => panic!("{label}: must be refused, got {v:?}"),
        Err(e) => e,
    };
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied, "{label}: {err}");
    assert_eq!(err.message(), Some(reason), "{label}");
}

fn decision_records(records: &[AuditRecord]) -> Vec<&AuditRecord> {
    records.iter().filter(|r| r.input.is_some()).collect()
}

// ── below v3, nothing changes ───────────────────────────────────────────────────

/// The same document at version 2: no gate, the policy decides (and `wild`'s wildcard
/// allows another tenant's bucket name, as it always has), and `ListBuckets` is the
/// backend's answer, filtered.
#[tokio::test]
async fn a_v2_bundle_keeps_todays_path_policy_decided_and_forwarded() {
    let backend = fake_backend().await;
    let fx = common::fixture_with_backend("v3-v2-control", placed_bundle(2, BACKEND), &backend.url);
    assert!(!fx.gw.bundles.current().placement().places_buckets());

    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request_as("wild", "GetObject", get("ledger", "k"), Method::GET);
    access
        .get_object(&mut req)
        .await
        .expect("at v2 the policy alone decides, and the wildcard grant allows");
    assert_eq!(fx.pdp_calls(), 1);

    let out = list_buckets(&fx, "wild", ListBucketsInput::default())
        .await
        .expect("listing");
    assert!(
        backend.requests.load(Ordering::Relaxed) > 0,
        "at v2 ListBuckets is the backend's answer"
    );
    // The backend's whole namespace survives the wildcard: v2's behaviour, unchanged.
    assert_eq!(names(&out), ["ledger", "logs", "reports", "zeta"]);
}

// ── v3: the owning-tenant gate ──────────────────────────────────────────────────

#[tokio::test]
async fn a_bucket_of_another_tenant_is_refused_before_any_policy_is_asked() {
    let fx = common::fixture("v3-cross-tenant", v3());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request_as("wild", "GetObject", get("ledger", "k"), Method::GET);
    assert_refused(
        "GetObject on globex's bucket",
        access.get_object(&mut req).await,
        BUCKET_OF_ANOTHER_TENANT,
    );
    assert_eq!(fx.pdp_calls(), 0, "the PDP must never be asked about it");
    assert!(
        fx.capture.snapshot().is_empty(),
        "a refused question is not an emitted input"
    );
    assert!(req.extensions.get::<s0::access::AuthzProof>().is_none());

    // One decision record, attributed like any other, carrying the placement reason.
    let records = fx.await_audit_records(1).await;
    let records = decision_records(&records);
    assert_eq!(records.len(), 1, "{records:?}");
    let rec = records[0];
    let input = rec.input.as_ref().expect("a decision record");
    assert_eq!(input.bucket, "ledger");
    assert_eq!(input.tenant, "acme");
    assert_eq!(rec.requested_by, "wild");
    assert!(!rec.result.allow);
    assert_eq!(rec.result.reason, BUCKET_OF_ANOTHER_TENANT);
    assert_eq!(rec.gateway.outcome, Outcome::Denied);
    assert_eq!(rec.gateway.backend_id, BACKEND);
    assert_eq!(
        rec.gateway.object_name.as_deref(),
        Some("ledger.bay-1"),
        "the record names the resource that was reached for"
    );
}

/// Every record names the bundle's object name for each bucket it is about, so a
/// consumer can join it to the bucket without re-deriving one name from the other — and
/// names nothing the bundle did not publish.
#[tokio::test]
async fn the_record_carries_the_bundles_object_name_for_each_bucket() {
    let fx = common::fixture("v3-object-names", v3());
    let access = GatewayAccess::new(fx.gw.clone());

    // Allowed: the record is held for the forward leg and emitted when the request ends.
    let mut req = fx.request("GetObject", get("reports", "2024/q1.csv"), Method::GET);
    access.get_object(&mut req).await.expect("allowed");
    drop(req);
    // A copy out of another tenant's bucket: both names, on the refusal.
    let mut copy = common::ops::copy_object_input();
    copy.copy_source = CopySource::Bucket {
        bucket: "ledger".into(),
        key: "src.csv".into(),
        version_id: None,
    };
    let mut req = fx.request_as("wild", "CopyObject", copy, Method::PUT);
    access.copy_object(&mut req).await.expect_err("refused");
    // A bucket the bundle does not place has no object name to give.
    let mut req = fx.request_as("wild", "GetObject", get("elsewhere", "k"), Method::GET);
    access.get_object(&mut req).await.expect_err("refused");

    let records = fx.await_audit_records(3).await;
    let by_bucket = |bucket: &str| {
        records
            .iter()
            .find(|r| r.input.as_ref().is_some_and(|i| i.bucket == bucket))
            .unwrap_or_else(|| panic!("no record for {bucket}: {records:?}"))
            .gateway
            .clone()
    };
    let read = by_bucket("reports");
    assert_eq!(read.outcome, Outcome::Allowed);
    assert_eq!(read.object_name.as_deref(), Some("reports.bay-1"));
    assert_eq!(read.copy_source_object_name, None);
    // The copy's record is the destination's (`reports`, the copy's own bucket).
    let copy = records
        .iter()
        .find(|r| r.input.as_ref().is_some_and(|i| i.copy_source.is_some()))
        .expect("the copy's record")
        .gateway
        .clone();
    assert_eq!(copy.object_name.as_deref(), Some("reports.bay-1"));
    assert_eq!(
        copy.copy_source_object_name.as_deref(),
        Some("ledger.bay-1")
    );
    let elsewhere = by_bucket("elsewhere");
    assert_eq!(elsewhere.object_name, None);
}

/// Below v3 there is nothing to name, and the record is the one it always was: the
/// fields are not even serialized.
#[tokio::test]
async fn a_v2_record_carries_no_object_name() {
    let fx = common::fixture("v3-v2-record", placed_bundle(2, BACKEND));
    let mut req = fx.request("GetObject", get("reports", "2024/q1.csv"), Method::GET);
    GatewayAccess::new(fx.gw.clone())
        .get_object(&mut req)
        .await
        .expect("allowed");
    drop(req);
    let records = fx.await_audit_records(1).await;
    let rec = decision_records(&records)[0];
    let json = serde_json::to_value(rec).expect("serialize");
    assert!(
        json["gateway"].get("object_name").is_none()
            && json["gateway"].get("copy_source_object_name").is_none(),
        "{json}"
    );
}

#[tokio::test]
async fn a_bucket_no_tenant_has_on_this_backend_is_refused() {
    let fx = common::fixture("v3-not-here", v3());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request_as(
        "wild",
        "HeadBucket",
        HeadBucketInput {
            bucket: "elsewhere".into(),
            ..Default::default()
        },
        Method::HEAD,
    );
    assert_refused(
        "HeadBucket on an unplaced bucket",
        access.head_bucket(&mut req).await,
        BUCKET_NOT_ON_THIS_BACKEND,
    );
    // An object name is not an S3 name.
    let mut req = fx.request_as("wild", "GetObject", get("reports.bay-1", "k"), Method::GET);
    assert_refused(
        "GetObject by object name",
        access.get_object(&mut req).await,
        BUCKET_NOT_ON_THIS_BACKEND,
    );
    assert_eq!(fx.pdp_calls(), 0);
    let records = fx.await_audit_records(2).await;
    for rec in decision_records(&records) {
        assert_eq!(rec.result.reason, BUCKET_NOT_ON_THIS_BACKEND);
    }
}

/// The positive control: the owner's own bucket reaches the PDP, and the policy still
/// decides it — the gate admits, it never grants.
#[tokio::test]
async fn the_owning_tenants_bucket_is_admitted_to_the_policy_which_still_decides() {
    let fx = common::fixture("v3-owner", v3());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request("GetObject", get("reports", "2024/q1.csv"), Method::GET);
    access
        .get_object(&mut req)
        .await
        .expect("alice may read reports/2024/");
    assert_eq!(fx.pdp_calls(), 1);

    let mut req = fx.request("GetObject", get("reports", "2023/old.csv"), Method::GET);
    let err = access
        .get_object(&mut req)
        .await
        .expect_err("outside alice's prefix");
    assert!(
        err.message().is_some_and(|m| m.starts_with("deny:")),
        "the policy's own reason, not the gateway's: {err}"
    );
    assert_eq!(fx.pdp_calls(), 2);
}

/// Every hook shape meets the gate, including the ones whose single record summarizes
/// several decisions — and each record names the placement, not the summary.
#[tokio::test]
async fn every_hook_shape_refuses_another_tenants_bucket_with_the_placement_reason() {
    let fx = common::fixture("v3-every-shape", v3());
    let access = GatewayAccess::new(fx.gw.clone());
    let foreign_source = || CopySource::Bucket {
        bucket: "ledger".into(),
        key: "src.csv".into(),
        version_id: None,
    };
    let mut refused = 0;
    macro_rules! refused {
        ($label:expr, $op:expr, $method:expr, $input:expr, $hook:ident) => {{
            let mut req = fx.request_as("wild", $op, $input, $method);
            assert_refused(
                $label,
                access.$hook(&mut req).await,
                BUCKET_OF_ANOTHER_TENANT,
            );
            refused += 1;
        }};
    }

    refused!(
        "GetObject",
        "GetObject",
        Method::GET,
        get("ledger", "k"),
        get_object
    );
    refused!(
        "PutObject",
        "PutObject",
        Method::PUT,
        PutObjectInput {
            bucket: "ledger".into(),
            key: "k".into(),
            ..Default::default()
        },
        put_object
    );
    refused!(
        "PutObject with an inline tag set, whose rider decision must not be the record",
        "PutObject",
        Method::PUT,
        PutObjectInput {
            bucket: "ledger".into(),
            key: "k".into(),
            tagging: Some("tier=internal".into()),
            ..Default::default()
        },
        put_object
    );
    refused!(
        "DeleteObject",
        "DeleteObject",
        Method::DELETE,
        DeleteObjectInput {
            bucket: "ledger".into(),
            key: "k".into(),
            ..Default::default()
        },
        delete_object
    );
    let mut delete = common::ops::delete_objects_input();
    delete.bucket = "ledger".into();
    refused!(
        "DeleteObjects",
        "DeleteObjects",
        Method::POST,
        delete,
        delete_objects
    );
    let mut copy = common::ops::copy_object_input();
    copy.bucket = "ledger".into();
    refused!(
        "CopyObject into another tenant's bucket",
        "CopyObject",
        Method::PUT,
        copy,
        copy_object
    );
    let mut copy = common::ops::copy_object_input();
    copy.copy_source = foreign_source();
    refused!(
        "CopyObject out of another tenant's bucket",
        "CopyObject",
        Method::PUT,
        copy,
        copy_object
    );
    let mut part_copy = common::ops::upload_part_copy_input();
    part_copy.copy_source = foreign_source();
    refused!(
        "UploadPartCopy out of another tenant's bucket",
        "UploadPartCopy",
        Method::PUT,
        part_copy,
        upload_part_copy
    );
    refused!(
        "ListObjectsV2",
        "ListObjectsV2",
        Method::GET,
        ListObjectsV2Input {
            bucket: "ledger".into(),
            ..Default::default()
        },
        list_objects_v2
    );
    refused!(
        "ListObjects",
        "ListObjects",
        Method::GET,
        ListObjectsInput {
            bucket: "ledger".into(),
            ..Default::default()
        },
        list_objects
    );
    refused!(
        "ListMultipartUploads",
        "ListMultipartUploads",
        Method::GET,
        ListMultipartUploadsInput {
            bucket: "ledger".into(),
            ..Default::default()
        },
        list_multipart_uploads
    );
    refused!(
        "CreateMultipartUpload",
        "CreateMultipartUpload",
        Method::POST,
        CreateMultipartUploadInput {
            bucket: "ledger".into(),
            key: "k".into(),
            ..Default::default()
        },
        create_multipart_upload
    );
    refused!(
        "GetBucketLocation",
        "GetBucketLocation",
        Method::GET,
        GetBucketLocationInput {
            bucket: "ledger".into(),
            ..Default::default()
        },
        get_bucket_location
    );
    let mut tagging = common::ops::put_object_tagging_input();
    tagging.bucket = "ledger".into();
    refused!(
        "PutObjectTagging",
        "PutObjectTagging",
        Method::PUT,
        tagging,
        put_object_tagging
    );

    assert_eq!(
        fx.pdp_calls(),
        0,
        "no question about globex's bucket reached the PDP"
    );
    let records = fx.await_audit_records(refused).await;
    let records = decision_records(&records);
    assert_eq!(records.len(), refused, "one record per refused request");
    for rec in records {
        assert_eq!(rec.result.reason, BUCKET_OF_ANOTHER_TENANT, "{rec:?}");
        assert_eq!(rec.gateway.outcome, Outcome::Denied);
    }
}

/// The placement `check` admitted the request under is the one it is decided under: a
/// bundle swap between the two must not let a later sub-decision see the bucket elsewhere.
#[tokio::test]
async fn a_request_keeps_the_placement_it_was_admitted_under() {
    let fx = common::fixture("v3-pinned", v3());
    let mut req = fx.request_as("wild", "GetObject", get("ledger", "k"), Method::GET);
    fx.gw
        .bundles
        .store(Bundle::new("rev-v2", placed_bundle(2, BACKEND)));
    assert_refused(
        "pinned placement",
        GatewayAccess::new(fx.gw.clone()).get_object(&mut req).await,
        BUCKET_OF_ANOTHER_TENANT,
    );
}

// ── v3: the backend-id check ────────────────────────────────────────────────────

/// A bundle served to the wrong instance describes buckets this backend does not have.
/// Everything is refused — the owner's own bucket and the account scope included — and
/// nothing is forwarded.
#[tokio::test]
async fn a_bundle_projected_for_another_backend_fails_closed() {
    let backend = fake_backend().await;
    let fx = common::fixture_with_backend(
        "v3-wrong-backend",
        placed_bundle(3, "archive"),
        &backend.url,
    );
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request("GetObject", get("reports", "2024/q1.csv"), Method::GET);
    let err = access
        .get_object(&mut req)
        .await
        .expect_err("a request alice holds a grant for, on her own bucket, is refused");
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
    let message = err.message().unwrap_or_default().to_string();
    assert!(
        message.starts_with("deny (gateway):")
            && message.contains("\"archive\"")
            && message.contains("\"bay-1\""),
        "{message}"
    );

    let out = list_buckets(&fx, "wild", ListBucketsInput::default())
        .await
        .expect("a refused enumeration is an empty listing");
    assert!(names(&out).is_empty());
    assert_eq!(backend.requests.load(Ordering::Relaxed), 0);
    assert_eq!(fx.pdp_calls(), 0);

    let records = fx.await_audit_records(2).await;
    let records = decision_records(&records);
    assert_eq!(records.len(), 2);
    for rec in records {
        assert_eq!(rec.result.reason, message, "{rec:?}");
        assert_eq!(rec.gateway.outcome, Outcome::Denied);
    }
}

/// A placing document that cannot be read is not treated as an old one.
#[tokio::test]
async fn an_unreadable_v3_bundle_fails_closed() {
    let mut bundle = v3();
    bundle.as_object_mut().expect("object").remove("backend");
    let fx = common::fixture("v3-unreadable", bundle);
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request("GetObject", get("reports", "2024/q1.csv"), Method::GET);
    let err = access.get_object(&mut req).await.expect_err("refused");
    assert!(
        err.message().is_some_and(
            |m| m.starts_with("deny (gateway): the policy bundle in force cannot be used")
        ),
        "{err}"
    );
    let out = list_buckets(&fx, "wild", ListBucketsInput::default())
        .await
        .expect("empty listing");
    assert!(names(&out).is_empty());
    assert_eq!(fx.pdp_calls(), 0);
}

// ── v3: ListBuckets from the bundle ─────────────────────────────────────────────

/// The listing is the requester's tenant's buckets from the bundle, filtered by the
/// policy's visibility, with `created_at` as the creation date — and the backend, which
/// would have listed another tenant's bucket too, is never asked.
#[tokio::test]
async fn list_buckets_is_answered_from_the_bundle_and_never_forwarded() {
    let backend = fake_backend().await;
    let fx = common::fixture_with_backend("v3-list", v3(), &backend.url);

    // `wild`'s wildcard grant is the unrestricted view — of its own tenant only.
    let out = list_buckets(&fx, "wild", ListBucketsInput::default())
        .await
        .expect("listing");
    assert_eq!(names(&out), ["logs", "reports", "zeta"]);
    let dates: Vec<String> = out
        .buckets
        .clone()
        .unwrap_or_default()
        .into_iter()
        .map(|b| {
            let mut s = Vec::new();
            b.creation_date
                .expect("created_at is the creation date")
                .format(TimestampFormat::DateTime, &mut s)
                .expect("format");
            String::from_utf8(s).expect("utf8")
        })
        .collect();
    assert_eq!(
        dates,
        [
            "2026-01-02T00:00:00.000Z",
            "2026-01-01T00:00:00.000Z",
            "2026-01-03T00:00:00.000Z"
        ]
    );
    assert!(
        out.owner.is_none(),
        "no Owner: there is no upstream identity to name"
    );

    // A named grant sees exactly that bucket.
    let out = list_buckets(&fx, "alice", ListBucketsInput::default())
        .await
        .expect("listing");
    assert_eq!(names(&out), ["reports"]);

    assert_eq!(
        backend.requests.load(Ordering::Relaxed),
        0,
        "a v3 ListBuckets must never reach the backend"
    );
}

#[tokio::test]
async fn the_bundle_listing_pages_and_filters_exactly_as_a_drained_one() {
    let backend = fake_backend().await;
    let fx = common::fixture_with_backend("v3-list-pages", v3(), &backend.url);

    let mut seen = Vec::new();
    let mut token = None;
    for _ in 0..10 {
        let out = list_buckets(
            &fx,
            "wild",
            ListBucketsInput {
                max_buckets: Some(1),
                continuation_token: token.clone(),
                ..Default::default()
            },
        )
        .await
        .expect("page");
        let page = names(&out);
        assert_eq!(page.len(), 1, "one bucket per page: {page:?}");
        seen.extend(page);
        match out.continuation_token {
            Some(next) => token = Some(next),
            None => break,
        }
    }
    assert_eq!(
        seen,
        ["logs", "reports", "zeta"],
        "every bucket once, in order"
    );

    let out = list_buckets(
        &fx,
        "wild",
        ListBucketsInput {
            prefix: Some("re".into()),
            ..Default::default()
        },
    )
    .await
    .expect("prefixed");
    assert_eq!(names(&out), ["reports"]);
    assert_eq!(out.prefix.as_deref(), Some("re"));

    let err = list_buckets(
        &fx,
        "wild",
        ListBucketsInput {
            continuation_token: Some("garbage".into()),
            ..Default::default()
        },
    )
    .await
    .expect_err("a malformed token is refused, not restarted");
    assert_eq!(*err.code(), S3ErrorCode::InvalidArgument);

    // A principal with no visibility gets the same empty answer as everywhere else.
    let out = list_buckets(&fx, "nobody", ListBucketsInput::default())
        .await
        .expect("empty");
    assert!(names(&out).is_empty());

    assert_eq!(backend.requests.load(Ordering::Relaxed), 0);
}

/// A listing the hook refused carries no proof, and the bundle listing will not hand the
/// tenant's buckets out without one.
#[tokio::test]
async fn the_bundle_listing_requires_the_authorization_proof() {
    use s0::proxy::obligations::{BucketSource, BucketVisibility, ResponseObligations};

    let fx = common::fixture("v3-list-proof", v3());
    let mut req: S3Request<ListBucketsInput> = fx.request_as(
        "wild",
        "ListBuckets",
        ListBucketsInput::default(),
        Method::GET,
    );
    // Installed by hand, past the hook: a visibility and a source, but no decision.
    ResponseObligations::buckets(
        BucketVisibility::All,
        BucketSource::Bundle(vec![Bucket {
            bucket_region: None,
            creation_date: None,
            name: Some("reports".into()),
        }]),
    )
    .install(&mut req.extensions);
    let err = gateway_s3(&fx)
        .list_buckets(req)
        .await
        .expect_err("no proof, no listing");
    assert_eq!(*err.code(), S3ErrorCode::InternalError);
}

// ── through the real server ─────────────────────────────────────────────────────

/// The same properties on the production path, where `check` — not a test seeder —
/// pins the placement: a signed `ListBuckets` is answered from the bundle, and a signed
/// read of another tenant's bucket is refused with the placement reason.
#[tokio::test]
async fn through_the_server_the_placement_is_pinned_by_check() {
    let backend = fake_backend().await;
    let fx = common::fixture_with_backend("v3-blackbox", v3(), &backend.url);
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
    let base = format!("http://{addr}");
    let host = base.trim_start_matches("http://").to_string();
    let send = |r: RawRequest| {
        let headers = r.sign(&host, common::ACCESS_KEY, common::SECRET_KEY);
        let method = Method::from_bytes(r.method.as_bytes()).expect("method");
        let mut builder = reqwest::Client::new()
            .request(method, r.url(&base))
            .timeout(Duration::from_secs(10));
        for (k, v) in &headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        async move {
            let resp = builder.send().await.expect("the gateway answers");
            (
                resp.status().as_u16(),
                resp.text().await.unwrap_or_default(),
            )
        }
    };

    // The static credential is alice's: she sees `reports`, and only it.
    let (status, body) = send(RawRequest::new("GET", "/")).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("<Name>reports</Name>"), "{body}");
    assert!(!body.contains("ledger") && !body.contains("logs"), "{body}");
    assert!(
        body.contains("2026-01-01T00:00:00"),
        "created_at is the date: {body}"
    );

    let (status, body) = send(RawRequest::new("GET", "/ledger/k")).await;
    assert_eq!(status, 403, "{body}");
    assert!(body.contains(BUCKET_OF_ANOTHER_TENANT), "{body}");

    assert_eq!(
        backend.requests.load(Ordering::Relaxed),
        0,
        "neither request may reach the backend"
    );
}
