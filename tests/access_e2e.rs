//! End-to-end enforcement through the real `S3Access` typed hooks: principal →
//! OPA input → regorus decision → obligation/mutation. Exercises the object
//! read/deny path, per-key multi-delete filtering (blind spot #2), and single-prefix
//! list rewrite against the shipped rego — no live backend needed (the hooks
//! only read the routing table, they never open a backend connection).
//!
//! The *security* properties these paths carry (copy exfiltration, verb separation,
//! unbounded listing) live in `tests/security_regressions.rs`; this file is the happy
//! path plus the fail-closed backstop.

mod common;

use std::sync::Arc;

use http::Method;
use s0::access::{GatewayAccess, OperationName};
use s0::identity::ResolvedPrincipal;
use s0::proxy::RouteSnapshot;
use s3s::access::S3Access;
use s3s::dto::{
    CreateMultipartUploadInput, Delete, DeleteObjectsInput, GetObjectInput,
    ListMultipartUploadsInput, ListObjectsV2Input, ObjectIdentifier,
};

/// `alice` is prefix-scoped to `reports/2024/`; `multi` holds list grants on two
/// prefixes, which is what drives the fan-out obligation.
fn bundle() -> serde_json::Value {
    let mut b = common::alice_bundle();
    b["tenants"]["acme"]["user_attributes"]["multi"] =
        serde_json::json!({ "groups": [], "attributes": [] });
    b["tenants"]["acme"]["s3_grants"]["multi"] = serde_json::json!([
        { "bucket": "reports", "actions": ["list_objects"], "prefixes": ["2024/", "2025/"] }
    ]);
    b
}

#[tokio::test]
async fn get_object_within_grant_is_allowed() {
    let fx = common::fixture("e2e-get-allow", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "GetObject",
        GetObjectInput {
            bucket: "reports".into(),
            key: "2024/q1.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.get_object(&mut req).await.is_ok());
}

#[tokio::test]
async fn get_object_outside_grant_is_denied() {
    let fx = common::fixture("e2e-get-deny", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "GetObject",
        GetObjectInput {
            bucket: "reports".into(),
            key: "2023/old.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.get_object(&mut req).await.is_err());
}

#[tokio::test]
async fn multi_delete_filters_to_authorized_keys() {
    let fx = common::fixture("e2e-multidelete", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let oid = |key: &str| ObjectIdentifier {
        e_tag: None,
        key: key.into(),
        last_modified_time: None,
        size: None,
        version_id: None,
    };
    let mut req = fx.request(
        "DeleteObjects",
        DeleteObjectsInput {
            bucket: "reports".into(),
            bypass_governance_retention: None,
            checksum_algorithm: None,
            delete: Delete {
                objects: vec![oid("2024/a.csv"), oid("2023/b.csv")],
                ..Default::default()
            },
            expected_bucket_owner: None,
            mfa: None,
            request_payer: None,
        },
        Method::POST,
    );
    // At least one key allowed => Ok, and the denied key is stripped from the forward.
    assert!(access.delete_objects(&mut req).await.is_ok());
    let kept: Vec<&str> = req
        .input
        .delete
        .objects
        .iter()
        .map(|o| o.key.as_str())
        .collect();
    assert_eq!(kept, vec!["2024/a.csv"]);
}

#[tokio::test]
async fn unbounded_list_is_narrowed_to_grant_prefix() {
    let fx = common::fixture("e2e-list-narrow", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "ListObjectsV2",
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: None,
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.list_objects_v2(&mut req).await.is_ok());
    assert_eq!(req.input.prefix.as_deref(), Some("2024/"));
}

#[tokio::test]
async fn create_multipart_upload_within_grant_is_allowed() {
    let fx = common::fixture("e2e-cmu-allow", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "CreateMultipartUpload",
        CreateMultipartUploadInput {
            bucket: "reports".into(),
            key: "2024/big.bin".into(),
            ..Default::default()
        },
        Method::POST,
    );
    assert!(access.create_multipart_upload(&mut req).await.is_ok());
}

#[tokio::test]
async fn create_multipart_upload_outside_prefix_is_denied() {
    let fx = common::fixture("e2e-cmu-deny", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "CreateMultipartUpload",
        CreateMultipartUploadInput {
            bucket: "reports".into(),
            key: "2023/big.bin".into(),
            ..Default::default()
        },
        Method::POST,
    );
    assert!(access.create_multipart_upload(&mut req).await.is_err());
}

#[tokio::test]
async fn list_multipart_uploads_is_narrowed_to_grant_prefix() {
    let fx = common::fixture("e2e-lmu", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "ListMultipartUploads",
        ListMultipartUploadsInput {
            bucket: "reports".into(),
            prefix: None,
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.list_multipart_uploads(&mut req).await.is_ok());
    assert_eq!(req.input.prefix.as_deref(), Some("2024/"));
}

#[tokio::test]
async fn multi_prefix_list_allows_and_stashes_fanout() {
    use s0::proxy::obligations::ResponseObligations;
    let fx = common::fixture("e2e-fanout", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    // `multi` holds list grants on two prefixes; an unbounded list is now allowed with
    // a fan-out obligation (previously it fail-closed).
    let mut req = fx.request_as(
        "multi",
        "ListObjectsV2",
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: None,
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.list_objects_v2(&mut req).await.is_ok());
    let obligations = ResponseObligations::of(&req).expect("response obligations stashed");
    let fo = obligations
        .list_fanout
        .as_ref()
        .expect("fan-out obligation stashed");
    assert_eq!(fo.prefixes, vec!["2024/".to_string(), "2025/".to_string()]);
    assert!(
        obligations.visible_buckets.is_none(),
        "a list fan-out must not carry a bucket-visibility verdict; the two obligations \
         travel in one extension but are not interchangeable"
    );
}

#[tokio::test]
async fn a_hook_without_the_check_context_fails_closed() {
    // The typed hooks read the principal, the route snapshot and the op name that
    // `check` stashed. If any is missing, `check` did not run — the hook must error,
    // never fall back to a default route or an empty org (which would silently
    // mis-attribute, and in the route's case mis-target, the decision).
    let fx = common::fixture("e2e-failclosed", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let input = || GetObjectInput {
        bucket: "reports".into(),
        key: "2024/q1.csv".into(),
        ..Default::default()
    };

    let mut req = fx.request("GetObject", input(), Method::GET);
    req.extensions.remove::<Arc<RouteSnapshot>>();
    assert!(access.get_object(&mut req).await.is_err());

    let mut req = fx.request("GetObject", input(), Method::GET);
    req.extensions.remove::<OperationName>();
    assert!(access.get_object(&mut req).await.is_err());

    let mut req = fx.request("GetObject", input(), Method::GET);
    req.extensions.remove::<Arc<ResolvedPrincipal>>();
    assert!(access.get_object(&mut req).await.is_err());

    // Control: with the full context the same request is allowed.
    let mut req = fx.request("GetObject", input(), Method::GET);
    assert!(access.get_object(&mut req).await.is_ok());
}
