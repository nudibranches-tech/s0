//! `create_objects` over S3 (ADR-009 F1): a write that cannot overwrite — `PutObject` or
//! `CompleteMultipartUpload` carrying `If-None-Match: *` — is authorized by the drop-box
//! verb, and the multipart steps that make nothing visible follow it.
//!
//! Driven through the real typed hooks, so what is asserted is the decision, its audit
//! record, and the proof the forward path would require.

mod common;

use http::Method;
use s0::access::{AuthzProof, GatewayAccess};
use s0::authz::OpaInput;
use s3s::S3Request;
use s3s::access::S3Access;
use s3s::dto::*;

fn bundle() -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": {
                "dropper": { "groups": [], "attributes": [] },
                "writer": { "groups": [], "attributes": [] },
                "reader": { "groups": [], "attributes": [] }
            },
            "bucket_attributes": { "inbound": { "denylist": {} } },
            "s3_grants": {
                "dropper": [ { "bucket": "inbound", "actions": ["create_objects", "read_objects"], "prefixes": ["drop/"] } ],
                "writer": [ { "bucket": "inbound", "actions": ["write_objects"], "prefixes": [] } ],
                "reader": [ { "bucket": "inbound", "actions": ["read_objects"], "prefixes": [] } ]
            }
        } }
    })
}

fn native(tag: &str) -> common::Fixture {
    common::fixture_with_config(tag, bundle(), "http://127.0.0.1:1", |c| {
        c["backends"][0]["conditional_create"] = serde_json::json!("native");
    })
}

fn put(key: &str, conditional: bool) -> PutObjectInput {
    PutObjectInput {
        bucket: "inbound".into(),
        key: key.into(),
        if_none_match: conditional.then_some(ETagCondition::Any),
        ..Default::default()
    }
}

fn complete(key: &str, conditional: bool) -> CompleteMultipartUploadInput {
    CompleteMultipartUploadInput {
        bucket: "inbound".into(),
        key: key.into(),
        upload_id: "u-1".into(),
        if_none_match: conditional.then_some(ETagCondition::Any),
        ..Default::default()
    }
}

fn proved<T>(req: &S3Request<T>) -> bool {
    req.extensions.get::<AuthzProof>().is_some()
}

async fn last_input(fx: &common::Fixture) -> OpaInput {
    let recs = fx.await_audit_records(1).await;
    recs.last()
        .and_then(|r| r.input.clone())
        .expect("a decision record")
}

#[tokio::test]
async fn a_conditional_put_is_a_create_and_a_create_only_principal_may_send_it() {
    let fx = native("s3-create-put");
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request_as("dropper", "PutObject", put("drop/a.csv", true), Method::PUT);
    access
        .put_object(&mut req)
        .await
        .expect("If-None-Match: * is a create");
    assert!(proved(&req));
    // The INM rides on the very value that is forwarded.
    assert!(
        req.input
            .if_none_match
            .as_ref()
            .is_some_and(ETagCondition::is_any)
    );
    // An allowed record is held until the forward settles it; dropping the request
    // settles it unenriched.
    drop(req);
    let input = last_input(&fx).await;
    assert_eq!(
        input.action.as_str(),
        "create_objects",
        "the record names the verb that decided"
    );

    // Without the condition the same write may overwrite: write_objects, denied.
    let mut req = fx.request_as(
        "dropper",
        "PutObject",
        put("drop/b.csv", false),
        Method::PUT,
    );
    assert!(access.put_object(&mut req).await.is_err());
    assert!(!proved(&req));

    // An entity-tag If-None-Match overwrites any other version: not a create.
    let mut i = put("drop/c.csv", false);
    i.if_none_match = Some(ETagCondition::ETag(ETag::Strong("abc".into())));
    let mut req = fx.request_as("dropper", "PutObject", i, Method::PUT);
    assert!(access.put_object(&mut req).await.is_err());

    // The create grant is still scoped by prefix.
    let mut req = fx.request_as(
        "dropper",
        "PutObject",
        put("elsewhere/a", true),
        Method::PUT,
    );
    assert!(access.put_object(&mut req).await.is_err());
    // And read_objects confers nothing.
    let mut req = fx.request_as("reader", "PutObject", put("drop/a.csv", true), Method::PUT);
    assert!(access.put_object(&mut req).await.is_err());
}

#[tokio::test]
async fn a_writer_asks_exactly_the_question_it_always_did() {
    let fx = native("s3-create-writer");
    let access = GatewayAccess::new(fx.gw.clone());
    let before = fx.pdp_calls();
    let mut req = fx.request_as("writer", "PutObject", put("any/key", true), Method::PUT);
    access
        .put_object(&mut req)
        .await
        .expect("write_objects covers a create");
    assert_eq!(
        fx.pdp_calls() - before,
        1,
        "one question: write_objects, no fallback asked"
    );
    drop(req);
    assert_eq!(last_input(&fx).await.action.as_str(), "write_objects");
}

#[tokio::test]
async fn the_multipart_lifecycle_follows_the_commit_condition() {
    let fx = native("s3-create-mpu");
    let access = GatewayAccess::new(fx.gw.clone());
    let as_dropper = |op: &str| (op.to_string(), "dropper");

    let (op, sub) = as_dropper("CreateMultipartUpload");
    let mut req = fx.request_as(
        sub,
        &op,
        CreateMultipartUploadInput {
            bucket: "inbound".into(),
            key: "drop/big.bin".into(),
            ..Default::default()
        },
        Method::POST,
    );
    access
        .create_multipart_upload(&mut req)
        .await
        .expect("starting makes nothing visible");

    let mut req = fx.request_as(
        "dropper",
        "UploadPart",
        UploadPartInput {
            bucket: "inbound".into(),
            key: "drop/big.bin".into(),
            upload_id: "u-1".into(),
            part_number: 1,
            ..Default::default()
        },
        Method::PUT,
    );
    access
        .upload_part(&mut req)
        .await
        .expect("a part is invisible");

    let mut req = fx.request_as(
        "dropper",
        "CompleteMultipartUpload",
        complete("drop/big.bin", false),
        Method::POST,
    );
    assert!(
        access.complete_multipart_upload(&mut req).await.is_err(),
        "an unconditional commit may overwrite"
    );
    let mut req = fx.request_as(
        "dropper",
        "CompleteMultipartUpload",
        complete("drop/big.bin", true),
        Method::POST,
    );
    access
        .complete_multipart_upload(&mut req)
        .await
        .expect("a conditional commit is a create");
    assert!(proved(&req));

    let mut req = fx.request_as(
        "dropper",
        "AbortMultipartUpload",
        AbortMultipartUploadInput {
            bucket: "inbound".into(),
            key: "drop/big.bin".into(),
            upload_id: "u-1".into(),
            ..Default::default()
        },
        Method::DELETE,
    );
    access
        .abort_multipart_upload(&mut req)
        .await
        .expect("cleaning up makes nothing visible");
}

#[tokio::test]
async fn a_backend_not_declared_native_never_takes_a_create_only_write() {
    // The default: `check_then_write`. If-None-Match is the only thing stopping an
    // overwrite, and nothing says this backend honours it.
    let fx = common::fixture("s3-create-not-native", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request_as("dropper", "PutObject", put("drop/a.csv", true), Method::PUT);
    let e = access.put_object(&mut req).await.unwrap_err();
    assert!(
        format!("{e:?}").contains("not declared conditional_create: native"),
        "{e:?}"
    );
    assert!(!proved(&req));
    let recs = fx.await_audit_records(1).await;
    let rec = recs.last().unwrap();
    assert!(!rec.result.allow);
    assert!(
        rec.result.reason.starts_with("deny (gateway): "),
        "{}",
        rec.result.reason
    );

    // Writers are unaffected.
    let mut req = fx.request_as("writer", "PutObject", put("any", true), Method::PUT);
    access.put_object(&mut req).await.expect("writer");
}

#[tokio::test]
async fn copy_object_is_never_create_only() {
    let fx = native("s3-create-copy");
    let access = GatewayAccess::new(fx.gw.clone());
    let input = CopyObjectInput::builder()
        .bucket("inbound".into())
        .key("drop/copy.csv".into())
        .copy_source(CopySource::Bucket {
            bucket: "inbound".into(),
            key: "drop/a.csv".into(),
            version_id: None,
        })
        .build()
        .unwrap();
    let mut req = fx.request_as("dropper", "CopyObject", input, Method::PUT);
    assert!(
        access.copy_object(&mut req).await.is_err(),
        "CopyObject has no destination condition (E4): it can overwrite"
    );
}
