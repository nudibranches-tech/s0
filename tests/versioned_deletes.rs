//! A delete that names an object version is decided under `delete_object_versions`, not
//! `delete_objects`: the two verbs are independent grants (AWS `s3:DeleteObjectVersion`
//! parity), decided per entry in a batch.

mod common;

use http::Method;
use s0::access::GatewayAccess;
use s0::audit::VersionedKey;
use s0::model::Action;
use s3s::S3ErrorCode;
use s3s::access::S3Access;
use s3s::dto::{Delete, DeleteObjectInput, DeleteObjectsInput, ObjectIdentifier};

/// alice may delete unversioned objects under `2024/` and specific versions under `2025/`.
fn split_bundle() -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": [], "attributes": [] } },
            "bucket_attributes": { "reports": { "denylist": {} } },
            "s3_grants": { "alice": [
                { "bucket": "reports", "actions": ["delete_objects"], "prefixes": ["2024/"] },
                { "bucket": "reports", "actions": ["delete_object_versions"], "prefixes": ["2025/"] }
            ] },
            "group_grants": {}
        }}
    })
}

fn entry(key: &str, version: Option<&str>) -> ObjectIdentifier {
    ObjectIdentifier {
        key: key.into(),
        e_tag: None,
        last_modified_time: None,
        size: None,
        version_id: version.map(Into::into),
    }
}

fn batch(objects: Vec<ObjectIdentifier>) -> DeleteObjectsInput {
    DeleteObjectsInput {
        bucket: "reports".into(),
        bypass_governance_retention: None,
        checksum_algorithm: None,
        delete: Delete {
            objects,
            ..Default::default()
        },
        expected_bucket_owner: None,
        mfa: None,
        request_payer: None,
    }
}

fn single(key: &str, version: Option<&str>) -> DeleteObjectInput {
    DeleteObjectInput {
        bucket: "reports".into(),
        key: key.into(),
        version_id: version.map(Into::into),
        ..Default::default()
    }
}

fn forwarded(req: &s3s::S3Request<DeleteObjectsInput>) -> Vec<(String, Option<String>)> {
    req.input
        .delete
        .objects
        .iter()
        .map(|o| (o.key.clone(), o.version_id.clone()))
        .collect()
}

fn asked_actions(fx: &common::Fixture) -> Vec<String> {
    fx.capture
        .snapshot()
        .iter()
        .map(|c| c.raw["action"].as_str().expect("action").to_string())
        .collect()
}

async fn delete_one(tag: &str, key: &str, version: Option<&str>) -> (bool, Vec<String>) {
    let fx = common::fixture(tag, split_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request("DeleteObject", single(key, version), Method::DELETE);
    let allowed = access.delete_object(&mut req).await.is_ok();
    (allowed, asked_actions(&fx))
}

#[tokio::test]
async fn a_versioned_delete_is_decided_under_delete_object_versions() {
    let (allowed, asked) = delete_one("vd-single", "2025/a.csv", Some("v1")).await;
    assert!(allowed);
    assert_eq!(asked, ["delete_object_versions"]);

    // The same key with no version is the unversioned verb, which this prefix lacks.
    let (allowed, asked) = delete_one("vd-single-plain", "2025/a.csv", None).await;
    assert!(!allowed);
    assert_eq!(asked, ["delete_objects"]);

    // And the reverse: delete_objects does not confer a versioned delete.
    let (allowed, asked) = delete_one("vd-single-conf", "2024/a.csv", Some("v1")).await;
    assert!(!allowed);
    assert_eq!(asked, ["delete_object_versions"]);
}

#[tokio::test]
async fn a_null_version_id_is_a_versioned_delete() {
    let (allowed, asked) = delete_one("vd-null", "2025/a.csv", Some("null")).await;
    assert!(allowed);
    assert_eq!(asked, ["delete_object_versions"]);
}

#[tokio::test]
async fn a_mixed_batch_decides_each_entry_under_its_own_verb() {
    let fx = common::fixture("vd-mixed", split_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "DeleteObjects",
        batch(vec![
            entry("2024/plain.csv", None),
            entry("2025/versioned.csv", Some("v1")),
            entry("2024/versioned.csv", Some("v2")),
            entry("2025/plain.csv", None),
        ]),
        Method::POST,
    );
    access.delete_objects(&mut req).await.expect("some allowed");
    assert_eq!(
        forwarded(&req),
        [
            ("2024/plain.csv".to_string(), None),
            ("2025/versioned.csv".to_string(), Some("v1".to_string())),
        ],
        "an entry is forwarded only when its own verb is granted on its own key"
    );
    assert_eq!(
        asked_actions(&fx),
        [
            "delete_objects",
            "delete_object_versions",
            "delete_object_versions",
            "delete_objects"
        ]
    );

    drop(req);
    let records = fx.await_audit_records(1).await;
    let record = &records[0];
    assert_eq!(
        record.input.as_ref().expect("input").action,
        Action::DeleteObjectVersions,
        "a batch carrying any version is recorded under the versioned verb"
    );
    assert_eq!(
        record.gateway.versions,
        [
            VersionedKey {
                key: "2025/versioned.csv".into(),
                version_id: "v1".into()
            },
            VersionedKey {
                key: "2024/versioned.csv".into(),
                version_id: "v2".into()
            },
        ]
    );
    assert_eq!(
        record.gateway.denied_keys,
        ["2024/versioned.csv", "2025/plain.csv"]
    );
    assert_eq!(
        record.gateway.denied_versions,
        [VersionedKey {
            key: "2024/versioned.csv".into(),
            version_id: "v2".into()
        }],
        "the refused versioned entry is told apart from the refused plain one"
    );
}

#[tokio::test]
async fn a_single_versioned_delete_records_the_version_it_names() {
    for (tag, key, allowed) in [
        ("vd-rec-ok", "2025/a.csv", true),
        ("vd-rec-no", "2024/a.csv", false),
    ] {
        let fx = common::fixture(tag, split_bundle());
        let access = GatewayAccess::new(fx.gw.clone());
        let mut req = fx.request("DeleteObject", single(key, Some("v9")), Method::DELETE);
        assert_eq!(access.delete_object(&mut req).await.is_ok(), allowed);
        drop(req);
        let records = fx.await_audit_records(1).await;
        assert_eq!(
            records[0].gateway.versions,
            [VersionedKey {
                key: key.into(),
                version_id: "v9".into()
            }]
        );
    }
}

#[tokio::test]
async fn an_unversioned_batch_is_recorded_under_delete_objects() {
    let fx = common::fixture("vd-plain-batch", split_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "DeleteObjects",
        batch(vec![entry("2024/a.csv", None)]),
        Method::POST,
    );
    access.delete_objects(&mut req).await.expect("allowed");
    drop(req);
    let records = fx.await_audit_records(1).await;
    assert_eq!(
        records[0].input.as_ref().expect("input").action,
        Action::DeleteObjects
    );
    assert!(records[0].gateway.versions.is_empty());
}

#[tokio::test]
async fn a_batch_naming_one_key_twice_forwards_only_the_allowed_entry() {
    // The same key, once under each verb: only one is granted. A filter keyed on the key
    // would forward both (or neither); the decision is per entry.
    let fx = common::fixture("vd-twice", split_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "DeleteObjects",
        batch(vec![
            entry("2025/x.csv", None),
            entry("2025/x.csv", Some("v1")),
        ]),
        Method::POST,
    );
    access.delete_objects(&mut req).await.expect("one allowed");
    assert_eq!(
        forwarded(&req),
        [("2025/x.csv".to_string(), Some("v1".to_string()))]
    );

    let fx = common::fixture("vd-twice-rev", split_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "DeleteObjects",
        batch(vec![
            entry("2024/x.csv", Some("v1")),
            entry("2024/x.csv", None),
        ]),
        Method::POST,
    );
    access.delete_objects(&mut req).await.expect("one allowed");
    assert_eq!(forwarded(&req), [("2024/x.csv".to_string(), None)]);
}

#[tokio::test]
async fn a_batch_of_only_refused_versioned_entries_is_denied() {
    let fx = common::fixture("vd-all-denied", split_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "DeleteObjects",
        batch(vec![entry("2024/x.csv", Some("v1"))]),
        Method::POST,
    );
    let err = access
        .delete_objects(&mut req)
        .await
        .expect_err("delete_objects does not confer a versioned delete");
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
}
