//! The delegated audit record is a contract with the platform's decision-log ingest, which
//! dispatches on `path` and reads `delegated.*` (ADR-011 D5, amending ADR-002). The shape
//! the gateway ships is the contract, not the ADR's prose, so it is captured from a real
//! delegated request, committed under `tests/data/platform/`, and pinned both ways:
//!
//! 1. the gateway still emits exactly the committed document (volatile ids and the
//!    timestamp aside);
//! 2. the committed document still parses into `AuditRecord` and serializes back
//!    unchanged, so a field the type drops or invents is caught.
//!
//! The platform repository mirrors these files and carries its own test against them.
//! Regenerate with `S0_DELEGATED_FIXTURE_REGENERATE=1 cargo test --test
//! delegated_audit_drift`, and review the diff as a change to a published contract. The
//! shape test reads the files the other two write, so run it a second time without the
//! variable. `result.allow` is `true` for every answered status but `403 AccessDenied`, so
//! the ingest must key on `gateway.outcome`.

mod common;

use std::collections::BTreeSet;
use std::path::PathBuf;

use common::control_stub::ControlStub;
use common::wire::{send_op, serve};
use s0::audit::{AuditRecord, DELEGATED_PATH};
use s3s::S3ErrorCode;

const VOLATILE_ID: &str = "00000000-0000-0000-0000-000000000000";
const VOLATILE_TIME: &str = "2026-11-02T00:00:00Z";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/platform")
        .join(name)
}

/// What the gateway emits for one delegated request, with the two values no test can pin
/// replaced by fixed ones.
async fn emitted(
    tag: &str,
    op: &str,
    scripted: Option<(S3ErrorCode, u16, &str)>,
) -> serde_json::Value {
    let stub = ControlStub::start().await;
    if let Some((code, status, message)) = scripted {
        stub.fail(op, code, status, message);
    }
    let fx = common::fixture_with_control(tag, common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;
    send_op(&base, op, "reports").await;
    let records = fx.await_audit_records(1).await;
    assert_eq!(records.len(), 1, "{records:#?}");
    let mut doc = serde_json::to_value(&records[0]).expect("record serializes");
    doc["decision_id"] = VOLATILE_ID.into();
    doc["timestamp"] = VOLATILE_TIME.into();
    doc
}

async fn check_against_fixture(name: &str, doc: serde_json::Value) {
    let path = fixture_path(name);
    if std::env::var("S0_DELEGATED_FIXTURE_REGENERATE").is_ok() {
        let mut pretty = serde_json::to_string_pretty(&doc).expect("pretty json");
        pretty.push('\n');
        std::fs::write(&path, pretty).expect("write fixture");
    }
    let committed: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("no fixture at {path:?} ({e}); regenerate it")),
    )
    .expect("fixture is JSON");
    assert_eq!(
        doc, committed,
        "the gateway no longer emits the delegated record committed in {name}. This is a \
         published contract: regenerate with S0_DELEGATED_FIXTURE_REGENERATE=1 only for a \
         deliberate change, and update the platform's mirror"
    );
    let parsed: AuditRecord =
        serde_json::from_value(committed.clone()).expect("the fixture parses as an AuditRecord");
    assert_eq!(
        serde_json::to_value(&parsed).expect("serializes"),
        committed,
        "{name} does not survive a round trip through AuditRecord"
    );
}

#[tokio::test]
async fn the_gateway_emits_the_committed_allowed_record() {
    let doc = emitted("drift-allowed", "PutBucketCors", None).await;
    check_against_fixture("delegated_audit_record.json", doc).await;
}

#[tokio::test]
async fn the_gateway_emits_the_committed_error_record() {
    let doc = emitted(
        "drift-error",
        "PutBucketLifecycleConfiguration",
        Some((
            S3ErrorCode::OperationAborted,
            409,
            "a conflicting write is in progress",
        )),
    )
    .await;
    check_against_fixture("delegated_audit_record_error.json", doc).await;
}

#[tokio::test]
async fn the_gateway_emits_the_committed_denied_record() {
    let doc = emitted(
        "drift-denied",
        "PutBucketCors",
        Some((S3ErrorCode::AccessDenied, 403, "Access Denied")),
    )
    .await;
    check_against_fixture("delegated_audit_record_denied.json", doc).await;
}

#[tokio::test]
async fn the_gateway_emits_the_committed_unanswered_record() {
    let fx = common::fixture_with_control(
        "drift-unanswered",
        common::alice_bundle(),
        "http://127.0.0.1:2",
    );
    let base = serve(&fx).await;
    send_op(&base, "PutBucketCors", "reports").await;
    let records = fx.await_audit_records(1).await;
    assert_eq!(records.len(), 1, "{records:#?}");
    let mut doc = serde_json::to_value(&records[0]).expect("record serializes");
    doc["decision_id"] = VOLATILE_ID.into();
    doc["timestamp"] = VOLATILE_TIME.into();
    check_against_fixture("delegated_audit_record_unanswered.json", doc).await;
}

fn keys(doc: &serde_json::Value) -> BTreeSet<&str> {
    doc.as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn the_committed_records_have_the_shape_the_ingest_dispatches_on() {
    for name in [
        "delegated_audit_record.json",
        "delegated_audit_record_error.json",
        "delegated_audit_record_denied.json",
        "delegated_audit_record_unanswered.json",
    ] {
        let doc: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(fixture_path(name)).expect("fixture present"),
        )
        .expect("JSON");
        assert_eq!(doc["path"], DELEGATED_PATH, "{name}");
        assert_eq!(
            keys(&doc),
            BTreeSet::from([
                "decision_id",
                "path",
                "delegated",
                "result",
                "requested_by",
                "timestamp",
                "labels",
                "gateway",
            ]),
            "{name}: neither `input` nor `gate` may be present"
        );
        let delegated = keys(&doc["delegated"]);
        for required in ["operation", "bucket", "tenant", "subject"] {
            assert!(delegated.contains(required), "{name}: delegated.{required}");
        }
        assert_eq!(doc["gateway"]["backend"], "not_attempted", "{name}");
        assert!(doc["labels"]["s0/organization-id"].is_string(), "{name}");
    }
}
