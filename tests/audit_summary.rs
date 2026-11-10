//! ADR-011 through the real `S3Access` hooks: the allowed reads of a subject the bundle
//! lists in `org_settings.audit_summary_subjects` are recorded as one summary; its
//! denials, and every request of anyone else, keep a record each.

mod common;

use std::sync::Arc;

use http::Method;
use s0::access::GatewayAccess;
use s0::audit::{AuditRecord, BackendOutcome, PendingAudit};
use s3s::access::S3Access;
use s3s::dto::GetObjectInput;

fn bundle() -> serde_json::Value {
    let mut b = common::alice_bundle();
    b["org_settings"]["audit_summary_subjects"] = serde_json::json!(["user:replicator"]);
    b["tenants"]["acme"]["user_attributes"]["replicator"] =
        serde_json::json!({ "groups": [], "attributes": [] });
    b["tenants"]["acme"]["s3_grants"]["replicator"] = serde_json::json!([
        { "bucket": "reports", "actions": ["read_objects", "list_objects"], "prefixes": [] }
    ]);
    b
}

/// A `GetObject` the backend then answered, settled the way the forward path does.
async fn read(
    access: &GatewayAccess,
    fx: &common::Fixture,
    sub: &str,
    bucket: &str,
    key: &str,
) -> bool {
    let mut req = fx.request_as(
        sub,
        "GetObject",
        GetObjectInput {
            bucket: bucket.into(),
            key: key.into(),
            ..Default::default()
        },
        Method::GET,
    );
    let allowed = access.get_object(&mut req).await.is_ok();
    if let Some(pending) = req.extensions.get::<Arc<PendingAudit>>() {
        pending.settle(BackendOutcome::SucceededStatusUnknown, None);
    }
    allowed
}

fn summaries(records: &[AuditRecord]) -> Vec<&AuditRecord> {
    records
        .iter()
        .filter(|r| r.gateway.summary.is_some())
        .collect()
}

#[tokio::test]
async fn a_listed_subjects_reads_are_one_summary_and_its_denial_its_own_record() {
    let fx = common::fixture("audit-summary-listed", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    for n in 0..5 {
        assert!(
            read(
                &access,
                &fx,
                "replicator",
                "reports",
                &format!("2024/{n}.csv")
            )
            .await
        );
    }
    assert!(!read(&access, &fx, "replicator", "payroll", "2024/salaries.csv").await);

    let records = fx.await_audit_records(2).await;

    assert_eq!(records.len(), 2, "one summary and one denial: {records:#?}");
    let summary = summaries(&records);
    assert_eq!(summary.len(), 1);
    let folded = summary[0].gateway.summary.as_ref().expect("summary");
    assert_eq!(folded.requests, 5);
    let input = summary[0].input.as_ref().expect("input");
    assert_eq!(
        (input.bucket.as_str(), input.object.as_deref()),
        ("reports", None)
    );
    let denial = records
        .iter()
        .find(|r| !r.result.allow)
        .expect("the denial");
    assert!(denial.gateway.summary.is_none());
    assert_eq!(
        denial.input.as_ref().and_then(|i| i.object.as_deref()),
        Some("2024/salaries.csv"),
        "a denial keeps every detail"
    );
}

#[tokio::test]
async fn an_unlisted_subject_keeps_a_record_per_read() {
    let fx = common::fixture("audit-summary-unlisted", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    for n in 0..3 {
        assert!(read(&access, &fx, "alice", "reports", &format!("2024/{n}.csv")).await);
    }

    let records = fx.await_audit_records(3).await;

    assert_eq!(records.len(), 3);
    assert!(summaries(&records).is_empty());
}
