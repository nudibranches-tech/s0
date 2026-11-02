//! The delegated class, black box: signed S3 requests over real HTTP into an assembled
//! gateway whose control backend is an in-process s3s stub.
//!
//! Two invariants carry the class (ADR-011 D7), and neither is satisfiable by inspection:
//! a delegated operation never reaches the policy engine, and an enforced operation never
//! reaches the control backend.

mod common;

use common::control_stub::{ControlStub, StubCall};
use common::ops::assert_matches_delegable_set;
use common::wire::{Answer, send_op, serve};
use http::Method;
use s0::access::GatewayAccess;
use s0::access::optable::delegable_ops;
use s0::audit::{AuditRecord, DELEGATED_PATH, GateStage, Outcome};
use s3s::S3;
use s3s::S3ErrorCode;
use s3s::access::S3Access;
use s3s::dto::*;

const BACKEND: &str = "bay-1";

/// A v3 bundle in which `ledger` belongs to another tenant and every write is frozen:
/// the policy would refuse anything touching it, and the placement would too.
fn hostile_bundle() -> serde_json::Value {
    let mut b = common::alice_bundle();
    b["grant_schema_version"] = serde_json::json!(3);
    b["backend"] = serde_json::json!({ "id": BACKEND, "kind": "ceph" });
    b["org_settings"]["freeze_writes"] = serde_json::json!(true);
    b["tenants"]["acme"]["bucket_attributes"] = serde_json::json!({
        "reports": { "denylist": {}, "object_name": "reports.bay-1",
                     "created_at": "2026-01-01T00:00:00Z" }
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

fn delegated(records: &[AuditRecord]) -> Vec<&AuditRecord> {
    records
        .iter()
        .filter(|r| r.path == DELEGATED_PATH)
        .collect()
}

#[tokio::test]
async fn a_delegated_operation_never_reaches_the_policy_engine() {
    let stub = ControlStub::start().await;
    let fx = common::fixture_with_control("deleg-no-pdp", hostile_bundle(), &stub.endpoint);
    let base = serve(&fx).await;

    for op in delegable_ops() {
        let answer = send_op(&base, op, "ledger").await;
        assert!(
            (200..300).contains(&answer.status),
            "{op} did not reach the control backend: {} {}",
            answer.status,
            answer.body
        );
    }

    assert_eq!(
        fx.pdp_calls(),
        0,
        "a delegated operation asked the policy engine"
    );
    assert!(
        fx.capture.snapshot().is_empty(),
        "a delegated operation produced a policy input"
    );
    let mut seen: Vec<String> = stub.calls().into_iter().map(|c| c.operation).collect();
    seen.sort_unstable();
    assert_eq!(seen.len(), 15, "{seen:?}");
    assert_matches_delegable_set(seen.iter().map(String::as_str).collect());

    let records = fx.await_audit_records(15).await;
    assert_eq!(records.len(), 15, "{records:#?}");
    for rec in &records {
        assert_eq!(rec.path, DELEGATED_PATH);
        assert!(rec.input.is_none() && rec.gate.is_none(), "{rec:#?}");
    }
}

#[tokio::test]
async fn an_enforced_operation_never_reaches_the_control_backend() {
    let stub = ControlStub::start().await;
    let fx = common::fixture_with_control("deleg-no-ctl", common::alice_bundle(), &stub.endpoint);
    let access = GatewayAccess::new(fx.gw.clone());
    let s3 = common::gateway_s3(&fx.gw);

    macro_rules! probe {
        ($m:ident, $name:literal, $input:expr) => {{
            let mut req = fx.request($name, $input, Method::GET);
            let _ = access.$m(&mut req).await;
            // The same request through the hook, then through the arm with whatever
            // proof the hook left on it; a second one with none at all.
            let _ = s3.$m(req).await;
            let _ = s3.$m(fx.request($name, $input, Method::GET)).await;
        }};
    }
    crate::each_enforced_op!(probe);
    assert_eq!(
        stub.count(),
        0,
        "an enforced operation reached the control backend"
    );

    // And a sample over the wire: the storage backend is a closed port, so these fail
    // loudly, and the control backend still hears nothing.
    let base = serve(&fx).await;
    let host = base.trim_start_matches("http://").to_string();
    for (method, path) in [("HEAD", "/reports"), ("GET", "/reports/2024/q1.csv")] {
        let req = common::sigv4::RawRequest::new(method, path);
        let answer =
            common::wire::send_raw(&base, &host, req, common::ACCESS_KEY, common::SECRET_KEY).await;
        assert_ne!(answer.status, 200, "{method} {path}");
    }
    assert_eq!(stub.count(), 0);
}

#[tokio::test]
async fn the_caller_identity_rides_in_signed_headers() {
    let stub = ControlStub::start().await;
    let fx = common::fixture_with_control("deleg-headers", common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;

    let answer = send_op(&base, "CreateBucket", "brand-new").await;
    assert_eq!(answer.status, 200, "{}", answer.body);

    let records = fx.await_audit_records(1).await;
    let [call]: [StubCall; 1] = stub.calls().try_into().expect("one control call");
    let expected = [
        ("x-s0-caller-subject", "sa:alice"),
        ("x-s0-caller-tenant", "acme"),
        ("x-s0-caller-organization", "org-acme"),
        ("x-s0-backend-id", BACKEND),
    ];
    for (name, value) in expected {
        assert_eq!(call.header(name), Some(value), "{name}");
    }
    assert_eq!(
        call.header("x-s0-request-id"),
        Some(records[0].decision_id.as_str()),
        "the request id joins the call to the delegated audit record"
    );
    for name in call.s0_headers.iter().map(|(n, _)| n.as_str()) {
        assert_eq!(call.header_count(name), 1, "{name} appears more than once");
        assert!(
            call.signed_headers.iter().any(|s| s == name),
            "{name} is not in SignedHeaders {:?}",
            call.signed_headers
        );
    }
    assert_eq!(call.s0_headers.len(), 5);
}

#[tokio::test]
async fn an_unconfigured_delegable_operation_is_refused_like_today() {
    let stub = ControlStub::start().await;
    let mut section = common::control_backend_json(&stub.endpoint);
    section["operations"] = serde_json::json!(["GetBucketCors"]);
    let fx =
        common::fixture_with_control_section("deleg-unlisted", common::alice_bundle(), section);
    let base = serve(&fx).await;

    let listed = send_op(&base, "GetBucketCors", "reports").await;
    assert_eq!(listed.status, 200, "{}", listed.body);

    let unlisted = send_op(&base, "PutBucketCors", "reports").await;
    assert_eq!(unlisted.status, 403, "{}", unlisted.body);
    assert!(unlisted.body.contains("PutBucketCors"), "{}", unlisted.body);
    assert_eq!(
        stub.count(),
        1,
        "only the listed operation reaches the control backend"
    );

    let records = fx.await_audit_records(2).await;
    let gate = records
        .iter()
        .find_map(|r| r.gate.as_ref())
        .expect("the refusal is a gate record");
    assert_eq!(gate.stage, GateStage::OperationNotEnforced);
    assert_eq!(gate.operation, "PutBucketCors");
}

fn assert_passes_through(answer: &Answer, code: &str, status: u16, message: &str) {
    assert_eq!(answer.status, status, "{}", answer.body);
    assert!(
        answer.body.contains(&format!("<Code>{code}</Code>")),
        "code {code} not in {}",
        answer.body
    );
    assert!(
        answer.body.contains(message),
        "message {message:?} not in {}",
        answer.body
    );
}

#[tokio::test]
async fn control_backend_errors_pass_through_with_the_gateway_request_id() {
    let stub = ControlStub::start().await;
    let fx = common::fixture_with_control("deleg-errors", common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;

    let cases: [(&str, S3ErrorCode, u16, &str); 6] = [
        (
            "GetBucketCors",
            S3ErrorCode::NoSuchCORSConfiguration,
            404,
            "no cors here",
        ),
        (
            "PutBucketLifecycleConfiguration",
            S3ErrorCode::OperationAborted,
            409,
            "try again later",
        ),
        (
            "PutBucketTagging",
            S3ErrorCode::MalformedXML,
            400,
            "bad tag document",
        ),
        (
            "DeleteBucketTagging",
            S3ErrorCode::InvalidTag,
            400,
            "reserved tag prefix",
        ),
        (
            "GetBucketEncryption",
            S3ErrorCode::NotImplemented,
            501,
            "encryption is not available",
        ),
        (
            "GetBucketVersioning",
            S3ErrorCode::Custom("HfSpecApplied".into()),
            409,
            "spec not yet applied",
        ),
    ];
    for (op, code, status, message) in &cases {
        stub.fail(op, code.clone(), *status, message);
    }

    let mut answers = Vec::new();
    for (op, code, status, message) in &cases {
        let answer = send_op(&base, op, "reports").await;
        assert_passes_through(&answer, code.as_str(), *status, message);
        answers.push(answer);
    }
    assert_eq!(
        stub.count(),
        cases.len(),
        "every error is one call, never retried"
    );

    let records = fx.await_audit_records(cases.len()).await;
    for (answer, (op, code, status, _)) in answers.iter().zip(&cases) {
        let rec = records
            .iter()
            .find(|r| r.delegated.as_ref().is_some_and(|d| d.operation == *op))
            .unwrap_or_else(|| panic!("no delegated record for {op}"));
        assert!(
            answer
                .body
                .contains(&format!("<RequestId>{}</RequestId>", rec.decision_id)),
            "{op}: the error body must carry the delegated record's id: {}",
            answer.body
        );
        let d = rec.delegated.as_ref().expect("delegated");
        assert_eq!(d.control_status, Some(*status), "{op}");
        assert_eq!(d.control_error.as_deref(), Some(code.as_str()), "{op}");
        assert_eq!(rec.gateway.outcome, Outcome::Error, "{op}");
        assert!(rec.result.allow, "{op}: only AccessDenied is a denial");
    }
}

#[tokio::test]
async fn an_access_denied_from_the_control_backend_is_recorded_as_a_denial() {
    let stub = ControlStub::start().await;
    let fx = common::fixture_with_control("deleg-denied", common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;
    stub.fail("PutBucketCors", S3ErrorCode::AccessDenied, 403, "frozen");

    let answer = send_op(&base, "PutBucketCors", "reports").await;
    assert_passes_through(&answer, "AccessDenied", 403, "frozen");

    let records = fx.await_audit_records(1).await;
    let rec = delegated(&records)[0];
    assert_eq!(rec.gateway.outcome, Outcome::Denied);
    assert!(!rec.result.allow);
    assert_eq!(rec.delegated.as_ref().unwrap().control_status, Some(403));
}

#[tokio::test]
async fn an_unreachable_control_backend_answers_503() {
    let fx =
        common::fixture_with_control("deleg-down", common::alice_bundle(), "http://127.0.0.1:2");
    let base = serve(&fx).await;

    let answer = send_op(&base, "GetBucketCors", "reports").await;
    assert_eq!(answer.status, 503, "{}", answer.body);
    assert!(
        answer.body.contains("<Code>ServiceUnavailable</Code>"),
        "{}",
        answer.body
    );

    let records = fx.await_audit_records(1).await;
    let rec = delegated(&records)[0];
    let d = rec.delegated.as_ref().unwrap();
    assert_eq!(d.control_status, None);
    assert_eq!(d.control_error, None);
    assert_eq!(rec.gateway.outcome, Outcome::Error);
    assert_eq!(rec.result.reason, "control backend unreachable");
    assert!(answer.body.contains(&rec.decision_id), "{}", answer.body);
}

#[tokio::test]
async fn a_control_backend_5xx_is_not_retried() {
    let stub = ControlStub::start().await;
    let fx = common::fixture_with_control("deleg-5xx", common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;
    stub.fail("PutBucketTagging", S3ErrorCode::InternalError, 500, "boom");
    stub.fail(
        "GetBucketCors",
        S3ErrorCode::ServiceUnavailable,
        503,
        "busy",
    );

    let first = send_op(&base, "PutBucketTagging", "reports").await;
    assert_eq!(first.status, 500, "{}", first.body);
    let second = send_op(&base, "GetBucketCors", "reports").await;
    assert_eq!(second.status, 503, "{}", second.body);
    assert_eq!(
        stub.count(),
        2,
        "a delegated write is not known to be idempotent: one attempt each"
    );
}

#[tokio::test]
async fn a_delegated_request_writes_exactly_one_delegated_audit_record() {
    let stub = ControlStub::start().await;
    let fx = common::fixture_with_control("deleg-audit", common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;

    let answer = send_op(&base, "PutBucketVersioning", "reports").await;
    assert_eq!(answer.status, 200, "{}", answer.body);

    let records = fx.await_audit_records(1).await;
    assert_eq!(records.len(), 1, "{records:#?}");
    let rec = &records[0];
    assert_eq!(rec.path, DELEGATED_PATH);
    assert!(rec.input.is_none() && rec.gate.is_none());
    let d = rec.delegated.as_ref().expect("delegated half");
    assert_eq!(d.operation, "PutBucketVersioning");
    assert_eq!(d.bucket, "reports");
    assert_eq!(d.tenant, "acme");
    assert_eq!(d.subject, "sa:alice");
    assert_eq!(d.control_status, Some(200));
    assert_eq!(d.control_error, None);
    assert_eq!(rec.requested_by, "alice");
    assert_eq!(rec.gateway.outcome, Outcome::Allowed);
    assert_eq!(rec.gateway.backend_id, BACKEND);
    assert_eq!(rec.gateway.backend, s0::audit::BackendOutcome::NotAttempted);
    assert!(rec.result.allow);
    assert_eq!(
        rec.labels
            .get(s0::audit::DEFAULT_ORG_LABEL_KEY)
            .map(String::as_str),
        Some("org-acme")
    );
    assert_eq!(answer.request_id(), Some(rec.decision_id.as_str()));
}

#[tokio::test]
async fn an_anonymous_delegated_request_is_refused_like_any_other() {
    let stub = ControlStub::start().await;
    let fx = common::fixture_with_control("deleg-anon", common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;

    let status = reqwest::Client::new()
        .put(format!("{base}/brand-new"))
        .send()
        .await
        .expect("answer")
        .status();
    assert_eq!(status, 403);
    assert_eq!(stub.count(), 0);
}

#[tokio::test]
async fn the_hooks_of_a_gateway_with_no_control_backend_still_refuse() {
    // No `control_backend`: the table refuses at the gate, and a hook reached some other
    // way still demands the proof.
    let fx = common::fixture("deleg-none", common::alice_bundle());
    let base = serve(&fx).await;
    let answer = send_op(&base, "CreateBucket", "brand-new").await;
    assert_eq!(answer.status, 403, "{}", answer.body);

    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request("CreateBucket", CreateBucketInput::default(), Method::PUT);
    assert!(access.create_bucket(&mut req).await.is_err());
    let s3 = common::gateway_s3(&fx.gw);
    let err = s3
        .create_bucket(fx.request("CreateBucket", CreateBucketInput::default(), Method::PUT))
        .await
        .expect_err("no control backend, no proof");
    assert_eq!(*err.code(), S3ErrorCode::InternalError);
}

#[tokio::test]
async fn concurrent_delegated_calls_each_sign_their_own_request() {
    let stub = ControlStub::start().await;
    let fx =
        common::fixture_with_control("deleg-concurrent", common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;

    let ops: Vec<&str> = delegable_ops().into_iter().cycle().take(45).collect();
    let tasks: Vec<_> = ops
        .iter()
        .map(|op| {
            let (base, op) = (base.clone(), op.to_string());
            tokio::spawn(async move { (send_op(&base, &op, "reports").await, op) })
        })
        .collect();
    for task in tasks {
        let (answer, op) = task.await.expect("request task");
        assert!((200..300).contains(&answer.status), "{op}: {}", answer.body);
    }

    let records = fx.await_audit_records(ops.len()).await;
    assert_eq!(records.len(), ops.len(), "{records:#?}");
    let calls = stub.calls();
    assert_eq!(calls.len(), ops.len());
    let mut joined = std::collections::BTreeSet::new();
    for call in &calls {
        let id = call.header("x-s0-request-id").expect("a request id");
        let record = records
            .iter()
            .find(|r| r.decision_id == id)
            .unwrap_or_else(|| panic!("no audit record for request id {id}"));
        assert_eq!(
            record.delegated.as_ref().map(|d| d.operation.as_str()),
            Some(call.operation.as_str()),
            "the call signed for another request's record"
        );
        assert!(joined.insert(id.to_string()), "request id {id} reused");
    }
}

#[tokio::test]
async fn a_request_that_ends_before_delegation_does_not_blame_the_control_backend() {
    let stub = ControlStub::start().await;
    let fx =
        common::fixture_with_control("deleg-malformed", common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;
    let host = base.trim_start_matches("http://").to_string();

    let route = common::routes::route("PutBucketCors");
    let mut req = common::sigv4::RawRequest::new(route.method, "/reports")
        .body(b"<CORSConfiguration".to_vec());
    for (k, v) in &route.query {
        req = req.query(k, v);
    }
    let answer =
        common::wire::send_raw(&base, &host, req, common::ACCESS_KEY, common::SECRET_KEY).await;
    assert_eq!(answer.status, 400, "{}", answer.body);

    assert_eq!(
        stub.count(),
        0,
        "a malformed request reached the control backend"
    );
    let records = fx.await_audit_records(1).await;
    let records = delegated(&records);
    assert_eq!(records.len(), 1, "{records:#?}");
    let rec = records[0];
    assert_eq!(
        rec.result.reason,
        "request ended before the control backend was called"
    );
    assert!(!rec.result.allow);
    assert_eq!(rec.gateway.outcome, Outcome::Error);
    assert!(
        rec.delegated
            .as_ref()
            .expect("context")
            .control_status
            .is_none()
    );
}

#[tokio::test]
async fn a_request_that_ends_during_the_call_does_not_claim_it_was_never_made() {
    let stub = ControlStub::start().await;
    stub.delay("CreateBucket", std::time::Duration::from_secs(30));
    let fx =
        common::fixture_with_control("deleg-abandoned", common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;

    let client = tokio::spawn({
        let base = base.clone();
        async move { send_op(&base, "CreateBucket", "reports").await }
    });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while stub.calls().is_empty() {
        assert!(
            std::time::Instant::now() < deadline,
            "the call never reached the control backend"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    client.abort();

    let records = fx.await_audit_records(1).await;
    let records = delegated(&records);
    assert_eq!(records.len(), 1, "{records:#?}");
    let rec = records[0];
    assert_eq!(
        rec.result.reason,
        "request ended before the control backend answered"
    );
    assert!(!rec.result.allow);
    assert_eq!(rec.gateway.outcome, Outcome::Error);
    assert_eq!(rec.delegated.as_ref().unwrap().control_status, None);
}

#[tokio::test]
async fn a_refused_gateway_credential_is_not_blamed_on_the_caller() {
    let stub = ControlStub::start().await;
    let mut section = common::control_backend_json(&stub.endpoint);
    section["secret_access_key"] = serde_json::json!("not-the-controls-secret");
    let fx = common::fixture_with_control_section(
        "deleg-bad-credential",
        common::alice_bundle(),
        section,
    );
    let base = serve(&fx).await;

    let answer = send_op(&base, "GetBucketCors", "reports").await;
    assert_eq!(answer.status, 503, "{}", answer.body);
    assert!(
        answer.body.contains("<Code>ServiceUnavailable</Code>"),
        "{}",
        answer.body
    );
    assert!(
        !answer.body.contains("SignatureDoesNotMatch"),
        "{}",
        answer.body
    );

    let records = fx.await_audit_records(1).await;
    let records = delegated(&records);
    assert_eq!(records.len(), 1);
    let rec = records[0];
    assert_eq!(rec.gateway.outcome, Outcome::Error);
    let d = rec.delegated.as_ref().expect("context");
    assert_eq!(d.control_status, Some(403));
    assert_eq!(d.control_error.as_deref(), Some("SignatureDoesNotMatch"));
}

#[tokio::test]
async fn the_never_delegable_control_plane_ops_stay_refused_with_delegation_on() {
    let stub = ControlStub::start().await;
    let fx = common::fixture_with_control("deleg-never", common::alice_bundle(), &stub.endpoint);
    let base = serve(&fx).await;
    let host = base.trim_start_matches("http://").to_string();

    for (op, method, query) in [
        ("DeleteBucket", "DELETE", None),
        ("GetBucketPolicy", "GET", Some("policy")),
        ("PutBucketPolicy", "PUT", Some("policy")),
    ] {
        let mut req = common::sigv4::RawRequest::new(method, "/reports");
        if let Some(q) = query {
            req = req.query(q, "");
        }
        let answer =
            common::wire::send_raw(&base, &host, req, common::ACCESS_KEY, common::SECRET_KEY).await;
        assert_eq!(answer.status, 403, "{op}: {}", answer.body);
    }
    assert_eq!(
        stub.count(),
        0,
        "a never-delegable operation reached the control backend"
    );

    let records = fx.await_audit_records(3).await;
    assert_eq!(records.len(), 3, "{records:#?}");
    for rec in &records {
        let gate = rec.gate.as_ref().expect("a gate record");
        assert_eq!(gate.stage, GateStage::OperationNotEnforced, "{rec:#?}");
    }
}
