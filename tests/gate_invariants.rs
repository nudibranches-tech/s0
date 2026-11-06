//! The three fail-closed layers, probed at runtime rather than asserted on paper.
//!
//! `tests/op_coverage.rs` proves `OP_TABLE` is well-formed, which is not the same as
//! proving the code matches it, and both ways it can fail to are silent: a missing
//! `S3Access` hook defaults to `Ok(())`, so an op marked `Enforced` is *allowed* with no
//! decision and no audit record; and a hook that does not authorize still forwards unless
//! dispatch demands an `AuthzProof`. Both probes are cross-checked against
//! `enforced_ops()`, so adding an op to the table without adding it here fails the build
//! rather than quietly losing coverage.

mod common;

use std::sync::Arc;

use common::ops::{assert_matches_delegable_set, assert_matches_enforced_set};
use http::{Extensions, HeaderMap, Method};
use s0::access::{AuthzProof, GatewayAccess, OperationName};
use s0::gateway::Gateway;
use s0::proxy::GatewayS3;
use s3s::access::S3Access;
use s3s::dto::*;
use s3s::{S3, S3ErrorCode, S3Request};

fn gateway_s3(gw: &Arc<Gateway>) -> GatewayS3 {
    common::gateway_s3(gw)
}

/// A request with NO `check` context at all — what a hook sees if the backstop never
/// ran, and what dispatch sees if no hook ran.
fn bare_request<T>(input: T) -> S3Request<T> {
    S3Request {
        input,
        method: Method::GET,
        uri: "/".parse().unwrap(),
        headers: HeaderMap::new(),
        extensions: Extensions::new(),
        credentials: None,
        region: None,
        service: None,
        trailing_headers: None,
    }
}

// ── layer 1: every enforced op really has a hook ────────────────────────────────

#[tokio::test]
async fn every_enforced_op_has_an_s3access_hook() {
    let fx = common::fixture("gate-hooks", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut seen = Vec::new();
    macro_rules! probe {
        ($m:ident, $name:literal, $input:expr) => {{
            // No principal, no route, no op name. Every real hook builds a `ReqCtx`
            // first and fails closed; the s3s default hook returns `Ok(())`.
            let mut req = bare_request($input);
            assert!(
                access.$m(&mut req).await.is_err(),
                "{} is Enforced but its S3Access hook returned Ok(()) on a request with \
                 no check context — that is the s3s fail-OPEN default, i.e. the hook is \
                 missing",
                $name
            );
            seen.push($name);
        }};
    }
    crate::each_enforced_op!(probe);
    assert_matches_enforced_set(seen);

    // Negative control — the probe must be able to tell the two apart. PutBucketAcl
    // has no hook, so on exactly the same context-free request the s3s default answers
    // `Ok(())`. That is the fail-open this test exists to catch, and it is only
    // meaningful because it is observable here.
    let mut req = bare_request(PutBucketAclInput::default());
    assert!(
        access.put_bucket_acl(&mut req).await.is_ok(),
        "s3s no longer fails open on an unimplemented access hook — re-read this test"
    );
}

// ── layer 2: every enforced op really has a dispatch arm ────────────────────────

/// The request is seeded **exactly as `check` seeds it** — principal, route snapshot,
/// operation name — and carries everything except an [`AuthzProof`].
///
/// That is the whole point of using `fx.request` here rather than `bare_request`: with a
/// bare request the arm fails on the missing route snapshot, so the assertion below holds
/// whether or not the forward path demands the proof. Seeding the route removes that
/// alternative cause, and the message assertion pins the remaining one.
#[tokio::test]
async fn every_enforced_op_has_a_gateway_s3_dispatch_arm() {
    let fx = common::fixture("gate-arms", common::alice_bundle());
    let s3 = gateway_s3(&fx.gw);
    let mut seen = Vec::new();
    macro_rules! probe {
        ($m:ident, $name:literal, $input:expr) => {{
            let Err(err) = s3.$m(fx.request($name, $input, Method::GET)).await else {
                panic!("{} forwarded a request with no authorization proof", $name)
            };
            assert_ne!(
                *err.code(),
                S3ErrorCode::NotImplemented,
                "{} is Enforced but has no GatewayS3 dispatch arm — check would let it \
                 through and it would 501",
                $name
            );
            // The arm exists AND it demands the proof before anything else: routing
            // would have succeeded on this request, so an error at all means the
            // forward path refused it, and the message says which refusal it was.
            assert_eq!(*err.code(), S3ErrorCode::InternalError, "{}", $name);
            assert!(
                format!("{err}").contains("authorization decision"),
                "{} failed for a reason other than the missing proof: {err}",
                $name
            );
            seen.push($name);
        }};
    }
    crate::each_enforced_op!(probe);
    assert_matches_enforced_set(seen);

    // Positive control on the seeding itself. If `fx.request` ever stopped installing
    // the route snapshot, every probe above would still see an InternalError — from
    // the missing route — and this test would silently go back to proving nothing.
    let req = fx.request("GetObject", GetObjectInput::default(), Method::GET);
    assert!(
        req.extensions
            .get::<Arc<s0::proxy::RouteSnapshot>>()
            .is_some(),
        "the arm probe must run on a routable request, or a missing route is an \
         alternative explanation for every InternalError above"
    );
}

#[tokio::test]
async fn denied_ops_have_no_dispatch_arm() {
    // The complement of the check above: a denied op must fall to the s3s
    // `NotImplemented` default, so even a bug in `check` cannot reach a backend.
    let fx = common::fixture("gate-denied-arms", common::alice_bundle());
    let s3 = gateway_s3(&fx.gw);
    let expect_not_implemented = |code: &S3ErrorCode, op: &str| {
        assert_eq!(
            *code,
            S3ErrorCode::NotImplemented,
            "{op} is denied but has a dispatch arm"
        );
    };

    let e = s3
        .put_bucket_acl(bare_request(PutBucketAclInput::default()))
        .await
        .err()
        .unwrap();
    expect_not_implemented(e.code(), "PutBucketAcl");

    let e = s3
        .get_bucket_replication(bare_request(GetBucketReplicationInput::default()))
        .await
        .err()
        .unwrap();
    expect_not_implemented(e.code(), "GetBucketReplication");

    // The two structural denials.
    let e = s3
        .create_session(bare_request(CreateSessionInput::default()))
        .await
        .err()
        .unwrap();
    expect_not_implemented(e.code(), "CreateSession");

    let e = s3
        .write_get_object_response(bare_request(WriteGetObjectResponseInput::default()))
        .await
        .err()
        .unwrap();
    expect_not_implemented(e.code(), "WriteGetObjectResponse");
}

#[tokio::test]
async fn post_object_forwards_only_with_a_proof() {
    // `post_object` is the one S3 method whose s3s default is not NotImplemented: it
    // re-dispatches through `put_object`. For every other denied op a missing dispatch
    // arm produces a 501; for this one it produces a silent *forward*, so the only thing
    // between a hook that did not authorize and the backend is the AuthzProof. Called
    // out by name because that failure mode is unique and unobvious.
    let fx = common::fixture("gate-postobject", common::alice_bundle());
    let s3 = gateway_s3(&fx.gw);
    let mut req = fx.request("PostObject", PostObjectInput::default(), Method::POST);
    req.input.bucket = "reports".into();
    req.input.key = "2024/x".into();
    let Err(err) = s3.post_object(req).await else {
        panic!("a form upload with no authorization decision must not be forwarded")
    };
    assert_ne!(
        *err.code(),
        S3ErrorCode::NotImplemented,
        "PostObject is Enforced; it must have a real dispatch arm"
    );
    assert_eq!(*err.code(), S3ErrorCode::InternalError);
    assert!(
        format!("{err}").contains("authorization decision"),
        "unexpected error: {err}"
    );
}

// ── layer 3: the authorization proof ────────────────────────────────────────────

#[tokio::test]
async fn hook_that_forgets_to_enforce_cannot_forward() {
    // The request is seeded exactly as `check` seeds it — principal, route, op name —
    // so routing and attribution would both succeed. What is missing is a decision.
    let fx = common::fixture("gate-proof", common::alice_bundle());
    let s3 = gateway_s3(&fx.gw);
    let req = fx.request(
        "GetObject",
        GetObjectInput {
            bucket: "reports".into(),
            key: "2024/q1.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    let Err(err) = s3.get_object(req).await else {
        panic!("forwarding without a decision must fail")
    };
    assert_eq!(*err.code(), S3ErrorCode::InternalError);
    assert!(
        format!("{err}").contains("authorization decision"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn every_enforced_hook_mints_a_proof_when_it_allows() {
    let fx = common::fixture("gate-mints", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut seen = Vec::new();
    macro_rules! probe {
        ($m:ident, $name:literal, $input:expr) => {{
            let mut req = fx.request($name, $input, Method::GET);
            access
                .$m(&mut req)
                .await
                .unwrap_or_else(|e| panic!("{} should be allowed by the grant: {e}", $name));
            let proof = req
                .extensions
                .get::<AuthzProof>()
                .unwrap_or_else(|| panic!("{} allowed the request but minted no proof", $name));
            assert_eq!(proof.operation(), $name);
            seen.push($name);
        }};
    }
    crate::each_enforced_op!(probe);
    assert_matches_enforced_set(seen);
}

#[tokio::test]
async fn a_denied_hook_mints_no_proof() {
    let fx = common::fixture("gate-denied-proof", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "GetObject",
        GetObjectInput {
            bucket: "reports".into(),
            // Outside the granted 2024/ prefix.
            key: "2023/old.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.get_object(&mut req).await.is_err());
    assert!(
        req.extensions.get::<AuthzProof>().is_none(),
        "a denied request must carry no authorization proof"
    );
}

#[tokio::test]
async fn a_proof_minted_for_another_operation_does_not_forward() {
    // One request is one operation, so this can only fire on a wiring bug — but the
    // proof is the thing standing between a wiring bug and the backend, so it checks.
    let fx = common::fixture("gate-proof-relabel", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let s3 = gateway_s3(&fx.gw);
    let mut req = fx.request(
        "GetObject",
        GetObjectInput {
            bucket: "reports".into(),
            key: "2024/q1.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    access.get_object(&mut req).await.expect("allowed");
    assert!(req.extensions.get::<AuthzProof>().is_some());

    // Re-label the request as a different op after the fact.
    req.extensions.insert(OperationName("PutObject".into()));
    let Err(err) = s3.get_object(req).await else {
        panic!("a proof for another operation must not forward")
    };
    assert_eq!(*err.code(), S3ErrorCode::InternalError);
    assert!(
        format!("{err}").contains("does not match"),
        "unexpected error: {err}"
    );
}

// ── the delegated class: the same three layers, with a proof of its own ─────────

#[tokio::test]
async fn every_delegable_op_has_a_hook_that_demands_a_delegation_proof() {
    let fx = common::fixture("gate-delegated-hooks", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut seen = Vec::new();
    macro_rules! probe {
        ($m:ident, $name:literal, $input:expr) => {{
            // Bare: the s3s default hook would answer `Ok(())`, which for a delegated
            // operation would read as an authorization nobody made.
            let mut bare = bare_request($input.clone());
            assert!(
                access.$m(&mut bare).await.is_err(),
                "{} is Delegable but its S3Access hook returned Ok(()) with no check \
                 context — the s3s fail-OPEN default, i.e. the hook is missing",
                $name
            );
            // Seeded exactly as `check` seeds an enforced request, but with no
            // `DelegationProof`: the hook must still refuse.
            let mut seeded = fx.request($name, $input, Method::GET);
            let err = access
                .$m(&mut seeded)
                .await
                .expect_err("a delegated hook must refuse without a delegation proof");
            assert_eq!(*err.code(), S3ErrorCode::InternalError, "{}", $name);
            assert!(
                format!("{err}").contains("delegation decision"),
                "{} refused for a reason other than the missing proof: {err}",
                $name
            );
            seen.push($name);
        }};
    }
    crate::each_delegable_op!(probe);
    assert_matches_delegable_set(seen);
}

#[tokio::test]
async fn every_delegable_op_arm_refuses_without_a_delegation_proof() {
    let stub = common::control_stub::ControlStub::start().await;
    let fx = common::fixture_with_control(
        "gate-delegated-arms",
        common::alice_bundle(),
        &stub.endpoint,
    );
    let s3 = gateway_s3(&fx.gw);
    let mut seen = Vec::new();
    macro_rules! probe {
        ($m:ident, $name:literal, $input:expr) => {{
            let Err(err) = s3.$m(fx.request($name, $input, Method::GET)).await else {
                panic!("{} was delegated with no delegation proof", $name)
            };
            assert_ne!(
                *err.code(),
                S3ErrorCode::NotImplemented,
                "{} is Delegable but has no GatewayS3 dispatch arm",
                $name
            );
            assert_eq!(*err.code(), S3ErrorCode::InternalError, "{}", $name);
            assert!(
                format!("{err}").contains("delegation decision"),
                "{} failed for a reason other than the missing proof: {err}",
                $name
            );
            seen.push($name);
        }};
    }
    crate::each_delegable_op!(probe);
    assert_matches_delegable_set(seen);
    assert_eq!(
        stub.count(),
        0,
        "a refused arm must not reach the control backend"
    );
}

#[tokio::test]
async fn an_authz_proof_does_not_open_a_delegated_arm() {
    // The strongest `AuthzProof` there is: one a real enforced hook minted for a real
    // request, carried onto a delegable one.
    let stub = common::control_stub::ControlStub::start().await;
    let fx = common::fixture_with_control(
        "gate-authz-not-delegation",
        common::alice_bundle(),
        &stub.endpoint,
    );
    let access = GatewayAccess::new(fx.gw.clone());
    let s3 = gateway_s3(&fx.gw);
    let mut enforced = fx.request(
        "GetObject",
        GetObjectInput {
            bucket: "reports".into(),
            key: "2024/q1.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    access.get_object(&mut enforced).await.expect("allowed");
    let proof = enforced
        .extensions
        .get::<AuthzProof>()
        .cloned()
        .expect("minted");

    let mut req = fx.request(
        "CreateBucket",
        CreateBucketInput {
            bucket: "reports".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    req.extensions.insert(proof);
    let Err(err) = s3.create_bucket(req).await else {
        panic!("an authorization proof opened a delegated arm")
    };
    assert_eq!(*err.code(), S3ErrorCode::InternalError);
    assert!(format!("{err}").contains("delegation decision"), "{err}");
    assert_eq!(stub.count(), 0);
}
