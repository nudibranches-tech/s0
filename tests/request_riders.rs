//! ACL / grant-header / tagging / governance-bypass screening on write paths.
//!
//! Without it, a request carrying `x-amz-acl: public-read` would pass the hook untouched,
//! reach the backend and make the object world-readable behind a decision record that said
//! "allowed write". `x-amz-grant-*`, `x-amz-tagging` on write and
//! `x-amz-bypass-governance-retention` are the same class of unauthorized rider.
//!
//! Every test has a positive control: a deny-all bug would otherwise make the file green.
//! Two properties are asserted throughout:
//!
//! 1. **no `AuthzProof` is minted.** A refusal that still stamped the proof would be
//!    forwarded by the dispatcher regardless of the 403 the hook returned.
//! 2. **exactly one audit record, naming what was refused.** The `acl_grants` /
//!    `requested_tags` / `bypass_governance` fields ride inside `input`, so the record
//!    answers "what did they try to do" and not merely "something was denied".

mod common;

use http::Method;
use s0::access::{AuthzProof, GatewayAccess};
use s0::audit::{AuditRecord, Outcome};
use s3s::S3ErrorCode;
use s3s::access::S3Access;
use s3s::dto::*;

/// The five object grant headers, by the name they arrive under.
const OBJECT_GRANT_HEADERS: &[&str] = &[
    "x-amz-grant-full-control",
    "x-amz-grant-read",
    "x-amz-grant-read-acp",
    "x-amz-grant-write-acp",
];

/// `uri=` form naming the AllUsers group — the header that makes an object public.
const ALL_USERS: &str = "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"";

/// [`common::alice_bundle`] with a `bucket: "*", actions: ["*"]` grant.
///
/// Every org Owner is seeded exactly this, which is what makes the code-level refusals
/// load-bearing: a policy-only guard on public ACLs would leave every Owner one
/// `--acl public-read` away from publishing sensitive data. Every "refused in code" test
/// re-runs against this bundle.
fn wildcard_bundle() -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false, "reserved_tag_keys": ["acme/*"] },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": [], "attributes": [] } },
            "bucket_attributes": { "reports": { "denylist": {} } },
            "s3_grants": { "alice": [
                { "bucket": "*", "actions": ["*"], "prefixes": [] }
            ] },
            "group_grants": {}
        }}
    })
}

/// The one refused record a rejected request must leave, with the invariants every
/// refusal in this file shares.
async fn sole_refusal(fx: &common::Fixture) -> AuditRecord {
    let records = fx.await_audit_records(1).await;
    assert_eq!(
        records.len(),
        1,
        "a refused request must leave exactly one record: {records:#?}"
    );
    let rec = records.into_iter().next().unwrap();
    assert!(
        matches!(rec.gateway.outcome, Outcome::Denied) && !rec.result.allow,
        "{rec:#?}"
    );
    assert!(
        rec.gate.is_none(),
        "this is a refusal on a real, named resource, not a pre-policy gate denial: \
         {rec:#?}"
    );
    assert!(
        rec.input.is_some(),
        "the record must name what was refused: {rec:#?}"
    );
    rec
}

// ── a public ACL on a write ─────────────────────────────────────────────────────

#[tokio::test]
async fn put_object_with_x_amz_acl_public_read_is_refused() {
    // Refused rather than stripped, deliberately: see `s0::access::headers`. A strip would
    // answer 200 to a request whose stated intent was not honoured, and nothing in the
    // response would say so.
    for bundle in [common::alice_bundle(), wildcard_bundle()] {
        let fx = common::fixture("riders-acl-public", bundle);
        let access = GatewayAccess::new(fx.gw.clone());
        let mut req = fx.request(
            "PutObject",
            PutObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                acl: Some(ObjectCannedACL::from_static(ObjectCannedACL::PUBLIC_READ)),
                ..Default::default()
            },
            Method::PUT,
        );
        let err = access
            .put_object(&mut req)
            .await
            .expect_err("a public-read ACL must never reach the backend");
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
        assert!(
            req.extensions.get::<AuthzProof>().is_none(),
            "a refused write must mint no proof, or the dispatcher forwards it anyway"
        );

        let rec = sole_refusal(&fx).await;
        assert!(
            rec.result.reason.contains("public-read")
                && rec.result.reason.contains("refused in code, not by policy"),
            "{rec:#?}"
        );
        // The attempt itself is on the record — a regulator's question is "what did they
        // try", not "was something denied".
        let input = rec.input.expect("an input");
        assert_eq!(input.acl_grants.len(), 1);
        assert_eq!(input.acl_grants[0].source, "acl");
        assert_eq!(input.acl_grants[0].value, "public-read");
    }
}

#[tokio::test]
async fn every_public_canned_acl_is_refused_on_every_write_shaped_op() {
    // The hole is not PutObject-specific. CopyObject is the worst of the four: its
    // destination bucket need not be the source's, so a public ACL there publishes a copy
    // of data the caller only held read on. `CreateBucket` is refused at the gate instead
    // when no control backend lists it, which is strictly earlier, and
    // `security_regressions.rs` pins that; a delegated one is screened by the control
    // backend (ADR-012 D3).
    let fx = common::fixture("riders-acl-ops", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    for acl in ["public-read", "public-read-write", "authenticated-read"] {
        let canned = || Some(ObjectCannedACL::from(acl.to_string()));

        let mut req = fx.request(
            "PutObject",
            PutObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                acl: canned(),
                ..Default::default()
            },
            Method::PUT,
        );
        assert!(
            access.put_object(&mut req).await.is_err(),
            "PutObject {acl}"
        );

        let mut req = fx.request(
            "PostObject",
            PostObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                acl: canned(),
                ..Default::default()
            },
            Method::POST,
        );
        assert!(
            access.post_object(&mut req).await.is_err(),
            "PostObject {acl}"
        );

        let mut req = fx.request(
            "CreateMultipartUpload",
            CreateMultipartUploadInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                acl: canned(),
                ..Default::default()
            },
            Method::POST,
        );
        assert!(
            access.create_multipart_upload(&mut req).await.is_err(),
            "CreateMultipartUpload {acl}"
        );

        let mut input = common::ops::copy_object_input();
        input.acl = canned();
        let mut req = fx.request("CopyObject", input, Method::PUT);
        assert!(
            access.copy_object(&mut req).await.is_err(),
            "CopyObject {acl}"
        );
    }

    // Positive control: the identical four requests without an ACL are all allowed under
    // this bundle, so the refusals above are about the ACL and not about the fixture.
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    access.put_object(&mut req).await.expect("plain write");
}

#[tokio::test]
async fn each_x_amz_grant_header_is_refused_when_it_names_a_public_group() {
    // The sibling of the canned ACL, and the one nobody looks at because it is five
    // headers instead of one. `x-amz-grant-read: uri="…/AllUsers"` is exactly as public
    // as `x-amz-acl: public-read`.
    for header in OBJECT_GRANT_HEADERS {
        let fx = common::fixture("riders-grant-hdr", wildcard_bundle());
        let access = GatewayAccess::new(fx.gw.clone());
        let mut input = PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            ..Default::default()
        };
        match *header {
            "x-amz-grant-full-control" => input.grant_full_control = Some(ALL_USERS.into()),
            "x-amz-grant-read" => input.grant_read = Some(ALL_USERS.into()),
            "x-amz-grant-read-acp" => input.grant_read_acp = Some(ALL_USERS.into()),
            "x-amz-grant-write-acp" => input.grant_write_acp = Some(ALL_USERS.into()),
            other => panic!("unhandled grant header {other}"),
        }
        let mut req = fx.request("PutObject", input, Method::PUT);
        let err = match access.put_object(&mut req).await {
            Err(e) => e,
            Ok(()) => panic!("{header} naming AllUsers must be refused"),
        };
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied, "{header}");
        assert!(req.extensions.get::<AuthzProof>().is_none(), "{header}");

        let rec = sole_refusal(&fx).await;
        assert!(
            rec.result.reason.contains("AllUsers") || rec.result.reason.contains("allusers"),
            "{header}: {rec:#?}"
        );
        let input = rec.input.expect("an input");
        assert_eq!(
            input.acl_grants[0].source,
            header.trim_start_matches("x-amz-"),
            "the record must name WHICH header carried the grant"
        );
    }

    // Positive control: the SAME headers, absent, on the same bundle. It has to be this
    // rather than "a named grantee is allowed", since a named grantee is refused too, and
    // without it every assertion above would hold on a deny-all build.
    let fx = common::fixture("riders-grant-hdr-ok", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    access
        .put_object(&mut req)
        .await
        .expect("a write carrying no grant header at all");
}

// `grant-write` exists only on the bucket ACL, and no enforced op can carry one — the
// gate refuses `CreateBucket` unless a control backend answers it, and that one screens
// the grants (ADR-012 D3) — so there is nothing to screen here.
// `AclFields::write` is kept anyway: it is what makes the ACL normalizer complete, so a
// future op that CAN carry the header is screened the day it is added.

#[tokio::test]
async fn a_canned_acl_this_build_does_not_recognize_is_refused() {
    // Fail-closed on the S3 API growing an ACL name. The gateway cannot prove an unknown
    // canned ACL is not public, and the backend will happily expand it.
    let fx = common::fixture("riders-acl-unknown", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            acl: Some(ObjectCannedACL::from("log-delivery-write".to_string())),
            ..Default::default()
        },
        Method::PUT,
    );
    assert!(access.put_object(&mut req).await.is_err());
    let rec = sole_refusal(&fx).await;
    assert!(rec.result.reason.contains("does not recognize"), "{rec:#?}");
}

// ── the compatibility case: `private` is not a grant ────────────────────────────

#[tokio::test]
async fn a_benign_canned_private_acl_is_still_allowed_and_still_recorded() {
    // The whole argument for the strip escape hatch is `s3cmd`/`rclone`, which send
    // `x-amz-acl: private` on every upload. `private` asks for the ACL an object has
    // anyway, so it is handled as "no grant requested" — one const array, no switch, no
    // request rewriting, and therefore nothing an operator can flip on for everything.
    let fx = common::fixture("riders-acl-private", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            acl: Some(ObjectCannedACL::from_static(ObjectCannedACL::PRIVATE)),
            ..Default::default()
        },
        Method::PUT,
    );
    access
        .put_object(&mut req)
        .await
        .expect("a canned private ACL must not break ordinary clients");
    assert!(req.extensions.get::<AuthzProof>().is_some());

    // Allowed, but not invisible: what the caller asked for is a fact about the request,
    // so it still reaches the PDP and the record.
    let captured = fx.capture.snapshot();
    assert_eq!(
        captured.last().expect("a capture").raw["acl_grants"],
        serde_json::json!([{ "source": "acl", "value": "private" }])
    );
    // And exactly ONE decision was asked for: `private` confers nothing, so it must not
    // drag a write_object_acl sub-decision onto every ordinary upload.
    assert_eq!(fx.pdp_calls(), 1);
}

// ── a real, non-public grant is an authorization question ───────────────────────

#[tokio::test]
async fn a_named_grantee_acl_is_refused_in_code_on_every_write_path() {
    // An object ACL is a SECOND access-control list, held by the backend, that the control
    // plane does not project, cannot display and cannot revoke. Granting through it is
    // granting outside the managed access model, so there is no verb to ask the PDP about
    // and the refusal is unconditional.
    //
    // All four write paths are asserted, because the refusal lives in `screen_riders` and a
    // hook that stopped routing through it would silently reopen the hole. The bundle is
    // the WILDCARD one on purpose: `"actions": ["*"]` is what every org Owner is seeded,
    // and it must not help.
    let fx = common::fixture("riders-acl-conferring", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let named = || Some("id=\"a-colleague\"".to_string());
    let canned = || {
        Some(ObjectCannedACL::from(
            "bucket-owner-full-control".to_string(),
        ))
    };

    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            grant_read: named(),
            ..Default::default()
        },
        Method::PUT,
    );
    let err = access
        .put_object(&mut req)
        .await
        .expect_err("no grant can authorize conferring an ACL");
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
    assert!(req.extensions.get::<AuthzProof>().is_none());

    let rec = sole_refusal(&fx).await;
    assert!(
        rec.result.reason.contains("no verb that authorizes"),
        "the reason must say the refusal is unconditional, not that a grant was \
         missing: {rec:#?}"
    );
    assert!(
        rec.result.reason.starts_with("deny (gateway):"),
        "this is the GATEWAY refusing, not a PDP verdict; mislabelling it would put a \
         policy decision on the record that no policy made: {rec:#?}"
    );
    assert!(
        !rec.result
            .reason
            .contains("every caller of this object store"),
        "a named grantee is not a public exposure and must not be reported as one: \
         {rec:#?}"
    );
    let input = rec.input.expect("the record must name what was attempted");
    assert_eq!(input.acl_grants[0].source, "grant-read");
    assert_eq!(input.acl_grants[0].value, "id=\"a-colleague\"");

    // …and it costs NO policy question. There is no verb to ask about, and asking one
    // anyway would put a decision on the record for a question with only one answer.
    assert_eq!(
        fx.pdp_calls(),
        0,
        "a conferring ACL is screened in code, ahead of the PDP"
    );

    // The other three write paths, each on its own fixture so the pdp-call count above
    // stays readable. A canned conferring ACL on some, a grant header on others: both
    // shapes reach `screen_riders`, and both must be refused everywhere.
    let fx = common::fixture("riders-acl-conferring-post", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PostObject",
        PostObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            acl: canned(),
            ..Default::default()
        },
        Method::POST,
    );
    assert!(access.post_object(&mut req).await.is_err(), "PostObject");

    let fx = common::fixture("riders-acl-conferring-cmu", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "CreateMultipartUpload",
        CreateMultipartUploadInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            grant_full_control: named(),
            ..Default::default()
        },
        Method::POST,
    );
    assert!(
        access.create_multipart_upload(&mut req).await.is_err(),
        "CreateMultipartUpload — the ONLY point in the multipart lifecycle where the \
         completed object's ACL is fixed"
    );

    let fx = common::fixture("riders-acl-conferring-copy", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut input = common::ops::copy_object_input();
    input.acl = canned();
    let mut req = fx.request("CopyObject", input, Method::PUT);
    assert!(
        access.copy_object(&mut req).await.is_err(),
        "CopyObject — the worst of the four, because the destination bucket need not be \
         the source's"
    );

    // Positive control. Without it, everything above is equally true of a build that
    // refuses every write: the same four ops, same bundle, same objects, no ACL.
    let fx = common::fixture("riders-acl-conferring-ok", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    access.put_object(&mut req).await.expect("plain write");
    let mut input = common::ops::copy_object_input();
    input.acl = None;
    let mut req = fx.request("CopyObject", input, Method::PUT);
    access.copy_object(&mut req).await.expect("plain copy");
}

// ── WORM defeat ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_delete_with_bypass_governance_retention_is_refused_without_the_verb() {
    // There IS no verb: the gateway's grant vocabulary has no equivalent of AWS's
    // `s3:BypassGovernanceRetention`, so no grant can express "may destroy a retained
    // object" — which means the refusal cannot be a policy decision and has to be a code
    // one. The wildcard bundle is the proof that it is: `actions: ["*"]` still cannot
    // buy it.
    for bundle in [common::alice_bundle(), wildcard_bundle()] {
        let fx = common::fixture("riders-bypass", bundle);
        let access = GatewayAccess::new(fx.gw.clone());
        let mut req = fx.request(
            "DeleteObject",
            DeleteObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                bypass_governance_retention: Some(true),
                ..Default::default()
            },
            Method::DELETE,
        );
        let err = access
            .delete_object(&mut req)
            .await
            .expect_err("a governance bypass must never reach the backend");
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
        assert!(req.extensions.get::<AuthzProof>().is_none());

        let rec = sole_refusal(&fx).await;
        assert!(
            rec.result.reason.contains("bypass-governance-retention"),
            "{rec:#?}"
        );
        assert!(
            rec.input.expect("an input").bypass_governance,
            "the attempt must be on the record: 'who tried to defeat retention' is a \
             question a regulated audit trail has to answer"
        );
    }
}

#[tokio::test]
async fn a_versioned_delete_with_governance_bypass_is_still_refused() {
    // Destroying a retained version is the case the bypass header exists for. The new verb
    // must not be a way around the screen: not for a scoped grant, not for a wildcard one.
    for bundle in [common::alice_bundle(), wildcard_bundle()] {
        let fx = common::fixture("riders-bypass-versioned", bundle);
        let access = GatewayAccess::new(fx.gw.clone());
        let mut req = fx.request(
            "DeleteObject",
            DeleteObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                version_id: Some("3HL4kqtJlcpXroDTDmJ".into()),
                bypass_governance_retention: Some(true),
                ..Default::default()
            },
            Method::DELETE,
        );
        let err = access
            .delete_object(&mut req)
            .await
            .expect_err("a governance bypass must never reach the backend");
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
        assert!(req.extensions.get::<AuthzProof>().is_none());

        let rec = sole_refusal(&fx).await;
        assert!(
            rec.result.reason.contains("bypass-governance-retention"),
            "{rec:#?}"
        );
    }
}

#[tokio::test]
async fn a_multi_delete_carrying_the_bypass_header_is_refused_whole() {
    // The header covers the entire batch, so it is screened before any key is decided —
    // a partially-honoured WORM bypass is not something this gateway should be able to
    // produce, and per-key filtering would produce exactly that.
    let fx = common::fixture("riders-bypass-batch", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut input = common::ops::delete_objects_input();
    input.bypass_governance_retention = Some(true);
    let mut req = fx.request("DeleteObjects", input, Method::POST);
    assert!(access.delete_objects(&mut req).await.is_err());
    assert!(req.extensions.get::<AuthzProof>().is_none());
    assert_eq!(
        fx.pdp_calls(),
        0,
        "the batch is refused before a single key is asked about"
    );
    let rec = sole_refusal(&fx).await;
    assert!(
        rec.result.reason.contains("bypass-governance-retention"),
        "{rec:#?}"
    );

    // Positive control: the same batch without the header is allowed.
    let fx = common::fixture("riders-bypass-batch-ok", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "DeleteObjects",
        common::ops::delete_objects_input(),
        Method::POST,
    );
    access.delete_objects(&mut req).await.expect("plain batch");
}

// ── tagging: self-elevation and the reserved key space ──────────────────────────

#[tokio::test]
async fn a_tag_write_to_a_reserved_key_is_refused() {
    // The self-elevation guard. If a policy conditions a grant on a reserved tag key, a
    // principal that can write that key satisfies the condition with data it supplies
    // itself — write_object_tags being a separate verb is necessary and not sufficient,
    // because a principal legitimately holding it on its own prefix can still elevate
    // *within* that prefix.
    for bundle in [common::alice_bundle(), wildcard_bundle()] {
        let fx = common::fixture("riders-reserved-tag", bundle);
        let access = GatewayAccess::new(fx.gw.clone());
        let mut req = fx.request(
            "PutObjectTagging",
            PutObjectTaggingInput {
                tagging: Tagging {
                    tag_set: vec![Tag {
                        key: Some("acme/classification".into()),
                        value: Some("public".into()),
                    }],
                },
                ..common::ops::put_object_tagging_input()
            },
            Method::PUT,
        );
        let err = access
            .put_object_tagging(&mut req)
            .await
            .expect_err("a reserved tag key must never be writable");
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
        assert!(req.extensions.get::<AuthzProof>().is_none());
        let rec = sole_refusal(&fx).await;
        assert!(
            rec.result.reason.contains("reserved by the control plane"),
            "{rec:#?}"
        );
        // The proposed set is on the record, not the object's current one: the decision
        // is about the state the object is entering.
        let tags = rec.input.expect("an input").requested_tags.expect("tags");
        assert_eq!(tags["acme/classification"], "public");
    }

    // Positive control: an unreserved key under the same bundle is allowed.
    let fx = common::fixture("riders-reserved-tag-ok", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectTagging",
        common::ops::put_object_tagging_input(),
        Method::PUT,
    );
    access
        .put_object_tagging(&mut req)
        .await
        .expect("an unreserved key is an ordinary tag write");
    assert!(req.extensions.get::<AuthzProof>().is_some());
}

#[tokio::test]
async fn tagging_is_inert_when_reserved_tag_keys_is_absent() {
    // THE shipped default. Until the control plane publishes the list, every tag write is
    // refused — including one that names no keys at all (`DeleteObjectTagging`) and one
    // riding inline on a `PutObject`. An absent security-relevant input must not read as
    // "no restriction": that default is indistinguishable from a correctly configured
    // deployment right up to the first ABAC condition someone writes.
    let fx = common::fixture("riders-inert", common::bundle_without_reserved_tag_keys());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request(
        "PutObjectTagging",
        common::ops::put_object_tagging_input(),
        Method::PUT,
    );
    assert!(
        access.put_object_tagging(&mut req).await.is_err(),
        "PutObjectTagging must be inert"
    );
    assert!(req.extensions.get::<AuthzProof>().is_none());
    let rec = sole_refusal(&fx).await;
    assert!(
        rec.result.reason.contains("has not published")
            && rec.result.reason.contains("reserved_tag_keys"),
        "the reason must name the missing input, or an operator cannot tell an inert \
         deployment from a broken grant: {rec:#?}"
    );

    let fx = common::fixture(
        "riders-inert-del",
        common::bundle_without_reserved_tag_keys(),
    );
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "DeleteObjectTagging",
        DeleteObjectTaggingInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            ..Default::default()
        },
        Method::DELETE,
    );
    assert!(
        access.delete_object_tagging(&mut req).await.is_err(),
        "clearing tags is a tag write too: it changes the ABAC facts about an object \
         exactly as setting one does"
    );
    assert!(req.extensions.get::<AuthzProof>().is_none());

    let fx = common::fixture(
        "riders-inert-put",
        common::bundle_without_reserved_tag_keys(),
    );
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            tagging: Some("tier=public".into()),
            ..Default::default()
        },
        Method::PUT,
    );
    assert!(
        access.put_object(&mut req).await.is_err(),
        "an inline x-amz-tagging is a tag write wearing a PutObject's clothes"
    );

    // Positive controls, both halves. Under the SAME bundle a write with no tags is
    // allowed — so tagging is inert, not the gateway.
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    access
        .put_object(&mut req)
        .await
        .expect("an untagged write is unaffected by the reserved-key default");
    // And under a bundle that DOES publish a list, the identical tag write is allowed —
    // so the refusal is about the absent list and not about tagging being broken.
    let fx = common::fixture("riders-inert-control", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectTagging",
        common::ops::put_object_tagging_input(),
        Method::PUT,
    );
    access
        .put_object_tagging(&mut req)
        .await
        .expect("a published list makes tag writes live");
}

#[tokio::test]
async fn an_inline_x_amz_tagging_requires_the_write_object_tags_verb() {
    // `PutObject` with `x-amz-tagging` is a `PutObjectTagging` in disguise. Charging it
    // only to `write_objects` would let a principal with write-but-not-tag-write install
    // the tag an ABAC condition reads.
    let bundle = serde_json::json!({
        "org_settings": { "freeze_writes": false, "reserved_tag_keys": [] },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": [], "attributes": [] } },
            "bucket_attributes": { "reports": { "denylist": {} } },
            // write_objects, deliberately WITHOUT write_object_tags.
            "s3_grants": { "alice": [
                { "bucket": "reports", "actions": ["write_objects"], "prefixes": ["2024/"] }
            ] },
            "group_grants": {}
        }}
    });
    let fx = common::fixture("riders-inline-tags", bundle);
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            tagging: Some("tier=public".into()),
            ..Default::default()
        },
        Method::PUT,
    );
    let err = access
        .put_object(&mut req)
        .await
        .expect_err("write_objects alone must not carry a tag write");
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
    assert!(req.extensions.get::<AuthzProof>().is_none());
    let rec = sole_refusal(&fx).await;
    assert!(rec.result.reason.contains("write_object_tags"), "{rec:#?}");
    let input = rec.input.expect("an input");
    assert_eq!(
        input.requested_tags.expect("tags")["tier"],
        "public",
        "the header-derived tag set must reach the PDP under the same field name as a \
         PutObjectTagging body, or a policy has to know which op it came from"
    );

    // Positive control: the same request under a bundle that grants the tag verb.
    let fx = common::fixture("riders-inline-tags-ok", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            tagging: Some("tier=public".into()),
            ..Default::default()
        },
        Method::PUT,
    );
    access
        .put_object(&mut req)
        .await
        .expect("write_objects + write_object_tags carries the inline tag set");
}

#[tokio::test]
async fn a_copy_that_replaces_tags_is_authorized_as_a_tag_write() {
    // `x-amz-tagging-directive: REPLACE` makes a copy install a caller-chosen tag set on
    // the destination — the same self-elevation as an inline tagging header, on the op
    // that can also change bucket.
    let bundle = serde_json::json!({
        "org_settings": { "freeze_writes": false, "reserved_tag_keys": [] },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": [], "attributes": [] } },
            "bucket_attributes": { "reports": { "denylist": {} } },
            "s3_grants": { "alice": [
                { "bucket": "reports", "actions": ["read_objects", "write_objects"],
                  "prefixes": ["2024/"] }
            ] },
            "group_grants": {}
        }}
    });
    let fx = common::fixture("riders-copy-tags", bundle);
    let access = GatewayAccess::new(fx.gw.clone());
    let mut input = common::ops::copy_object_input();
    input.tagging_directive = Some(TaggingDirective::from_static(TaggingDirective::REPLACE));
    input.tagging = Some("tier=public".into());
    let mut req = fx.request("CopyObject", input, Method::PUT);
    assert!(
        access.copy_object(&mut req).await.is_err(),
        "a REPLACE copy without write_object_tags must be refused"
    );
    assert!(req.extensions.get::<AuthzProof>().is_none());
    let rec = sole_refusal(&fx).await;
    assert!(rec.result.reason.contains("write_object_tags"), "{rec:#?}");

    // Positive control: the same copy with the default COPY directive is allowed — the
    // destination inherits the source's tags, which is the residual recorded on the op's
    // blind-spot list rather than something this test pretends is closed.
    let fx = common::fixture("riders-copy-tags-ok", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request("CopyObject", common::ops::copy_object_input(), Method::PUT);
    access.copy_object(&mut req).await.expect("plain copy");
}

#[tokio::test]
async fn an_ambiguous_tagging_header_is_refused_rather_than_guessed() {
    // A tag set the gateway and RGW could decode differently means the PDP authorized a
    // tag set the object never receives — the same parser-differential argument that
    // already refuses a duplicate key in a `TagSet` body.
    let fx = common::fixture("riders-tag-ambiguous", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    for header in ["tier=a&tier=b", "tier", "tier=a+b"] {
        let mut req = fx.request(
            "PutObject",
            PutObjectInput {
                bucket: "reports".into(),
                key: "2024/x".into(),
                tagging: Some(header.into()),
                ..Default::default()
            },
            Method::PUT,
        );
        assert!(
            access.put_object(&mut req).await.is_err(),
            "x-amz-tagging {header:?} must be refused"
        );
        assert!(req.extensions.get::<AuthzProof>().is_none());
    }
}

// ── the strip escape hatch is not implemented, and that is a decision ───────────

#[tokio::test]
async fn no_strip_obligation_exists_and_a_policy_emitting_one_denies() {
    // There is no `strip_request_fields` obligation, and `deny_unknown_fields` on
    // `Obligations` turns a policy that emits one into a denial — the correct behaviour
    // for an obligation this PEP will not apply, and the same mechanism that protects
    // every other unimplemented obligation.
    assert!(
        !s0::authz::IMPLEMENTED_OBLIGATIONS.contains(&"strip_request_fields"),
        "shipping a strip switch means the first thing a frustrated operator does when \
         --acl private 403s is turn it on, for every principal and every request"
    );
    let err = serde_json::from_str::<s0::authz::Decision>(
        r#"{"allow":true,"reason":"ok","obligations":{"strip_request_fields":["acl"]}}"#,
    )
    .expect_err("a strip obligation must not deserialize");
    assert!(format!("{err}").contains("strip_request_fields"), "{err}");
}

// ── object lock (ADR-015): two verbs, inline riders, the bypass on retention ────

/// alice with `write_objects` (and `read_objects`) on `2024/`, plus whatever lock verbs
/// `lock` names.
fn lock_bundle(lock: &[&str]) -> serde_json::Value {
    let mut actions = vec!["read_objects", "write_objects"];
    actions.extend_from_slice(lock);
    serde_json::json!({
        "org_settings": { "freeze_writes": false, "reserved_tag_keys": ["acme/*"] },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": [], "attributes": [] } },
            "bucket_attributes": { "reports": { "denylist": {} } },
            "s3_grants": { "alice": [
                { "bucket": "reports", "actions": actions, "prefixes": ["2024/"] }
            ] },
            "group_grants": {}
        }}
    })
}

fn retain_until(days_from_now: i64) -> Timestamp {
    let at = chrono::Utc::now() + chrono::Duration::days(days_from_now);
    Timestamp::parse(
        TimestampFormat::DateTime,
        &at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
    )
    .expect("timestamp")
}

fn compliance() -> Option<ObjectLockMode> {
    Some(ObjectLockMode::from_static(ObjectLockMode::COMPLIANCE))
}

fn hold_on() -> Option<ObjectLockLegalHoldStatus> {
    Some(ObjectLockLegalHoldStatus::from_static(
        ObjectLockLegalHoldStatus::ON,
    ))
}

/// One write of each rider-carrying shape, with the given inline lock fields.
async fn each_lock_carrying_write(
    fx: &common::Fixture,
    mode: Option<ObjectLockMode>,
    until: Option<Timestamp>,
    hold: Option<ObjectLockLegalHoldStatus>,
) -> Vec<(&'static str, Result<(), s3s::S3Error>, bool)> {
    let access = GatewayAccess::new(fx.gw.clone());
    let mut out = Vec::new();

    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            object_lock_mode: mode.clone(),
            object_lock_retain_until_date: until.clone(),
            object_lock_legal_hold_status: hold.clone(),
            ..Default::default()
        },
        Method::PUT,
    );
    let r = access.put_object(&mut req).await;
    out.push(("PutObject", r, req.extensions.get::<AuthzProof>().is_some()));

    let mut req = fx.request(
        "PostObject",
        PostObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            object_lock_mode: mode.clone(),
            object_lock_retain_until_date: until.clone(),
            object_lock_legal_hold_status: hold.clone(),
            ..Default::default()
        },
        Method::POST,
    );
    let r = access.post_object(&mut req).await;
    out.push((
        "PostObject",
        r,
        req.extensions.get::<AuthzProof>().is_some(),
    ));

    let mut req = fx.request(
        "CreateMultipartUpload",
        CreateMultipartUploadInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            object_lock_mode: mode.clone(),
            object_lock_retain_until_date: until.clone(),
            object_lock_legal_hold_status: hold.clone(),
            ..Default::default()
        },
        Method::POST,
    );
    let r = access.create_multipart_upload(&mut req).await;
    out.push((
        "CreateMultipartUpload",
        r,
        req.extensions.get::<AuthzProof>().is_some(),
    ));

    let mut input = common::ops::copy_object_input();
    input.object_lock_mode = mode;
    input.object_lock_retain_until_date = until;
    input.object_lock_legal_hold_status = hold;
    let mut req = fx.request("CopyObject", input, Method::PUT);
    let r = access.copy_object(&mut req).await;
    out.push((
        "CopyObject",
        r,
        req.extensions.get::<AuthzProof>().is_some(),
    ));
    out
}

#[tokio::test]
async fn an_inline_retention_needs_write_object_retention_on_every_write_shape() {
    // Without the rider, every write_objects holder could make an object undeletable for
    // years in COMPLIANCE mode — the mirror image of the governance bypass.
    let fx = common::fixture("riders-lock-retention-denied", lock_bundle(&[]));
    for (op, result, proved) in
        each_lock_carrying_write(&fx, compliance(), Some(retain_until(30)), None).await
    {
        let err = result.expect_err(op);
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied, "{op}");
        assert!(!proved, "{op} minted a proof for a refused write");
    }
    let records = fx.await_audit_records(4).await;
    assert_eq!(records.len(), 4, "one record per request: {records:#?}");
    for rec in &records {
        assert!(!rec.result.allow, "{rec:#?}");
        assert!(
            rec.result.reason.contains("write_object_retention"),
            "{rec:#?}"
        );
        let input = rec.input.as_ref().expect("an input");
        let asked = input
            .requested_retention
            .as_ref()
            .expect("the retention asked for");
        assert_eq!(asked.mode.as_deref(), Some("COMPLIANCE"));
        assert!(asked.retain_until.is_some());
        let days = asked.retain_days.expect("retain_days");
        assert!((30..=31).contains(&days), "{days}");
    }

    // Positive control: the same four writes with the retention verb granted.
    let fx = common::fixture(
        "riders-lock-retention-ok",
        lock_bundle(&["write_object_retention"]),
    );
    for (op, result, proved) in
        each_lock_carrying_write(&fx, compliance(), Some(retain_until(30)), None).await
    {
        result.unwrap_or_else(|e| panic!("{op} with write_object_retention: {e}"));
        assert!(proved, "{op}");
    }
}

#[tokio::test]
async fn an_inline_legal_hold_needs_the_legal_hold_verb_not_the_retention_one() {
    let fx = common::fixture(
        "riders-lock-hold-denied",
        lock_bundle(&["write_object_retention"]),
    );
    for (op, result, _) in each_lock_carrying_write(&fx, None, None, hold_on()).await {
        let err = result.expect_err(op);
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied, "{op}");
        assert!(
            format!("{err}").contains("write_object_legal_hold"),
            "{op}: {err}"
        );
    }

    let fx = common::fixture(
        "riders-lock-hold-ok",
        lock_bundle(&["write_object_legal_hold"]),
    );
    for (op, result, _) in each_lock_carrying_write(&fx, None, None, hold_on()).await {
        result.unwrap_or_else(|e| panic!("{op} with write_object_legal_hold: {e}"));
    }

    // Both riders on one write take both decisions: the hold verb alone is not enough
    // for a write that also sets a retention.
    let fx = common::fixture(
        "riders-lock-both",
        lock_bundle(&["write_object_legal_hold"]),
    );
    for (op, result, _) in
        each_lock_carrying_write(&fx, compliance(), Some(retain_until(1)), hold_on()).await
    {
        assert!(result.is_err(), "{op}");
    }
}

#[tokio::test]
async fn a_lock_rider_is_one_more_decision_and_still_one_audit_record() {
    let fx = common::fixture(
        "riders-lock-cost",
        lock_bundle(&["write_object_retention", "write_object_legal_hold"]),
    );
    let access = GatewayAccess::new(fx.gw.clone());

    // A plain write costs exactly one decision.
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/plain".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    access.put_object(&mut req).await.expect("plain write");
    assert_eq!(
        fx.pdp_calls(),
        1,
        "a write without lock headers costs one decision"
    );
    drop(req);

    // A write with both riders: the write, the retention, the hold.
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/locked".into(),
            object_lock_mode: compliance(),
            object_lock_retain_until_date: Some(retain_until(10)),
            object_lock_legal_hold_status: hold_on(),
            ..Default::default()
        },
        Method::PUT,
    );
    access.put_object(&mut req).await.expect("locked write");
    assert_eq!(fx.pdp_calls(), 4);
    drop(req);

    let records = fx.await_audit_records(2).await;
    assert_eq!(records.len(), 2, "one record per request: {records:#?}");
    let locked = records
        .iter()
        .find(|r| r.input.as_ref().and_then(|i| i.object.as_deref()) == Some("2024/locked"))
        .expect("the locked write's record");
    let input = locked.input.as_ref().expect("input");
    assert_eq!(
        input.action,
        s0::model::Action::WriteObjects,
        "the record is against the primary input"
    );
    let asked = input
        .requested_retention
        .as_ref()
        .expect("requested_retention");
    assert_eq!(asked.legal_hold.as_deref(), Some("ON"));
    let plain = records
        .iter()
        .find(|r| r.input.as_ref().and_then(|i| i.object.as_deref()) == Some("2024/plain"))
        .expect("the plain write's record");
    assert!(
        plain
            .input
            .as_ref()
            .expect("input")
            .requested_retention
            .is_none(),
        "a write without a lock field carries no requested_retention"
    );
}

#[tokio::test]
async fn a_half_specified_inline_retention_is_refused_before_any_decision() {
    let fx = common::fixture(
        "riders-lock-malformed",
        lock_bundle(&["write_object_retention", "write_object_legal_hold"]),
    );
    for (mode, until) in [
        (compliance(), None),
        (None, Some(retain_until(5))),
        (
            Some(ObjectLockMode::from_static("FOREVER")),
            Some(retain_until(5)),
        ),
    ] {
        for (op, result, proved) in each_lock_carrying_write(&fx, mode.clone(), until, None).await {
            assert!(result.is_err(), "{op} {mode:?}");
            assert!(!proved, "{op}");
        }
    }
    assert_eq!(
        fx.pdp_calls(),
        0,
        "a parser differential is refused in code"
    );
}

fn put_retention(mode: &'static str, days: i64) -> PutObjectRetentionInput {
    PutObjectRetentionInput {
        bucket: "reports".into(),
        key: "2024/x".into(),
        retention: Some(ObjectLockRetention {
            mode: Some(ObjectLockRetentionMode::from_static(mode)),
            retain_until_date: Some(retain_until(days)),
        }),
        ..Default::default()
    }
}

#[tokio::test]
async fn put_object_retention_input_carries_requested_retention() {
    let fx = common::fixture(
        "riders-retention-input",
        lock_bundle(&["write_object_retention"]),
    );
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectRetention",
        put_retention(ObjectLockRetentionMode::GOVERNANCE, 3650),
        Method::PUT,
    );
    access
        .put_object_retention(&mut req)
        .await
        .expect("granted");
    assert_eq!(
        fx.pdp_calls(),
        1,
        "the primary decision IS the retention one"
    );
    drop(req);
    let records = fx.await_audit_records(1).await;
    let input = records[0].input.as_ref().expect("input");
    assert_eq!(input.action, s0::model::Action::WriteObjectRetention);
    let asked = input
        .requested_retention
        .as_ref()
        .expect("requested_retention");
    assert_eq!(asked.mode.as_deref(), Some("GOVERNANCE"));
    assert!(
        asked
            .retain_until
            .as_deref()
            .is_some_and(|d| d.ends_with('Z'))
    );
    let days = asked.retain_days.expect("retain_days");
    assert!((3650..=3651).contains(&days), "{days}");
    assert_eq!(asked.legal_hold, None);
}

#[tokio::test]
async fn put_object_legal_hold_input_carries_the_legal_hold_only() {
    let fx = common::fixture(
        "riders-hold-input",
        lock_bundle(&["write_object_legal_hold"]),
    );
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectLegalHold",
        common::ops::put_object_legal_hold_input(),
        Method::PUT,
    );
    access
        .put_object_legal_hold(&mut req)
        .await
        .expect("granted");
    drop(req);
    let records = fx.await_audit_records(1).await;
    let input = records[0].input.as_ref().expect("input");
    assert_eq!(input.action, s0::model::Action::WriteObjectLegalHold);
    assert_eq!(
        input.requested_retention,
        Some(s0::authz::RequestedRetention {
            legal_hold: Some("ON".into()),
            ..Default::default()
        })
    );

    // A hold with no status is refused: its direction is unknowable.
    let fx = common::fixture(
        "riders-hold-no-status",
        lock_bundle(&["write_object_legal_hold"]),
    );
    let access = GatewayAccess::new(fx.gw.clone());
    let mut input = common::ops::put_object_legal_hold_input();
    input.legal_hold = Some(ObjectLockLegalHold { status: None });
    let mut req = fx.request("PutObjectLegalHold", input, Method::PUT);
    assert!(access.put_object_legal_hold(&mut req).await.is_err());
    assert!(req.extensions.get::<AuthzProof>().is_none());
}

#[tokio::test]
async fn the_lock_verbs_and_write_objects_confer_nothing_on_each_other() {
    // write_objects alone: neither lock operation.
    let fx = common::fixture("riders-lock-independent", lock_bundle(&[]));
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectRetention",
        put_retention(ObjectLockRetentionMode::GOVERNANCE, 1),
        Method::PUT,
    );
    assert!(access.put_object_retention(&mut req).await.is_err());
    let mut req = fx.request(
        "PutObjectLegalHold",
        common::ops::put_object_legal_hold_input(),
        Method::PUT,
    );
    assert!(access.put_object_legal_hold(&mut req).await.is_err());

    // Each lock verb alone: not the other one, and not a data write.
    let only = |verb: &str| {
        serde_json::json!({
            "org_settings": { "freeze_writes": false, "reserved_tag_keys": ["acme/*"] },
            "tenants": { "acme": {
                "user_attributes": { "alice": { "groups": [], "attributes": [] } },
                "bucket_attributes": { "reports": { "denylist": {} } },
                "s3_grants": { "alice": [
                    { "bucket": "reports", "actions": [verb], "prefixes": ["2024/"] }
                ] },
                "group_grants": {}
            }}
        })
    };
    let fx = common::fixture("riders-lock-only-retention", only("write_object_retention"));
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectRetention",
        put_retention(ObjectLockRetentionMode::COMPLIANCE, 1),
        Method::PUT,
    );
    access
        .put_object_retention(&mut req)
        .await
        .expect("the retention verb sets retention");
    let mut req = fx.request(
        "PutObjectLegalHold",
        common::ops::put_object_legal_hold_input(),
        Method::PUT,
    );
    assert!(access.put_object_legal_hold(&mut req).await.is_err());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    assert!(
        access.put_object(&mut req).await.is_err(),
        "the retention verb writes no data"
    );

    let fx = common::fixture("riders-lock-only-hold", only("write_object_legal_hold"));
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectLegalHold",
        common::ops::put_object_legal_hold_input(),
        Method::PUT,
    );
    access
        .put_object_legal_hold(&mut req)
        .await
        .expect("the hold verb places a hold");
    let mut req = fx.request(
        "PutObjectRetention",
        put_retention(ObjectLockRetentionMode::GOVERNANCE, 1),
        Method::PUT,
    );
    assert!(access.put_object_retention(&mut req).await.is_err());

    // Reading retention and holds is read_objects.
    let fx = common::fixture("riders-lock-reads", lock_bundle(&[]));
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "GetObjectRetention",
        GetObjectRetentionInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            ..Default::default()
        },
        Method::GET,
    );
    access.get_object_retention(&mut req).await.expect("read");
    let mut req = fx.request(
        "GetObjectLegalHold",
        GetObjectLegalHoldInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            ..Default::default()
        },
        Method::GET,
    );
    access.get_object_legal_hold(&mut req).await.expect("read");
}

#[tokio::test]
async fn put_object_retention_with_the_governance_bypass_is_refused_in_code() {
    // The bypass is how a GOVERNANCE retention is shortened or lifted. The retention
    // verb does not express it, and a wildcard grant cannot buy it.
    for bundle in [lock_bundle(&["write_object_retention"]), wildcard_bundle()] {
        let fx = common::fixture("riders-retention-bypass", bundle);
        let access = GatewayAccess::new(fx.gw.clone());
        let mut input = put_retention(ObjectLockRetentionMode::GOVERNANCE, 1);
        input.bypass_governance_retention = Some(true);
        let mut req = fx.request("PutObjectRetention", input, Method::PUT);
        let err = access
            .put_object_retention(&mut req)
            .await
            .expect_err("a governance bypass must never reach the backend");
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
        assert!(req.extensions.get::<AuthzProof>().is_none());
        assert_eq!(fx.pdp_calls(), 0, "refused in code, before any decision");
        let rec = sole_refusal(&fx).await;
        assert!(
            rec.result.reason.contains("bypass-governance-retention"),
            "{rec:#?}"
        );
        let input = rec.input.expect("an input");
        assert!(input.bypass_governance, "the attempt is on the record");
        assert!(input.requested_retention.is_some());
    }

    // Positive control: the wildcard grant sets a retention without the header.
    let fx = common::fixture("riders-retention-wildcard", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectRetention",
        put_retention(ObjectLockRetentionMode::COMPLIANCE, 1),
        Method::PUT,
    );
    access
        .put_object_retention(&mut req)
        .await
        .expect("\"*\" confers write_object_retention (ADR-015 D5)");
}

#[tokio::test]
async fn freeze_writes_stops_both_lock_verbs() {
    let mut bundle = lock_bundle(&["write_object_retention", "write_object_legal_hold"]);
    bundle["org_settings"]["freeze_writes"] = serde_json::json!(true);
    let fx = common::fixture("riders-lock-frozen", bundle);
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectRetention",
        put_retention(ObjectLockRetentionMode::GOVERNANCE, 1),
        Method::PUT,
    );
    assert!(access.put_object_retention(&mut req).await.is_err());
    let mut req = fx.request(
        "PutObjectLegalHold",
        common::ops::put_object_legal_hold_input(),
        Method::PUT,
    );
    assert!(access.put_object_legal_hold(&mut req).await.is_err());
}

/// alice with `create_objects` (and `read_objects`) on `2024/` — no `write_objects` —
/// plus whatever lock verbs `lock` names, on a backend declared `conditional_create:
/// native`, so an `If-None-Match: *` write is decided by the create-only fallback.
fn create_only_lock_fixture(tag: &str, lock: &[&str]) -> common::Fixture {
    let mut bundle = lock_bundle(lock);
    bundle["tenants"]["acme"]["s3_grants"]["alice"][0]["actions"][1] =
        serde_json::json!("create_objects");
    common::fixture_with_config(tag, bundle, "http://127.0.0.1:1", |c| {
        c["backends"][0]["conditional_create"] = serde_json::json!("native");
    })
}

fn create_put(key: &str, conditional: bool) -> PutObjectInput {
    PutObjectInput {
        bucket: "reports".into(),
        key: key.into(),
        if_none_match: conditional.then_some(ETagCondition::Any),
        object_lock_mode: compliance(),
        object_lock_retain_until_date: Some(retain_until(30)),
        ..Default::default()
    }
}

#[tokio::test]
async fn a_create_only_write_still_takes_its_lock_riders() {
    // `create_objects` (ADR-014 F1) is only the fallback for the PRIMARY decision; the
    // lock riders are decided before it, against their own verbs, whichever verb ends up
    // deciding the write. A drop-box key must not stamp a COMPLIANCE retention it was
    // never granted.
    let fx = create_only_lock_fixture("riders-lock-create-denied", &[]);
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request("PutObject", create_put("2024/a", true), Method::PUT);
    let err = access
        .put_object(&mut req)
        .await
        .expect_err("a create-only write with a retention needs write_object_retention");
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
    assert!(format!("{err}").contains("write_object_retention"), "{err}");
    assert!(req.extensions.get::<AuthzProof>().is_none());
    let mut req = fx.request(
        "CreateMultipartUpload",
        CreateMultipartUploadInput {
            bucket: "reports".into(),
            key: "2024/b".into(),
            object_lock_legal_hold_status: hold_on(),
            ..Default::default()
        },
        Method::POST,
    );
    let err = access
        .create_multipart_upload(&mut req)
        .await
        .expect_err("a create-only upload with a hold needs write_object_legal_hold");
    assert!(
        format!("{err}").contains("write_object_legal_hold"),
        "{err}"
    );
    assert!(req.extensions.get::<AuthzProof>().is_none());

    // Positive control: the retention verb granted, the conditional write is allowed and
    // recorded under create_objects, carrying the retention it asked for.
    let fx = create_only_lock_fixture("riders-lock-create-ok", &["write_object_retention"]);
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request("PutObject", create_put("2024/c", true), Method::PUT);
    access
        .put_object(&mut req)
        .await
        .expect("create_objects + write_object_retention");
    assert!(req.extensions.get::<AuthzProof>().is_some());
    // The write, the retention rider, then the create-only fallback.
    assert_eq!(fx.pdp_calls(), 3);
    drop(req);
    let records = fx.await_audit_records(1).await;
    let input = records
        .last()
        .and_then(|r| r.input.as_ref())
        .expect("the write's record");
    assert_eq!(input.action, s0::model::Action::CreateObjects);
    assert_eq!(
        input
            .requested_retention
            .as_ref()
            .and_then(|r| r.mode.as_deref()),
        Some("COMPLIANCE")
    );

    // The same write without If-None-Match may overwrite: write_objects, still denied,
    // even though the rider's own verb is held.
    let mut req = fx.request("PutObject", create_put("2024/d", false), Method::PUT);
    assert!(access.put_object(&mut req).await.is_err());
    assert!(req.extensions.get::<AuthzProof>().is_none());
}
