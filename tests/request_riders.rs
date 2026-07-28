//! The ACL / grant-header / tagging / governance-bypass retrofit.
//!
//! This is a **regression suite on operations that already shipped**, not new coverage.
//! Before it existed, `PutObject` was authorized on `(bucket, key)` and nothing else, so
//! a request carrying `x-amz-acl: public-read` passed the hook untouched, reached RGW,
//! and made the object world-readable — behind a decision record that said "allowed
//! write". `CopyObject`, `CreateMultipartUpload`, `CreateBucket` and `PostObject` had the
//! same hole; `x-amz-grant-*`, `x-amz-tagging` on write and
//! `x-amz-bypass-governance-retention` were uninspected on top of it.
//!
//! Every test here has a positive control, for the reason stated in
//! `security_regressions.rs`: a deny-all bug would otherwise make the whole file green.
//!
//! Two properties are asserted over and over, because they are the ones that matter:
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
/// The DEFAULT ACCESS MODEL seeds exactly this for every org Owner, which is what makes
/// the code-level refusals load-bearing: a policy-only guard on public ACLs would leave
/// every Owner one `--acl public-read` away from publishing a patient record. Every
/// "refused in code" test re-runs against this bundle.
fn wildcard_bundle() -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false, "reserved_tag_keys": ["hyperfluid/*"] },
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

// ── the headline defect: a public ACL on a write ────────────────────────────────

#[tokio::test]
async fn put_object_with_x_amz_acl_public_read_is_refused() {
    // THE regression. `aws s3 cp --acl public-read` used to succeed against a gateway
    // whose entire purpose is to be the authorization point.
    //
    // Refused rather than stripped, deliberately: see `s0::access::headers` for the
    // argument. A strip would answer 200 to a request whose stated intent was not
    // honoured, and nothing in the response would say so.
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
    // The hole was never PutObject-specific. CopyObject is the worse case of the four:
    // its destination bucket need not be the source's, so a public ACL there publishes
    // a copy of data the caller only held read on.
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

        let mut req = fx.request(
            "CreateBucket",
            CreateBucketInput {
                bucket: "newbucket".into(),
                acl: Some(BucketCannedACL::from(acl.to_string())),
                ..Default::default()
            },
            Method::PUT,
        );
        assert!(
            access.create_bucket(&mut req).await.is_err(),
            "CreateBucket {acl}"
        );
    }

    // Positive control: the identical five requests without an ACL are all allowed under
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
    let mut req = fx.request(
        "CreateBucket",
        CreateBucketInput {
            bucket: "newbucket".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    access.create_bucket(&mut req).await.expect("plain create");
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

    // Positive control: the same five headers naming a specific principal are an
    // authorization question, not an unconditional refusal — they reach the PDP and are
    // allowed where write_object_acl is granted.
    let fx = common::fixture("riders-grant-hdr-ok", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            grant_read: Some("id=\"a-colleague\"".into()),
            ..Default::default()
        },
        Method::PUT,
    );
    access.put_object(&mut req).await.expect("named grantee");
}

#[tokio::test]
async fn x_amz_grant_write_on_a_bucket_create_is_refused() {
    // `grant-write` exists only on the bucket ACL, and it is the one grant header that
    // hands out WRITE. It is refused for a structural reason rather than a public-group
    // one: this gateway does not authorize bucket ACLs at all (`PutBucketAcl` is denied
    // at the gate), so a create-time bucket ACL would be a back door into the operation
    // the table refuses at the front.
    let fx = common::fixture("riders-bucket-grant", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "CreateBucket",
        CreateBucketInput {
            bucket: "newbucket".into(),
            grant_write: Some("id=\"someone-else\"".into()),
            ..Default::default()
        },
        Method::PUT,
    );
    let err = access
        .create_bucket(&mut req)
        .await
        .expect_err("a create-time bucket ACL must be refused");
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
    assert!(req.extensions.get::<AuthzProof>().is_none());
    let rec = sole_refusal(&fx).await;
    assert!(
        rec.result.reason.contains("does not authorize bucket ACLs"),
        "{rec:#?}"
    );
    let input = rec.input.expect("an input");
    assert_eq!(input.acl_grants[0].source, "grant-write");
}

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
async fn a_named_grantee_acl_requires_the_separate_write_object_acl_verb() {
    // The modelling decision: a `PutObject` carrying an ACL is two requests — write
    // these bytes, and set who may read them. AWS agrees (`s3:PutObject` +
    // `s3:PutObjectAcl`); folding the second into the first is what made the header
    // invisible.
    let fx = common::fixture("riders-acl-verb", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            grant_read: Some("id=\"a-colleague\"".into()),
            ..Default::default()
        },
        Method::PUT,
    );
    let err = access
        .put_object(&mut req)
        .await
        .expect_err("alice holds write_objects but not write_object_acl");
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
    assert!(req.extensions.get::<AuthzProof>().is_none());
    let rec = sole_refusal(&fx).await;
    assert!(rec.result.reason.contains("write_object_acl"), "{rec:#?}");
    assert!(
        !rec.result.reason.starts_with("deny (gateway):"),
        "this one IS a policy verdict — the gateway asked and the PDP said no — so it \
         must not be labelled as a gateway-side refusal: {rec:#?}"
    );

    // Positive control: the same request under a bundle that grants the verb.
    let fx = common::fixture("riders-acl-verb-ok", wildcard_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObject",
        PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            grant_read: Some("id=\"a-colleague\"".into()),
            ..Default::default()
        },
        Method::PUT,
    );
    access
        .put_object(&mut req)
        .await
        .expect("write_object_acl is granted here");
    assert!(req.extensions.get::<AuthzProof>().is_some());
    assert_eq!(
        fx.pdp_calls(),
        2,
        "a non-public ACL costs a second decision, on write_object_acl"
    );
}

// ── WORM defeat ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_delete_with_bypass_governance_retention_is_refused_without_the_verb() {
    // There IS no verb: the frozen 13-verb vocabulary has no equivalent of AWS's
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
    // The self-elevation guard. If a policy conditions a grant on `hyperfluid/*`, a
    // principal that can write that key can satisfy the condition with data it supplies
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
                        key: Some("hyperfluid/classification".into()),
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
        assert_eq!(tags["hyperfluid/classification"], "public");
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
    // THE shipped default. Until hyperfluid publishes the list, every tag write is
    // refused — including one that names no keys at all (`DeleteObjectTagging`) and one
    // riding inline on a `PutObject`. An absent security-relevant input must not read as
    // "no restriction"; the alternative default is indistinguishable from a correctly
    // configured deployment right up to the moment someone writes the first ABAC
    // condition.
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
    // Master plan §2.3 offers `strip_request_fields`; open question 6 asks whether it
    // should exist at all. It does not, and `deny_unknown_fields` on `Obligations` turns
    // a policy that emits it into a denial — the correct behaviour for an obligation this
    // PEP will not apply, and the same mechanism that protects every other unimplemented
    // obligation.
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
