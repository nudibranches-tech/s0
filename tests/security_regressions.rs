//! Named regressions for the ways this gateway has been, or could be, wrong.
//!
//! Every test here corresponds to a lesson from the failed attempt (see
//! `S0-INTEGRATION-SYNTHESIS.md` §10) or to a hazard the current design still carries.
//! They run against the real typed hooks, the real embedded regorus engine and the real
//! shipped rego — the same path a request takes in production, minus the backend.
//!
//! Each one has a **positive control**: a nearly identical request that must be
//! allowed. Without it a deny-all bug makes the whole file green, which is exactly how
//! 35 rego tests once passed against a production that authorized nothing.

mod common;

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::sigv4::RawRequest;
use http::Method;
use s0::access::{AuthzProof, GatewayAccess};
use s0::audit::{BackendOutcome, GateStage, Outcome};
use s3s::S3ErrorCode;
use s3s::access::S3Access;
use s3s::dto::*;

/// Boot the real serving path on a loopback port. Needed because `S3AccessContext` has
/// crate-private fields: `check` — where every gate denial lives — cannot be called
/// in-process, so the only way to test it is over TCP.
async fn spawn_gateway(tag: &str, bundle: serde_json::Value) -> (String, common::Fixture) {
    let fx = common::fixture(tag, bundle);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr: SocketAddr = listener.local_addr().unwrap();
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
    (format!("http://{addr}"), fx)
}

/// One raw request, optionally SigV4-signed. `None` credentials means genuinely
/// unsigned — s3s then hands `check` a context with no credentials at all, which is the
/// anonymous branch.
async fn send_signed(
    base: &str,
    host: &str,
    method: &'static str,
    path: &str,
    query: &[(&str, &str)],
    creds: Option<(&str, &str)>,
) -> u16 {
    let mut r = RawRequest::new(method, path.to_string());
    for (k, v) in query {
        r = r.query(k, v);
    }
    let headers = match creds {
        Some((ak, sk)) => r.sign(host, ak, sk),
        None => vec![("host".to_string(), host.to_string())],
    };
    let mut builder = reqwest::Client::new()
        .request(method.parse().expect("http method"), r.url(base))
        .timeout(Duration::from_secs(10))
        .body(r.body.clone());
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    builder
        .send()
        .await
        .expect("the gateway must answer")
        .status()
        .as_u16()
}

/// Four principals, each holding exactly one thing, so "grant X does not confer Y" is
/// answerable without a second bundle:
///
/// - `writer`  — write on `staging`, and nothing anywhere else. No read on `secrets`.
/// - `reader`  — read on `staging`.
/// - `lister`  — list on `reports/2024/`, no read.
/// - `copyist` — read on `secrets` *and* write on `staging`: the one principal for whom
///   a copy out of `secrets` is legitimate.
/// - `alice`   — the subject the checked-in static credential resolves to, with a read
///   on `staging`. Only the black-box tests, which must sign as a credential the
///   gateway really knows, use it.
/// - `spanner` — list on **two** prefixes of `reports`, so its listing carries a
///   multi-prefix obligation and only `ListObjectsV2` (without a delimiter) can serve
///   it. The principal that exercises the fan-out refusal paths.
fn bundle() -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": {
                "writer":  { "groups": [], "attributes": [] },
                "reader":  { "groups": [], "attributes": [] },
                "alice":   { "groups": [], "attributes": [] },
                "lister":  { "groups": [], "attributes": [] },
                "spanner": { "groups": [], "attributes": [] },
                "copyist": { "groups": [], "attributes": [] }
            },
            "bucket_attributes": {},
            "s3_grants": {
                "writer":  [ { "bucket": "staging", "actions": ["write_objects"], "prefixes": [] } ],
                "reader":  [ { "bucket": "staging", "actions": ["read_objects"], "prefixes": [] } ],
                "alice":   [ { "bucket": "staging", "actions": ["read_objects"], "prefixes": [] } ],
                "lister":  [ { "bucket": "reports", "actions": ["list_objects"], "prefixes": ["2024/"] } ],
                "spanner": [ { "bucket": "reports", "actions": ["list_objects"], "prefixes": ["2024/", "2025/"] } ],
                "copyist": [
                    { "bucket": "secrets", "actions": ["read_objects"], "prefixes": [] },
                    { "bucket": "staging", "actions": ["write_objects"], "prefixes": [] }
                ]
            },
            "group_grants": {}
        }}
    })
}

fn copy_source() -> CopySource {
    CopySource::Bucket {
        bucket: "secrets".into(),
        key: "payroll/2026.csv".into(),
        version_id: None,
    }
}

fn copy_object_input() -> CopyObjectInput {
    let mut b = CopyObjectInput::builder();
    b.set_bucket("staging".into());
    b.set_key("exfil.csv".into());
    b.set_copy_source(copy_source());
    b.build().expect("copy object input")
}

fn upload_part_copy_input() -> UploadPartCopyInput {
    let mut b = UploadPartCopyInput::builder();
    b.set_bucket("staging".into());
    b.set_key("exfil.csv".into());
    b.set_copy_source(copy_source());
    b.set_part_number(1);
    b.set_upload_id("upload-1".into());
    b.build().expect("upload part copy input")
}

fn oid(key: &str) -> ObjectIdentifier {
    ObjectIdentifier {
        key: key.into(),
        e_tag: None,
        last_modified_time: None,
        size: None,
        version_id: None,
    }
}

// ── CopyObject exfiltration ─────────────────────────────────────────────────────

#[tokio::test]
async fn copy_object_from_a_read_denied_bucket_is_refused() {
    // THE latent hole in this design, and the reason it stayed hidden last time: with
    // the gateway deny-all, nobody could observe that a copy authorizes only its
    // destination. `x-amz-copy-source` is a *read* of another bucket performed by the
    // backend under the tenant-owner credential — so a principal with write-only access
    // to a scratch bucket can name any object in the tenant as a source and read it out
    // through a bucket it is allowed to read. It must be two decisions, not one.
    let fx = common::fixture("sec-copy", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request_as("writer", "CopyObject", copy_object_input(), Method::PUT);
    let err = access
        .copy_object(&mut req)
        .await
        .expect_err("a write-only principal must not copy out of a bucket it cannot read");
    assert!(format!("{err}").contains("copy denied"), "{err}");
    assert!(
        req.extensions.get::<AuthzProof>().is_none(),
        "a denied copy must mint no authorization proof — the proof is the only thing \
         standing between a hook bug and the backend"
    );

    // Positive control: the *same* copy, by the one principal that may read the source.
    // Without this, the assertion above would hold for a gateway that denies every
    // copy, which proves nothing about source authorization.
    let mut req = fx.request_as("copyist", "CopyObject", copy_object_input(), Method::PUT);
    access
        .copy_object(&mut req)
        .await
        .expect("read on the source + write on the destination is a legitimate copy");
    assert!(req.extensions.get::<AuthzProof>().is_some());
}

#[tokio::test]
async fn upload_part_copy_from_a_read_denied_bucket_is_refused() {
    // The same exfiltration, one API away: UploadPartCopy carries the identical
    // `x-amz-copy-source` header and is trivially the workaround if only CopyObject is
    // covered. It goes through the same `enforce_copy`, and this test is what keeps
    // that true.
    let fx = common::fixture("sec-upc", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request_as(
        "writer",
        "UploadPartCopy",
        upload_part_copy_input(),
        Method::PUT,
    );
    assert!(access.upload_part_copy(&mut req).await.is_err());
    assert!(req.extensions.get::<AuthzProof>().is_none());

    let mut req = fx.request_as(
        "copyist",
        "UploadPartCopy",
        upload_part_copy_input(),
        Method::PUT,
    );
    access
        .upload_part_copy(&mut req)
        .await
        .expect("the legitimate multipart copy must still work");
}

// ── coarse verbs must not over-grant ────────────────────────────────────────────

#[tokio::test]
async fn a_write_grant_does_not_confer_delete() {
    // Pre-fix, the projection collapsed verbs and `write` conferred `delete`. A write
    // grant is "you may add objects here"; deletion is destruction of someone else's
    // data and needs its own grant.
    let fx = common::fixture("sec-write-delete", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request_as(
        "writer",
        "PutObject",
        PutObjectInput {
            bucket: "staging".into(),
            key: "report.csv".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    access
        .put_object(&mut req)
        .await
        .expect("the write grant must actually allow a write");

    let mut req = fx.request_as(
        "writer",
        "DeleteObject",
        DeleteObjectInput {
            bucket: "staging".into(),
            key: "report.csv".into(),
            ..Default::default()
        },
        Method::DELETE,
    );
    assert!(
        access.delete_object(&mut req).await.is_err(),
        "write_objects must not confer delete_objects"
    );
}

#[tokio::test]
async fn a_list_grant_does_not_confer_read() {
    // The other half of the same lesson: `list` conferred `read`, so a principal
    // allowed to see key *names* could fetch their contents.
    let fx = common::fixture("sec-list-read", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request_as(
        "lister",
        "ListObjectsV2",
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: Some("2024/".into()),
            ..Default::default()
        },
        Method::GET,
    );
    access
        .list_objects_v2(&mut req)
        .await
        .expect("the list grant must actually allow a list");

    let mut req = fx.request_as(
        "lister",
        "GetObject",
        GetObjectInput {
            bucket: "reports".into(),
            // A key the list above would have returned.
            key: "2024/q1.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    assert!(
        access.get_object(&mut req).await.is_err(),
        "list_objects must not confer read_objects on the keys it enumerates"
    );
}

#[tokio::test]
async fn a_read_grant_does_not_confer_write() {
    let fx = common::fixture("sec-read-write", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request_as(
        "reader",
        "GetObject",
        GetObjectInput {
            bucket: "staging".into(),
            key: "report.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    access.get_object(&mut req).await.expect("read is granted");

    let mut req = fx.request_as(
        "reader",
        "PutObject",
        PutObjectInput {
            bucket: "staging".into(),
            key: "report.csv".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    assert!(access.put_object(&mut req).await.is_err());
}

// ── listing must never be unbounded ─────────────────────────────────────────────

#[tokio::test]
async fn an_unbounded_list_is_never_forwarded_unbounded() {
    // Lesson 4: a client-supplied list prefix is only safe fail-closed. A prefix-scoped
    // subject asking for the whole bucket must not get the whole bucket — the request
    // that reaches the backend has to be inside the grant.
    //
    // NOTE: the master plan phrases this as "unbounded list denied". The shipped design
    // *narrows* instead, which is strictly better for clients and equally safe as long
    // as the narrowing really happens; the property that matters — and that is asserted
    // here — is that nothing unbounded is forwarded. A subject with no list grant at all
    // is still denied outright (below).
    let fx = common::fixture("sec-unbounded-list", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request_as(
        "lister",
        "ListObjectsV2",
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: None,
            ..Default::default()
        },
        Method::GET,
    );
    access.list_objects_v2(&mut req).await.expect("narrowed");
    assert_eq!(
        req.input.prefix.as_deref(),
        Some("2024/"),
        "an unbounded list by a prefix-scoped subject must be rewritten into the grant"
    );

    // Sibling ops with no fan-out dispatch must reach the same conclusion, or the
    // narrowing is one API call away from being bypassed.
    let mut req = fx.request_as(
        "lister",
        "ListObjects",
        ListObjectsInput {
            bucket: "reports".into(),
            prefix: None,
            ..Default::default()
        },
        Method::GET,
    );
    access.list_objects(&mut req).await.expect("narrowed");
    assert_eq!(req.input.prefix.as_deref(), Some("2024/"));

    // A prefix *outside* the grant is not silently widened into it either.
    let mut req = fx.request_as(
        "lister",
        "ListObjectsV2",
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: Some("2023/".into()),
            ..Default::default()
        },
        Method::GET,
    );
    assert!(
        access.list_objects_v2(&mut req).await.is_err(),
        "a list outside every granted prefix must be denied, not narrowed"
    );
}

#[tokio::test]
async fn a_subject_with_no_list_grant_cannot_enumerate_a_bucket_it_can_write() {
    // The unbounded-list denial proper: `writer` may put objects into `staging` but
    // holds no list verb, so enumerating it is refused rather than narrowed to "".
    let fx = common::fixture("sec-no-list", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request_as(
        "writer",
        "ListObjectsV2",
        ListObjectsV2Input {
            bucket: "staging".into(),
            prefix: None,
            ..Default::default()
        },
        Method::GET,
    );
    assert!(access.list_objects_v2(&mut req).await.is_err());
    assert!(req.extensions.get::<AuthzProof>().is_none());
    assert_eq!(
        req.input.prefix, None,
        "a denied list must not leave a rewritten prefix behind"
    );
}

// ── multi-delete ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn multi_delete_strips_denied_keys_rather_than_allowing_the_batch() {
    // Blind spot #2: the keys live in the XML body, so a single decision on the bucket
    // would authorize every key in the batch. Each key is its own decision and the
    // forwarded request carries only the allowed ones.
    let fx = common::fixture("sec-multidelete", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request(
        "DeleteObjects",
        DeleteObjectsInput {
            bucket: "reports".into(),
            bypass_governance_retention: None,
            checksum_algorithm: None,
            delete: Delete {
                objects: vec![
                    oid("2024/a.csv"),
                    oid("2023/b.csv"),
                    oid("2024/c.csv"),
                    oid("other/d.csv"),
                ],
                ..Default::default()
            },
            expected_bucket_owner: None,
            mfa: None,
            request_payer: None,
        },
        Method::POST,
    );
    access
        .delete_objects(&mut req)
        .await
        .expect("a batch with at least one allowed key proceeds");
    let kept: Vec<&str> = req
        .input
        .delete
        .objects
        .iter()
        .map(|o| o.key.as_str())
        .collect();
    assert_eq!(
        kept,
        vec!["2024/a.csv", "2024/c.csv"],
        "only keys inside the grant may reach the backend"
    );
}

#[tokio::test]
async fn multi_delete_with_no_allowed_key_is_refused_outright() {
    // The boundary case the stripping creates: if every key is denied, forwarding an
    // empty batch would return a cheerful 200 for a request that deleted nothing and
    // was entirely unauthorized.
    let fx = common::fixture("sec-multidelete-none", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request(
        "DeleteObjects",
        DeleteObjectsInput {
            bucket: "reports".into(),
            bypass_governance_retention: None,
            checksum_algorithm: None,
            delete: Delete {
                objects: vec![oid("2023/a.csv"), oid("2022/b.csv")],
                ..Default::default()
            },
            expected_bucket_owner: None,
            mfa: None,
            request_payer: None,
        },
        Method::POST,
    );
    assert!(access.delete_objects(&mut req).await.is_err());
    assert!(req.extensions.get::<AuthzProof>().is_none());
}

#[tokio::test]
async fn every_multi_delete_key_is_its_own_pdp_question() {
    // The mechanism behind the test above, asserted directly: the capture tap sees one
    // emitted input per key, each naming that key. A single bucket-level decision would
    // show up here as one capture with no `object`, and the stripping test alone could
    // not tell the two apart.
    let fx = common::fixture("sec-multidelete-capture", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request(
        "DeleteObjects",
        DeleteObjectsInput {
            bucket: "reports".into(),
            bypass_governance_retention: None,
            checksum_algorithm: None,
            delete: Delete {
                objects: vec![oid("2024/a.csv"), oid("2023/b.csv"), oid("2024/c.csv")],
                ..Default::default()
            },
            expected_bucket_owner: None,
            mfa: None,
            request_payer: None,
        },
        Method::POST,
    );
    let _ = access.delete_objects(&mut req).await;

    let objects: Vec<String> = fx
        .capture
        .snapshot()
        .iter()
        .filter_map(|c| c.raw["object"].as_str().map(str::to_string))
        .collect();
    assert_eq!(
        objects,
        vec!["2024/a.csv", "2023/b.csv", "2024/c.csv"],
        "each key must be decided on its own"
    );
}

// ── the copy is two questions, not one ──────────────────────────────────────────

#[tokio::test]
async fn a_copy_emits_a_source_read_and_a_destination_write() {
    // The structural claim the exfiltration test rests on, checked at the wire: a copy
    // asks two questions, the first a `read_objects` on the *source* bucket. If the
    // source half ever stopped being emitted, the exfiltration test would still pass
    // for a while (the destination write is denied for `writer` too, on other buckets)
    // — this is what makes that impossible.
    let fx = common::fixture("sec-copy-shape", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request_as("copyist", "CopyObject", copy_object_input(), Method::PUT);
    access.copy_object(&mut req).await.expect("allowed");

    let captured = fx.capture.snapshot();
    let src = captured
        .iter()
        .find(|c| c.raw["action"] == "read_objects")
        .expect("a copy must emit a source read");
    assert_eq!(src.raw["bucket"], "secrets");
    assert_eq!(src.raw["object"], "payroll/2026.csv");

    let dst = captured
        .iter()
        .find(|c| c.raw["action"] == "write_objects")
        .expect("a copy must emit a destination write");
    assert_eq!(dst.raw["bucket"], "staging");
    assert_eq!(dst.raw["object"], "exfil.csv");
    assert_eq!(dst.raw["copy_source"]["bucket"], "secrets");
}

// ── org-global kill switch ──────────────────────────────────────────────────────

#[tokio::test]
async fn freeze_writes_stops_writes_and_deletes_but_not_reads() {
    // `freeze_writes` is the only control the live production bundle actually carries,
    // and M5 trades RGW's own enforcement of it for this one. It had better work.
    let mut frozen = bundle();
    frozen["org_settings"]["freeze_writes"] = serde_json::json!(true);
    let fx = common::fixture("sec-freeze", frozen);
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request_as(
        "writer",
        "PutObject",
        PutObjectInput {
            bucket: "staging".into(),
            key: "report.csv".into(),
            ..Default::default()
        },
        Method::PUT,
    );
    assert!(access.put_object(&mut req).await.is_err());

    let mut req = fx.request_as(
        "reader",
        "GetObject",
        GetObjectInput {
            bucket: "staging".into(),
            key: "report.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    access
        .get_object(&mut req)
        .await
        .expect("freeze_writes must not stop reads");
}

// ── attribution ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_denied_request_is_attributed_to_the_right_tenant_and_org() {
    // A decision the audit trail cannot attribute is not evidence. Every emitted input
    // — including the denied ones — carries the tenant and org from the route snapshot
    // `check` resolved, never a default.
    let fx = common::fixture("sec-attribution", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request_as("writer", "CopyObject", copy_object_input(), Method::PUT);
    let _ = access.copy_object(&mut req).await;

    let captured = fx.capture.snapshot();
    assert!(!captured.is_empty());
    for c in &captured {
        assert_eq!(c.raw["tenant"], "acme", "{:?}", c.raw);
        assert_eq!(c.raw["organization_id"], "org-acme", "{:?}", c.raw);
        assert_eq!(c.raw["backend"]["id"], "bay-1", "{:?}", c.raw);
        assert_eq!(c.raw["principal"]["sub"], "writer", "{:?}", c.raw);
    }
    // Keep the fixture (and its audit worker) alive to the end of the test.
    drop(Arc::clone(&fx.gw));
}

// ── obligations must be understood, not dropped ─────────────────────────────────

#[tokio::test]
async fn an_obligation_this_binary_does_not_implement_denies_rather_than_being_ignored() {
    // The fail-open twin of the 35-green-tests bug. The policy module is hot-swapped
    // from the control-plane bundle (`RegorusPdp::reload`), so a newer control plane can
    // emit an obligation this binary predates — `excluded_prefixes`, say, which
    // *narrows* a listing. Without `deny_unknown_fields` on `Obligations` the field is
    // dropped, the decision deserializes to `allow: true` with `Obligations::default()`,
    // `classify_list` returns `AllowAsIs`, and the listing the obligation existed to
    // bound is forwarded unbounded. The restriction becomes an unrestriction.
    //
    // The required behaviour is a refusal: an obligation we cannot honor is a denial.
    //
    // Each phase below lists a *different* prefix on purpose. The decision cache is
    // keyed by bundle revision and the revision does not move across a `reload` here,
    // so reusing one prefix would answer phases 2 and 3 out of phase 1's cache entry
    // and the test would prove nothing about the pushed policy.
    let fx = common::fixture("sec-unknown-obligation", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let list = |prefix: &str| ListObjectsV2Input {
        bucket: "reports".into(),
        prefix: Some(prefix.into()),
        ..Default::default()
    };

    // Positive control, against the shipped policy: this shape of request is allowed
    // today, so the denial below cannot be a deny-all artifact.
    let mut req = fx.request_as(
        "lister",
        "ListObjectsV2",
        list("2024/control/"),
        Method::GET,
    );
    access
        .list_objects_v2(&mut req)
        .await
        .expect("the shipped policy allows a listing inside the grant");

    // A control plane now pushes a policy carrying an obligation from the future. The
    // module compiles and the verdict is `allow`; the only thing this binary cannot do
    // is honor the obligation.
    const FUTURE_OBLIGATION: &str = concat!(
        "package s0.gateway\n\n",
        "decision := {\"allow\": true, \"reason\": \"allowed, minus a deny-grant\", ",
        "\"obligations\": {\"excluded_prefixes\": [\"2024/payroll/\"]}}\n"
    );
    fx.gw
        .pdp
        .reload(Some(FUTURE_OBLIGATION), &bundle())
        .await
        .expect("the pushed module itself is valid rego");

    let mut req = fx.request_as("lister", "ListObjectsV2", list("2024/future/"), Method::GET);
    let err = access.list_objects_v2(&mut req).await.expect_err(
        "an obligation this binary cannot honor must deny; forwarding as though the \
         obligation were absent turns a restriction into an unrestriction",
    );
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied, "{err:?}");
    assert_eq!(
        req.input.prefix.as_deref(),
        Some("2024/future/"),
        "nothing was rewritten and nothing was forwarded"
    );

    // Same push, minus the unknown key: the refusal is about the obligation, not about
    // pushing a module at all.
    const KNOWN_OBLIGATION: &str = concat!(
        "package s0.gateway\n\n",
        "decision := {\"allow\": true, \"reason\": \"allowed\", ",
        "\"obligations\": {\"narrow_prefix\": \"2024/\"}}\n"
    );
    fx.gw
        .pdp
        .reload(Some(KNOWN_OBLIGATION), &bundle())
        .await
        .expect("reload");
    let mut req = fx.request_as("lister", "ListObjectsV2", list("2024/known/"), Method::GET);
    access
        .list_objects_v2(&mut req)
        .await
        .expect("an obligation this binary does implement is honored, not refused");
    assert_eq!(req.input.prefix.as_deref(), Some("2024/"));

    drop(Arc::clone(&fx.gw));
}

// ── the audit record must agree with what the client was told ───────────────────

#[tokio::test]
async fn a_list_the_gateway_refuses_is_audited_as_denied_not_allowed() {
    // Defect 4. `enforce_list` audited `Outcome::Allowed` and minted a proof for any
    // non-`Deny` verdict, and the *caller* then refused a fan-out it had no dispatch
    // for. Two refusal sites, both after the record was written: a `FanOut` on
    // `ListObjects`/`ListMultipartUploads`, and a `ListObjectsV2` carrying a delimiter.
    // The decision log said allowed; the client got a 403.
    //
    // For a regulated audit trail that is worse than no record at all: a missing record
    // is a gap you can see, a wrong one is evidence that exonerates the wrong thing.
    let fx = common::fixture("sec-audit-refused-list", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    // ── site 1: a v1 list, which has no fan-out dispatch at all.
    {
        let mut req = fx.request_as(
            "spanner",
            "ListObjects",
            ListObjectsInput {
                bucket: "reports".into(),
                prefix: None,
                ..Default::default()
            },
            Method::GET,
        );
        let err = access
            .list_objects(&mut req)
            .await
            .expect_err("a multi-prefix grant cannot be served by the v1 list");
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied, "{err:?}");
        assert!(
            req.extensions.get::<AuthzProof>().is_none(),
            "a request that is about to be refused must mint no authorization proof"
        );
    }

    // ── site 2: a v2 list carrying a delimiter, which the fan-out cannot express.
    {
        let mut req = fx.request_as(
            "spanner",
            "ListObjectsV2",
            ListObjectsV2Input {
                bucket: "reports".into(),
                prefix: None,
                delimiter: Some("/".into()),
                ..Default::default()
            },
            Method::GET,
        );
        let err = access
            .list_objects_v2(&mut req)
            .await
            .expect_err("delimiter listing across granted prefixes is unsupported");
        assert_eq!(*err.code(), S3ErrorCode::AccessDenied, "{err:?}");
        assert!(req.extensions.get::<AuthzProof>().is_none());
    }

    let records = fx.await_audit_records(2).await;
    assert_eq!(
        records.len(),
        2,
        "one record per refused request, no more and no fewer"
    );
    for rec in &records {
        assert!(
            matches!(rec.gateway.outcome, Outcome::Denied),
            "the client got a 403; the record must say denied, got {:?} — reason {:?}",
            rec.gateway.outcome,
            rec.result.reason
        );
        assert!(
            !rec.result.allow,
            "and the verdict it carries must be a deny: {:?}",
            rec.result
        );
        // The reason on the record is the reason the client was given — one string, so
        // an operator reading the log sees the message the client saw.
        assert!(
            rec.result.reason.contains("list a single prefix"),
            "the record must carry the refusal the client got, not the PDP's allow: {:?}",
            rec.result.reason
        );
    }

    // Positive control: the identical grant on the one operation that *can* fan out is
    // allowed, and audited as allowed. Without this, a gateway that denied every list
    // would pass everything above.
    let mut req = fx.request_as(
        "spanner",
        "ListObjectsV2",
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: None,
            ..Default::default()
        },
        Method::GET,
    );
    access
        .list_objects_v2(&mut req)
        .await
        .expect("a multi-prefix listing on the op with fan-out dispatch is allowed");
    assert!(req.extensions.get::<AuthzProof>().is_some());
    // Dropping the request releases the pending record, which is emitted (unenriched)
    // because nothing forwarded it.
    drop(req);

    let records = fx.await_audit_records(3).await;
    assert_eq!(records.len(), 3);
    assert!(
        matches!(records[2].gateway.outcome, Outcome::Allowed),
        "{:?}",
        records[2].gateway.outcome
    );
}

// ── the deny-by-default surface must leave evidence ─────────────────────────────

#[tokio::test]
async fn a_gate_denial_emits_exactly_one_audit_record() {
    // Defect 5. Anonymous requests, all 84 gate-denied operations, rejected credentials
    // and unroutable tenants produced a `tracing::warn!` and nothing else — so the
    // decision log held zero evidence of the entire deny-by-default surface and zero
    // evidence of credential-forgery attempts. "Was this gateway probed?" was
    // unanswerable from the audit trail, which is the artifact the question is supposed
    // to be answered from.
    //
    // This has to run over real HTTP: `S3AccessContext` has crate-private fields, so
    // `check` is not callable in-process.
    let (base, fx) = spawn_gateway("sec-gate-audit", bundle()).await;
    let host = base.trim_start_matches("http://").to_string();

    // A denied operation, signed with a credential the gateway really knows — so the
    // 403 is the gate's, not a signature failure's.
    let status = send_signed(
        &base,
        &host,
        "DELETE",
        "/reports",
        &[],
        Some((common::ACCESS_KEY, common::SECRET_KEY)),
    )
    .await;
    assert_eq!(status, 403, "DeleteBucket is not enforced by this build");

    let records = fx.await_audit_records(1).await;
    assert_eq!(
        records.len(),
        1,
        "exactly one record per gate denial: {records:#?}"
    );
    let rec = &records[0];
    let gate = rec
        .gate
        .as_ref()
        .expect("a gate denial must carry the gate context, not a fabricated OpaInput");
    assert_eq!(gate.stage, GateStage::OperationNotEnforced);
    assert_eq!(gate.operation, "DeleteBucket");
    assert_eq!(
        gate.access_key_id.as_deref(),
        Some(common::ACCESS_KEY),
        "the access-key id is the only identifier available here, and it is what makes \
         a probe attributable"
    );
    assert!(
        matches!(rec.gateway.outcome, Outcome::Denied) && !rec.result.allow,
        "{rec:#?}"
    );
    assert!(
        rec.input.is_none(),
        "no policy question was asked, so the record must not invent one: {rec:#?}"
    );

    // An unsigned request: the same surface, minus any identity at all. The record must
    // still exist — an anonymous probe is exactly the thing you want on the record —
    // and must claim no access key rather than an empty one.
    let status = send_signed(&base, &host, "GET", "/reports/2024/q1.csv", &[], None).await;
    assert_eq!(status, 403);

    let records = fx.await_audit_records(2).await;
    assert_eq!(records.len(), 2, "{records:#?}");
    let gate = records[1].gate.as_ref().expect("gate context");
    assert_eq!(gate.stage, GateStage::Anonymous);
    assert_eq!(gate.access_key_id, None);
    assert_eq!(records[1].requested_by, "");

    // A session credential presented **without** its session token: the shape of a
    // stripped or replayed STS session. It gets past s3s's signature check (an STS
    // secret is derived, not stored, so the signature verifies) and is refused by
    // identity resolution — which is the only stage that can distinguish it. An access
    // key s3s has never heard of cannot reach `check` at all: s3s asks for its secret
    // first and 403s on the signature, so this is the reachable identity-rejection.
    let sts = s0::auth::sts::StsAuthority::new(vec![0u8; 32], vec![1u8; 32]).expect("sts");
    let forged_key = sts.access_key_id("no-such-session");
    let derived_secret = sts
        .derive_secret(sts.current_kid(), "no-such-session")
        .expect("the current kid is in the ring");
    let status = send_signed(
        &base,
        &host,
        "GET",
        "/reports/2024/q1.csv",
        &[],
        Some((&forged_key, &derived_secret)),
    )
    .await;
    assert_eq!(status, 403);

    let records = fx.await_audit_records(3).await;
    assert_eq!(records.len(), 3, "{records:#?}");
    let gate = records[2].gate.as_ref().expect("gate context");
    assert_eq!(gate.stage, GateStage::IdentityRejected);
    assert_eq!(gate.access_key_id.as_deref(), Some(forged_key.as_str()));

    // Positive control: an *enforced* operation by a known principal still produces the
    // ordinary decision record, with a real input — so the three above are gate records
    // because the gate refused them, not because every record lost its input.
    let status = send_signed(
        &base,
        &host,
        "GET",
        "/staging/report.csv",
        &[],
        Some((common::ACCESS_KEY, common::SECRET_KEY)),
    )
    .await;
    assert_ne!(status, 403, "GetObject is enforced and alice may read it");
    let records = fx.await_audit_records(4).await;
    assert_eq!(records.len(), 4, "{records:#?}");
    let decision = records.last().expect("the decision record");
    assert!(decision.gate.is_none());
    let input = decision.input.as_ref().expect("a real policy question");
    assert_eq!(input.bucket, "staging");
    assert_eq!(input.principal.sub, "alice");

    // …and, since the fixture points at a closed port, the forward failed. That is the
    // post-forward enrichment (plan task 18): the record is written after the backend
    // leg, so `outcome: error` has a producer for the first time. The policy verdict is
    // still readable and still an allow — the request was authorized and then broke.
    assert!(
        matches!(decision.gateway.outcome, Outcome::Error),
        "{decision:#?}"
    );
    assert!(
        decision.result.allow,
        "the policy did allow it: {decision:#?}"
    );
    assert_eq!(decision.gateway.backend, BackendOutcome::Failed);
    assert_eq!(
        decision.gateway.backend_status, None,
        "a connection that never reached a backend has no backend status; \
         `S3Error::status_code()` would have volunteered a synthesized 500"
    );
}

#[tokio::test]
async fn an_unauthenticated_scanner_cannot_flood_the_audit_sink() {
    // The cardinality half of defect 5, and the reason gate records are rate-limited
    // rather than emitted one-for-one. An unsigned request costs the attacker nothing
    // and would otherwise cost the gateway one audit record each: at line rate that
    // fills the bounded queue and starts dropping the *decision* records of real
    // access. An attacker able to suppress the audit trail of genuine access is a worse
    // outcome than an attacker being under-logged, so the gate stream is budgeted.
    //
    // What must NOT happen is silent sampling: the count is preserved in
    // `s0_audit_gate_suppressed_total` and handed to the next record that is emitted.
    let (base, fx) = spawn_gateway("sec-gate-flood", bundle()).await;
    let host = base.trim_start_matches("http://").to_string();

    // Well past the burst, sequentially — the budget only refills with wall time.
    for _ in 0..200 {
        let status = send_signed(&base, &host, "GET", "/reports/2024/q1.csv", &[], None).await;
        assert_eq!(status, 403, "every one of these is still refused");
    }

    // Shipping is asynchronous, so converge on "every probe accounted for" rather than
    // sampling once and racing the worker.
    let suppressed = fx
        .gw
        .audit
        .metrics()
        .gate_suppressed
        .load(Ordering::Relaxed);
    let mut records = fx.audit_log.all();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while (records.len() as u64) + suppressed < 200 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
        records = fx.audit_log.all();
    }
    assert!(
        !records.is_empty(),
        "the budget must not silence the stream entirely"
    );
    assert!(
        records.len() < 200,
        "200 unauthenticated probes must not become 200 audit records: got {}",
        records.len()
    );
    assert_eq!(
        records.len() as u64 + suppressed,
        200,
        "every probe is either recorded or counted — none may simply vanish"
    );
    assert!(
        records
            .iter()
            .any(|r| r.gate.as_ref().is_some_and(|g| g.suppressed_since_last > 0)),
        "a record emitted after suppression must carry how many it stands in for, so a \
         reader of the trail sees the flood without joining against a metric"
    );

    // Suppression is deliberate policy, not loss: it must not inflate the counter that
    // means "this process lost audit records", or that counter stops being alertable.
    assert_eq!(
        fx.gw.audit.dropped_total(),
        0,
        "a rate-limited gate stream is not audit loss and must not be reported as such"
    );
}
