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
                "wholelister": { "groups": [], "attributes": [] },
                "spanner": { "groups": [], "attributes": [] },
                "copyist": { "groups": [], "attributes": [] }
            },
            "bucket_attributes": {},
            "s3_grants": {
                "writer":  [ { "bucket": "staging", "actions": ["write_objects"], "prefixes": [] } ],
                "reader":  [ { "bucket": "staging", "actions": ["read_objects"], "prefixes": [] } ],
                "alice":   [ { "bucket": "staging", "actions": ["read_objects"], "prefixes": [] } ],
                "lister":  [ { "bucket": "reports", "actions": ["list_objects"], "prefixes": ["2024/"] } ],
                // The positive control for the unbounded-list deny: same verb, same
                // bucket, WHOLE-bucket scope. Without it, a rego change that denied
                // every list would look like a pass.
                "wholelister": [ { "bucket": "reports", "actions": ["list_objects"], "prefixes": [] } ],
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
async fn an_unbounded_list_is_denied_not_silently_narrowed() {
    // Lesson 4: a client-supplied list prefix is only safe fail-closed. A prefix-scoped
    // subject asking for the whole bucket must not get the whole bucket.
    //
    // CHANGED 2026-08-09, and the old comment on this test is the reason it is worth
    // spelling out. It used to read: "the master plan phrases this as *unbounded list
    // denied*; the shipped design *narrows* instead, which is strictly better for
    // clients and equally safe as long as the narrowing really happens." Both halves
    // of that were wrong.
    //
    //   1. It is not AWS behaviour. AWS grants prefix-scoped listing as a BUCKET
    //      resource plus a `s3:prefix` condition, and a `ListObjectsV2` with no prefix
    //      fails that condition — `AccessDenied`. AWS does not narrow. Hyperfluid's
    //      goal is parity with the ecosystem, and a deviation has to be deliberate and
    //      documented; this one was neither.
    //   2. It is not "equally safe". Narrowing leaks nothing, but it returns a
    //      FILTERED listing with no signal that it was filtered. A user running
    //      `aws s3 ls s3://reports/` sees `2024/` and concludes that is all the bucket
    //      holds. In a regulated product, presenting a partial view as a complete one
    //      is worse than an error: the error gets a support ticket, the short listing
    //      gets believed.
    //
    // This CLOSES a divergence rather than opening one — hyperfluid's pushed `s3.rego`
    // and the console's object routes (`01d7f7f`) already denied here; this
    // compiled-in default was the last PEP still narrowing.
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
    let err = access
        .list_objects_v2(&mut req)
        .await
        .expect_err("an unbounded list by a prefix-scoped subject must be DENIED");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("unbounded list"),
        "the denial must say what to do about it — a caller told only \"no grant \
         matches\" goes hunting for a permission when the fix is a prefix. got: {msg}"
    );
    assert!(
        req.input.prefix.is_none(),
        "a denied list must not have been rewritten on the way out"
    );

    // The same request in its other spelling. A client that sends `prefix=` explicitly
    // is asking the identical question and must get the identical answer, or the deny
    // is one query-string away from being bypassed.
    let mut req = fx.request_as(
        "lister",
        "ListObjectsV2",
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: Some(String::new()),
            ..Default::default()
        },
        Method::GET,
    );
    assert!(
        access.list_objects_v2(&mut req).await.is_err(),
        "an explicit empty prefix is an unbounded list and must be denied too"
    );

    // Sibling ops with no fan-out dispatch must reach the same conclusion, or the rule
    // is one API call away from being bypassed.
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
    assert!(
        access.list_objects(&mut req).await.is_err(),
        "the V1 listing op must deny the unbounded request exactly as V2 does"
    );

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

    // NARROWING IS NOT WHAT WAS REMOVED. A request WIDER than the grant but overlapping
    // it is still allowed and still rewritten into the grant: the caller named a scope
    // and gets a genuine subset of the scope it named, so nothing is being passed off
    // as complete. Only the case where the caller named NO scope became a deny.
    let mut req = fx.request_as(
        "lister",
        "ListObjectsV2",
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: Some("20".into()),
            ..Default::default()
        },
        Method::GET,
    );
    access
        .list_objects_v2(&mut req)
        .await
        .expect("an over-broad but overlapping list is narrowed, not denied");
    assert_eq!(
        req.input.prefix.as_deref(),
        Some("2024/"),
        "the request that reaches the backend has to be inside the grant"
    );

    // THE POSITIVE CONTROL. Same op, same bucket, same unbounded request — but a
    // WHOLE-BUCKET grant. It must still be allowed and still be forwarded unbounded,
    // or this test is passing because listing broke rather than because the unbounded
    // case is refused.
    let mut req = fx.request_as(
        "wholelister",
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
        .expect("a whole-bucket grant still authorizes an unbounded list");
    assert!(
        req.input.prefix.is_none(),
        "a whole-bucket lister must not be narrowed into anything"
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
        "package s3.authz\n\n",
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
        "package s3.authz\n\n",
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

#[tokio::test]
async fn a_policy_that_allows_a_bucket_listing_without_saying_which_buckets_shows_none() {
    // The `visible_buckets` twin of the test above, and the reason its empty case is the
    // OPPOSITE of `allowed_prefixes`'. A policy author who allows `list_buckets` and
    // forgets the obligation has, in every other obligation's convention, said
    // "unrestricted". Here that would publish the tenant's entire bucket namespace —
    // because the forward is re-signed with the owner credential and the backend answers
    // with all of it. So the absent obligation must mean *nothing*, and this is what
    // holds it there.
    let fx = common::fixture("sec-listbuckets-default", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    const ALLOW_WITH_NO_OBLIGATION: &str = concat!(
        "package s3.authz\n\n",
        "decision := {\"allow\": true, \"reason\": \"allowed, and silent about buckets\", ",
        "\"obligations\": {}}\n"
    );
    fx.gw
        .pdp
        .reload(Some(ALLOW_WITH_NO_OBLIGATION), &bundle())
        .await
        .expect("the pushed module is valid rego");

    let mut req = fx.request_as(
        "lister",
        "ListBuckets",
        ListBucketsInput::default(),
        Method::GET,
    );
    access
        .list_buckets(&mut req)
        .await
        .expect("an allowed enumeration is never an error");
    assert_eq!(
        s0::proxy::obligations::ResponseObligations::of(&req)
            .and_then(|o| o.visible_buckets.clone())
            .expect("a visibility obligation is always installed"),
        s0::proxy::obligations::BucketVisibility::Nothing,
        "an allow that names no visible buckets must show none — treating it as \
         'unrestricted' would hand the whole tenant namespace to anyone the policy \
         allowed to call ListBuckets at all"
    );

    // Positive control: the same push, with the obligation spelled out, does show them.
    // A DIFFERENT principal, on purpose: the decision cache is keyed by bundle revision
    // and the revision does not move across a `reload`, so re-asking as `lister` would be
    // answered out of the entry above and this control would prove nothing.
    const ALLOW_WITH_OBLIGATION: &str = concat!(
        "package s3.authz\n\n",
        "decision := {\"allow\": true, \"reason\": \"allowed\", ",
        "\"obligations\": {\"all_buckets_visible\": true}}\n"
    );
    fx.gw
        .pdp
        .reload(Some(ALLOW_WITH_OBLIGATION), &bundle())
        .await
        .expect("reload");
    let mut req = fx.request_as(
        "lister-control",
        "ListBuckets",
        ListBucketsInput::default(),
        Method::GET,
    );
    access.list_buckets(&mut req).await.expect("allowed");
    assert_eq!(
        s0::proxy::obligations::ResponseObligations::of(&req)
            .and_then(|o| o.visible_buckets.clone())
            .expect("obligation"),
        s0::proxy::obligations::BucketVisibility::All,
        "the unfiltered path must still be reachable when a rego author types it out"
    );
}

#[tokio::test]
async fn a_must_understand_obligation_this_gateway_cannot_apply_denies() {
    // `deny_unknown_fields` covers the case where the *field* is unknown. It cannot cover
    // the reverse skew: a policy that needs an obligation applied, pushed to a fleet where
    // some replicas are older. `must_understand` names what has to be honored, and a name
    // this binary does not implement is a denial — so a premature policy push is a loud,
    // uniform outage rather than a silent partial enforcement across the fleet.
    let fx = common::fixture("sec-must-understand", bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let get = || GetObjectInput {
        bucket: "reports".into(),
        key: "2024/q1.csv".into(),
        ..Default::default()
    };

    const DEMANDS_THE_FUTURE: &str = concat!(
        "package s3.authz\n\n",
        "decision := {\"allow\": true, \"reason\": \"allowed\", ",
        "\"obligations\": {\"must_understand\": [\"excluded_prefixes\"]}}\n"
    );
    fx.gw
        .pdp
        .reload(Some(DEMANDS_THE_FUTURE), &bundle())
        .await
        .expect("valid rego");
    let mut req = fx.request_as("reader", "GetObject", get(), Method::GET);
    let err = access.get_object(&mut req).await.expect_err(
        "an obligation the policy declared mandatory and this binary cannot apply must \
         deny, not be skipped",
    );
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
    assert!(
        format!("{err}").contains("excluded_prefixes"),
        "the refusal must name what is missing, or an operator cannot act on it: {err}"
    );
    assert!(req.extensions.get::<AuthzProof>().is_none());

    // Positive control: naming an obligation this binary *does* implement is not a
    // refusal, so the denial above is about capability rather than about the field.
    const DEMANDS_THE_PRESENT: &str = concat!(
        "package s3.authz\n\n",
        "decision := {\"allow\": true, \"reason\": \"allowed\", ",
        "\"obligations\": {\"must_understand\": [\"narrow_prefix\"]}}\n"
    );
    fx.gw
        .pdp
        .reload(Some(DEMANDS_THE_PRESENT), &bundle())
        .await
        .expect("valid rego");
    let mut req = fx.request_as("reader2", "GetObject", get(), Method::GET);
    access
        .get_object(&mut req)
        .await
        .expect("an implemented obligation named as mandatory is honored, not refused");
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
    //
    // Every request below asks for `20` — wider than both of `spanner`'s granted
    // prefixes and overlapping both, which is what produces the multi-prefix verdict.
    // They used to send no prefix at all; since 2026-08-09 an unbounded list is refused
    // one layer earlier (in the policy, for being unbounded — AWS parity), which would
    // make this test measure that deny instead of the fan-out refusal it is about.
    let fx = common::fixture("sec-audit-refused-list", bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    // ── site 1: a v1 list, which has no fan-out dispatch at all.
    {
        let mut req = fx.request_as(
            "spanner",
            "ListObjects",
            ListObjectsInput {
                bucket: "reports".into(),
                prefix: Some("20".into()),
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
                prefix: Some("20".into()),
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
            prefix: Some("20".into()),
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
    // Defect 5. Anonymous requests, all 76 gate-denied operations, rejected credentials
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
    // 403 is the gate's, not a signature failure's. `GetBucketAcl` has been outside the
    // enforced scope in every milestone: it was chosen over `DeleteBucket` when M4
    // enforced that one, and it outlived the 2026-08-08 re-scoping that denied
    // `DeleteBucket` again. A policy denial and a gate denial are both 403, and only the
    // record distinguishes them — which is exactly what is under test.
    let status = send_signed(
        &base,
        &host,
        "GET",
        "/reports",
        &[("acl", "")],
        Some((common::ACCESS_KEY, common::SECRET_KEY)),
    )
    .await;
    assert_eq!(status, 403, "GetBucketAcl is not enforced by this build");

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
    assert_eq!(gate.operation, "GetBucketAcl");
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

// ── M4 semantic caps and control-plane bodies ───────────────────────────────────
//
// Accepted review defect B-1: a cap implemented as `return Err(s3_error!(
// InvalidRequest, …))` short-circuits ahead of every audit site, so an over-cap request
// produces NO record at all and reaches the client as a 400 — a refusal on
// authorization grounds, reported as a client formatting mistake and invisible to the
// decision log. Every cap below is therefore a real Deny sub-decision on the op's own
// verb. Each test asserts both halves: the request is refused, AND the refusal is on
// the record as a decision (`gate: None`, a real `input`), not as a gate denial.

/// The record a locally-decided refusal must leave. Returns it so callers can assert on
/// the verb and the reason.
async fn sole_denial_record(fx: &common::Fixture) -> s0::audit::AuditRecord {
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
        "a cap is a policy-layer refusal on a real resource, not a pre-policy gate \
         denial: {rec:#?}"
    );
    assert!(
        rec.input.is_some(),
        "the record must name what was refused — bucket, key and verb: {rec:#?}"
    );
    assert!(
        rec.result.reason.starts_with("deny (gateway):"),
        "a refusal no policy was asked about must say so, or the trail reads as a policy \
         verdict on a question that was never put: {rec:#?}"
    );
    rec
}

#[tokio::test]
async fn an_over_cap_tag_set_is_denied_and_audited() {
    let fx = common::fixture("sec-tag-cap", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    // The default cap is AWS's own: 10 tags per object.
    let tag_set: Vec<Tag> = (0..11)
        .map(|i| Tag {
            key: Some(format!("k{i}")),
            value: Some("v".into()),
        })
        .collect();
    let mut req = fx.request(
        "PutObjectTagging",
        PutObjectTaggingInput {
            tagging: Tagging { tag_set },
            ..common::ops::put_object_tagging_input()
        },
        Method::PUT,
    );
    let err = access
        .put_object_tagging(&mut req)
        .await
        .expect_err("an over-cap tag set must be refused");
    assert_eq!(
        *err.code(),
        S3ErrorCode::AccessDenied,
        "a cap violation is a denial, not an InvalidRequest — the status class is what \
         an operator triages on"
    );
    assert!(
        req.extensions.get::<AuthzProof>().is_none(),
        "a capped request must mint no proof"
    );
    let rec = sole_denial_record(&fx).await;
    let input = rec.input.as_ref().unwrap();
    assert_eq!(input.action.as_str(), "write_object_tags");
    assert!(
        rec.result.reason.contains("over the 10-tag cap"),
        "{rec:#?}"
    );
}

#[tokio::test]
async fn a_tag_set_with_a_duplicate_key_is_refused() {
    // A TagSet is a list, so it can carry one key twice. Folding it into a map keeps
    // one of them and the backend keeps whichever *it* prefers — the policy would then
    // have authorized a tag set the object never receives. Same class as the parser
    // differentials the canonicalize-before-forward rule exists to prevent.
    let fx = common::fixture("sec-tag-dup", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectTagging",
        PutObjectTaggingInput {
            tagging: Tagging {
                tag_set: vec![
                    Tag {
                        key: Some("tier".into()),
                        value: Some("internal".into()),
                    },
                    Tag {
                        key: Some("tier".into()),
                        value: Some("public".into()),
                    },
                ],
            },
            ..common::ops::put_object_tagging_input()
        },
        Method::PUT,
    );
    assert!(access.put_object_tagging(&mut req).await.is_err());
    let rec = sole_denial_record(&fx).await;
    assert!(rec.result.reason.contains("twice"), "{rec:#?}");

    // Positive control: the same request with one tag is allowed and the tag set the
    // PDP saw is the one being installed.
    let fx = common::fixture("sec-tag-ok", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "PutObjectTagging",
        common::ops::put_object_tagging_input(),
        Method::PUT,
    );
    access.put_object_tagging(&mut req).await.expect("allowed");
    let captured = fx.capture.snapshot();
    assert_eq!(
        captured.last().expect("a capture").raw["requested_tags"]["tier"],
        serde_json::json!("internal"),
        "the tag set a write asks to install must reach the PDP, or a policy can never \
         refuse a self-elevating tag write"
    );
}

// ── the gateway is data-plane only (settled 2026-08-08) ─────────────────────────

/// The six operations M4 enforced and the 2026-08-08 settlement sent back to `Denied`,
/// each with the S3 request that reaches it, so the refusal is measured over the wire
/// rather than asserted against the table that decides it.
///
/// `(op, method, path, query)`. Query strings are what route a bucket sub-resource:
/// `PUT /reports?policy` is `PutBucketPolicy` and `PUT /reports` is `CreateBucket`.
type ReDeniedRequest = (
    &'static str,
    &'static str,
    &'static str,
    &'static [(&'static str, &'static str)],
);

const RE_DENIED_REQUESTS: [ReDeniedRequest; 6] = [
    ("CreateBucket", "PUT", "/brand-new", &[]),
    ("DeleteBucket", "DELETE", "/reports", &[]),
    ("GetBucketPolicy", "GET", "/reports", &[("policy", "")]),
    ("PutBucketPolicy", "PUT", "/reports", &[("policy", "")]),
    ("GetBucketCors", "GET", "/reports", &[("cors", "")]),
    ("PutBucketCors", "PUT", "/reports", &[("cors", "")]),
];

#[tokio::test]
async fn the_six_control_plane_ops_are_refused_at_the_gate_and_on_the_record() {
    // THE regression for the 2026-08-08 settlement, and it is deliberately a black-box
    // test: every one of these six had a working hook, a dispatch arm and a passing
    // authorization path in M4, so "we deleted the code" is only half the claim. The
    // other half is that a real, correctly-signed S3 request for each is refused by the
    // *gate* — before deserialization, with no policy question asked — and leaves a
    // record saying so.
    //
    // The `input.is_none()` assertion is the one that distinguishes this from a policy
    // denial. A gate denial must not fabricate an `OpaInput`, because a decision log
    // that shows a question nobody asked is worse than one that shows nothing.
    //
    // Why it matters that these are refused at the GATE rather than by a bundle: the
    // bundle is pushed by the control plane and can be wrong. `check` cannot.
    let (base, fx) = spawn_gateway("sec-data-plane-only", common::alice_bundle()).await;
    let host = base.trim_start_matches("http://").to_string();

    for (op, method, path, query) in RE_DENIED_REQUESTS {
        let status = send_signed(
            &base,
            &host,
            method,
            path,
            query,
            Some((common::ACCESS_KEY, common::SECRET_KEY)),
        )
        .await;
        assert_eq!(
            status, 403,
            "{op} reached the backend or answered something other than a refusal"
        );
    }

    let records = fx.await_audit_records(RE_DENIED_REQUESTS.len()).await;
    assert_eq!(records.len(), RE_DENIED_REQUESTS.len(), "{records:#?}");
    let mut seen: Vec<&str> = Vec::new();
    for rec in &records {
        let gate = rec
            .gate
            .as_ref()
            .unwrap_or_else(|| panic!("a gate denial must carry gate context: {rec:#?}"));
        assert_eq!(
            gate.stage,
            GateStage::OperationNotEnforced,
            "{} was refused at the wrong stage",
            gate.operation
        );
        assert!(
            rec.input.is_none(),
            "{} produced an OpaInput; no policy question is asked for an op the gate \
             refuses: {rec:#?}",
            gate.operation
        );
        assert!(matches!(rec.gateway.outcome, Outcome::Denied) && !rec.result.allow);
        seen.push(match gate.operation.as_str() {
            "CreateBucket" => "CreateBucket",
            "DeleteBucket" => "DeleteBucket",
            "GetBucketPolicy" => "GetBucketPolicy",
            "PutBucketPolicy" => "PutBucketPolicy",
            "GetBucketCors" => "GetBucketCors",
            "PutBucketCors" => "PutBucketCors",
            other => panic!("unexpected gate denial for {other}"),
        });
    }
    seen.sort_unstable();
    let mut expected: Vec<&str> = RE_DENIED_REQUESTS.iter().map(|(op, ..)| *op).collect();
    expected.sort_unstable();
    assert_eq!(
        seen, expected,
        "s3s routed these requests to operations other than the six under test — the \
         paths and query strings above no longer name what this test thinks they name"
    );
}

#[tokio::test]
async fn the_positive_control_the_six_refusals_need() {
    // Without this, `the_six_control_plane_ops_are_refused_at_the_gate_and_on_the_record`
    // is equally true of a gateway that refuses everything — the exact shape of the bug
    // this repository has already paid for once. `HeadBucket` is the right control: it
    // is a bucket-shaped request on the same bucket, signed with the same credential,
    // and it is enforced.
    let (base, fx) = spawn_gateway("sec-data-plane-control", common::alice_bundle()).await;
    let host = base.trim_start_matches("http://").to_string();
    let status = send_signed(
        &base,
        &host,
        "HEAD",
        "/reports",
        &[],
        Some((common::ACCESS_KEY, common::SECRET_KEY)),
    )
    .await;
    assert_ne!(
        status, 403,
        "HeadBucket is Enforced and alice holds `read` on reports; a 403 here means the \
         six refusals above prove nothing"
    );

    let records = fx.await_audit_records(1).await;
    let rec = &records[0];
    assert!(rec.gate.is_none(), "HeadBucket must not be gate-refused");
    let input = rec.input.as_ref().expect("an enforced op asks a question");
    assert_eq!(
        input.action.as_str(),
        "read",
        "HeadBucket decides against the existence verb, the same one ListBuckets uses"
    );
    assert!(rec.result.allow, "{rec:#?}");
}

#[tokio::test]
async fn the_existence_verb_answers_head_bucket_and_list_buckets_identically() {
    // The defect that started the 2026-08-08 change was two PEPs answering one question
    // differently. Its gateway-local form: a principal whose `aws s3 ls` came back empty
    // while its next `head-bucket` on a bucket in that list succeeded — or the reverse.
    // One verb, so one answer.
    let one_read_grant = serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": [], "attributes": [] } },
            "bucket_attributes": {},
            "s3_grants": { "alice": [
                { "bucket": "reports", "actions": ["read"], "prefixes": [] }
            ] },
            "group_grants": {}
        }}
    });
    let fx = common::fixture("sec-existence", one_read_grant);
    let access = GatewayAccess::new(fx.gw.clone());

    let mut head = fx.request(
        "HeadBucket",
        HeadBucketInput {
            bucket: "reports".into(),
            ..Default::default()
        },
        Method::HEAD,
    );
    access
        .head_bucket(&mut head)
        .await
        .expect("a `read` grant answers HeadBucket");

    let mut list = fx.request("ListBuckets", ListBucketsInput::default(), Method::GET);
    access
        .list_buckets(&mut list)
        .await
        .expect("…and the same grant answers ListBuckets");
    assert!(
        list.extensions.get::<AuthzProof>().is_some(),
        "the enumeration was allowed, so it must be proved — an empty listing produced \
         by a DENIAL mints no proof, and that is the case this test must not accept"
    );

    // The negative half, on the same bundle: `read` is not a fall-through to the object
    // verbs. Seeing that a bucket exists is not seeing what is inside it.
    let mut get = fx.request(
        "GetObject",
        GetObjectInput {
            bucket: "reports".into(),
            key: "2024/q1.csv".into(),
            ..Default::default()
        },
        Method::GET,
    );
    assert!(
        access.get_object(&mut get).await.is_err(),
        "`read` says the bucket exists; it must not confer read_objects"
    );

    // …and a HeadBucket on a bucket the grant does not name is still refused, so `read`
    // has not become a tenant-wide existence oracle.
    let mut other = fx.request(
        "HeadBucket",
        HeadBucketInput {
            bucket: "payroll".into(),
            ..Default::default()
        },
        Method::HEAD,
    );
    assert!(
        access.head_bucket(&mut other).await.is_err(),
        "a `read` grant on `reports` must not answer for `payroll`"
    );
}

#[tokio::test]
async fn a_bucket_shaped_read_carries_no_visible_buckets_obligation() {
    // The subtlest hazard the merge introduced, and the reason every rego rule reading
    // `read` carries a shape gate. `read` is in both `bucket_actions` and
    // `account_actions`; if the account-scope obligations rule loses its
    // `account_scoped` gate, a permitted HeadBucket comes back carrying an obligation
    // about a listing it is not.
    //
    // Which way that fails depends on the bundle, and both directions are bad:
    //
    //   * against the SHIPPED module, which emits no `must_understand`, `enforce_bucket`
    //     simply ignores the obligation — a restriction the policy declared and the PEP
    //     silently did not apply, the exact fail-open shape this project exists to avoid;
    //   * against a pushed module that DOES mark it `must_understand` (the recommended
    //     way to ship a visibility rule), `unimplemented_obligations` turns it into a
    //     hard deny and HeadBucket breaks for every principal in every organization.
    //
    // So the assertion is on the obligation itself rather than on allow/deny: it is the
    // only observation that catches both.
    let wildcard = serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": [], "attributes": [] } },
            "bucket_attributes": {},
            // A wildcard `read`, so `bucket_obligations` has something to emit and the
            // ungated rule really would fire.
            "s3_grants": { "alice": [
                { "bucket": "*", "actions": ["read"], "prefixes": [] },
                { "bucket": "reports", "actions": ["read"], "prefixes": [] }
            ] },
            "group_grants": {}
        }}
    });
    let fx = common::fixture("sec-headbucket-obligation", wildcard);
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request(
        "HeadBucket",
        HeadBucketInput {
            bucket: "reports".into(),
            ..Default::default()
        },
        Method::HEAD,
    );
    access
        .head_bucket(&mut req)
        .await
        .expect("a bucket-shaped `read` must not pick up the account scope's obligation");
    // The record of an ALLOWED request is held for the forward leg. Nothing forwards
    // here, so dropping the request is what settles it — `PendingAudit`'s `Drop` emits it
    // unenriched rather than losing it.
    drop(req);

    let records = fx.await_audit_records(1).await;
    let rec = &records[0];
    assert!(rec.result.allow, "{rec:#?}");
    assert_eq!(
        serde_json::to_value(&rec.result.obligations).expect("obligations serialize"),
        serde_json::json!({}),
        "a HeadBucket decision must carry no obligations at all: {rec:#?}"
    );
}

#[tokio::test]
async fn an_over_cap_multi_delete_is_denied_and_audited() {
    // The cap that predates defect B-1 and had the shape the defect describes: it
    // returned `InvalidRequest` ahead of `ReqCtx`, so an over-cap multi-delete left no
    // audit record at all and reached the client as a 400. It refuses like every other
    // cap now — one record, `Outcome::Denied`, no proof.
    let fx = common::fixture("sec-delete-cap", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let objects: Vec<ObjectIdentifier> = (0..1001).map(|i| oid(&format!("2024/{i}"))).collect();
    let mut req = fx.request(
        "DeleteObjects",
        DeleteObjectsInput {
            bucket: "reports".into(),
            delete: Delete {
                objects,
                ..Default::default()
            },
            ..common::ops::delete_objects_input()
        },
        Method::POST,
    );
    let err = access
        .delete_objects(&mut req)
        .await
        .expect_err("an over-cap multi-delete must be refused");
    assert_eq!(*err.code(), S3ErrorCode::AccessDenied);
    assert!(req.extensions.get::<AuthzProof>().is_none());
    let rec = sole_denial_record(&fx).await;
    assert!(
        rec.result.reason.contains("over the 1000-key cap"),
        "{rec:#?}"
    );
    assert!(
        rec.input.as_ref().unwrap().delete_keys.is_none(),
        "an audit record must not copy the unbounded list that was refused for being \
         unbounded: {rec:#?}"
    );
    assert_eq!(
        fx.pdp_calls(),
        0,
        "the cap must refuse before 1001 policy questions are asked"
    );
}

// ── the forward must send what the caller signed ────────────────────────────────

/// A `list`-shaped header arrives as ONE header with comma-separated values, and s3s
/// does not split it — so the forward re-encoded it as a single quoted element and the
/// backend answered `400 InvalidArgument`.
///
/// Found by driving `boto3` through the gateway at a real MinIO backend, not by a unit
/// test: `get_object_attributes(ObjectAttributes=["ETag"])` worked, `["ETag",
/// "ObjectSize"]` did not, and both worked when the same client talked to MinIO
/// directly. `s3s`'s `parse_list_header` (`http/de.rs:118-132`) iterates
/// `headers.get_all(name)` and never splits on the comma, so
/// `x-amz-object-attributes: ETag,ObjectSize` parses to the one-element list
/// `["ETag,ObjectSize"]`; the AWS SDK then quotes any element containing a comma, and
/// the backend receives `"ETag,ObjectSize"`.
///
/// This is not an authorization hole — the attribute list is not separately authorized,
/// which is a recorded blind spot on `GetObjectAttributes` — but a gateway that changes
/// a signed request's meaning is a gateway whose audit record describes something other
/// than what the backend was asked, and that is worth pinning.
#[tokio::test]
async fn a_comma_separated_list_header_survives_the_forward_intact() {
    let fx = common::fixture("comma-list", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request(
        "GetObjectAttributes",
        GetObjectAttributesInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            // What `parse_list_header` actually produces for
            // `x-amz-object-attributes: ETag,ObjectSize`.
            object_attributes: vec![ObjectAttributes::from("ETag,ObjectSize".to_string())],
            ..Default::default()
        },
        Method::GET,
    );
    access
        .get_object_attributes(&mut req)
        .await
        .expect("an ordinary attributes read is allowed");
    assert!(req.extensions.get::<AuthzProof>().is_some());
    let attrs: Vec<&str> = req
        .input
        .object_attributes
        .iter()
        .map(ObjectAttributes::as_str)
        .collect();
    assert_eq!(
        attrs,
        vec!["ETag", "ObjectSize"],
        "the comma list must be split before the forward re-encodes it, or the backend \
         receives a single quoted element and rejects the request"
    );

    // The positive control that keeps this from being satisfied by a hook that rewrites
    // everything: a single-attribute request is passed through untouched.
    let mut req = fx.request(
        "GetObjectAttributes",
        GetObjectAttributesInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            object_attributes: vec![ObjectAttributes::from_static(ObjectAttributes::ETAG)],
            ..Default::default()
        },
        Method::GET,
    );
    access
        .get_object_attributes(&mut req)
        .await
        .expect("allowed");
    let attrs: Vec<&str> = req
        .input
        .object_attributes
        .iter()
        .map(ObjectAttributes::as_str)
        .collect();
    assert_eq!(attrs, vec!["ETag"]);

    // And the same defect on the other list header this gateway forwards, so a fix that
    // only covered the op it was found on would fail here.
    let mut req = fx.request(
        "ListObjectsV2",
        ListObjectsV2Input {
            bucket: "reports".into(),
            prefix: Some("2024/".into()),
            optional_object_attributes: Some(vec![OptionalObjectAttributes::from(
                "RestoreStatus,RestoreStatus".to_string(),
            )]),
            ..Default::default()
        },
        Method::GET,
    );
    access.list_objects_v2(&mut req).await.expect("allowed");
    assert_eq!(
        req.input
            .optional_object_attributes
            .as_ref()
            .map(Vec::len)
            .unwrap_or_default(),
        2
    );
}
