//! Response obligations: what the gateway removes from an answer the backend produced.
//!
//! Every forward is re-signed with the per-`(backend, tenant)` **owner** credential, so
//! the backend lists the tenant's whole bucket namespace no matter who asked, and stamps
//! that shared identity on `Owner` / `Initiator`. The visibility obligation is the
//! authorization; the identity fields are stripped.
//!
//! These tests therefore run against a backend that answers: a raw HTTP responder speaking
//! real S3 XML through the real `aws-sdk-s3` client the proxy pool builds. It counts
//! requests, which lets the empty cases assert the backend was never contacted at all.

mod common;

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::Method;
use s0::access::GatewayAccess;
use s0::proxy::obligations::{BucketVisibility, ResponseObligations};
use s0::proxy::{GatewayS3, S3GatewayState};
use s3s::access::S3Access;
use s3s::dto::{ListBucketsInput, ListBucketsOutput, ListMultipartUploadsInput, ListPartsInput};
use s3s::{S3, S3Request};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── a backend that answers ──────────────────────────────────────────────────────

struct FakeBackend {
    url: String,
    requests: Arc<AtomicUsize>,
}

/// Serve `names` as a real `ListBuckets` response, `page` entries at a time.
///
/// The order of `names` is preserved exactly as given — deliberately unsorted, because
/// "the merged listing is gateway-ordered" can only be tested against a backend whose
/// order is something else. Paging is by integer offset in `continuation-token`.
async fn fake_backend(names: &[&str], page: usize) -> FakeBackend {
    let names: Vec<String> = names.iter().map(|s| (*s).to_string()).collect();
    spawn_fake(move |head| list_buckets_xml(&names, offset_in(head), page)).await
}

/// A backend answering every request with `body(request_head)`.
///
/// Raw HTTP rather than a mock S3 crate: the point is to exercise the *real* aws-sdk-s3
/// parse path the proxy pool uses.
async fn spawn_fake<F>(body: F) -> FakeBackend
where
    F: Fn(&str) -> String + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    let body = Arc::new(body);
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let counter = counter.clone();
            let body = body.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buf = [0u8; 2048];
                loop {
                    match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buf[..n]),
                    }
                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                counter.fetch_add(1, Ordering::Relaxed);
                let head = String::from_utf8_lossy(&head).to_string();
                let payload = body(&head);
                let resp = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/xml\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{payload}",
                    payload.len()
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    FakeBackend {
        url: format!("http://{addr}"),
        requests,
    }
}

/// The page offset the gateway asked for, carried in `continuation-token`.
fn offset_in(head: &str) -> usize {
    head.split("continuation-token=")
        .nth(1)
        .and_then(|s| s.split(['&', ' ']).next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

fn list_buckets_xml(names: &[String], start: usize, page: usize) -> String {
    let rows: String = names
        .iter()
        .skip(start)
        .take(page)
        .map(|n| format!("<Bucket><Name>{n}</Name><CreationDate>2024-01-01T00:00:00.000Z</CreationDate></Bucket>"))
        .collect();
    // The Owner the backend reports is the tenant-owner credential every request is
    // re-signed with — the same value for every principal, so the gateway must not
    // forward it.
    let next = start + page;
    let token = if next < names.len() {
        format!("<ContinuationToken>{next}</ContinuationToken>")
    } else {
        String::new()
    };
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Owner><ID>tenant-owner-canonical-id</ID><DisplayName>acme-owner</DisplayName></Owner>\
         <Buckets>{rows}</Buckets>{token}</ListAllMyBucketsResult>"
    )
}

// ── helpers ─────────────────────────────────────────────────────────────────────

fn gateway_s3(fx: &common::Fixture) -> GatewayS3 {
    GatewayS3::new(Arc::new(S3GatewayState::new(
        fx.gw.registry.clone(),
        fx.gw.limits.clone(),
    )))
}

/// Drive one `ListBuckets` all the way through: the real hook (which decides and installs
/// the visibility obligation) and then the real dispatch arm (which applies it).
async fn list_buckets(
    fx: &common::Fixture,
    sub: &str,
    input: ListBucketsInput,
) -> Result<ListBucketsOutput, s3s::S3Error> {
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req: S3Request<ListBucketsInput> =
        fx.request_as(sub, "ListBuckets", input, Method::GET);
    access
        .list_buckets(&mut req)
        .await
        .expect("the hook answers a refusal with an empty listing, never an error");
    gateway_s3(fx).list_buckets(req).await.map(|r| r.output)
}

fn names(out: &ListBucketsOutput) -> Vec<String> {
    out.buckets
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|b| b.name)
        .collect()
}

/// A tenant whose namespace is deliberately larger than any one principal's grants, and
/// deliberately not in sorted order.
const TENANT_BUCKETS: [&str; 5] = ["zeta", "reports", "payroll", "logs", "alpha"];

/// `sub` holds the existence verb `read` plus an object read on each of `buckets`.
fn bundle_for(sub: &str, buckets: &[&str]) -> serde_json::Value {
    let grants: Vec<serde_json::Value> = buckets
        .iter()
        .map(|b| {
            serde_json::json!({
                "bucket": b, "actions": ["read", "read_objects"], "prefixes": []
            })
        })
        .collect();
    serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": {
                sub: { "groups": [], "attributes": [] },
                // A member with no grants at all: the "allowed to ask, holds nothing"
                // case, which must be indistinguishable from a flat denial.
                "nobody": { "groups": [], "attributes": [] }
            },
            "bucket_attributes": {},
            "s3_grants": { sub: grants },
            "group_grants": {}
        }}
    })
}

// ── the property: you see what you were granted, and nothing else ───────────────

#[tokio::test]
async fn a_principal_sees_only_the_buckets_it_was_granted() {
    let backend = fake_backend(&TENANT_BUCKETS, 100).await;
    let fx = common::fixture_with_backend(
        "lb-granted",
        bundle_for("alice", &["reports", "logs"]),
        &backend.url,
    );

    let out = list_buckets(&fx, "alice", ListBucketsInput::default())
        .await
        .expect("an allowed listing");

    assert_eq!(
        names(&out),
        vec!["logs", "reports"],
        "the response must be the intersection of the tenant namespace and the grants"
    );
    // The ungranted buckets are not reordered or truncated away — they are absent, and
    // the backend really did return them (the fake serves all five in one page).
    for invisible in ["zeta", "payroll", "alpha"] {
        assert!(
            !names(&out).contains(&invisible.to_string()),
            "{invisible} is not granted to alice and must not appear in her bucket list"
        );
    }
    assert!(
        backend.requests.load(Ordering::Relaxed) > 0,
        "this test is only meaningful if the backend was actually asked"
    );
}

#[tokio::test]
async fn the_owner_element_is_withheld() {
    // The backend reports the tenant-owner credential's canonical id, identically for
    // every principal in the tenant, because that is who the gateway re-signed as.
    // Forwarding it publishes the shared backend identity; substituting the caller would
    // invent a canonical id the backend never issued. So it is dropped.
    let backend = fake_backend(&TENANT_BUCKETS, 100).await;
    let fx =
        common::fixture_with_backend("lb-owner", bundle_for("alice", &["reports"]), &backend.url);

    let out = list_buckets(&fx, "alice", ListBucketsInput::default())
        .await
        .expect("allowed");
    assert_eq!(names(&out), vec!["reports"]);
    assert!(
        out.owner.is_none(),
        "the tenant-owner identity must not ride out on a bucket listing"
    );
}

#[tokio::test]
async fn the_merged_listing_is_gateway_ordered() {
    // The backend promises no order across ListBuckets pages, so the gateway sorts. The
    // fake serves an unsorted namespace across several pages precisely so this cannot pass
    // by accident.
    let backend = fake_backend(&TENANT_BUCKETS, 2).await;
    let fx = common::fixture_with_backend(
        "lb-order",
        serde_json::json!({
            "org_settings": { "freeze_writes": false },
            "tenants": { "acme": {
                "user_attributes": { "alice": { "groups": [], "attributes": [] } },
                "bucket_attributes": {},
                "s3_grants": { "alice": [
                    { "bucket": "*", "actions": ["read"], "prefixes": [] }
                ] },
                "group_grants": {}
            }}
        }),
        &backend.url,
    );

    let out = list_buckets(&fx, "alice", ListBucketsInput::default())
        .await
        .expect("allowed");
    assert_eq!(
        names(&out),
        vec!["alpha", "logs", "payroll", "reports", "zeta"],
        "the response order is the gateway's lexicographic sort, not the backend's"
    );
    assert!(
        backend.requests.load(Ordering::Relaxed) >= 3,
        "the gateway must have drained the backend's pages, not stopped at the first"
    );
}

#[tokio::test]
async fn pagination_across_a_filtered_set_is_correct_and_stable() {
    // The consequence of filtering: the backend's own max-buckets and continuation-token
    // no longer describe the client's sequence, so the gateway owns both. Walking the
    // pages must yield exactly the granted set, once each, in order.
    let backend = fake_backend(&TENANT_BUCKETS, 2).await;
    let fx = common::fixture_with_backend(
        "lb-pages",
        bundle_for("alice", &["alpha", "logs", "reports", "zeta"]),
        &backend.url,
    );

    let mut seen: Vec<String> = Vec::new();
    let mut token = None;
    for _ in 0..10 {
        let out = list_buckets(
            &fx,
            "alice",
            ListBucketsInput {
                max_buckets: Some(2),
                continuation_token: token.clone(),
                ..Default::default()
            },
        )
        .await
        .expect("allowed");
        assert!(out.buckets.as_ref().is_some_and(|b| b.len() <= 2));
        seen.extend(names(&out));
        match out.continuation_token {
            Some(t) => token = Some(t),
            None => break,
        }
    }
    assert_eq!(seen, vec!["alpha", "logs", "reports", "zeta"]);
    assert!(
        !seen.contains(&"payroll".to_string()),
        "an ungranted bucket must not surface on any page"
    );
}

#[tokio::test]
async fn a_cursor_issued_under_different_grants_is_refused_not_rebased() {
    // Losing your place is recoverable; silently restarting a paginating job so it
    // reprocesses page 1 believing it advanced is not. Same rule as the object-list
    // cursor.
    let backend = fake_backend(&TENANT_BUCKETS, 100).await;
    let fx = common::fixture_with_backend(
        "lb-cursor",
        bundle_for("alice", &["alpha", "logs", "reports"]),
        &backend.url,
    );
    let page1 = list_buckets(
        &fx,
        "alice",
        ListBucketsInput {
            max_buckets: Some(1),
            ..Default::default()
        },
    )
    .await
    .expect("allowed");
    let cursor = page1
        .continuation_token
        .expect("a truncated page hands out a token");

    // Same principal, narrower grants: the cursor no longer describes a scope this
    // gateway would serve.
    let narrowed = common::fixture_with_backend(
        "lb-cursor-2",
        bundle_for("alice", &["reports"]),
        &backend.url,
    );
    let err = list_buckets(
        &narrowed,
        "alice",
        ListBucketsInput {
            max_buckets: Some(1),
            continuation_token: Some(cursor),
            ..Default::default()
        },
    )
    .await
    .expect_err("a cursor bound to another visibility scope must be refused");
    assert_eq!(*err.code(), s3s::S3ErrorCode::InvalidArgument, "{err}");

    // A token this gateway did not issue is the same class of fault, not "page 1".
    let err = list_buckets(
        &narrowed,
        "alice",
        ListBucketsInput {
            continuation_token: Some("garbage".into()),
            ..Default::default()
        },
    )
    .await
    .expect_err("a malformed token must be refused");
    assert_eq!(*err.code(), s3s::S3ErrorCode::InvalidArgument);
}

// ── the empty cases: empty, not 403, and indistinguishable from each other ──────

#[tokio::test]
async fn no_grants_is_an_empty_listing_not_a_403_and_never_reaches_the_backend() {
    // A principal holding nothing gets an empty list, and the two ways of holding nothing
    // — `nobody`, denied because it has no `read` grant anywhere, and `alice`, allowed to
    // enumerate but with an empty visible set — must be indistinguishable to the caller:
    // same status, same body, and neither contacts the backend, so not measurable with a
    // stopwatch either. The distinction survives only in the audit record.
    let backend = fake_backend(&TENANT_BUCKETS, 100).await;
    let fx = common::fixture_with_backend(
        "lb-empty",
        serde_json::json!({
            "org_settings": { "freeze_writes": false },
            "tenants": { "acme": {
                "user_attributes": {
                    "alice":  { "groups": [], "attributes": [] },
                    "nobody": { "groups": [], "attributes": [] }
                },
                // Alice may enumerate, and the one bucket she is granted is one she is
                // denylisted from — so the visible set is empty while the enumeration
                // itself is allowed.
                "bucket_attributes": { "payroll": { "denylist": { "alice": true } } },
                "s3_grants": { "alice": [
                    { "bucket": "payroll", "actions": ["read"], "prefixes": [] }
                ] },
                "group_grants": {}
            }}
        }),
        &backend.url,
    );

    let denied = list_buckets(&fx, "nobody", ListBucketsInput::default())
        .await
        .expect("a refusal is an empty listing, not an error");
    let allowed_but_empty = list_buckets(&fx, "alice", ListBucketsInput::default())
        .await
        .expect("an allowed listing over an empty grant set");

    assert_eq!(names(&denied), Vec::<String>::new());
    assert_eq!(names(&allowed_but_empty), Vec::<String>::new());
    assert_eq!(
        denied.continuation_token, allowed_but_empty.continuation_token,
        "the two empty cases must not differ in the token either"
    );
    assert!(denied.owner.is_none() && allowed_but_empty.owner.is_none());
    assert_eq!(
        backend.requests.load(Ordering::Relaxed),
        0,
        "an empty bucket listing must be answered without contacting the backend — \
         otherwise 'no access' and 'no buckets' are distinguishable by latency"
    );
}

#[tokio::test]
async fn the_denial_and_the_empty_allow_are_still_different_in_the_audit_record() {
    // The other half of the property above: the client cannot tell them apart, and the
    // decision log must. A refusal that leaves no evidence is not a refusal anyone can
    // audit, and this is a path whose HTTP status says nothing.
    let backend = fake_backend(&TENANT_BUCKETS, 100).await;
    let fx = common::fixture_with_backend(
        "lb-audit",
        serde_json::json!({
            "org_settings": { "freeze_writes": false },
            "tenants": { "acme": {
                "user_attributes": {
                    "alice":  { "groups": [], "attributes": [] },
                    "nobody": { "groups": [], "attributes": [] }
                },
                "bucket_attributes": { "payroll": { "denylist": { "alice": true } } },
                "s3_grants": { "alice": [
                    { "bucket": "payroll", "actions": ["read"], "prefixes": [] }
                ] },
                "group_grants": {}
            }}
        }),
        &backend.url,
    );

    list_buckets(&fx, "nobody", ListBucketsInput::default())
        .await
        .expect("empty listing");
    list_buckets(&fx, "alice", ListBucketsInput::default())
        .await
        .expect("empty listing");

    let records = fx.await_audit_records(2).await;
    let for_sub = |sub: &str| {
        records
            .iter()
            .find(|r| r.input.as_ref().is_some_and(|i| i.principal.sub == sub))
            .unwrap_or_else(|| panic!("no audit record for {sub}: {records:#?}"))
            .clone()
    };
    assert!(
        !for_sub("nobody").result.allow,
        "a principal that may not enumerate is recorded as denied, even though it was \
         answered with 200 and an empty list"
    );
    assert!(
        for_sub("alice").result.allow,
        "a principal that may enumerate and holds nothing is recorded as allowed"
    );
    for sub in ["alice", "nobody"] {
        assert_eq!(
            for_sub(sub)
                .input
                .expect("a decision record carries its input")
                .bucket,
            "",
            "ListBuckets is an ACCOUNT-scoped decision; a bucket name here would mean \
             the wildcard-grant rules could match it"
        );
        assert_eq!(
            for_sub(sub).input.expect("input").action,
            s0::model::Action::Read
        );
    }
}

// ── the fail-closed edges ───────────────────────────────────────────────────────

#[tokio::test]
async fn the_dispatch_arm_refuses_a_request_no_hook_decided() {
    // The response-obligation analogue of the AuthzProof. Absence of an obligation is
    // *not* permission to forward: for this op, forwarding is the leak.
    let backend = fake_backend(&TENANT_BUCKETS, 100).await;
    let fx = common::fixture_with_backend("lb-nohook", common::alice_bundle(), &backend.url);
    let req = fx.request("ListBuckets", ListBucketsInput::default(), Method::GET);
    let Err(err) = gateway_s3(&fx).list_buckets(req).await else {
        panic!("a bucket listing with no visibility obligation must not be forwarded")
    };
    assert_eq!(*err.code(), s3s::S3ErrorCode::InternalError);
    assert!(
        format!("{err}").contains("authorization decision"),
        "unexpected error: {err}"
    );
    assert_eq!(
        backend.requests.load(Ordering::Relaxed),
        0,
        "the refusal must happen before the backend is contacted"
    );
}

#[tokio::test]
async fn a_denied_listing_mints_no_proof() {
    // The hook answers `Ok(())` on a denial — it has to, because only the dispatcher can
    // produce a response — so the usual "denied ⇒ no proof" invariant is worth asserting
    // by name here rather than inferring it from the generic sweep.
    let fx = common::fixture("lb-noproof", bundle_for("alice", &["reports"]));
    let access = GatewayAccess::new(fx.gw.clone());
    let mut req = fx.request_as(
        "nobody",
        "ListBuckets",
        ListBucketsInput::default(),
        Method::GET,
    );
    access.list_buckets(&mut req).await.expect("empty listing");
    assert!(
        req.extensions.get::<s0::access::AuthzProof>().is_none(),
        "a denied enumeration must carry no authorization proof; nothing is fetched on \
         that path and nothing may be"
    );
    assert_eq!(
        ResponseObligations::of(&req)
            .and_then(|o| o.visible_buckets.clone())
            .expect("a visibility obligation is installed even on a denial"),
        BucketVisibility::Nothing
    );
}

#[tokio::test]
async fn a_wildcard_grant_alone_does_not_reach_the_account_scope_through_bucket_rules() {
    // `bucket_matches(g) if g.bucket == "*"` also matches the EMPTY bucket name an
    // account-scoped decision carries, so a wildcard grant with any verb could otherwise
    // satisfy the ordinary bucket rules. `read` in the ACCOUNT shape must be the only
    // thing that opens enumeration: the grant below is every other data-plane verb on
    // every bucket, and it must not enumerate.
    let backend = fake_backend(&TENANT_BUCKETS, 100).await;
    let fx = common::fixture_with_backend(
        "lb-b2",
        serde_json::json!({
            "org_settings": { "freeze_writes": false },
            "tenants": { "acme": {
                "user_attributes": { "alice": { "groups": [], "attributes": [] } },
                "bucket_attributes": {},
                "s3_grants": { "alice": [
                    // Every data-plane verb on every bucket, and NOT `read`.
                    { "bucket": "*",
                      "actions": ["read_objects", "list_objects", "write_objects",
                                  "delete_objects", "write_object_tags"],
                      "prefixes": [] }
                ] },
                "group_grants": {}
            }}
        }),
        &backend.url,
    );
    let out = list_buckets(&fx, "alice", ListBucketsInput::default())
        .await
        .expect("empty listing");
    assert_eq!(
        names(&out),
        Vec::<String>::new(),
        "a wildcard grant without `read` must not enumerate the tenant"
    );
    assert_eq!(backend.requests.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn a_denylisted_subject_loses_the_unrestricted_view_rather_than_keeping_it() {
    // The account-scope reading of the per-bucket denylist. The decision names no bucket
    // and the bundle cannot enumerate the tenant's buckets, so "all except these" is not
    // expressible: the wildcard view is dropped entirely and only the named grants remain.
    // Harsher than strictly necessary, and in the safe direction.
    let backend = fake_backend(&TENANT_BUCKETS, 100).await;
    let fx = common::fixture_with_backend(
        "lb-denylist",
        serde_json::json!({
            "org_settings": { "freeze_writes": false },
            "tenants": { "acme": {
                "user_attributes": { "alice": { "groups": [], "attributes": [] } },
                "bucket_attributes": { "payroll": { "denylist": { "alice": true } } },
                "s3_grants": { "alice": [
                    { "bucket": "*", "actions": ["read"], "prefixes": [] },
                    { "bucket": "reports", "actions": ["read"], "prefixes": [] }
                ] },
                "group_grants": {}
            }}
        }),
        &backend.url,
    );
    let out = list_buckets(&fx, "alice", ListBucketsInput::default())
        .await
        .expect("allowed");
    assert_eq!(
        names(&out),
        vec!["reports"],
        "the wildcard view is dropped and only the explicitly-named grants remain"
    );
    assert!(
        !names(&out).contains(&"payroll".to_string()),
        "the denylisted bucket is the one thing that must certainly not be visible"
    );
}

#[tokio::test]
async fn the_client_prefix_is_honored_and_the_page_size_is_clamped() {
    let backend = fake_backend(&TENANT_BUCKETS, 100).await;
    let fx = common::fixture_with_backend(
        "lb-prefix",
        bundle_for("alice", &["reports", "payroll", "logs"]),
        &backend.url,
    );
    let out = list_buckets(
        &fx,
        "alice",
        ListBucketsInput {
            prefix: Some("p".into()),
            // Absurd page size: the gateway owns the pagination now, so this is clamped
            // rather than honored.
            max_buckets: Some(i32::MAX),
            ..Default::default()
        },
    )
    .await
    .expect("allowed");
    assert_eq!(names(&out), vec!["payroll"]);
    assert_eq!(out.prefix.as_deref(), Some("p"));

    // A visibility set is a set of NAMES, not of prefixes: `reports` does not confer
    // `reports-archive`.
    let vis = BucketVisibility::only(BTreeSet::from(["reports".to_string()]));
    assert!(!vis.admits("reports-archive"));
}

// ── the identity fields on the multipart listings ───────────────────────────────

/// `Owner` and `Initiator` on a multipart listing name the **tenant-owner credential**
/// under this gateway, identically for every principal, because that is who the forward
/// was re-signed as. They answer a question the caller did not ask with a fact about the
/// backend's shared identity, so they are stripped.
const OWNER_XML: &str = "<Owner><ID>tenant-owner-canonical-id</ID><DisplayName>acme-owner</DisplayName></Owner>\
     <Initiator><ID>tenant-owner-canonical-id</ID><DisplayName>acme-owner</DisplayName></Initiator>";

#[tokio::test]
async fn list_multipart_uploads_strips_the_shared_identity_and_re_applies_the_prefix() {
    // Two transforms, two reasons. The identity fields are the same leak as on
    // ListBuckets' Owner. The prefix re-application is different: the hook narrowed the
    // request to `2024/`, and whether the backend honored that is not observable here —
    // so the fake answers with a key OUTSIDE the narrowed prefix, which is what a backend
    // ignoring the parameter would do.
    //
    // The request asks for `20`, WIDER than alice's `2024/` grant and overlapping it,
    // which is the shape narrowing exists for. An unbounded list is denied rather than
    // narrowed, so it cannot reach this response path at all.
    let backend = spawn_fake(|_| {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Bucket>reports</Bucket><IsTruncated>false</IsTruncated>\
             <Upload><Key>2024/inside.csv</Key><UploadId>u-1</UploadId>\
             <Initiated>2024-01-01T00:00:00.000Z</Initiated>{OWNER_XML}</Upload>\
             <Upload><Key>2023/outside.csv</Key><UploadId>u-2</UploadId>\
             <Initiated>2024-01-01T00:00:00.000Z</Initiated>{OWNER_XML}</Upload>\
             </ListMultipartUploadsResult>"
        )
    })
    .await;
    let fx = common::fixture_with_backend("mpu-scrub", common::alice_bundle(), &backend.url);
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request(
        "ListMultipartUploads",
        ListMultipartUploadsInput {
            bucket: "reports".into(),
            // Over-broad: alice holds a single prefix grant under `20`, so the hook
            // narrows it to `2024/` — the prefix the response is re-checked against.
            prefix: Some("20".into()),
            ..Default::default()
        },
        Method::GET,
    );
    access
        .list_multipart_uploads(&mut req)
        .await
        .expect("allowed");
    assert_eq!(
        req.input.prefix.as_deref(),
        Some("2024/"),
        "the hook must have narrowed the request, or this test measures nothing"
    );

    let out = gateway_s3(&fx)
        .list_multipart_uploads(req)
        .await
        .expect("forwarded")
        .output;
    let uploads = out.uploads.unwrap_or_default();
    assert_eq!(
        uploads
            .iter()
            .filter_map(|u| u.key.clone())
            .collect::<Vec<_>>(),
        vec!["2024/inside.csv"],
        "an upload outside the narrowed prefix must be dropped even though the backend \
         returned it"
    );
    for upload in &uploads {
        assert!(
            upload.owner.is_none() && upload.initiator.is_none(),
            "the shared tenant-owner identity must not ride out on an upload listing"
        );
    }
}

#[tokio::test]
async fn list_parts_strips_the_shared_identity_and_keeps_the_parts() {
    // The parts themselves are NOT withheld: the caller already holds `read_objects` on
    // this key, and part sizes and ETags describe an object it may read outright. Only
    // the identity fields go — the distinction matters, because over-filtering a response
    // breaks multipart clients for no security gain.
    let backend = spawn_fake(|_| {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListPartsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Bucket>reports</Bucket><Key>2024/x</Key><UploadId>upload-1</UploadId>\
             <IsTruncated>false</IsTruncated>{OWNER_XML}\
             <Part><PartNumber>1</PartNumber><Size>5242880</Size><ETag>\"abc\"</ETag>\
             <LastModified>2024-01-01T00:00:00.000Z</LastModified></Part>\
             </ListPartsResult>"
        )
    })
    .await;
    let fx = common::fixture_with_backend("parts-scrub", common::alice_bundle(), &backend.url);
    let access = GatewayAccess::new(fx.gw.clone());

    let mut req = fx.request(
        "ListParts",
        ListPartsInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            upload_id: "upload-1".into(),
            ..Default::default()
        },
        Method::GET,
    );
    access.list_parts(&mut req).await.expect("allowed");
    let out = gateway_s3(&fx)
        .list_parts(req)
        .await
        .expect("forwarded")
        .output;

    assert!(
        out.owner.is_none() && out.initiator.is_none(),
        "the shared tenant-owner identity must not ride out on a part listing"
    );
    assert_eq!(
        out.parts.unwrap_or_default().len(),
        1,
        "the parts are the answer to an authorized question and must survive"
    );
}
