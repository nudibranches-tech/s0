//! The gate over real HTTP, for **every** operation s3s can route.
//!
//! `s3s::access::S3AccessContext` has crate-private fields, so no in-process test can
//! call `check` — hence signed requests over TCP into the assembled `S3Service`. A bad
//! signature also 403s, so every denial assertion checks that the error body *names the
//! operation*, and the positive controls keep the sweep from passing vacuously.
//!
//! The route table `data/s3s-0.14.1-routes.tsv` is regenerated from `resolve_route` in
//! the pinned crate source — smallest request per op, plus `PostObject`, which
//! `ops/mod.rs` routes ahead of `resolve_route`.

mod common;

use std::net::SocketAddr;
use std::time::Duration;

use common::routes::{self, Route};
use common::sigv4::{self, RawRequest};
use s0::access::optable::{Coverage, DangerTier, OP_TABLE, spec};

/// Boot a real gateway on a loopback port and return its base URL. The backend
/// endpoint points at a closed port: nothing that is *denied* should get far enough to
/// forward, and if something does, the failure is loud rather than silent.
async fn spawn_gateway(tag: &str, bundle: serde_json::Value) -> (String, common::Fixture) {
    let fx = common::fixture(tag, bundle);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr: SocketAddr = listener.local_addr().unwrap();
    drop(listener);
    let gw = fx.gw.clone();
    tokio::spawn(async move {
        // The real serving path — connection cap, h2 settings and drain included —
        // rather than a bespoke accept loop that could differ from production.
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

struct Response {
    status: u16,
    body: String,
}

async fn send(base: &str, route: &Route) -> Response {
    let host = base.trim_start_matches("http://").to_string();

    // A browser form upload carries no Authorization header at all: s3s short-circuits
    // multipart POSTs to the POST-policy signature path before it ever looks at SigV4
    // header auth. Signing it anyway would be modelling a client that does not exist.
    let (req, headers) = if route.multipart {
        let req = post_object_request();
        let mut headers = req.headers.clone();
        headers.push(("host".into(), host.clone()));
        (req, headers)
    } else {
        let mut r = RawRequest::new(route.method, route.path);
        for (k, v) in &route.query {
            r = r.query(k, v);
        }
        for (k, v) in &route.headers {
            r = r.header(k, v);
        }
        let headers = r.sign(&host, common::ACCESS_KEY, common::SECRET_KEY);
        (r, headers)
    };

    let mut builder = reqwest::Client::new()
        .request(req.method.parse().expect("http method"), req.url(base))
        .timeout(Duration::from_secs(10))
        .body(req.body.clone());
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder.send().await.unwrap_or_else(|e| {
        panic!(
            "{} did not get an HTTP response from the gateway: {e}",
            route.op
        )
    });
    Response {
        status: resp.status().as_u16(),
        body: resp.text().await.unwrap_or_default(),
    }
}

/// A browser form upload with a signed POST policy — the only way `PostObject` is
/// reachable, and the only operation whose s3s default *forwards* (through
/// `put_object`) rather than returning `NotImplemented`.
fn post_object_request() -> RawRequest {
    post_object_request_for("2024/q1.csv")
}

fn post_object_request_for(key: &str) -> RawRequest {
    const BOUNDARY: &str = "s0blackboxboundary";
    let now = chrono::Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date = now.format("%Y%m%d").to_string();
    let credential = format!(
        "{}/{date}/{}/{}/aws4_request",
        common::ACCESS_KEY,
        sigv4::REGION,
        sigv4::SERVICE
    );
    // Every non-exempt form field must appear as a policy condition, or s3s rejects the
    // upload with its own AccessDenied before `check` ever runs — which would make this
    // row assert nothing about the gate.
    let policy = serde_json::json!({
        "expiration": "2099-01-01T00:00:00Z",
        "conditions": [
            { "x-amz-date": amz_date },
            { "x-amz-credential": credential },
            { "x-amz-algorithm": "AWS4-HMAC-SHA256" },
            { "key": key },
        ]
    })
    .to_string();
    let policy_b64 = sigv4::base64(policy.as_bytes());
    let signature = sigv4::sign_post_policy(&policy_b64, common::SECRET_KEY, &date);

    let field = |name: &str, value: &str| {
        format!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
    };
    // The leading CRLF is not decoration: s3s's multipart parser scans for
    // `\r\n--<boundary>`, so a body starting flush at the first boundary parses as zero
    // fields and the request is rejected before it reaches the gate.
    let body = format!(
        "\r\n{}{}{}{}{}{}{}--{BOUNDARY}--\r\n",
        field("key", key),
        field("policy", &policy_b64),
        field("x-amz-algorithm", "AWS4-HMAC-SHA256"),
        field("x-amz-credential", &credential),
        field("x-amz-date", &amz_date),
        field("x-amz-signature", &signature),
        format_args!(
            "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"file\"; \
             filename=\"q1.csv\"\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
        ),
    );
    RawRequest::new("POST", "/reports")
        .header(
            "content-type",
            &format!("multipart/form-data; boundary={BOUNDARY}"),
        )
        .body(body.into_bytes())
}

fn assert_refused_by_the_gate(route: &Route, resp: &Response) {
    assert_eq!(
        resp.status, 403,
        "{} must be refused by the gate with 403, got {}: {}",
        route.op, resp.status, resp.body
    );
    if route.method == "HEAD" {
        // HTTP forbids a body on a HEAD response, so the status is all there is. The
        // HeadObject positive control below signs through the same code path, which is
        // what keeps this row from being satisfiable by a signature failure.
        return;
    }
    assert!(
        resp.body.contains("<Code>AccessDenied</Code>"),
        "{} was refused, but not with AccessDenied — this is not the gate: {}",
        route.op,
        resp.body
    );
    assert!(
        resp.body.contains(route.op),
        "{} got a 403 that does not name the operation, so s3s may have resolved a \
         different route or the refusal came from signature verification rather than \
         the gate: {}",
        route.op,
        resp.body
    );
}

#[tokio::test]
async fn every_denied_op_403s_over_real_http() {
    let (base, fx) = spawn_gateway("blackbox-denied", common::alice_bundle()).await;

    let all = routes::all();
    assert_eq!(
        all.len(),
        99,
        "the route table must cover every s3s operation"
    );
    let mut checked = Vec::new();
    for route in all {
        let s = spec(route.op).unwrap_or_else(|| panic!("{} is not in OP_TABLE", route.op));
        if s.coverage == Coverage::Enforced {
            continue;
        }
        let resp = send(&base, route).await;
        assert_refused_by_the_gate(route, &resp);
        if s.tier == DangerTier::NeverImplement && route.method != "HEAD" {
            // The structural denials must be refused for the structural reason. If one
            // ever became merely "not enforced", flipping its table entry would enable
            // it — which is the whole thing `unauthorizable()` exists to prevent.
            assert!(
                resp.body.contains("cannot be authorized"),
                "{} must be refused as structurally unauthorizable, not as merely \
                 unenforced: {}",
                route.op,
                resp.body
            );
        }
        checked.push(route.op);
    }

    // Cross-check against the table rather than trusting the loop: if a row went
    // missing from the TSV, the loop above would silently cover less.
    let mut expected: Vec<&str> = OP_TABLE
        .iter()
        .filter(|s| s.coverage != Coverage::Enforced)
        .map(|s| s.name)
        .collect();
    checked.sort_unstable();
    expected.sort_unstable();
    assert_eq!(
        checked, expected,
        "the set of ops driven over HTTP and OP_TABLE's denied set disagree"
    );
    assert_eq!(
        checked.len(),
        76,
        "99 operations minus the 23 enforced. The six control-plane ops (CreateBucket, \
         DeleteBucket and the bucket policy/CORS pairs) are among them, and this is the \
         test that proves the refusal reaches the WIRE, not just the table"
    );
    drop(fx);
}

#[tokio::test]
async fn create_session_is_refused_even_if_policy_would_allow() {
    // The bundle below grants alice everything, on every bucket, with no prefix scope —
    // so any op that reached the PDP would be allowed. CreateSession still must not:
    // it returns credentials the client then uses DIRECTLY against the backend, which
    // is a permanent and total bypass of this gateway. It is refused in code, ahead of
    // and independently of both `Coverage` and any pushed policy.
    let permissive = serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": [], "attributes": [] } },
            "bucket_attributes": {},
            "s3_grants": { "alice": [
                { "bucket": "*", "actions": ["*"], "prefixes": [] }
            ] },
            "group_grants": {}
        }}
    });
    let (base, fx) = spawn_gateway("blackbox-create-session", permissive).await;
    let table = routes::all();
    let route = table
        .iter()
        .find(|r| r.op == "CreateSession")
        .expect("CreateSession row");

    let resp = send(&base, route).await;
    assert_eq!(resp.status, 403, "{}", resp.body);
    assert!(
        resp.body.contains("cannot be authorized") && resp.body.contains("CreateSession"),
        "CreateSession must be refused structurally: {}",
        resp.body
    );

    // The control that gives the assertion above its meaning: under this same bundle a
    // GetObject on a key no prefix grant covers is allowed all the way to the forward.
    // Without it, "CreateSession is 403" would be true of a gateway that denies
    // everything.
    let allowed = table.iter().find(|r| r.op == "GetObject").unwrap();
    let resp = send(&base, allowed).await;
    assert_ne!(
        resp.status, 403,
        "the permissive bundle must actually allow — otherwise the CreateSession \
         assertion above proves nothing: {}",
        resp.body
    );

    // …and the same for the other structural denial, which has no bucket and no key,
    // so there is no resource for even a wildcard grant to name.
    let wgor = table
        .iter()
        .find(|r| r.op == "WriteGetObjectResponse")
        .unwrap();
    let resp = send(&base, wgor).await;
    assert_eq!(resp.status, 403);
    assert!(resp.body.contains("cannot be authorized"), "{}", resp.body);
    drop(fx);
}

#[tokio::test]
async fn an_enforced_op_passes_the_gate_and_reaches_the_forward_path() {
    // The positive control for the whole file: without it, the sweep above would pass
    // just as happily if the gateway 403'd everything for an unrelated reason. GetObject
    // on a granted key is allowed by `check` and by the policy, so it gets as far as the
    // forward, where the configured backend (port 1) is not listening.
    let (base, fx) = spawn_gateway("blackbox-allowed", common::alice_bundle()).await;
    let table = routes::all();

    let get = table.iter().find(|r| r.op == "GetObject").unwrap();
    let resp = send(&base, get).await;
    assert_ne!(
        resp.status, 403,
        "an allowed GetObject was refused at the gate: {}",
        resp.body
    );

    // HEAD separately: HeadBucket's denial assertion cannot inspect a body, so its
    // signature path needs its own control.
    let head = table.iter().find(|r| r.op == "HeadObject").unwrap();
    let resp = send(&base, head).await;
    assert_ne!(
        resp.status, 403,
        "an allowed HeadObject was refused at the gate — the HEAD signing path is \
         broken, which would make every HEAD denial above vacuous"
    );
    drop(fx);
}

#[tokio::test]
async fn a_form_upload_is_authorized_on_its_form_carried_key() {
    // PostObject is the one enforced op no SDK can express and the one whose key lives
    // in the multipart body rather than the path — so this is the only place the whole
    // chain is observable: s3s's pre-`check` multipart parse, the gate, the typed hook
    // reading `input.key`, and the forward. It is also the op whose trait default
    // *forwards*, so "denied ops fall to NotImplemented" never protected it.
    let (base, fx) = spawn_gateway("blackbox-postobject", common::alice_bundle()).await;
    let route = routes::route("PostObject");

    // `2024/q1.csv` is inside alice's granted prefix: allowed, so it reaches the
    // forward, where the configured backend (port 1) is not listening.
    let resp = send(&base, route).await;
    assert_ne!(
        resp.status, 403,
        "an allowed form upload was refused at the gate: {}",
        resp.body
    );

    // The same request for a key outside the grant must be denied — by the policy, on
    // the strength of the key the *form* carried. If the hook read anything else, this
    // would be indistinguishable from the allow above.
    let outside = post_object_request_for("2023/outside.csv");
    let host = base.trim_start_matches("http://").to_string();
    let mut headers = outside.headers.clone();
    headers.push(("host".into(), host));
    let mut builder = reqwest::Client::new()
        .request(
            outside.method.parse().expect("http method"),
            outside.url(&base),
        )
        .timeout(Duration::from_secs(10))
        .body(outside.body.clone());
    for (k, v) in &headers {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder.send().await.expect("response");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(status, 403, "{body}");
    assert!(
        !body.contains("is not permitted by the gateway"),
        "this must be a policy denial on the form key, not a gate denial: {body}"
    );
    drop(fx);
}

#[tokio::test]
async fn a_bucket_listing_a_principal_may_not_make_is_an_empty_200_over_real_http() {
    // The one enforced operation whose refusal is NOT a 403. Both principals below end
    // up with nothing to show — one denied the enumeration outright, one denylisted from
    // the only bucket it was granted — and the two answers must be byte-identical, or
    // the status is an oracle for whether a credential holds `list_buckets`. Neither
    // reaches the backend (port 1, closed), so a *forwarded* listing would show as a 503.
    let bundle = serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": [], "attributes": [] } },
            "bucket_attributes": { "reports": { "denylist": { "alice": true } } },
            "s3_grants": { "alice": [
                { "bucket": "reports", "actions": ["list_buckets"], "prefixes": [] }
            ] },
            "group_grants": {}
        }}
    });
    let (base, fx) = spawn_gateway("blackbox-listbuckets-empty", bundle).await;
    let resp = send(&base, routes::route("ListBuckets")).await;
    assert_eq!(
        resp.status, 200,
        "an empty bucket listing must be an empty listing, never a 403 and never a \
         backend error: {}",
        resp.body
    );
    assert!(
        !resp.body.contains("<Bucket>"),
        "no bucket may appear in this listing: {}",
        resp.body
    );
    assert!(
        !resp.body.contains("<Owner>"),
        "the tenant-owner identity must not ride out on a bucket listing: {}",
        resp.body
    );
    drop(fx);

    // The control that gives the assertion its meaning: with a grant that *does* make a
    // bucket visible, the same request reaches the forward path — and fails there,
    // because the configured backend is not listening. Without this, "200 with no
    // buckets" would also be true of a gateway whose ListBuckets did nothing at all.
    let (base, fx) = spawn_gateway("blackbox-listbuckets-visible", common::alice_bundle()).await;
    let resp = send(&base, routes::route("ListBuckets")).await;
    assert_ne!(
        resp.status, 200,
        "a principal with a visible bucket must reach the backend, so with no backend \
         listening this cannot succeed: {}",
        resp.body
    );
    assert_ne!(
        resp.status, 403,
        "…and it must not be refused at the gate either: {}",
        resp.body
    );
    drop(fx);
}

#[tokio::test]
async fn a_policy_denial_is_still_a_403_on_an_enforced_op() {
    // The other half of the control: an enforced op outside the granted prefix is
    // denied by the PDP, not by the gate. Same status, different layer — and the layer
    // is what the audit record distinguishes.
    let (base, fx) = spawn_gateway("blackbox-policy-deny", common::alice_bundle()).await;
    let mut route = RawRequest::new("GET", "/reports/2023/old.csv");
    route = route.header("x-amz-noop", "1");
    let host = base.trim_start_matches("http://").to_string();
    let signed = route.sign(&host, common::ACCESS_KEY, common::SECRET_KEY);
    let mut builder = reqwest::Client::new()
        .get(route.url(&base))
        .timeout(Duration::from_secs(10));
    for (k, v) in &signed {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder.send().await.expect("response");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    assert_eq!(status, 403, "{body}");
    assert!(
        !body.contains("is not permitted by the gateway"),
        "this must be a policy denial, not a gate denial: {body}"
    );
    drop(fx);
}

#[tokio::test]
async fn a_public_acl_header_is_refused_over_real_http() {
    // The hook-level suite (`tests/request_riders.rs`) builds `PutObjectInput` directly,
    // so it proves the *decision* but assumes the *parse*: that `x-amz-acl` on the wire
    // really lands in `PutObjectInput::acl`. That assumption is load-bearing, because
    // everything the gateway does not read is reconstructed onto the forward from the
    // parsed input — so a header that does not parse still reaches the backend.
    let (base, fx) = spawn_gateway("blackbox-acl", common::alice_bundle()).await;
    let host = base.trim_start_matches("http://").to_string();

    let put = |acl: Option<&'static str>| {
        let mut r = RawRequest::new("PUT", "/reports/2024/q1.csv");
        if let Some(acl) = acl {
            r = r.header("x-amz-acl", acl);
        }
        r
    };

    for acl in ["public-read", "public-read-write", "authenticated-read"] {
        let r = put(Some(acl));
        let signed = r.sign(&host, common::ACCESS_KEY, common::SECRET_KEY);
        let mut builder = reqwest::Client::new()
            .put(r.url(&base))
            .timeout(Duration::from_secs(10))
            .body(r.body.clone());
        for (k, v) in &signed {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let resp = builder.send().await.expect("response");
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        assert_eq!(status, 403, "x-amz-acl: {acl} must be refused: {body}");
        assert!(
            body.contains("<Code>AccessDenied</Code>") && body.contains(acl),
            "the refusal must name the ACL it refused, or an operator cannot tell it \
             from an ordinary policy denial: {body}"
        );
    }

    // The positive control that makes the three assertions above mean something: the
    // byte-identical request without the header reaches the forward path (and fails
    // there, against the closed backend port), so the 403s are about the ACL.
    let r = put(None);
    let signed = r.sign(&host, common::ACCESS_KEY, common::SECRET_KEY);
    let mut builder = reqwest::Client::new()
        .put(r.url(&base))
        .timeout(Duration::from_secs(10))
        .body(r.body.clone());
    for (k, v) in &signed {
        builder = builder.header(k.as_str(), v.as_str());
    }
    let resp = builder.send().await.expect("response");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    assert_ne!(
        status, 403,
        "the same PutObject without an ACL header must be allowed: {body}"
    );
    drop(fx);
}
