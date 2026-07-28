//! The gate over real HTTP, for **every** operation s3s can route.
//!
//! `tests/op_coverage.rs` drives `optable::gate_op` directly, because
//! `s3s::access::S3AccessContext` has crate-private fields and cannot be built outside
//! s3s — so no in-process test can call `check` itself. This file closes that gap:
//! signed requests over TCP, into the assembled `S3Service` (`server::build_service`),
//! through s3s's own route resolution, into the real `check`.
//!
//! It is table-driven off `data/s3s-0.14.1-routes.tsv`, which is extracted from the
//! pinned s3s crate's own `resolve_route`. That is what makes "all 84 denied ops"
//! affordable: an SDK exposes one typed builder per operation, so the tail would be one
//! hand-written call per op with no new information per call — and the SDK cannot
//! express `PostObject` at all.
//!
//! ## Why this cannot pass vacuously
//!
//! s3s verifies the signature *before* it resolves the route, so a bad signature also
//! produces a 403 — and a file that only asserted "403" would pass just as happily if
//! the gateway refused everything for an unrelated reason. Three things prevent that:
//!
//! 1. every denial assertion checks the error body **names the operation**, which only
//!    happens if s3s resolved the route to that op and `check` refused it by name;
//! 2. the two structural denials are asserted to carry the *structural* reason, not the
//!    ordinary not-enforced one;
//! 3. positive controls: an allowed `GetObject` (and a `HeadObject`, since HEAD carries
//!    no body and its assertion is necessarily weaker) must reach the forward path.
//!
//! ## Regenerating the route table
//!
//! The table is derived from `resolve_route` in the pinned crate:
//! `~/.cargo/registry/src/*/s3s-0.14.1/src/ops/generated.rs`. Each row is the smallest
//! request that resolves to that operation: method, path shape, the query parameters
//! s3s discriminates on, and any header it keys off. `PostObject` is the one row not in
//! `resolve_route` — `ops/mod.rs` routes a multipart/form-data POST to a bucket to it
//! before `resolve_route` is consulted. If s3s moves, `tests/op_coverage.rs` fails
//! first (it pins the version), and this table must be regenerated with it.

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
            { "key": "2024/q1.csv" },
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
        field("key", "2024/q1.csv"),
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
    assert_eq!(checked.len(), 84);
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
    // The positive control for the whole file. Without it, the sweep above would pass
    // just as happily if the gateway 403'd every request for an unrelated reason (bad
    // signature, unknown credential, unroutable tenant).
    //
    // GetObject on a granted key is allowed by `check` AND by the policy, so it gets as
    // far as the forward, where the configured backend (port 1) is not listening.
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
