//! F13, end to end: what bounds the one socket that is both internet-facing and
//! unauthenticated by design.
//!
//! Since F2 published `AssumeRoleWithWebIdentity` through an Ingress on a sibling host,
//! the mint is reachable from outside the cluster and, correctly, requires no platform
//! credential to be served — the web identity token *is* the credential, exactly as at
//! `sts.amazonaws.com`. The Ingress in front of it deliberately applies no rate
//! limiting (Cilium's Ingress has no rate-limit annotation, and an nginx-shaped key
//! would be silently ignored), and an in-cluster caller reaches the Service directly
//! anyway. So every bound on this listener is the one in `mint::serve_on`, and this
//! file is where each is shown to exist.
//!
//! Everything here drives **`mint::serve_on`** — the production accept loop — over a
//! real socket. Two properties are load-bearing and are asserted separately in almost
//! every test, because getting one without the other is worse than having neither:
//!
//! * **the bound holds** — beyond it, a connection is not served; and
//! * **no legitimate mint is ever refused** — the bound queues, it does not reject,
//!   and a slot held by a slow client comes back. A bound that turns real traffic away
//!   is worse than no bound at all: it is an outage the operator caused on purpose.
//!
//! The listener is bound here and handed to `serve_on` still open. Binding, reading the
//! port back, dropping it and passing the address to `serve_with_shutdown` is a race
//! another test binary in the same `cargo test` run can win — and the loser then talks
//! to a *different* gateway on the port it thought it owned.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use s0::auth::sts::StsAuthority;
use s0::config::StsMintConfig;
use s0::mint::{Mint, MintLimits, MintMetrics, StandardVerifier};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

const PRIVATE_PEM: &str = include_str!("testdata/oidc_test_rsa.pem");
const PUBLIC_PEM: &str = include_str!("testdata/oidc_test_rsa_pub.pem");
const ISSUER: &str = "https://kc.example/realms/acme";
const AUDIENCE: &str = "s0";

/// The bearer door, with a real RS256 keypair standing in for the IdP.
///
/// Deliberately the *bearer* door and not the web-identity one: this file is about the
/// listener, not about either protocol on it, and the bearer exchange needs no bundle,
/// no registry and no routing table — so nothing it measures can be an artefact of a
/// fixture. Both doors share one accept loop, which is the thing under test.
fn mint_config() -> StsMintConfig {
    StsMintConfig {
        listen: "127.0.0.1:0".parse().expect("addr"),
        issuer: ISSUER.into(),
        audience: AUDIENCE.into(),
        jwks_uri: None,
        public_key_pem: Some(PUBLIC_PEM.to_string()),
        sub_claim: "sub".into(),
        groups_claim: "groups".into(),
        tenant_claim: "harbor".into(),
        org_claim: "org".into(),
        jwks_timeout_secs: 5,
        // No background refresh: a PEM key source has nothing to refresh, and a timer
        // ticking underneath a test about timers is a way to measure the wrong one.
        jwks_refresh_secs: 0,
        web_identity_enabled: false,
        web_identity_audiences: Vec::new(),
        role_name_template: None,
        max_duration_secs: 3600,
        // Overridden per test by `MintLimits`; these are the production defaults and
        // are what `MintLimits::from_config` is checked against below.
        max_connections: 256,
        connection_timeout_secs: 30,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

/// A token the production `StandardVerifier` really accepts, so a `200` in this file
/// means a credential was minted and not that an error path happened to be cheap.
fn token() -> String {
    encode(
        &Header::new(Algorithm::RS256),
        &serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "exp": now() + 3600,
            "sub": "pipeline-runner", "harbor": "acme", "org": "org-acme",
            "groups": ["editor"]
        }),
        &EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).expect("rsa key"),
    )
    .expect("sign")
}

struct Harness {
    base: String,
    addr: SocketAddr,
    metrics: Arc<MintMetrics>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    task: JoinHandle<s0::error::Result<()>>,
}

impl Harness {
    /// Poll a metric until it holds, or fail loudly. The accept loop runs on its own
    /// task, so "has the server seen it yet?" is a question with a real answer and no
    /// fixed answer time; a sleep here would be either flaky or slow.
    async fn until(&self, what: &str, f: impl Fn(&MintMetrics) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if f(&self.metrics) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("timed out waiting for the mint listener: {what}");
    }

    fn stop(&mut self) {
        let _ = self.stop.take().expect("stopped once").send(());
    }
}

async fn harness(limits: MintLimits) -> Harness {
    let cfg = mint_config();
    let verifier = Arc::new(StandardVerifier::from_config(&cfg).expect("verifier"));
    let sts = Arc::new(StsAuthority::new(vec![4u8; 32], vec![8u8; 32]).expect("sts"));
    let metrics = Arc::new(MintMetrics::default());
    let mint = Arc::new(
        Mint::new(verifier, sts, Duration::from_secs(900))
            .with_limits(limits)
            .with_metrics(metrics.clone()),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        s0::mint::serve_on(mint, listener, async {
            let _ = stopped.await;
        })
        .await
    });
    Harness {
        base: format!("http://{addr}"),
        addr,
        metrics,
        stop: Some(stop),
        task,
    }
}

/// One well-formed bearer mint, written by hand so the test owns the socket.
fn bearer_request(token: &str) -> String {
    format!(
        "POST / HTTP/1.1\r\nHost: mint\r\nAuthorization: Bearer {token}\r\n\
         Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
}

/// Read until the end of the response head (or EOF), with a budget.
async fn read_head<R: AsyncReadExt + Unpin>(r: &mut R, budget: Duration) -> String {
    let mut buf = Vec::new();
    let deadline = Instant::now() + budget;
    let mut chunk = [0u8; 4096];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let n = tokio::time::timeout(left, r.read(&mut chunk))
            .await
            .expect("the mint answered within the budget")
            .expect("read");
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// One mint over a fresh reqwest connection: `(status, AccessKeyId)`.
async fn mint_over_http(base: &str, token: &str) -> (u16, String) {
    let resp = reqwest::Client::new()
        .post(base)
        .header("authorization", format!("Bearer {token}"))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .expect("the mint answered");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
    (
        status,
        body["AccessKeyId"].as_str().unwrap_or_default().to_string(),
    )
}

// ── the connection bound ───────────────────────────────────────────────────────

/// **The F13 headline.** Beyond the bound a connection is not served; when a slot
/// drains it is, and with a real credential rather than an error.
///
/// The permit is taken *before* `accept`, exactly as `server::serve_with_shutdown`
/// does for the data plane, which is what makes this a **queue and not a rejection**:
/// the extra connection sits in the kernel's accept backlog. That distinction is the
/// whole safety argument — a bound that answers a legitimate caller with an error is
/// an outage, and this one cannot, because it has no way to produce a response at all.
#[tokio::test]
async fn the_connection_bound_holds_traffic_beyond_it_and_serves_it_as_slots_drain() {
    let mut h = harness(MintLimits {
        max_connections: 2,
        // Long enough that nothing below is reclaimed by the lifetime bound instead
        // of by the connection bound; this test is about the latter alone.
        connection_timeout: Duration::from_secs(300),
    })
    .await;

    // Two connections that complete the handshake and then say nothing. Each holds a
    // permit for as long as it is open.
    let hold_a = TcpStream::connect(h.addr).await.expect("connect a");
    let hold_b = TcpStream::connect(h.addr).await.expect("connect b");
    h.until("both permits taken", |m| {
        m.connections_active.load(Ordering::Relaxed) == 2
    })
    .await;

    // A third caller, with a perfectly good token. The TCP connect succeeds (the
    // backlog takes it) and the request is written, but nothing is accepting it.
    let mut third = TcpStream::connect(h.addr).await.expect("connect c");
    let tok = token();
    third
        .write_all(bearer_request(&tok).as_bytes())
        .await
        .expect("write");
    let mut probe = [0u8; 16];
    assert!(
        tokio::time::timeout(Duration::from_millis(750), third.read(&mut probe))
            .await
            .is_err(),
        "a third connection must not be served while both permits are held"
    );
    assert_eq!(
        h.metrics.connections_active.load(Ordering::Relaxed),
        2,
        "the bound is 2 and exactly 2 connections are being served"
    );
    // …and the bound biting is OBSERVABLE. A mint that is silently queued and a
    // broken IdP look identical from every other angle.
    assert!(
        h.metrics.connection_limit_saturated.load(Ordering::Relaxed) >= 1,
        "saturation must be counted at the point the bound bites"
    );

    // Drain one slot. The queued caller is served — 200 and a real access key, not a
    // 503: the bound never refuses, it only makes you wait.
    drop(hold_a);
    let head = read_head(&mut third, Duration::from_secs(10)).await;
    assert!(
        head.starts_with("HTTP/1.1 200 OK"),
        "the queued mint must succeed once a slot drains, not be refused: {head}"
    );
    assert!(
        head.contains("cache-control: no-store"),
        "and it is a real credential response: {head}"
    );

    drop(hold_b);
    h.stop();
    let _ = tokio::time::timeout(Duration::from_secs(20), h.task).await;
}

/// **No legitimate token ever stops working**, even when the bound is almost entirely
/// consumed by something else.
///
/// The shape is the burst the runbook worries about — a Deployment rolling many pods
/// at once, every one of them minting on startup — compressed by holding all but one
/// of the slots first, so the queue is *guaranteed* rather than merely likely. 64
/// simultaneous callers through a single free permit, and all 64 get their own
/// credential.
#[tokio::test]
async fn every_caller_in_a_burst_is_still_minted_a_credential_through_one_free_slot() {
    let mut h = harness(MintLimits {
        max_connections: 4,
        connection_timeout: Duration::from_secs(300),
    })
    .await;

    // Occupy three of the four slots with idle connections, leaving one.
    let holders: Vec<TcpStream> = {
        let mut v = Vec::new();
        for _ in 0..3 {
            v.push(TcpStream::connect(h.addr).await.expect("connect"));
        }
        v
    };
    h.until("three slots held", |m| {
        m.connections_active.load(Ordering::Relaxed) == 3
    })
    .await;

    let tok = token();
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..64 {
        let base = h.base.clone();
        let tok = tok.clone();
        set.spawn(async move { mint_over_http(&base, &tok).await });
    }

    let mut keys = HashSet::new();
    while let Some(joined) = set.join_next().await {
        let (status, key) = joined.expect("task");
        assert_eq!(
            status, 200,
            "a legitimate mint was refused under load; a bound that turns real \
             traffic away is worse than no bound"
        );
        assert!(
            key.starts_with("HFST"),
            "the answer must be a session credential, not an empty 200: {key:?}"
        );
        keys.insert(key);
    }
    assert_eq!(keys.len(), 64, "each caller got its own distinct session");
    assert!(
        h.metrics.connection_limit_saturated.load(Ordering::Relaxed) >= 1,
        "the bound must actually have bitten, or this test proves nothing"
    );

    drop(holders);
    h.stop();
    let _ = tokio::time::timeout(Duration::from_secs(20), h.task).await;
}

// ── the lifetime bound ─────────────────────────────────────────────────────────

/// A connection bound **without** a lifetime bound makes slowloris cheaper, not
/// dearer: an attacker who opens `max_connections` sockets and never speaks holds every
/// slot forever, and has locked out the fleet's whole credential path with a few
/// hundred connections and no token.
///
/// So the two land together, and this is the test that says the slot comes back.
/// Nothing here is `hyper`'s `header_read_timeout` — that knob needs a timer on the h1
/// builder that does not survive `into_owned()` and panics once per connection; this
/// project added it once and removed it. This is a `tokio::time::timeout` around the
/// connection future, which has no such coupling and bounds the whole connection.
#[tokio::test]
async fn a_client_that_says_nothing_loses_its_slot_to_the_lifetime_bound() {
    let mut h = harness(MintLimits {
        max_connections: 1,
        connection_timeout: Duration::from_secs(2),
    })
    .await;

    let mut lurker = TcpStream::connect(h.addr).await.expect("connect");
    h.until("the lurker holds the only slot", |m| {
        m.connections_active.load(Ordering::Relaxed) == 1
    })
    .await;

    // The server closes it. A read returning 0 is the FIN; a read that hangs would be
    // the bug this exists to exclude.
    let mut probe = [0u8; 8];
    let n = tokio::time::timeout(Duration::from_secs(15), lurker.read(&mut probe))
        .await
        .expect("the lifetime bound must close an idle connection, not hold it")
        .expect("read");
    assert_eq!(n, 0, "an idle connection is closed, never answered");
    assert!(
        h.metrics.connection_timeouts.load(Ordering::Relaxed) >= 1,
        "and the close is counted, so slowloris is visible rather than merely survived"
    );

    // The slot came back, and the next real caller gets it.
    h.until("the slot is released", |m| {
        m.connections_active.load(Ordering::Relaxed) == 0
    })
    .await;
    let (status, key) = mint_over_http(&h.base, &token()).await;
    assert_eq!(
        status, 200,
        "the slot the lurker held must be returned to real traffic"
    );
    assert!(key.starts_with("HFST"));

    h.stop();
    let _ = tokio::time::timeout(Duration::from_secs(20), h.task).await;
}

// ── the body bound ─────────────────────────────────────────────────────────────

/// An oversized body is refused **without being read**, which is the only version of
/// this bound worth having: a 413 emitted after buffering a gigabyte is the
/// allocation it was meant to prevent, plus a status code.
///
/// Proved by declaring a body far larger than the ceiling and then never sending it. A
/// server that insisted on reading what was declared would still be waiting; this one
/// answers as soon as the ceiling is crossed.
#[tokio::test]
async fn an_oversized_body_is_refused_without_being_read_to_the_end() {
    let mut h = harness(MintLimits::default()).await;

    let sock = TcpStream::connect(h.addr).await.expect("connect");
    let (mut rd, mut wr) = sock.into_split();
    let writer = tokio::spawn(async move {
        let head = "POST / HTTP/1.1\r\nHost: mint\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 104857600\r\n\r\n";
        let _ = wr.write_all(head.as_bytes()).await;
        // A little over the 64 KiB ceiling, and then silence — 99.9 MB of the
        // declared body is never sent.
        let _ = wr
            .write_all(b"Action=AssumeRoleWithWebIdentity&WebIdentityToken=")
            .await;
        let _ = wr.write_all(&vec![b'A'; 80 * 1024]).await;
        std::future::pending::<()>().await;
    });

    let head = read_head(&mut rd, Duration::from_secs(15)).await;
    assert!(
        head.starts_with("HTTP/1.1 413"),
        "the mint must refuse an oversized body as soon as the ceiling is crossed, \
         without waiting for the body it was promised: {head}"
    );
    assert!(
        h.metrics.bodies_too_large.load(Ordering::Relaxed) >= 1,
        "and the refusal is counted"
    );
    writer.abort();

    // The positive control the bound needs: a body comfortably below the ceiling is
    // read and the mint succeeds. 64 KiB is eight times a Keycloak access token
    // carrying a realm's worth of role claims, so no real client is near it.
    let resp = reqwest::Client::new()
        .post(&h.base)
        .header("authorization", format!("Bearer {}", token()))
        .header("content-type", "application/x-www-form-urlencoded")
        .body("padding=".to_string() + &"B".repeat(60 * 1024))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .expect("answered");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a body under the ceiling must still mint"
    );

    h.stop();
    let _ = tokio::time::timeout(Duration::from_secs(20), h.task).await;
}

// ── the header bound ───────────────────────────────────────────────────────────

/// The header block is bounded, and it is **hyper** that bounds it — h1 refuses a
/// message head larger than its read buffer with a `431`, and h2 advertises a
/// `max_header_list_size`. Nothing here is hand-rolled.
///
/// What `mint::serve_on` does is tighten hyper's h1 default (8 KiB + 100 × 4 KiB
/// ≈ 408 KiB) to 64 KiB, because on this socket the multiplier is `max_connections`
/// times an anonymous caller's discretion — ~100 MiB of header buffer to serve requests
/// whose real headers are a `Host` and a `Content-Length`.
#[tokio::test]
async fn an_oversized_header_block_is_refused_and_a_realistic_one_is_not() {
    let mut h = harness(MintLimits::default()).await;

    let sock = TcpStream::connect(h.addr).await.expect("connect");
    let (mut rd, mut wr) = sock.into_split();
    let writer = tokio::spawn(async move {
        let req = format!(
            "POST / HTTP/1.1\r\nHost: mint\r\nX-Pad: {}\r\nContent-Length: 0\r\n\r\n",
            "A".repeat(128 * 1024)
        );
        let _ = wr.write_all(req.as_bytes()).await;
        std::future::pending::<()>().await;
    });
    let head = read_head(&mut rd, Duration::from_secs(15)).await;
    assert!(
        head.starts_with("HTTP/1.1 431"),
        "a 128 KiB header block must be refused, not buffered: {head}"
    );
    writer.abort();

    // The positive control, and it is the one that matters: the bearer door's own
    // `Authorization` line carries a Keycloak access token, routinely 4–8 KiB. A
    // ceiling that refused those would break the door it was added to protect.
    let resp = reqwest::Client::new()
        .post(&h.base)
        .header("authorization", format!("Bearer {}", token()))
        .header("x-pad", "C".repeat(16 * 1024))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .expect("answered");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a 16 KiB header block is ordinary traffic and must mint"
    );

    h.stop();
    let _ = tokio::time::timeout(Duration::from_secs(20), h.task).await;
}

// ── draining, which the bounds must not have broken ────────────────────────────

/// A rolling update still drains cleanly with the bounds in place.
///
/// The mint's graceful shutdown exists because the listener used to be aborted
/// mid-request when the runtime dropped, producing sporadic credential failures on
/// every deploy that were indistinguishable from an IdP problem. Adding a bound that
/// broke it would have traded F13 for exactly that.
#[tokio::test]
async fn graceful_shutdown_still_drains_and_then_stops_accepting() {
    let mut h = harness(MintLimits::default()).await;

    // A real mint over a pooled keep-alive connection, then left idle — the state a
    // rolling update actually finds, and the one that would hold a naive drain open.
    let client = reqwest::Client::builder()
        .pool_idle_timeout(Duration::from_secs(300))
        .build()
        .expect("client");
    let resp = client
        .post(&h.base)
        .header("authorization", format!("Bearer {}", token()))
        .timeout(Duration::from_secs(30))
        .send()
        .await
        .expect("answered");
    assert_eq!(resp.status().as_u16(), 200);
    let _ = resp.text().await;

    h.stop();
    let outcome = tokio::time::timeout(Duration::from_secs(20), h.task)
        .await
        .expect("the mint drained within its budget rather than hanging");
    assert!(
        outcome.expect("join").is_ok(),
        "the serving loop returns cleanly after the drain"
    );

    // …and the socket is gone, so the next connection goes to another replica rather
    // than to a listener that has stopped answering.
    assert!(
        TcpStream::connect(h.addr).await.is_err(),
        "a drained mint stops accepting"
    );
}

/// The drain still happens **when the bound is fully held**, which is the interesting
/// case and the one the new code could have broken.
///
/// With every permit taken, the accept loop is parked on the semaphore rather than on
/// `accept`. If the shutdown trigger were not in *that* `select!` too, this is exactly
/// where a saturated mint would stop observing SIGTERM — and a pod that cannot drain is
/// killed by the grace period instead, which is the failure the graceful path exists to
/// prevent. The lifetime bound is set far beyond the test's own patience so that a
/// drain here cannot be the timeout firing by luck.
#[tokio::test]
async fn shutdown_is_observed_even_when_every_connection_slot_is_held() {
    let mut h = harness(MintLimits {
        max_connections: 1,
        connection_timeout: Duration::from_secs(600),
    })
    .await;

    let _lurker = TcpStream::connect(h.addr).await.expect("connect");
    h.until("the only slot is held", |m| {
        m.connections_active.load(Ordering::Relaxed) == 1
    })
    .await;
    // A second connection, so the loop is provably parked waiting for a permit and not
    // merely waiting on `accept`.
    let _queued = TcpStream::connect(h.addr).await.expect("connect");
    h.until("the loop is parked on the bound", |m| {
        m.connection_limit_saturated.load(Ordering::Relaxed) >= 1
    })
    .await;

    h.stop();
    let outcome = tokio::time::timeout(Duration::from_secs(20), h.task)
        .await
        .expect("a saturated mint must still observe the shutdown signal");
    assert!(outcome.expect("join").is_ok());
}

// ── the numbers themselves ─────────────────────────────────────────────────────

/// The defaults are the ones the config documents, and they reach the listener.
///
/// Pinned because both numbers are arguments, not preferences: 256 is sized against
/// the largest legitimate burst (a rolling Deployment, each pod minting on startup)
/// and is a quarter of the data plane's 1024; 30 s is an order of magnitude above the
/// worst legitimate request, which is one verification plus, on a `kid` miss, a JWKS
/// fetch bounded by `jwks_timeout_secs`.
#[tokio::test]
async fn the_configured_bounds_are_the_ones_the_listener_applies() {
    let cfg = mint_config();
    let limits = MintLimits::from_config(&cfg);
    assert_eq!(limits.max_connections, 256);
    assert_eq!(limits.connection_timeout, Duration::from_secs(30));

    // A `Mint` built without limits is bounded, not unbounded: "nothing configured"
    // must never mean "no limits" on this socket of all sockets.
    let default = MintLimits::default();
    assert_eq!(default.max_connections, limits.max_connections);
    assert_eq!(default.connection_timeout, limits.connection_timeout);

    // And the listener publishes what it is enforcing, so the saturation counter is
    // interpretable without reading the pod's config.
    let h = harness(MintLimits {
        max_connections: 7,
        connection_timeout: Duration::from_secs(30),
    })
    .await;
    h.until("the limit is published", |m| {
        m.connection_limit.load(Ordering::Relaxed) == 7
    })
    .await;
    let mut h = h;
    h.stop();
    let _ = tokio::time::timeout(Duration::from_secs(20), h.task).await;
}
