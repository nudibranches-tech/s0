//! **P2, proven by execution across both repositories**: s0's *real* bundle poller
//! against hyperfluid's *real*, now-guarded bundle endpoint.
//!
//! Everything else that touches P2 stops at one repository's edge.
//! `src/bundle_refresh.rs`'s unit tests read the credential off the bytes s0 puts on a
//! socket — but the socket is a stub that would accept anything.
//! `tests/cross_repo_contract.rs` reads hyperfluid's source and checks the guard is
//! still applied to the route — but reading source is not running it. And hyperfluid's
//! own `s3_gateway_bundle_auth.rs` drives its real router with a hand-written header —
//! which is exactly the "matching strings" this whole workstream keeps being burned by.
//!
//! The claim only one of these can make is the one that matters:
//!
//! * **With the credential**, `bundle_refresh::spawn` — the task `main.rs` starts —
//!   fetches, parses, reloads the engine and records a success against the real
//!   console handler. Revocation lands.
//! * **Without it**, that same task records only failures, the engine keeps its
//!   previous data, and the console answers exactly `401` with no `ETag` and no
//!   revision. Revocation stops landing, and the pod stays Ready — which is why this
//!   has to be observable at all.
//! * **The sibling routes** (`ceph-bundle`, the per-DataDock `last-bundle`) still
//!   answer an uncredentialed caller. They are polled by OPA deployments whose bundle
//!   plugin cannot present a secret; a 401 on either is a live outage of the RGW
//!   authorization path on every existing cluster, not a hardening.
//!
//! # Running it
//!
//! `scripts/live-cross-repo-proof.sh` starts hyperfluid's
//! `serve_the_real_internal_router_for_the_cross_repo_live_proof` (which needs its
//! testcontainers Postgres), waits for the handshake file, runs this file against it,
//! and stops the server. Every test here is `#[ignore]`d and skips loudly when
//! `S0_LIVE_CONSOLE_HANDSHAKE` is unset, so nothing here can pass by absence in the
//! ordinary suite — and nothing here is the *gate* for P2 either. The gates are
//! `tests/cross_repo_contract.rs` here and `s3_gateway_bundle_auth.rs` there, both
//! always on. This is the proof that the gates are guarding something real.

use std::sync::Arc;
use std::time::{Duration, Instant};

use s0::bundle_refresh::{self, BundleHealth, BundleSource};
use s0::internal::SHARED_SECRET_HEADER;
use s0::pdp::{Bundle, BundleStore, GATEWAY_REGO, Pdp, RegorusPdp};
use s0::secret::Secret;

const HANDSHAKE_ENV: &str = "S0_LIVE_CONSOLE_HANDSHAKE";

/// What the hyperfluid side wrote when it came up.
struct Peer {
    base: String,
    organization_id: String,
    data_dock_id: String,
    shared_secret: String,
}

impl Peer {
    fn s3_gateway_bundle_url(&self) -> String {
        format!(
            "{}/api/internal/v1/organizations/{}/s3-gateway-bundle",
            self.base, self.organization_id
        )
    }
    fn ceph_bundle_url(&self) -> String {
        format!(
            "{}/api/internal/v1/organizations/{}/ceph-bundle",
            self.base, self.organization_id
        )
    }
    fn last_bundle_url(&self) -> String {
        format!(
            "{}/api/v1/data-docks/{}/last-bundle",
            self.base, self.data_dock_id
        )
    }
}

/// Read the handshake, or skip loudly. Deliberately not a hard failure: this file is
/// meaningless without the peer, and a red test on a developer machine with no
/// Postgres would train people to ignore it.
fn peer(checking: &str) -> Option<Peer> {
    let Ok(path) = std::env::var(HANDSHAKE_ENV) else {
        eprintln!(
            "\n!!! SKIPPED: the cross-repo LIVE proof was NOT run — {checking}\n\
             \x20   {HANDSHAKE_ENV} is unset. Run scripts/live-cross-repo-proof.sh, which \
             starts hyperfluid's real internal router and points this file at it.\n"
        );
        return None;
    };
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{HANDSHAKE_ENV}={path} is not readable: {e}"));
    let v: serde_json::Value =
        serde_json::from_str(&raw).unwrap_or_else(|e| panic!("handshake is not JSON: {e}"));
    let s = |k: &str| {
        v[k].as_str()
            .unwrap_or_else(|| panic!("handshake has no {k:?}: {v}"))
            .to_string()
    };
    Some(Peer {
        base: s("base"),
        organization_id: s("organization_id"),
        data_dock_id: s("data_dock_id"),
        shared_secret: s("shared_secret"),
    })
}

/// A real PDP over the shipped module, and a bundle store holding a known seed
/// revision, so "the poller loaded something new" is observable.
fn pdp_and_store() -> (Arc<dyn Pdp>, Arc<BundleStore>) {
    let seed = serde_json::json!({ "org_settings": {}, "tenants": {} });
    let engine = RegorusPdp::new(GATEWAY_REGO, &seed).expect("regorus");
    let store = Arc::new(BundleStore::new(Bundle::new("seed-revision", seed)));
    (Arc::new(engine) as Arc<dyn Pdp>, store)
}

async fn until(deadline: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + deadline;
    while Instant::now() < end {
        if done() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    done()
}

// ── the proof ──────────────────────────────────────────────────────────────────

/// **With the credential, revocation lands.** The real polling task fetches from the
/// real guarded handler, parses the document the real projection produced, reloads the
/// real engine and records a success.
#[tokio::test]
#[ignore = "cross-repo LIVE proof; run scripts/live-cross-repo-proof.sh"]
async fn the_bundle_poller_authenticates_against_the_guarded_endpoint() {
    let Some(peer) = peer("the credentialed bundle poll") else {
        return;
    };
    let (pdp, store) = pdp_and_store();
    let source = BundleSource::http(
        peer.s3_gateway_bundle_url(),
        Duration::from_secs(10),
        Some(Secret::from(peer.shared_secret.as_str())),
    )
    .expect("source");
    assert!(source.is_authenticated());

    let health = Arc::new(BundleHealth::new(true));
    bundle_refresh::spawn(
        pdp,
        store.clone(),
        source,
        Duration::from_millis(250),
        health.clone(),
    );

    let ok = until(Duration::from_secs(30), || health.successes() >= 1).await;
    assert!(
        ok,
        "the credentialed poll never succeeded ({} failures). The gateway would be \
         serving its last good bundle forever, on a Ready pod, with revocation \
         silently not landing.",
        health.failures()
    );
    // …and it really loaded a document, rather than succeeding on an empty one: the
    // revision moved off the seed, which only happens after `parse_bundle` and
    // `pdp.reload` both succeeded on the console's own bytes.
    assert_ne!(
        store.revision(),
        "seed-revision",
        "the poll succeeded but no bundle was applied"
    );
}

/// **Without the credential, it is refused — and refused in a way an operator can
/// see.** This is the assertion that makes the one above mean something: a guard that
/// accepted everything would satisfy the success case just as happily.
#[tokio::test]
#[ignore = "cross-repo LIVE proof; run scripts/live-cross-repo-proof.sh"]
async fn the_bundle_poller_is_refused_without_the_credential() {
    let Some(peer) = peer("the uncredentialed bundle poll") else {
        return;
    };

    // First, exactly what the console answers, so the failure below is attributable to
    // the guard rather than to an outage. 401 specifically — and no ETag, because the
    // ETag is the change-detection oracle over the grant table.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    let resp = client
        .get(peer.s3_gateway_bundle_url())
        .header("If-None-Match", "\"any-revision-at-all\"")
        .send()
        .await
        .expect("the console answered");
    assert_eq!(
        resp.status(),
        401,
        "the s3-gateway bundle answered an uncredentialed conditional request with {}",
        resp.status()
    );
    assert!(
        resp.headers().get("etag").is_none(),
        "an ETag reached an uncredentialed caller: that IS the oracle"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        !body.contains("s3_grants") && !body.contains("tenants"),
        "the refusal body carries bundle content: {body}"
    );

    // …and now the real poller, which must record failures and apply nothing.
    let (pdp, store) = pdp_and_store();
    let source = BundleSource::http(peer.s3_gateway_bundle_url(), Duration::from_secs(10), None)
        .expect("source");
    assert!(!source.is_authenticated());
    let health = Arc::new(BundleHealth::new(true));
    bundle_refresh::spawn(
        pdp,
        store.clone(),
        source,
        Duration::from_millis(250),
        health.clone(),
    );

    assert!(
        until(Duration::from_secs(20), || health.failures() >= 2).await,
        "the uncredentialed poller recorded no failures — the endpoint is still open"
    );
    assert_eq!(
        health.successes(),
        0,
        "an uncredentialed poll SUCCEEDED against the guarded endpoint"
    );
    assert!(!health.ready(), "an uncredentialed gateway reported ready");
    assert_eq!(
        store.revision(),
        "seed-revision",
        "an uncredentialed poll applied a bundle"
    );

    // The positive control on this same server, so "401 for everyone" is excluded.
    let resp = client
        .get(peer.s3_gateway_bundle_url())
        .header(SHARED_SECRET_HEADER, &peer.shared_secret)
        .send()
        .await
        .expect("the console answered");
    assert_eq!(
        resp.status(),
        200,
        "the credentialed caller was refused too, so the 401 above proves nothing"
    );
}

/// **The three sibling routes still serve unauthenticated.**
///
/// `ceph-bundle` and `last-bundle` are polled by the per-Org and per-service OPA
/// deployments, whose bundle plugin takes a URL and cannot present a secret. A 401 on
/// either is not a hardening: it is RGW's own `ceph.authz` PEP frozen on its last good
/// bundle on every cluster that exists today — precisely the breakage the milestone's
/// hard constraint forbids, and precisely what the "obvious" one-line fix (layering the
/// guard on the whole router) would have caused.
#[tokio::test]
#[ignore = "cross-repo LIVE proof; run scripts/live-cross-repo-proof.sh"]
async fn the_opa_polled_sibling_bundles_are_still_unauthenticated() {
    let Some(peer) = peer("the OPA-polled sibling routes") else {
        return;
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");

    for (what, url) in [
        (
            "the per-Org ceph bundle, polled by the org's OPA in front of RGW",
            peer.ceph_bundle_url(),
        ),
        (
            "the per-DataDock last-bundle, polled by the per-service OPA sidecars",
            peer.last_bundle_url(),
        ),
    ] {
        let status = client
            .get(&url)
            .send()
            .await
            .expect("the console answered")
            .status();
        assert_ne!(
            status, 401,
            "{url} now requires a shared secret, but {what} — its poller cannot send \
             one. Every bundle poll on every existing cluster would 401."
        );
    }
}
