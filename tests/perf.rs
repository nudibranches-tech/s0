//! Performance budget gate. Loose thresholds — generous enough not to flake
//! on shared CI runners, tight enough to catch a gross regression (e.g. someone makes
//! the decision path 100× slower). The actual numbers are printed so the budget is
//! visible. Target: PDP decision sub-ms cached, low-ms uncached; zero body copies on
//! GET/PUT (already true on the s3s streaming path).

use std::sync::Arc;
use std::time::Instant;

use s0::authz::OpaInput;
use s0::pdp::{Bundle, BundleStore, CachingPdp, GATEWAY_REGO, Pdp, RegorusPdp};

fn bundle() -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": ["analysts"], "attributes": [] } },
            "bucket_attributes": { "reports": { "denylist": {} } },
            "s3_grants": { "alice": [
                { "bucket": "reports", "actions": ["read_objects"], "prefixes": ["2024/"] }
            ] },
            "group_grants": {}
        }}
    })
}

fn input() -> OpaInput {
    serde_json::from_value(serde_json::json!({
        "principal": { "sub": "alice", "type": "user", "attributes": { "groups": ["analysts"] } },
        "backend": { "id": "bay-1", "kind": "ceph" },
        "tenant": "acme",
        "organization_id": "org-acme",
        "action": "read_objects",
        "bucket": "reports",
        "object": "2024/q1.csv",
        "request": { "method": "GET" }
    }))
    .unwrap()
}

#[tokio::test]
async fn decision_latency_budget() {
    let data = bundle();
    let regorus = RegorusPdp::new(GATEWAY_REGO, &data).unwrap();
    let inp = input();

    // Warm up (first eval pays prepare).
    for _ in 0..50 {
        regorus.decide(&inp).await.unwrap();
    }

    // Uncached: regorus re-evaluates every call.
    let n = 2000;
    let start = Instant::now();
    for _ in 0..n {
        let d = regorus.decide(&inp).await.unwrap();
        assert!(d.allow);
    }
    let uncached_us = start.elapsed().as_micros() as f64 / n as f64;

    // Cached: revision-keyed cache hits after the first.
    let bundles = Arc::new(BundleStore::new(Bundle::new("rev-1", data.clone())));
    let cached = CachingPdp::new(
        Arc::new(RegorusPdp::new(GATEWAY_REGO, &data).unwrap()) as Arc<dyn Pdp>,
        bundles,
        10_000,
    );
    cached.decide(&inp).await.unwrap();
    let start = Instant::now();
    for _ in 0..n {
        cached.decide(&inp).await.unwrap();
    }
    let cached_us = start.elapsed().as_micros() as f64 / n as f64;

    eprintln!("PDP decide: uncached ~{uncached_us:.1}µs, cached ~{cached_us:.1}µs");

    // Loose regression gate.
    assert!(
        uncached_us < 2000.0,
        "uncached decide {uncached_us:.1}µs exceeds 2ms budget"
    );
    assert!(
        cached_us < 500.0,
        "cached decide {cached_us:.1}µs exceeds 500µs budget"
    );
}
