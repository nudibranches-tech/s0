//! What has to hold before s0 can run as N replicas behind one Service.
//!
//! Every property here is one a single-replica deployment never exercises and a
//! rolling update exercises on every deploy:
//!
//! - a listener that does not observe SIGTERM while idle is *killed*, not drained;
//! - a readiness probe that passes before the pod has reached the control plane puts
//!   a stale-policy replica into the Service;
//! - two replicas sharing a spill file destroy each other's audit records.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use s0::admin::{self, AdminState};
use s0::audit::{self, AuditConfig, AuditRecord, BackendOutcome, GatewayMeta, Outcome};
use s0::auth::sts::StsAuthority;
use s0::auth::{Identity, StaticCredentialStore};
use s0::authz::{Backend, Decision, OpaInput, Principal, PrincipalAttributes, RequestMeta};
use s0::bundle_refresh::{self, BundleHealth, BundleSource};
use s0::config::GatewayConfig;
use s0::gateway::Gateway;
use s0::mint::{self, Mint, OidcVerifier, VerifiedIdentity};
use s0::model::{Action, BackendKind, PrincipalType};
use s0::pdp::{Bundle, BundleStore, GATEWAY_REGO, Pdp, RegorusPdp};
use s0::proxy::BackendRegistry;
use s0::server;

// ── fixtures ────────────────────────────────────────────────────────────────────

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("s0-ha-{tag}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("tmpdir");
    d
}

fn bundle_json() -> serde_json::Value {
    serde_json::json!({
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": {}, "bucket_attributes": {},
            "s3_grants": {}, "group_grants": {}
        }}
    })
}

async fn test_gateway(dir: &std::path::Path) -> Arc<Gateway> {
    let cfg = GatewayConfig::from_json(
        &serde_json::json!({
            "listen": "127.0.0.1:0",
            "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
            "pdp": { "mode": "embedded" },
            "audit": { "sink_url": "http://127.0.0.1:59999/none",
                       "spill_path": dir.join("audit.ndjson") },
            "backends": [{ "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:7480" }],
            "tenants": [{ "tenant": "acme", "organization_id": "org-acme", "backend_id": "bay-1",
                          "owner_access_key": "OWNER", "owner_secret_key": "OWNERSECRET" }],
            "bundle_path": "/dev/null"
        })
        .to_string(),
    )
    .expect("config");
    let data = bundle_json();
    let bundles = Arc::new(BundleStore::new(Bundle::new("rev-seeded", data.clone())));
    let pdp: Arc<dyn Pdp> = Arc::new(RegorusPdp::new(GATEWAY_REGO, &data).expect("regorus"));
    let (audit, _handle) = audit::spawn(AuditConfig {
        sink_url: cfg.audit.sink_url.clone(),
        spill_path: cfg.audit.spill_path.clone(),
        ..AuditConfig::default()
    });
    let credentials = Arc::new(StaticCredentialStore::new());
    Arc::new(Gateway {
        identity: Arc::new(Identity::new(
            Arc::new(StsAuthority::new(vec![0u8; 32], vec![1u8; 32]).unwrap()),
            credentials.clone(),
        )),
        pdp,
        audit,
        registry: Arc::new(BackendRegistry::from_config(&cfg).unwrap()),
        credentials,
        limits: Arc::new(arc_swap::ArcSwap::from_pointee(cfg.limits.clone())),
        bundles,
        capture: None,
    })
}

fn record(id: &str) -> AuditRecord {
    AuditRecord::new(
        id.to_string(),
        "2026-07-27T00:00:00Z".into(),
        OpaInput {
            principal: Principal {
                sub: "alice".into(),
                kind: PrincipalType::User,
                attributes: PrincipalAttributes::default(),
            },
            backend: Backend {
                id: "bay-1".into(),
                kind: BackendKind::Ceph,
            },
            tenant: "acme".into(),
            organization_id: "org-acme".into(),
            action: Action::ReadObjects,
            bucket: "reports".into(),
            object: Some(format!("{id}.csv")),
            prefix: None,
            copy_source: None,
            delete_keys: None,
            object_tags: None,
            request: RequestMeta::default(),
        },
        Decision::allow("grant matched"),
        GatewayMeta {
            backend_id: "bay-1".into(),
            backend_kind: "ceph".into(),
            outcome: Outcome::Allowed,
            denied_keys: vec![],
            backend: BackendOutcome::NotAttempted,
            backend_status: None,
        },
    )
}

async fn get(port: u16, path: &str) -> (u16, String) {
    let url = format!("http://127.0.0.1:{port}{path}");
    let resp = reqwest::Client::new()
        .get(&url)
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("admin request");
    let status = resp.status().as_u16();
    (status, resp.text().await.unwrap_or_default())
}

// ── graceful shutdown ───────────────────────────────────────────────────────────

#[tokio::test]
async fn sigterm_on_an_idle_listener_drains_immediately() {
    let dir = tmpdir("s3-drain");
    let gw = test_gateway(&dir).await;
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let listener = tokio::spawn(async move {
        server::serve_with_shutdown(gw, "127.0.0.1:0".parse().unwrap(), async {
            let _ = stopped.await;
        })
        .await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;
    stop.send(()).expect("listener still running");

    // The accept was previously awaited OUTSIDE the shutdown select, so an idle
    // listener only noticed the signal when the next connection happened to arrive —
    // i.e. never, on a quiet pod, until the grace period killed it.
    let exited = tokio::time::timeout(Duration::from_secs(2), listener)
        .await
        .expect("an idle listener must drain promptly, not wait for a connection");
    exited.expect("join").expect("clean exit");
    let _ = std::fs::remove_dir_all(dir);
}

struct FixedVerifier;
#[async_trait::async_trait]
impl OidcVerifier for FixedVerifier {
    async fn verify(&self, _token: &str) -> s0::error::Result<VerifiedIdentity> {
        Ok(VerifiedIdentity {
            sub: "alice".into(),
            groups: vec![],
            tenant: "acme".into(),
            org: "org-acme".into(),
        })
    }
}

#[tokio::test]
async fn the_mint_serves_then_drains_on_shutdown() {
    // `mint::serve` was an infinite accept loop with no signal handling, so its task
    // was aborted when main returned — every rolling update produced sporadic mint
    // failures that looked like IdP flakiness.
    let sts = Arc::new(StsAuthority::new(vec![4u8; 32], vec![8u8; 32]).unwrap());
    let mint = Arc::new(Mint::new(
        Arc::new(FixedVerifier),
        sts,
        Duration::from_secs(900),
    ));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let task = tokio::spawn(async move {
        mint::serve_with_shutdown(mint, addr, async {
            let _ = stopped.await;
        })
        .await
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // It really is serving before we shut it down — otherwise a listener that exited
    // instantly would pass the drain assertion below.
    let resp = reqwest::Client::new()
        .post(format!("http://{addr}/"))
        .header("authorization", "Bearer any")
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .expect("mint reachable");
    assert_eq!(resp.status().as_u16(), 200);
    assert!(resp.text().await.unwrap().contains("AccessKeyId"));

    stop.send(()).expect("mint still running");
    let exited = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("an idle mint must drain promptly");
    exited.expect("join").expect("clean exit");
}

// ── admin listener ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn readiness_waits_for_a_real_poll_then_metrics_report_the_state() {
    let dir = tmpdir("admin");
    let bundle_file = dir.join("bundle.json");
    std::fs::write(&bundle_file, bundle_json().to_string()).unwrap();

    let (sink, _audit) = audit::spawn(AuditConfig {
        sink_url: "http://127.0.0.1:59999/none".into(),
        spill_path: dir.join("audit.ndjson"),
        instance: "pod-admin".into(),
        ..AuditConfig::default()
    });
    // The store is seeded with a revision at build time — exactly what makes a
    // "revision is non-empty" readiness check vacuous.
    let bundles = Arc::new(BundleStore::new(Bundle::new("rev-seeded", bundle_json())));
    let health = Arc::new(BundleHealth::new(false));
    let state = Arc::new(AdminState::new(&sink, health.clone(), bundles.clone()));

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let admin_task = {
        let state = state.clone();
        tokio::spawn(async move {
            admin::serve_with_shutdown(state, addr, async {
                let _ = stopped.await;
            })
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    let port = addr.port();

    // Liveness is up immediately and never depends on the control plane: if it did, a
    // control-plane outage would restart every replica in the fleet.
    assert_eq!(get(port, "/healthz").await.0, 200);

    // Readiness is NOT up, despite a non-empty bundle revision being in force.
    let (status, body) = get(port, "/readyz").await;
    assert_eq!(
        status, 503,
        "a pod that has never polled must not join the Service"
    );
    assert!(body.contains("no successful bundle poll"), "{body}");
    assert_eq!(
        bundles.revision(),
        "rev-seeded",
        "…even though a revision is seeded"
    );

    // Now run the real poller against a real source.
    let pdp: Arc<dyn Pdp> =
        Arc::new(RegorusPdp::new(GATEWAY_REGO, &bundle_json()).expect("regorus"));
    bundle_refresh::spawn(
        pdp,
        bundles.clone(),
        BundleSource::File(bundle_file),
        Duration::from_millis(20),
        health.clone(),
    );

    let mut ready = false;
    for _ in 0..100 {
        if get(port, "/readyz").await.0 == 200 {
            ready = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(ready, "readiness must follow a successful poll");

    // Metrics: the audit drop counter is the whole reason this endpoint exists.
    let (status, metrics) = get(port, "/metrics").await;
    assert_eq!(status, 200);
    assert!(
        metrics.contains("\ns0_audit_dropped_total 0\n"),
        "{metrics}"
    );
    assert!(metrics.contains("s0_ready 1"), "{metrics}");
    assert!(
        metrics.contains("s0_bundle_poll_success_total"),
        "{metrics}"
    );
    assert!(
        metrics.contains("s0_bundle_source_remote 0"),
        "a file-backed bundle must not claim control-plane reachability: {metrics}"
    );

    // A pod on the way out fails readiness while it is still answering, so the
    // endpoint controller pulls it before it stops accepting.
    state.begin_shutdown();
    assert_eq!(get(port, "/readyz").await.0, 503);
    assert_eq!(
        get(port, "/healthz").await.0,
        200,
        "still alive while draining"
    );
    assert_eq!(get(port, "/nope").await.0, 404);

    let _ = stop.send(());
    let _ = tokio::time::timeout(Duration::from_secs(2), admin_task).await;
    let _ = std::fs::remove_dir_all(dir);
}

// ── multi-replica audit spill ───────────────────────────────────────────────────

#[tokio::test]
async fn two_workers_do_not_destroy_each_others_spill() {
    // Two replicas, one configured spill path (a shared RWX volume, or a ConfigMap
    // whose ${POD_NAME} was never interpolated). Before the ownership claim, whichever
    // replica replayed first deleted the whole file — including records the other had
    // appended and it had never read. Silently.
    let dir = tmpdir("spill");
    let shared = dir.join("audit-spill.ndjson");

    let cfg = |instance: &str| AuditConfig {
        // Unroutable sink, so every record takes the spill path.
        sink_url: "http://127.0.0.1:1/none".into(),
        spill_path: shared.clone(),
        instance: instance.to_string(),
        flush_interval: Duration::from_millis(20),
        http_timeout: Duration::from_millis(50),
        batch_max: 4,
        ..AuditConfig::default()
    };

    let (sink_a, handle_a) = audit::spawn(cfg("pod-a"));
    let (sink_b, handle_b) = audit::spawn(cfg("pod-b"));

    for i in 0..8 {
        sink_a.emit(record(&format!("a-{i}")));
        sink_b.emit(record(&format!("b-{i}")));
    }
    // Long enough for both workers to flush, fail to POST, spill, and run several
    // replay passes against each other.
    tokio::time::sleep(Duration::from_millis(300)).await;
    handle_a.drain(Duration::from_secs(2)).await;
    handle_b.drain(Duration::from_secs(2)).await;

    // Collect (file, decision_ids) for every spill file in the directory.
    let mut files: Vec<(PathBuf, Vec<String>)> = Vec::new();
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("ndjson") {
            continue; // `.owner` markers
        }
        let ids: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| {
                let v: serde_json::Value =
                    serde_json::from_str(l).expect("a spill line must be intact JSON");
                v["decision_id"].as_str().unwrap().to_string()
            })
            .collect();
        files.push((path, ids));
    }
    files.sort_by_key(|(p, _)| p.clone());

    // THE property: the two replicas are not writing the same file. Everything else
    // about spill correctness — read-whole, POST, delete-whole — is only sound for a
    // single writer, so this is the precondition, not a nicety.
    assert_eq!(
        files.len(),
        2,
        "two replicas must not share one spill file; found {:?}",
        files.iter().map(|(p, _)| p).collect::<Vec<_>>()
    );
    for (path, ids) in &files {
        let owner = if path.to_string_lossy().contains("pod-b") {
            "b-"
        } else {
            "a-"
        };
        assert!(
            ids.iter().all(|id| id.starts_with(owner)),
            "{path:?} mixes records from both replicas: {ids:?}"
        );
    }

    // And nothing was lost along the way.
    let mut ids: Vec<String> = files.iter().flat_map(|(_, ids)| ids.clone()).collect();
    ids.sort();
    let mut expected: Vec<String> = (0..8)
        .flat_map(|i| [format!("a-{i}"), format!("b-{i}")])
        .collect();
    expected.sort();
    assert_eq!(
        ids, expected,
        "every emitted record must still be on disk, each in its owner's file"
    );

    // Both workers have now exited with a non-empty spill file. That is not "pending":
    // the spill is node-local scratch that dies with the pod, so the honest count is
    // lost — and it must show up in the exported total, which is the whole reason the
    // total exists. (Before this was wired, these 16 records were reported as pending
    // and `dropped_total` was 0 on precisely the shutdown where audit loss happens.)
    for (who, sink) in [("a", &sink_a), ("b", &sink_b)] {
        let m = sink.metrics();
        assert_eq!(
            m.spill_abandoned.load(Ordering::Relaxed),
            8,
            "replica {who} left 8 records in the spill at exit and must say so"
        );
        assert!(
            sink.dropped_total() >= 8,
            "replica {who}: abandoned spill must reach s0_audit_dropped_total, got {}",
            sink.dropped_total()
        );
        assert_eq!(
            m.queue_dropped.load(Ordering::Relaxed),
            0,
            "replica {who} must not have lost anything at the queue"
        );
    }

    let _ = std::fs::remove_dir_all(dir);
}
