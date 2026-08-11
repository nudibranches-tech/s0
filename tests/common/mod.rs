//! Shared fixtures for the integration suite. One definition of each, because a suite
//! that builds them per file drifts into testing a gateway nobody ships:
//!
//! - one gateway builder, running the real `Gateway` over the real shipped rego;
//! - one request seeder mirroring exactly what `S3Access::check` stashes, so a hook
//!   under test sees what it sees in production;
//! - one raw SigV4 signer ([`sigv4`]), so black-box tests exercise the real signature
//!   path rather than an SDK's idea of it.
//!
//! Every gateway built here has the golden-capture tap installed.

#![allow(dead_code)] // each test binary uses a different subset

pub mod ops;
pub mod routes;
pub mod sigv4;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use http::{Extensions, HeaderMap, Method};
use s0::access::OperationName;
use s0::audit::{AuditBackend, AuditConfig, AuditHandle, AuditRecord, spawn_with_backend};
use s0::auth::sts::StsAuthority;
use s0::auth::{Identity, StaticCredentialStore};
use s0::authz::CaptureSink;
use s0::authz::{Decision, OpaInput};
use s0::config::GatewayConfig;
use s0::gateway::Gateway;
use s0::identity::ResolvedPrincipal;
use s0::model::PrincipalType;
use s0::pdp::{Bundle, BundleStore, CachingPdp, GATEWAY_REGO, Pdp, RegorusPdp};
use s0::proxy::BackendRegistry;
use s3s::S3Request;

/// The static credential the black-box tests sign with.
pub const ACCESS_KEY: &str = "AKIAGATEWAYTESTKEY";
pub const SECRET_KEY: &str = "gateway-test-secret";

/// A per-test scratch directory, so parallel test binaries never share a spill file.
pub fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("s0-test-{tag}-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&d).expect("scratch dir");
    d
}

/// The grant fixture most tests run against: `alice` may read/list/write/delete objects
/// (and write their tags) under `reports/2024/`, and may see that the `reports` bucket
/// exists. Nothing anywhere else.
///
/// Two grants, not one: object verbs are narrowed by `prefixes`, while `read` has no key
/// to test a prefix against and is emitted with `"prefixes": []` — the shape the
/// projection is required to produce (ADR-006). `read` is what `HeadBucket`,
/// `GetBucketLocation` and `ListBuckets` all decide against.
///
/// `org_settings.reserved_tag_keys` is **published** here, because the shipped default
/// for an absent list is to refuse every tag write (`access::tagging`); the inert path
/// has its own bundle, [`bundle_without_reserved_tag_keys`].
pub fn alice_bundle() -> serde_json::Value {
    serde_json::json!({
        "org_settings": {
            "freeze_writes": false,
            // A control-plane-owned namespace, the shape a real one emits: policy
            // conditions live under it, so no S3 caller may write into it.
            "reserved_tag_keys": ["acme/*"]
        },
        "tenants": { "acme": {
            "user_attributes": { "alice": { "groups": [], "attributes": [] } },
            "bucket_attributes": { "reports": { "denylist": {} } },
            "s3_grants": { "alice": [
                { "bucket": "reports",
                  "actions": ["read_objects", "list_objects", "write_objects", "delete_objects",
                              "write_object_tags"],
                  "prefixes": ["2024/"] },
                { "bucket": "reports",
                  "actions": ["read"],
                  "prefixes": [] }
            ] },
            "group_grants": {}
        }}
    })
}

/// [`alice_bundle`] with the reserved-key list **removed** — the state a deployment is
/// in until the control plane publishes one.
///
/// Tag writes are inert under it: `PutObjectTagging`, `DeleteObjectTagging` and an
/// inline `x-amz-tagging` on a write are all refused. It needs its own fixture precisely
/// because that is a *default*: a test that only ever ran against a published list would
/// not notice if absence started meaning "reserve nothing".
pub fn bundle_without_reserved_tag_keys() -> serde_json::Value {
    let mut bundle = alice_bundle();
    bundle["org_settings"]
        .as_object_mut()
        .expect("org_settings")
        .remove("reserved_tag_keys");
    bundle
}

/// The gateway config every fixture shares. `backend_endpoint` decides how far an
/// *allowed* request gets: point it at a closed port and the forward fails loudly
/// instead of silently succeeding against something real.
pub fn config_json(dir: &std::path::Path, backend_endpoint: &str) -> String {
    serde_json::json!({
        "listen": "127.0.0.1:0",
        "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
        "pdp": { "mode": "embedded" },
        "audit": { "sink_url": "http://127.0.0.1:59999/none",
                   "spill_path": dir.join("audit.ndjson") },
        "backends": [
            { "id": "bay-1", "kind": "ceph", "endpoint_url": backend_endpoint }
        ],
        "tenants": [
            { "tenant": "acme", "organization_id": "org-acme", "backend_id": "bay-1",
              "owner_access_key": "OWNER", "owner_secret_key": "OWNERSECRET" }
        ],
        "static_credentials": [
            { "access_key_id": ACCESS_KEY, "secret_access_key": SECRET_KEY,
              "principal_sub": "alice", "tenant": "acme", "organization_id": "org-acme" }
        ],
        "bundle_path": "/dev/null"
    })
    .to_string()
}

/// Counts every `decide` the enforce path issues, from **outside** the decision cache.
///
/// Makes "`GatewayAccess::decide` is the only PDP call site" checkable: a hook calling
/// `gw.pdp.decide` directly bumps this counter without producing a capture, and
/// `tests/golden_capture.rs` compares the two.
struct CountingPdp {
    inner: Arc<dyn Pdp>,
    calls: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl Pdp for CountingPdp {
    async fn decide(&self, input: &OpaInput) -> s0::error::Result<Decision> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.inner.decide(input).await
    }

    async fn reload(
        &self,
        policy: Option<&str>,
        data: &serde_json::Value,
    ) -> s0::error::Result<()> {
        self.inner.reload(policy, data).await
    }
}

/// Everything the gateway actually recorded, in order.
///
/// An [`AuditBackend`] rather than a tap on the sink, so it sees exactly what a real
/// destination would: post-batch, post-worker, after the record has round-tripped
/// through the queue.
#[derive(Default)]
pub struct RecordedAudit(std::sync::Mutex<Vec<AuditRecord>>);

#[async_trait::async_trait]
impl AuditBackend for RecordedAudit {
    fn name(&self) -> &'static str {
        "test-recorder"
    }

    async fn ship(&self, batch: &[AuditRecord]) -> Result<(), String> {
        self.0
            .lock()
            .expect("recorded audit")
            .extend_from_slice(batch);
        Ok(())
    }
}

impl RecordedAudit {
    pub fn all(&self) -> Vec<AuditRecord> {
        self.0.lock().expect("recorded audit").clone()
    }
}

/// An assembled test gateway plus the handles a test must keep alive.
pub struct Fixture {
    pub gw: Arc<Gateway>,
    pub capture: Arc<CaptureSink>,
    pub cfg: GatewayConfig,
    /// Dropping this drops the audit worker, after which every `emit` logs an error.
    pub audit: AuditHandle,
    /// What the gateway shipped to its audit backend.
    pub audit_log: Arc<RecordedAudit>,
    pub dir: PathBuf,
    pdp_calls: Arc<AtomicUsize>,
}

/// Build a gateway over `bundle`, with the golden-capture tap installed.
///
/// Deliberately constructed field-by-field rather than through `Gateway::build`:
/// `build` hard-codes `capture: None` (see `authz::capture`), which is the property
/// that keeps capture out of every deployed binary.
pub fn fixture(tag: &str, bundle: serde_json::Value) -> Fixture {
    // Port 1 is closed, deliberately: a request that reaches the forward path fails
    // loudly instead of quietly succeeding against something real, so "was this
    // forwarded?" is observable without a backend.
    fixture_with_backend(tag, bundle, "http://127.0.0.1:1")
}

/// [`fixture`] pointed at a backend that answers — for the tests that must observe what
/// the gateway does to a *response*.
pub fn fixture_with_backend(tag: &str, bundle: serde_json::Value, endpoint: &str) -> Fixture {
    let dir = scratch(tag);
    let cfg = GatewayConfig::from_json(&config_json(&dir, endpoint)).expect("config");
    let bundles = Arc::new(BundleStore::new(Bundle::new("rev-1", bundle.clone())));
    let engine = RegorusPdp::new(GATEWAY_REGO, &bundle).expect("regorus");
    let pdp_calls = Arc::new(AtomicUsize::new(0));
    let pdp: Arc<dyn Pdp> = Arc::new(CountingPdp {
        inner: Arc::new(CachingPdp::new(
            Arc::new(engine) as Arc<dyn Pdp>,
            bundles.clone(),
            1000,
        )),
        calls: pdp_calls.clone(),
    });
    // The static store is populated from the same config the registry uses, so a
    // black-box test signs with a credential the gateway really knows. An empty store
    // here would make every signed request fail with InvalidAccessKeyId — a 403 that
    // looks exactly like a gate denial.
    let credentials = Arc::new(StaticCredentialStore::from_config(&cfg));
    let identity = Arc::new(Identity::new(
        Arc::new(StsAuthority::new(vec![0u8; 32], vec![1u8; 32]).unwrap()),
        credentials.clone(),
    ));
    let registry = Arc::new(BackendRegistry::from_config(&cfg).unwrap());
    let audit_log = Arc::new(RecordedAudit::default());
    let (audit_sink, audit) = spawn_with_backend(
        AuditConfig {
            sink_url: cfg.audit.sink_url.clone(),
            spill_path: cfg.audit.spill_path.clone(),
            instance: tag.to_string(),
            // One record per batch, so a record is shipped on the worker's next poll
            // rather than on the flush ticker: `await_audit_records` then converges in
            // milliseconds instead of racing a 2 s timer.
            batch_max: 1,
            ..AuditConfig::default()
        },
        audit_log.clone(),
    );
    let capture = Arc::new(CaptureSink::new(4096));
    let gw = Arc::new(Gateway {
        identity,
        pdp,
        audit: audit_sink,
        registry,
        credentials,
        limits: Arc::new(arc_swap::ArcSwap::from_pointee(cfg.limits.clone())),
        bundles,
        capture: Some(capture.clone()),
    });
    Fixture {
        gw,
        capture,
        cfg,
        audit,
        audit_log,
        dir,
        pdp_calls,
    }
}

pub fn principal(sub: &str) -> ResolvedPrincipal {
    ResolvedPrincipal {
        sub: sub.into(),
        principal_type: PrincipalType::User,
        groups: vec![],
        tenant: "acme".into(),
        organization_id: "org-acme".into(),
    }
}

/// Seed a request exactly as `S3Access::check` does: the resolved principal, the
/// secret-free route snapshot, and the s3s op name. A hook that runs without all three
/// fails closed, so a test that skipped this would measure the backstop, not the policy.
/// The route snapshot comes from a real `BackendRegistry` over the same config the
/// gateway uses, so the fixture cannot drift from the routing it claims to model.
pub fn seeded_request<T>(
    cfg: &GatewayConfig,
    principal: ResolvedPrincipal,
    op: &str,
    input: T,
    method: Method,
    uri: &str,
) -> S3Request<T> {
    let registry = BackendRegistry::from_config(cfg).expect("registry");
    let route = registry
        .route_snapshot(&principal.tenant)
        .expect("tenant routable");
    let mut extensions = Extensions::new();
    extensions.insert(Arc::new(route));
    extensions.insert(Arc::new(principal));
    extensions.insert(OperationName(op.into()));
    S3Request {
        input,
        method,
        uri: uri.parse().expect("request uri"),
        headers: HeaderMap::new(),
        extensions,
        credentials: None,
        region: None,
        service: None,
        trailing_headers: None,
    }
}

impl Fixture {
    /// [`seeded_request`] bound to this fixture's config and to `alice`.
    pub fn request<T>(&self, op: &str, input: T, method: Method) -> S3Request<T> {
        seeded_request(&self.cfg, principal("alice"), op, input, method, "/")
    }

    pub fn request_as<T>(&self, sub: &str, op: &str, input: T, method: Method) -> S3Request<T> {
        seeded_request(&self.cfg, principal(sub), op, input, method, "/")
    }

    /// A request carrying the real method and URI this operation arrives with, taken
    /// from the s3s route table. Used by the capture harness: `RequestMeta` is derived
    /// from both, so a corpus built from `GET /` would record a method and a query
    /// string no client ever sends.
    pub fn request_on_route<T>(&self, op: &str, input: T) -> S3Request<T> {
        let route = routes::route(op);
        seeded_request(
            &self.cfg,
            principal("alice"),
            op,
            input,
            route.method.parse().expect("http method"),
            &route.request_target(),
        )
    }

    /// How many decisions the enforce path has asked for, counted outside the cache.
    pub fn pdp_calls(&self) -> usize {
        self.pdp_calls.load(Ordering::Relaxed)
    }

    /// Wait until at least `n` records have reached the audit backend, then hold still
    /// for a grace period and return everything. The grace period is the point:
    /// "exactly one record" is only checkable if a second one had a chance to arrive,
    /// and shipping is asynchronous by design.
    pub async fn await_audit_records(&self, n: usize) -> Vec<AuditRecord> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while self.audit_log.all().len() < n && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        self.audit_log.all()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
