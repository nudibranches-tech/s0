//! The admin listener: liveness, readiness, and metrics, on a port of its own.
//!
//! Separate from the S3 data plane because these endpoints are unauthenticated (a probe
//! cannot sign SigV4); they expose no policy data, no principal and no secret. The
//! runtime image is distroless, so an HTTP probe is the only one available — a TCP check
//! on the S3 port would pass on a pod that never reached the control plane.
//!
//! **Liveness never depends on the control plane**: failing `/healthz` on a stale bundle
//! would turn a control-plane outage into a fleet-wide restart. Readiness fails *before*
//! the data plane stops accepting, so the pod leaves the Service while it still drains.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use tokio::net::TcpListener;

use crate::audit::{AuditMetrics, AuditSink};
use crate::bundle_refresh::BundleHealth;
use crate::error::Result;
use crate::mint::MintMetrics;
use crate::pdp::BundleStore;

/// In-flight probe/scrape budget on shutdown. Probes are sub-millisecond; anything
/// still running past this is stuck.
const ADMIN_DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

/// What the admin endpoints report on. Cheap to clone (all `Arc`s).
pub struct AdminState {
    audit: Arc<AuditMetrics>,
    health: Arc<BundleHealth>,
    bundles: Arc<BundleStore>,
    /// The mint listener's counters, when this process runs a mint.
    ///
    /// `Option` rather than a zeroed struct: a gateway with no `sts_mint` section binds
    /// no mint port, and a structurally-0 `s0_mint_*` series would put a flat line on a
    /// dashboard where the honest answer is "this pod has no mint".
    mint: Option<Arc<MintMetrics>>,
    instance: String,
    shutting_down: AtomicBool,
}

impl AdminState {
    pub fn new(audit: &AuditSink, health: Arc<BundleHealth>, bundles: Arc<BundleStore>) -> Self {
        AdminState {
            audit: audit.metrics(),
            health,
            bundles,
            mint: None,
            instance: crate::config::instance_id(),
            shutting_down: AtomicBool::new(false),
        }
    }

    /// Publish the mint listener's bounds and counters. Call it only when a mint
    /// is actually served; see the field docs.
    #[must_use]
    pub fn with_mint_metrics(mut self, metrics: Arc<MintMetrics>) -> Self {
        self.mint = Some(metrics);
        self
    }

    /// Start failing readiness. Call on the shutdown signal, *before* the data plane
    /// stops accepting: kubernetes needs a failing `/readyz` to take this pod out of
    /// the Service, and it only learns that by polling.
    pub fn begin_shutdown(&self) {
        self.shutting_down.store(true, Ordering::Relaxed);
    }

    fn ready(&self) -> std::result::Result<(), &'static str> {
        if self.shutting_down.load(Ordering::Relaxed) {
            return Err("shutting down");
        }
        if !self.health.ready() {
            return Err("no successful bundle poll yet");
        }
        Ok(())
    }
}

/// Serve the admin endpoints until the caller triggers shutdown.
///
/// Note the shutdown trigger is a caller-supplied future, not the process signal: the
/// admin listener must outlive the data plane's drain so probes keep being answered
/// (with a failing `/readyz`) for as long as the pod is still working.
pub async fn serve_with_shutdown(
    state: Arc<AdminState>,
    listen: SocketAddr,
    shutdown: impl std::future::Future<Output = ()> + Send,
) -> Result<()> {
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, "admin listening (/healthz /readyz /metrics)");
    let http = ConnBuilder::new(TokioExecutor::new());
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);

    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = &mut shutdown => break,
        };
        let (stream, _) = match accepted {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%e, "admin accept failed; backing off");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let state = state.clone();
        let svc = service_fn(move |req: Request<Incoming>| {
            let state = state.clone();
            async move { Ok::<_, std::convert::Infallible>(route(&state, req)) }
        });
        let conn = http
            .serve_connection(TokioIo::new(stream), svc)
            .into_owned();
        let conn = graceful.watch(conn);
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }

    tokio::select! {
        _ = graceful.shutdown() => tracing::info!("admin connections drained"),
        _ = tokio::time::sleep(ADMIN_DRAIN_TIMEOUT) => {
            tracing::warn!("admin drain timed out");
        }
    }
    Ok(())
}

fn route(state: &AdminState, req: Request<Incoming>) -> Response<Full<Bytes>> {
    // GET and HEAD only: kubernetes `httpGet` probes issue GET, and nothing here has
    // side effects. (A drain endpoint would need POST, which `httpGet` cannot send —
    // hence `begin_shutdown` being driven by the signal, not by a request.)
    if req.method() != Method::GET && req.method() != Method::HEAD {
        return text(StatusCode::METHOD_NOT_ALLOWED, "use GET\n");
    }
    match req.uri().path() {
        "/healthz" => text(StatusCode::OK, "ok\n"),
        "/readyz" => match state.ready() {
            Ok(()) => text(StatusCode::OK, "ready\n"),
            Err(why) => text(
                StatusCode::SERVICE_UNAVAILABLE,
                &format!("not ready: {why}\n"),
            ),
        },
        "/metrics" => prometheus(state),
        _ => text(StatusCode::NOT_FOUND, "not found\n"),
    }
}

fn text(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(body.to_string())))
        .expect("static response")
}

/// Prometheus text exposition. Hand-rolled: the counter set is small and fixed, and a
/// client library would be a dependency plus a registry to keep in sync with the
/// counters that already exist.
fn prometheus(state: &AdminState) -> Response<Full<Bytes>> {
    let m = &state.audit;
    let h = &state.health;
    let mut out = String::with_capacity(2048);

    metric(
        &mut out,
        "s0_audit_dropped_total",
        "counter",
        "Audit records this process is known to have LOST, from any cause. Any \
         non-zero value is an audit-integrity incident; alert on increase.",
        m.dropped_total(),
    );
    metric(
        &mut out,
        "s0_audit_queue_dropped_total",
        "counter",
        "Audit records dropped because the in-process queue was full or the worker \
         was gone.",
        m.queue_dropped.load(Ordering::Relaxed),
    );
    metric(
        &mut out,
        "s0_audit_spill_dropped_total",
        "counter",
        "Audit records lost at the disk spill: file at cap, write failed, or a \
         spilled line came back unparseable.",
        m.spill_dropped.load(Ordering::Relaxed),
    );
    metric(
        &mut out,
        "s0_audit_shipped_total",
        "counter",
        "Audit records the control plane accepted.",
        m.shipped.load(Ordering::Relaxed),
    );
    metric(
        &mut out,
        "s0_audit_spilled_total",
        "counter",
        "Audit records written to the local spill file after a failed ship. Pending \
         while the process lives; anything still there when it exits is counted in \
         s0_audit_spill_abandoned_total instead, because the spill is node-local and \
         dies with the pod.",
        m.spilled.load(Ordering::Relaxed),
    );
    metric(
        &mut out,
        "s0_audit_spill_abandoned_total",
        "counter",
        "Audit records still in the spill file when the worker exited. LOST: the spill \
         is node-local scratch, deleted with the pod. Included in \
         s0_audit_dropped_total. Non-zero after a rolling update means the sink was \
         down for the whole drain.",
        m.spill_abandoned.load(Ordering::Relaxed),
    );
    metric(
        &mut out,
        "s0_audit_gate_suppressed_total",
        "counter",
        "Gate-denial records deliberately not emitted because the budget was exhausted \
         — an unauthenticated caller can produce these without limit, and letting them \
         fill the queue would evict real decision records. NOT counted as dropped: the \
         count is preserved here and on the next emitted gate record. Sustained \
         non-zero means someone is scanning.",
        m.gate_suppressed.load(Ordering::Relaxed),
    );
    metric(
        &mut out,
        "s0_audit_spill_replayed_total",
        "counter",
        "Audit records recovered from the spill file and shipped.",
        m.spill_replayed.load(Ordering::Relaxed),
    );
    metric(
        &mut out,
        "s0_audit_post_failures_total",
        "counter",
        "Failed POSTs to the audit sink (batches, not records).",
        m.post_failures.load(Ordering::Relaxed),
    );
    metric(
        &mut out,
        "s0_bundle_poll_success_total",
        "counter",
        "Bundle polls that fetched and applied successfully.",
        h.successes(),
    );
    metric(
        &mut out,
        "s0_bundle_poll_failure_total",
        "counter",
        "Bundle polls that failed. Sustained failure means revocation is not landing.",
        h.failures(),
    );
    metric(
        &mut out,
        "s0_bundle_last_success_timestamp_seconds",
        "gauge",
        "Unix time of the last successful bundle poll; 0 if there has never been one. \
         Bundle age is the alertable signal for a stale policy.",
        h.last_success_unix().unwrap_or(0),
    );
    metric(
        &mut out,
        "s0_bundle_source_remote",
        "gauge",
        "1 when the bundle is polled from the control plane, 0 when it is a local \
         file (development). Readiness on a local-file source proves nothing about \
         control-plane reachability.",
        h.is_remote() as u64,
    );
    metric(
        &mut out,
        "s0_ready",
        "gauge",
        "1 when /readyz would answer 200.",
        state.ready().is_ok() as u64,
    );

    // The mint listener. Present only on a pod that serves one — see `AdminState::mint`.
    // These are the only numbers that distinguish "the credential path is bounded and the
    // bound is biting" from "the identity provider is broken".
    if let Some(m) = &state.mint {
        metric(
            &mut out,
            "s0_mint_connection_limit",
            "gauge",
            "Configured sts_mint.max_connections. The saturation counter below is \
             meaningless without it.",
            m.connection_limit.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "s0_mint_connections_active",
            "gauge",
            "Mint connections currently being served. Approaching \
             s0_mint_connection_limit means the next connection waits.",
            m.connections_active.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "s0_mint_connections_accepted_total",
            "counter",
            "Mint connections accepted since start.",
            m.connections_accepted.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "s0_mint_connection_limit_saturated_total",
            "counter",
            "Times the mint's connection bound was already full when the accept loop \
             asked for a slot, so the next connection waited in the kernel backlog. \
             NOT a refusal — no mint is answered with an error because of this — but \
             sustained increase means either raise sts_mint.max_connections or find \
             out who is calling. This socket is unauthenticated by design.",
            m.connection_limit_saturated.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "s0_mint_connection_timeouts_total",
            "counter",
            "Mint connections closed for outliving sts_mint.connection_timeout_secs. \
             A legitimate client never reaches this; sustained increase is a slow-client \
             (slowloris) attempt to hold every connection slot.",
            m.connection_timeouts.load(Ordering::Relaxed),
        );
        metric(
            &mut out,
            "s0_mint_bodies_too_large_total",
            "counter",
            "Mint requests refused 413 for exceeding the body ceiling. The oversized \
             bytes were never read off the socket.",
            m.bodies_too_large.load(Ordering::Relaxed),
        );
    }

    out.push_str("# HELP s0_build_info Build and instance identity.\n");
    out.push_str("# TYPE s0_build_info gauge\n");
    out.push_str(&format!(
        "s0_build_info{{version=\"{}\",instance=\"{}\"}} 1\n",
        escape_label(env!("CARGO_PKG_VERSION")),
        escape_label(&state.instance),
    ));

    out.push_str("# HELP s0_bundle_revision_info The bundle revision in force.\n");
    out.push_str("# TYPE s0_bundle_revision_info gauge\n");
    out.push_str(&format!(
        "s0_bundle_revision_info{{revision=\"{}\"}} 1\n",
        escape_label(&state.bundles.revision()),
    ));

    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
        .header("cache-control", "no-store")
        .body(Full::new(Bytes::from(out)))
        .expect("metrics response")
}

fn metric(out: &mut String, name: &str, kind: &str, help: &str, value: u64) {
    out.push_str(&format!(
        "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
    ));
}

fn escape_label(v: &str) -> String {
    v.replace('\\', r"\\")
        .replace('"', "\\\"")
        .replace('\n', "")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditConfig, spawn as spawn_audit};
    use crate::pdp::Bundle;

    fn state(remote: bool, tmp: &std::path::Path) -> (Arc<AdminState>, Arc<BundleHealth>) {
        let (sink, _handle) = spawn_audit(AuditConfig {
            spill_path: tmp.join("admin-test-spill.ndjson"),
            ..AuditConfig::default()
        });
        let health = Arc::new(BundleHealth::new(remote));
        let bundles = Arc::new(BundleStore::new(Bundle::new(
            "rev-1",
            serde_json::json!({}),
        )));
        (
            Arc::new(AdminState::new(&sink, health.clone(), bundles)),
            health,
        )
    }

    fn tmpdir() -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("s0-admin-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[tokio::test]
    async fn readiness_gates_on_a_successful_poll_not_on_holding_a_revision() {
        let dir = tmpdir();
        let (st, health) = state(true, &dir);
        // The store already carries a seeded revision, so holding one proves nothing
        // about control-plane reachability. Readiness must still be false.
        assert_eq!(st.bundles.revision(), "rev-1");
        assert!(
            st.ready().is_err(),
            "a pod that has never polled is not ready"
        );

        health.record_success();
        assert!(st.ready().is_ok());

        // ...and a pod on its way out fails readiness even though it has polled.
        st.begin_shutdown();
        assert!(st.ready().is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn metrics_expose_the_audit_drop_counter() {
        let dir = tmpdir();
        let (st, _h) = state(false, &dir);
        let body = prometheus(&st).into_body();
        let text = String::from_utf8(
            http_body_util::BodyExt::collect(body)
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();
        assert!(text.contains("\ns0_audit_dropped_total 0\n"), "{text}");
        assert!(text.contains("# TYPE s0_audit_dropped_total counter"));
        assert!(text.contains("s0_bundle_source_remote 0"));
        assert!(text.contains("s0_ready 0"));
        assert!(text.contains("s0_bundle_revision_info{revision=\"rev-1\"} 1"));
        // No `sts_mint` on this state ⇒ no mint series at all. See `AdminState::mint`:
        // a flat 0 would claim a bounded mint on a pod that serves none.
        assert!(!text.contains("s0_mint_"), "{text}");
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A queued mint and a broken identity provider produce the same symptom — "clients
    /// cannot get credentials" on a gateway that looks healthy — with opposite remedies.
    /// These counters are the only thing that tells them apart, so the scrape is pinned.
    #[tokio::test]
    async fn metrics_expose_the_mint_bounds_and_the_counters_that_show_them_biting() {
        let dir = tmpdir();
        let (st, _h) = state(false, &dir);
        let mint = Arc::new(crate::mint::MintMetrics::default());
        mint.connection_limit.store(256, Ordering::Relaxed);
        mint.connections_active.store(3, Ordering::Relaxed);
        mint.connection_limit_saturated.store(11, Ordering::Relaxed);
        mint.connection_timeouts.store(4, Ordering::Relaxed);
        mint.bodies_too_large.store(2, Ordering::Relaxed);

        let st = Arc::new(
            Arc::try_unwrap(st)
                .unwrap_or_else(|_| panic!("sole owner"))
                .with_mint_metrics(mint),
        );
        let body = prometheus(&st).into_body();
        let text = String::from_utf8(
            http_body_util::BodyExt::collect(body)
                .await
                .unwrap()
                .to_bytes()
                .to_vec(),
        )
        .unwrap();

        // The bound itself, without which the saturation count below means nothing.
        assert!(text.contains("\ns0_mint_connection_limit 256\n"), "{text}");
        assert!(text.contains("\ns0_mint_connections_active 3\n"), "{text}");
        assert!(
            text.contains("\ns0_mint_connection_limit_saturated_total 11\n"),
            "{text}"
        );
        assert!(
            text.contains("\ns0_mint_connection_timeouts_total 4\n"),
            "{text}"
        );
        assert!(
            text.contains("\ns0_mint_bodies_too_large_total 2\n"),
            "{text}"
        );
        assert!(text.contains("# TYPE s0_mint_connection_limit_saturated_total counter"));
        assert!(text.contains("# TYPE s0_mint_connections_active gauge"));
        let _ = std::fs::remove_dir_all(dir);
    }
}
