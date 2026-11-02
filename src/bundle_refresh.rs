//! Live bundle refresh. Polls the projected policy data and, on a content change,
//! reloads the engine and bumps the [`BundleStore`] revision — so a revoked grant takes
//! effect without a restart, and every stale decision-cache entry misses.
//!
//! Source is the control-plane bundle endpoint when configured, else a local bundle
//! file. The engine is reloaded *before* the revision is advertised, so no request ever
//! sees a new revision backed by the old policy.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::GatewayConfig;
use crate::counters::LabeledCounters;
use crate::error::GatewayError;
use crate::pdp::{Bundle, BundleStore, Pdp, content_revision, parse_bundle};
use crate::secret::Secret;

/// The shortest gap between two on-demand fetches triggered by a placement miss.
pub const ON_DEMAND_MIN_INTERVAL: Duration = Duration::from_secs(1);
/// The longest a request waits for an on-demand fetch before it is decided with whatever
/// placement is current.
pub const ON_MISS_WAIT: Duration = Duration::from_secs(2);
const WAIT_BACKOFF_START: Duration = Duration::from_millis(250);
const WAIT_BACKOFF_MAX: Duration = Duration::from_secs(1);

pub enum BundleSource {
    File(PathBuf),
    Http {
        client: reqwest::Client,
        url: String,
        /// The credential presented on every fetch, or `None` when the endpoint needs
        /// none. See [`BundleSource::http`].
        shared_secret: Option<Secret<String>>,
    },
}

impl BundleSource {
    /// The source `config` names: the control plane's bundle endpoint when `bundle_url`
    /// is set, else the local bundle file.
    pub fn from_config(config: &GatewayConfig) -> Result<Self, GatewayError> {
        match &config.bundle_url {
            Some(url) => Self::http(
                url.clone(),
                Duration::from_secs(config.bundle_timeout_secs),
                config.bundle_shared_secret.clone(),
            ),
            None => Ok(BundleSource::File(config.bundle_path.clone())),
        }
    }

    /// Build the polling HTTP source. The timeout bounds the *whole* request, so a
    /// control plane that accepts the connection and never answers cannot wedge the
    /// single refresh task and silently stop revocation from landing.
    ///
    /// `shared_secret` ([`crate::internal::SHARED_SECRET_HEADER`]) is optional so s0
    /// stays runnable against a plain file or an unauthenticated URL, but it is never
    /// sent conditionally: once configured it rides on every request this source makes,
    /// retries included. It is a header rather than a query parameter because a query
    /// parameter lands in access logs and in every proxy in between.
    pub fn http(
        url: String,
        timeout: Duration,
        shared_secret: Option<Secret<String>>,
    ) -> Result<Self, GatewayError> {
        let client = reqwest::Client::builder()
            .gzip(true)
            .timeout(timeout)
            // Separate, tighter bound on connection establishment: a blackholed
            // control-plane IP must not consume the whole request budget.
            .connect_timeout(timeout.min(Duration::from_secs(5)))
            .build()
            .map_err(|e| GatewayError::Config(format!("bundle http client: {e}")))?;
        Ok(BundleSource::Http {
            client,
            url,
            shared_secret,
        })
    }

    /// True when the source is the control plane rather than a local file. Readiness
    /// is defined against a *remote* poll (see [`crate::admin`]).
    pub fn is_remote(&self) -> bool {
        matches!(self, BundleSource::Http { .. })
    }

    /// True when this source presents a credential. Reported so an operator can tell
    /// an authenticated poll from an unauthenticated one without reading the config.
    pub fn is_authenticated(&self) -> bool {
        matches!(
            self,
            BundleSource::Http {
                shared_secret: Some(_),
                ..
            }
        )
    }

    async fn fetch(&self) -> Result<String, String> {
        match self {
            BundleSource::File(path) => tokio::fs::read_to_string(path)
                .await
                .map_err(|e| e.to_string()),
            BundleSource::Http {
                client,
                url,
                shared_secret,
            } => {
                let mut request = client.get(url);
                if let Some(secret) = shared_secret {
                    request = request.header(
                        crate::internal::SHARED_SECRET_HEADER,
                        secret.expose().as_str(),
                    );
                }
                let resp = request.send().await.map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    // 401/403 is worth calling out by name: it is the shape a rotated
                    // or unrendered `bundle_shared_secret` takes, and it is otherwise
                    // indistinguishable from a control-plane outage in the logs.
                    if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                        || resp.status() == reqwest::StatusCode::FORBIDDEN
                    {
                        return Err(format!(
                            "status {} — the bundle endpoint rejected this gateway's \
                             credential (bundle_shared_secret {}); revocation is NOT \
                             landing",
                            resp.status(),
                            if shared_secret.is_some() {
                                "is set and was sent"
                            } else {
                                "is not set, so nothing was sent"
                            }
                        ));
                    }
                    return Err(format!("status {}", resp.status()));
                }
                resp.text().await.map_err(|e| e.to_string())
            }
        }
    }
}

/// Observed state of the polling loop, and the basis for readiness.
///
/// Readiness gates on **≥1 successful poll**, not on holding a non-empty bundle
/// revision: `Gateway::build` seeds a revision from the local bundle file, so a revision
/// check would pass on an instance that has never reached the control plane and is
/// deciding on an arbitrarily old bundle — possibly one predating a revocation.
#[derive(Debug)]
pub struct BundleHealth {
    /// Whether the source is the control plane rather than a local file. A file
    /// source cannot demonstrate control-plane reachability and says so.
    remote: bool,
    successes: AtomicU64,
    failures: AtomicU64,
    /// Unix seconds of the last successful poll; 0 ⇒ never.
    last_success_unix: AtomicU64,
}

impl BundleHealth {
    pub fn new(remote: bool) -> Self {
        BundleHealth {
            remote,
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
            last_success_unix: AtomicU64::new(0),
        }
    }

    /// True once this process has fetched and applied the bundle at least once.
    pub fn ready(&self) -> bool {
        self.successes.load(Ordering::Relaxed) > 0
    }

    pub fn is_remote(&self) -> bool {
        self.remote
    }

    pub fn successes(&self) -> u64 {
        self.successes.load(Ordering::Relaxed)
    }

    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }

    /// Unix seconds of the last successful poll, or `None` if there has never been
    /// one. Exported so staleness is alertable even though it does not (yet) fail
    /// readiness.
    pub fn last_success_unix(&self) -> Option<u64> {
        match self.last_success_unix.load(Ordering::Relaxed) {
            0 => None,
            t => Some(t),
        }
    }

    /// `pub(crate)` so the admin tests can drive readiness without a control plane;
    /// nothing outside the crate can fake a successful poll.
    pub(crate) fn record_success(&self) {
        self.successes.fetch_add(1, Ordering::Relaxed);
        self.last_success_unix.store(now_unix(), Ordering::Relaxed);
    }

    pub(crate) fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether a refresh changed what is in force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refreshed {
    Unchanged,
    Reloaded,
}

/// How a wait for a bucket to appear in the placement ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlacementWaitOutcome {
    /// The bundle in force places no buckets, so there is nothing to wait for.
    NotPlacing,
    Placed,
    TimedOut,
}

impl PlacementWaitOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            PlacementWaitOutcome::NotPlacing => "not_placing",
            PlacementWaitOutcome::Placed => "placed",
            PlacementWaitOutcome::TimedOut => "timed_out",
        }
    }
}

/// Waits until a bucket is placed under a tenant. The forward layer holds this rather
/// than the refresher, so it never has a policy handle in reach.
#[async_trait::async_trait]
pub trait PlacementWait: Send + Sync {
    async fn wait_until_placed(
        &self,
        backend: &str,
        tenant: &str,
        bucket: &str,
        budget: Duration,
    ) -> PlacementWaitOutcome;
}

#[derive(Default)]
struct OnDemand {
    last_started: Option<Instant>,
    /// The `completed` count when the fetch in flight was reserved, while one is.
    in_flight_from: Option<u64>,
}

/// The one place a bundle is fetched and applied: the poll loop, a placement wait and a
/// placement miss all go through it, serialized by a single gate.
pub struct BundleRefresher {
    pdp: Arc<dyn Pdp>,
    bundles: Arc<BundleStore>,
    source: Arc<BundleSource>,
    health: Arc<BundleHealth>,
    gate: Arc<tokio::sync::Mutex<()>>,
    completed: tokio::sync::watch::Sender<u64>,
    last: Arc<Mutex<Result<Refreshed, String>>>,
    on_demand: Mutex<OnDemand>,
    on_demand_total: LabeledCounters,
}

impl BundleRefresher {
    pub fn new(
        pdp: Arc<dyn Pdp>,
        bundles: Arc<BundleStore>,
        source: BundleSource,
        health: Arc<BundleHealth>,
    ) -> Arc<Self> {
        Arc::new(BundleRefresher {
            pdp,
            bundles,
            source: Arc::new(source),
            health,
            gate: Arc::new(tokio::sync::Mutex::new(())),
            completed: tokio::sync::watch::channel(0).0,
            last: Arc::new(Mutex::new(Ok(Refreshed::Unchanged))),
            on_demand: Mutex::new(OnDemand::default()),
            on_demand_total: LabeledCounters::default(),
        })
    }

    pub fn health(&self) -> &Arc<BundleHealth> {
        &self.health
    }

    pub fn source(&self) -> &BundleSource {
        &self.source
    }

    /// The `s0_bundle_on_demand_refresh_total{trigger,result}` counters.
    pub fn on_demand_total(&self) -> &LabeledCounters {
        &self.on_demand_total
    }

    /// Fetch the bundle and apply it when its content changed.
    ///
    /// Fetches never overlap. A caller that waited behind another caller's fetch takes
    /// that fetch's answer rather than starting one more. The fetch and the reload run in
    /// a task of their own that owns the gate, so a caller dropped mid-refresh cannot
    /// split the engine reload from the revision store, nor let a second refresh start
    /// while the first still runs.
    pub async fn refresh(self: &Arc<Self>) -> Result<Refreshed, String> {
        let seen = *self.completed.borrow();
        let guard = self.gate.clone().lock_owned().await;
        if *self.completed.borrow() != seen {
            return self.last.lock().unwrap_or_else(|e| e.into_inner()).clone();
        }
        let this = self.clone();
        tokio::spawn(async move {
            let result = refresh_once(&this.pdp, &this.bundles, &this.source).await;
            match &result {
                Ok(_) => this.health.record_success(),
                Err(_) => this.health.record_failure(),
            }
            *this.last.lock().unwrap_or_else(|e| e.into_inner()) = result.clone();
            this.completed.send_modify(|n| *n += 1);
            drop(guard);
            result
        })
        .await
        .unwrap_or_else(|e| Err(format!("bundle refresh task failed: {e}")))
    }

    /// Fetch now because a request was refused for a bucket the bundle does not place.
    ///
    /// At most one fetch per [`ON_DEMAND_MIN_INTERVAL`] per replica: a request arriving
    /// while one is in flight joins it, one arriving within the interval after it does
    /// not fetch. A request waits at most [`ON_MISS_WAIT`]. Returns whether a fetch
    /// finished in that time.
    pub async fn refresh_on_miss(self: &Arc<Self>) -> bool {
        enum Role {
            Lead,
            Join(u64),
            Skip,
        }
        let role = {
            let mut state = self.on_demand.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(from) = state.in_flight_from {
                Role::Join(from)
            } else if state
                .last_started
                .is_some_and(|t| t.elapsed() < ON_DEMAND_MIN_INTERVAL)
            {
                Role::Skip
            } else {
                state.in_flight_from = Some(*self.completed.borrow());
                state.last_started = Some(Instant::now());
                Role::Lead
            }
        };
        match role {
            Role::Skip => {
                self.on_demand_total.increment("miss", "rate_limited");
                false
            }
            Role::Join(from) => {
                let mut rx = self.completed.subscribe();
                let done = tokio::time::timeout(ON_MISS_WAIT, rx.wait_for(|n| *n != from))
                    .await
                    .is_ok();
                self.on_demand_total
                    .increment("miss", if done { "coalesced" } else { "timed_out" });
                done
            }
            Role::Lead => {
                let _clear = ClearInFlight(self);
                match tokio::time::timeout(ON_MISS_WAIT, self.refresh()).await {
                    Ok(Ok(Refreshed::Reloaded)) => {
                        self.on_demand_total.increment("miss", "reloaded");
                        true
                    }
                    Ok(Ok(Refreshed::Unchanged)) => {
                        self.on_demand_total.increment("miss", "unchanged");
                        true
                    }
                    Ok(Err(e)) => {
                        tracing::warn!(%e, "on-demand bundle refresh failed");
                        self.on_demand_total.increment("miss", "failed");
                        false
                    }
                    Err(_) => {
                        self.on_demand_total.increment("miss", "timed_out");
                        false
                    }
                }
            }
        }
    }

    fn placed(&self, backend: &str, tenant: &str, bucket: &str) -> bool {
        let bundle = self.bundles.current();
        let placement = bundle.placement();
        placement.places_buckets() && placement.refusal(backend, tenant, bucket).is_none()
    }
}

struct ClearInFlight<'a>(&'a BundleRefresher);

impl Drop for ClearInFlight<'_> {
    fn drop(&mut self) {
        self.0
            .on_demand
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .in_flight_from = None;
    }
}

#[async_trait::async_trait]
impl PlacementWait for Arc<BundleRefresher> {
    async fn wait_until_placed(
        &self,
        backend: &str,
        tenant: &str,
        bucket: &str,
        budget: Duration,
    ) -> PlacementWaitOutcome {
        if !self.bundles.current().placement().places_buckets() {
            return PlacementWaitOutcome::NotPlacing;
        }
        let deadline = Instant::now() + budget;
        let mut backoff = WAIT_BACKOFF_START;
        loop {
            if self.placed(backend, tenant, bucket) {
                return PlacementWaitOutcome::Placed;
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return PlacementWaitOutcome::TimedOut;
            };
            if remaining.is_zero() {
                return PlacementWaitOutcome::TimedOut;
            }
            if let Ok(Err(e)) = tokio::time::timeout(remaining, self.refresh()).await {
                tracing::warn!(%e, "bundle refresh while waiting for a placement failed");
            }
            if self.placed(backend, tenant, bucket) {
                return PlacementWaitOutcome::Placed;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            tokio::time::sleep(backoff.min(remaining)).await;
            backoff = (backoff * 2).min(WAIT_BACKOFF_MAX);
        }
    }
}

/// Spawn the refresh loop. Returns immediately; the loop runs until the process ends.
/// The first tick fires without waiting out the interval, so a fresh pod becomes ready
/// as soon as it can reach the source rather than one poll period later.
pub fn spawn(refresher: Arc<BundleRefresher>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(e) = refresher.refresh().await {
                tracing::warn!(%e, "bundle refresh failed; keeping current revision");
            }
        }
    });
}

async fn refresh_once(
    pdp: &Arc<dyn Pdp>,
    bundles: &Arc<BundleStore>,
    source: &BundleSource,
) -> Result<Refreshed, String> {
    let raw = source.fetch().await?;
    let revision = content_revision(&raw);
    if revision == bundles.revision() {
        return Ok(Refreshed::Unchanged);
    }
    let parsed = parse_bundle(&raw)?;
    // Reload the engine first (with the pushed module, if any), then advertise the new
    // revision.
    pdp.reload(parsed.policy.as_deref(), &parsed.data)
        .await
        .map_err(|e| e.to_string())?;
    bundles.store(Bundle::new(revision.clone(), parsed.data));
    tracing::info!(%revision, "bundle reloaded");
    Ok(Refreshed::Reloaded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A one-shot HTTP server that records the request head and answers with `body`.
    /// Returns its URL and a handle yielding the headers it saw.
    ///
    /// Raw TCP rather than a mock client: the claim under test is "the credential is
    /// on the wire", and a stub that intercepts before the socket cannot prove it.
    async fn capture_one_request(
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<BTreeMap<String, String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 1024];
            // Read until the end of the request head. There is no request body.
            loop {
                let n = stream.read(&mut chunk).await.expect("read");
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&chunk[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf).to_string();
            let headers = head
                .lines()
                .skip(1)
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
                .collect::<BTreeMap<_, _>>();
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(response.as_bytes()).await.expect("write");
            stream.flush().await.expect("flush");
            headers
        });
        (format!("http://{addr}/bundle"), handle)
    }

    /// The poller presents its credential to an authenticated bundle endpoint,
    /// asserted on the bytes that reach the socket.
    #[tokio::test]
    async fn a_configured_bundle_credential_is_sent_on_the_wire() {
        let (url, seen) = capture_one_request(r#"{"data":{}}"#).await;
        let source = BundleSource::http(
            url,
            Duration::from_secs(5),
            Some(Secret::from("BUNDLE-SHARED-SECRET")),
        )
        .expect("source");
        assert!(source.is_authenticated());
        let body = source.fetch().await.expect("fetch");
        assert_eq!(body, r#"{"data":{}}"#);

        let headers = seen.await.expect("server task");
        assert_eq!(
            headers
                .get(&crate::internal::SHARED_SECRET_HEADER.to_ascii_lowercase())
                .map(String::as_str),
            Some("BUNDLE-SHARED-SECRET"),
            "the bundle poll carried no credential: {headers:?}"
        );
    }

    /// …and an unconfigured one sends nothing, so a gateway pointed at a plain file
    /// server or a dev URL still works. This is the half that makes the field
    /// genuinely optional rather than optional-in-the-schema-only.
    #[tokio::test]
    async fn an_unconfigured_bundle_credential_sends_no_header() {
        let (url, seen) = capture_one_request(r#"{"data":{}}"#).await;
        let source = BundleSource::http(url, Duration::from_secs(5), None).expect("source");
        assert!(!source.is_authenticated());
        source.fetch().await.expect("fetch");
        let headers = seen.await.expect("server task");
        assert!(
            !headers.contains_key(&crate::internal::SHARED_SECRET_HEADER.to_ascii_lowercase()),
            "an unconfigured poller sent an auth header: {headers:?}"
        );
    }

    fn bundle_body(buckets: &[&str]) -> String {
        let attributes: serde_json::Map<String, serde_json::Value> = buckets
            .iter()
            .map(|b| ((*b).to_string(), serde_json::json!({})))
            .collect();
        serde_json::json!({ "data": {
            "grant_schema_version": 3,
            "backend": { "id": "bay-1", "kind": "ceph" },
            "tenants": { "acme": { "bucket_attributes": attributes } },
        }})
        .to_string()
    }

    /// Serves `bodies` in order, one per request, repeating the last; counts requests.
    async fn scripted_server(
        bodies: Vec<String>,
        delay: Duration,
    ) -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let served = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = served.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let body = bodies[n.min(bodies.len() - 1)].clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        let Ok(read) = stream.read(&mut chunk).await else {
                            return;
                        };
                        if read == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..read]);
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    tokio::time::sleep(delay).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        (format!("http://{addr}/bundle"), served)
    }

    fn refresher_for(url: String) -> Arc<BundleRefresher> {
        refresher_seeded(
            url,
            serde_json::from_str::<serde_json::Value>(&bundle_body(&[])).expect("json")["data"]
                .clone(),
        )
    }

    fn refresher_seeded(url: String, seed: serde_json::Value) -> Arc<BundleRefresher> {
        let pdp: Arc<dyn Pdp> = Arc::new(
            crate::pdp::RegorusPdp::new(crate::pdp::GATEWAY_REGO, &serde_json::json!({}))
                .expect("regorus"),
        );
        let bundles = Arc::new(BundleStore::new(Bundle::new("seed", seed)));
        let source = BundleSource::http(url, Duration::from_secs(5), None).expect("source");
        BundleRefresher::new(pdp, bundles, source, Arc::new(BundleHealth::new(true)))
    }

    #[tokio::test]
    async fn concurrent_refreshes_share_one_fetch() {
        let (url, served) =
            scripted_server(vec![bundle_body(&["a"])], Duration::from_millis(200)).await;
        let refresher = refresher_for(url);
        let results = futures_join(
            (0..8)
                .map(|_| {
                    let r = refresher.clone();
                    tokio::spawn(async move { r.refresh().await })
                })
                .collect(),
        )
        .await;
        assert!(results.iter().all(|r| r.is_ok()), "{results:?}");
        assert_eq!(served.load(Ordering::SeqCst), 1);
        assert_eq!(refresher.health().successes(), 1);
    }

    async fn futures_join<T>(handles: Vec<tokio::task::JoinHandle<T>>) -> Vec<T> {
        let mut out = Vec::new();
        for h in handles {
            out.push(h.await.expect("task"));
        }
        out
    }

    #[tokio::test]
    async fn refresh_on_miss_is_rate_limited() {
        let (url, served) = scripted_server(vec![bundle_body(&["a"])], Duration::ZERO).await;
        let refresher = refresher_for(url);
        assert!(refresher.refresh_on_miss().await);
        assert!(!refresher.refresh_on_miss().await);
        assert!(!refresher.refresh_on_miss().await);
        assert_eq!(served.load(Ordering::SeqCst), 1);
        assert_eq!(refresher.on_demand_total().get("miss", "reloaded"), 1);
        assert_eq!(refresher.on_demand_total().get("miss", "rate_limited"), 2);

        tokio::time::sleep(ON_DEMAND_MIN_INTERVAL).await;
        assert!(refresher.refresh_on_miss().await);
        assert_eq!(served.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_burst_of_misses_costs_one_fetch() {
        let (url, served) =
            scripted_server(vec![bundle_body(&["a"])], Duration::from_millis(200)).await;
        let refresher = refresher_for(url);
        let results = futures_join(
            (0..8)
                .map(|_| {
                    let r = refresher.clone();
                    tokio::spawn(async move { r.refresh_on_miss().await })
                })
                .collect(),
        )
        .await;
        assert!(results.iter().all(|done| *done), "{results:?}");
        assert_eq!(served.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn a_cancelled_caller_does_not_split_reload_from_store() {
        let (url, served) =
            scripted_server(vec![bundle_body(&["a"])], Duration::from_millis(200)).await;
        let refresher = refresher_for(url);
        let caller = {
            let r = refresher.clone();
            tokio::spawn(async move { r.refresh().await })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;
        caller.abort();
        let _ = caller.await;
        // The fetch in flight still finishes and is applied as one step.
        let mut applied = false;
        for _ in 0..100 {
            if refresher.bundles.revision() != "seed" {
                applied = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(applied, "the abandoned refresh was never applied");
        assert!(refresher.bundles.current().placement().places_buckets());
        assert_eq!(served.load(Ordering::SeqCst), 1);
        assert_eq!(refresher.health().successes(), 1);
        // …and the gate was released with it.
        assert!(refresher.refresh().await.is_ok());
    }

    #[tokio::test]
    async fn wait_until_placed_returns_once_placed() {
        let (url, served) = scripted_server(
            vec![bundle_body(&["other"]), bundle_body(&["other", "fresh"])],
            Duration::ZERO,
        )
        .await;
        let refresher = refresher_for(url);
        let outcome = refresher
            .wait_until_placed("bay-1", "acme", "fresh", Duration::from_secs(5))
            .await;
        assert_eq!(outcome, PlacementWaitOutcome::Placed);
        assert_eq!(served.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn wait_until_placed_gives_up_at_its_budget() {
        let (url, _) = scripted_server(vec![bundle_body(&["other"])], Duration::ZERO).await;
        let refresher = refresher_for(url);
        let started = Instant::now();
        let outcome = refresher
            .wait_until_placed("bay-1", "acme", "fresh", Duration::from_millis(600))
            .await;
        assert_eq!(outcome, PlacementWaitOutcome::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[tokio::test]
    async fn a_non_placing_bundle_is_not_waited_on() {
        let (url, served) = scripted_server(vec![r#"{"data":{}}"#.into()], Duration::ZERO).await;
        let refresher = refresher_seeded(url, serde_json::json!({}));
        let outcome = refresher
            .wait_until_placed("bay-1", "acme", "fresh", Duration::from_secs(5))
            .await;
        assert_eq!(outcome, PlacementWaitOutcome::NotPlacing);
        assert_eq!(served.load(Ordering::SeqCst), 0);
    }
}
