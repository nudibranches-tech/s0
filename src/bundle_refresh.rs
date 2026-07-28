//! Live bundle refresh. Polls the projected policy data and, on a
//! content change, reloads the engine and bumps the [`BundleStore`] revision — so a
//! revoked grant takes effect without a restart, and every stale decision-cache entry
//! misses by construction.
//!
//! Source is the control-plane bundle endpoint when configured, else the local bundle
//! file (dev). The engine is reloaded *before* the revision is advertised, so no request
//! ever sees a new revision backed by the old policy.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::error::GatewayError;
use crate::pdp::{Bundle, BundleStore, Pdp, content_revision, parse_bundle};

pub enum BundleSource {
    File(PathBuf),
    Http {
        client: reqwest::Client,
        url: String,
    },
}

impl BundleSource {
    /// Build the polling HTTP source. The timeout is not optional: it bounds the
    /// *whole* request, so a control plane that accepts the connection and never
    /// answers cannot wedge the single refresh task and silently stop revocation
    /// from landing.
    pub fn http(url: String, timeout: Duration) -> Result<Self, GatewayError> {
        let client = reqwest::Client::builder()
            .gzip(true)
            .timeout(timeout)
            // Separate, tighter bound on connection establishment: a blackholed
            // control-plane IP must not consume the whole request budget.
            .connect_timeout(timeout.min(Duration::from_secs(5)))
            .build()
            .map_err(|e| GatewayError::Config(format!("bundle http client: {e}")))?;
        Ok(BundleSource::Http { client, url })
    }

    /// True when the source is the control plane rather than a local file. Readiness
    /// is defined against a *remote* poll (see [`crate::admin`]).
    pub fn is_remote(&self) -> bool {
        matches!(self, BundleSource::Http { .. })
    }

    async fn fetch(&self) -> Result<String, String> {
        match self {
            BundleSource::File(path) => tokio::fs::read_to_string(path)
                .await
                .map_err(|e| e.to_string()),
            BundleSource::Http { client, url } => {
                let resp = client.get(url).send().await.map_err(|e| e.to_string())?;
                if !resp.status().is_success() {
                    return Err(format!("status {}", resp.status()));
                }
                resp.text().await.map_err(|e| e.to_string())
            }
        }
    }
}

/// Observed state of the polling loop, and the basis for readiness.
///
/// Readiness deliberately gates on **≥1 successful poll**, not on the gateway holding
/// a non-empty bundle revision: `Gateway::build` seeds a revision from the local
/// bundle file before any listener exists, so a revision check would be vacuously true
/// on a pod that has never reached the control plane at all. Such a pod would join the
/// Service and start deciding on a bundle that could be arbitrarily old — including
/// one predating a revocation.
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
    /// readiness — see the open question in the plan §6.2.
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

/// Spawn the refresh loop. Returns immediately; the loop runs until the process ends.
/// The first tick fires without waiting out the interval, so a fresh pod becomes ready
/// as soon as it can reach the source rather than one poll period later.
pub fn spawn(
    pdp: Arc<dyn Pdp>,
    bundles: Arc<BundleStore>,
    source: BundleSource,
    interval: Duration,
    health: Arc<BundleHealth>,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            match refresh_once(&pdp, &bundles, &source).await {
                Ok(()) => health.record_success(),
                Err(e) => {
                    health.record_failure();
                    tracing::warn!(%e, "bundle refresh failed; keeping current revision");
                }
            }
        }
    });
}

async fn refresh_once(
    pdp: &Arc<dyn Pdp>,
    bundles: &Arc<BundleStore>,
    source: &BundleSource,
) -> Result<(), String> {
    let raw = source.fetch().await?;
    let revision = content_revision(&raw);
    if revision == bundles.revision() {
        return Ok(());
    }
    let parsed = parse_bundle(&raw)?;
    // Reload the engine first (with the pushed module, if any), then advertise the new
    // revision.
    pdp.reload(parsed.policy.as_deref(), &parsed.data)
        .await
        .map_err(|e| e.to_string())?;
    bundles.store(Bundle::new(revision.clone(), parsed.data));
    tracing::info!(%revision, "bundle reloaded");
    Ok(())
}
