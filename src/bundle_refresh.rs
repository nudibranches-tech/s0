//! Live bundle refresh (§3.4, §6.1). Polls the projected policy data and, on a
//! content change, reloads the engine and bumps the [`BundleStore`] revision — so a
//! revoked grant takes effect without a restart, and every stale decision-cache entry
//! misses by construction (§4.3.2).
//!
//! Source is the console bundle endpoint when configured, else the local bundle file
//! (dev). The engine is reloaded *before* the revision is advertised, so no request
//! ever sees a new revision backed by the old policy.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::pdp::{Bundle, BundleStore, Pdp, content_revision, parse_bundle};

pub enum BundleSource {
    File(PathBuf),
    Http {
        client: reqwest::Client,
        url: String,
    },
}

impl BundleSource {
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

/// Spawn the refresh loop. Returns immediately; the loop runs until the process ends.
pub fn spawn(
    pdp: Arc<dyn Pdp>,
    bundles: Arc<BundleStore>,
    source: BundleSource,
    interval: Duration,
) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            if let Err(e) = refresh_once(&pdp, &bundles, &source).await {
                tracing::warn!(%e, "bundle refresh failed; keeping current revision");
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
