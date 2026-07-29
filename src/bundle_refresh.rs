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
use crate::secret::Secret;

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
    /// Build the polling HTTP source. The timeout is not optional: it bounds the
    /// *whole* request, so a control plane that accepts the connection and never
    /// answers cannot wedge the single refresh task and silently stop revocation
    /// from landing.
    ///
    /// `shared_secret` is the platform `X-Shared-Secret`
    /// ([`crate::internal::SHARED_SECRET_HEADER`] — the same header, the same value,
    /// the same idiom as every other console↔component internal call). It is
    /// **optional**: s0 must stay runnable against a plain file or an unauthenticated
    /// URL, and refusing to poll without a credential would break every deployment
    /// that does not have one. But it is not *conditionally* sent — when it is
    /// configured it rides on every request this source ever makes, including the
    /// retries after a failure, because a poller that drops the credential on some
    /// path is a poller that silently stops receiving revocations.
    ///
    /// Why a header and not a query parameter or basic auth: a query parameter lands
    /// in the control plane's access log and in every proxy in between, which is the
    /// same class of leak `Secret<T>` exists to prevent on this side.
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

    /// P2's s0 half: the bundle endpoint is authenticated, and this poller presents
    /// the credential. Asserted on the bytes that reach the socket.
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
}
