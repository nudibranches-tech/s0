//! Process shutdown signalling, shared by every listener the gateway runs.
//!
//! Each listener awaits its own [`signal`] future: tokio delivers a signal to every
//! registered stream, so one SIGTERM reaches the S3 front, the STS mint and the admin
//! listener alike. That matters for a rolling update — a listener with no signal
//! handling is not "quietly ignoring" the signal, it is *aborted* when the runtime
//! drops, taking its in-flight requests with it.
//!
//! Ordering is the caller's job (`main`): the data plane drains first, the audit
//! worker next, and the admin listener last, so probes keep answering (with a failing
//! `/readyz`) for as long as the pod is still doing work.

/// Resolves on SIGTERM (kubelet's stop signal) or Ctrl-C.
///
/// If the SIGTERM handler cannot be installed we fall back to Ctrl-C only, rather
/// than returning immediately — a future that resolves at once would make every
/// listener exit the instant it starts.
pub async fn signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(%e, "cannot install SIGTERM handler; ctrl-c only");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
