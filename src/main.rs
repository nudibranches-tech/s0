//! Gateway entrypoint: init observability, load config, build the gateway, start the
//! live bundle refresher, the admin listener and the STS mint, and serve.
//!
//! Shutdown ordering is deliberate and is the whole reason this is not three detached
//! `tokio::spawn`s:
//!
//! 1. SIGTERM ⇒ `/readyz` starts failing, so kubernetes takes this pod out of the
//!    Service while it is still able to answer in-flight requests.
//! 2. The S3 front and the mint stop accepting and drain their connections.
//! 3. The audit worker drains, so records already emitted are shipped or spilled.
//! 4. The admin listener stops last, so probes and a final scrape keep working for
//!    the whole drain.
//!
//! That sums to just over the 30 s S3 drain + 10 s audit drain, so the deployment's
//! `terminationGracePeriodSeconds` must exceed ~45 s; the kubernetes default of 30 s
//! truncates the audit drain and loses records.

use std::sync::Arc;
use std::time::Duration;

use s0::admin::{self, AdminState};
use s0::bundle_refresh::{self, BundleHealth, BundleSource};
use s0::config::GatewayConfig;
use s0::error::Result;
use s0::mint::{self, Mint, StandardVerifier};
use s0::{gateway::Gateway, server, shutdown};

/// Budget for the mint's own drain once the S3 front is down.
const MINT_JOIN_TIMEOUT: Duration = Duration::from_secs(15);
/// Budget for the audit worker to ship or spill everything queued.
const AUDIT_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Budget for the admin listener, which is only ever serving probes.
const ADMIN_JOIN_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,s0=debug".into()),
        )
        .json()
        .init();

    let config = GatewayConfig::load()?;
    let listen = config.listen;
    let instance = s0::config::instance_id();
    tracing::info!(%instance, "s0 starting");
    let (gateway, audit_handle) = Gateway::build(&config)?;

    let source = match &config.bundle_url {
        Some(url) => {
            BundleSource::http(url.clone(), Duration::from_secs(config.bundle_timeout_secs))?
        }
        None => BundleSource::File(config.bundle_path.clone()),
    };
    let health = Arc::new(BundleHealth::new(source.is_remote()));
    bundle_refresh::spawn(
        gateway.pdp.clone(),
        gateway.bundles.clone(),
        source,
        Duration::from_secs(config.bundle_poll_secs),
        health.clone(),
    );

    // Probes and metrics come up first: a pod that is starting must be able to report
    // "not ready" rather than refuse the connection.
    let admin_state = Arc::new(AdminState::new(
        &gateway.audit,
        health,
        gateway.bundles.clone(),
    ));
    let (admin_stop, admin_stopped) = tokio::sync::oneshot::channel::<()>();
    let admin_task = {
        let state = admin_state.clone();
        let listen = config.admin_listen;
        tokio::spawn(async move {
            if let Err(e) = admin::serve_with_shutdown(state, listen, async {
                let _ = admin_stopped.await;
            })
            .await
            {
                // Not fatal for the data plane, and fail-closed anyway: with no
                // listener the readiness probe gets connection-refused, so the pod
                // never joins the Service.
                tracing::error!(%e, %listen, "admin listener exited; this pod cannot report readiness");
            }
        })
    };
    // Fail readiness on the signal, not when the drain finishes: the pod must leave
    // the Service *before* it stops accepting, or the endpoint controller keeps
    // sending it requests it is about to refuse.
    {
        let state = admin_state.clone();
        tokio::spawn(async move {
            shutdown::signal().await;
            state.begin_shutdown();
            tracing::info!("shutdown signal; readiness now failing");
        });
    }

    // The badge desk: OIDC token -> gateway session creds, on its own listener.
    let mint_task = match &config.sts_mint {
        Some(sts_cfg) => {
            let verifier = Arc::new(StandardVerifier::from_config(sts_cfg)?);
            // Keep the JWKS cache warm so a key rotation is not a fleet-wide mint
            // failure on the first request after it.
            let jwks_refresh = verifier.spawn_jwks_refresh();
            let mint = Arc::new(Mint::new(
                verifier,
                gateway.identity.sts(),
                config.session_ttl(),
            ));
            let mint_listen = sts_cfg.listen;
            Some((
                tokio::spawn(async move {
                    if let Err(e) = mint::serve(mint, mint_listen).await {
                        tracing::error!(%e, "sts mint server exited");
                    }
                }),
                jwks_refresh,
            ))
        }
        None => None,
    };

    server::serve(gateway, listen).await?;

    // The S3 front has drained. Let the mint finish its own drain (it saw the same
    // signal) rather than aborting it with the runtime.
    if let Some((task, jwks_refresh)) = mint_task {
        if tokio::time::timeout(MINT_JOIN_TIMEOUT, task).await.is_err() {
            tracing::error!("sts mint drain timed out");
        }
        if let Some(h) = jwks_refresh {
            h.abort();
        }
    }

    // Then drain the audit worker so any queued/buffered records are shipped or
    // spilled rather than aborted with the runtime (§9.2: on shutdown, no silent
    // audit loss).
    audit_handle.drain(AUDIT_DRAIN_TIMEOUT).await;

    // Admin last: probes and a final metrics scrape stay available for the whole
    // drain, including the audit drain that decides whether anything was lost.
    let _ = admin_stop.send(());
    let _ = tokio::time::timeout(ADMIN_JOIN_TIMEOUT, admin_task).await;
    Ok(())
}
