//! Gateway entrypoint: load config, build the gateway, start its listeners, and serve.
//!
//! Four listeners on four ports with three auth postures: the S3 data plane (SigV4), the
//! admin listener (unauthenticated probes and metrics), the STS mint (unauthenticated by
//! design — the OIDC/web-identity token IS the credential) and the internal API (shared
//! secret). Authentication is a property of the socket, never of the path.
//!
//! Shutdown is ordered, not detached: readiness fails first, then the S3 front, mint and
//! internal API drain, then the audit worker, and the admin listener last — ~45 s total,
//! so `terminationGracePeriodSeconds` must exceed it or audit records are lost.

use std::sync::Arc;
use std::time::Duration;

use s0::admin::{self, AdminState};
use s0::bundle_refresh::{self, BundleHealth, BundleSource};
use s0::config::GatewayConfig;
use s0::error::Result;
use s0::internal::{self, InternalApi};
use s0::mint::{self, Mint, MintLimits, MintMetrics, StandardVerifier};
use s0::webidentity::{WebIdentityConfig, WebIdentitySts};
use s0::{gateway::Gateway, server, shutdown};

/// Budget for the mint's own drain once the S3 front is down.
const MINT_JOIN_TIMEOUT: Duration = Duration::from_secs(15);
/// Same budget for the internal session endpoint, which drains the same way.
const INTERNAL_JOIN_TIMEOUT: Duration = Duration::from_secs(15);
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
    // `version` rides on the first line this process writes, so "which bytes is this pod
    // running?" is answerable from the log rather than only from the image digest. It is
    // the crate version, not a build stamp: a process cannot know the digest it was
    // unpacked from, and a timestamp would describe *when* it was built, not *what*.
    tracing::info!(
        %instance,
        version = env!("CARGO_PKG_VERSION"),
        "s0 starting"
    );
    let (gateway, audit_handle) = Gateway::build(&config)?;

    let source = match &config.bundle_url {
        Some(url) => BundleSource::http(
            url.clone(),
            Duration::from_secs(config.bundle_timeout_secs),
            config.bundle_shared_secret.clone(),
        )?,
        None => BundleSource::File(config.bundle_path.clone()),
    };
    if source.is_remote() && !source.is_authenticated() {
        // Not fatal — s0 must stay runnable against an unauthenticated URL — but the
        // bundle endpoint carries the org's grant rules and answers 304, which makes it
        // a change-detection oracle over the grant table.
        tracing::warn!(
            "polling the bundle endpoint WITHOUT a credential; set bundle_shared_secret \
             if the control plane requires one"
        );
    }
    let health = Arc::new(BundleHealth::new(source.is_remote()));
    bundle_refresh::spawn(
        gateway.pdp.clone(),
        gateway.bundles.clone(),
        source,
        Duration::from_secs(config.bundle_poll_secs),
        health.clone(),
    );

    // Built here, before the admin listener, because the same `Arc` has to reach two
    // places: the mint's accept loop, which keeps the numbers, and `/metrics`, which
    // publishes them. A second copy would report zeros forever.
    let mint_metrics = Arc::new(MintMetrics::default());

    // Probes and metrics come up first: a pod that is starting must be able to report
    // "not ready" rather than refuse the connection.
    let admin_state = {
        let state = AdminState::new(&gateway.audit, health, gateway.bundles.clone());
        // Only when a mint is actually served — see `AdminState::mint`.
        let state = if config.sts_mint.is_some() {
            state.with_mint_metrics(mint_metrics.clone())
        } else {
            state
        };
        Arc::new(state)
    };
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

    // OIDC token -> gateway session credentials, on its own listener, alongside
    // `Action=AssumeRoleWithWebIdentity` in the AWS STS wire protocol — the only door an
    // off-the-shelf S3 client can open. Both are on THIS socket and no other: the
    // credential is the IdP token, so the posture is a property of the socket.
    let mint_task = match &config.sts_mint {
        Some(sts_cfg) => {
            let verifier = Arc::new(StandardVerifier::from_config(sts_cfg)?);
            // Keep the JWKS cache warm so a key rotation is not a fleet-wide mint
            // failure on the first request after it.
            let jwks_refresh = verifier.spawn_jwks_refresh();
            let mut mint = Mint::new(
                verifier.clone(),
                gateway.identity.sts(),
                config.session_ttl(),
            )
            // This socket is internet-facing AND unauthenticated by design, and nothing
            // in front of it rate-limits, so its bounds exist here or nowhere.
            .with_limits(MintLimits::from_config(sts_cfg))
            .with_metrics(mint_metrics.clone());
            if sts_cfg.web_identity_enabled {
                // The SAME `StsAuthority` the S3 front verifies with, and the same
                // routing table the request pipeline resolves against. A second of
                // either would mint credentials this process could not honour, or
                // accept a tenant it could not route.
                mint = mint.with_web_identity(Arc::new(
                    WebIdentitySts::new(
                        verifier,
                        gateway.identity.sts(),
                        gateway.registry.clone(),
                        WebIdentityConfig::from_config(sts_cfg, config.session_ttl()),
                    )
                    // …and the SAME BundleStore the PDP decides against, so a tenant's
                    // own service account is addressed to this gateway when the bundle
                    // already knows it. Additive to the configured audience list, never
                    // instead of it, and read live so a revocation lands within a poll.
                    .with_bundle_subjects(gateway.bundles.clone()),
                ));
                tracing::info!(
                    listen = %sts_cfg.listen,
                    issuer = %sts_cfg.issuer,
                    role_name_template = ?sts_cfg.role_name_template,
                    max_duration_secs = sts_cfg.max_duration_secs,
                    "AssumeRoleWithWebIdentity is served on the mint listener \
                     (unauthenticated by design: the web identity token is the credential)"
                );
            } else {
                tracing::warn!(
                    "sts_mint.web_identity_enabled is false: no S3 client can obtain a \
                     credential from this gateway on its own"
                );
            }
            let mint = Arc::new(mint);
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

    // The internal session endpoint: authenticated, on a listener of its own. Absent
    // from the config ⇒ no task, no bind, no port. See `s0::internal` for why it is not
    // a route on the admin listener.
    let internal_task = match &config.internal {
        Some(internal_cfg) => {
            let api = Arc::new(
                InternalApi::new(
                    internal_cfg,
                    gateway.identity.sts(),
                    gateway.registry.clone(),
                )
                // The same derived-key half the S3 front admits with, so the endpoint
                // cannot mint a key the data plane would refuse. `None` here when no
                // ring is configured, which leaves the route answering 409.
                .with_derived_keys(gateway.identity.derived()),
            );
            let internal_listen = internal_cfg.listen;
            Some(tokio::spawn(async move {
                if let Err(e) =
                    internal::serve_with_shutdown(api, internal_listen, shutdown::signal()).await
                {
                    tracing::error!(%e, %internal_listen, "internal api exited");
                }
            }))
        }
        None => None,
    };

    server::serve(gateway, listen).await?;

    // The internal API saw the same signal; let it finish its own drain rather than
    // being aborted with the runtime — an aborted mint looks to its caller like an
    // unexplained credential failure on every deploy.
    if let Some(task) = internal_task
        && tokio::time::timeout(INTERNAL_JOIN_TIMEOUT, task)
            .await
            .is_err()
    {
        tracing::error!("internal api drain timed out");
    }

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
    // spilled rather than aborted with the runtime (on shutdown, no silent
    // audit loss).
    audit_handle.drain(AUDIT_DRAIN_TIMEOUT).await;

    // Admin last: probes and a final metrics scrape stay available for the whole
    // drain, including the audit drain that decides whether anything was lost.
    let _ = admin_stop.send(());
    let _ = tokio::time::timeout(ADMIN_JOIN_TIMEOUT, admin_task).await;
    Ok(())
}
