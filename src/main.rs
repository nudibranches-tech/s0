//! Gateway entrypoint: init observability, load config, build the gateway, start the
//! live bundle refresher, and serve.

use std::sync::Arc;
use std::time::Duration;

use hyperfluid_s3_gateway::bundle_refresh::{self, BundleSource};
use hyperfluid_s3_gateway::config::GatewayConfig;
use hyperfluid_s3_gateway::error::Result;
use hyperfluid_s3_gateway::mint::{self, Mint, StandardVerifier};
use hyperfluid_s3_gateway::{gateway::Gateway, server};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hyperfluid_s3_gateway=debug".into()),
        )
        .json()
        .init();

    let config = GatewayConfig::load()?;
    let listen = config.listen;
    tracing::info!("hyperfluid-s3-gateway starting");
    let (gateway, audit_handle) = Gateway::build(&config)?;

    let source = match &config.bundle_url {
        Some(url) => BundleSource::Http {
            client: reqwest::Client::builder()
                .gzip(true)
                .build()
                .unwrap_or_default(),
            url: url.clone(),
        },
        None => BundleSource::File(config.bundle_path.clone()),
    };
    bundle_refresh::spawn(
        gateway.pdp.clone(),
        gateway.bundles.clone(),
        source,
        Duration::from_secs(config.bundle_poll_secs),
    );

    // The badge desk (§4.2): OIDC token -> gateway session creds, on its own listener.
    if let Some(sts_cfg) = &config.sts_mint {
        let verifier = Arc::new(StandardVerifier::from_config(sts_cfg)?);
        let mint = Arc::new(Mint::new(
            verifier,
            gateway.identity.sts(),
            config.session_ttl(),
        ));
        let mint_listen = sts_cfg.listen;
        tokio::spawn(async move {
            if let Err(e) = mint::serve(mint, mint_listen).await {
                tracing::error!(%e, "sts mint server exited");
            }
        });
    }

    server::serve(gateway, listen).await?;

    // The HTTP server has drained its connections; now drain the audit worker so any
    // queued/buffered records are shipped or spilled rather than aborted with the
    // runtime (§9.2: on shutdown, no silent audit loss).
    audit_handle.drain(Duration::from_secs(10)).await;
    Ok(())
}
