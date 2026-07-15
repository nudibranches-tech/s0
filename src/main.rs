//! Gateway entrypoint: init observability, load config, build the gateway, start the
//! live bundle refresher, and serve.

use std::time::Duration;

use hyperfluid_s3_gateway::bundle_refresh::{self, BundleSource};
use hyperfluid_s3_gateway::config::GatewayConfig;
use hyperfluid_s3_gateway::error::Result;
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
    let gateway = Gateway::build(&config)?;

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

    server::serve(gateway, listen).await
}
