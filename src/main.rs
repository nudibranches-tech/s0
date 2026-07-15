//! Gateway entrypoint: init observability, load config, build the gateway, serve.

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
    server::serve(gateway, listen).await
}
