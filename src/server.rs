//! S3 front assembly + hyper serving loop (§4.1). Wires the auth, access, and proxy
//! layers onto an `s3s::S3Service` and serves it with graceful shutdown.
//!
//! Both `set_auth` and `set_access` are required: without `set_auth` the general
//! `check` backstop is silently skipped (substrate trap), which would defeat §6.2.

use std::net::SocketAddr;
use std::sync::Arc;

use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use s3s::config::{S3Config, StaticConfigProvider};
use s3s::service::{S3Service, S3ServiceBuilder};
use tokio::net::TcpListener;

use crate::access::GatewayAccess;
use crate::auth::GatewayAuth;
use crate::error::Result;
use crate::gateway::Gateway;
use crate::proxy::GatewayS3;

pub fn build_service(gw: Arc<Gateway>) -> S3Service {
    let s3 = GatewayS3::new(gw.registry.clone());
    let mut builder = S3ServiceBuilder::new(s3);
    builder.set_auth(GatewayAuth::new(gw.identity.clone()));
    builder.set_access(GatewayAccess::new(gw.clone()));
    builder.set_config(Arc::new(StaticConfigProvider::new(Arc::new(s3_config(&gw)))));
    builder.build()
}

/// Map the gateway's hardening limits onto `s3s::S3Config` (§9.1). `S3Config` is
/// `#[non_exhaustive]`; mutate a `default()` rather than struct-literal it.
fn s3_config(gw: &Gateway) -> S3Config {
    let mut cfg = S3Config::default();
    cfg.xml_max_body_size = gw.limits.xml_max_body_size;
    cfg.post_object_max_file_size = gw.limits.post_object_max_file_size;
    cfg.presigned_url_max_skew_time_secs = gw.limits.presigned_url_max_skew_time_secs;
    cfg
}

pub async fn serve(gw: Arc<Gateway>, listen: SocketAddr) -> Result<()> {
    let service = build_service(gw);
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, "gateway listening");

    let http = ConnBuilder::new(TokioExecutor::new());
    let graceful = GracefulShutdown::new();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%e, "accept failed");
                continue;
            }
        };
        let conn = http.serve_connection(TokioIo::new(stream), service.clone());
        let conn = graceful.watch(conn.into_owned());
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(%peer, %e, "connection ended");
            }
        });
    }
}
