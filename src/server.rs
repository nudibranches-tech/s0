//! S3 front assembly + hyper serving loop. Wires the auth, access, and proxy
//! layers onto an `s3s::S3Service` and serves it with graceful shutdown.
//!
//! Both `set_auth` and `set_access` are required: without `set_auth` the general
//! `check` backstop is silently skipped (a substrate trap), which would defeat the
//! deny-by-default gate.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use hyper_util::server::graceful::GracefulShutdown;
use s3s::config::{S3Config, StaticConfigProvider};
use s3s::service::{S3Service, S3ServiceBuilder};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

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
    builder.set_config(Arc::new(StaticConfigProvider::new(Arc::new(s3_config(
        &gw,
    )))));
    builder.build()
}

/// Map the gateway's hardening limits onto `s3s::S3Config`. `S3Config` is
/// `#[non_exhaustive]`; mutate a `default()` rather than struct-literal it.
fn s3_config(gw: &Gateway) -> S3Config {
    let mut cfg = S3Config::default();
    cfg.xml_max_body_size = gw.limits.xml_max_body_size;
    cfg.post_object_max_file_size = gw.limits.post_object_max_file_size;
    cfg.presigned_url_max_skew_time_secs = gw.limits.presigned_url_max_skew_time_secs;
    cfg
}

pub async fn serve(gw: Arc<Gateway>, listen: SocketAddr) -> Result<()> {
    let limits = gw.limits.clone();
    let service = build_service(gw);
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, "gateway listening");

    // s3s does not protect the HTTP layer; we own connection bounding, the
    // header-read (slowloris) timeout, h2 keep-alive, and graceful drain.
    // NOTE: the auto builder's h1 `header_read_timeout` needs a timer that does not
    // survive `into_owned()` below, so it panics per connection; a reliable request
    // read-timeout is a follow-up. The connection cap + h2 keep-alive remain.
    let mut http = ConnBuilder::new(TokioExecutor::new());
    http.http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .keep_alive_timeout(Duration::from_secs(20));
    let conn_limit = Arc::new(Semaphore::new(limits.max_connections));
    let graceful = GracefulShutdown::new();

    loop {
        let permit = tokio::select! {
            p = conn_limit.clone().acquire_owned() => p.expect("semaphore never closed"),
            _ = shutdown_signal() => {
                tracing::info!("shutdown signal; draining connections");
                break;
            }
        };
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                // Back off instead of busy-spinning on a persistent accept error
                // (e.g. fd exhaustion). The permit is released by the drop below.
                tracing::warn!(%e, "accept failed; backing off");
                drop(permit);
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let conn = http.serve_connection(TokioIo::new(stream), service.clone());
        let conn = graceful.watch(conn.into_owned());
        tokio::spawn(async move {
            if let Err(e) = conn.await {
                tracing::debug!(%peer, %e, "connection ended");
            }
            drop(permit);
        });
    }

    tokio::select! {
        _ = graceful.shutdown() => tracing::info!("all connections drained"),
        _ = tokio::time::sleep(Duration::from_secs(30)) => {
            tracing::warn!("drain timed out after 30s");
        }
    }
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => {
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
