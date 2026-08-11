//! S3 front assembly + hyper serving loop. Wires the auth, access, and proxy
//! layers onto an `s3s::S3Service` and serves it with graceful shutdown.
//!
//! Both `set_auth` and `set_access` are required: without `set_auth` the general `check`
//! backstop is silently skipped, which would defeat the deny-by-default gate.

use std::future::Future;
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
use crate::proxy::{GatewayS3, S3GatewayState};

pub fn build_service(gw: Arc<Gateway>) -> S3Service {
    let s3 = GatewayS3::new(Arc::new(S3GatewayState::new(
        gw.registry.clone(),
        gw.limits.clone(),
    )));
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
///
/// These three are read **once**, at service assembly: `StaticConfigProvider` hands s3s an
/// immutable `Arc<S3Config>`, so changing them needs a restart. Worth saying because they
/// sit in the same `LimitsConfig` as the caps that *are* hot-reloadable.
fn s3_config(gw: &Gateway) -> S3Config {
    let limits = gw.limits();
    let mut cfg = S3Config::default();
    cfg.xml_max_body_size = limits.xml_max_body_size;
    cfg.post_object_max_file_size = limits.post_object_max_file_size;
    cfg.presigned_url_max_skew_time_secs = limits.presigned_url_max_skew_time_secs;
    cfg
}

/// Serve the S3 front until SIGTERM/Ctrl-C, then drain.
pub async fn serve(gw: Arc<Gateway>, listen: SocketAddr) -> Result<()> {
    serve_with_shutdown(gw, listen, crate::shutdown::signal()).await
}

/// As [`serve`], with a caller-supplied shutdown trigger — the seam tests use to
/// drive a real listener through a real drain without a process signal.
pub async fn serve_with_shutdown(
    gw: Arc<Gateway>,
    listen: SocketAddr,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<()> {
    // Read once, before the gateway is moved into the service: the accept loop's
    // connection cap is a property of this listener and cannot change under it.
    let max_connections = gw.limits().max_connections;
    let service = build_service(gw);
    let listener = TcpListener::bind(listen).await?;
    tracing::info!(%listen, "gateway listening");
    tokio::pin!(shutdown);

    // s3s does not protect the HTTP layer; we own connection bounding, h2 keep-alive and
    // graceful drain. The auto builder's h1 `header_read_timeout` is not set: it needs a
    // timer that does not survive the `into_owned()` below, so it panics per connection.
    let mut http = ConnBuilder::new(TokioExecutor::new());
    http.http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Some(Duration::from_secs(20)))
        .keep_alive_timeout(Duration::from_secs(20));
    let conn_limit = Arc::new(Semaphore::new(max_connections));
    let graceful = GracefulShutdown::new();

    loop {
        let permit = tokio::select! {
            p = conn_limit.clone().acquire_owned() => p.expect("semaphore never closed"),
            _ = &mut shutdown => {
                tracing::info!("shutdown signal; draining connections");
                break;
            }
        };
        // `accept` sits INSIDE the select: awaiting it outside means an idle listener does
        // not observe SIGTERM until the next connection happens to arrive, and the process
        // is killed by the grace period instead of draining. Both branches are cancel-safe.
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = &mut shutdown => {
                tracing::info!("shutdown signal; draining connections");
                drop(permit);
                break;
            }
        };
        let (stream, peer) = match accepted {
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
