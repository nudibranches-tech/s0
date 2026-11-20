//! A bundle endpoint that serves a scripted sequence of documents over raw TCP, and counts
//! the fetches it answered.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use s0::bundle_refresh::{BundleHealth, BundleRefresher, BundleSource};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::Fixture;

pub struct BundleServer {
    pub url: String,
    served: Arc<AtomicUsize>,
}

impl BundleServer {
    /// Serve `bodies` in order, one per fetch, repeating the last, each after `delay`.
    pub async fn start(bodies: Vec<serde_json::Value>, delay: Duration) -> BundleServer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let served = Arc::new(AtomicUsize::new(0));
        let counter = served.clone();
        let bodies: Vec<String> = bodies
            .into_iter()
            .map(|data| serde_json::json!({ "data": data }).to_string())
            .collect();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let n = counter.fetch_add(1, Ordering::SeqCst);
                let body = bodies[n.min(bodies.len() - 1)].clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        match stream.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(read) => buf.extend_from_slice(&chunk[..read]),
                        }
                        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    tokio::time::sleep(delay).await;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        BundleServer {
            url: format!("http://{addr}/bundle"),
            served,
        }
    }

    /// How many fetches reached the server.
    pub fn fetches(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

/// Give `fx`'s gateway a refresher polling `server`, as `Gateway::build` does. Must run
/// before the gateway is served, while the fixture holds the only handle on it.
pub fn install_refresher(fx: &mut Fixture, server: &BundleServer) -> Arc<BundleRefresher> {
    let source =
        BundleSource::http(server.url.clone(), Duration::from_secs(5), None).expect("source");
    let refresher = BundleRefresher::new(
        fx.gw.pdp.clone(),
        fx.gw.bundles.clone(),
        source,
        Arc::new(BundleHealth::new(true)),
    );
    Arc::get_mut(&mut fx.gw)
        .expect("the fixture holds the only handle on its gateway")
        .refresher = Some(refresher.clone());
    refresher
}
