//! Async, batched audit shipping (§9.2). The data path only ever `try_send`s onto a
//! bounded queue — it never awaits the sink. A background worker batches records to
//! the console decision-log endpoint and spills to local disk on sink outage.
//!
//! Invariant: **audit-emit failure never fails the request.** Audit loss and authz
//! loss are different failures (§9.2); a console outage must not become a storage
//! outage. Overflow/errors raise a loud alert and increment a counter, but the data
//! path proceeds.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use super::record::AuditRecord;

#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Console ingest, e.g. `https://console/api/v1/decision-logs`.
    pub sink_url: String,
    pub queue_capacity: usize,
    pub batch_max: usize,
    pub flush_interval: Duration,
    pub http_timeout: Duration,
    pub spill_path: PathBuf,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            sink_url: "http://127.0.0.1:9000/api/v1/decision-logs".into(),
            queue_capacity: 100_000,
            batch_max: 256,
            flush_interval: Duration::from_secs(2),
            http_timeout: Duration::from_secs(5),
            spill_path: PathBuf::from("/var/lib/hyperfluid-gateway/audit-spill.ndjson"),
        }
    }
}

/// Cheap-to-clone handle held by every request path.
#[derive(Clone)]
pub struct AuditSink {
    tx: mpsc::Sender<AuditRecord>,
    dropped: Arc<AtomicU64>,
}

impl AuditSink {
    /// Non-blocking. On overflow the record is dropped with a loud alert — the
    /// request is never held up for the audit queue.
    pub fn emit(&self, record: AuditRecord) {
        if let Err(err) = self.tx.try_send(record) {
            let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            match err {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::error!(dropped_total = n, "audit queue full; record dropped")
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!(dropped_total = n, "audit worker gone; record dropped")
                }
            }
        }
    }

    pub fn dropped_total(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Spawn the audit worker and return a handle. Must run inside a tokio runtime.
pub fn spawn(cfg: AuditConfig) -> AuditSink {
    let (tx, rx) = mpsc::channel(cfg.queue_capacity);
    let dropped = Arc::new(AtomicU64::new(0));
    let client = reqwest::Client::builder()
        .timeout(cfg.http_timeout)
        .build()
        .unwrap_or_default();
    tokio::spawn(Worker { rx, cfg, client }.run());
    AuditSink { tx, dropped }
}

struct Worker {
    rx: mpsc::Receiver<AuditRecord>,
    cfg: AuditConfig,
    client: reqwest::Client,
}

impl Worker {
    async fn run(mut self) {
        let mut buf: Vec<AuditRecord> = Vec::with_capacity(self.cfg.batch_max);
        let mut ticker = tokio::time::interval(self.cfg.flush_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                maybe = self.rx.recv() => match maybe {
                    Some(rec) => {
                        buf.push(rec);
                        if buf.len() >= self.cfg.batch_max {
                            self.flush(&mut buf).await;
                        }
                    }
                    None => {
                        self.flush(&mut buf).await;
                        break;
                    }
                },
                _ = ticker.tick() => {
                    self.flush(&mut buf).await;
                    self.replay_spill().await;
                }
            }
        }
    }

    async fn flush(&self, buf: &mut Vec<AuditRecord>) {
        if buf.is_empty() {
            return;
        }
        let batch = std::mem::take(buf);
        if let Err(err) = self.post(&batch).await {
            tracing::error!(%err, count = batch.len(), "audit sink post failed; spilling to disk");
            self.spill(&batch).await;
        }
    }

    async fn post(&self, batch: &[AuditRecord]) -> Result<(), String> {
        let resp = self
            .client
            .post(&self.cfg.sink_url)
            .json(&batch)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("status {}", resp.status()))
        }
    }

    async fn spill(&self, batch: &[AuditRecord]) {
        let mut lines = String::new();
        for rec in batch {
            match serde_json::to_string(rec) {
                Ok(s) => {
                    lines.push_str(&s);
                    lines.push('\n');
                }
                Err(e) => tracing::error!(%e, "audit spill serialize failed"),
            }
        }
        if let Some(parent) = self.cfg.spill_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.cfg.spill_path)
            .await;
        match file {
            Ok(mut f) => {
                if let Err(e) = f.write_all(lines.as_bytes()).await {
                    tracing::error!(%e, "audit spill write failed; records lost");
                }
            }
            Err(e) => tracing::error!(%e, "audit spill open failed; records lost"),
        }
    }

    /// Best-effort replay of spilled records once the sink recovers. On a clean POST
    /// the spill file is truncated; on failure it is left for the next tick.
    async fn replay_spill(&self) {
        let contents = match tokio::fs::read_to_string(&self.cfg.spill_path).await {
            Ok(c) if !c.trim().is_empty() => c,
            _ => return,
        };
        let batch: Vec<AuditRecord> = contents
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect();
        if batch.is_empty() {
            let _ = tokio::fs::remove_file(&self.cfg.spill_path).await;
            return;
        }
        if self.post(&batch).await.is_ok() {
            let _ = tokio::fs::remove_file(&self.cfg.spill_path).await;
            tracing::info!(count = batch.len(), "audit spill replayed");
        }
    }
}
