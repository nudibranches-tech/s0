//! Async, batched audit shipping. The data path only ever `try_send`s onto a
//! bounded queue — it never awaits the sink. A background worker batches records to
//! the control-plane decision-log endpoint and spills to local disk on sink outage.
//!
//! Invariant: **audit-emit failure never fails the request.** Audit loss and authz
//! loss are different failures; a sink outage must not become a storage
//! outage. Overflow/errors raise a loud alert and increment a counter, but the data
//! path proceeds.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use super::backend::{AuditBackend, ControlPlaneBackend, StdoutNdjsonBackend};
use super::record::AuditRecord;

/// Cap on the on-disk spill file: replay reads it whole, so this bounds replay memory
/// during a long sink outage.
const MAX_SPILL_BYTES: u64 = 64 * 1024 * 1024;

/// Gate-denial audit budget: burst, then a sustained refill rate, per replica.
///
/// Check-level denials are the one audit stream an **unauthenticated** caller controls
/// the rate of, so emitting them unconditionally would let a scanner fill the bounded
/// queue and displace *decision* records. Suppression is loud rather than silent: it
/// increments `s0_audit_gate_suppressed_total` and the count rides on the next emitted
/// gate record, so the fact and size of a flood are never lost — only the per-request
/// detail. 8/s sustained is far below the queue's drain rate.
const GATE_BURST: u64 = 64;
const GATE_REFILL_PER_SEC: f64 = 8.0;

/// Counters for everything that can happen to a record between the data path and the
/// control plane.
///
/// The failure mode they describe is **silent**: a dropped audit record produces no
/// client-visible error and no failed request, and in a regulated deployment "we cannot
/// prove this access was logged" is itself the incident. All of these are exported by
/// the admin listener's `/metrics`, because a log line is not alertable the way a
/// counter is.
#[derive(Debug, Default)]
pub struct AuditMetrics {
    /// Records never handed to the worker: the bounded queue was full, or the worker
    /// was gone. Lost.
    pub queue_dropped: AtomicU64,
    /// Records the control plane accepted.
    pub shipped: AtomicU64,
    /// Failed POST attempts (a batch, not a record, count).
    pub post_failures: AtomicU64,
    /// Records written to the spill file after a failed POST. Not lost — pending.
    pub spilled: AtomicU64,
    /// Records lost at the spill layer: the file was at its cap, the write failed, or
    /// a line came back unparseable. Lost.
    pub spill_dropped: AtomicU64,
    /// Records recovered from the spill file and shipped.
    pub spill_replayed: AtomicU64,
    /// Records still in the spill file when the worker exited. **Lost.** The spill lives
    /// on node-local scratch (`emptyDir`), deleted with the pod, so a record left there
    /// at shutdown is gone rather than pending. Deliberately a conservative upper bound:
    /// a bare container restart keeps the `emptyDir` and [`claim_spill_path`] lets the
    /// same instance replay its own file, but over-counting loss is the right direction
    /// to be wrong in.
    pub spill_abandoned: AtomicU64,
    /// Gate-denial records deliberately not emitted because an unauthenticated caller
    /// was producing them faster than the budget (see `GATE_BURST`). **Not** counted as
    /// dropped: this is a policy, not a failure, and the alternative is letting a
    /// scanner evict real decision records. Alert on it separately.
    pub gate_suppressed: AtomicU64,
}

impl AuditMetrics {
    fn add(counter: &AtomicU64, n: usize) {
        counter.fetch_add(n as u64, Ordering::Relaxed);
    }

    /// Every record this process is known to have lost, from either end.
    pub fn dropped_total(&self) -> u64 {
        self.queue_dropped.load(Ordering::Relaxed)
            + self.spill_dropped.load(Ordering::Relaxed)
            + self.spill_abandoned.load(Ordering::Relaxed)
    }
}

/// Token bucket over the gate-denial stream. Cheap and uncontended: gate denials are
/// by definition requests that are going no further, so this is never on a hot path.
#[derive(Debug)]
struct GateBudget {
    state: Mutex<GateBudgetState>,
}

#[derive(Debug)]
struct GateBudgetState {
    tokens: f64,
    last: Instant,
    /// Suppressed since the last record that was actually emitted; handed to that
    /// record and reset, so the count is never merely inferable from a counter delta.
    suppressed_since_last: u64,
}

impl GateBudget {
    fn new() -> Self {
        GateBudget {
            state: Mutex::new(GateBudgetState {
                tokens: GATE_BURST as f64,
                last: Instant::now(),
                suppressed_since_last: 0,
            }),
        }
    }

    /// `Some(n)` to emit, carrying the number suppressed since the previous emission;
    /// `None` to suppress this one.
    fn take(&self) -> Option<u64> {
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();
        let elapsed = now.duration_since(st.last).as_secs_f64();
        st.last = now;
        st.tokens = (st.tokens + elapsed * GATE_REFILL_PER_SEC).min(GATE_BURST as f64);
        if st.tokens < 1.0 {
            st.suppressed_since_last += 1;
            return None;
        }
        st.tokens -= 1.0;
        Some(std::mem::take(&mut st.suppressed_since_last))
    }
}

/// Which [`AuditBackend`] [`spawn`] builds. Selected at boot from
/// `audit.backend` in the gateway config; a test injects its own with
/// [`spawn_with_backend`] instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditBackendKind {
    /// Batched POST to the control-plane decision-log endpoint.
    #[default]
    ControlPlane,
    /// One flat JSON line per record on stdout, for the log agent already tailing the
    /// pod. No `sink_url` is used.
    StdoutNdjson,
}

#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Control-plane ingest, e.g. `https://control-plane/api/v1/decision-logs`.
    /// Unused by [`AuditBackendKind::StdoutNdjson`].
    pub sink_url: String,
    pub backend: AuditBackendKind,
    pub queue_capacity: usize,
    pub batch_max: usize,
    pub flush_interval: Duration,
    pub http_timeout: Duration,
    /// Where records go when the sink is down. **Must not be shared between
    /// replicas** — see [`claim_spill_path`]; a shared RWX volume is unsupported.
    pub spill_path: PathBuf,
    /// Who "this replica" is, for spill ownership. Defaults to
    /// [`crate::config::instance_id`]; settable so a test can act as two replicas in
    /// one process, and so an operator can pin it if the pod name is not the right
    /// identity.
    pub instance: String,
    /// How records are labelled for the consumer that ingests them.
    pub labels: crate::audit::LabelPolicy,
}

impl Default for AuditConfig {
    fn default() -> Self {
        AuditConfig {
            sink_url: "http://127.0.0.1:9000/api/v1/decision-logs".into(),
            backend: AuditBackendKind::ControlPlane,
            queue_capacity: 100_000,
            batch_max: 256,
            flush_interval: Duration::from_secs(2),
            http_timeout: Duration::from_secs(5),
            spill_path: PathBuf::from("/var/lib/s0/audit-spill.ndjson"),
            instance: crate::config::instance_id(),
            labels: crate::audit::LabelPolicy::default(),
        }
    }
}

/// Cheap-to-clone handle held by every request path.
#[derive(Clone)]
pub struct AuditSink {
    tx: mpsc::Sender<AuditRecord>,
    metrics: Arc<AuditMetrics>,
    gate: Arc<GateBudget>,
    labels: crate::audit::LabelPolicy,
}

impl AuditSink {
    /// How this deployment labels records. Every record builder takes it, so a
    /// misconfigured key is one value in one place rather than a constant in the binary.
    pub fn labels(&self) -> &crate::audit::LabelPolicy {
        &self.labels
    }

    /// Emit a **gate** record — a denial from before the policy question existed.
    ///
    /// Separate from [`Self::emit`] because this is the one audit stream whose rate an
    /// unauthenticated caller controls; see `GATE_BURST`. The record carries the number
    /// suppressed since the last emitted one, so a reader sees the flood even though it
    /// does not see every event.
    pub fn emit_gate_denial(&self, mut record: AuditRecord) {
        let Some(suppressed) = self.gate.take() else {
            let n = self.metrics.gate_suppressed.fetch_add(1, Ordering::Relaxed) + 1;
            tracing::warn!(
                gate_suppressed = n,
                "gate-denial audit budget exhausted; this denial is counted, not recorded"
            );
            return;
        };
        if let Some(gate) = record.gate.as_mut() {
            gate.suppressed_since_last = suppressed;
        }
        self.emit(record);
    }

    /// Non-blocking. On overflow the record is dropped with a loud alert — the
    /// request is never held up for the audit queue.
    pub fn emit(&self, record: AuditRecord) {
        if let Err(err) = self.tx.try_send(record) {
            let n = self.metrics.queue_dropped.fetch_add(1, Ordering::Relaxed) + 1;
            match err {
                mpsc::error::TrySendError::Full(_) => {
                    tracing::error!(queue_dropped = n, "audit queue full; record dropped")
                }
                mpsc::error::TrySendError::Closed(_) => {
                    tracing::error!(queue_dropped = n, "audit worker gone; record dropped")
                }
            }
        }
    }

    /// Every record this process is known to have lost. Exported as
    /// `s0_audit_dropped_total`.
    pub fn dropped_total(&self) -> u64 {
        self.metrics.dropped_total()
    }

    /// The full counter set, for the admin listener.
    pub fn metrics(&self) -> Arc<AuditMetrics> {
        self.metrics.clone()
    }
}

/// Awaitable handle for draining the worker on shutdown, so buffered + queued records
/// are shipped instead of aborted when the runtime drops (on shutdown, no silent
/// loss). Held by `main`, awaited after the HTTP server drains.
pub struct AuditHandle {
    join: tokio::task::JoinHandle<()>,
    shutdown: Arc<tokio::sync::Notify>,
}

impl AuditHandle {
    /// Signal the worker to drain everything currently queued + buffered, ship it, then
    /// await the worker (bounded by `timeout`). Call after the HTTP server has drained
    /// its connections, so no new records race the drain.
    pub async fn drain(self, timeout: Duration) {
        self.shutdown.notify_one();
        match tokio::time::timeout(timeout, self.join).await {
            Ok(_) => tracing::info!("audit worker drained on shutdown"),
            Err(_) => {
                tracing::error!("audit worker drain timed out; some records may be lost")
            }
        }
    }
}

/// Spawn the audit worker over the backend `cfg.backend` names, and return the emit
/// handle plus an [`AuditHandle`] for shutdown draining. Must run inside a tokio
/// runtime.
pub fn spawn(cfg: AuditConfig) -> (AuditSink, AuditHandle) {
    let backend: Arc<dyn AuditBackend> = match cfg.backend {
        AuditBackendKind::ControlPlane => {
            let client = reqwest::Client::builder()
                .timeout(cfg.http_timeout)
                .build()
                .unwrap_or_else(|e| {
                    tracing::error!(%e, "audit http client build failed; using default client (no timeout)");
                    reqwest::Client::new()
                });
            Arc::new(ControlPlaneBackend::new(client, cfg.sink_url.clone()))
        }
        AuditBackendKind::StdoutNdjson => Arc::new(StdoutNdjsonBackend),
    };
    spawn_with_backend(cfg, backend)
}

/// [`spawn`] against a caller-supplied backend. This is the seam the retargeting
/// exists for (a Kafka backend is a new type here, not a new spill state machine), and
/// it is how a test observes what the gateway actually recorded.
pub fn spawn_with_backend(
    cfg: AuditConfig,
    backend: Arc<dyn AuditBackend>,
) -> (AuditSink, AuditHandle) {
    let labels = cfg.labels.clone();
    let (tx, rx) = mpsc::channel(cfg.queue_capacity);
    let metrics = Arc::new(AuditMetrics::default());
    let shutdown = Arc::new(tokio::sync::Notify::new());
    let spill_path = claim_spill_path(&cfg.spill_path, &cfg.instance);
    tracing::info!(
        backend = backend.name(),
        spill_path = %spill_path.display(),
        "audit worker starting"
    );
    let join = tokio::spawn(
        Worker {
            rx,
            cfg,
            spill_path,
            backend,
            shutdown: shutdown.clone(),
            metrics: metrics.clone(),
        }
        .run(),
    );
    (
        AuditSink {
            tx,
            metrics,
            gate: Arc::new(GateBudget::new()),
            labels,
        },
        AuditHandle { join, shutdown },
    )
}

/// Resolve the configured spill path to one **this process alone** writes.
///
/// Two replicas sharing a spill file destroy each other's records silently: replay reads
/// the whole file, POSTs it and `remove_file`s it, including records another pod appended
/// but this one never read. A shared RWX volume is therefore unsupported; the spill
/// belongs on node-local scratch with a pod-unique path component. Ownership is claimed
/// here rather than merely documented, via an `<path>.owner` marker: if it names another
/// instance we neither fight over the file nor delete it, but take an instance-unique
/// path and log loudly.
fn claim_spill_path(configured: &Path, instance: &str) -> PathBuf {
    if let Some(parent) = configured.parent()
        && !parent.as_os_str().is_empty()
        && let Err(e) = std::fs::create_dir_all(parent)
    {
        tracing::error!(%e, path = %configured.display(), "audit spill directory unusable");
        return configured.to_path_buf();
    }
    match claim(configured, instance) {
        Ok(true) => configured.to_path_buf(),
        Ok(false) => {
            let unique = instance_unique(configured, instance);
            tracing::error!(
                configured = %configured.display(),
                using = %unique.display(),
                instance,
                "audit spill file is owned by another instance — a spill path shared \
                 between replicas is UNSUPPORTED and loses records; using an \
                 instance-unique path and leaving the existing file for its owner"
            );
            // Best-effort: the unique path embeds our own instance id, so the only way
            // this second claim fails is a genuine fs error, already logged by claim().
            let _ = claim(&unique, instance);
            unique
        }
        Err(e) => {
            // Cannot read/write the marker (read-only mount, no permission). Spilling
            // itself will fail the same way and is already counted; do not also
            // silently relocate the file.
            tracing::error!(%e, path = %configured.display(), "audit spill ownership check failed");
            configured.to_path_buf()
        }
    }
}

/// `true` if `instance` owns `path` after this call, `false` if someone else does.
fn claim(path: &Path, instance: &str) -> std::io::Result<bool> {
    let marker = owner_marker(path);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
    {
        Ok(mut f) => {
            use std::io::Write;
            f.write_all(instance.as_bytes())?;
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            // A restart under a stable identity re-claims its own file, so records
            // spilled before the restart are still replayed.
            Ok(std::fs::read_to_string(&marker)?.trim() == instance)
        }
        Err(e) => Err(e),
    }
}

fn owner_marker(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(".owner");
    PathBuf::from(s)
}

/// `/var/lib/s0/audit-spill.ndjson` + `s0-abc12` ⇒ `/var/lib/s0/audit-spill.s0-abc12.ndjson`.
fn instance_unique(path: &Path, instance: &str) -> PathBuf {
    let sanitized: String = instance
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let name = match path.extension() {
        Some(ext) => format!("{stem}.{sanitized}.{}", ext.to_string_lossy()),
        None => format!("{stem}.{sanitized}"),
    };
    path.with_file_name(name)
}

struct Worker {
    rx: mpsc::Receiver<AuditRecord>,
    cfg: AuditConfig,
    /// The claimed path — never `cfg.spill_path` directly.
    spill_path: PathBuf,
    backend: Arc<dyn AuditBackend>,
    shutdown: Arc<tokio::sync::Notify>,
    metrics: Arc<AuditMetrics>,
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
                        self.finish().await;
                        break;
                    }
                },
                _ = ticker.tick() => {
                    self.flush(&mut buf).await;
                    self.replay_spill().await;
                }
                _ = self.shutdown.notified() => {
                    // Shutdown: drain everything currently queued, ship it, and exit.
                    // serve() has already drained the data path, so nothing races in.
                    while let Ok(rec) = self.rx.try_recv() {
                        buf.push(rec);
                        if buf.len() >= self.cfg.batch_max {
                            self.flush(&mut buf).await;
                        }
                    }
                    self.flush(&mut buf).await;
                    self.finish().await;
                    break;
                }
            }
        }
    }

    /// The last thing the worker does, on either exit path: one final replay attempt,
    /// then count whatever is still on disk as lost.
    ///
    /// A flush that fails spills, so without this the records spilled last — at shutdown
    /// — would never be replayed and would still be reported as pending, on exactly the
    /// event (a rolling update with the sink down) where audit loss matters most.
    async fn finish(&self) {
        self.replay_spill().await;
        let abandoned = self.count_spill_lines().await;
        if abandoned > 0 {
            AuditMetrics::add(&self.metrics.spill_abandoned, abandoned);
            tracing::error!(
                lost = abandoned,
                path = %self.spill_path.display(),
                backend = self.backend.name(),
                "audit spill still non-empty at worker exit; these records are LOST \
                 (node-local spill is deleted with the pod) — they are counted in \
                 s0_audit_dropped_total, not in s0_audit_spilled_total"
            );
        }
    }

    /// Non-empty lines left in the spill file. Counted rather than parsed: an
    /// unparseable line is just as lost as a parseable one, and at this point we are
    /// recording how much was lost, not what.
    async fn count_spill_lines(&self) -> usize {
        match tokio::fs::read_to_string(&self.spill_path).await {
            Ok(c) => c.lines().filter(|l| !l.trim().is_empty()).count(),
            Err(_) => 0,
        }
    }

    async fn flush(&self, buf: &mut Vec<AuditRecord>) {
        if buf.is_empty() {
            return;
        }
        let batch = std::mem::take(buf);
        match self.backend.ship(&batch).await {
            Ok(()) => AuditMetrics::add(&self.metrics.shipped, batch.len()),
            Err(err) => {
                self.metrics.post_failures.fetch_add(1, Ordering::Relaxed);
                tracing::error!(%err, count = batch.len(), backend = self.backend.name(), "audit sink ship failed; spilling to disk");
                self.spill(&batch).await;
            }
        }
    }

    async fn spill(&self, batch: &[AuditRecord]) {
        let mut lines = String::new();
        let mut serialized = 0usize;
        for rec in batch {
            match serde_json::to_string(rec) {
                Ok(s) => {
                    lines.push_str(&s);
                    lines.push('\n');
                    serialized += 1;
                }
                Err(e) => {
                    AuditMetrics::add(&self.metrics.spill_dropped, 1);
                    tracing::error!(%e, "audit spill serialize failed; record lost");
                }
            }
        }
        if let Some(parent) = self.spill_path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }
        // Bound the spill file: replay reads it whole, so unbounded growth during a long
        // outage would OOM the process. At the cap we drop (loud alert) rather than grow.
        if let Ok(meta) = tokio::fs::metadata(&self.spill_path).await
            && meta.len() > MAX_SPILL_BYTES
        {
            AuditMetrics::add(&self.metrics.spill_dropped, serialized);
            tracing::error!(
                size = meta.len(),
                cap = MAX_SPILL_BYTES,
                lost = serialized,
                "audit spill at cap; dropping batch (records lost)"
            );
            return;
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.spill_path)
            .await;
        match file {
            Ok(mut f) => {
                // One `write_all` per batch, and the file is opened in append mode, so
                // a batch is a single positioned write rather than a read-modify-write
                // — the shape that would interleave and corrupt lines.
                if let Err(e) = f.write_all(lines.as_bytes()).await {
                    AuditMetrics::add(&self.metrics.spill_dropped, serialized);
                    tracing::error!(%e, lost = serialized, "audit spill write failed; records lost");
                } else {
                    AuditMetrics::add(&self.metrics.spilled, serialized);
                }
            }
            Err(e) => {
                AuditMetrics::add(&self.metrics.spill_dropped, serialized);
                tracing::error!(%e, lost = serialized, "audit spill open failed; records lost");
            }
        }
    }

    /// Best-effort replay of spilled records once the sink recovers. On a clean POST
    /// the spill file is removed; on failure it is left for the next tick.
    ///
    /// Only this process's own spill file is ever read or removed (see
    /// [`claim_spill_path`]) — the read-whole/POST/delete-whole shape is only correct
    /// for a single writer.
    async fn replay_spill(&self) {
        let contents = match tokio::fs::read_to_string(&self.spill_path).await {
            Ok(c) if !c.trim().is_empty() => c,
            _ => return,
        };
        let mut batch: Vec<AuditRecord> = Vec::new();
        let mut unparseable = 0usize;
        for line in contents.lines().filter(|l| !l.trim().is_empty()) {
            match serde_json::from_str(line) {
                Ok(rec) => batch.push(rec),
                // Losing the record is unavoidable here; losing the *fact* is not —
                // silently skipping makes a truncated write look like a clean replay.
                Err(e) => {
                    unparseable += 1;
                    tracing::error!(%e, "audit spill line unparseable; record lost");
                }
            }
        }
        if unparseable > 0 {
            AuditMetrics::add(&self.metrics.spill_dropped, unparseable);
        }
        if batch.is_empty() {
            let _ = tokio::fs::remove_file(&self.spill_path).await;
            return;
        }
        if self.backend.ship(&batch).await.is_ok() {
            let _ = tokio::fs::remove_file(&self.spill_path).await;
            AuditMetrics::add(&self.metrics.spill_replayed, batch.len());
            AuditMetrics::add(&self.metrics.shipped, batch.len());
            tracing::info!(count = batch.len(), "audit spill replayed");
        } else {
            self.metrics.post_failures.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("s0-spill-{tag}-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).expect("tmpdir");
        d
    }

    #[test]
    fn two_replicas_never_share_a_spill_file() {
        let dir = tmpdir("share");
        let configured = dir.join("audit-spill.ndjson");

        // First replica takes the configured path.
        let a = claim_spill_path(&configured, "s0-abc12");
        assert_eq!(a, configured);

        // Second replica, same configured path (a shared RWX volume, or a ConfigMap
        // whose ${POD_NAME} was never interpolated). It must NOT end up on the same
        // file: the replay path reads the whole file, ships it and deletes it, so
        // sharing means each replica silently destroys records the other appended and
        // never read.
        let b = claim_spill_path(&configured, "s0-xyz98");
        assert_ne!(
            b, a,
            "a second replica must not write the first's spill file"
        );
        assert_eq!(b, dir.join("audit-spill.s0-xyz98.ndjson"));

        // The first replica's file is left intact and still owned by it — we relocate
        // rather than take over, so nothing another replica wrote is ever deleted.
        assert_eq!(
            std::fs::read_to_string(dir.join("audit-spill.ndjson.owner")).unwrap(),
            "s0-abc12"
        );

        // A restart under the same identity re-claims its own file, so records spilled
        // before the restart are still replayed rather than orphaned.
        assert_eq!(claim_spill_path(&configured, "s0-abc12"), configured);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn instance_unique_keeps_the_extension_and_sanitizes() {
        assert_eq!(
            instance_unique(Path::new("/var/lib/s0/audit-spill.ndjson"), "pod-1"),
            PathBuf::from("/var/lib/s0/audit-spill.pod-1.ndjson")
        );
        assert_eq!(
            instance_unique(Path::new("/var/lib/s0/spill"), "pod-1"),
            PathBuf::from("/var/lib/s0/spill.pod-1")
        );
        // An instance id is environment-supplied; it must not be able to escape the
        // directory or invent a nested path.
        assert_eq!(
            instance_unique(Path::new("/var/lib/s0/spill.ndjson"), "../../etc/x"),
            PathBuf::from("/var/lib/s0/spill.______etc_x.ndjson")
        );
    }

    /// A backend that fails on demand, so a test can decide whether records spill.
    struct Flaky {
        fail: std::sync::atomic::AtomicBool,
        shipped: Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl AuditBackend for Flaky {
        fn name(&self) -> &'static str {
            "flaky"
        }
        async fn ship(&self, batch: &[AuditRecord]) -> Result<(), String> {
            if self.fail.load(Ordering::Relaxed) {
                return Err("sink down".into());
            }
            let mut got = self.shipped.lock().unwrap();
            got.extend(batch.iter().map(|r| r.decision_id.clone()));
            Ok(())
        }
    }

    fn a_record(id: &str) -> AuditRecord {
        use crate::audit::{BackendOutcome, GatewayMeta, Outcome};
        use crate::authz::{
            Backend, Decision, OpaInput, Principal, PrincipalAttributes, RequestMeta,
        };
        use crate::model::{Action, BackendKind, PrincipalType};
        AuditRecord::new(
            id.into(),
            "2026-07-27T00:00:00Z".into(),
            OpaInput {
                principal: Principal {
                    sub: "alice".into(),
                    kind: PrincipalType::User,
                    attributes: PrincipalAttributes::default(),
                },
                backend: Backend {
                    id: "bay-1".into(),
                    kind: BackendKind::Ceph,
                },
                tenant: "acme".into(),
                organization_id: "org-acme".into(),
                action: Action::ReadObjects,
                bucket: "reports".into(),
                object: Some(format!("{id}.csv")),
                prefix: None,
                copy_source: None,
                delete_keys: None,
                object_tags: None,
                requested_tags: None,
                acl_grants: vec![],
                bypass_governance: false,
                request: RequestMeta::default(),
            },
            Decision::allow("grant matched"),
            GatewayMeta {
                backend_id: "bay-1".into(),
                backend_kind: "ceph".into(),
                outcome: Outcome::Allowed,
                denied_keys: vec![],
                backend: BackendOutcome::NotAttempted,
                backend_status: None,
            },
            &crate::audit::LabelPolicy::default(),
        )
    }

    #[tokio::test]
    async fn records_still_spilled_when_the_worker_exits_are_counted_lost_not_pending() {
        // The spill lives on node-local `emptyDir`, deleted with the pod, so a record
        // still there at worker exit is gone. Reporting it as `spilled` ("pending, not
        // lost") would leave `s0_audit_dropped_total` at 0 on exactly the event (a
        // rolling update with the sink down) it exists to catch.
        let dir = tmpdir("abandoned");
        let backend = Arc::new(Flaky {
            fail: std::sync::atomic::AtomicBool::new(true),
            shipped: Mutex::new(Vec::new()),
        });
        let (sink, handle) = spawn_with_backend(
            AuditConfig {
                spill_path: dir.join("audit-spill.ndjson"),
                instance: "pod-a".into(),
                batch_max: 2,
                flush_interval: Duration::from_millis(20),
                ..AuditConfig::default()
            },
            backend.clone(),
        );
        for i in 0..6 {
            sink.emit(a_record(&format!("rec-{i}")));
        }
        handle.drain(Duration::from_secs(2)).await;

        let m = sink.metrics();
        assert_eq!(m.spilled.load(Ordering::Relaxed), 6, "all six spilled");
        assert_eq!(
            m.spill_abandoned.load(Ordering::Relaxed),
            6,
            "and all six were still on disk when the worker exited"
        );
        assert_eq!(
            sink.dropped_total(),
            6,
            "abandonment must reach the exported loss total; counting it as pending is \
             how audit loss became invisible on the deployment where it happens"
        );

        // Positive control: the same records, same shutdown, with the sink up. Nothing
        // is spilled, nothing is abandoned, and the loss total stays 0 — so the count
        // above is about abandonment, not about shutdown always looking lossy.
        let dir2 = tmpdir("abandoned-ok");
        let backend = Arc::new(Flaky {
            fail: std::sync::atomic::AtomicBool::new(false),
            shipped: Mutex::new(Vec::new()),
        });
        let (sink, handle) = spawn_with_backend(
            AuditConfig {
                spill_path: dir2.join("audit-spill.ndjson"),
                instance: "pod-b".into(),
                batch_max: 2,
                flush_interval: Duration::from_millis(20),
                ..AuditConfig::default()
            },
            backend.clone(),
        );
        for i in 0..6 {
            sink.emit(a_record(&format!("rec-{i}")));
        }
        handle.drain(Duration::from_secs(2)).await;
        assert_eq!(backend.shipped.lock().unwrap().len(), 6);
        assert_eq!(sink.dropped_total(), 0);
        assert_eq!(sink.metrics().spill_abandoned.load(Ordering::Relaxed), 0);

        let _ = std::fs::remove_dir_all(dir);
        let _ = std::fs::remove_dir_all(dir2);
    }

    #[tokio::test]
    async fn a_spill_that_replays_at_shutdown_is_not_counted_as_lost() {
        // The shutdown path tries a replay before it gives up: a sink that came back
        // just before the pod went away must get its records, and nothing may be
        // reported as lost.
        let dir = tmpdir("shutdown-replay");
        let backend = Arc::new(Flaky {
            fail: std::sync::atomic::AtomicBool::new(true),
            shipped: Mutex::new(Vec::new()),
        });
        let (sink, handle) = spawn_with_backend(
            AuditConfig {
                spill_path: dir.join("audit-spill.ndjson"),
                instance: "pod-c".into(),
                batch_max: 2,
                // Long enough that no ticker replay runs before the drain below: the
                // replay under test is the one on the shutdown path.
                flush_interval: Duration::from_secs(30),
                ..AuditConfig::default()
            },
            backend.clone(),
        );
        for i in 0..4 {
            sink.emit(a_record(&format!("rec-{i}")));
        }
        // Wait for the *condition*, not for a duration: shipping is asynchronous and the
        // suite runs in parallel, so a fixed sleep flakes as "the sink lost records"
        // when the truth is "the test was early". The deadline still fails the test if
        // the spill genuinely never happens.
        //
        // The condition is "something reached the disk", not a record count: the flush
        // ticker's first tick is immediate, so it can flush a half-full buffer and leave
        // the remainder batched until a tick 30s away. How the four records divide
        // between spill and buffer is timing, not behaviour — what must hold is that the
        // shutdown path recovers *both* halves, which is what the asserts below check.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while sink.metrics().spilled.load(Ordering::Relaxed) == 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            sink.metrics().spilled.load(Ordering::Relaxed) > 0,
            "records must reach the spill file while the sink is down"
        );

        backend.fail.store(false, Ordering::Relaxed);
        handle.drain(Duration::from_secs(2)).await;

        let mut ids = backend.shipped.lock().unwrap().clone();
        ids.sort();
        assert_eq!(ids, vec!["rec-0", "rec-1", "rec-2", "rec-3"]);
        assert_eq!(sink.dropped_total(), 0);
        // Counters are read only now: `drain` awaited the worker, so nothing is still in
        // flight and the two below cannot be sampled from different instants — read
        // before the drain, `spilled` can miss a batch the worker was mid-spill on while
        // the sink came back, and this would compare a stale count against a final one.
        //
        // The subject of this test is the replay that ran on the shutdown path, not a
        // ticker replay (none can have fired — the interval is 30s) and not the drain's
        // flush of still-buffered records. Without this, a run that shipped everything
        // straight from the buffer would pass and leave the spill path unexercised.
        let m = sink.metrics();
        let spilled = m.spilled.load(Ordering::Relaxed);
        assert!(spilled > 0);
        assert_eq!(
            m.spill_replayed.load(Ordering::Relaxed),
            spilled,
            "every spilled record must be replayed by the shutdown path"
        );
        assert!(
            !dir.join("audit-spill.ndjson").exists(),
            "a fully replayed spill file is removed"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn unparseable_spill_lines_are_counted_not_silently_dropped() {
        let dir = tmpdir("corrupt");
        let spill = dir.join("audit-spill.ndjson");
        // A torn write from a previous process: one good line, one truncated.
        std::fs::write(&spill, "{\"not\":\"a record\"}\n{\"decision_i\n").unwrap();

        let (sink, handle) = spawn(AuditConfig {
            // Unroutable sink so nothing is shipped and the file is left alone.
            sink_url: "http://127.0.0.1:1/none".into(),
            spill_path: spill.clone(),
            instance: "pod-a".into(),
            flush_interval: Duration::from_millis(20),
            http_timeout: Duration::from_millis(50),
            ..AuditConfig::default()
        });
        // Let the ticker run a replay pass.
        tokio::time::sleep(Duration::from_millis(120)).await;
        handle.drain(Duration::from_secs(2)).await;

        // The records are unrecoverable either way; what must not happen is losing the
        // FACT that they were lost — a torn spill file must not look like a clean replay.
        let m = sink.metrics();
        assert_eq!(
            m.spill_dropped.load(Ordering::Relaxed),
            2,
            "both unparseable lines must be counted as lost"
        );
        assert_eq!(sink.dropped_total(), 2, "and surface in the exported total");
        let _ = std::fs::remove_dir_all(dir);
    }
}
