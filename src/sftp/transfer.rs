//! The data path: an object store behind a file protocol (ADR-012 D8, D9, D14).
//!
//! **Uploads** stream to multipart with no local disk. A write handle fills an in-memory
//! part buffer; a full part is sent as `UploadPart` with a bounded number outstanding; a
//! file that never fills one part is committed with a single `PutObject` at CLOSE. The
//! object becomes visible only when the commit succeeds — an S3 reader sees the whole
//! object or nothing — and every error path aborts the multipart upload.
//!
//! **Quotas** (ADR-010): an upload declares no size, but every piece it sends has one, so
//! each is charged to the bundle's byte quotas right before it goes out — a part as it
//! fills, the last part and a small file's `PutObject` at CLOSE, and the commit at zero, as
//! the S3 front charges `UploadPart`, `PutObject` and `CompleteMultipartUpload`. A part's
//! bytes stay in flight until the upload ends: counted as stored when it commits, given
//! back when its abort succeeds (an aborted multipart upload stores nothing), and kept when
//! the abort fails, since the parts then remain until the lifecycle rule removes them.
//!
//! **Downloads** stream one `GetObject`; a non-sequential READ reopens it with a `Range`.

use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use bytes::{Bytes, BytesMut};
use futures_util::StreamExt;
use s3s::dto::ETag;
use tokio::sync::OwnedSemaphorePermit;
use tokio::task::JoinSet;

use super::backend::{BackendError, ByteStream, SftpBackend};
use crate::access::SftpProof;
use crate::config::ConditionalCreate;
use crate::pdp::BundleStore;
use crate::quota::{Admission, QuotaLedger, QuotaRefusal, QuotaReservation, WriteTarget};

/// One part upload's result: its number and ETag.
type PartResult = Result<(i32, ETag), BackendError>;

/// The D14 byte observer: every accepted byte passes it before it is sent.
type Observer = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// How a transfer ended, for the audit record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Commit {
    Committed,
    Aborted,
    Rejected,
    Denied,
}

impl Commit {
    pub fn as_str(self) -> &'static str {
        match self {
            Commit::Committed => "committed",
            Commit::Aborted => "aborted",
            Commit::Rejected => "rejected",
            Commit::Denied => "denied",
        }
    }
}

/// What the client sees when a WRITE or CLOSE fails.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteError {
    /// `SSH_FX_OP_UNSUPPORTED`.
    Unsupported(&'static str),
    /// `SSH_FX_FAILURE`.
    Failure(String),
    /// Refused by a byte quota (ADR-010): the transfer ends as a denial. `reason` is the
    /// audit's, with the figures; `client` is the fixed sentence the client is told.
    Quota {
        reason: String,
        client: &'static str,
    },
}

impl WriteError {
    fn quota(refusal: &QuotaRefusal) -> Self {
        WriteError::Quota {
            reason: refusal.reason(),
            client: refusal.client_message(),
        }
    }
}

/// What an upload is charged against (ADR-010): this replica's ledger, and the quotas of
/// the bundle in force at each charge — like the authorization, re-read as the transfer
/// goes, so a quota lowered or a level filled mid-upload stops it at its next piece.
#[derive(Clone)]
pub struct UploadQuota {
    pub ledger: Arc<QuotaLedger>,
    pub bundles: Arc<BundleStore>,
    pub backend_id: String,
    pub tenant: String,
}

impl UploadQuota {
    /// Charge `bytes` written to `bucket`: `Ok(None)` when no quota applies to it.
    fn charge(
        &self,
        bucket: &str,
        bytes: u64,
    ) -> Result<Option<Arc<QuotaReservation>>, QuotaRefusal> {
        let bundle = self.bundles.current();
        let Some(quotas) = bundle.placement().quotas() else {
            return Ok(None);
        };
        let target = WriteTarget {
            backend: &self.backend_id,
            tenant: &self.tenant,
            bucket,
        };
        match self.ledger.admit(quotas, &target, Some(bytes)) {
            Admission::Unlimited => Ok(None),
            Admission::Reserved(reservation) => {
                // Charged right before the backend call it pays for.
                reservation.mark_dispatched();
                Ok(Some(reservation))
            }
            Admission::Refused(refusal) => Err(refusal),
        }
    }
}

/// Settle a single-call write's reservation with the backend's answer, as the S3 forward
/// path does: kept on success, given back on a refusal (a 4xx) or a call never made, and
/// on an unknown outcome kept, since the write may have landed.
fn settle_call(reservation: Option<Arc<QuotaReservation>>, result: &Result<(), BackendError>) {
    let Some(reservation) = reservation else {
        return;
    };
    match result {
        Ok(()) => reservation.commit(),
        Err(BackendError::Unlicensed(_)) => reservation.release(),
        Err(e) if e.status().is_some_and(|s| (400..500).contains(&s)) => reservation.release(),
        Err(_) => reservation.settle_unknown(),
    }
}

/// The extension point reserved for content inspection (ADR-012 D14).
pub trait CommitGate: Send + Sync {
    fn before_commit(&self, cx: &TransferContext<'_>) -> CommitVerdict;
}

/// What the commit gate sees.
pub struct TransferContext<'a> {
    pub bucket: &'a str,
    pub key: &'a str,
    pub bytes: u64,
}

/// The commit gate's answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitVerdict {
    Commit,
    Reject {
        reason: String,
    },
    /// Refused as unimplemented until a later ADR defines where quarantined objects go.
    Quarantine {
        reason: String,
    },
}

/// v1: nothing is inspected.
pub struct AlwaysCommit;

impl CommitGate for AlwaysCommit {
    fn before_commit(&self, _cx: &TransferContext<'_>) -> CommitVerdict {
        CommitVerdict::Commit
    }
}

/// Per-process registry of keys being uploaded right now. A second create-only OPEN on a
/// key already in flight in this replica is refused (ADR-012 D8). Across replicas only a
/// `native` backend closes the race.
#[derive(Default)]
pub struct InflightKeys {
    keys: Mutex<HashSet<(String, String, String)>>,
}

pub struct InflightGuard {
    owner: Arc<InflightKeys>,
    key: (String, String, String),
}

impl InflightKeys {
    pub fn claim(
        self: &Arc<Self>,
        backend: &str,
        bucket: &str,
        key: &str,
    ) -> Option<InflightGuard> {
        let k = (backend.to_string(), bucket.to_string(), key.to_string());
        let mut g = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if !g.insert(k.clone()) {
            return None;
        }
        Some(InflightGuard {
            owner: self.clone(),
            key: k,
        })
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.owner
            .keys
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.key);
    }
}

/// The transfer-shaping limits, read once at OPEN.
#[derive(Debug, Clone, Copy)]
pub struct UploadLimits {
    pub part_size: usize,
    pub max_inflight_parts: usize,
    pub reorder_window: usize,
    pub max_file_size: u64,
}

/// What one chunk held ahead of the gap is charged against `reorder_window` on top of its
/// length: the map node, the `Bytes` handle and the packet allocation it keeps alive. A
/// window counted in payload bytes alone would let one-byte writes hold ~150× the window.
const AHEAD_ENTRY_OVERHEAD: usize = 256;

/// One write handle's state machine.
pub struct Upload {
    backend: SftpBackend,
    proof: SftpProof,
    pub bucket: String,
    pub key: String,
    /// True on the create path: the commit must not overwrite.
    pub create_only: bool,
    mode: ConditionalCreate,
    limits: UploadLimits,
    /// The next byte offset expected.
    next: u64,
    /// Bytes accepted ahead of `next`, held until the gap fills. Bounded by
    /// `reorder_window`, charged per entry ([`AHEAD_ENTRY_OVERHEAD`]).
    ahead: BTreeMap<u64, Bytes>,
    ahead_cost: usize,
    buf: BytesMut,
    upload_id: Option<String>,
    parts: Vec<(i32, ETag)>,
    inflight: JoinSet<PartResult>,
    failed: Option<String>,
    pub last_write: Instant,
    observer: Observer,
    quota: UploadQuota,
    /// The parts' reservations, in flight until the upload commits or aborts.
    charged: Vec<Arc<QuotaReservation>>,
    // Held for the transfer's lifetime: released on drop.
    _memory: OwnedSemaphorePermit,
    _inflight_key: Option<InflightGuard>,
    finished: bool,
}

impl Upload {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        backend: SftpBackend,
        proof: SftpProof,
        bucket: String,
        key: String,
        create_only: bool,
        mode: ConditionalCreate,
        limits: UploadLimits,
        memory: OwnedSemaphorePermit,
        inflight_key: Option<InflightGuard>,
        quota: UploadQuota,
    ) -> Self {
        Upload {
            backend,
            proof,
            bucket,
            key,
            create_only,
            mode,
            limits,
            next: 0,
            ahead: BTreeMap::new(),
            ahead_cost: 0,
            buf: BytesMut::new(),
            upload_id: None,
            parts: Vec::new(),
            inflight: JoinSet::new(),
            failed: None,
            last_write: Instant::now(),
            // The D14 observer: each byte passes it before it is sent. A no-op in v1.
            observer: Arc::new(|_| {}),
            quota,
            charged: Vec::new(),
            _memory: memory,
            _inflight_key: inflight_key,
            finished: false,
        }
    }

    /// Bytes accepted in order so far.
    pub fn bytes(&self) -> u64 {
        self.next
    }

    pub fn parts(&self) -> u32 {
        (self.parts.len() + self.inflight.len()) as u32
    }

    /// Accept one WRITE. `Ok` means *accepted into the transfer*, not committed.
    ///
    /// A refused WRITE poisons the transfer: its bytes are missing from the object, so
    /// the CLOSE that follows (stock clients CLOSE after a write error) must abort, not
    /// commit a truncated file.
    pub async fn write(&mut self, offset: u64, data: Bytes) -> Result<(), WriteError> {
        self.last_write = Instant::now();
        if let Some(f) = &self.failed {
            return Err(WriteError::Failure(f.clone()));
        }
        let Some(end) = offset.checked_add(data.len() as u64) else {
            return Err(self.refuse(offset));
        };
        if end > self.limits.max_file_size {
            return Err(WriteError::Failure("file too large".into()));
        }
        if data.is_empty() {
            return Ok(());
        }
        if offset < self.next {
            // Overlaps bytes already accepted.
            return Err(self.refuse(offset));
        }
        if offset > self.next {
            let ahead_end = end - self.next;
            let cost = data.len() + AHEAD_ENTRY_OVERHEAD;
            if ahead_end > self.limits.reorder_window as u64
                || self.ahead_cost + cost > self.limits.reorder_window
                || self.overlaps_ahead(offset, end)
            {
                return Err(self.refuse(offset));
            }
            self.ahead_cost += cost;
            self.ahead.insert(offset, data);
            return Ok(());
        }
        if self.overlaps_ahead(offset, end) {
            // In order, but over bytes already held ahead: accepting it would strand the
            // held chunk behind `next` and fail the whole transfer at CLOSE.
            return Err(self.refuse(offset));
        }
        self.append(data).await?;
        // Drain anything the gap was holding back.
        while let Some(entry) = self.ahead.first_entry() {
            if *entry.key() != self.next {
                break;
            }
            let d = entry.remove();
            self.ahead_cost -= d.len() + AHEAD_ENTRY_OVERHEAD;
            self.append(d).await?;
        }
        Ok(())
    }

    fn overlaps_ahead(&self, start: u64, end: u64) -> bool {
        self.ahead
            .range(..end)
            .next_back()
            .is_some_and(|(o, d)| o + d.len() as u64 > start)
            || self.ahead.range(start..end).next().is_some()
    }

    async fn append(&mut self, data: Bytes) -> Result<(), WriteError> {
        (self.observer)(&data);
        self.next += data.len() as u64;
        self.buf.extend_from_slice(&data);
        while self.buf.len() >= self.limits.part_size {
            let part = self.buf.split_to(self.limits.part_size).freeze();
            self.send_part(part).await?;
        }
        Ok(())
    }

    async fn send_part(&mut self, part: Bytes) -> Result<(), WriteError> {
        if self.upload_id.is_none() {
            // Lazily, when the first part fills.
            match self
                .backend
                .create_multipart(&self.proof, &self.bucket, &self.key)
                .await
            {
                Ok(id) => self.upload_id = Some(id),
                Err(e) => return Err(self.fail(format!("backend error: {e}"))),
            }
        }
        // Bounded parts in flight: wait for one to finish before sending another. While
        // this waits, the session reads nothing from the channel, and SSH flow control
        // stops the client.
        while self.inflight.len() >= self.limits.max_inflight_parts {
            self.reap_one().await?;
        }
        let number = (self.parts.len() + self.inflight.len() + 1) as i32;
        if number > 10_000 {
            return Err(self.fail("file too large".into()));
        }
        match self.quota.charge(&self.bucket, part.len() as u64) {
            Ok(reservation) => self.charged.extend(reservation),
            Err(refusal) => return Err(self.refuse_quota(&refusal)),
        }
        let (backend, proof) = (self.backend.clone(), self.proof.clone());
        let (bucket, key) = (self.bucket.clone(), self.key.clone());
        let id = self.upload_id.clone().unwrap_or_default();
        self.inflight.spawn(async move {
            backend
                .upload_part(&proof, &bucket, &key, &id, number, part)
                .await
                .map(|etag| (number, etag))
        });
        Ok(())
    }

    async fn reap_one(&mut self) -> Result<(), WriteError> {
        match self.inflight.join_next().await {
            Some(Ok(Ok(p))) => {
                self.parts.push(p);
                Ok(())
            }
            Some(Ok(Err(e))) => Err(self.fail(format!("backend error: {e}"))),
            Some(Err(e)) => Err(self.fail(format!("part upload task failed: {e}"))),
            None => Ok(()),
        }
    }

    /// Refuse a non-sequential WRITE and poison the transfer: the client sees
    /// `SSH_FX_OP_UNSUPPORTED` for this WRITE, and the next WRITE or the CLOSE aborts.
    fn refuse(&mut self, offset: u64) -> WriteError {
        self.failed = Some(format!(
            "a non-sequential write at byte offset {offset} was refused; nothing was committed"
        ));
        WriteError::Unsupported("non-sequential write")
    }

    fn fail(&mut self, why: String) -> WriteError {
        self.failed = Some(why.clone());
        WriteError::Failure(why)
    }

    /// Refuse a piece over quota and poison the transfer: it cannot complete without it.
    fn refuse_quota(&mut self, refusal: &QuotaRefusal) -> WriteError {
        self.failed = Some(refusal.client_message().to_string());
        WriteError::quota(refusal)
    }

    /// The parts' bytes were stored as an object: count them as completed.
    fn commit_charged(&mut self) {
        for reservation in self.charged.drain(..) {
            reservation.commit();
        }
    }

    /// Abort: `AbortMultipartUpload` if one was started, and no `PutObject`. Idempotent.
    pub async fn abort(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.inflight.abort_all();
        while self.inflight.join_next().await.is_some() {}
        let aborted = match self.upload_id.take() {
            None => true,
            Some(id) => match self
                .backend
                .abort_multipart(&self.proof, &self.bucket, &self.key, &id)
                .await
            {
                Ok(()) => true,
                Err(e) => {
                    // The lifecycle rule (an operator obligation, D9) is the backstop.
                    tracing::warn!(bucket = %self.bucket, key = %self.key, error = %e, "AbortMultipartUpload failed; orphaned parts remain until the bucket lifecycle rule removes them");
                    false
                }
            },
        };
        // An aborted upload stores nothing; one whose abort failed keeps its parts until
        // the lifecycle rule, so they stay counted until a collection sees them gone.
        for reservation in self.charged.drain(..) {
            if aborted {
                reservation.release();
            } else {
                reservation.settle_unknown();
            }
        }
    }

    /// CLOSE: flush, gate, conditional commit. Steps 3–6 of the D14 ordering; the caller
    /// has already re-authorized (step 4) and settles the audit record (step 7).
    pub async fn commit(&mut self, gate: &dyn CommitGate) -> Result<(), (Commit, WriteError)> {
        if !self.ahead.is_empty() {
            self.abort().await;
            return Err((
                Commit::Aborted,
                WriteError::Failure("close with a gap in the written data".into()),
            ));
        }
        if let Some(f) = self.failed.clone() {
            self.abort().await;
            return Err((Commit::Aborted, WriteError::Failure(f)));
        }
        while !self.inflight.is_empty() {
            if let Err(e) = self.reap_one().await {
                self.abort().await;
                return Err((Commit::Aborted, e));
            }
        }
        match gate.before_commit(&TransferContext {
            bucket: &self.bucket,
            key: &self.key,
            bytes: self.next,
        }) {
            CommitVerdict::Commit => {}
            CommitVerdict::Reject { reason } => {
                self.abort().await;
                return Err((Commit::Rejected, WriteError::Failure(reason)));
            }
            CommitVerdict::Quarantine { reason } => {
                self.abort().await;
                return Err((
                    Commit::Rejected,
                    WriteError::Failure(format!(
                        "quarantine is not implemented; upload rejected ({reason})"
                    )),
                ));
            }
        }
        let conditional = self.create_only && self.mode == ConditionalCreate::Native;
        if self.create_only && self.mode == ConditionalCreate::CheckThenWrite {
            // Re-check immediately before the commit. Residual race: one backend round
            // trip, narrowed in-replica by the in-flight registry (D8).
            match self
                .backend
                .head(&self.proof, &self.bucket, &self.key)
                .await
            {
                Ok(None) => {}
                Ok(Some(_)) => {
                    self.abort().await;
                    return Err((Commit::Rejected, WriteError::Failure("file exists".into())));
                }
                Err(e) => {
                    self.abort().await;
                    return Err((
                        Commit::Aborted,
                        WriteError::Failure(format!("backend error: {e}")),
                    ));
                }
            }
        }
        let result = match self.upload_id.clone() {
            None => {
                let data = std::mem::take(&mut self.buf).freeze();
                let reservation = match self.quota.charge(&self.bucket, data.len() as u64) {
                    Ok(reservation) => reservation,
                    Err(refusal) => {
                        self.abort().await;
                        return Err((Commit::Denied, WriteError::quota(&refusal)));
                    }
                };
                let result = self
                    .backend
                    .put(&self.proof, &self.bucket, &self.key, data, conditional)
                    .await;
                settle_call(reservation, &result);
                result
            }
            Some(id) => {
                if !self.buf.is_empty() {
                    let last = std::mem::take(&mut self.buf).freeze();
                    let number = (self.parts.len() + 1) as i32;
                    match self.quota.charge(&self.bucket, last.len() as u64) {
                        Ok(reservation) => self.charged.extend(reservation),
                        Err(refusal) => {
                            self.abort().await;
                            return Err((Commit::Denied, WriteError::quota(&refusal)));
                        }
                    }
                    match self
                        .backend
                        .upload_part(&self.proof, &self.bucket, &self.key, &id, number, last)
                        .await
                    {
                        Ok(etag) => self.parts.push((number, etag)),
                        Err(e) => {
                            self.abort().await;
                            return Err((
                                Commit::Aborted,
                                WriteError::Failure(format!("backend error: {e}")),
                            ));
                        }
                    }
                }
                // Completing adds no bytes (the parts were charged as they went), but it
                // is still a write: charged at zero, refused only once a level is already
                // over its limit — what the S3 front does for CompleteMultipartUpload.
                if let Err(refusal) = self.quota.charge(&self.bucket, 0) {
                    self.abort().await;
                    return Err((Commit::Denied, WriteError::quota(&refusal)));
                }
                self.parts.sort_by_key(|(n, _)| *n);
                self.backend
                    .complete_multipart(
                        &self.proof,
                        &self.bucket,
                        &self.key,
                        &id,
                        self.parts.clone(),
                        conditional,
                    )
                    .await
            }
        };
        match result {
            Ok(()) => {
                self.finished = true;
                self.upload_id = None;
                self.commit_charged();
                Ok(())
            }
            Err(BackendError::PreconditionFailed) => {
                self.abort().await;
                Err((Commit::Rejected, WriteError::Failure("file exists".into())))
            }
            Err(e) => {
                self.abort().await;
                Err((
                    Commit::Aborted,
                    WriteError::Failure(format!("backend error: {e}")),
                ))
            }
        }
    }
}

/// One read handle.
/// A chunk the read-ahead task has pulled, with the budget it holds until consumed.
type Prefetched = (Result<Bytes, String>, Option<OwnedSemaphorePermit>);

/// Download read-ahead (ADR-012 D9): a task pulls the `GetObject` stream ahead of the
/// client's READs, holding at most `budget` bytes. The budget is a semaphore: the task
/// takes permits for a chunk before handing it over, and the reader releases them only
/// once the chunk is fully served, so a slow client stops the task rather than growing
/// memory. Dropping the prefetcher aborts the task and the backend body with it.
struct Prefetch {
    rx: tokio::sync::mpsc::UnboundedReceiver<Prefetched>,
    task: tokio::task::JoinHandle<()>,
}

impl Prefetch {
    fn spawn(mut stream: ByteStream, budget: usize) -> Self {
        let budget = budget.max(1);
        let sem = Arc::new(tokio::sync::Semaphore::new(budget));
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Some(item) = stream.next().await {
                let permit = match &item {
                    Ok(b) => {
                        // A chunk larger than the whole budget takes all of it rather than
                        // waiting forever.
                        let n = u32::try_from(b.len().clamp(1, budget)).unwrap_or(u32::MAX);
                        match sem.clone().acquire_many_owned(n).await {
                            Ok(p) => Some(p),
                            Err(_) => return,
                        }
                    }
                    Err(_) => None,
                };
                let stop = item.is_err();
                if tx.send((item, permit)).is_err() || stop {
                    return;
                }
            }
        });
        Prefetch { rx, task }
    }
}

impl Drop for Prefetch {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// One read handle.
pub struct Download {
    backend: SftpBackend,
    proof: SftpProof,
    pub bucket: String,
    pub key: String,
    pub size: u64,
    pos: u64,
    prefetch: Option<Prefetch>,
    read_ahead: usize,
    pending: Bytes,
    /// The budget held by `pending`, released when it is fully served.
    pending_permit: Option<OwnedSemaphorePermit>,
    pub bytes_sent: u64,
}

impl Download {
    /// Open the stream and start reading ahead. `Ok(None)` when the object does not exist.
    pub async fn open(
        backend: SftpBackend,
        proof: SftpProof,
        bucket: String,
        key: String,
        read_ahead: usize,
    ) -> Result<Option<Self>, BackendError> {
        match backend.get(&proof, &bucket, &key, 0).await {
            Ok((size, stream)) => Ok(Some(Download {
                backend,
                proof,
                bucket,
                key,
                size,
                pos: 0,
                prefetch: Some(Prefetch::spawn(stream, read_ahead)),
                read_ahead,
                pending: Bytes::new(),
                pending_permit: None,
                bytes_sent: 0,
            })),
            Err(BackendError::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Serve one READ. `Ok(None)` is EOF.
    pub async fn read(&mut self, offset: u64, len: u32) -> Result<Option<Bytes>, BackendError> {
        if offset >= self.size {
            return Ok(None);
        }
        if offset != self.pos {
            // Non-sequential: drop what was read ahead and reopen with a Range.
            let (_, stream) = self
                .backend
                .get(&self.proof, &self.bucket, &self.key, offset)
                .await?;
            self.prefetch = Some(Prefetch::spawn(stream, self.read_ahead));
            self.pending = Bytes::new();
            self.pending_permit = None;
            self.pos = offset;
        }
        let want = (len as u64).min(self.size - offset) as usize;
        let mut out = BytesMut::with_capacity(want);
        while out.len() < want {
            if self.pending.is_empty() {
                self.pending_permit = None;
                let next = match self.prefetch.as_mut() {
                    Some(p) => p.rx.recv().await,
                    None => None,
                };
                match next {
                    Some((Ok(b), permit)) => {
                        self.pending = b;
                        self.pending_permit = permit;
                    }
                    Some((Err(e), _)) => {
                        return Err(BackendError::Other {
                            status: None,
                            message: e,
                        });
                    }
                    None => break,
                }
            }
            let take = (want - out.len()).min(self.pending.len());
            out.extend_from_slice(&self.pending.split_to(take));
        }
        if self.pending.is_empty() {
            self.pending_permit = None;
        }
        if out.is_empty() {
            return Ok(None);
        }
        self.pos += out.len() as u64;
        self.bytes_sent += out.len() as u64;
        Ok(Some(out.freeze()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_ahead_pulls_ahead_but_never_past_its_budget() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let pulled = Arc::new(AtomicUsize::new(0));
        let counter = pulled.clone();
        // 100 chunks of 1 KiB, budget 4 KiB.
        let stream: ByteStream = Box::pin(futures_util::stream::iter(0..100).map(move |i| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok::<_, String>(Bytes::from(vec![i as u8; 1024]))
        }));
        let mut p = Prefetch::spawn(stream, 4 * 1024);
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let ahead = pulled.load(Ordering::SeqCst);
        assert!(ahead >= 4, "it reads ahead without being asked ({ahead})");
        assert!(
            ahead <= 5,
            "but holds at most the budget, plus the one chunk it waits to place ({ahead})"
        );
        // Consuming releases budget and lets it continue, in order.
        for i in 0..100u8 {
            let (b, permit) = p.rx.recv().await.unwrap();
            assert_eq!(b.unwrap()[0], i);
            drop(permit);
        }
        assert!(p.rx.recv().await.is_none(), "end of stream");
    }

    #[tokio::test]
    async fn a_chunk_larger_than_the_budget_does_not_deadlock() {
        let stream: ByteStream = Box::pin(futures_util::stream::iter(vec![
            Ok::<_, String>(Bytes::from(vec![1u8; 10_000])),
            Ok(Bytes::from(vec![2u8; 10])),
        ]));
        let mut p = Prefetch::spawn(stream, 1024);
        let (a, pa) = p.rx.recv().await.unwrap();
        assert_eq!(a.unwrap().len(), 10_000);
        drop(pa);
        let (b, _) = p.rx.recv().await.unwrap();
        assert_eq!(b.unwrap().len(), 10);
    }

    #[test]
    fn inflight_keys_are_exclusive_and_released() {
        let r = Arc::new(InflightKeys::default());
        let g = r.claim("b1", "inbound", "k").unwrap();
        assert!(
            r.claim("b1", "inbound", "k").is_none(),
            "upload in progress"
        );
        assert!(r.claim("b1", "inbound", "other").is_some());
        drop(g);
        assert!(r.claim("b1", "inbound", "k").is_some());
    }
}
