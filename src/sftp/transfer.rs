//! The data path: an object store behind a file protocol (ADR-009 D8, D9, D14).
//!
//! **Uploads** stream to multipart with no local disk. A write handle fills an in-memory
//! part buffer; a full part is sent as `UploadPart` with a bounded number outstanding; a
//! file that never fills one part is committed with a single `PutObject` at CLOSE. The
//! object becomes visible only when the commit succeeds — an S3 reader sees the whole
//! object or nothing — and every error path aborts the multipart upload.
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
}

/// The extension point reserved for content inspection (ADR-009 D14).
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
/// key already in flight in this replica is refused (ADR-009 D8). Across replicas only a
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
    /// `reorder_window`.
    ahead: BTreeMap<u64, Bytes>,
    ahead_bytes: usize,
    buf: BytesMut,
    upload_id: Option<String>,
    parts: Vec<(i32, ETag)>,
    inflight: JoinSet<PartResult>,
    failed: Option<String>,
    pub last_write: Instant,
    observer: Observer,
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
            ahead_bytes: 0,
            buf: BytesMut::new(),
            upload_id: None,
            parts: Vec::new(),
            inflight: JoinSet::new(),
            failed: None,
            last_write: Instant::now(),
            // The D14 observer: each byte passes it before it is sent. A no-op in v1.
            observer: Arc::new(|_| {}),
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
    pub async fn write(&mut self, offset: u64, data: Bytes) -> Result<(), WriteError> {
        self.last_write = Instant::now();
        if let Some(f) = &self.failed {
            return Err(WriteError::Failure(f.clone()));
        }
        let end = offset
            .checked_add(data.len() as u64)
            .ok_or(WriteError::Unsupported("non-sequential write"))?;
        if end > self.limits.max_file_size {
            return Err(WriteError::Failure("file too large".into()));
        }
        if data.is_empty() {
            return Ok(());
        }
        if offset < self.next {
            // Overlaps bytes already accepted.
            return Err(WriteError::Unsupported("non-sequential write"));
        }
        if offset > self.next {
            let ahead_end = end - self.next;
            if ahead_end > self.limits.reorder_window as u64
                || self.ahead_bytes + data.len() > self.limits.reorder_window
                || self.overlaps_ahead(offset, end)
            {
                return Err(WriteError::Unsupported("non-sequential write"));
            }
            self.ahead_bytes += data.len();
            self.ahead.insert(offset, data);
            return Ok(());
        }
        self.append(data).await?;
        // Drain anything the gap was holding back.
        while let Some(entry) = self.ahead.first_entry() {
            if *entry.key() != self.next {
                break;
            }
            let d = entry.remove();
            self.ahead_bytes -= d.len();
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

    fn fail(&mut self, why: String) -> WriteError {
        self.failed = Some(why.clone());
        WriteError::Failure(why)
    }

    /// Abort: `AbortMultipartUpload` if one was started, and no `PutObject`. Idempotent.
    pub async fn abort(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
        self.inflight.abort_all();
        while self.inflight.join_next().await.is_some() {}
        if let Some(id) = self.upload_id.take()
            && let Err(e) = self
                .backend
                .abort_multipart(&self.proof, &self.bucket, &self.key, &id)
                .await
        {
            // The lifecycle rule (an operator obligation, D9) is the backstop.
            tracing::warn!(bucket = %self.bucket, key = %self.key, error = %e, "AbortMultipartUpload failed; orphaned parts remain until the bucket lifecycle rule removes them");
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
                self.backend
                    .put(&self.proof, &self.bucket, &self.key, data, conditional)
                    .await
            }
            Some(id) => {
                if !self.buf.is_empty() {
                    let last = std::mem::take(&mut self.buf).freeze();
                    let number = (self.parts.len() + 1) as i32;
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
pub struct Download {
    backend: SftpBackend,
    proof: SftpProof,
    pub bucket: String,
    pub key: String,
    pub size: u64,
    pos: u64,
    stream: Option<ByteStream>,
    pending: Bytes,
    pub bytes_sent: u64,
}

impl Download {
    /// Open the stream. `Ok(None)` when the object does not exist.
    pub async fn open(
        backend: SftpBackend,
        proof: SftpProof,
        bucket: String,
        key: String,
    ) -> Result<Option<Self>, BackendError> {
        match backend.get(&proof, &bucket, &key, 0).await {
            Ok((size, stream)) => Ok(Some(Download {
                backend,
                proof,
                bucket,
                key,
                size,
                pos: 0,
                stream: Some(stream),
                pending: Bytes::new(),
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
            // Non-sequential: reopen with a Range.
            let (_, stream) = self
                .backend
                .get(&self.proof, &self.bucket, &self.key, offset)
                .await?;
            self.stream = Some(stream);
            self.pending = Bytes::new();
            self.pos = offset;
        }
        let want = (len as u64).min(self.size - offset) as usize;
        let mut out = BytesMut::with_capacity(want);
        while out.len() < want {
            if self.pending.is_empty() {
                let next = match self.stream.as_mut() {
                    Some(s) => s.next().await,
                    None => None,
                };
                match next {
                    Some(Ok(b)) => self.pending = b,
                    Some(Err(e)) => {
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
