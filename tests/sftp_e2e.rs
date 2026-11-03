//! The SFTP front, end to end (ADR-009): a real SSH client (russh) speaking SFTP v3 to the
//! real front, deciding through the real PDP, forwarding through the real re-signing proxy
//! to an in-memory S3 backend served by s3s over HTTP.
//!
//! What is asserted is what a partner and an auditor would see: status codes, what landed
//! in the bucket, and the audit records.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{BufMut, Bytes, BytesMut};
use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, ssh_key};
use s0::audit::{AuditRecord, SessionEventKind};
use s0::authz::Protocol;
use s0::config::SftpConfig;
use s0::sftp::SftpFront;
use s0::sftp::codec::*;
use s3s::dto::*;
use s3s::{S3, S3Error, S3ErrorCode, S3Request, S3Response, S3Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ── an in-memory S3 backend ──────────────────────────────────────────────────

/// `(bucket, key, parts)` of an in-progress multipart upload.
type Upload = (String, String, BTreeMap<i32, Bytes>);

#[derive(Default)]
struct Mem {
    objects: Mutex<BTreeMap<(String, String), Bytes>>,
    uploads: Mutex<HashMap<String, Upload>>,
    calls: Mutex<Vec<String>>,
    next: AtomicU64,
}

fn not_found() -> S3Error {
    S3Error::new(S3ErrorCode::NoSuchKey)
}

fn precondition() -> S3Error {
    S3Error::new(S3ErrorCode::PreconditionFailed)
}

async fn collect(body: Option<StreamingBlob>) -> Bytes {
    use futures_util::StreamExt;
    let mut out = BytesMut::new();
    if let Some(mut b) = body {
        while let Some(chunk) = b.next().await {
            out.extend_from_slice(&chunk.expect("body chunk"));
        }
    }
    out.freeze()
}

impl Mem {
    fn log(&self, op: &str, key: &str) {
        self.calls.lock().unwrap().push(format!("{op} {key}"));
    }
    fn get(&self, bucket: &str, key: &str) -> Option<Bytes> {
        self.objects
            .lock()
            .unwrap()
            .get(&(bucket.to_string(), key.to_string()))
            .cloned()
    }
    fn calls_matching(&self, op: &str) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.starts_with(op))
            .count()
    }
}

#[async_trait::async_trait]
impl S3 for Mem {
    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        self.log("HeadObject", &req.input.key);
        let o = self
            .get(&req.input.bucket, &req.input.key)
            .ok_or_else(not_found)?;
        Ok(S3Response::new(HeadObjectOutput {
            content_length: Some(o.len() as i64),
            last_modified: Some(Timestamp::from(std::time::SystemTime::now())),
            ..Default::default()
        }))
    }

    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        self.log("GetObject", &req.input.key);
        let o = self
            .get(&req.input.bucket, &req.input.key)
            .ok_or_else(not_found)?;
        let start = match req.input.range {
            Some(Range::Int { first, .. }) => first as usize,
            _ => 0,
        };
        let slice = o.slice(start.min(o.len())..);
        Ok(S3Response::new(GetObjectOutput {
            content_length: Some(slice.len() as i64),
            body: Some(StreamingBlob::from(s3s::Body::from(slice))),
            ..Default::default()
        }))
    }

    async fn put_object(
        &self,
        req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        self.log("PutObject", &req.input.key);
        let k = (req.input.bucket.clone(), req.input.key.clone());
        let data = collect(req.input.body).await;
        let mut objs = self.objects.lock().unwrap();
        if req.input.if_none_match.is_some() && objs.contains_key(&k) {
            return Err(precondition());
        }
        objs.insert(k, data);
        Ok(S3Response::new(PutObjectOutput::default()))
    }

    async fn delete_object(
        &self,
        req: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        self.log("DeleteObject", &req.input.key);
        self.objects
            .lock()
            .unwrap()
            .remove(&(req.input.bucket.clone(), req.input.key.clone()));
        Ok(S3Response::new(DeleteObjectOutput::default()))
    }

    async fn copy_object(
        &self,
        req: S3Request<CopyObjectInput>,
    ) -> S3Result<S3Response<CopyObjectOutput>> {
        self.log("CopyObject", &req.input.key);
        let CopySource::Bucket { bucket, key, .. } = &req.input.copy_source else {
            return Err(S3Error::new(S3ErrorCode::InvalidRequest));
        };
        let data = self.get(bucket, key).ok_or_else(not_found)?;
        self.objects
            .lock()
            .unwrap()
            .insert((req.input.bucket.clone(), req.input.key.clone()), data);
        Ok(S3Response::new(CopyObjectOutput::default()))
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        self.log("ListObjectsV2", req.input.prefix.as_deref().unwrap_or(""));
        let prefix = req.input.prefix.clone().unwrap_or_default();
        let delim = req.input.delimiter.clone();
        let max = req.input.max_keys.unwrap_or(1000).max(1) as usize;
        let objs = self.objects.lock().unwrap();
        let mut contents = Vec::new();
        let mut prefixes: Vec<String> = Vec::new();
        for ((b, k), v) in objs.iter() {
            if b != &req.input.bucket || !k.starts_with(&prefix) {
                continue;
            }
            if let Some(d) = &delim
                && let Some(i) = k[prefix.len()..].find(d.as_str())
            {
                let cp = k[..prefix.len() + i + 1].to_string();
                if !prefixes.contains(&cp) {
                    prefixes.push(cp);
                }
                continue;
            }
            contents.push(Object {
                key: Some(k.clone()),
                size: Some(v.len() as i64),
                last_modified: Some(Timestamp::from(std::time::SystemTime::now())),
                ..Default::default()
            });
        }
        contents.truncate(max);
        Ok(S3Response::new(ListObjectsV2Output {
            name: Some(req.input.bucket.clone()),
            key_count: Some(contents.len() as i32),
            contents: Some(contents),
            common_prefixes: Some(
                prefixes
                    .into_iter()
                    .map(|p| CommonPrefix { prefix: Some(p) })
                    .collect(),
            ),
            is_truncated: Some(false),
            ..Default::default()
        }))
    }

    async fn create_multipart_upload(
        &self,
        req: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        self.log("CreateMultipartUpload", &req.input.key);
        let id = format!("u-{}", self.next.fetch_add(1, Ordering::Relaxed));
        self.uploads.lock().unwrap().insert(
            id.clone(),
            (
                req.input.bucket.clone(),
                req.input.key.clone(),
                BTreeMap::new(),
            ),
        );
        Ok(S3Response::new(CreateMultipartUploadOutput {
            bucket: Some(req.input.bucket.clone()),
            key: Some(req.input.key.clone()),
            upload_id: Some(id),
            ..Default::default()
        }))
    }

    async fn upload_part(
        &self,
        req: S3Request<UploadPartInput>,
    ) -> S3Result<S3Response<UploadPartOutput>> {
        self.log("UploadPart", &req.input.key);
        let data = collect(req.input.body).await;
        let mut ups = self.uploads.lock().unwrap();
        let u = ups
            .get_mut(&req.input.upload_id)
            .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchUpload))?;
        u.2.insert(req.input.part_number, data);
        Ok(S3Response::new(UploadPartOutput {
            e_tag: Some(ETag::Strong(format!("p{}", req.input.part_number))),
            ..Default::default()
        }))
    }

    async fn upload_part_copy(
        &self,
        req: S3Request<UploadPartCopyInput>,
    ) -> S3Result<S3Response<UploadPartCopyOutput>> {
        self.log("UploadPartCopy", &req.input.key);
        let CopySource::Bucket { bucket, key, .. } = &req.input.copy_source else {
            return Err(S3Error::new(S3ErrorCode::InvalidRequest));
        };
        let src = self.get(bucket, key).ok_or_else(not_found)?;
        let (a, b) = req
            .input
            .copy_source_range
            .as_deref()
            .and_then(|r| r.strip_prefix("bytes="))
            .and_then(|r| r.split_once('-'))
            .map(|(a, b)| (a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()))
            .unwrap_or((0, src.len() - 1));
        let mut ups = self.uploads.lock().unwrap();
        let u = ups
            .get_mut(&req.input.upload_id)
            .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchUpload))?;
        u.2.insert(req.input.part_number, src.slice(a..=b));
        Ok(S3Response::new(UploadPartCopyOutput {
            copy_part_result: Some(CopyPartResult {
                e_tag: Some(ETag::Strong(format!("c{}", req.input.part_number))),
                ..Default::default()
            }),
            ..Default::default()
        }))
    }

    async fn complete_multipart_upload(
        &self,
        req: S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<CompleteMultipartUploadOutput>> {
        self.log("CompleteMultipartUpload", &req.input.key);
        let (bucket, key, parts) = self
            .uploads
            .lock()
            .unwrap()
            .remove(&req.input.upload_id)
            .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchUpload))?;
        let mut data = BytesMut::new();
        for p in parts.values() {
            data.extend_from_slice(p);
        }
        let mut objs = self.objects.lock().unwrap();
        if req.input.if_none_match.is_some() && objs.contains_key(&(bucket.clone(), key.clone())) {
            return Err(precondition());
        }
        objs.insert((bucket, key), data.freeze());
        Ok(S3Response::new(CompleteMultipartUploadOutput::default()))
    }

    async fn abort_multipart_upload(
        &self,
        req: S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        self.log("AbortMultipartUpload", &req.input.key);
        self.uploads.lock().unwrap().remove(&req.input.upload_id);
        Ok(S3Response::new(AbortMultipartUploadOutput::default()))
    }
}

async fn serve_backend(mem: Arc<Mem>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let mut b = s3s::service::S3ServiceBuilder::new(MemRef(mem));
    b.set_auth(s3s::auth::SimpleAuth::from_single("OWNER", "OWNERSECRET"));
    let service = b.build();
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let service = service.clone();
            tokio::spawn(async move {
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
            });
        }
    });
    format!("http://{addr}")
}

/// `S3` is implemented on `Mem`; the service needs an owned value.
struct MemRef(Arc<Mem>);

#[async_trait::async_trait]
impl S3 for MemRef {
    async fn head_object(
        &self,
        r: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        self.0.head_object(r).await
    }
    async fn get_object(
        &self,
        r: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        self.0.get_object(r).await
    }
    async fn put_object(
        &self,
        r: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        self.0.put_object(r).await
    }
    async fn delete_object(
        &self,
        r: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        self.0.delete_object(r).await
    }
    async fn copy_object(
        &self,
        r: S3Request<CopyObjectInput>,
    ) -> S3Result<S3Response<CopyObjectOutput>> {
        self.0.copy_object(r).await
    }
    async fn list_objects_v2(
        &self,
        r: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        self.0.list_objects_v2(r).await
    }
    async fn create_multipart_upload(
        &self,
        r: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        self.0.create_multipart_upload(r).await
    }
    async fn upload_part(
        &self,
        r: S3Request<UploadPartInput>,
    ) -> S3Result<S3Response<UploadPartOutput>> {
        self.0.upload_part(r).await
    }
    async fn upload_part_copy(
        &self,
        r: S3Request<UploadPartCopyInput>,
    ) -> S3Result<S3Response<UploadPartCopyOutput>> {
        self.0.upload_part_copy(r).await
    }
    async fn complete_multipart_upload(
        &self,
        r: S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<CompleteMultipartUploadOutput>> {
        self.0.complete_multipart_upload(r).await
    }
    async fn abort_multipart_upload(
        &self,
        r: S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        self.0.abort_multipart_upload(r).await
    }
}

// ── keys ─────────────────────────────────────────────────────────────────────

struct TestRng(u128);
impl ssh_key::rand_core::TryRng for TestRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.try_next_u64()? as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 = self
            .0
            .wrapping_mul(0x2360_ed05_1fc6_5da4_4385_df64_9fcc_f645)
            .wrapping_add(0x5851_f42d_4c95_7f2d_1405_7b7e_f767_814f);
        Ok((self.0 >> 64) as u64 ^ uuid::Uuid::new_v4().as_u128() as u64)
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for c in dst.chunks_mut(8) {
            let v = self.try_next_u64()?.to_le_bytes();
            c.copy_from_slice(&v[..c.len()]);
        }
        Ok(())
    }
}
impl ssh_key::rand_core::TryCryptoRng for TestRng {}

fn ed25519() -> PrivateKey {
    PrivateKey::random(
        &mut TestRng(uuid::Uuid::new_v4().as_u128()),
        Algorithm::Ed25519,
    )
    .unwrap()
}

fn fp(k: &PrivateKey) -> String {
    s0::sftp::account::fingerprint(k.public_key().key_data())
}

// ── the gateway under test ───────────────────────────────────────────────────

fn bundle(drop_key: &PrivateKey, reader_key: &PrivateKey) -> serde_json::Value {
    serde_json::json!({
        "sftp": {
            "version": 1,
            "accounts": {
                "acme-partner-drop": {
                    "tenant": "acme",
                    "subject_key": "sa:partner-drop",
                    "home": { "bucket": "inbound", "prefix": "partner-x/" },
                    "authorized_keys": [ { "key_type": "ssh-ed25519", "fingerprint": fp(drop_key) } ]
                },
                "acme-ops": {
                    "tenant": "acme",
                    "subject_key": "user:ops",
                    "home": { "bucket": "inbound", "prefix": "" },
                    "authorized_keys": [ { "key_type": "ssh-ed25519", "fingerprint": fp(reader_key) } ]
                }
            }
        },
        "org_settings": { "freeze_writes": false },
        "tenants": { "acme": {
            "user_attributes": {
                "partner-drop": { "groups": [], "attributes": {} },
                "ops": { "groups": [], "attributes": {} }
            },
            "bucket_attributes": { "inbound": { "denylist": {} } },
            "s3_grants": {
                "partner-drop": [ { "bucket": "inbound", "actions": ["create_objects"], "prefixes": ["partner-x/"] } ],
                "ops": [ { "bucket": "inbound", "actions": ["*"], "prefixes": [] } ]
            }
        } }
    })
}

struct Harness {
    fx: common::Fixture,
    mem: Arc<Mem>,
    addr: SocketAddr,
    drop_key: PrivateKey,
    ops_key: PrivateKey,
    _stop: tokio::sync::oneshot::Sender<()>,
}

async fn harness(tag: &str, mode: &str) -> Harness {
    let mem = Arc::new(Mem::default());
    let url = serve_backend(mem.clone()).await;
    let drop_key = ed25519();
    let ops_key = ed25519();
    let fx = common::fixture_with_config(tag, bundle(&drop_key, &ops_key), &url, |c| {
        c["backends"][0]["conditional_create"] = serde_json::json!(mode);
    });
    let host = ed25519();
    let host_path = fx.dir.join("ssh_host_ed25519_key");
    std::fs::write(
        &host_path,
        host.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&host_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let cfg: SftpConfig = serde_json::from_value(serde_json::json!({
        "enabled": true,
        "listen": "127.0.0.1:0",
        "host_keys": [host_path],
        "drain_secs": 1
    }))
    .unwrap();
    let front = SftpFront::build(fx.gw.clone(), &cfg).expect("front");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    tokio::spawn(front.serve_on(listener, async {
        let _ = stopped.await;
    }));
    Harness {
        fx,
        mem,
        addr,
        drop_key,
        ops_key,
        _stop: stop,
    }
}

// ── a minimal SFTP client ────────────────────────────────────────────────────

struct Client;
impl russh::client::Handler for Client {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _k: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct Sftp {
    stream: russh::ChannelStream<russh::client::Msg>,
    next_id: u32,
    _session: russh::client::Handle<Client>,
}

#[derive(Debug)]
enum Reply {
    Status(u32, String),
    Handle(Vec<u8>),
    Data(Vec<u8>),
    Name(Vec<String>),
    Attrs(u32),
    Other(u8),
}

fn s(b: &mut BytesMut, v: &[u8]) {
    b.put_u32(v.len() as u32);
    b.put_slice(v);
}

async fn connect(addr: SocketAddr, login: &str, key: &PrivateKey) -> Result<Sftp, String> {
    let cfg = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(cfg, addr, Client)
        .await
        .map_err(|e| e.to_string())?;
    let ok = session
        .authenticate_publickey(
            login,
            PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None),
        )
        .await
        .map_err(|e| e.to_string())?;
    if !ok.success() {
        return Err("authentication failed".into());
    }
    let ch = session
        .channel_open_session()
        .await
        .map_err(|e| e.to_string())?;
    ch.request_subsystem(true, "sftp")
        .await
        .map_err(|e| e.to_string())?;
    let mut sftp = Sftp {
        stream: ch.into_stream(),
        next_id: 1,
        _session: session,
    };
    let mut b = BytesMut::new();
    b.put_u8(SSH_FXP_INIT);
    b.put_u32(3);
    sftp.send_raw(b).await;
    let (t, _) = sftp.recv_raw().await.ok_or("no VERSION")?;
    assert_eq!(t, SSH_FXP_VERSION);
    Ok(sftp)
}

impl Sftp {
    async fn send_raw(&mut self, body: BytesMut) -> bool {
        let mut out = BytesMut::new();
        out.put_u32(body.len() as u32);
        out.extend_from_slice(&body);
        self.stream.write_all(&out).await.is_ok()
    }

    async fn recv_raw(&mut self) -> Option<(u8, Bytes)> {
        let mut len = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(10), self.stream.read_exact(&mut len))
            .await
            .ok()?
            .ok()?;
        let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
        self.stream.read_exact(&mut body).await.ok()?;
        Some((body[0], Bytes::from(body).slice(1..)))
    }

    async fn call(&mut self, kind: u8, f: impl FnOnce(&mut BytesMut)) -> Option<Reply> {
        let id = self.next_id;
        self.next_id += 1;
        let mut b = BytesMut::new();
        b.put_u8(kind);
        b.put_u32(id);
        f(&mut b);
        if !self.send_raw(b).await {
            return None;
        }
        let (t, body) = self.recv_raw().await?;
        let rd = |o: usize| u32::from_be_bytes(body[o..o + 4].try_into().unwrap());
        assert_eq!(rd(0), id, "reply id");
        Some(match t {
            SSH_FXP_STATUS => {
                let code = rd(4);
                let n = rd(8) as usize;
                Reply::Status(code, String::from_utf8_lossy(&body[12..12 + n]).into())
            }
            SSH_FXP_HANDLE => {
                let n = rd(4) as usize;
                Reply::Handle(body[8..8 + n].to_vec())
            }
            SSH_FXP_DATA => {
                let n = rd(4) as usize;
                Reply::Data(body[8..8 + n].to_vec())
            }
            SSH_FXP_NAME => {
                let count = rd(4);
                let mut o = 8;
                let mut names = Vec::new();
                for _ in 0..count {
                    let n = rd(o) as usize;
                    names.push(String::from_utf8_lossy(&body[o + 4..o + 4 + n]).into_owned());
                    o += 4 + n;
                    let l = rd(o) as usize;
                    o += 4 + l;
                    let flags = rd(o);
                    o += 4;
                    if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
                        o += 8;
                    }
                    if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
                        o += 8;
                    }
                    if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
                        o += 4;
                    }
                    if flags & SSH_FILEXFER_ATTR_ACMODTIME != 0 {
                        o += 8;
                    }
                }
                Reply::Name(names)
            }
            SSH_FXP_ATTRS => {
                let flags = rd(4);
                let mut o = 8;
                if flags & SSH_FILEXFER_ATTR_SIZE != 0 {
                    o += 8;
                }
                if flags & SSH_FILEXFER_ATTR_UIDGID != 0 {
                    o += 8;
                }
                Reply::Attrs(if flags & SSH_FILEXFER_ATTR_PERMISSIONS != 0 {
                    rd(o)
                } else {
                    0
                })
            }
            other => Reply::Other(other),
        })
    }

    async fn open(&mut self, path: &str, pflags: u32) -> Reply {
        self.call(SSH_FXP_OPEN, |b| {
            s(b, path.as_bytes());
            b.put_u32(pflags);
            b.put_u32(SSH_FILEXFER_ATTR_PERMISSIONS);
            b.put_u32(0o644);
        })
        .await
        .expect("reply")
    }

    async fn write(&mut self, h: &[u8], offset: u64, data: &[u8]) -> Reply {
        self.call(SSH_FXP_WRITE, |b| {
            s(b, h);
            b.put_u64(offset);
            s(b, data);
        })
        .await
        .expect("reply")
    }

    async fn read(&mut self, h: &[u8], offset: u64, len: u32) -> Reply {
        self.call(SSH_FXP_READ, |b| {
            s(b, h);
            b.put_u64(offset);
            b.put_u32(len);
        })
        .await
        .expect("reply")
    }

    async fn close(&mut self, h: &[u8]) -> Reply {
        self.call(SSH_FXP_CLOSE, |b| s(b, h)).await.expect("reply")
    }

    async fn path_op(&mut self, kind: u8, path: &str) -> Option<Reply> {
        self.call(kind, |b| s(b, path.as_bytes())).await
    }

    /// MKDIR carries an `attrs` field, which every real client sends (and the server
    /// ignores, D8).
    async fn mkdir(&mut self, path: &str) -> Reply {
        self.call(SSH_FXP_MKDIR, |b| {
            s(b, path.as_bytes());
            b.put_u32(SSH_FILEXFER_ATTR_PERMISSIONS);
            b.put_u32(0o755);
        })
        .await
        .expect("reply")
    }

    async fn rename(&mut self, a: &str, b2: &str) -> Reply {
        self.call(SSH_FXP_RENAME, |b| {
            s(b, a.as_bytes());
            s(b, b2.as_bytes());
        })
        .await
        .expect("reply")
    }

    async fn upload(&mut self, path: &str, data: &[u8]) -> Reply {
        let h = match self
            .open(path, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC)
            .await
        {
            Reply::Handle(h) => h,
            other => return other,
        };
        for (i, chunk) in data.chunks(32 * 1024).enumerate() {
            match self.write(&h, (i * 32 * 1024) as u64, chunk).await {
                Reply::Status(0, _) => {}
                other => return other,
            }
        }
        self.close(&h).await
    }

    async fn listdir(&mut self, path: &str) -> Result<Vec<String>, Reply> {
        let h = match self.path_op(SSH_FXP_OPENDIR, path).await.expect("reply") {
            Reply::Handle(h) => h,
            other => return Err(other),
        };
        let mut names = Vec::new();
        loop {
            match self
                .call(SSH_FXP_READDIR, |b| s(b, &h))
                .await
                .expect("reply")
            {
                Reply::Name(n) => names.extend(n),
                Reply::Status(1, _) => break,
                other => return Err(other),
            }
        }
        self.close(&h).await;
        names.sort();
        Ok(names)
    }
}

fn code(r: &Reply) -> u32 {
    match r {
        Reply::Status(c, _) => *c,
        other => panic!("expected a status, got {other:?}"),
    }
}

const OK: u32 = 0;
const EOF: u32 = 1;
const NO_SUCH_FILE: u32 = 2;
const PERMISSION_DENIED: u32 = 3;
const FAILURE: u32 = 4;
const OP_UNSUPPORTED: u32 = 8;

async fn records(fx: &common::Fixture, want: impl Fn(&[AuditRecord]) -> bool) -> Vec<AuditRecord> {
    for _ in 0..200 {
        let all = fx.audit_log.all();
        if want(&all) {
            return all;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    fx.audit_log.all()
}

// ── the scenarios ────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_drop_box_partner_can_create_and_nothing_else() {
    let h = harness("sftp-dropbox", "native").await;
    let mut c = connect(h.addr, "acme-partner-drop", &h.drop_key)
        .await
        .expect("connect");

    // Create: committed, byte for byte, under the home prefix.
    let r = c.upload("/2026-11-03.csv", b"id,amount\n1,10\n").await;
    assert_eq!(code(&r), OK, "{r:?}");
    assert_eq!(
        h.mem.get("inbound", "partner-x/2026-11-03.csv").as_deref(),
        Some(&b"id,amount\n1,10\n"[..])
    );

    // Overwrite: refused at OPEN, before any byte is written.
    let before = h.mem.calls_matching("PutObject");
    let r = c
        .open(
            "/2026-11-03.csv",
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
        )
        .await;
    assert_eq!(code(&r), PERMISSION_DENIED, "{r:?}");
    let Reply::Status(_, msg) = &r else { panic!() };
    assert!(
        msg.starts_with("file exists and overwrite is not granted: "),
        "{msg}"
    );
    assert_eq!(h.mem.calls_matching("PutObject"), before);
    let recs = records(&h.fx, |r| {
        r.iter()
            .any(|x| x.result.reason.contains("overwrite is not granted"))
    })
    .await;
    assert!(
        recs.iter()
            .any(|x| !x.result.allow && x.result.reason.contains("overwrite is not granted")),
        "the refused overwrite is on the record"
    );
    let r = c
        .open(
            "/2026-11-03.csv",
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL,
        )
        .await;
    assert_eq!(
        code(&r),
        FAILURE,
        "EXCL on an existing key is 'file exists'"
    );

    // Read, stat, list: none of it.
    assert_eq!(
        code(&c.open("/2026-11-03.csv", SSH_FXF_READ).await),
        PERMISSION_DENIED
    );
    assert_eq!(
        code(&c.path_op(SSH_FXP_STAT, "/2026-11-03.csv").await.unwrap()),
        PERMISSION_DENIED
    );
    assert!(matches!(
        c.listdir("/").await,
        Err(Reply::Status(PERMISSION_DENIED, _))
    ));
    // The virtual root itself is statable without a decision.
    assert!(
        matches!(c.path_op(SSH_FXP_STAT, "/").await.unwrap(), Reply::Attrs(m) if m & 0o040000 != 0)
    );

    // Delete and rename need verbs a drop box does not hold.
    assert_eq!(
        code(&c.path_op(SSH_FXP_REMOVE, "/2026-11-03.csv").await.unwrap()),
        PERMISSION_DENIED
    );
    assert_eq!(
        code(&c.rename("/2026-11-03.csv", "/x.csv").await),
        PERMISSION_DENIED
    );
    assert!(h.mem.get("inbound", "partner-x/2026-11-03.csv").is_some());

    // No escape from the root, in any spelling.
    for p in ["/../partner-y/a", "../x", "/a/../../b"] {
        assert_eq!(code(&c.upload(p, b"x").await), FAILURE, "{p}");
    }
    assert_eq!(code(&c.upload("/a\\b", b"x").await), FAILURE);
    assert!(h.mem.get("inbound", "partner-y/a").is_none());

    // The audit trail: one decision record per operation, on the S3 decision path,
    // carrying protocol=sftp and the session block.
    let recs = records(&h.fx, |r| {
        r.iter().any(|x| {
            x.gateway
                .session
                .as_ref()
                .is_some_and(|s| s.transfer.as_ref().is_some_and(|t| t.commit == "committed"))
        })
    })
    .await;
    let upload = recs
        .iter()
        .find(|x| {
            x.gateway
                .session
                .as_ref()
                .is_some_and(|s| s.transfer.as_ref().is_some_and(|t| t.commit == "committed"))
        })
        .expect("the committed upload is on the record");
    assert_eq!(upload.path, "s3/authz/decision");
    let input = upload.input.as_ref().unwrap();
    assert_eq!(input.request.protocol, Protocol::Sftp);
    assert_eq!(input.request.method, "OPEN");
    assert_eq!(input.action.as_str(), "create_objects");
    assert_eq!(input.object.as_deref(), Some("partner-x/2026-11-03.csv"));
    let s = upload.gateway.session.as_ref().unwrap();
    assert_eq!(s.login, "acme-partner-drop");
    assert_eq!(s.open_flags, ["WRITE", "CREAT", "TRUNC"]);
    assert_eq!(s.transfer.as_ref().unwrap().bytes, 15);
    assert_eq!(
        upload.labels.get("s0/organization-id").map(String::as_str),
        Some("org-acme")
    );
    assert!(recs.iter().any(|x| {
        x.session_event
            .as_ref()
            .is_some_and(|e| e.event == SessionEventKind::AuthSucceeded)
    }));
}

#[tokio::test]
async fn a_large_upload_streams_as_multipart_and_commits_atomically() {
    let h = harness("sftp-multipart", "native").await;
    let mut c = connect(h.addr, "acme-partner-drop", &h.drop_key)
        .await
        .expect("connect");
    let data: Vec<u8> = (0..(9 * 1024 * 1024 + 123))
        .map(|i| (i % 251) as u8)
        .collect();
    let r = c.upload("/big.bin", &data).await;
    assert_eq!(code(&r), OK, "{r:?}");
    assert_eq!(
        h.mem
            .get("inbound", "partner-x/big.bin")
            .map(|b| b.to_vec()),
        Some(data)
    );
    assert_eq!(h.mem.calls_matching("CreateMultipartUpload"), 1);
    assert_eq!(h.mem.calls_matching("UploadPart "), 2, "8 MiB + the tail");
    assert_eq!(h.mem.calls_matching("CompleteMultipartUpload"), 1);
    assert_eq!(h.mem.calls_matching("PutObject"), 0);
}

#[tokio::test]
async fn a_disconnect_without_close_aborts_and_commits_nothing() {
    let h = harness("sftp-abort", "check_then_write").await;
    let mut c = connect(h.addr, "acme-partner-drop", &h.drop_key)
        .await
        .expect("connect");
    let Reply::Handle(hd) = c
        .open(
            "/partial.bin",
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
        )
        .await
    else {
        panic!()
    };
    let chunk = vec![7u8; 32 * 1024];
    for i in 0..300u64 {
        assert_eq!(code(&c.write(&hd, i * 32 * 1024, &chunk).await), OK);
    }
    drop(c);
    for _ in 0..200 {
        if h.mem.calls_matching("AbortMultipartUpload") > 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(
        h.mem.calls_matching("AbortMultipartUpload"),
        1,
        "the started multipart upload is aborted"
    );
    assert!(
        h.mem.get("inbound", "partner-x/partial.bin").is_none(),
        "nothing is visible"
    );
    assert!(
        h.mem.uploads.lock().unwrap().is_empty(),
        "no orphaned upload"
    );
}

#[tokio::test]
async fn sequential_writes_only_and_the_gap_aborts_at_close() {
    let h = harness("sftp-gap", "native").await;
    let mut c = connect(h.addr, "acme-partner-drop", &h.drop_key)
        .await
        .expect("connect");
    let Reply::Handle(hd) = c
        .open("/gap.bin", SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC)
        .await
    else {
        panic!()
    };
    assert_eq!(code(&c.write(&hd, 0, b"abc").await), OK);
    assert_eq!(
        code(&c.write(&hd, 0, b"abc").await),
        OP_UNSUPPORTED,
        "overlap"
    );
    assert_eq!(
        code(&c.write(&hd, 10, b"xyz").await),
        OK,
        "ahead within the reorder window is held"
    );
    assert_eq!(
        code(&c.write(&hd, 1 << 40, b"x").await),
        FAILURE,
        "beyond max_file_size"
    );
    let Reply::Handle(hd) = c
        .open("/gap2.bin", SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC)
        .await
    else {
        panic!()
    };
    assert_eq!(code(&c.write(&hd, 0, b"abc").await), OK);
    assert_eq!(code(&c.write(&hd, 10, b"xyz").await), OK);
    assert_eq!(
        code(&c.close(&hd).await),
        FAILURE,
        "a CLOSE with a gap is refused"
    );
    assert!(h.mem.get("inbound", "partner-x/gap2.bin").is_none());
    // Append, resume and read-write opens are refused.
    for f in [
        SSH_FXF_WRITE | SSH_FXF_APPEND | SSH_FXF_CREAT,
        SSH_FXF_READ | SSH_FXF_WRITE,
        SSH_FXF_WRITE,
    ] {
        assert_eq!(code(&c.open("/z", f).await), OP_UNSUPPORTED, "{f:#x}");
    }
}

#[tokio::test]
async fn a_full_grant_browses_reads_renames_and_tidies() {
    let h = harness("sftp-ops", "native").await;
    let mut c = connect(h.addr, "acme-ops", &h.ops_key)
        .await
        .expect("connect");
    assert_eq!(code(&c.upload("/in/a.csv", b"alpha").await), OK);
    assert_eq!(code(&c.upload("/in/b.csv", b"beta").await), OK);
    assert_eq!(code(&c.mkdir("/archive").await), OK);
    assert_eq!(code(&c.mkdir("/archive").await), FAILURE, "existing marker");
    assert_eq!(c.listdir("/").await.unwrap(), [".", "..", "archive", "in"]);
    assert_eq!(
        c.listdir("/in").await.unwrap(),
        [".", "..", "a.csv", "b.csv"]
    );
    assert_eq!(
        c.listdir("/archive").await.unwrap(),
        [".", ".."],
        "the marker is not an entry"
    );

    // STAT: file, directory, nothing.
    assert!(
        matches!(c.path_op(SSH_FXP_STAT, "/in/a.csv").await.unwrap(), Reply::Attrs(m) if m & 0o100000 != 0)
    );
    assert!(
        matches!(c.path_op(SSH_FXP_STAT, "/in").await.unwrap(), Reply::Attrs(m) if m & 0o040000 != 0)
    );
    assert_eq!(
        code(&c.path_op(SSH_FXP_STAT, "/nope").await.unwrap()),
        NO_SUCH_FILE
    );

    // Download, sequential and ranged.
    let Reply::Handle(hd) = c.open("/in/a.csv", SSH_FXF_READ).await else {
        panic!()
    };
    assert!(matches!(c.read(&hd, 0, 3).await, Reply::Data(d) if d == b"alp"));
    assert!(matches!(c.read(&hd, 3, 100).await, Reply::Data(d) if d == b"ha"));
    assert!(matches!(c.read(&hd, 1, 2).await, Reply::Data(d) if d == b"lp"));
    assert_eq!(code(&c.read(&hd, 5, 10).await), EOF);
    assert_eq!(code(&c.close(&hd).await), OK);

    // Rename: create-only target refuses an existing name; then a real move.
    assert_eq!(code(&c.rename("/in/a.csv", "/in/b.csv").await), FAILURE);
    assert_eq!(code(&c.rename("/in/a.csv", "/archive/a.csv").await), OK);
    assert!(h.mem.get("inbound", "in/a.csv").is_none());
    assert_eq!(
        h.mem.get("inbound", "archive/a.csv").as_deref(),
        Some(&b"alpha"[..])
    );

    // RMDIR: not empty, then empty.
    assert_eq!(
        code(&c.path_op(SSH_FXP_RMDIR, "/archive").await.unwrap()),
        FAILURE
    );
    assert_eq!(
        code(&c.path_op(SSH_FXP_REMOVE, "/archive/a.csv").await.unwrap()),
        OK
    );
    assert_eq!(
        code(&c.path_op(SSH_FXP_RMDIR, "/archive").await.unwrap()),
        OK
    );
    assert_eq!(
        code(&c.path_op(SSH_FXP_RMDIR, "/archive").await.unwrap()),
        NO_SUCH_FILE
    );
    assert_eq!(
        code(&c.path_op(SSH_FXP_REMOVE, "/nope").await.unwrap()),
        NO_SUCH_FILE
    );

    // Overwrite is allowed with write_objects.
    assert_eq!(code(&c.upload("/in/b.csv", b"beta-2").await), OK);
    assert_eq!(
        h.mem.get("inbound", "in/b.csv").as_deref(),
        Some(&b"beta-2"[..])
    );
}

#[tokio::test]
async fn every_unsupported_request_gets_its_documented_answer() {
    let h = harness("sftp-unsupported", "native").await;
    let mut c = connect(h.addr, "acme-ops", &h.ops_key)
        .await
        .expect("connect");
    let r = c
        .call(SSH_FXP_SYMLINK, |b| {
            s(b, b"/a");
            s(b, b"/b");
        })
        .await
        .unwrap();
    assert_eq!(code(&r), OP_UNSUPPORTED);
    assert_eq!(
        code(&c.path_op(SSH_FXP_READLINK, "/a").await.unwrap()),
        OP_UNSUPPORTED
    );
    let r = c
        .call(SSH_FXP_SETSTAT, |b| {
            s(b, b"/a");
            b.put_u32(SSH_FILEXFER_ATTR_PERMISSIONS);
            b.put_u32(0o777);
        })
        .await
        .unwrap();
    assert_eq!(
        code(&r),
        OP_UNSUPPORTED,
        "chmod is not honoured, so it is not answered OK"
    );
    let r = c
        .call(SSH_FXP_SETSTAT, |b| {
            s(b, b"/a");
            b.put_u32(0);
        })
        .await
        .unwrap();
    assert_eq!(code(&r), OK, "an empty SETSTAT asks for nothing");
    for ext in [
        "statvfs@openssh.com",
        "fsync@openssh.com",
        "hardlink@openssh.com",
        "copy-data",
    ] {
        let r = c
            .call(SSH_FXP_EXTENDED, |b| {
                s(b, ext.as_bytes());
                s(b, b"/a");
            })
            .await
            .unwrap();
        assert_eq!(code(&r), OP_UNSUPPORTED, "{ext}");
    }
    let r = c
        .call(SSH_FXP_EXTENDED, |b| s(b, b"limits@openssh.com"))
        .await
        .unwrap();
    assert!(matches!(r, Reply::Other(SSH_FXP_EXTENDED_REPLY)), "{r:?}");
    let r = c.path_op(SSH_FXP_REALPATH, "/a/../b/.").await.unwrap();
    assert!(
        matches!(&r, Reply::Name(n) if n == &["/b".to_string()]),
        "{r:?}"
    );
    // An unknown packet type: OP_UNSUPPORTED, and the session survives.
    let r = c.call(77, |_| {}).await.unwrap();
    assert_eq!(code(&r), OP_UNSUPPORTED);
    assert!(matches!(
        c.path_op(SSH_FXP_STAT, "/").await.unwrap(),
        Reply::Attrs(_)
    ));
    // A malformed packet: BAD_MESSAGE, then the channel closes.
    let r = c.call(SSH_FXP_STAT, |b| b.put_u32(1_000)).await.unwrap();
    assert_eq!(code(&r), 5);
    assert!(
        c.path_op(SSH_FXP_STAT, "/").await.is_none(),
        "the stream is never resynchronized"
    );
}

#[tokio::test]
async fn authentication_is_by_listed_key_only_and_failures_are_unattributed() {
    let h = harness("sftp-auth", "native").await;
    let stranger = ed25519();
    assert!(
        connect(h.addr, "acme-partner-drop", &stranger)
            .await
            .is_err()
    );
    assert!(connect(h.addr, "no-such-login", &h.drop_key).await.is_err());
    assert!(
        connect(h.addr, "acme-ops", &h.drop_key).await.is_err(),
        "a key reaches only its own login"
    );
    let recs = records(&h.fx, |r| {
        r.iter()
            .filter(|x| {
                x.session_event
                    .as_ref()
                    .is_some_and(|e| e.event == SessionEventKind::AuthFailed)
            })
            .count()
            >= 3
    })
    .await;
    let failures: Vec<_> = recs
        .iter()
        .filter(|x| {
            x.session_event
                .as_ref()
                .is_some_and(|e| e.event == SessionEventKind::AuthFailed)
        })
        .collect();
    assert!(failures.len() >= 3);
    for f in failures {
        assert_eq!(f.path, "sftp/session");
        assert!(!f.result.allow);
        assert!(
            f.result.reason.starts_with("deny (gateway): "),
            "{}",
            f.result.reason
        );
        assert!(
            !f.labels.contains_key("s0/organization-id"),
            "a failed login is a client claim and must not be attributed to an organization"
        );
    }
}

#[tokio::test]
async fn revoking_the_key_closes_an_open_session() {
    let h = harness("sftp-revoke", "native").await;
    let mut c = connect(h.addr, "acme-ops", &h.ops_key)
        .await
        .expect("connect");
    assert_eq!(code(&c.upload("/before.csv", b"x").await), OK);
    // The control plane removes the key: a new bundle revision.
    let mut b = bundle(&h.drop_key, &h.ops_key);
    b["sftp"]["accounts"]["acme-ops"]["authorized_keys"] = serde_json::json!([]);
    h.fx.gw.bundles.store(s0::pdp::Bundle::new("rev-2", b));
    // The sweep on the swap closes the idle session; at the latest the next request does.
    let r = c.path_op(SSH_FXP_STAT, "/before.csv").await;
    assert!(r.is_none(), "the session must be closed, got {r:?}");
    let recs = records(&h.fx, |r| {
        r.iter().any(|x| {
            x.session_event
                .as_ref()
                .is_some_and(|e| e.event == SessionEventKind::Disconnected)
                && x.result.reason.contains("credential_revoked")
        })
    })
    .await;
    assert!(
        recs.iter()
            .any(|x| x.result.reason.contains("credential_revoked")),
        "the revocation is on the record"
    );
    assert!(connect(h.addr, "acme-ops", &h.ops_key).await.is_err());
}

#[tokio::test]
async fn freeze_writes_covers_sftp_creates() {
    let h = harness("sftp-freeze", "native").await;
    let mut b = bundle(&h.drop_key, &h.ops_key);
    b["org_settings"]["freeze_writes"] = serde_json::json!(true);
    h.fx.gw.pdp.reload(None, &b).await.unwrap();
    h.fx.gw.bundles.store(s0::pdp::Bundle::new("rev-frozen", b));
    let mut c = connect(h.addr, "acme-partner-drop", &h.drop_key)
        .await
        .expect("connect");
    let r = c.upload("/frozen.csv", b"x").await;
    assert_eq!(code(&r), PERMISSION_DENIED, "{r:?}");
    if let Reply::Status(_, msg) = &r {
        assert!(msg.contains("frozen"), "{msg}");
    }
}

#[tokio::test]
async fn every_channel_type_and_request_other_than_sftp_is_refused() {
    let h = harness("sftp-channels", "native").await;
    let cfg = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(cfg, h.addr, Client).await.unwrap();
    assert!(
        session
            .authenticate_publickey(
                "acme-ops",
                PrivateKeyWithHashAlg::new(Arc::new(h.ops_key.clone()), None)
            )
            .await
            .unwrap()
            .success()
    );

    // Port forwarding, in both directions, is refused.
    assert!(
        session
            .channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 1)
            .await
            .is_err()
    );
    assert!(session.tcpip_forward("127.0.0.1", 0).await.is_err());

    // One session channel per connection: a second one is refused.
    let _first = session.channel_open_session().await.unwrap();
    assert!(
        session.channel_open_session().await.is_err(),
        "a second session channel"
    );

    // exec / shell / pty on a session channel: an explicit failure, never a silent Ok.
    // (`env` is refused without closing the channel: see `env_then_sftp_works_like_stock_openssh`.)
    for which in ["exec", "shell", "pty", "subsystem-other"] {
        let cfg = Arc::new(russh::client::Config::default());
        let mut session = russh::client::connect(cfg, h.addr, Client).await.unwrap();
        assert!(
            session
                .authenticate_publickey(
                    "acme-ops",
                    PrivateKeyWithHashAlg::new(Arc::new(h.ops_key.clone()), None)
                )
                .await
                .unwrap()
                .success()
        );
        let mut ch = session.channel_open_session().await.unwrap();
        match which {
            "exec" => ch.exec(true, "id").await.unwrap(),
            "shell" => ch.request_shell(true).await.unwrap(),
            "pty" => ch
                .request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .unwrap(),
            _ => ch.request_subsystem(true, "shell").await.unwrap(),
        }
        let mut saw_failure = false;
        while let Some(msg) = tokio::time::timeout(Duration::from_secs(5), ch.wait())
            .await
            .ok()
            .flatten()
        {
            match msg {
                russh::ChannelMsg::Failure => saw_failure = true,
                russh::ChannelMsg::Success => panic!("{which} was accepted"),
                russh::ChannelMsg::Close => break,
                _ => {}
            }
        }
        assert!(saw_failure, "{which} must get SSH_MSG_CHANNEL_FAILURE");
    }
}

#[tokio::test]
async fn a_client_without_strict_kex_is_refused_before_authentication() {
    let h = harness("sftp-terrapin", "native").await;
    let mut cfg = russh::client::Config::default();
    cfg.preferred.kex = std::borrow::Cow::Owned(vec![
        russh::kex::CURVE25519,
        russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
    ]);
    let r = russh::client::connect(Arc::new(cfg), h.addr, Client).await;
    assert!(
        r.is_err(),
        "a Terrapin-vulnerable client must not reach authentication"
    );
    let recs = records(&h.fx, |r| {
        r.iter().any(|x| {
            x.session_event
                .as_ref()
                .is_some_and(|e| e.event == SessionEventKind::PreauthRejected)
        })
    })
    .await;
    let rej = recs
        .iter()
        .find(|x| {
            x.session_event
                .as_ref()
                .is_some_and(|e| e.event == SessionEventKind::PreauthRejected)
        })
        .expect("the refusal is on the record");
    assert!(
        rej.result.reason.contains("strict key exchange"),
        "{}",
        rej.result.reason
    );
}

/// Stock OpenSSH with `SendEnv LANG LC_*` (the Debian, Ubuntu and macOS default) sends
/// `env` before `subsystem sftp` on the same channel. The env is refused, and the session
/// must still start.
#[tokio::test]
async fn env_then_sftp_works_like_stock_openssh() {
    let h = harness("sftp-env", "native").await;
    let cfg = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(cfg, h.addr, Client).await.unwrap();
    assert!(
        session
            .authenticate_publickey(
                "acme-ops",
                PrivateKeyWithHashAlg::new(Arc::new(h.ops_key.clone()), None)
            )
            .await
            .unwrap()
            .success()
    );
    let mut ch = session.channel_open_session().await.unwrap();
    // As OpenSSH does it: no reply asked for…
    ch.set_env(false, "LANG", "en_US.UTF-8").await.unwrap();
    // …and with one, the refusal is explicit.
    ch.set_env(true, "LC_ALL", "C").await.unwrap();
    let mut refused = false;
    while let Some(msg) = tokio::time::timeout(Duration::from_secs(5), ch.wait())
        .await
        .ok()
        .flatten()
    {
        match msg {
            russh::ChannelMsg::Failure => {
                refused = true;
                break;
            }
            russh::ChannelMsg::Success => panic!("env was accepted"),
            russh::ChannelMsg::Close => panic!("env closed the channel"),
            _ => {}
        }
    }
    assert!(
        refused,
        "env must get SSH_MSG_CHANNEL_FAILURE when a reply is asked for"
    );
    ch.request_subsystem(true, "sftp").await.unwrap();
    let mut sftp = Sftp {
        stream: ch.into_stream(),
        next_id: 1,
        _session: session,
    };
    let mut b = BytesMut::new();
    b.put_u8(SSH_FXP_INIT);
    b.put_u32(3);
    assert!(sftp.send_raw(b).await);
    let (t, _) = sftp.recv_raw().await.expect("VERSION after env");
    assert_eq!(t, SSH_FXP_VERSION);
    assert_eq!(code(&sftp.upload("/after-env.csv", b"ok").await), OK);
    assert_eq!(
        h.mem.get("inbound", "after-env.csv").as_deref(),
        Some(&b"ok"[..])
    );
}

/// Downloads larger than the read-ahead budget stream intact, sequentially and after a
/// seek.
#[tokio::test]
async fn a_download_larger_than_the_read_ahead_streams_intact() {
    let h = harness("sftp-readahead", "native").await;
    let mut c = connect(h.addr, "acme-ops", &h.ops_key)
        .await
        .expect("connect");
    let data: Vec<u8> = (0..(3 * 1024 * 1024 + 7))
        .map(|i| (i % 253) as u8)
        .collect();
    assert_eq!(code(&c.upload("/big.bin", &data).await), OK);
    let Reply::Handle(hd) = c.open("/big.bin", SSH_FXF_READ).await else {
        panic!()
    };
    let mut got = Vec::new();
    loop {
        match c.read(&hd, got.len() as u64, 64 * 1024).await {
            Reply::Data(d) => got.extend_from_slice(&d),
            Reply::Status(1, _) => break,
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(got, data, "sequential read through the read-ahead");
    let off = 2 * 1024 * 1024 + 5;
    assert!(
        matches!(c.read(&hd, off as u64, 100).await, Reply::Data(d) if d == data[off..off + 100])
    );
    assert!(
        matches!(c.read(&hd, 10, 100).await, Reply::Data(d) if d == data[10..110]),
        "seek back"
    );
    assert_eq!(code(&c.close(&hd).await), OK);
}

// ── regressions ──────────────────────────────────────────────────────────────

impl Harness {
    /// Push a new bundle revision, to the PDP and to the session watchers.
    async fn push(&self, rev: &str, b: serde_json::Value) {
        self.fx.gw.pdp.reload(None, &b).await.unwrap();
        self.fx.gw.bundles.store(s0::pdp::Bundle::new(rev, b));
    }

    fn put(&self, key: &str, data: &[u8]) {
        self.mem
            .objects
            .lock()
            .unwrap()
            .insert(("inbound".into(), key.into()), Bytes::copy_from_slice(data));
    }

    /// The test bundle with the ops grant scoped to `prefixes`.
    fn ops_scoped(&self, prefixes: &[&str]) -> serde_json::Value {
        let mut b = bundle(&self.drop_key, &self.ops_key);
        b["tenants"]["acme"]["s3_grants"]["ops"] =
            serde_json::json!([{ "bucket": "inbound", "actions": ["*"], "prefixes": prefixes }]);
        b
    }
}

#[tokio::test]
async fn a_listing_whose_scope_narrows_mid_way_is_refused() {
    let h = harness("sftp-rescope", "native").await;
    for i in 0..(READDIR_PAGE + 10) {
        h.put(&format!("reports/f{i:04}.csv"), b"x");
    }
    h.put("reports/public/p.csv", b"x");
    let mut c = connect(h.addr, "acme-ops", &h.ops_key)
        .await
        .expect("connect");
    let Reply::Handle(hd) = c.path_op(SSH_FXP_OPENDIR, "/reports").await.unwrap() else {
        panic!()
    };
    assert!(matches!(
        c.call(SSH_FXP_READDIR, |b| s(b, &hd)).await.unwrap(),
        Reply::Name(_)
    ));
    // The policy narrows the user to reports/public/ while the handle is open.
    h.push("rev-narrow", h.ops_scoped(&["reports/public/"]))
        .await;
    let r = c.call(SSH_FXP_READDIR, |b| s(b, &hd)).await.unwrap();
    assert_eq!(code(&r), PERMISSION_DENIED, "{r:?}");
    // A reopened listing is scoped by the new decision.
    assert_eq!(
        c.listdir("/reports").await.unwrap(),
        vec![".", "..", "public"]
    );
}

/// The server's READDIR batch (`READDIR_BATCH`): more entries than this need a second page.
const READDIR_PAGE: usize = 128;

#[tokio::test]
async fn stat_inside_one_of_several_overlapping_grants_finds_the_file() {
    let h = harness("sftp-stat-overlap", "native").await;
    h.push("rev-overlap", h.ops_scoped(&["home/", "home/docs/2024/"]))
        .await;
    h.put("home/doc", b"hello");
    let mut c = connect(h.addr, "acme-ops", &h.ops_key)
        .await
        .expect("connect");
    let r = c.path_op(SSH_FXP_STAT, "/home/doc").await.unwrap();
    assert!(matches!(r, Reply::Attrs(_)), "{r:?}");
    let r = c.path_op(SSH_FXP_STAT, "/home/nothing").await.unwrap();
    assert_eq!(code(&r), NO_SUCH_FILE, "{r:?}");
}

#[tokio::test]
async fn read_and_directory_handles_are_capped() {
    let h = harness("sftp-handle-cap", "native").await;
    h.put("f.csv", b"x");
    let mut c = connect(h.addr, "acme-ops", &h.ops_key)
        .await
        .expect("connect");
    let mut open = Vec::new();
    for i in 0..64 {
        let r = if i % 2 == 0 {
            c.open("/f.csv", SSH_FXF_READ).await
        } else {
            c.path_op(SSH_FXP_OPENDIR, "/").await.unwrap()
        };
        let Reply::Handle(hd) = r else {
            panic!("handle {i}: {r:?}")
        };
        open.push(hd);
    }
    let r = c.open("/f.csv", SSH_FXF_READ).await;
    assert_eq!(code(&r), FAILURE, "{r:?}");
    let r = c.path_op(SSH_FXP_OPENDIR, "/").await.unwrap();
    assert_eq!(code(&r), FAILURE, "{r:?}");
    // Write handles have their own budget, and closing frees a slot.
    let r = c.upload("/w.csv", b"y").await;
    assert_eq!(code(&r), OK, "{r:?}");
    assert_eq!(code(&c.close(&open.pop().unwrap()).await), OK);
    assert!(matches!(
        c.open("/f.csv", SSH_FXF_READ).await,
        Reply::Handle(_)
    ));
}

#[tokio::test]
async fn an_in_order_write_over_a_held_chunk_is_refused() {
    let h = harness("sftp-overlap-ahead", "native").await;
    let mut c = connect(h.addr, "acme-partner-drop", &h.drop_key)
        .await
        .expect("connect");
    let Reply::Handle(hd) = c
        .open("/o.bin", SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC)
        .await
    else {
        panic!()
    };
    assert_eq!(code(&c.write(&hd, 100, &[2u8; 50]).await), OK, "held ahead");
    assert_eq!(
        code(&c.write(&hd, 0, &[1u8; 150]).await),
        OP_UNSUPPORTED,
        "covers the held chunk"
    );
    // The transfer is intact: the bytes that do fit complete it.
    assert_eq!(code(&c.write(&hd, 0, &[1u8; 100]).await), OK);
    assert_eq!(code(&c.close(&hd).await), OK);
    let got = h.mem.get("inbound", "partner-x/o.bin").unwrap();
    assert_eq!(&got[..100], &[1u8; 100][..]);
    assert_eq!(&got[100..], &[2u8; 50][..]);
}

#[tokio::test]
async fn a_session_does_not_outlive_its_certificate() {
    use russh::keys::ssh_key::certificate::{Builder, CertType};
    let h = harness("sftp-cert-expiry", "native").await;
    let ca = ed25519();
    let user = ed25519();
    let mut b = bundle(&h.drop_key, &h.ops_key);
    b["sftp"]["accounts"]["acme-cert"] = serde_json::json!({
        "tenant": "acme",
        "subject_key": "user:ops",
        "home": { "bucket": "inbound", "prefix": "" },
        "certificate_authorities": ["ops-ca"]
    });
    b["sftp"]["user_cas"] = serde_json::json!({
        "ops-ca": { "key_type": "ssh-ed25519", "fingerprint": fp(&ca), "tenants": ["acme"] }
    });
    h.push("rev-ca", b).await;
    h.put("f.csv", b"x");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let valid_before = now + 3;
    let mut cb = Builder::new_with_random_nonce(
        &mut TestRng(uuid::Uuid::new_v4().as_u128()),
        user.public_key().key_data().clone(),
        now - 60,
        valid_before,
    )
    .unwrap();
    cb.serial(1).unwrap();
    cb.key_id("ops@example.org").unwrap();
    cb.cert_type(CertType::User).unwrap();
    cb.valid_principal("acme-cert").unwrap();
    let cert = cb.sign(&ca).unwrap();

    let cfg = Arc::new(russh::client::Config::default());
    let mut session = russh::client::connect(cfg, h.addr, Client).await.unwrap();
    let ok = session
        .authenticate_openssh_cert("acme-cert", Arc::new(user), cert)
        .await
        .unwrap();
    assert!(ok.success(), "certificate login");
    let ch = session.channel_open_session().await.unwrap();
    ch.request_subsystem(true, "sftp").await.unwrap();
    let mut c = Sftp {
        stream: ch.into_stream(),
        next_id: 1,
        _session: session,
    };
    let mut init = BytesMut::new();
    init.put_u8(SSH_FXP_INIT);
    init.put_u32(3);
    c.send_raw(init).await;
    assert_eq!(c.recv_raw().await.unwrap().0, SSH_FXP_VERSION);
    assert!(matches!(
        c.path_op(SSH_FXP_STAT, "/f.csv").await,
        Some(Reply::Attrs(_))
    ));

    // No bundle change; only the clock moves past valid_before.
    while std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        < valid_before + 1
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let r = c.path_op(SSH_FXP_STAT, "/f.csv").await;
    assert!(r.is_none(), "the session must be closed, got {r:?}");
}
