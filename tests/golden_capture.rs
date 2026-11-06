//! The golden-capture harness: the corpus in `tests/data/captured_inputs/` is a
//! **recording** of what the gateway emits, not a description of it. Hand-written
//! fixtures make the policy correct about a request that does not exist. So every fixture
//! comes out of `Enforcer::decide` — the single funnel every PDP question passes
//! through — driven by the real typed hooks; every captured document must survive the
//! round-trip gate (`to_value(from_value::<OpaInput>(raw)?) == raw`), which catches a
//! renamed or dropped field; and every `Coverage::Enforced` op contributes a capture.
//! The SFTP front (ADR-009) decides through the same funnel, so a representative SFTP
//! session is captured into the same corpus, with `request.protocol: "sftp"`.
//!
//! Regenerate with `S0_CAPTURE_REGENERATE=1 cargo test --test golden_capture`, and read
//! the resulting diff as a wire-contract change.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use s0::access::GatewayAccess;
use s0::access::optable::enforced_ops;
use s0::authz::capture::round_trip;
use s3s::access::S3Access;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/captured_inputs")
}

/// Drive every enforced operation through its real hook and return what the PDP was
/// asked, keyed by capture id.
///
/// The request carries the method and URI the operation really arrives with (from the s3s
/// route table), because `RequestMeta` is derived from both: a corpus built from `GET /`
/// would record a method no client sends and a query string that never existed.
async fn capture_enforced_ops() -> (BTreeMap<String, serde_json::Value>, Vec<&'static str>) {
    let fx = common::fixture("golden-capture", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut seen = Vec::new();
    macro_rules! probe {
        ($m:ident, $name:literal, $input:expr) => {{
            let mut req = fx.request_on_route($name, $input);
            access
                .$m(&mut req)
                .await
                .unwrap_or_else(|e| panic!("{} must be allowed by the fixture grant: {e}", $name));
            seen.push($name);
        }};
    }
    crate::each_enforced_op!(probe);
    common::ops::assert_matches_enforced_set(seen.clone());

    // A denial is as much a wire shape as an allow, and it is the one a policy author
    // gets wrong. Capture the deny side of each request shape too.
    let mut req = fx.request_on_route(
        "GetObject",
        s3s::dto::GetObjectInput {
            bucket: "reports".into(),
            key: "2023/outside-the-grant.csv".into(),
            ..Default::default()
        },
    );
    assert!(access.get_object(&mut req).await.is_err());

    let mut req = fx.request_on_route(
        "ListObjectsV2",
        s3s::dto::ListObjectsV2Input {
            bucket: "reports".into(),
            // No prefix at all — the shape a bare `aws s3 ls s3://reports/` sends, and one
            // a policy author has to be able to see in the corpus. It is a DENY for this
            // prefix-scoped fixture, matching AWS (see `policy/gateway/authz.rego`,
            // `narrowed`). What this harness records is the absence of `prefix`.
            prefix: None,
            ..Default::default()
        },
    );
    assert!(access.list_objects_v2(&mut req).await.is_err());

    let mut req = fx.request_on_route(
        "DeleteObjects",
        s3s::dto::DeleteObjectsInput {
            bucket: "reports".into(),
            bypass_governance_retention: None,
            checksum_algorithm: None,
            delete: s3s::dto::Delete {
                objects: vec![
                    s3s::dto::ObjectIdentifier {
                        key: "2024/a.csv".into(),
                        e_tag: None,
                        last_modified_time: None,
                        size: None,
                        version_id: None,
                    },
                    s3s::dto::ObjectIdentifier {
                        key: "2023/b.csv".into(),
                        e_tag: None,
                        last_modified_time: None,
                        size: None,
                        version_id: None,
                    },
                ],
                ..Default::default()
            },
            expected_bucket_owner: None,
            mfa: None,
            request_payer: None,
        },
    );
    assert!(access.delete_objects(&mut req).await.is_ok());

    // A write carrying **riders**. Without this the corpus would contain no document with a
    // non-empty `acl_grants` or a header-derived `requested_tags`, so a policy author would
    // never see either. Deliberately the *allowed* combination — `private` is the one canned
    // ACL that confers nothing and `tier` is outside the reserved namespace — because the
    // refusals this stage adds are screened in code before `decide` and emit no capture.
    let mut req = fx.request_on_route(
        "PutObject",
        s3s::dto::PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            acl: Some(s3s::dto::ObjectCannedACL::from_static(
                s3s::dto::ObjectCannedACL::PRIVATE,
            )),
            tagging: Some("tier=internal".into()),
            ..Default::default()
        },
    );
    access
        .put_object(&mut req)
        .await
        .expect("a no-op canned ACL and an unreserved tag key must still be allowed");

    assert_eq!(
        fx.capture.dropped(),
        0,
        "the capture sink dropped records; the corpus would be incomplete"
    );
    assert_eq!(
        fx.capture.round_trip_failures(),
        0,
        "a captured input does not round-trip through OpaInput — the emitted wire shape \
         and the type have diverged, which is the exact failure this harness exists to \
         catch. Run with --nocapture and read the recorded error."
    );

    // THE structural invariant: the number of questions the PDP was asked equals the number
    // of documents captured. `Enforcer::decide` is the only place a capture is taken,
    // so a second `pdp.decide` call site anywhere on the request path shows up here as a
    // shortfall. The counter sits OUTSIDE the decision cache, so cache hits count too.
    let captured = fx.capture.snapshot();
    assert_eq!(
        captured.len(),
        fx.pdp_calls(),
        "the PDP was asked {} questions but only {} were captured — \
         `Enforcer::decide` is no longer the only call site",
        fx.pdp_calls(),
        captured.len()
    );

    let corpus = fx
        .capture
        .corpus()
        .into_iter()
        .map(|c| (c.id, c.raw))
        .collect();
    (corpus, seen)
}

/// The whole corpus: every enforced S3 operation, and the SFTP front's questions.
/// Both go through `Enforcer::decide`, so they share one directory and one id scheme
/// (`<operation>-<hash>`, where an SFTP operation is the request name: `OPEN`, `STAT`).
async fn capture_corpus() -> BTreeMap<String, serde_json::Value> {
    let (mut corpus, _) = capture_enforced_ops().await;
    for (id, raw) in sftp::capture().await {
        assert!(
            corpus.insert(id.clone(), raw).is_none(),
            "{id}: an SFTP capture collides with an S3 one"
        );
    }
    corpus
}

fn protocol(raw: &serde_json::Value) -> &str {
    raw["request"]["protocol"].as_str().unwrap_or("")
}

#[tokio::test]
async fn decide_is_the_only_pdp_call_site_and_every_capture_round_trips() {
    // The assertions all live in the helpers because the same run has to satisfy them
    // before its output may be written to disk.
    let corpus = capture_corpus().await;
    assert!(!corpus.is_empty());
    for (id, raw) in &corpus {
        round_trip(raw).unwrap_or_else(|e| panic!("{id}: {e}"));
    }
}

#[tokio::test]
async fn sftp_inputs_are_captured_with_their_protocol() {
    // ADR-009 test plan: SFTP-shaped inputs captured at the `Enforcer` funnel, so
    // `fixture_drift` sees `input.request.protocol`.
    let corpus = sftp::capture().await;
    assert!(!corpus.is_empty());
    for (id, raw) in &corpus {
        assert_eq!(protocol(raw), "sftp", "{id}");
    }
    let shapes: BTreeSet<(&str, &str)> = corpus
        .values()
        .map(|raw| {
            (
                raw["request"]["method"].as_str().unwrap_or(""),
                raw["action"].as_str().unwrap_or(""),
            )
        })
        .collect();
    for want in [
        ("OPEN", "create_objects"),
        ("OPEN", "read_objects"),
        ("OPENDIR", "list_objects"),
        ("RENAME", "create_objects"),
        ("REMOVE", "delete_objects"),
    ] {
        assert!(shapes.contains(&want), "no {want:?} capture in {shapes:?}");
    }
    assert!(
        corpus.values().any(|raw| !raw["copy_source"].is_null()),
        "a rename carries its source as `copy_source`"
    );
}

#[tokio::test]
async fn every_enforced_op_contributes_at_least_one_captured_input() {
    // An operation that is enforced but never appears in the corpus is one the policy
    // has never been tested against with a real input.
    let (corpus, _) = capture_enforced_ops().await;
    let ops: BTreeSet<&str> = corpus
        .keys()
        .map(|id| id.rsplit_once('-').expect("capture id shape").0)
        .collect();
    for op in enforced_ops() {
        assert!(
            ops.contains(op),
            "{op} is Coverage::Enforced but emitted no captured input — either its hook \
             does not call the PDP, or it is missing from each_enforced_op!"
        );
    }
}

#[tokio::test]
async fn the_checked_in_corpus_is_what_the_gateway_emits_today() {
    // The drift gate proper. A field rename, a dropped field, a changed default or a hook
    // that stops asking a question all land here as a diff: the corpus is the reviewable
    // artifact, not a cache.
    let corpus = capture_corpus().await;
    let dir = corpus_dir();

    if std::env::var("S0_CAPTURE_REGENERATE").is_ok() {
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("clear corpus");
        }
        std::fs::create_dir_all(&dir).expect("create corpus dir");
        for (id, raw) in &corpus {
            let pretty = serde_json::to_string_pretty(raw).expect("serialize");
            std::fs::write(dir.join(format!("{id}.json")), format!("{pretty}\n"))
                .expect("write capture");
        }
        eprintln!("regenerated {} captured inputs in {dir:?}", corpus.len());
        return;
    }

    let mut on_disk = BTreeMap::new();
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!("no captured corpus at {dir:?} ({e}); run with S0_CAPTURE_REGENERATE=1")
    });
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("file stem")
            .to_string();
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read capture"))
                .unwrap_or_else(|e| panic!("{path:?} is not JSON: {e}"));
        on_disk.insert(id, raw);
    }

    let emitted_ids: BTreeSet<&String> = corpus.keys().collect();
    let stored_ids: BTreeSet<&String> = on_disk.keys().collect();
    let added: Vec<_> = emitted_ids.difference(&stored_ids).collect();
    let removed: Vec<_> = stored_ids.difference(&emitted_ids).collect();
    assert!(
        added.is_empty() && removed.is_empty(),
        "the captured corpus is out of date.\n  now emitted but not checked in: {added:?}\n  \
         checked in but no longer emitted: {removed:?}\n\
         Regenerate with S0_CAPTURE_REGENERATE=1 and review the diff as a change to the \
         OPA input contract."
    );
    for (id, raw) in &corpus {
        assert_eq!(
            on_disk.get(id),
            Some(raw),
            "captured input {id} differs from the checked-in corpus"
        );
    }
}

#[tokio::test]
async fn a_corpus_input_is_a_real_decision_when_replayed() {
    // Replaying every checked-in document through the same engine the gateway runs proves
    // the files are still valid `OpaInput`s and not just well-formed JSON.
    use s0::pdp::{GATEWAY_REGO, Pdp, RegorusPdp};
    let engine = RegorusPdp::new(GATEWAY_REGO, &common::alice_bundle()).expect("regorus");
    let dir = corpus_dir();
    let mut replayed = 0;
    for entry in std::fs::read_dir(&dir).expect("corpus dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        let input: s0::authz::OpaInput = serde_json::from_value(raw)
            .unwrap_or_else(|e| panic!("{path:?} is no longer a valid OpaInput: {e}"));
        engine
            .decide(&input)
            .await
            .unwrap_or_else(|e| panic!("{path:?} failed to evaluate: {e}"));
        replayed += 1;
    }
    assert!(replayed > 0, "the corpus is empty");
}

// ── SFTP: the same funnel, the other protocol (ADR-009) ──────────────────────

/// The SFTP front decides through the same `Enforcer::decide`, so its questions are
/// captured by the same tap. They differ from every S3 capture in
/// `input.request.protocol` (`"sftp"`) and `input.request.method` (the SFTP request),
/// and they are the only producer of `create_objects` on a create-only account. Driven
/// end to end: a russh client speaking SFTP v3 to the real front, forwarding to an
/// in-memory S3 backend.
mod sftp {
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use bytes::{BufMut, Bytes, BytesMut};
    use russh::keys::{Algorithm, PrivateKey, PrivateKeyWithHashAlg, ssh_key};
    use s0::sftp::codec::*;
    use s3s::dto::*;
    use s3s::{S3, S3Error, S3ErrorCode, S3Request, S3Response, S3Result};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// `(bucket, key, parts)` of an in-progress multipart upload.
    type Upload = (String, String, BTreeMap<i32, Bytes>);

    /// Objects, and multipart uploads by id (a create-only rename is a multipart copy).
    #[derive(Default)]
    struct Mem(
        Mutex<BTreeMap<(String, String), Bytes>>,
        Mutex<BTreeMap<String, Upload>>,
    );

    impl Mem {
        fn get(&self, bucket: &str, key: &str) -> Option<Bytes> {
            self.0
                .lock()
                .unwrap()
                .get(&(bucket.to_string(), key.to_string()))
                .cloned()
        }
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

    struct MemRef(Arc<Mem>);

    #[async_trait::async_trait]
    impl S3 for MemRef {
        async fn head_object(
            &self,
            req: S3Request<HeadObjectInput>,
        ) -> S3Result<S3Response<HeadObjectOutput>> {
            let o = self
                .0
                .get(&req.input.bucket, &req.input.key)
                .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchKey))?;
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
            let o = self
                .0
                .get(&req.input.bucket, &req.input.key)
                .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchKey))?;
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
            let k = (req.input.bucket.clone(), req.input.key.clone());
            let data = collect(req.input.body).await;
            let mut objs = self.0.0.lock().unwrap();
            if req.input.if_none_match.is_some() && objs.contains_key(&k) {
                return Err(S3Error::new(S3ErrorCode::PreconditionFailed));
            }
            objs.insert(k, data);
            Ok(S3Response::new(PutObjectOutput::default()))
        }

        async fn delete_object(
            &self,
            req: S3Request<DeleteObjectInput>,
        ) -> S3Result<S3Response<DeleteObjectOutput>> {
            self.0
                .0
                .lock()
                .unwrap()
                .remove(&(req.input.bucket.clone(), req.input.key.clone()));
            Ok(S3Response::new(DeleteObjectOutput::default()))
        }

        async fn copy_object(
            &self,
            req: S3Request<CopyObjectInput>,
        ) -> S3Result<S3Response<CopyObjectOutput>> {
            let CopySource::Bucket { bucket, key, .. } = &req.input.copy_source else {
                return Err(S3Error::new(S3ErrorCode::InvalidRequest));
            };
            let data = self
                .0
                .get(bucket, key)
                .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchKey))?;
            self.0
                .0
                .lock()
                .unwrap()
                .insert((req.input.bucket.clone(), req.input.key.clone()), data);
            Ok(S3Response::new(CopyObjectOutput::default()))
        }

        async fn create_multipart_upload(
            &self,
            req: S3Request<CreateMultipartUploadInput>,
        ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
            let id = uuid::Uuid::new_v4().to_string();
            self.0.1.lock().unwrap().insert(
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

        async fn upload_part_copy(
            &self,
            req: S3Request<UploadPartCopyInput>,
        ) -> S3Result<S3Response<UploadPartCopyOutput>> {
            let CopySource::Bucket { bucket, key, .. } = &req.input.copy_source else {
                return Err(S3Error::new(S3ErrorCode::InvalidRequest));
            };
            let src = self
                .0
                .get(bucket, key)
                .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchKey))?;
            let (a, b) = req
                .input
                .copy_source_range
                .as_deref()
                .and_then(|r| r.strip_prefix("bytes="))
                .and_then(|r| r.split_once('-'))
                .map(|(a, b)| (a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()))
                .unwrap_or((0, src.len() - 1));
            self.0
                .1
                .lock()
                .unwrap()
                .get_mut(&req.input.upload_id)
                .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchUpload))?
                .2
                .insert(req.input.part_number, src.slice(a..=b));
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
            let (bucket, key, parts) = self
                .0
                .1
                .lock()
                .unwrap()
                .remove(&req.input.upload_id)
                .ok_or_else(|| S3Error::new(S3ErrorCode::NoSuchUpload))?;
            let mut data = BytesMut::new();
            for p in parts.values() {
                data.extend_from_slice(p);
            }
            let k = (bucket, key);
            let mut objs = self.0.0.lock().unwrap();
            if req.input.if_none_match.is_some() && objs.contains_key(&k) {
                return Err(S3Error::new(S3ErrorCode::PreconditionFailed));
            }
            objs.insert(k, data.freeze());
            Ok(S3Response::new(CompleteMultipartUploadOutput::default()))
        }

        async fn abort_multipart_upload(
            &self,
            req: S3Request<AbortMultipartUploadInput>,
        ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
            self.0.1.lock().unwrap().remove(&req.input.upload_id);
            Ok(S3Response::new(AbortMultipartUploadOutput::default()))
        }

        async fn list_objects_v2(
            &self,
            req: S3Request<ListObjectsV2Input>,
        ) -> S3Result<S3Response<ListObjectsV2Output>> {
            let prefix = req.input.prefix.clone().unwrap_or_default();
            let delim = req.input.delimiter.clone();
            let objs = self.0.0.lock().unwrap();
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
    }

    async fn serve_backend(mem: Arc<Mem>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let mut b = s3s::service::S3ServiceBuilder::new(MemRef(mem));
        b.set_auth(s3s::auth::SimpleAuth::from_single("OWNER", "OWNERSECRET"));
        let service = b.build();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
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

    /// A create-only drop box and a full-grant operator, as in `tests/sftp_e2e.rs`.
    /// The keys are random per run; nothing about them reaches an `OpaInput`.
    fn bundle(drop_key: &PrivateKey, ops_key: &PrivateKey) -> serde_json::Value {
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
                        "authorized_keys": [ { "key_type": "ssh-ed25519", "fingerprint": fp(ops_key) } ]
                    }
                }
            },
            "org_settings": { "freeze_writes": false },
            "tenants": { "acme": {
                "user_attributes": {
                    "partner-drop": { "groups": [], "attributes": {} },
                    "ops": { "groups": ["operators"], "attributes": {} }
                },
                "bucket_attributes": { "inbound": { "denylist": {} } },
                "s3_grants": {
                    "partner-drop": [ { "bucket": "inbound", "actions": ["create_objects"], "prefixes": ["partner-x/"] } ],
                    "ops": [ { "bucket": "inbound", "actions": ["*"], "prefixes": [] } ]
                }
            } }
        })
    }

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

    fn s(b: &mut BytesMut, v: &[u8]) {
        b.put_u32(v.len() as u32);
        b.put_slice(v);
    }

    impl Sftp {
        async fn connect(addr: SocketAddr, login: &str, key: &PrivateKey) -> Sftp {
            let cfg = Arc::new(russh::client::Config::default());
            let mut session = russh::client::connect(cfg, addr, Client).await.unwrap();
            let ok = session
                .authenticate_publickey(
                    login,
                    PrivateKeyWithHashAlg::new(Arc::new(key.clone()), None),
                )
                .await
                .unwrap();
            assert!(ok.success(), "{login} logs in");
            let ch = session.channel_open_session().await.unwrap();
            ch.request_subsystem(true, "sftp").await.unwrap();
            let mut sftp = Sftp {
                stream: ch.into_stream(),
                next_id: 1,
                _session: session,
            };
            let mut b = BytesMut::new();
            b.put_u8(SSH_FXP_INIT);
            b.put_u32(3);
            sftp.send(b).await;
            assert_eq!(sftp.recv().await.0, SSH_FXP_VERSION);
            sftp
        }

        async fn send(&mut self, body: BytesMut) {
            let mut out = BytesMut::new();
            out.put_u32(body.len() as u32);
            out.extend_from_slice(&body);
            self.stream.write_all(&out).await.unwrap();
        }

        async fn recv(&mut self) -> (u8, Bytes) {
            let mut len = [0u8; 4];
            tokio::time::timeout(Duration::from_secs(20), self.stream.read_exact(&mut len))
                .await
                .expect("reply in time")
                .unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
            self.stream.read_exact(&mut body).await.unwrap();
            (body[0], Bytes::from(body).slice(1..))
        }

        /// One request; the reply's type and, for a STATUS, its code; for a HANDLE,
        /// the handle.
        async fn call(&mut self, kind: u8, f: impl FnOnce(&mut BytesMut)) -> (u8, u32, Vec<u8>) {
            let id = self.next_id;
            self.next_id += 1;
            let mut b = BytesMut::new();
            b.put_u8(kind);
            b.put_u32(id);
            f(&mut b);
            self.send(b).await;
            let (t, body) = self.recv().await;
            let rd = |o: usize| u32::from_be_bytes(body[o..o + 4].try_into().unwrap());
            assert_eq!(rd(0), id, "reply id");
            match t {
                SSH_FXP_STATUS => (t, rd(4), body[12..12 + rd(8) as usize].to_vec()),
                SSH_FXP_HANDLE => (t, 0, body[8..8 + rd(4) as usize].to_vec()),
                _ => (t, 0, vec![]),
            }
        }

        async fn path(&mut self, kind: u8, path: &str) -> (u8, u32, Vec<u8>) {
            self.call(kind, |b| s(b, path.as_bytes())).await
        }

        async fn open(&mut self, path: &str, pflags: u32) -> (u8, u32, Vec<u8>) {
            self.call(SSH_FXP_OPEN, |b| {
                s(b, path.as_bytes());
                b.put_u32(pflags);
                b.put_u32(SSH_FILEXFER_ATTR_PERMISSIONS);
                b.put_u32(0o644);
            })
            .await
        }

        async fn handle(&mut self, kind: u8, h: &[u8]) -> (u8, u32, Vec<u8>) {
            self.call(kind, |b| s(b, h)).await
        }

        async fn upload(&mut self, path: &str, data: &[u8]) {
            let (t, _, h) = self
                .open(path, SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC)
                .await;
            assert_eq!(t, SSH_FXP_HANDLE, "open {path} for writing");
            let (_, code, _) = self
                .call(SSH_FXP_WRITE, |b| {
                    s(b, &h);
                    b.put_u64(0);
                    s(b, data);
                })
                .await;
            assert_eq!(code, 0, "write {path}");
            assert_eq!(self.handle(SSH_FXP_CLOSE, &h).await.1, 0, "close {path}");
        }
    }

    /// Drive a representative SFTP session per account and return what the PDP was
    /// asked, keyed by capture id — with the same structural checks the S3 harness runs.
    pub async fn capture() -> BTreeMap<String, serde_json::Value> {
        let mem = Arc::new(Mem::default());
        let url = serve_backend(mem.clone()).await;
        let drop_key = ed25519();
        let ops_key = ed25519();
        let fx = crate::common::fixture_with_config(
            "golden-capture-sftp",
            bundle(&drop_key, &ops_key),
            &url,
            |c| c["backends"][0]["conditional_create"] = serde_json::json!("native"),
        );
        let host_path = fx.dir.join("ssh_host_ed25519_key");
        std::fs::write(
            &host_path,
            ed25519()
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&host_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let cfg: s0::config::SftpConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "listen": "127.0.0.1:0",
            "host_keys": [host_path],
            "drain_secs": 1
        }))
        .unwrap();
        let front = s0::sftp::SftpFront::build(fx.gw.clone(), &cfg).expect("front");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(front.serve_on(listener, async {
            let _ = stopped.await;
        }));

        // The drop box: an upload create (allow), then a read it does not hold (deny).
        let mut d = Sftp::connect(addr, "acme-partner-drop", &drop_key).await;
        d.upload("/2026-11-03.csv", b"id,amount\n1,10\n").await;
        assert_eq!(
            d.open("/2026-11-03.csv", SSH_FXF_READ).await.1,
            3,
            "a drop box cannot read"
        );
        assert!(mem.get("inbound", "partner-x/2026-11-03.csv").is_some());

        // The operator: an overwrite-capable upload, stat, a read, a listing, a mkdir,
        // a rename, a remove.
        let mut o = Sftp::connect(addr, "acme-ops", &ops_key).await;
        o.upload("/in/a.csv", b"alpha").await;
        assert_eq!(o.path(SSH_FXP_STAT, "/in/a.csv").await.0, SSH_FXP_ATTRS);
        let (t, _, h) = o.open("/in/a.csv", SSH_FXF_READ).await;
        assert_eq!(t, SSH_FXP_HANDLE);
        let (t, _, _) = o
            .call(SSH_FXP_READ, |b| {
                s(b, &h);
                b.put_u64(0);
                b.put_u32(1024);
            })
            .await;
        assert_eq!(t, SSH_FXP_DATA);
        assert_eq!(o.handle(SSH_FXP_CLOSE, &h).await.1, 0);
        let (t, _, h) = o.path(SSH_FXP_OPENDIR, "/in").await;
        assert_eq!(t, SSH_FXP_HANDLE);
        assert_eq!(o.handle(SSH_FXP_READDIR, &h).await.0, SSH_FXP_NAME);
        assert_eq!(o.handle(SSH_FXP_CLOSE, &h).await.1, 0);
        let (_, code, _) = o
            .call(SSH_FXP_MKDIR, |b| {
                s(b, b"/archive");
                b.put_u32(0);
            })
            .await;
        assert_eq!(code, 0, "mkdir");
        let (_, code, msg) = o
            .call(SSH_FXP_RENAME, |b| {
                s(b, b"/in/a.csv");
                s(b, b"/archive/a.csv");
            })
            .await;
        assert_eq!(code, 0, "rename: {}", String::from_utf8_lossy(&msg));
        assert_eq!(o.path(SSH_FXP_REMOVE, "/archive/a.csv").await.1, 0);
        assert!(mem.get("inbound", "archive/a.csv").is_none());
        drop((d, o, stop));

        assert_eq!(fx.capture.dropped(), 0, "the capture sink dropped records");
        assert_eq!(
            fx.capture.round_trip_failures(),
            0,
            "an SFTP-shaped input does not round-trip through OpaInput"
        );
        let captured = fx.capture.snapshot();
        assert_eq!(
            captured.len(),
            fx.pdp_calls(),
            "the SFTP front asked the PDP {} questions but only {} were captured — \
             `Enforcer::decide` is no longer its only call site",
            fx.pdp_calls(),
            captured.len()
        );
        fx.capture
            .corpus()
            .into_iter()
            .map(|c| (c.id, c.raw))
            .collect()
    }
}
