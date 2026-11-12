//! The SFTP front's only way to reach a backend (ADR-012 D2).
//!
//! Every call goes through `BackendRegistry::proxy_for(route)` — the same per-tenant
//! re-signing client the S3 front uses, under the tenant backend credential — and every
//! call first asks the [`SftpProof`] whether it licenses exactly this `(operation, bucket,
//! key)`. A call the proof does not license is an internal error. The typed s3s inputs are
//! built here and nowhere else, from values that already passed `sftp::paths`.

use std::sync::Arc;

use bytes::Bytes;
use futures_util::StreamExt;
use s3s::dto::*;
use s3s::{S3, S3Error, S3Request};
use s3s_aws::Proxy;

use crate::access::{SftpBackendOp as Op, SftpLicense, SftpProof};
use crate::proxy::{BackendRegistry, RouteSnapshot};

/// A backend failure, classified for the SFTP status it becomes.
#[derive(Debug)]
pub enum BackendError {
    /// 404 / NoSuchKey.
    NotFound,
    /// 412: a conditional write lost to a concurrent create.
    PreconditionFailed,
    /// The proof did not license the call — a defect in this binary.
    Unlicensed(String),
    /// Anything else, with the backend's own status when it named one.
    Other {
        status: Option<u16>,
        message: String,
    },
}

impl BackendError {
    fn from_s3(e: &S3Error) -> Self {
        let status = e.status_code().map(|s| s.as_u16());
        match (status, e.code().as_str()) {
            (Some(404), _) | (_, "NoSuchKey" | "NotFound") => BackendError::NotFound,
            (Some(412), _) | (_, "PreconditionFailed") => BackendError::PreconditionFailed,
            _ => BackendError::Other {
                status,
                message: e.message().unwrap_or_else(|| e.code().as_str()).to_string(),
            },
        }
    }

    pub fn status(&self) -> Option<u16> {
        match self {
            BackendError::NotFound => Some(404),
            BackendError::PreconditionFailed => Some(412),
            BackendError::Unlicensed(_) => None,
            BackendError::Other { status, .. } => *status,
        }
    }
}

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendError::NotFound => f.write_str("not found"),
            BackendError::PreconditionFailed => f.write_str("precondition failed"),
            BackendError::Unlicensed(m) => f.write_str(m),
            BackendError::Other { status, message } => match status {
                Some(s) => write!(f, "backend error {s}: {message}"),
                None => write!(f, "backend error: {message}"),
            },
        }
    }
}

pub type BResult<T> = Result<T, BackendError>;

/// A download body. `Sync` so a session holding one can be borrowed across an await.
pub type ByteStream =
    std::pin::Pin<Box<dyn futures_util::Stream<Item = Result<Bytes, String>> + Send + Sync>>;

/// What a stat reveals: existence, size and modification time — nothing more (D7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjectMeta {
    pub size: u64,
    /// Unix seconds.
    pub mtime: u32,
}

/// One page of a delimiter listing.
#[derive(Debug, Default)]
pub struct ListPage {
    pub objects: Vec<(String, ObjectMeta)>,
    pub prefixes: Vec<String>,
    pub next: Option<String>,
}

/// The backend, bound to the route the session's decisions were taken against.
#[derive(Clone)]
pub struct SftpBackend {
    registry: Arc<BackendRegistry>,
    route: Arc<RouteSnapshot>,
}

fn req<T>(input: T) -> S3Request<T> {
    S3Request {
        input,
        method: http::Method::GET,
        uri: http::Uri::from_static("/"),
        headers: http::HeaderMap::new(),
        extensions: http::Extensions::new(),
        credentials: None,
        region: None,
        service: None,
        trailing_headers: None,
    }
}

fn mtime(t: Option<Timestamp>) -> u32 {
    let Some(t) = t else { return 0 };
    let mut buf = Vec::new();
    if t.format(TimestampFormat::EpochSeconds, &mut buf).is_err() {
        return 0;
    }
    std::str::from_utf8(&buf)
        .ok()
        .and_then(|s| s.split('.').next()?.parse::<i64>().ok())
        .and_then(|v| u32::try_from(v).ok())
        .unwrap_or(0)
}

fn size(n: Option<i64>) -> u64 {
    n.and_then(|n| u64::try_from(n).ok()).unwrap_or(0)
}

fn blob(data: Bytes) -> StreamingBlob {
    StreamingBlob::from(s3s::Body::from(data))
}

impl SftpBackend {
    pub fn new(registry: Arc<BackendRegistry>, route: Arc<RouteSnapshot>) -> Self {
        SftpBackend { registry, route }
    }

    pub fn route(&self) -> &RouteSnapshot {
        &self.route
    }

    fn proxy(&self, proof: &SftpProof, want: &SftpLicense) -> BResult<Arc<Proxy>> {
        proof.require(want).map_err(BackendError::Unlicensed)?;
        self.registry
            .proxy_for(&self.route)
            .map_err(|e| BackendError::Other {
                status: None,
                message: e.to_string(),
            })
    }

    /// `HeadObject`, metadata only. `Ok(None)` when the key does not exist.
    pub async fn head(
        &self,
        proof: &SftpProof,
        bucket: &str,
        key: &str,
    ) -> BResult<Option<ObjectMeta>> {
        let p = self.proxy(proof, &SftpLicense::on(Op::HeadObject, bucket, key))?;
        let input = HeadObjectInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            ..Default::default()
        };
        match p.head_object(req(input)).await {
            Ok(r) => Ok(Some(ObjectMeta {
                size: size(r.output.content_length),
                mtime: mtime(r.output.last_modified),
            })),
            Err(e) => match BackendError::from_s3(&e) {
                BackendError::NotFound => Ok(None),
                other => Err(other),
            },
        }
    }

    /// `ListObjectsV2`.
    pub async fn list(
        &self,
        proof: &SftpProof,
        bucket: &str,
        prefix: &str,
        delimiter: bool,
        continuation: Option<String>,
        max_keys: Option<i32>,
    ) -> BResult<ListPage> {
        let p = self.proxy(proof, &SftpLicense::on(Op::ListObjectsV2, bucket, prefix))?;
        let input = ListObjectsV2Input {
            bucket: bucket.to_string(),
            prefix: (!prefix.is_empty()).then(|| prefix.to_string()),
            delimiter: delimiter.then(|| "/".to_string()),
            continuation_token: continuation,
            max_keys,
            ..Default::default()
        };
        let out = p
            .list_objects_v2(req(input))
            .await
            .map_err(|e| BackendError::from_s3(&e))?
            .output;
        Ok(ListPage {
            objects: out
                .contents
                .unwrap_or_default()
                .into_iter()
                .filter_map(|o| {
                    Some((
                        o.key?,
                        ObjectMeta {
                            size: size(o.size),
                            mtime: mtime(o.last_modified),
                        },
                    ))
                })
                .collect(),
            prefixes: out
                .common_prefixes
                .unwrap_or_default()
                .into_iter()
                .filter_map(|c| c.prefix)
                .collect(),
            next: if out.is_truncated.unwrap_or(false) {
                out.next_continuation_token
            } else {
                None
            },
        })
    }

    /// `GetObject` from `offset`, as a stream of chunks, plus the object's total size.
    pub async fn get(
        &self,
        proof: &SftpProof,
        bucket: &str,
        key: &str,
        offset: u64,
    ) -> BResult<(u64, ByteStream)> {
        let p = self.proxy(proof, &SftpLicense::on(Op::GetObject, bucket, key))?;
        let input = GetObjectInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            range: (offset > 0).then_some(Range::Int {
                first: offset,
                last: None,
            }),
            ..Default::default()
        };
        let out = p
            .get_object(req(input))
            .await
            .map_err(|e| BackendError::from_s3(&e))?
            .output;
        let len = size(out.content_length);
        let stream: ByteStream = match out.body {
            Some(b) => Box::pin(b.map(|r| r.map_err(|e| e.to_string()))),
            None => Box::pin(futures_util::stream::empty()),
        };
        Ok((offset + len, stream))
    }

    /// `PutObject` of a whole small object, optionally conditional on absence.
    pub async fn put(
        &self,
        proof: &SftpProof,
        bucket: &str,
        key: &str,
        data: Bytes,
        if_none_match: bool,
    ) -> BResult<()> {
        let p = self.proxy(proof, &SftpLicense::on(Op::PutObject, bucket, key))?;
        let input = PutObjectInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            content_length: Some(data.len() as i64),
            body: Some(blob(data)),
            if_none_match: if_none_match.then_some(ETagCondition::Any),
            ..Default::default()
        };
        p.put_object(req(input))
            .await
            .map_err(|e| BackendError::from_s3(&e))?;
        Ok(())
    }

    pub async fn create_multipart(
        &self,
        proof: &SftpProof,
        bucket: &str,
        key: &str,
    ) -> BResult<String> {
        let p = self.proxy(
            proof,
            &SftpLicense::on(Op::CreateMultipartUpload, bucket, key),
        )?;
        let input = CreateMultipartUploadInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            ..Default::default()
        };
        p.create_multipart_upload(req(input))
            .await
            .map_err(|e| BackendError::from_s3(&e))?
            .output
            .upload_id
            .ok_or_else(|| BackendError::Other {
                status: None,
                message: "CreateMultipartUpload returned no upload id".into(),
            })
    }

    /// One part. Returns its ETag.
    pub async fn upload_part(
        &self,
        proof: &SftpProof,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        data: Bytes,
    ) -> BResult<ETag> {
        let p = self.proxy(proof, &SftpLicense::on(Op::UploadPart, bucket, key))?;
        let input = UploadPartInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id: upload_id.to_string(),
            part_number,
            content_length: Some(data.len() as i64),
            body: Some(blob(data)),
            ..Default::default()
        };
        p.upload_part(req(input))
            .await
            .map_err(|e| BackendError::from_s3(&e))?
            .output
            .e_tag
            .ok_or_else(|| BackendError::Other {
                status: None,
                message: "UploadPart returned no ETag".into(),
            })
    }

    /// A server-side copy of a byte range into one part (`UploadPartCopy`).
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_part_copy(
        &self,
        proof: &SftpProof,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_number: i32,
        src_bucket: &str,
        src_key: &str,
        range: (u64, u64),
    ) -> BResult<ETag> {
        let p = self.proxy(
            proof,
            &SftpLicense::copy(Op::UploadPartCopy, bucket, key, src_bucket, src_key),
        )?;
        let input = UploadPartCopyInput::builder()
            .bucket(bucket.to_string())
            .key(key.to_string())
            .upload_id(upload_id.to_string())
            .part_number(part_number)
            .copy_source(CopySource::Bucket {
                bucket: src_bucket.into(),
                key: src_key.into(),
                version_id: None,
            })
            .copy_source_range(Some(format!("bytes={}-{}", range.0, range.1)))
            .build()
            .map_err(|e| BackendError::Other {
                status: None,
                message: format!("UploadPartCopy input: {e}"),
            })?;
        p.upload_part_copy(req(input))
            .await
            .map_err(|e| BackendError::from_s3(&e))?
            .output
            .copy_part_result
            .and_then(|r| r.e_tag)
            .ok_or_else(|| BackendError::Other {
                status: None,
                message: "UploadPartCopy returned no ETag".into(),
            })
    }

    pub async fn complete_multipart(
        &self,
        proof: &SftpProof,
        bucket: &str,
        key: &str,
        upload_id: &str,
        parts: Vec<(i32, ETag)>,
        if_none_match: bool,
    ) -> BResult<()> {
        let p = self.proxy(
            proof,
            &SftpLicense::on(Op::CompleteMultipartUpload, bucket, key),
        )?;
        let input = CompleteMultipartUploadInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id: upload_id.to_string(),
            multipart_upload: Some(CompletedMultipartUpload {
                parts: Some(
                    parts
                        .into_iter()
                        .map(|(n, e)| CompletedPart {
                            part_number: Some(n),
                            e_tag: Some(e),
                            ..Default::default()
                        })
                        .collect(),
                ),
            }),
            if_none_match: if_none_match.then_some(ETagCondition::Any),
            ..Default::default()
        };
        p.complete_multipart_upload(req(input))
            .await
            .map_err(|e| BackendError::from_s3(&e))?;
        Ok(())
    }

    pub async fn abort_multipart(
        &self,
        proof: &SftpProof,
        bucket: &str,
        key: &str,
        upload_id: &str,
    ) -> BResult<()> {
        let p = self.proxy(
            proof,
            &SftpLicense::on(Op::AbortMultipartUpload, bucket, key),
        )?;
        let input = AbortMultipartUploadInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            upload_id: upload_id.to_string(),
            ..Default::default()
        };
        p.abort_multipart_upload(req(input))
            .await
            .map_err(|e| BackendError::from_s3(&e))?;
        Ok(())
    }

    pub async fn delete(&self, proof: &SftpProof, bucket: &str, key: &str) -> BResult<()> {
        let p = self.proxy(proof, &SftpLicense::on(Op::DeleteObject, bucket, key))?;
        let input = DeleteObjectInput {
            bucket: bucket.to_string(),
            key: key.to_string(),
            ..Default::default()
        };
        p.delete_object(req(input))
            .await
            .map_err(|e| BackendError::from_s3(&e))?;
        Ok(())
    }

    /// `CopyObject` (overwrite allowed: no destination condition exists in s3s 0.14.1, E4).
    pub async fn copy(
        &self,
        proof: &SftpProof,
        bucket: &str,
        key: &str,
        src_key: &str,
    ) -> BResult<()> {
        let p = self.proxy(
            proof,
            &SftpLicense::copy(Op::CopyObject, bucket, key, bucket, src_key),
        )?;
        let input = CopyObjectInput::builder()
            .bucket(bucket.to_string())
            .key(key.to_string())
            .copy_source(CopySource::Bucket {
                bucket: bucket.into(),
                key: src_key.into(),
                version_id: None,
            })
            .build()
            .map_err(|e| BackendError::Other {
                status: None,
                message: format!("CopyObject input: {e}"),
            })?;
        p.copy_object(req(input))
            .await
            .map_err(|e| BackendError::from_s3(&e))?;
        Ok(())
    }
}
