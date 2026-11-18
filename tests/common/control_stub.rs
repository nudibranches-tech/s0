//! An in-process control backend: an s3s server that implements only the 16 delegable
//! operations, verifies SigV4 against the control credential, and records what it saw.
//!
//! It records the operation, the `x-s0-*` header values, the raw `SignedHeaders` list and
//! the count of requests that reached the socket, answers a scripted error per operation, and refuses everything else
//! with s3s's own `NotImplemented`. The count is taken at the transport, before s3s
//! authenticates or dispatches, so it includes requests that are refused. It is what "an enforced operation never reaches
//! the control backend" is measured against.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use http::HeaderMap;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use s3s::auth::SimpleAuth;
use s3s::dto::*;
use s3s::service::S3ServiceBuilder;
use s3s::{S3, S3Error, S3ErrorCode, S3Request, S3Response, S3Result};

pub const CONTROL_ACCESS_KEY: &str = "s0ctl.k0.org-acme.bay-1";
pub const CONTROL_SECRET_KEY: &str = "control-test-secret";

/// One request the stub answered or refused.
#[derive(Debug, Clone)]
pub struct StubCall {
    pub operation: String,
    /// Every `x-s0-*` header, in order of appearance, with duplicates preserved.
    pub s0_headers: Vec<(String, String)>,
    /// The names listed in the request's `SignedHeaders=`.
    pub signed_headers: Vec<String>,
}

impl StubCall {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.s0_headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    pub fn header_count(&self, name: &str) -> usize {
        self.s0_headers.iter().filter(|(n, _)| n == name).count()
    }
}

#[derive(Debug, Clone)]
struct Scripted {
    code: S3ErrorCode,
    status: http::StatusCode,
    message: String,
}

#[derive(Default)]
struct StubState {
    requests: AtomicUsize,
    calls: Mutex<Vec<StubCall>>,
    scripted: Mutex<HashMap<String, Scripted>>,
    delays: Mutex<HashMap<String, std::time::Duration>>,
}

#[derive(Clone)]
struct StubS3(Arc<StubState>);

impl StubS3 {
    async fn answer(&self, operation: &str, headers: &HeaderMap) -> S3Result<()> {
        let s0_headers = headers
            .iter()
            .filter(|(n, _)| n.as_str().starts_with("x-s0-"))
            .map(|(n, v)| {
                (
                    n.as_str().to_string(),
                    v.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let signed_headers = headers
            .get(http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|a| a.split("SignedHeaders=").nth(1))
            .and_then(|a| a.split(',').next())
            .map(|names| names.split(';').map(str::to_string).collect())
            .unwrap_or_default();
        self.0.calls.lock().expect("stub calls").push(StubCall {
            operation: operation.to_string(),
            s0_headers,
            signed_headers,
        });
        let delay = self
            .0
            .delays
            .lock()
            .expect("stub delays")
            .get(operation)
            .copied();
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        let scripted = self
            .0
            .scripted
            .lock()
            .expect("stub script")
            .get(operation)
            .cloned();
        match scripted {
            Some(s) => {
                let mut err = S3Error::with_message(s.code, s.message);
                err.set_status_code(s.status);
                Err(err)
            }
            None => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl S3 for StubS3 {
    async fn create_bucket(
        &self,
        req: S3Request<CreateBucketInput>,
    ) -> S3Result<S3Response<CreateBucketOutput>> {
        self.answer("CreateBucket", &req.headers).await?;
        Ok(S3Response::new(CreateBucketOutput::default()))
    }

    async fn delete_bucket(
        &self,
        req: S3Request<DeleteBucketInput>,
    ) -> S3Result<S3Response<DeleteBucketOutput>> {
        self.answer("DeleteBucket", &req.headers).await?;
        Ok(S3Response::new(DeleteBucketOutput::default()))
    }

    async fn get_bucket_cors(
        &self,
        req: S3Request<GetBucketCorsInput>,
    ) -> S3Result<S3Response<GetBucketCorsOutput>> {
        self.answer("GetBucketCors", &req.headers).await?;
        Ok(S3Response::new(GetBucketCorsOutput::default()))
    }

    async fn put_bucket_cors(
        &self,
        req: S3Request<PutBucketCorsInput>,
    ) -> S3Result<S3Response<PutBucketCorsOutput>> {
        self.answer("PutBucketCors", &req.headers).await?;
        Ok(S3Response::new(PutBucketCorsOutput::default()))
    }

    async fn delete_bucket_cors(
        &self,
        req: S3Request<DeleteBucketCorsInput>,
    ) -> S3Result<S3Response<DeleteBucketCorsOutput>> {
        self.answer("DeleteBucketCors", &req.headers).await?;
        Ok(S3Response::new(DeleteBucketCorsOutput::default()))
    }

    async fn get_bucket_lifecycle_configuration(
        &self,
        req: S3Request<GetBucketLifecycleConfigurationInput>,
    ) -> S3Result<S3Response<GetBucketLifecycleConfigurationOutput>> {
        self.answer("GetBucketLifecycleConfiguration", &req.headers)
            .await?;
        Ok(S3Response::new(
            GetBucketLifecycleConfigurationOutput::default(),
        ))
    }

    async fn put_bucket_lifecycle_configuration(
        &self,
        req: S3Request<PutBucketLifecycleConfigurationInput>,
    ) -> S3Result<S3Response<PutBucketLifecycleConfigurationOutput>> {
        self.answer("PutBucketLifecycleConfiguration", &req.headers)
            .await?;
        Ok(S3Response::new(
            PutBucketLifecycleConfigurationOutput::default(),
        ))
    }

    async fn delete_bucket_lifecycle(
        &self,
        req: S3Request<DeleteBucketLifecycleInput>,
    ) -> S3Result<S3Response<DeleteBucketLifecycleOutput>> {
        self.answer("DeleteBucketLifecycle", &req.headers).await?;
        Ok(S3Response::new(DeleteBucketLifecycleOutput::default()))
    }

    async fn get_bucket_tagging(
        &self,
        req: S3Request<GetBucketTaggingInput>,
    ) -> S3Result<S3Response<GetBucketTaggingOutput>> {
        self.answer("GetBucketTagging", &req.headers).await?;
        Ok(S3Response::new(GetBucketTaggingOutput::default()))
    }

    async fn put_bucket_tagging(
        &self,
        req: S3Request<PutBucketTaggingInput>,
    ) -> S3Result<S3Response<PutBucketTaggingOutput>> {
        self.answer("PutBucketTagging", &req.headers).await?;
        Ok(S3Response::new(PutBucketTaggingOutput::default()))
    }

    async fn delete_bucket_tagging(
        &self,
        req: S3Request<DeleteBucketTaggingInput>,
    ) -> S3Result<S3Response<DeleteBucketTaggingOutput>> {
        self.answer("DeleteBucketTagging", &req.headers).await?;
        Ok(S3Response::new(DeleteBucketTaggingOutput::default()))
    }

    async fn get_bucket_versioning(
        &self,
        req: S3Request<GetBucketVersioningInput>,
    ) -> S3Result<S3Response<GetBucketVersioningOutput>> {
        self.answer("GetBucketVersioning", &req.headers).await?;
        Ok(S3Response::new(GetBucketVersioningOutput::default()))
    }

    async fn put_bucket_versioning(
        &self,
        req: S3Request<PutBucketVersioningInput>,
    ) -> S3Result<S3Response<PutBucketVersioningOutput>> {
        self.answer("PutBucketVersioning", &req.headers).await?;
        Ok(S3Response::new(PutBucketVersioningOutput::default()))
    }

    async fn get_bucket_encryption(
        &self,
        req: S3Request<GetBucketEncryptionInput>,
    ) -> S3Result<S3Response<GetBucketEncryptionOutput>> {
        self.answer("GetBucketEncryption", &req.headers).await?;
        Ok(S3Response::new(GetBucketEncryptionOutput::default()))
    }

    async fn put_bucket_encryption(
        &self,
        req: S3Request<PutBucketEncryptionInput>,
    ) -> S3Result<S3Response<PutBucketEncryptionOutput>> {
        self.answer("PutBucketEncryption", &req.headers).await?;
        Ok(S3Response::new(PutBucketEncryptionOutput::default()))
    }

    async fn delete_bucket_encryption(
        &self,
        req: S3Request<DeleteBucketEncryptionInput>,
    ) -> S3Result<S3Response<DeleteBucketEncryptionOutput>> {
        self.answer("DeleteBucketEncryption", &req.headers).await?;
        Ok(S3Response::new(DeleteBucketEncryptionOutput::default()))
    }
}

/// A running control backend stub.
pub struct ControlStub {
    pub endpoint: String,
    state: Arc<StubState>,
}

impl ControlStub {
    /// Bind a loopback port and serve the stub until the test process ends.
    pub async fn start() -> ControlStub {
        let state = Arc::new(StubState::default());
        let mut builder = S3ServiceBuilder::new(StubS3(state.clone()));
        builder.set_auth(SimpleAuth::from_single(
            CONTROL_ACCESS_KEY,
            CONTROL_SECRET_KEY,
        ));
        let service = builder.build();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind control stub");
        let addr: SocketAddr = listener.local_addr().expect("stub addr");
        let serving = state.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let service = service.clone();
                let state = serving.clone();
                tokio::spawn(async move {
                    let counted = hyper::service::service_fn(move |req| {
                        state.requests.fetch_add(1, Ordering::SeqCst);
                        let service = service.clone();
                        async move { hyper::service::Service::call(&service, req).await }
                    });
                    let _ = ConnBuilder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), counted)
                        .await;
                });
            }
        });
        ControlStub {
            endpoint: format!("http://{addr}"),
            state,
        }
    }

    /// Answer `operation` with this error from now on.
    pub fn fail(&self, operation: &str, code: S3ErrorCode, status: u16, message: &str) {
        self.state.scripted.lock().expect("stub script").insert(
            operation.to_string(),
            Scripted {
                code,
                status: http::StatusCode::from_u16(status).expect("status"),
                message: message.to_string(),
            },
        );
    }

    /// Hold every answer to `operation` for `delay` before it is given.
    pub fn delay(&self, operation: &str, delay: std::time::Duration) {
        self.state
            .delays
            .lock()
            .expect("stub delays")
            .insert(operation.to_string(), delay);
    }

    pub fn calls(&self) -> Vec<StubCall> {
        self.state.calls.lock().expect("stub calls").clone()
    }

    /// Every request that reached the stub's socket, whatever became of it.
    pub fn count(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }
}
