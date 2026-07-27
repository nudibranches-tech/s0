//! Backend proxy. Forwards allowed, canonicalized requests to the
//! target backend, re-signed with a **per-tenant / per-backend** credential — never
//! the caller's. `s3s_aws::Proxy` wraps exactly one `aws_sdk_s3::Client`, so
//! per-tenant credentials require a client pool keyed on `(backend, tenant)` with a
//! dispatching `impl S3` in front (this is the real architecture, not a line item).
//!
//! Canonicalize-before-forward holds by construction: the typed hook mutates
//! `S3Request<Input>` and we forward that same value — there is no raw passthrough.

pub mod fanout;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::{Client, Config};
use s3s::dto::*;
use s3s::{S3, S3Error, S3Request, S3Response, S3Result, s3_error};
use s3s_aws::Proxy;

use crate::config::{BackendConfig, GatewayConfig};
use crate::error::{GatewayError, Result};
use crate::identity::ResolvedPrincipal;
use crate::model::{BackendId, BackendKind};

/// One tenant's routing: which backend, which per-tenant credential, which Org.
struct TenantRoute {
    backend: Arc<BackendConfig>,
    owner_access_key: String,
    owner_secret_key: String,
    organization_id: String,
}

/// Resolves a tenant to a re-signing `Proxy`, building and caching one client per
/// `(backend, tenant)`. Backend credentials never leave this registry.
pub struct BackendRegistry {
    routes: HashMap<String, TenantRoute>,
    pool: Mutex<HashMap<(String, String), Arc<Proxy>>>,
}

impl BackendRegistry {
    pub fn from_config(cfg: &GatewayConfig) -> Result<Self> {
        let backends: HashMap<&str, Arc<BackendConfig>> = cfg
            .backends
            .iter()
            .map(|b| (b.id.as_str(), Arc::new(b.clone())))
            .collect();
        let mut routes = HashMap::new();
        for t in &cfg.tenants {
            let backend = backends
                .get(t.backend_id.as_str())
                .ok_or_else(|| GatewayError::Config(format!("unknown backend {}", t.backend_id)))?
                .clone();
            routes.insert(
                t.tenant.clone(),
                TenantRoute {
                    backend,
                    owner_access_key: t.owner_access_key.clone(),
                    owner_secret_key: t.owner_secret_key.clone(),
                    organization_id: t.organization_id.clone(),
                },
            );
        }
        Ok(BackendRegistry {
            routes,
            pool: Mutex::new(HashMap::new()),
        })
    }

    pub fn organization_of(&self, tenant: &str) -> Option<&str> {
        self.routes.get(tenant).map(|r| r.organization_id.as_str())
    }

    pub fn backend_of(&self, tenant: &str) -> Option<(BackendId, BackendKind)> {
        self.routes
            .get(tenant)
            .map(|r| (BackendId(r.backend.id.clone()), r.backend.kind))
    }

    /// Get (or lazily build) the re-signing proxy for a tenant.
    pub fn proxy_for(&self, tenant: &str) -> Result<Arc<Proxy>> {
        let route = self
            .routes
            .get(tenant)
            .ok_or_else(|| GatewayError::Backend(format!("no route for tenant {tenant}")))?;
        let key = (route.backend.id.clone(), tenant.to_string());
        // Recover from a poisoned lock (a prior build_proxy panic) rather than let one
        // panic become a permanent gateway-wide forward outage — the map is intact.
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = pool.get(&key) {
            return Ok(p.clone());
        }
        let proxy = Arc::new(build_proxy(
            &route.backend,
            &route.owner_access_key,
            &route.owner_secret_key,
        ));
        pool.insert(key, proxy.clone());
        Ok(proxy)
    }
}

fn build_proxy(backend: &BackendConfig, access_key: &str, secret_key: &str) -> Proxy {
    let creds = Credentials::new(
        access_key.to_string(),
        secret_key.to_string(),
        None,
        None,
        "gateway-backend",
    );
    let conf: Config = Config::builder()
        // behavior-version-latest is NOT enabled in s3s-aws's aws-sdk pin; setting it
        // explicitly is required or build() panics (a substrate quirk).
        .behavior_version(BehaviorVersion::latest())
        .endpoint_url(backend.endpoint_url.clone())
        .region(Region::new(backend.region.clone()))
        .credentials_provider(creds)
        .force_path_style(backend.force_path_style)
        .build();
    Proxy::from(Client::from_conf(conf))
}

/// The dispatching `impl S3` in front of the per-tenant proxies. Only the ops the
/// gateway authorizes are forwarded; every other op is denied at
/// `S3Access::check` before reaching here, so they fall to the trait's
/// `NotImplemented` default.
pub struct GatewayS3 {
    registry: Arc<BackendRegistry>,
}

impl GatewayS3 {
    pub fn new(registry: Arc<BackendRegistry>) -> Self {
        GatewayS3 { registry }
    }

    fn proxy_for_req<T>(&self, req: &S3Request<T>) -> S3Result<Arc<Proxy>> {
        let principal = req
            .extensions
            .get::<Arc<ResolvedPrincipal>>()
            .ok_or_else(|| s3_error!(InternalError, "resolved principal missing from request"))?;
        self.registry
            .proxy_for(&principal.tenant)
            .map_err(|e| s3_error!(ServiceUnavailable, "backend unavailable: {e}"))
    }
}

#[async_trait::async_trait]
impl S3 for GatewayS3 {
    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        self.proxy_for_req(&req)?.get_object(req).await
    }

    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        self.proxy_for_req(&req)?.head_object(req).await
    }

    async fn put_object(
        &self,
        req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        self.proxy_for_req(&req)?.put_object(req).await
    }

    async fn delete_object(
        &self,
        req: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        self.proxy_for_req(&req)?.delete_object(req).await
    }

    async fn delete_objects(
        &self,
        req: S3Request<DeleteObjectsInput>,
    ) -> S3Result<S3Response<DeleteObjectsOutput>> {
        self.proxy_for_req(&req)?.delete_objects(req).await
    }

    async fn copy_object(
        &self,
        req: S3Request<CopyObjectInput>,
    ) -> S3Result<S3Response<CopyObjectOutput>> {
        self.proxy_for_req(&req)?.copy_object(req).await
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        let proxy = self.proxy_for_req(&req)?;
        // Multi-prefix fan-out obligation stashed by the access layer (ADR-004)?
        if let Some(fo) = req.extensions.get::<Arc<fanout::ListFanout>>().cloned() {
            return fan_out_list_v2(proxy, req, &fo.prefixes).await;
        }
        proxy.list_objects_v2(req).await
    }

    async fn list_objects(
        &self,
        req: S3Request<ListObjectsInput>,
    ) -> S3Result<S3Response<ListObjectsOutput>> {
        self.proxy_for_req(&req)?.list_objects(req).await
    }

    async fn create_multipart_upload(
        &self,
        req: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        self.proxy_for_req(&req)?.create_multipart_upload(req).await
    }

    async fn upload_part(
        &self,
        req: S3Request<UploadPartInput>,
    ) -> S3Result<S3Response<UploadPartOutput>> {
        self.proxy_for_req(&req)?.upload_part(req).await
    }

    async fn upload_part_copy(
        &self,
        req: S3Request<UploadPartCopyInput>,
    ) -> S3Result<S3Response<UploadPartCopyOutput>> {
        self.proxy_for_req(&req)?.upload_part_copy(req).await
    }

    async fn complete_multipart_upload(
        &self,
        req: S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<CompleteMultipartUploadOutput>> {
        self.proxy_for_req(&req)?
            .complete_multipart_upload(req)
            .await
    }

    async fn abort_multipart_upload(
        &self,
        req: S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        self.proxy_for_req(&req)?.abort_multipart_upload(req).await
    }

    async fn list_parts(
        &self,
        req: S3Request<ListPartsInput>,
    ) -> S3Result<S3Response<ListPartsOutput>> {
        self.proxy_for_req(&req)?.list_parts(req).await
    }

    async fn list_multipart_uploads(
        &self,
        req: S3Request<ListMultipartUploadsInput>,
    ) -> S3Result<S3Response<ListMultipartUploadsOutput>> {
        self.proxy_for_req(&req)?.list_multipart_uploads(req).await
    }
}

/// Execute a multi-prefix `ListObjectsV2` by fanning out one backend LIST per granted
/// prefix and merging into a single page with a gateway-owned continuation cursor
/// (ADR-004). Each page is re-decided by the access layer, so live revocation holds.
// ListObjectsV2Output is #[non_exhaustive], so struct-update syntax is unavailable;
// field-reassign on a Default instance is the only construction path.
#[allow(clippy::field_reassign_with_default)]
async fn fan_out_list_v2(
    proxy: Arc<Proxy>,
    req: S3Request<ListObjectsV2Input>,
    prefixes: &[String],
) -> S3Result<S3Response<ListObjectsV2Output>> {
    let bucket = req.input.bucket.clone();
    let max_keys = req.input.max_keys.unwrap_or(1000).clamp(1, 1000) as usize;
    let cursor = req
        .input
        .continuation_token
        .as_deref()
        .and_then(fanout::Cursor::decode);

    // Backend errors from any sub-list must abort the whole page (never silently drop
    // keys, which would corrupt pagination). Captured here since the lister returns a
    // plain Vec.
    let error: Arc<Mutex<Option<S3Error>>> = Arc::new(Mutex::new(None));
    let template = req;

    let lister = |prefix: String, start_after: Option<String>, limit: usize| {
        let proxy = proxy.clone();
        let error = error.clone();
        let mut sub = template.clone();
        sub.input.prefix = Some(prefix);
        sub.input.start_after = start_after;
        sub.input.continuation_token = None;
        sub.input.delimiter = None;
        sub.input.max_keys = Some(limit as i32);
        async move {
            match proxy.list_objects_v2(sub).await {
                Ok(resp) => {
                    // A backend may return fewer than `limit` keys yet still be
                    // truncated; keep the flag so fan_out re-lists instead of stopping.
                    let truncated = resp.output.is_truncated.unwrap_or(false);
                    (resp.output.contents.unwrap_or_default(), truncated)
                }
                Err(e) => {
                    *error.lock().expect("fanout error cell") = Some(e);
                    (Vec::new(), false)
                }
            }
        }
    };

    let page = fanout::fan_out(
        prefixes,
        cursor,
        max_keys,
        |o: &Object| o.key.clone().unwrap_or_default(),
        lister,
    )
    .await
    .map_err(|e| s3_error!(InvalidArgument, "{e}"))?;

    if let Some(e) = error.lock().expect("fanout error cell").take() {
        return Err(e);
    }

    let mut output = ListObjectsV2Output::default();
    output.name = Some(bucket);
    output.max_keys = Some(max_keys as i32);
    output.key_count = Some(page.items.len() as i32);
    output.is_truncated = Some(page.truncated);
    output.contents = Some(page.items);
    output.next_continuation_token = page.next.map(|c| c.encode());
    Ok(S3Response::new(output))
}
