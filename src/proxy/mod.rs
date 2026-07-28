//! Backend proxy. Forwards allowed, canonicalized requests to the
//! target backend, re-signed with a **per-tenant / per-backend** credential — never
//! the caller's. `s3s_aws::Proxy` wraps exactly one `aws_sdk_s3::Client`, so
//! per-tenant credentials require a client pool keyed on `(backend, tenant)` with a
//! dispatching `impl S3` in front (this is the real architecture, not a line item).
//!
//! Canonicalize-before-forward holds by construction: the typed hook mutates
//! `S3Request<Input>` and we forward that same value — there is no raw passthrough.

pub mod bucketfilter;
pub mod fanout;
pub mod obligations;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use aws_sdk_s3::config::timeout::TimeoutConfig;
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::{Client, Config};
use s3s::dto::*;
use s3s::{S3, S3Error, S3Request, S3Response, S3Result, s3_error};
use s3s_aws::Proxy;

use crate::access::proof;
use crate::audit::{BackendOutcome, PendingAudit};
use crate::config::{BackendConfig, GatewayConfig, LimitsConfig};
use crate::error::{GatewayError, Result};
use crate::model::{BackendId, BackendKind};
use crate::proxy::obligations::{BucketVisibility, ResponseObligations};
use crate::secret::Secret;

/// One tenant's routing: which backend, which per-tenant credential, which Org.
struct TenantRoute {
    backend: Arc<BackendConfig>,
    owner_access_key: String,
    /// Stays a [`Secret`] all the way from the config to the SigV4 signer, so no
    /// intermediate struct can print it — see `src/secret.rs`.
    owner_secret_key: Secret<String>,
    organization_id: String,
}

/// The secret-free half of a [`TenantRoute`]: everything the request pipeline needs
/// to route and attribute a request, and nothing it must not hold.
///
/// `S3Access::check` resolves one of these per request and stashes it in
/// `req.extensions`, so every later stage reads the *same* snapshot instead of
/// re-querying a routing table that may swap underneath it. The owner credentials
/// stay in the registry — they must never reach the request extensions, which are
/// visible to every layer above (see the module invariant).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteSnapshot {
    pub tenant: String,
    pub backend_id: BackendId,
    pub backend_kind: BackendKind,
    /// The gateway's AUTHORITATIVE tenant→org binding — never the credential's
    /// self-declared org, so audit attribution is not drift-able.
    pub organization_id: String,
}

/// The routing table: one immutable snapshot, swapped wholesale.
type Routes = HashMap<String, TenantRoute>;

/// Pool identity for a re-signing client: `(backend id, tenant)`.
type PoolKey = (String, String);

/// Resolves a tenant to a re-signing `Proxy`, building and caching one client per
/// `(backend, tenant)`. Backend credentials never leave this registry.
///
/// The routing table lives behind an [`ArcSwap`] so an operator-rendered config can be
/// applied without restarting the process ([`BackendRegistry::apply_config`], plan task
/// 10). Two properties are load-bearing and are what the tests at the bottom of this
/// file pin:
///
/// 1. **One snapshot per request.** `check` resolves a [`RouteSnapshot`] once and
///    stashes it in `req.extensions`; every later stage reads that value, never the
///    table. A swap therefore cannot move a request from under itself — see
///    [`BackendRegistry::proxy_for`], which takes the snapshot rather than a tenant
///    name and refuses if the table has since disagreed with it.
/// 2. **A swap invalidates the client pool.** The pooled clients hold owner
///    credentials baked into their signing config, so keeping them across a config
///    apply would let a rotated-out key keep signing indefinitely.
pub struct BackendRegistry {
    routes: ArcSwap<Routes>,
    pool: Mutex<HashMap<PoolKey, Arc<Proxy>>>,
    /// Connection bounds applied to every pooled backend client (see [`build_proxy`]).
    /// Not swappable: they are baked into a built client, and re-reading them without
    /// rebuilding the pool would report a change that did not happen.
    timeouts: TimeoutConfig,
}

impl BackendRegistry {
    pub fn from_config(cfg: &GatewayConfig) -> Result<Self> {
        Ok(BackendRegistry {
            routes: ArcSwap::from_pointee(build_routes(cfg)?),
            pool: Mutex::new(HashMap::new()),
            timeouts: backend_timeouts(&cfg.limits),
        })
    }

    /// Install a new routing table from a freshly-loaded config.
    ///
    /// The table is built **before** anything is swapped, so a config that does not
    /// resolve leaves the running one untouched — a half-applied routing table is a
    /// tenant pointed at the wrong backend, which is worse than not applying at all.
    ///
    /// The client pool is dropped afterwards. That costs a connection re-establish per
    /// active tenant, and it is not optional: a pooled client carries the owner
    /// credential it was built with, so a rotated secret would otherwise stay in use
    /// for the life of the process.
    pub fn apply_config(&self, cfg: &GatewayConfig) -> Result<()> {
        let routes = build_routes(cfg)?;
        let tenants = routes.len();
        self.routes.store(Arc::new(routes));
        let dropped = {
            let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *pool).len()
        };
        tracing::info!(
            tenants,
            pooled_clients_dropped = dropped,
            "backend routing table replaced"
        );
        Ok(())
    }

    /// Resolve a tenant to its secret-free routing snapshot, or `None` when the
    /// tenant is not routable. Returns an owned value precisely so that no caller
    /// holds a borrow into a table that may be swapped underneath it.
    pub fn route_snapshot(&self, tenant: &str) -> Option<RouteSnapshot> {
        let routes = self.routes.load();
        let route = routes.get(tenant)?;
        Some(RouteSnapshot {
            tenant: tenant.to_string(),
            backend_id: BackendId(route.backend.id.clone()),
            backend_kind: route.backend.kind,
            organization_id: route.organization_id.clone(),
        })
    }

    /// Get (or lazily build) the re-signing proxy for the route this request was
    /// **authorized against**.
    ///
    /// Takes the snapshot rather than a tenant name so the forward cannot silently
    /// land on a different backend than the decision contemplated: if the table has
    /// been swapped since `check` resolved the snapshot and now routes this tenant
    /// elsewhere, the request is refused rather than forwarded. The window is one
    /// config apply wide and the client's retry is re-authorized against the new
    /// table, so failing closed costs a retry and buying the alternative costs a
    /// request landing in the wrong Org's bucket.
    pub fn proxy_for(&self, snapshot: &RouteSnapshot) -> Result<Arc<Proxy>> {
        let routes = self.routes.load();
        let route = routes.get(&snapshot.tenant).ok_or_else(|| {
            GatewayError::Backend(format!("no route for tenant {}", snapshot.tenant))
        })?;
        if route.backend.id != snapshot.backend_id.0 {
            return Err(GatewayError::Backend(format!(
                "tenant {} was authorized against backend {} but now routes to {}; \
                 refusing to forward across a routing change",
                snapshot.tenant, snapshot.backend_id.0, route.backend.id
            )));
        }
        let key: PoolKey = (route.backend.id.clone(), snapshot.tenant.clone());
        // Recover from a poisoned lock (a prior build_proxy panic) rather than let one
        // panic become a permanent gateway-wide forward outage — the map is intact.
        let mut pool = self.pool.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(p) = pool.get(&key) {
            return Ok(p.clone());
        }
        let proxy = Arc::new(build_proxy(
            &route.backend,
            &route.owner_access_key,
            route.owner_secret_key.expose(),
            self.timeouts.clone(),
        ));
        pool.insert(key, proxy.clone());
        Ok(proxy)
    }
}

fn build_routes(cfg: &GatewayConfig) -> Result<Routes> {
    let backends: HashMap<&str, Arc<BackendConfig>> = cfg
        .backends
        .iter()
        .map(|b| (b.id.as_str(), Arc::new(b.clone())))
        .collect();
    let mut routes = Routes::new();
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
    Ok(routes)
}

/// Connection bounds for the backend client.
///
/// Only `connect_timeout` is set by default. The SDK's `read_timeout` is measured
/// from *request initiation*, so on a bulk `PutObject`/`UploadPart` it spans the whole
/// upload — a finite value there would cap object size over a slow link rather than
/// catch a hung backend. It is therefore opt-in (`limits.backend_read_timeout_secs`),
/// and no `operation_timeout` is set at all.
fn backend_timeouts(limits: &LimitsConfig) -> TimeoutConfig {
    let mut b = TimeoutConfig::builder().connect_timeout(limits.backend_connect_timeout());
    if let Some(read) = limits.backend_read_timeout() {
        b = b.read_timeout(read);
    }
    b.build()
}

fn build_proxy(
    backend: &BackendConfig,
    access_key: &str,
    secret_key: &str,
    timeouts: TimeoutConfig,
) -> Proxy {
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
        .timeout_config(timeouts)
        .build();
    Proxy::from(Client::from_conf(conf))
}

/// Everything the forwarding path draws on. A struct rather than a bare registry
/// because the forward half keeps growing (limits, response obligations, the
/// pending-audit handle) — and deliberately *not* the whole `Gateway`: by the time a
/// request reaches here it is already authorized, so this layer must not hold a PDP
/// handle it could be tempted to re-decide with.
pub struct S3GatewayState {
    pub registry: Arc<BackendRegistry>,
    /// The *live* limits handle, not a copy: the forward path has no readers today,
    /// and whoever adds the first one must get the value a config apply installed
    /// rather than the one this service was assembled with.
    limits: Arc<ArcSwap<LimitsConfig>>,
}

impl S3GatewayState {
    pub fn new(registry: Arc<BackendRegistry>, limits: Arc<ArcSwap<LimitsConfig>>) -> Self {
        S3GatewayState { registry, limits }
    }

    /// The hardening limits in force right now.
    pub fn limits(&self) -> arc_swap::Guard<Arc<LimitsConfig>> {
        self.limits.load()
    }

    /// The two bounds a filtered `ListBuckets` page is cut with: `(page size, backend
    /// pages this request may drain)`.
    ///
    /// Read as owned values rather than handed out as a guard because the caller holds
    /// them across an `await` — and read *here*, from the live handle, so a config apply
    /// lands rather than being frozen at service-assembly time.
    fn bucket_listing_bounds(&self) -> (usize, usize) {
        let limits = self.limits();
        (
            limits.max_buckets_per_page.max(1),
            limits.max_bucket_list_pages.max(1),
        )
    }
}

/// The dispatching `impl S3` in front of the per-tenant proxies. Only the ops
/// `OP_TABLE` marks `Coverage::Enforced` have an arm here; every other op is denied at
/// `S3Access::check` before reaching this layer, and falls to the trait's
/// `NotImplemented` default if it somehow does not — with the one exception noted on
/// [`GatewayS3::post_object`], whose trait default forwards rather than refusing.
///
/// `tests/gate_invariants.rs` probes both halves of that claim: every enforced op has
/// an arm, and a sample of denied ops still lands on `NotImplemented`.
pub struct GatewayS3 {
    state: Arc<S3GatewayState>,
}

impl GatewayS3 {
    pub fn new(state: Arc<S3GatewayState>) -> Self {
        GatewayS3 { state }
    }

    /// The re-signing proxy for this request's tenant, taken from the route
    /// `check` already resolved — the forward must use the same route the decision
    /// was made against, never a freshly-resolved one.
    ///
    /// Every arm below goes through here, which makes it the single place the
    /// authorization proof is demanded: a hook that forgets to enforce cannot reach a
    /// backend client, because the client is only obtainable after the proof checks
    /// out.
    fn proxy_for_req<T>(&self, req: &S3Request<T>) -> S3Result<Arc<Proxy>> {
        proof::require(req)?;
        let route = req
            .extensions
            .get::<Arc<RouteSnapshot>>()
            .ok_or_else(|| s3_error!(InternalError, "route snapshot missing from request"))?;
        self.state
            .registry
            .proxy_for(route)
            .map_err(|e| s3_error!(ServiceUnavailable, "backend unavailable: {e}"))
    }

    /// Resolve the proxy, run the backend call, and settle this request's audit record
    /// with what the backend leg actually did (plan task 18).
    ///
    /// Every arm goes through here, which is what makes the enrichment total rather
    /// than per-op: `backend_status` and `outcome: "error"` used to be a hardcoded
    /// `None` and a variant with no producer, because the record was emitted before the
    /// forward existed.
    ///
    /// The pending handle is cloned out **before** `call` takes ownership of `req`:
    /// otherwise the request's extensions — and the last reference to the record —
    /// would be dropped inside the backend call, and the record would be emitted
    /// unenriched a moment before the answer arrived.
    async fn forward<T, O, F, Fut>(&self, req: S3Request<T>, call: F) -> S3Result<S3Response<O>>
    where
        F: FnOnce(Arc<Proxy>, S3Request<T>) -> Fut + Send,
        Fut: std::future::Future<Output = S3Result<S3Response<O>>> + Send,
    {
        let proxy = self.proxy_for_req(&req)?;
        let pending = req.extensions.get::<Arc<PendingAudit>>().cloned();
        let result = call(proxy, req).await;
        if let Some(pending) = pending {
            match &result {
                Ok(_) => pending.settle(BackendOutcome::SucceededStatusUnknown, None),
                Err(e) => pending.settle(BackendOutcome::Failed, backend_status(e)),
            }
        }
        result
    }
}

/// The backend's HTTP status — **only** when it is genuinely the backend's.
///
/// `S3Error::status_code()` falls back to the status implied by the error *code*
/// (`s3s-0.14.1/src/error/mod.rs:133`), so it happily answers `500` for a connection
/// refused that never reached the backend, and `400` for a malformed continuation token
/// this gateway rejected itself. Writing either into a regulated record as the
/// backend's status would be asserting something nobody observed — the same class of
/// mistake as synthesizing `200` on the success path (plan defect E-1).
///
/// So the status is reported only when both hold:
///
/// - the error carries a `source`, which only s3s-aws sets (`s3s-aws/src/error.rs:26`);
///   a gateway-minted `s3_error!` never does; and
/// - the code is not `InternalError`, which s3s-aws only ever replaces from
///   `meta.code()` on the `SdkError::ServiceError` branch — and that same branch is the
///   only one that calls `set_status_code` with a real response status
///   (`s3s-aws/src/error.rs:11-24,38-41`).
///
/// An `InternalError` from s3s-aws is genuinely ambiguous (a service error whose code
/// we could not map looks identical to a dispatch failure), so it reports nothing.
fn backend_status(err: &S3Error) -> Option<u16> {
    if err.source().is_none() || *err.code() == s3s::S3ErrorCode::InternalError {
        return None;
    }
    err.status_code().map(|s| s.as_u16())
}

#[async_trait::async_trait]
impl S3 for GatewayS3 {
    async fn get_object(
        &self,
        req: S3Request<GetObjectInput>,
    ) -> S3Result<S3Response<GetObjectOutput>> {
        self.forward(req, |p, r| async move { p.get_object(r).await })
            .await
    }

    async fn head_object(
        &self,
        req: S3Request<HeadObjectInput>,
    ) -> S3Result<S3Response<HeadObjectOutput>> {
        self.forward(req, |p, r| async move { p.head_object(r).await })
            .await
    }

    async fn put_object(
        &self,
        req: S3Request<PutObjectInput>,
    ) -> S3Result<S3Response<PutObjectOutput>> {
        self.forward(req, |p, r| async move { p.put_object(r).await })
            .await
    }

    async fn delete_object(
        &self,
        req: S3Request<DeleteObjectInput>,
    ) -> S3Result<S3Response<DeleteObjectOutput>> {
        self.forward(req, |p, r| async move { p.delete_object(r).await })
            .await
    }

    async fn delete_objects(
        &self,
        req: S3Request<DeleteObjectsInput>,
    ) -> S3Result<S3Response<DeleteObjectsOutput>> {
        self.forward(req, |p, r| async move { p.delete_objects(r).await })
            .await
    }

    async fn copy_object(
        &self,
        req: S3Request<CopyObjectInput>,
    ) -> S3Result<S3Response<CopyObjectOutput>> {
        self.forward(req, |p, r| async move { p.copy_object(r).await })
            .await
    }

    async fn list_objects_v2(
        &self,
        req: S3Request<ListObjectsV2Input>,
    ) -> S3Result<S3Response<ListObjectsV2Output>> {
        self.forward(req, |proxy, req| async move {
            // Multi-prefix fan-out obligation stashed by the access layer (ADR-004)?
            let prefixes = ResponseObligations::of(&req)
                .and_then(|o| o.list_fanout.clone())
                .map(|f| f.prefixes);
            if let Some(prefixes) = prefixes {
                return fan_out_list_v2(proxy, req, &prefixes).await;
            }
            proxy.list_objects_v2(req).await
        })
        .await
    }

    async fn list_objects(
        &self,
        req: S3Request<ListObjectsInput>,
    ) -> S3Result<S3Response<ListObjectsOutput>> {
        self.forward(req, |p, r| async move { p.list_objects(r).await })
            .await
    }

    async fn create_multipart_upload(
        &self,
        req: S3Request<CreateMultipartUploadInput>,
    ) -> S3Result<S3Response<CreateMultipartUploadOutput>> {
        self.forward(
            req,
            |p, r| async move { p.create_multipart_upload(r).await },
        )
        .await
    }

    async fn upload_part(
        &self,
        req: S3Request<UploadPartInput>,
    ) -> S3Result<S3Response<UploadPartOutput>> {
        self.forward(req, |p, r| async move { p.upload_part(r).await })
            .await
    }

    async fn upload_part_copy(
        &self,
        req: S3Request<UploadPartCopyInput>,
    ) -> S3Result<S3Response<UploadPartCopyOutput>> {
        self.forward(req, |p, r| async move { p.upload_part_copy(r).await })
            .await
    }

    async fn complete_multipart_upload(
        &self,
        req: S3Request<CompleteMultipartUploadInput>,
    ) -> S3Result<S3Response<CompleteMultipartUploadOutput>> {
        self.forward(
            req,
            |p, r| async move { p.complete_multipart_upload(r).await },
        )
        .await
    }

    async fn abort_multipart_upload(
        &self,
        req: S3Request<AbortMultipartUploadInput>,
    ) -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        self.forward(req, |p, r| async move { p.abort_multipart_upload(r).await })
            .await
    }

    /// Parts of one upload, with the identity fields stripped.
    ///
    /// The parts themselves disclose nothing new: the caller already holds `read_objects`
    /// on this key, and part sizes and ETags describe the object it may read. `Owner` and
    /// `Initiator` are different — under this gateway they always name the **shared
    /// tenant-owner credential** every request is re-signed with, never the principal who
    /// created the upload. Forwarding them publishes the backend identity the whole
    /// re-signing design exists to keep off the wire, and answers a question the caller
    /// did not ask, so they are dropped.
    async fn list_parts(
        &self,
        req: S3Request<ListPartsInput>,
    ) -> S3Result<S3Response<ListPartsOutput>> {
        let mut resp = self
            .forward(req, |p, r| async move { p.list_parts(r).await })
            .await?;
        resp.output.owner = None;
        resp.output.initiator = None;
        Ok(resp)
    }

    /// In-flight uploads under the granted prefix, with the identity fields stripped and
    /// the prefix re-applied.
    ///
    /// Two transforms, for two different reasons:
    ///
    /// - **`Owner` / `Initiator` are dropped**, for the reason on [`Self::list_parts`]:
    ///   they name the tenant-owner credential, not the caller.
    /// - **uploads outside the request's prefix are dropped.** The access hook narrows
    ///   `prefix` to a granted scope and the backend is expected to honor it, but "the
    ///   backend honored the filter" is not something this gateway can observe — and the
    ///   keys of in-flight uploads are exactly what a prefix-scoped principal must not
    ///   see. Re-applying the filter costs a string comparison per row and removes the
    ///   assumption. The markers are left as the backend set them, so pagination still
    ///   works; a page may simply come back short.
    async fn list_multipart_uploads(
        &self,
        req: S3Request<ListMultipartUploadsInput>,
    ) -> S3Result<S3Response<ListMultipartUploadsOutput>> {
        let prefix = req.input.prefix.clone();
        let mut resp = self
            .forward(req, |p, r| async move { p.list_multipart_uploads(r).await })
            .await?;
        if let Some(uploads) = resp.output.uploads.as_mut() {
            uploads.retain(|u| match (&prefix, &u.key) {
                (Some(p), Some(k)) => k.starts_with(p.as_str()),
                // No prefix on the request ⇒ a whole-bucket list grant, nothing to
                // re-apply. A row with no key at all was never authorized against
                // anything, so it goes.
                (None, Some(_)) => true,
                _ => false,
            });
            for upload in uploads.iter_mut() {
                upload.owner = None;
                upload.initiator = None;
            }
        }
        Ok(resp)
    }

    /// Enumerate buckets — the one arm that **withholds** what the backend returned.
    ///
    /// Everything here follows from one fact: the forward is re-signed with the
    /// per-`(backend, tenant)` owner credential, so the backend answers with the tenant's
    /// entire bucket namespace regardless of the caller. The visibility obligation the
    /// access hook installed is therefore not an optimization — it is the authorization.
    ///
    /// Three branches, in order:
    ///
    /// 1. **no obligation** ⇒ refuse. Only [`GatewayAccess::list_buckets`] installs one,
    ///    so its absence means no decision was made about this request. This is the same
    ///    fail-closed argument as the [`AuthzProof`](crate::access::AuthzProof), applied
    ///    to a response transform: forwarding here would publish the namespace.
    /// 2. **[`BucketVisibility::Nothing`]** ⇒ an empty listing, produced without touching
    ///    the backend and without demanding a proof (there is nothing to fetch). This is
    ///    the single branch serving both "denied" and "allowed with no grants", which is
    ///    what makes them indistinguishable to the caller — see the hook for why that
    ///    matters.
    /// 3. otherwise ⇒ drain, filter, sort, page.
    async fn list_buckets(
        &self,
        req: S3Request<ListBucketsInput>,
    ) -> S3Result<S3Response<ListBucketsOutput>> {
        let Some(visibility) =
            ResponseObligations::of(&req).and_then(|o| o.visible_buckets.clone())
        else {
            return Err(s3_error!(
                InternalError,
                "list buckets reached the forward path with no bucket-visibility \
                 obligation, which means no authorization decision was applied to it"
            ));
        };
        if visibility == BucketVisibility::Nothing {
            // `Some(vec![])`, not `None`: an S3 client reads a missing `<Buckets>` and a
            // present-but-empty one differently, and the honest statement is "you have
            // zero buckets", not "this field was not populated".
            return Ok(S3Response::new(ListBucketsOutput {
                buckets: Some(Vec::new()),
                prefix: req.input.prefix.clone(),
                ..Default::default()
            }));
        }
        let (max_page, max_pages) = self.state.bucket_listing_bounds();
        // A caller-supplied `max-buckets` is clamped, not honored: the page boundaries
        // are the gateway's now, so an unbounded request must not turn into an unbounded
        // response.
        let page_size = req
            .input
            .max_buckets
            .map_or(max_page, |m| (m.max(1) as usize).min(max_page));
        self.forward(req, move |proxy, req| async move {
            filtered_bucket_listing(proxy, req, &visibility, page_size, max_pages).await
        })
        .await
    }

    /// PostObject: the ONE `S3` method whose s3s default is not `NotImplemented` — it
    /// re-dispatches through `put_object` (`s3_trait.rs:4401-4406`).
    ///
    /// M1 carried an explicit `NotImplemented` override here precisely because of that:
    /// while the op was `Coverage::Denied`, inheriting the default would have let a form
    /// upload *forward* on the strength of a trait default, out of reach of the "denied
    /// ops fall to NotImplemented" argument the whole table rests on. Now that PostObject
    /// is `Coverage::Enforced` the override is gone and this arm forwards deliberately —
    /// but the hazard has not: for this one op, deleting the arm below does **not**
    /// produce a 501, it produces a silent forward through `put_object`. What stops that
    /// from being a fail-open is [`Self::forward`], which demands the [`AuthzProof`]
    /// before any client exists; `tests/gate_invariants.rs::post_object_forwards_only_with_a_proof`
    /// is the guard.
    ///
    /// `s3s_aws::Proxy` has no `post_object` either, so the forward lands on the same
    /// default: the input is converted to a `PutObjectInput` and sent as a PUT. The
    /// proof is checked against `OperationName` = `PostObject` before that conversion.
    async fn post_object(
        &self,
        req: S3Request<PostObjectInput>,
    ) -> S3Result<S3Response<PostObjectOutput>> {
        self.forward(req, |p, r| async move { p.post_object(r).await })
            .await
    }

    // ── bucket existence and lifecycle ──────────────────────────────────────────

    async fn head_bucket(
        &self,
        req: S3Request<HeadBucketInput>,
    ) -> S3Result<S3Response<HeadBucketOutput>> {
        self.forward(req, |p, r| async move { p.head_bucket(r).await })
            .await
    }

    async fn get_bucket_location(
        &self,
        req: S3Request<GetBucketLocationInput>,
    ) -> S3Result<S3Response<GetBucketLocationOutput>> {
        self.forward(req, |p, r| async move { p.get_bucket_location(r).await })
            .await
    }

    async fn create_bucket(
        &self,
        req: S3Request<CreateBucketInput>,
    ) -> S3Result<S3Response<CreateBucketOutput>> {
        self.forward(req, |p, r| async move { p.create_bucket(r).await })
            .await
    }

    async fn delete_bucket(
        &self,
        req: S3Request<DeleteBucketInput>,
    ) -> S3Result<S3Response<DeleteBucketOutput>> {
        self.forward(req, |p, r| async move { p.delete_bucket(r).await })
            .await
    }

    // ── bucket sub-resources ────────────────────────────────────────────────────

    async fn get_bucket_policy(
        &self,
        req: S3Request<GetBucketPolicyInput>,
    ) -> S3Result<S3Response<GetBucketPolicyOutput>> {
        self.forward(req, |p, r| async move { p.get_bucket_policy(r).await })
            .await
    }

    async fn put_bucket_policy(
        &self,
        req: S3Request<PutBucketPolicyInput>,
    ) -> S3Result<S3Response<PutBucketPolicyOutput>> {
        self.forward(req, |p, r| async move { p.put_bucket_policy(r).await })
            .await
    }

    async fn get_bucket_cors(
        &self,
        req: S3Request<GetBucketCorsInput>,
    ) -> S3Result<S3Response<GetBucketCorsOutput>> {
        self.forward(req, |p, r| async move { p.get_bucket_cors(r).await })
            .await
    }

    async fn put_bucket_cors(
        &self,
        req: S3Request<PutBucketCorsInput>,
    ) -> S3Result<S3Response<PutBucketCorsOutput>> {
        self.forward(req, |p, r| async move { p.put_bucket_cors(r).await })
            .await
    }

    // ── object tagging and attributes ───────────────────────────────────────────

    async fn get_object_tagging(
        &self,
        req: S3Request<GetObjectTaggingInput>,
    ) -> S3Result<S3Response<GetObjectTaggingOutput>> {
        self.forward(req, |p, r| async move { p.get_object_tagging(r).await })
            .await
    }

    async fn put_object_tagging(
        &self,
        req: S3Request<PutObjectTaggingInput>,
    ) -> S3Result<S3Response<PutObjectTaggingOutput>> {
        self.forward(req, |p, r| async move { p.put_object_tagging(r).await })
            .await
    }

    async fn delete_object_tagging(
        &self,
        req: S3Request<DeleteObjectTaggingInput>,
    ) -> S3Result<S3Response<DeleteObjectTaggingOutput>> {
        self.forward(req, |p, r| async move { p.delete_object_tagging(r).await })
            .await
    }

    async fn get_object_attributes(
        &self,
        req: S3Request<GetObjectAttributesInput>,
    ) -> S3Result<S3Response<GetObjectAttributesOutput>> {
        self.forward(req, |p, r| async move { p.get_object_attributes(r).await })
            .await
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
    let cursor = decode_cursor(req.input.continuation_token.as_deref())?;

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

/// Drain the backend's bucket list, intersect it with the principal's visibility, and
/// return one gateway-cut page.
///
/// The drain is the part worth reading twice. A filtered listing cannot be produced
/// page-by-page against the backend's pagination: entries are removed, so the backend's
/// offsets stop describing the client's sequence, and the *order* the pages arrive in is
/// not something RGW promises (defect B-9). So the whole list is read, sorted
/// gateway-side, and paged from there. Two things bound it, and both fail loudly rather
/// than truncating: a page cap, and a check that the backend's token actually advances —
/// a backend echoing one token forever would otherwise spin here.
///
/// A short answer is never acceptable on this path. An authorization-filtered listing
/// that quietly omitted buckets would look exactly like a revoked grant, which is the one
/// thing a caller cannot debug.
// ListBucketsOutput is constructed field-by-field: struct-update syntax on a
// `#[non_exhaustive]`-adjacent generated DTO is unavailable, as in fan_out_list_v2.
#[allow(clippy::field_reassign_with_default)]
async fn filtered_bucket_listing(
    proxy: Arc<Proxy>,
    req: S3Request<ListBucketsInput>,
    visibility: &BucketVisibility,
    page_size: usize,
    max_pages: usize,
) -> S3Result<S3Response<ListBucketsOutput>> {
    let cursor = decode_cursor(req.input.continuation_token.as_deref())?;
    let name_prefix = req.input.prefix.clone();

    let mut all: Vec<Bucket> = Vec::new();
    let mut token: Option<String> = None;
    for page in 0.. {
        if page >= max_pages {
            return Err(s3_error!(
                ServiceUnavailable,
                "this tenant's bucket list exceeds the {max_pages}-page drain bound; the \
                 gateway will not answer a bucket listing it cannot filter completely"
            ));
        }
        let mut sub = req.clone();
        sub.input.continuation_token = token.clone();
        // The backend's page size is its own business; the gateway's page is cut after
        // filtering. Asking for the client's `max-buckets` here would just make the
        // drain longer.
        sub.input.max_buckets = None;
        let out = proxy.list_buckets(sub).await?.output;
        if let Some(buckets) = out.buckets {
            all.extend(buckets);
        }
        match out.continuation_token {
            Some(next) if !next.is_empty() && Some(&next) != token.as_ref() => token = Some(next),
            // Either the backend is done, or it handed back the token it was given.
            // The second is a backend bug; stopping is right either way, and the page
            // cap above is what catches a backend that cycles between two tokens.
            _ => break,
        }
    }

    let page = bucketfilter::page(all, visibility, name_prefix.as_deref(), cursor, page_size)
        .map_err(|e| s3_error!(InvalidArgument, "{e}"))?;

    let mut output = ListBucketsOutput::default();
    output.buckets = Some(page.buckets);
    output.continuation_token = page.next.map(|c| c.encode());
    output.prefix = name_prefix;
    // `Owner` is withheld, not mapped. What the backend reports is the tenant-owner
    // credential this gateway re-signed as — the same value for every principal in the
    // tenant — so forwarding it would publish the shared backend identity, and
    // substituting the caller would be inventing a canonical user id the backend never
    // issued.
    output.owner = None;
    Ok(S3Response::new(output))
}

/// Decode a client-supplied continuation token, or refuse the request.
///
/// A token we cannot decode is an **error**, never "start over from page 1". Restarting
/// silently hands the client the first page with a fresh token and no signal that its
/// position was lost: a paginating job re-reads what it already processed and believes
/// it paginated correctly. That is not hypothetical — widening `scope_hash` from 16 to
/// 64 hex characters made every cursor issued by an older build undecodable, so the
/// rollout that shipped it would have restarted every in-flight listing in the fleet.
///
/// A cursor whose *scope* changed is already a loud `InvalidArgument`
/// (`fanout::Cursor::validate`); a cursor that is malformed, truncated or forged is the
/// same class of fault and gets the same answer. Losing your place is recoverable;
/// silently reprocessing is not.
fn decode_cursor(token: Option<&str>) -> S3Result<Option<fanout::Cursor>> {
    match token {
        None => Ok(None),
        Some(t) => Ok(Some(fanout::Cursor::decode(t).ok_or_else(|| {
            s3_error!(InvalidArgument, "malformed continuation token")
        })?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A config with `tenants` / `backends` under the caller's control, so a test can
    /// describe a re-route or a credential rotation as the operator would.
    pub(super) fn config(backends: serde_json::Value, tenants: serde_json::Value) -> GatewayConfig {
        GatewayConfig::from_json(
            &serde_json::json!({
                "listen": "127.0.0.1:0",
                "sts": { "master_key_hex": "00".repeat(32), "signing_key_hex": "11".repeat(32) },
                "pdp": { "mode": "embedded" },
                "audit": { "sink_url": "http://127.0.0.1:59999/none",
                           "spill_path": "/dev/null" },
                "backends": backends,
                "tenants": tenants,
                "bundle_path": "/dev/null"
            })
            .to_string(),
        )
        .expect("config")
    }

    pub(super) fn two_backends() -> serde_json::Value {
        serde_json::json!([
            { "id": "bay-1", "kind": "ceph", "endpoint_url": "http://127.0.0.1:7480" },
            { "id": "bay-2", "kind": "remote_s3", "endpoint_url": "http://127.0.0.1:7481" },
        ])
    }

    pub(super) fn acme_on(backend: &str, secret: &str) -> serde_json::Value {
        serde_json::json!([
            { "tenant": "acme", "organization_id": "org-acme", "backend_id": backend,
              "owner_access_key": "OWNER", "owner_secret_key": secret }
        ])
    }

    fn registry() -> BackendRegistry {
        let cfg = config(two_backends(), acme_on("bay-1", "OWNERSECRET"));
        BackendRegistry::from_config(&cfg).expect("registry")
    }

    #[test]
    fn route_snapshot_carries_no_owner_credentials() {
        // Destructured WITHOUT `..` on purpose: adding a field to RouteSnapshot is a
        // compile error here, so the next person must justify it against the module
        // invariant — backend credentials never leave this registry, and this value
        // goes into the request extensions where every layer can read it.
        let RouteSnapshot {
            tenant,
            backend_id,
            backend_kind,
            organization_id,
        } = registry().route_snapshot("acme").expect("acme is routable");
        assert_eq!(tenant, "acme");
        assert_eq!(backend_id, BackendId("bay-1".into()));
        assert_eq!(backend_kind, BackendKind::Ceph);
        assert_eq!(organization_id, "org-acme");
    }

    #[test]
    fn unroutable_tenant_has_no_snapshot() {
        assert!(registry().route_snapshot("not-a-tenant").is_none());
    }

    // ── hot-swappable routing (plan task 10) ────────────────────────────────────

    #[test]
    fn applying_a_config_replaces_the_routing_table() {
        let reg = registry();
        assert_eq!(
            reg.route_snapshot("acme").unwrap().backend_id,
            BackendId("bay-1".into())
        );
        assert!(reg.route_snapshot("globex").is_none());

        let next = config(
            two_backends(),
            serde_json::json!([
                { "tenant": "acme", "organization_id": "org-acme", "backend_id": "bay-2",
                  "owner_access_key": "OWNER", "owner_secret_key": "S" },
                { "tenant": "globex", "organization_id": "org-globex", "backend_id": "bay-1",
                  "owner_access_key": "OWNER2", "owner_secret_key": "S2" },
            ]),
        );
        reg.apply_config(&next).expect("apply");

        let acme = reg.route_snapshot("acme").unwrap();
        assert_eq!(acme.backend_id, BackendId("bay-2".into()));
        assert_eq!(acme.backend_kind, BackendKind::RemoteS3);
        assert_eq!(
            reg.route_snapshot("globex").unwrap().organization_id,
            "org-globex"
        );

        // A tenant removed from the config stops being routable — the revocation
        // direction of the same mechanism.
        reg.apply_config(&config(two_backends(), acme_on("bay-1", "S")))
            .expect("apply");
        assert!(reg.route_snapshot("globex").is_none());
    }

    #[test]
    fn a_config_that_does_not_resolve_leaves_the_running_one_untouched() {
        // Half-applying a routing table means a tenant pointed at somebody else's
        // backend. The build must therefore complete before anything is stored.
        let reg = registry();
        // Built by hand, past `GatewayConfig::from_json`, on purpose. Load-time
        // validation already refuses an unknown `backend_id` — assert that first, so
        // this test cannot quietly become a test of the loader — but `apply_config`
        // must not *depend* on having been handed a validated config: it is a `&self`
        // method on a running gateway and its ordering guarantee has to stand alone.
        assert!(
            GatewayConfig::from_json(
                &serde_json::json!({
                    "listen": "127.0.0.1:0",
                    "sts": { "master_key_hex": "00".repeat(32),
                             "signing_key_hex": "11".repeat(32) },
                    "pdp": { "mode": "embedded" },
                    "audit": { "sink_url": "http://127.0.0.1:59999/none",
                               "spill_path": "/dev/null" },
                    "backends": two_backends(),
                    "tenants": [
                        { "tenant": "acme", "organization_id": "org-acme",
                          "backend_id": "nope",
                          "owner_access_key": "O", "owner_secret_key": "S" }
                    ],
                    "bundle_path": "/dev/null"
                })
                .to_string()
            )
            .is_err(),
            "the loader must still refuse an unknown backend_id"
        );

        let mut broken = config(
            two_backends(),
            serde_json::json!([
                { "tenant": "acme", "organization_id": "org-acme", "backend_id": "bay-2",
                  "owner_access_key": "O", "owner_secret_key": "S" },
                { "tenant": "globex", "organization_id": "org-globex", "backend_id": "bay-1",
                  "owner_access_key": "O", "owner_secret_key": "S" },
            ]),
        );
        // The second tenant is the one that fails to resolve; the first would have
        // applied cleanly, which is exactly the half-applied table this must prevent.
        broken.tenants[1].backend_id = "nope".into();
        assert!(reg.apply_config(&broken).is_err());
        // Not "acme still routes" — acme routes to what it routed to before, and the
        // half of the config that *was* valid did not land either.
        assert_eq!(
            reg.route_snapshot("acme").unwrap().backend_id,
            BackendId("bay-1".into())
        );
        assert!(reg.route_snapshot("globex").is_none());
    }

    #[test]
    fn a_forward_cannot_cross_a_routing_change_it_was_not_authorized_against() {
        // The invariant the RouteSnapshot exists for, at the one place the snapshot
        // meets the mutable table. `check` resolved this snapshot; between then and the
        // forward, the operator repointed the tenant.
        let reg = registry();
        let authorized_against = reg.route_snapshot("acme").expect("routable");
        assert!(reg.proxy_for(&authorized_against).is_ok());

        reg.apply_config(&config(two_backends(), acme_on("bay-2", "OWNERSECRET")))
            .expect("apply");

        let Err(err) = reg.proxy_for(&authorized_against) else {
            panic!("forwarding onto a backend the decision never saw must fail")
        };
        assert!(format!("{err}").contains("refusing to forward"), "{err}");

        // A request that arrives *after* the apply resolves its own snapshot and is
        // forwarded normally: the refusal is scoped to the swap window, not permanent.
        let fresh = reg.route_snapshot("acme").expect("routable");
        assert_eq!(fresh.backend_id, BackendId("bay-2".into()));
        assert!(reg.proxy_for(&fresh).is_ok());
    }

    #[test]
    fn applying_a_config_drops_the_pooled_clients() {
        // A pooled client bakes in the owner credential it was built with, so surviving
        // a config apply would mean a rotated-out secret keeps signing for the life of
        // the process. Observed through client identity: same Arc before, different
        // after.
        let reg = registry();
        let route = reg.route_snapshot("acme").expect("routable");
        let first = reg.proxy_for(&route).expect("proxy");
        assert!(
            Arc::ptr_eq(&first, &reg.proxy_for(&route).expect("proxy")),
            "the pool must serve the same client twice, or this test measures nothing"
        );

        // Same backend, rotated owner secret — the case where nothing about routing
        // changed and only the credential did.
        reg.apply_config(&config(two_backends(), acme_on("bay-1", "ROTATED")))
            .expect("apply");
        let after = reg.proxy_for(&route).expect("proxy");
        assert!(
            !Arc::ptr_eq(&first, &after),
            "the pooled client survived a credential rotation"
        );
    }

    #[test]
    fn only_a_status_the_backend_really_reported_reaches_the_audit_record() {
        use s3s::S3ErrorCode;

        // What s3s-aws produces for a real service error: the backend's own code, and a
        // status it explicitly set from the HTTP response. This one is genuine and must
        // be recorded.
        let mut real = S3Error::new(S3ErrorCode::NoSuchKey);
        real.set_source(Box::new(std::io::Error::other("sdk service error")));
        real.set_status_code(http::StatusCode::NOT_FOUND);
        assert_eq!(backend_status(&real), Some(404));

        // A gateway-minted refusal. `S3Error::status_code()` falls back to the status
        // implied by the *code*, so asking it directly would write `400` into the record
        // as though a backend had answered — for a request that never left the process.
        let ours = s3_error!(InvalidArgument, "malformed continuation token");
        assert_eq!(
            ours.status_code().map(|s| s.as_u16()),
            Some(400),
            "the fallback really is there; this is what must not be trusted"
        );
        assert_eq!(
            backend_status(&ours),
            None,
            "a status the gateway invented for its own error is not the backend's"
        );

        // A dispatch failure (connection refused, timeout): s3s-aws attaches the SDK
        // error as the source but leaves the code at InternalError and sets no status.
        // Ambiguous with an unmapped service code, so we say nothing rather than 500.
        let mut dispatch = S3Error::new(S3ErrorCode::InternalError);
        dispatch.set_source(Box::new(std::io::Error::other("dispatch failure")));
        assert_eq!(dispatch.status_code().map(|s| s.as_u16()), Some(500));
        assert_eq!(
            backend_status(&dispatch),
            None,
            "a connection that never reached the backend has no backend status"
        );
    }

    #[test]
    fn an_undecodable_continuation_token_is_refused_not_restarted() {
        // No token means page 1 — that is the only way a listing legitimately starts.
        assert!(decode_cursor(None).expect("absent token").is_none());

        // A token this build issued round-trips.
        let issued = fanout::Cursor {
            scope_hash: fanout::scope_hash(&["2024/".to_string()]),
            last_key: "2024/a.csv".into(),
        }
        .encode();
        let back = decode_cursor(Some(&issued))
            .expect("a well-formed token decodes")
            .expect("some");
        assert_eq!(back.last_key, "2024/a.csv");

        // Anything else is an error, not page 1. The three shapes that matter: garbage,
        // a token from a build whose cursor encoding differed, and the empty string.
        for bad in ["garbage", "v1.notahash.32303234", ""] {
            let err = decode_cursor(Some(bad)).expect_err(
                "an undecodable cursor must be refused; restarting the listing silently \
                 makes a paginating client reprocess page 1 believing it advanced",
            );
            assert_eq!(*err.code(), s3s::S3ErrorCode::InvalidArgument, "{bad:?}");
        }
    }
}
