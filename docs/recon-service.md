# s3s 0.14.1 — Build & Serve Reference

All paths are `s3s-0.14.1/src/…`. `S3Result<T> = std::result::Result<T, S3Error>` (`error/mod.rs:33`, note default `T=()`). `S3ErrorCode` is an enum (`error/generated.rs:251`). Macro `s3s::s3_error!(Code, "msg")` builds an `S3Error`.

## Core `use` paths (crate root re-exports, `lib.rs:160-171`)
```rust
use s3s::{S3, S3Request, S3Response, S3Result, Body};          // S3 trait, protocol types, body
use s3s::{HttpRequest, HttpResponse, HttpError, TrailingHeaders};
use s3s::S3Operation;                                          // { pub name: &'static str } (s3_op.rs:1)
use s3s::service::{S3Service, S3ServiceBuilder};               // service.rs
use s3s::config::{S3Config, S3ConfigProvider, StaticConfigProvider, HotReloadConfigProvider};
use s3s::auth::{S3Auth, SimpleAuth, Credentials, SecretKey};
use s3s::access::{S3Access, S3AccessContext};
use s3s::host::{S3Host, SingleDomain, MultiDomain, VirtualHost, DomainError};
use s3s::route::S3Route;
use s3s::validation::{NameValidation, AwsNameValidation};
use s3s::dto::*;                                               // *Input / *Output types
```
`HttpRequest<B=Body> = http::Request<B>`, `HttpResponse<B=Body> = http::Response<B>` (`protocol.rs:14-15`). `Body` is `s3s::http::Body` re-exported (`http/body.rs:23`).

---

## 1. Constructing the service — `S3ServiceBuilder` (`service.rs:120-452`)

```rust
pub struct S3ServiceBuilder {
    s3: Arc<dyn S3>,
    config: Option<Arc<dyn S3ConfigProvider>>,
    host: Option<Box<dyn S3Host>>,
    auth: Option<Box<dyn S3Auth>>,
    access: Option<Box<dyn S3Access>>,
    route: Option<Box<dyn S3Route>>,
    validation: Option<Box<dyn NameValidation>>,
}
```
Exact method set (all `set_*` take `&mut self`, consume-on-`build`):
```rust
pub fn new(s3: impl S3) -> Self                                   // s3 boxed into Arc<dyn S3>
pub fn set_config(&mut self, config: Arc<dyn S3ConfigProvider>)  // NOTE: Arc<dyn ...>, not impl
pub fn set_host(&mut self, host: impl S3Host)                    // boxed
pub fn set_auth(&mut self, auth: impl S3Auth)                    // boxed
pub fn set_access(&mut self, access: impl S3Access)              // boxed
pub fn set_route(&mut self, route: impl S3Route)                 // boxed
pub fn set_validation(&mut self, validation: impl NameValidation)
pub fn build(self) -> S3Service                                  // #[must_use]
```
Defaults when unset (`build`, `service.rs:438-451`): config → `Arc::new(StaticConfigProvider::default())`; everything else `None`. There is **no** `base_domain`/`set_host_string` convenience — host is set via an `S3Host` impl (see §6). Everything is stored in `Arc<Inner>`; `S3Service` is `#[derive(Clone)]` and cheap to clone.

Minimal + configured:
```rust
let service = S3ServiceBuilder::new(MyS3).build();

let mut b = S3ServiceBuilder::new(MyS3);
b.set_auth(SimpleAuth::from_single("AK", "SK"));
b.set_host(SingleDomain::new("s3.example.com").unwrap());
let mut cfg = S3Config::default();
cfg.xml_max_body_size = 10 * 1024 * 1024;
b.set_config(Arc::new(StaticConfigProvider::new(Arc::new(cfg))));
let service = b.build();
```

---

## 2. What the built service implements (`service.rs:540-709`)

`S3Service` implements **both** hyper and tower service traits, plus an inherent `call`.

Inherent (used by both impls and callable directly):
```rust
pub async fn call(&self, req: HttpRequest) -> Result<HttpResponse, HttpError>   // service.rs:614
```

hyper (`service.rs:662-674`):
```rust
impl hyper::service::Service<http::Request<hyper::body::Incoming>> for S3Service {
    type Response = HttpResponse;                                   // = http::Response<Body>
    type Error    = HttpError;
    type Future   = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;
    fn call(&self, req: http::Request<hyper::body::Incoming>) -> Self::Future;
}
```

tower — generic over any `http_body::Body` (this is what Axum/tower layers use) (`service.rs:676-709`):
```rust
impl<B> tower::Service<http::Request<B>> for S3Service
where
    B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Response = HttpResponse;
    type Error    = HttpError;
    type Future   = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>>; // always Ready(Ok)
    fn call(&mut self, req: http::Request<B>) -> Self::Future;
}
```

### Hyper wiring (from `https.rs` example + service.rs doctest)
Exact types: `hyper_util::server::conn::auto::Builder as ConnBuilder`, `hyper_util::rt::{TokioExecutor, TokioIo}`, `tokio::net::TcpListener`.
```rust
let service = S3ServiceBuilder::new(MyS3).build();
let listener = TcpListener::bind("127.0.0.1:8014").await?;
let http_server = ConnBuilder::new(TokioExecutor::new());          // HTTP/1+2 autodetect
let graceful = hyper_util::server::graceful::GracefulShutdown::new();
loop {
    let (stream, _) = listener.accept().await?;
    let conn = http_server.serve_connection(TokioIo::new(stream), service.clone());
    let conn = graceful.watch(conn.into_owned());
    tokio::spawn(async move { let _ = conn.await; });
}
```
The `serve_connection(io, service)` accepts `S3Service` directly (its hyper `Service` impl). Clone per-connection (`Arc` inside). HTTPS: wrap `stream` with `tokio_rustls::TlsAcceptor::accept` → `TokioIo::new(tls_stream)` (rest identical; `https.rs:180`).

### Axum/tower wiring (`axum.rs` example)
`S3Service`’s tower impl has `Error = HttpError` (not `Infallible`), so as a `fallback_service` it must be wrapped:
```rust
use axum::error_handling::HandleError;
let s3 = HandleError::new(s3_service, |err: HttpError| async move { /* -> Response<Body> */ });
let app = axum::Router::new().route("/health", get(h)).fallback_service(s3);
axum::serve(listener, app).await?;
```
There is also `examples/tokio_util.rs`: helpers `convert_body(s3s::Body) -> impl AsyncBufRead` and `convert_streaming_blob(s3s::dto::StreamingBlob) -> impl AsyncBufRead` via `tokio_util::io::StreamReader` over `body.into_stream()` — for consuming request bodies as `AsyncRead`.

---

## 3. `S3Config` and providers (`config.rs`)

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]      // missing JSON fields → Default
#[non_exhaustive]      // construct via `S3Config { .., ..Default::default() }`
pub struct S3Config {
    pub xml_max_body_size: usize,                 // 20*1024*1024   (20 MB)
    pub post_object_max_file_size: u64,           // 5*1024*1024*1024 (5 GB)
    pub form_max_field_size: usize,               // 1024*1024      (1 MB)
    pub form_max_fields_size: usize,              // 20*1024*1024   (20 MB)
    pub form_max_parts: usize,                    // 1000
    pub presigned_url_max_skew_time_secs: u32,    // 900            (15 min)
    pub normalize_forward_slash_path: bool,       // false
}
```
Defaults exactly as above (`impl Default`, `config.rs:159-171`). Because it's `#[non_exhaustive]`, external crates must build it with functional-update: `S3Config { xml_max_body_size: N, ..Default::default() }` (mutation-after-`default()` also works, as fields are `pub`).

Provider trait + two impls:
```rust
pub trait S3ConfigProvider: Send + Sync + 'static {
    fn snapshot(&self) -> Arc<S3Config>;          // consistent immutable read
}

pub struct StaticConfigProvider { /* Arc<S3Config> */ }
impl StaticConfigProvider { pub fn new(config: Arc<S3Config>) -> Self; }
impl Default for StaticConfigProvider;            // = S3Config::default()

pub struct HotReloadConfigProvider { /* arc_swap::ArcSwap<S3Config> */ }
impl HotReloadConfigProvider {
    pub fn new(config: Arc<S3Config>) -> Self;
    pub fn update(&self, config: Arc<S3Config>);  // atomic lock-free swap
}
impl Default for HotReloadConfigProvider;
```
**Yes, there is a `HotReloadConfigProvider`** (backed by `arc_swap::ArcSwap`). Attach either via `builder.set_config(Arc::new(provider))` (param type is `Arc<dyn S3ConfigProvider>`). Hold your own `Arc<HotReloadConfigProvider>` clone to call `.update(Arc::new(new_cfg))` at runtime; the live service sees it on the next `snapshot()` (verified: `service.rs:821-843`). Runtime reads happen via `ccx.config.snapshot()` inside the pipeline (e.g. `ops/mod.rs:362,526,627`).

---

## 4. `trait S3` (`s3_trait.rs`) — 99 ops, all defaulted

```rust
//! Auto generated by `s3s_codegen::v1::s3_trait::codegen`
use crate::dto::*;
use crate::error::S3Result;
use crate::protocol::{S3Request, S3Response};

#[async_trait::async_trait]
pub trait S3: Send + Sync + 'static {
    async fn abort_multipart_upload(&self, _req: S3Request<AbortMultipartUploadInput>)
        -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        Err(s3_error!(NotImplemented, "AbortMultipartUpload is not implemented yet"))
    }
    // ... 98 more, identical shape ...
}
```
**Every method has a default impl** returning `Err(s3_error!(NotImplemented, "<Op> is not implemented yet"))`, so `impl S3 for MockS3 {}` compiles (`service.rs:760`). Requires `#[async_trait::async_trait]` on the impl. Count confirmed: 99 `async fn` in the trait.

Exact signatures for the requested five (copied verbatim):
```rust
async fn put_object(&self, _req: S3Request<PutObjectInput>)
    -> S3Result<S3Response<PutObjectOutput>>                         // :6111
async fn get_object(&self, _req: S3Request<GetObjectInput>)
    -> S3Result<S3Response<GetObjectOutput>>                         // :3063
async fn delete_objects(&self, _req: S3Request<DeleteObjectsInput>)
    -> S3Result<S3Response<DeleteObjectsOutput>>                     // :1986
async fn copy_object(&self, _req: S3Request<CopyObjectInput>)
    -> S3Result<S3Response<CopyObjectOutput>>                        // :487
async fn list_objects_v2(&self, _req: S3Request<ListObjectsV2Input>)
    -> S3Result<S3Response<ListObjectsV2Output>>                     // :4301
```
Pattern is invariant: `async fn <op>(&self, req: S3Request<<Op>Input>) -> S3Result<S3Response<<Op>Output>>`. (A few multi-line ops wrap args, e.g. `write_get_object_response`, but the type shape is identical.)

### `S3Request<T>` / `S3Response<T>` (`protocol.rs:78-189`)
```rust
#[derive(Debug, Clone)]
pub struct S3Request<T> {
    pub input: T,
    pub method: http::Method,
    pub uri: http::Uri,
    pub headers: http::HeaderMap,
    pub extensions: http::Extensions,
    pub credentials: Option<s3s::auth::Credentials>,   // None = anonymous
    pub region: Option<s3s::region::Region>,
    pub service: Option<String>,
    pub trailing_headers: Option<TrailingHeaders>,     // SigV4 streaming trailers
}
impl<T> S3Request<T> { pub fn map_input<U>(self, f: impl FnOnce(T)->U) -> S3Request<U>; }

#[derive(Debug, Clone)]
pub struct S3Response<T> {
    pub output: T,
    pub status: Option<http::StatusCode>,   // overrides output-implied status
    pub headers: http::HeaderMap,           // overrides/extends output-implied headers
    pub extensions: http::Extensions,
}
impl<T> S3Response<T> {
    pub fn new(output: T) -> Self;
    pub fn with_status(output: T, status: StatusCode) -> Self;
    pub fn with_headers(output: T, headers: HeaderMap) -> Self;
    pub fn map_output<U>(self, f: impl FnOnce(T)->U) -> S3Response<U>;
}
```
`TrailingHeaders(Arc<Mutex<Option<HeaderMap>>>)` with `is_ready()`, `take() -> Option<HeaderMap>`, `read(|&HeaderMap| R) -> Option<R>` (`protocol.rs:35-75`).

---

## 5. Pipeline order — CONFIRMED, with code pointers

Entry `S3Service::call` (`service.rs:614`) builds `ops::CallContext` and calls `ops::call(&mut req, &ccx)` (`ops/mod.rs:260`). `CallContext` (`ops/mod.rs:64-72`) carries `&Arc<dyn S3>`, `&Arc<dyn S3ConfigProvider>`, and `Option<&dyn _>` for host/auth/access/route/validation.

Order is established across `prepare()` then `call()`:

`prepare()` (`ops/mod.rs:315-632`), in sequence:
1. **Host/path parse** — inject Host from HTTP/2 `:authority`; decode URI; virtual-host vs path-style parse with `NameValidation` + `normalize_forward_slash_path` (`:328-378`).
2. Extract query string + `content_length` (`:380-381`).
3. **SigV4/SigV2 verify** — `SignatureContext { auth, config, ... }.check().await? -> Option<credentials>` (`:390-415`). This is where signatures are validated and `auth.get_secret_key` is consulted; may transform body (chunked/streaming decode) and populate `trailing_headers`/`multipart`.
4. **Region** — derive from verified credential region (authoritative), else fall back to `S3Host` region (`:423-470`).
5. Custom-route match: `route.is_match(method, uri, headers, &mut extensions)` → `Prepare::CustomRoute` short-circuit (`:490-494`).
6. `resolve_route(...) -> (op: &'static dyn Operation, needs_full_body: bool)` (`:496-596`). (POST-object multipart takes a dedicated branch that buffers the file stream under `post_object_max_file_size` **before** this — `:497-565`.)
7. **General `S3Access::check` — no typed input, body not yet buffered**, gated on auth being configured (`:608-622`):
   ```rust
   if ccx.auth.is_some() {
       let mut acx = S3AccessContext { credentials, s3_path, s3_op, method, uri, headers, extensions };
       match ccx.access {
           Some(access) => access.check(&mut acx).await?,
           None          => crate::access::default_check(&mut acx)?,  // denies anon
       }
   }
   ```
8. **Body buffer** — `if needs_full_body { extract_full_body(content_length, &mut req.body, config.xml_max_body_size).await? }` (`:626-629`). Enforces `xml_max_body_size` (→ `MaxMessageLengthExceeded`).
9. Return `Prepare::S3(op)`.

Then `ops::call` runs the op (`:270-280`) → `Operation::call` (generated, e.g. `ops/generated.rs:535-551`):
10. **Deserialize** `input = Self::deserialize_http(req)?`.
11. `s3_req = build_s3_request(input, req)` (moves method/uri/headers/extensions/credentials/region/service/trailing_headers into `S3Request<T>`).
12. **Typed per-op `S3Access` hook** — `if let Some(access) = ccx.access { access.<op>(&mut s3_req).await? }`.
13. **`S3::<op>`** — `s3.<op>(s3_req).await`, then `serialize_http`.

So the claimed chain **sigv4 verify → region → S3Access::check [no body] → body buffer → deserialize → typed S3Access hook → S3::op** is exactly what the code does.

> ⚠️ Two distinct gates (important): the **general `check`** runs only when **auth** is configured (step 7, `ops/mod.rs:608`). The **typed per-op hook** runs whenever **access** is configured — it is **not** gated on auth (step 12, `ops/generated.rs:539`). Setting `set_access` without `set_auth` therefore runs your typed hooks but skips the general `check`/`default_check`.

---

## 6. Supporting traits (for wiring auth/access/host/route)

`S3Auth` (`auth/mod.rs:109-154`):
```rust
#[async_trait::async_trait]
pub trait S3Auth: Send + Sync + 'static {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey>;   // Err(InvalidAccessKeyId) if unknown
}
```
`SimpleAuth` (`auth/simple_auth.rs`): `new()`, `from_single(impl Into<String>, impl Into<SecretKey>)`, `register(String, SecretKey) -> Option<SecretKey>`, `lookup(&str) -> Option<&SecretKey>`.
`Credentials { pub access_key: String, pub secret_key: SecretKey }`; `SecretKey(Box<str>)` (`auth/secret_key.rs:9-15`).

`S3Access` — generated (`access/generated.rs:11+`), `default_check` (`access/mod.rs:112`):
```rust
#[async_trait::async_trait]
pub trait S3Access: Send + Sync + 'static {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> { super::default_check(cx) }
    async fn copy_object(&self, _req: &mut S3Request<CopyObjectInput>) -> S3Result<()> { Ok(()) }
    async fn put_object(&self, _req: &mut S3Request<PutObjectInput>) -> S3Result<()> { Ok(()) }
    // ... one Ok(())-returning method per S3 op ...
}
// default_check: Some(creds) => Ok(()) ; None => Err(s3_error!(AccessDenied, "Signature is required"))
```
`S3AccessContext<'a>` accessors (`access/context.rs`): `credentials() -> Option<&Credentials>`, `s3_path() -> &S3Path`, `s3_op() -> &S3Operation`, `method()`, `uri()`, `headers()`, `extensions_mut() -> &mut Extensions`.

`S3Host` (`host.rs`):
```rust
pub trait S3Host: Send + Sync + 'static {
    fn parse_host_header<'a>(&'a self, host: &'a str) -> S3Result<VirtualHost<'a>>;
}
pub struct SingleDomain; impl SingleDomain { pub fn new(base_domain: &str) -> Result<Self, DomainError>; }   // :171
pub struct MultiDomain;  impl MultiDomain  { pub fn new<I>(base_domains: I) -> Result<Self, DomainError> /* I: IntoIterator<Item=&str> */; } // :212
// VirtualHost<'a>: new(domain), builder .with_bucket(..).with_region(..); accessors domain()/bucket()->Option<&str>/region()->Option<&str>
```

`S3Route` (`route.rs:129-273`):
```rust
#[async_trait::async_trait]
pub trait S3Route: Send + Sync + 'static {
    fn is_match(&self, method: &Method, uri: &Uri, headers: &HeaderMap, extensions: &mut Extensions) -> bool;
    async fn check_access(&self, req: &mut S3Request<Body>) -> S3Result<()> {   // default: deny if no creds
        match req.credentials { Some(_) => Ok(()), None => Err(s3_error!(AccessDenied, "Signature is required")) }
    }
    async fn call(&self, req: S3Request<Body>) -> S3Result<S3Response<Body>>;   // required
}
```
Custom-route dispatch (`ops/mod.rs:281-304`) runs `route.check_access(&mut s3_req).await?` then `route.call(s3_req).await`; the general S3Access step is bypassed for matched routes.

`NameValidation` (`validation`): `fn validate_bucket_name(&self, name: &str) -> bool` (has default returning AWS rules); default impl is `AwsNameValidation::new()` when unset.
