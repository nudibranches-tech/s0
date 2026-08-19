# Substrate API reference — `s3s` 0.14.1, `s3s-aws` 0.14.1, `regorus` 0.10.1

s0 sits on three crates whose APIs are load-bearing for its safety argument, and two of
them are experimental. This is a reference for those APIs, verified against the vendored
source of each pinned version rather than against their published docs.

> **Every `file:line` reference below points into a *dependency's* source tree, not into
> this repository.** A path like `src/dto/mod.rs` means
> `<cargo registry>/s3s-0.14.1/src/dto/mod.rs`. Sections 0–5 are `s3s`, section 6 is
> `s3s-aws`, sections 7 and 9 are `regorus`. Nothing here resolves under s0's own `src/`.

`aws-sdk-s3` signatures are quoted from 1.138.0, which is API-identical to the 1.135.0
that `s3s-aws` pins.

---

## ⚠ Verified claims, and the traps around them

Four assumptions s0's design rests on are **confirmed** against the vendored source, and
are set out below with their evidence. Four *adjacent* facts that no design document
states are load-bearing traps — read "Traps" before writing against these APIs.

### (a) Pipeline order — CONFIRMED

Assumed: `sigv4 header-only verify -> region -> S3Access::check with NO body -> body buffer -> deserialize -> typed hook with full input -> S3::op`.

Evidence — `S3Service::call` (`service.rs:614`) builds `ops::CallContext` (`ops/mod.rs:64-72`: `&Arc<dyn S3>`, `&Arc<dyn S3ConfigProvider>`, `Option<&dyn _>` for host/auth/access/route/validation) and calls `ops::call` (`ops/mod.rs:260`). `prepare()` (`ops/mod.rs:315-632`) then `call()` execute, in order:

1. Host/path parse — inject Host from HTTP/2 `:authority`; decode URI; virtual-host vs path-style parse with `NameValidation` + `normalize_forward_slash_path` (`:328-378`).
2. Extract query string + `content_length` (`:380-381`).
3. **SigV4/SigV2 verify** — `SignatureContext { auth, config, ... }.check().await? -> Option<credentials>` (`:390-415`). Consults `auth.get_secret_key`; may transform the body (aws-chunked/streaming decode wrapper — not buffered) and populate `trailing_headers`/`multipart`.
4. **Region** — from verified credential region (authoritative), else `S3Host` fallback (`:423-470`).
5. Custom-route match: `route.is_match(...)` → `Prepare::CustomRoute` short-circuit (`:490-494`).
6. `resolve_route(...) -> (op: &'static dyn Operation, needs_full_body: bool)` (`:496-596`). PostObject multipart takes a dedicated branch that buffers the file stream under `post_object_max_file_size` **before** this returns (`:497-565`).
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
8. **Body buffer** — `if needs_full_body { extract_full_body(content_length, &mut req.body, config.xml_max_body_size).await? }` (`:626-629`); overflow → `MaxMessageLengthExceeded`.
9. Return `Prepare::S3(op)`; `ops::call` (`:270-280`) → generated `Operation::call` (e.g. `ops/generated.rs:535-551`):
10. **Deserialize** `input = Self::deserialize_http(req)?`.
11. `s3_req = build_s3_request(input, req)` (moves method/uri/headers/extensions/credentials/region/service/trailing_headers into `S3Request<T>`).
12. **Typed per-op `S3Access` hook** — `if let Some(access) = ccx.access { access.<op>(&mut s3_req).await? }` (`ops/generated.rs:539`).
13. **`S3::<op>`** — `s3.<op>(s3_req).await`, then `serialize_http`.

Precision on "header-only": recon confirms signature verification completes before the body-buffer step (step 8) and `S3AccessContext` has no body field at all; streaming/chunked payload verification is attached as a lazy body transform, not performed in step 3.

### (b) `S3Access::check` signature — CONFIRMED

Claimed: `check(&mut S3AccessContext) -> S3Result<()>`. Exact source form (`access/generated.rs:11`, `#[async_trait::async_trait]`):

```rust
async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
    super::default_check(cx)
}
```

Matches modulo the elided `&self` / `async` / `'_` lifetime. Note it is a **defaulted** method, and the default is **fail-CLOSED for anonymous**: `default_check` (`access/mod.rs:112`) returns `Ok(())` for any `Some(credentials)` and `Err(s3_error!(AccessDenied, "Signature is required"))` for `None`.

### (c) All 99 typed per-op hooks default to `Ok(())` / fail-OPEN — CONFIRMED

`access/generated.rs` (791 lines, codegen header) contains exactly **100 `async fn`** = 1 `check` + **99 typed hooks**; **198 occurrences of `Ok(())`** = 99 × (1 doc line + 1 body). Every hook body is literally `Ok(())`. Shape (async-trait `async fn`, not bare `impl Future`):

```rust
async fn copy_object(&self, _req: &mut S3Request<CopyObjectInput>) -> S3Result<()> { Ok(()) }
```

### (d) `s3s_aws::Proxy` wraps exactly one client — CONFIRMED

`s3s-aws-0.14.1/src/proxy/mod.rs:9-15` (entire file):

```rust
pub struct Proxy(aws_sdk_s3::Client);

impl From<aws_sdk_s3::Client> for Proxy {
    fn from(value: aws_sdk_s3::Client) -> Self {
        Self(value)
    }
}
```

Single private tuple field; the **only** constructor is `From<aws_sdk_s3::Client>` (no `new`); the inner client cannot be extracted. One `Proxy` == one client == correct unit per (backend, tenant).

### Traps — true facts the the design requirements omits

1. **The general `check` runs ONLY when an auth provider is set** (`ops/mod.rs:608`, module docs `access/mod.rs:19-29`). `set_access` without `set_auth` ⇒ `check`/`default_check` are **silently skipped**. The gateway MUST call both `set_auth` and `set_access`.
2. **Typed per-op hooks are NOT gated on auth** — they run whenever access is configured (`ops/generated.rs:539`). So with access-only wiring you get hooks but no general gate; with both, you get both.
3. **Fail-direction asymmetry**: `check` default is fail-CLOSED (denies anonymous only — allows *any* authenticated principal); the 99 typed hooks are fail-OPEN. Deny-by-default requires overriding `check` AND treating every un-overridden typed hook as an implicit allow.
4. **PostObject**: (i) its multipart form/file is buffered *before* the general `check` (`ops/mod.rs:497-565`), so "check with NO body" does not hold for POST form uploads; (ii) **`s3s_aws::Proxy` does not implement `post_object`** — re-verified during consolidation by diffing `async fn` names between `s3s_trait.rs` (99) and `proxy/generated.rs` (98): the single missing op is `post_object`, which falls back to the `S3` trait default `Err(s3_error!(NotImplemented, ...))`. POST form uploads will 501 through the proxy unless handled separately (in-crate `pub(crate)` converters `post_object_input_into_put_object_input` exist at `dto/generated.rs:37904/37952` but are **not public**).
5. **Custom `S3Route` matches bypass `S3Access` entirely** (`ops/mod.rs:281-304`) — they get `route.check_access` (default: deny-anon) instead.

Minor recon correction, resolved from source: `S3Operation`'s `name` field is `pub(crate)`, **not** `pub` — external code must use the `.name()` method (see §2.5).

---

## 0. Canonical imports

```rust
// s3s
use s3s::{S3, S3Request, S3Response, S3Result, S3Error, S3ErrorCode, S3Operation, Body};
use s3s::{HttpRequest, HttpResponse, HttpError, TrailingHeaders};
use s3s::s3_error;                              // #[macro_export] at crate root
use s3s::auth::{S3Auth, SecretKey, Credentials, SimpleAuth};
use s3s::access::{S3Access, S3AccessContext};
use s3s::service::{S3Service, S3ServiceBuilder};
use s3s::config::{S3Config, S3ConfigProvider, StaticConfigProvider, HotReloadConfigProvider};
use s3s::host::{S3Host, SingleDomain, MultiDomain, VirtualHost, DomainError};
use s3s::route::S3Route;
use s3s::validation::{NameValidation, AwsNameValidation};
use s3s::path::S3Path;
use s3s::header::{X_AMZ_ID_2, X_AMZ_REQUEST_ID};    // header-name constants module
use s3s::dto::*;                                     // all *Input/*Output, CopySource, aliases

// s3s-aws
use s3s_aws::Proxy;                                  // lib.rs:22
use s3s_aws::conv::{AwsConversion, try_from_aws, try_into_aws}; // pub mod (lib.rs:16)
use s3s_aws::{Client, Connector};                    // reverse adapter (lib.rs:19)

// regorus
use regorus::{Engine, Value};                        // lib.rs:169,180
```

Aliases: `HttpRequest<B = Body> = http::Request<B>`, `HttpResponse<B = Body> = http::Response<B>` (`protocol.rs:14-15`). `Body` is `s3s::http::Body` re-exported (`http/body.rs:23`). `Region` on `S3Request` is `s3s::region::Region` (further API not captured by recon). `S3Result<T = (), E = S3Error> = std::result::Result<T, E>` (`error/mod.rs:33` — note defaults).

---

## 1. Auth

### 1.1 `trait S3Auth` (`auth/mod.rs:109`) — one required method, no default

```rust
#[async_trait::async_trait]
pub trait S3Auth: Send + Sync + 'static {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey>;
}
```

- Stored as `Box<dyn S3Auth>`; dyn-dispatched via async-trait.
- Pure `access_key -> SecretKey` lookup — it never sees the operation. Presign/anonymous decisions happen in the signature layer and surface downstream as `Option<Credentials>` on `S3Request` / `S3AccessContext`.
- Convention: unknown key → `Err(s3_error!(InvalidAccessKeyId))` (`SimpleAuth` uses `NotSignedUp` instead).

### 1.2 `SecretKey` (`auth/secret_key.rs:14`)

```rust
#[derive(Clone)]
pub struct SecretKey(Box<str>);          // inner field private

impl SecretKey {
    fn new(s: impl Into<Box<str>>) -> Self;   // private
    #[must_use] pub fn expose(&self) -> &str; // ONLY accessor
}
```

Trait impls: `Zeroize`; `Drop` (zeroize-on-drop); `ConstantTimeEq` (`ct_eq(&self, &Self) -> subtle::Choice`); `From<String>`, `From<Box<str>>`, `From<&str>`; custom `Debug` (redacts to `"[SENSITIVE-SECRET-KEY]"`); `Deserialize` (real, reads a `String`); `Serialize` (redacts). **No `PartialEq`/`Eq`/`Hash`** — compare only via `ConstantTimeEq`.

### 1.3 `Credentials` (`auth/secret_key.rs:8`)

```rust
#[derive(Debug, Clone)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: SecretKey,
}
```

Both fields public; derived `Debug` is safe (secret redacted). No `Serialize`/`Deserialize` on `Credentials` itself.

### 1.4 `SimpleAuth` (`auth/simple_auth.rs`) — reference in-memory impl

```rust
#[derive(Debug, Default)]
pub struct SimpleAuth { map: HashMap<String, SecretKey> }

impl SimpleAuth {
    #[must_use] pub fn new() -> Self;
    #[must_use] pub fn from_single(access_key: impl Into<String>, secret_key: impl Into<SecretKey>) -> Self;
    pub fn register(&mut self, access_key: String, secret_key: SecretKey) -> Option<SecretKey>;
    #[must_use] pub fn lookup(&self, access_key: &str) -> Option<&SecretKey>;
}
// get_secret_key: miss => Err(s3_error!(NotSignedUp, "Your account is not signed up")); hit => Ok(clone)
```

---

## 2. Access

### 2.1 `trait S3Access` (`access/generated.rs:11`) — codegen, `check` + 99 typed hooks

```rust
#[async_trait::async_trait]
pub trait S3Access: Send + Sync + 'static {
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        super::default_check(cx)
    }
    // ... 99 typed per-op hooks, one per S3 op, all defaulting to Ok(()) ...
}
```

Stored as `Box<dyn S3Access>`. `check` is the general gate, invoked **before** op-input deserialization (pipeline step 7) and only when auth is configured.

### 2.2 `default_check` (`access/mod.rs:112`) — fail-CLOSED for anonymous

```rust
pub(crate) fn default_check(cx: &mut S3AccessContext<'_>) -> S3Result<()> {
    match cx.credentials() {
        Some(_) => Ok(()),
        None => Err(s3_error!(AccessDenied, "Signature is required")),
    }
}
```

`pub(crate)` — not callable from your crate; replicate its two-liner if you need the same behavior inside an override.

### 2.3 `S3AccessContext<'a>` (`access/context.rs:10`) — fields `pub(crate)`, use accessors

```rust
pub struct S3AccessContext<'a> {
    pub(crate) credentials: Option<&'a Credentials>,
    pub(crate) s3_path:    &'a S3Path,
    pub(crate) s3_op:      &'a S3Operation,
    pub(crate) method:     &'a Method,          // hyper::Method
    pub(crate) uri:        &'a Uri,             // hyper::Uri
    pub(crate) headers:    &'a HeaderMap,       // hyper::HeaderMap
    pub(crate) extensions: &'a mut Extensions,  // hyper::http::Extensions
}
```

Accessors (all `#[must_use]`):

```rust
pub fn credentials(&self)        -> Option<&Credentials>   // None == anonymous
pub fn s3_path(&self)            -> &S3Path
pub fn s3_op(&self)              -> &S3Operation
pub fn method(&self)             -> &Method
pub fn uri(&self)                -> &Uri
pub fn headers(&self)            -> &HeaderMap
pub fn extensions_mut(&mut self) -> &mut Extensions        // ONLY mutable accessor; no shared extensions()
```

No public constructor; borrows the request (`&'a`), no body field. Use `extensions_mut()` to stash per-request state (e.g. a policy decision) for later stages.

### 2.4 `S3Path` (`path.rs:14-110`) — re-verified from source during consolidation

```rust
#[derive(Debug, PartialEq, Eq)]
pub enum S3Path {
    Root,
    Bucket { bucket: Box<str> },
    Object { bucket: Box<str>, key: Box<str> },
}

impl S3Path {
    #[must_use] pub fn root() -> Self;
    #[must_use] pub fn bucket(bucket: &str) -> Self;
    #[must_use] pub fn object(bucket: &str, key: &str) -> Self;
    #[must_use] pub fn is_root(&self) -> bool;
    #[must_use] pub fn as_bucket(&self) -> Option<&str>;            // Bucket only
    #[must_use] pub fn as_object(&self) -> Option<(&str, &str)>;    // Object only -> (bucket, key)
    #[must_use] pub fn get_bucket_name(&self) -> Option<&str>;      // Bucket | Object
    #[must_use] pub fn get_object_key(&self) -> Option<&str>;      // Object only
}

pub enum ParseS3PathError { InvalidPath, InvalidBucketName, KeyTooLong }  // path.rs:33, thiserror
#[must_use] pub fn check_bucket_name(name: &str) -> bool;                 // path.rs:115
```

### 2.5 `S3Operation` (`s3_op.rs:1-19`) — re-verified from source during consolidation

```rust
pub struct S3Operation {
    pub(crate) name: &'static str,   // NOT pub — you cannot read the field directly
}

impl S3Operation {
    #[must_use] pub fn name(&self) -> &str;   // e.g. "GetObject", "ListObjectsV2"
}
```

Use `cx.s3_op().name()` and match on the AWS PascalCase op name.

### 2.6 Typed per-op hooks — 99 methods, all `Ok(())`

Shape (async-trait `async fn`; method name = snake_case op; type param = `dto::{Op}Input`):

```rust
/// Checks whether the CopyObject request has accesses to the resources.
/// This method returns `Ok(())` by default.
async fn copy_object(&self, _req: &mut S3Request<CopyObjectInput>) -> S3Result<()> {
    Ok(())
}
```

The eight gateway-critical hooks (all identical shape, `access/generated.rs` line refs):

```rust
async fn copy_object(&self, _req: &mut S3Request<CopyObjectInput>) -> S3Result<()> { Ok(()) }        // :47
async fn delete_object(&self, _req: &mut S3Request<DeleteObjectInput>) -> S3Result<()> { Ok(()) }    // :198
async fn delete_objects(&self, _req: &mut S3Request<DeleteObjectsInput>) -> S3Result<()> { Ok(()) }  // :212
async fn get_object(&self, _req: &mut S3Request<GetObjectInput>) -> S3Result<()> { Ok(()) }          // :394
async fn head_object(&self, _req: &mut S3Request<HeadObjectInput>) -> S3Result<()> { Ok(()) }        // :464
async fn list_objects_v2(&self, _req: &mut S3Request<ListObjectsV2Input>) -> S3Result<()> { Ok(()) } // :546
async fn post_object(&self, _req: &mut S3Request<PostObjectInput>) -> S3Result<()> { Ok(()) }        // :560
async fn put_object(&self, _req: &mut S3Request<PutObjectInput>) -> S3Result<()> { Ok(()) }          // :711
```

Semantics:
- Hooks run **post-deserialization** (pipeline step 12) with `&mut S3Request<{Op}Input>` — they can **mutate the input in place** (this is where key/prefix rewrites happen) and read `req.credentials`, `req.headers`, `req.extensions`.
- `check` runs **pre-deserialization** with `&mut S3AccessContext` — has `s3_op()`/`s3_path()`/`headers()`/`uri()` but no typed input and no body.

### 2.7 Enforcement matrix

| Wiring | General `check` | Typed hooks |
|---|---|---|
| `set_auth` + `set_access` | runs (your override or `default_check` fallback) | run |
| `set_auth` only | runs (`default_check`: deny anon) | skipped (no access provider) |
| `set_access` only | **SKIPPED entirely** | run |
| Custom `S3Route` matched | bypassed — `route.check_access` instead | bypassed |

---

## 3. Core protocol and error types

### 3.1 `S3Request<T>` (`protocol.rs:79`) — all fields `pub`, owned

```rust
#[derive(Debug, Clone)]
pub struct S3Request<T> {
    pub input: T,
    pub method: Method,                       // http::Method
    pub uri: Uri,                             // http::Uri
    pub headers: HeaderMap,                   // http::HeaderMap
    pub extensions: Extensions,               // http::Extensions
    pub credentials: Option<Credentials>,     // None == anonymous
    pub region: Option<Region>,               // s3s::region::Region
    pub service: Option<String>,
    pub trailing_headers: Option<TrailingHeaders>,  // SigV4 streaming trailers
}
impl<T> S3Request<T> {
    pub fn map_input<U>(self, f: impl FnOnce(T) -> U) -> S3Request<U>;
}
```

### 3.2 `S3Response<T>` (`protocol.rs:132`)

```rust
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
    pub fn map_output<U>(self, f: impl FnOnce(T) -> U) -> S3Response<U>;
}
```

### 3.3 `TrailingHeaders` (`protocol.rs:35-75`)

`TrailingHeaders(Arc<Mutex<Option<HeaderMap>>>)` with `is_ready()`, `take() -> Option<HeaderMap>`, `read(|&HeaderMap| R) -> Option<R>`.

### 3.4 Errors (`error/mod.rs`)

```rust
pub type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;   // :31
pub type S3Result<T = (), E = S3Error> = std::result::Result<T, E>;       // :33

#[derive(Debug, thiserror::Error)]
pub struct S3Error(Box<Inner>);                                           // :36 (Inner private)
// Inner { code: S3ErrorCode, message: Option<Cow<'static, str>>, request_id,
//         status_code: Option<StatusCode>, source: Option<StdError>, headers: Option<HeaderMap> }
```

`S3Error` API:

```rust
pub fn new(code: S3ErrorCode) -> Self;
pub fn with_message(code: S3ErrorCode, msg: impl Into<Cow<'static, str>>) -> Self;
pub fn with_message_fmt(code: S3ErrorCode, args: fmt::Arguments<'_>) -> Self;  // #[doc(hidden)], macro use
pub fn with_source(code: S3ErrorCode, source: StdError) -> Self;
pub fn internal_error<E: Error + Send + Sync + 'static>(source: E) -> Self;    // -> InternalError
pub fn set_code / set_message / set_request_id / set_source / set_status_code / set_headers(&mut self, ...);
pub fn code(&self) -> &S3ErrorCode;
pub fn message(&self) -> Option<&str>;
pub fn request_id(&self) -> Option<&str>;
pub fn source(&self) -> Option<&(dyn Error + Send + Sync + 'static)>;
pub fn status_code(&self) -> Option<StatusCode>;   // falls back to code.status_code()
pub fn headers(&self) -> Option<&HeaderMap>;
pub fn to_http_response(self) -> S3Result<HttpResponse>;
```

`S3ErrorCode` (`error/generated.rs:251`): enum with a `Custom(_)` variant; `as_str()`, `FromStr` (Infallible), `from_bytes`. Codes used across this doc: `AccessDenied`, `InvalidAccessKeyId`, `NotSignedUp`, `InternalError`, `NotImplemented`, `MaxMessageLengthExceeded`.

### 3.5 `s3_error!` macro (`error/mod.rs:221`, `#[macro_export]`)

```rust
s3_error!(Code)                     // => S3Error::new(S3ErrorCode::Code)
s3_error!(Code, "fmt {}", x)        // => S3Error::with_message_fmt(S3ErrorCode::Code, format_args!(...))
s3_error!(source_expr, Code)        // => above + err.set_source(Box::new(source_expr))
s3_error!(source_expr, Code, "...") // => message form + set_source
```

Codes are bare idents resolved as `$crate::S3ErrorCode::$code`.

---

## 4. DTOs (`s3s::dto`)

### 4.1 Module layout and re-exports (`src/dto/mod.rs`)

```rust
pub use self::generated::*;      // line 19 — all *Input/*Output, ObjectIdentifier, Delete, aliases
mod copy_source;                 // line 27
pub use self::copy_source::*;    // line 28 — CopySource, ParseCopySourceError
pub type List<T> = Vec<T>;       // line 51
```

All `*Input` structs have plain `pub` fields (no `#[non_exhaustive]`), freely mutable in place.

### 4.2 Type aliases (keys/prefixes are plain `String`; lists are `Vec`)

| Alias | Definition | `generated.rs` line |
|---|---|---|
| `BucketName` | `= String` | 833 |
| `ObjectKey` | `= String` | 14329 |
| `ObjectVersionId` | `= String` | 14840 |
| `Prefix` | `= String` | 16038 |
| `Delimiter` | `= String` | 5085 |
| `Token` | `= String` (continuation_token) | 20720 |
| `StartAfter` | `= String` | 20338 |
| `Marker` | `= String` (v1 pagination) | 13511 |
| `NextToken` | `= String` | 13868 |
| `MaxKeys` | `= i32` | 13519 |
| `KeyCount` | `= i32` | 11514 |
| `AccountId` | `= String` | 192 |
| `Quiet` | `= bool` | 18531 |
| `FetchOwner` | `= bool` | 7506 |
| `ObjectIdentifierList` | `= List<ObjectIdentifier>` = `Vec<ObjectIdentifier>` | 14327 |
| `OptionalObjectAttributesList` | `= List<OptionalObjectAttributes>` | 14916 |

### 4.3 DeleteObjects — multi-delete keys path: `input.delete.objects[i].key`

`delete` is **required (non-Option)**; `objects` is a **non-Option `Vec`**; `key` is a **non-Option `String`**.

```rust
// generated.rs:4851
pub struct DeleteObjectsInput {
    pub bucket: BucketName,                                   // :4870 (String, required)
    pub bypass_governance_retention: Option<BypassGovernanceRetention>,
    pub checksum_algorithm: Option<ChecksumAlgorithm>,
    pub delete: Delete,                                       // :4922 (required, NOT Option)
    pub expected_bucket_owner: Option<AccountId>,
    // ... mfa, request_payer elided (not authz-relevant)
}

// generated.rs:3954
pub struct Delete {
    pub objects: ObjectIdentifierList,   // :3963  Vec<ObjectIdentifier>, required
    pub quiet: Option<Quiet>,            // :3966  Option<bool>
}

// generated.rs:14275
pub struct ObjectIdentifier {
    pub e_tag: Option<ETag>,                          // :14281
    pub key: ObjectKey,                               // :14288  String, required
    pub last_modified_time: Option<LastModifiedTime>, // :14294
    pub size: Option<Size>,                           // :14299
    pub version_id: Option<ObjectVersionId>,          // :14304  Option<String>
}
```

Rewrite loop: `for oid in &mut input.delete.objects { oid.key = rewrite(&oid.key); }`

### 4.4 CopyObject — source is a **parsed enum**, not a raw string

```rust
// generated.rs:1848
pub struct CopyObjectInput {
    pub bucket: BucketName,        // :1903  dest bucket (String, required)
    pub copy_source: CopySource,   // :2003  source (parsed enum, required)
    pub key: ObjectKey,            // :2154  dest key (String, required)
    // ... acl, metadata, tagging, sse_*, etc. elided
}
```

`CopySource` (`dto/copy_source.rs:20`) — all fields `Box<str>`:

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum CopySource {
    Bucket {
        bucket: Box<str>,
        key: Box<str>,
        version_id: Option<Box<str>>,
    },
    AccessPoint {
        partition: Box<str>, region: Box<str>, account_id: Box<str>,
        access_point_name: Box<str>, key: Box<str>, version_id: Option<Box<str>>,
    },
    Outpost {
        partition: Box<str>, region: Box<str>, account_id: Box<str>,
        outpost_id: Box<str>, key: Box<str>, version_id: Option<Box<str>>,
    },
}

impl CopySource {
    pub fn parse(header: &str) -> Result<Self, ParseCopySourceError>;      // :263
    #[must_use] pub fn format_to_string(&self) -> String;                  // :295 — re-emit header value
}
impl http::TryFromHeaderValue for CopySource {                             // :349
    type Error = ParseCopySourceError;
    fn try_from_header_value(val: &http::HeaderValue) -> Result<Self, Self::Error>;
}

// copy_source.rs:64
pub enum ParseCopySourceError {
    PatternMismatch, InvalidBucketName, InvalidKey, InvalidEncoding,
    InvalidArn, InvalidAccessPointName, InvalidAccountId,
}
```

Only `CopySource::Bucket` carries a bare source `bucket`; `AccessPoint`/`Outpost` carry an ARN identity (no plain bucket). For authz you must match on the variant. To rewrite, rebuild the variant (fields are `Box<str>` — `rewritten.into()`), then `format_to_string()` regenerates the `x-amz-copy-source` value if needed.

### 4.5 ListObjectsV2 / ListObjects (v1) — prefix rewrite + re-pagination

```rust
// generated.rs:12807 — FULL field list
pub struct ListObjectsV2Input {
    pub bucket: BucketName,                                       // String, required
    pub continuation_token: Option<Token>,                        // Option<String>
    pub delimiter: Option<Delimiter>,                             // Option<String>
    pub encoding_type: Option<EncodingType>,
    pub expected_bucket_owner: Option<AccountId>,
    pub fetch_owner: Option<FetchOwner>,                          // Option<bool>
    pub max_keys: Option<MaxKeys>,                                // Option<i32>
    pub optional_object_attributes: Option<OptionalObjectAttributesList>,
    pub prefix: Option<Prefix>,                                   // Option<String>
    pub request_payer: Option<RequestPayer>,
    pub start_after: Option<StartAfter>,                          // Option<String>
}
```

`ListObjectsV2Output` (re-pagination surface): `pub next_continuation_token: Option<NextToken>`, `pub is_truncated: Option<IsTruncated>`, `pub key_count: Option<KeyCount>`, `pub contents: Option<ObjectList>`, `pub common_prefixes: Option<CommonPrefixList>`, plus echoed `prefix`/`delimiter`/`start_after`/`continuation_token`.

```rust
// generated.rs:12618 — FULL field list
pub struct ListObjectsInput {
    pub bucket: BucketName,                    // String, required
    pub delimiter: Option<Delimiter>,          // Option<String>
    pub encoding_type: Option<EncodingType>,
    pub expected_bucket_owner: Option<AccountId>,
    pub marker: Option<Marker>,                // Option<String>  (v1 cursor)
    pub max_keys: Option<MaxKeys>,             // Option<i32>
    pub optional_object_attributes: Option<OptionalObjectAttributesList>,
    pub prefix: Option<Prefix>,                // Option<String>
    pub request_payer: Option<RequestPayer>,
}
```

v1 output cursor: `pub next_marker: Option<NextMarker>` — only populated when a `delimiter` is set.

### 4.6 GetObject / PutObject / HeadObject — `bucket`/`key` are required `String`s

```rust
// generated.rs:9022
pub struct GetObjectInput {
    pub bucket: BucketName,   // :9043
    pub key: ObjectKey,       // :9082
    // ... range, version_id: Option<ObjectVersionId>, part_number, sse_*, etc.
}

// generated.rs:17433
pub struct PutObjectInput {
    pub bucket: BucketName,   // :17482
    pub key: ObjectKey,       // :17670
    // ... body: Option<StreamingBlob>, metadata, content_*, sse_*, tagging, etc.
}

// generated.rs:10124
pub struct HeadObjectInput {
    pub bucket: BucketName,   // :10143
    pub key: ObjectKey,       // :10229
    // ... range, version_id, part_number, etc.
}
```

Rewrite: `input.key = rewrite(&input.key);` (owned `String`).

### 4.7 PostObject — synthetic op, separate hook required

`generated.rs:37902`: "`PostObject` is a synthetic API in s3s" (not a real AWS SDK op); extra fields for POST behavior (`success_action_redirect`, `success_action_status`).

```rust
// generated.rs:15331
pub struct PostObjectInput {
    pub bucket: BucketName,   // :15380  String, required
    // ... bucket_key_enabled, if_none_match, ...
    pub key: ObjectKey,       // :15568  String, required  <-- form-upload key lives here
    pub metadata: Option<Metadata>,
    // ... success_action_redirect / success_action_status (POST-only)
}
```

Hand-written `Debug` (`:15737`). In-crate conversions are `pub(crate)` only (`:37904` / `:37952`) — not usable externally. A hook covering only `put_object` **misses** form uploads; gate `post_object` separately. (And recall: `s3s_aws::Proxy` does not implement `post_object` — see Traps.)

### 4.8 Rewrite cheat-sheet

| Op | Field path | Type | Mutability |
|---|---|---|---|
| GetObject / PutObject / HeadObject / PostObject | `input.key` | `String` | `input.key = ...` |
| DeleteObjects | `input.delete.objects[i].key` | `String` in `Vec` | iterate `&mut`, set `.key` |
| CopyObject (dest) | `input.key` | `String` | `input.key = ...` |
| CopyObject (source) | `input.copy_source` variant `bucket`/`key` | `Box<str>` in enum | rebuild variant; `format_to_string()` re-emits header |
| ListObjectsV2 | `input.prefix` / `.start_after` / `.continuation_token` / `.delimiter` | `Option<String>` | `input.prefix = Some(...)` |
| ListObjects v1 | `input.prefix` / `.marker` / `.delimiter` | `Option<String>` | same |

Bucket fields are required `String` on every op above **except** the `CopySource::AccessPoint`/`Outpost` variants (ARN identity, no bare bucket).

---

## 5. Service, config, and server wiring

### 5.1 `S3ServiceBuilder` (`service.rs:120-452`)

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

impl S3ServiceBuilder {
    pub fn new(s3: impl S3) -> Self;                                  // s3 boxed into Arc<dyn S3>
    pub fn set_config(&mut self, config: Arc<dyn S3ConfigProvider>);  // NOTE: Arc<dyn ...>, not impl
    pub fn set_host(&mut self, host: impl S3Host);                    // boxed
    pub fn set_auth(&mut self, auth: impl S3Auth);                    // boxed          (:267)
    pub fn set_access(&mut self, access: impl S3Access);              // boxed          (:326)
    pub fn set_route(&mut self, route: impl S3Route);                 // boxed
    pub fn set_validation(&mut self, validation: impl NameValidation);
    #[must_use] pub fn build(self) -> S3Service;
}
```

Defaults when unset (`build`, `service.rs:438-451`): config → `Arc::new(StaticConfigProvider::default())`; everything else `None`. There is **no** string-based host convenience — use an `S3Host` impl (§5.6). `S3Service` stores everything in `Arc<Inner>`, is `#[derive(Clone)]`, cheap to clone.

### 5.2 `S3Service` — what it implements (`service.rs:540-709`)

Inherent:

```rust
pub async fn call(&self, req: HttpRequest) -> Result<HttpResponse, HttpError>;   // service.rs:614
```

hyper (`service.rs:662-674`):

```rust
impl hyper::service::Service<http::Request<hyper::body::Incoming>> for S3Service {
    type Response = HttpResponse;    // = http::Response<Body>
    type Error    = HttpError;
    type Future   = futures::future::BoxFuture<'static, Result<Self::Response, Self::Error>>;
    fn call(&self, req: http::Request<hyper::body::Incoming>) -> Self::Future;
}
```

tower — generic over any `http_body::Body` (what Axum/tower layers use) (`service.rs:676-709`):

```rust
impl<B> tower::Service<http::Request<B>> for S3Service
where
    B: http_body::Body<Data = bytes::Bytes> + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    type Response = HttpResponse;
    type Error    = HttpError;
    type Future   = BoxFuture<'static, Result<Self::Response, Self::Error>>;
    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>>;  // always Ready(Ok)
    fn call(&mut self, req: http::Request<B>) -> Self::Future;
}
```

### 5.3 Server wiring

hyper (exact types: `hyper_util::server::conn::auto::Builder as ConnBuilder`, `hyper_util::rt::{TokioExecutor, TokioIo}`, `tokio::net::TcpListener`):

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

HTTPS: wrap `stream` with `tokio_rustls::TlsAcceptor::accept` → `TokioIo::new(tls_stream)`; rest identical (`examples/https.rs:180`).

Axum/tower: `S3Service`'s tower `Error = HttpError` (not `Infallible`), so wrap for `fallback_service`:

```rust
use axum::error_handling::HandleError;
let s3 = HandleError::new(s3_service, |err: HttpError| async move { /* -> Response<Body> */ });
let app = axum::Router::new().route("/health", get(h)).fallback_service(s3);
axum::serve(listener, app).await?;
```

Body helpers (`examples/tokio_util.rs`): `convert_body(s3s::Body) -> impl AsyncBufRead` and `convert_streaming_blob(s3s::dto::StreamingBlob) -> impl AsyncBufRead` via `tokio_util::io::StreamReader` over `body.into_stream()`.

### 5.4 `S3Config` + providers (`config.rs`)

```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]      // missing JSON fields -> Default
#[non_exhaustive]      // external construction: S3Config { field: v, ..Default::default() }
pub struct S3Config {
    pub xml_max_body_size: usize,                 // default 20*1024*1024      (20 MB)
    pub post_object_max_file_size: u64,           // default 5*1024*1024*1024  (5 GB)
    pub form_max_field_size: usize,               // default 1024*1024         (1 MB)
    pub form_max_fields_size: usize,              // default 20*1024*1024      (20 MB)
    pub form_max_parts: usize,                    // default 1000
    pub presigned_url_max_skew_time_secs: u32,    // default 900               (15 min)
    pub normalize_forward_slash_path: bool,       // default false
}
// impl Default: config.rs:159-171
```

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

Attach via `builder.set_config(Arc::new(provider))`. Keep your own `Arc<HotReloadConfigProvider>` clone; `.update(Arc::new(new_cfg))` is visible on the next `snapshot()` (verified `service.rs:821-843`; runtime reads at `ops/mod.rs:362,526,627`).

### 5.5 `trait S3` (`s3_trait.rs`) — 99 ops, all defaulted to `NotImplemented`

```rust
#[async_trait::async_trait]
pub trait S3: Send + Sync + 'static {
    async fn abort_multipart_upload(&self, _req: S3Request<AbortMultipartUploadInput>)
        -> S3Result<S3Response<AbortMultipartUploadOutput>> {
        Err(s3_error!(NotImplemented, "AbortMultipartUpload is not implemented yet"))
    }
    // ... 98 more, identical shape ...
}
```

Every method has a default impl returning `Err(s3_error!(NotImplemented, "<Op> is not implemented yet"))`, so `impl S3 for MockS3 {}` compiles (`service.rs:760`). Impls need `#[async_trait::async_trait]`. Invariant pattern: `async fn <op>(&self, req: S3Request<<Op>Input>) -> S3Result<S3Response<<Op>Output>>`. Verbatim key ops:

```rust
async fn copy_object(&self, _req: S3Request<CopyObjectInput>)
    -> S3Result<S3Response<CopyObjectOutput>>;                       // :487
async fn delete_objects(&self, _req: S3Request<DeleteObjectsInput>)
    -> S3Result<S3Response<DeleteObjectsOutput>>;                    // :1986
async fn get_object(&self, _req: S3Request<GetObjectInput>)
    -> S3Result<S3Response<GetObjectOutput>>;                        // :3063
async fn list_objects_v2(&self, _req: S3Request<ListObjectsV2Input>)
    -> S3Result<S3Response<ListObjectsV2Output>>;                    // :4301
async fn put_object(&self, _req: S3Request<PutObjectInput>)
    -> S3Result<S3Response<PutObjectOutput>>;                        // :6111
```

### 5.6 `S3Host` / `S3Route` / `NameValidation`

```rust
// host.rs
pub trait S3Host: Send + Sync + 'static {
    fn parse_host_header<'a>(&'a self, host: &'a str) -> S3Result<VirtualHost<'a>>;
}
pub struct SingleDomain; impl SingleDomain { pub fn new(base_domain: &str) -> Result<Self, DomainError>; }  // :171
pub struct MultiDomain;  impl MultiDomain  { pub fn new<I>(base_domains: I) -> Result<Self, DomainError>; } // :212  I: IntoIterator<Item = &str>
// VirtualHost<'a>: new(domain), builder .with_bucket(..)/.with_region(..);
// accessors: domain(), bucket() -> Option<&str>, region() -> Option<&str>
```

```rust
// route.rs:129-273
#[async_trait::async_trait]
pub trait S3Route: Send + Sync + 'static {
    fn is_match(&self, method: &Method, uri: &Uri, headers: &HeaderMap, extensions: &mut Extensions) -> bool;
    async fn check_access(&self, req: &mut S3Request<Body>) -> S3Result<()> {   // default: deny anon
        match req.credentials { Some(_) => Ok(()), None => Err(s3_error!(AccessDenied, "Signature is required")) }
    }
    async fn call(&self, req: S3Request<Body>) -> S3Result<S3Response<Body>>;   // required
}
```

Matched routes run `route.check_access(&mut s3_req).await?` then `route.call(s3_req).await` (`ops/mod.rs:281-304`) — the general `S3Access` step is bypassed.

`NameValidation`: `fn validate_bucket_name(&self, name: &str) -> bool` (defaulted to AWS rules); when unset the service uses `AwsNameValidation::new()`.

---

## 6. s3s-aws 0.14.1 — `Proxy`, conversions, aws client

Crate `s3s_aws`. Pinned deps: `aws-sdk-s3 = 1.135.0` (default-features **off**; features `http-1x`, `rt-tokio`, `sigv4a`, `default-https-client` — **`behavior-version-latest` is NOT enabled**), `s3s = 0.14.1`.

### 6.1 `Proxy` (`src/proxy/mod.rs:9-15` — whole file)

```rust
pub struct Proxy(aws_sdk_s3::Client);

impl From<aws_sdk_s3::Client> for Proxy {
    fn from(value: aws_sdk_s3::Client) -> Self { Self(value) }
}
```

Type path `s3s_aws::Proxy` (`lib.rs:22`). Only ctor: `Proxy::from(client)` / `client.into()`. Field `.0` private — no way back to the inner client. Stateless besides `.0`; `aws_sdk_s3::Client` is cheap-clone (Arc-internal), so one `Proxy` per (backend, tenant) is fine.

### 6.2 `impl S3 for Proxy` (`src/proxy/generated.rs:14-15`)

`#[async_trait::async_trait] impl S3 for Proxy` with **98** forwarding methods (all trait ops **except `post_object`**, which falls to the trait's `NotImplemented` default — verified by name diff). Uniform body (from `abort_multipart_upload`, `:16-40`):

```rust
#[tracing::instrument(skip(self, req))]
async fn abort_multipart_upload(
    &self,
    req: S3Request<s3s::dto::AbortMultipartUploadInput>,
) -> S3Result<S3Response<s3s::dto::AbortMultipartUploadOutput>> {
    let input = req.input;
    debug!(?input);
    let mut b = self.0.abort_multipart_upload();                 // fluent builder on wrapped Client
    b = b.set_bucket(Some(try_into_aws(input.bucket)?));         // s3s dto -> aws, field by field
    b = b.set_key(Some(try_into_aws(input.key)?));
    // ... one set_* per field ...
    let result = b.send().await;
    match result {
        Ok(output) => {
            let headers = super::meta::build_headers(&output)?;  // x-amz-request-id / x-amz-id-2
            let output = try_from_aws(output)?;                  // aws -> s3s dto
            debug!(?output);
            Ok(S3Response::with_headers(output, headers))
        }
        Err(e) => Err(wrap_sdk_error!(e)),
    }
}
```

Note: the Proxy consumes `req.input` only — `req.credentials`/`region`/`headers` are **not** forwarded upstream; the wrapped client re-signs with its own configured credentials (which is exactly the gateway's re-signing model).

### 6.3 Conversions — `pub mod s3s_aws::conv` (`src/conv/mod.rs`)

```rust
pub trait AwsConversion: Sized {
    type Target;      // the aws_sdk_s3 type
    type Error;
    fn try_from_aws(x: Self::Target) -> Result<Self, Self::Error>;   // aws -> s3s
    fn try_into_aws(x: Self) -> Result<Self::Target, Self::Error>;   // s3s -> aws
}

pub fn try_from_aws<T: AwsConversion>(x: T::Target) -> Result<T, T::Error>;      // mod.rs:21
pub fn try_into_aws<T: AwsConversion>(x: T) -> S3Result<T::Target, T::Error>;    // mod.rs:25  (S3Result<T,E> ≡ Result<T,E>)
#[must_use] pub fn string_from_integer(x: i32) -> String;                        // mod.rs:40
pub fn integer_from_string(x: &str) -> S3Result<i32>;                            // mod.rs:44
// unwrap_from_aws is private (mod.rs:29)
```

One `impl AwsConversion` per DTO, auto-generated (`conv/generated.rs`, 9274 lines). `Target` examples: `s3s::dto::GetObjectOutput` → `aws_sdk_s3::operation::get_object::GetObjectOutput` (`:3586`); `s3s::dto::ListBucketsOutput` → `aws_sdk_s3::operation::list_buckets::ListBucketsOutput` (`:4892`); `s3s::dto::SelectObjectContentInput` → `aws_sdk_s3::operation::select_object_content::SelectObjectContentInput` (`builtin.rs:139`). Direct use: `<s3s::dto::GetObjectInput as AwsConversion>::try_into_aws(input)`.

Hand-written impls (`src/conv/builtin.rs`): identity for `bool, i32, i64, String, HashMap<String,String>`; blanket `Option<T>`, `Vec<T>`; `s3s::dto::Timestamp` ⇄ `aws_sdk_s3::primitives::DateTime`; `CopySource` ⇄ `String`; `Range` ⇄ `String`; `ETag`/`ETagCondition` ⇄ `String`; `Event` ⇄ `aws_sdk_s3::types::Event`; `Tag` ⇄ `aws_sdk_s3::types::Tag`; `StreamingBlob` ⇄ `aws_sdk_s3::primitives::ByteStream`; `s3s::dto::Body` ⇄ `aws_sdk_s3::primitives::Blob`.

Body bridging (`src/body.rs`): `s3s_body_into_sdk_body(s3s::Body) -> aws_smithy_types::body::SdkBody` (= `SdkBody::from_body_1_x`); `sdk_body_into_s3s_body(SdkBody) -> s3s::Body` (= `s3s::Body::http_body`).

Reverse adapter (loopback, no socket): `s3s_aws::Client` / `s3s_aws::Connector` (`src/connector.rs`) — `impl aws_smithy_runtime_api::client::http::HttpClient for Client(S3Service)`, built via `impl From<S3Service> for Client`.

### 6.4 Response/error propagation

Success headers (`src/proxy/meta.rs`):

```rust
pub fn build_headers<T>(output: &T) -> S3Result<HeaderMap>
where
    T: RequestId + RequestIdExt,   // aws_sdk_s3::operation::{RequestId, RequestIdExt}
// inserts X_AMZ_REQUEST_ID from output.request_id(); X_AMZ_ID_2 from output.extended_request_id()
```

Errors (`src/error.rs:1-28`):

```rust
macro_rules! wrap_sdk_error {
    ($e:expr) => {{
        use aws_sdk_s3::error::SdkError;
        use aws_sdk_s3::operation::RequestId;
        use s3s::{S3Error, S3ErrorCode};

        let mut err = S3Error::new(S3ErrorCode::InternalError);   // default
        let source = $e;
        tracing::debug!("sdk error: {:?}", source);
        if let SdkError::ServiceError(ref e) = source {           // only ServiceError is mined
            let meta = e.err().meta();
            if let Some(val) = meta.code().and_then(|s| S3ErrorCode::from_bytes(s.as_bytes())) { err.set_code(val); }
            if let Some(val) = meta.message()    { err.set_message(val.to_owned()); }
            if let Some(val) = meta.request_id() { err.set_request_id(val); }
            crate::error::SetStatusCode(&mut err, e).call();       // copies HTTP status
        }
        err.set_source(Box::new(source));                          // original SdkError kept as source
        err
    }};
}
```

`SetStatusCode` (`error.rs:37-52`) copies the raw HTTP status via `hyper::StatusCode::from_u16`; the code has a literal `// TODO: headers?` — **error-response headers are not propagated**.

Propagation caveats for the gateway:
- Non-`ServiceError` kinds (`ConstructionFailure`, `DispatchFailure`, `TimeoutError`, `ResponseError`) collapse to bare `InternalError` (500); only `.source` carries detail. Remap in your dispatch layer if you want e.g. RGW-unreachable → 503.
- Success responses forward only `x-amz-request-id`/`x-amz-id-2` plus whatever the DTO carries; other upstream headers are dropped. Error responses forward no headers.
- Streaming: `GetObjectOutput.body` is lazy — `ByteStream` → `SdkBody` → `s3s::Body` → `StreamingBlob`, never buffered (`builtin.rs:111-124`). `select_object_content` event streams go through `src/event_stream.rs::from_aws` (per-event `try_from_aws`, errors yielded via `wrap_sdk_error!`).

### 6.5 aws-sdk-s3 client for a Ceph RGW endpoint (static creds + path-style)

Builder signatures (`aws-sdk-s3/src/config.rs`):

```rust
// aws_sdk_s3::config::Builder
pub fn behavior_version(mut self, behavior_version: crate::config::BehaviorVersion) -> Self;                            // :1384
pub fn endpoint_url(mut self, endpoint_url: impl Into<::std::string::String>) -> Self;                                  // :1188
pub fn region(mut self, region: impl Into<Option<crate::config::Region>>) -> Self;                                      // :1273
pub fn credentials_provider(mut self, credentials_provider: impl crate::config::ProvideCredentials + 'static) -> Self;  // :1283
pub fn force_path_style(mut self, force_path_style: impl Into<bool>) -> Self;                                           // :551
// aws_sdk_s3::Client
pub fn from_conf(conf: crate::Config) -> Self;                                                                          // client.rs:109
```

Re-exports under `aws_sdk_s3::config`: `Region = ::aws_types::region::Region` (`:1808`); `Credentials = ::aws_credential_types::Credentials` (`:1658`); `BehaviorVersion = ::aws_smithy_runtime_api::client::behavior_version::BehaviorVersion` (`:1792`); `ProvideCredentials` / `SharedCredentialsProvider` (`:1852`/`:1810`). `Credentials: ProvideCredentials` — pass it straight in.

```rust
aws_sdk_s3::config::Credentials::new(
    access_key_id: impl Into<String>,
    secret_access_key: impl Into<String>,
    session_token: Option<String>,
    expires_after: Option<std::time::SystemTime>,
    provider_name: &'static str,
) -> Self;                                                                            // aws-credential-types/src/credentials_impl.rs:119
aws_sdk_s3::config::Region::new(impl Into<std::borrow::Cow<'static, str>>) -> Self;   // :45
aws_sdk_s3::config::BehaviorVersion::latest() -> Self;                                // :39
```

```rust
use aws_sdk_s3::config::{BehaviorVersion, Credentials, Region};
use aws_sdk_s3::{Client, Config};

let creds = Credentials::new(access_key, secret_key, None, None, "static");
let conf: Config = Config::builder()
    .behavior_version(BehaviorVersion::latest())   // REQUIRED: behavior-version-latest feature off; omit => panic at build()
    .endpoint_url("https://s3-backend.example.com:7480")     // Ceph RGW
    .region(Region::new("us-east-1"))              // RGW ignores it but SigV4 needs a value
    .credentials_provider(creds)
    .force_path_style(true)                        // RGW: path-style, not vhost
    .build();
let client = Client::from_conf(conf);
let proxy = s3s_aws::Proxy::from(client);
```

`Config::builder()` avoids all env/IMDS credential resolution — correct for per-tenant static creds. `Client` is cheap to clone (Arc-shared config/connector); pooling one per (backend, tenant) is fine.

---

## 7. regorus 0.10.1 — embedded PDP

Default features `["full-opa", "arc", "rvm"]`. With `arc`: `pub use alloc::sync::Arc as Rc;` (`src/lib.rs:201-202`) — **every `Rc<...>` below is `Arc`**. All fallible APIs return `anyhow::Result`.

### 7.1 Engine

```rust
// engine.rs:23-31
#[derive(Debug, Clone)]
pub struct Engine {
    modules: Rc<Vec<Ref<Module>>>,
    interpreter: Interpreter,
    prepared: bool,
    rego_v1: bool,
    execution_timer_config: Option<ExecutionTimerConfig>,
    policy_length_config: PolicyLengthConfig,
}

pub fn new() -> Self;    // also impl Default; Rego v1 by default (rego_v1: true)
```

### 7.2 Policy

```rust
pub fn add_policy(&mut self, path: String, rego: String) -> Result<String>;   // engine.rs:242 — returns package path, e.g. "data.gateway.authz"
#[cfg(feature = "std")]
pub fn add_policy_from_file<P: AsRef<std::path::Path>>(&mut self, path: P) -> Result<String>;
```

Parse errors come back as `anyhow::Error` with source-location text. Any `add_policy` sets `prepared = false` (next eval re-runs analysis). **Policies can only be added, never removed/replaced — build a fresh `Engine` per policy revision.**

### 7.3 Data (bundle)

```rust
pub fn add_data(&mut self, data: Value) -> Result<()>;           // engine.rs:463 — MERGE; err if not object / conflicting key
pub fn add_data_json(&mut self, data_json: &str) -> Result<()>;  // engine.rs:504
pub fn clear_data(&mut self);                                    // engine.rs:430 — resets data doc to {}
pub fn get_data(&self) -> Value;                                 // engine.rs:500 — cheap Arc-backed clone
```

No in-place replace. Per bundle revision either `clear_data(); add_data(v)?` (next eval pays one re-prepare) or clone a policy-only base engine and `add_data` the new bundle. `set_input` does **not** invalidate the prepared state.

### 7.4 Input

```rust
pub fn set_input(&mut self, input: Value);                        // engine.rs:400
pub fn set_input_json(&mut self, input_json: &str) -> Result<()>; // engine.rs:404
```

`Value` construction: `Value::from_json_str(json: &str) -> Result<Value>` (`value.rs:352`), `to_json_str(&self) -> Result<String>` (`value.rs:457`, pretty), `impl From<serde_json::Value> for Value` (`value.rs:652`), `Value: Serialize + Deserialize`.

### 7.5 Evaluate

```rust
pub fn eval_rule(&mut self, rule: String) -> Result<Value>;                                  // engine.rs:820 — PREFERRED fast path
pub fn eval_query(&mut self, query: String, enable_tracing: bool) -> Result<QueryResults>;   // engine.rs:862
pub fn eval_bool_query(&mut self, query: String, enable_tracing: bool) -> Result<bool>;      // engine.rs:903
pub fn eval_allow_query(&mut self, query: String, enable_tracing: bool) -> bool;             // engine.rs:943 — Ok(true) only
pub fn eval_deny_query(&mut self, query: String, enable_tracing: bool) -> bool;              // engine.rs:966
```

- `eval_rule` lazily evaluates only the named rule; the path must be a **full rule path** (`"data.gateway.authz.decision"`) — `"data"` or a bare package errors with `"not a valid rule path"`. A rule whose body fails with no `default` returns `Value::Undefined` (Ok, not Err).
- `QueryResults { pub result: Vec<QueryResult> }`; `QueryResult { pub expressions: Vec<Expression>, pub bindings: Value }`; `Expression { pub value: Value, pub text: Rc<str>, pub location: Location }` (`lib.rs:354-498`). Value at `results.result[0].expressions[0].value`.

```rust
// value.rs:42-71, 834+, 1397+
pub enum Value { Null, Bool(bool), Number(Number), String(Rc<str>),
                 Array(Rc<Vec<Value>>), Set(Rc<BTreeSet<Value>>),
                 Object(Rc<BTreeMap<Value, Value>>), Undefined }
pub fn as_bool(&self) -> Result<&bool>;
pub fn as_string(&self) -> Result<&Rc<str>>;      // Arc<str> under default features
pub fn as_object(&self) -> Result<&BTreeMap<Value, Value>>;
pub fn as_i64(&self) -> Result<i64>;              // + as_u64/as_f64/as_array/as_set...
impl ops::Index<&Value> for Value;                 // missing key / wrong type -> &Value::Undefined (never panics)
impl<T> ops::Index<T> for Value where Value: From<T>;   // v["key"], v[0]
```

### 7.6 `CompiledPolicy` — zero-clone eval (`&self`)

```rust
pub fn compile_with_entrypoint(&mut self, rule: &Rc<str>) -> Result<CompiledPolicy>;  // engine.rs:771
// compiled_policy.rs:32-35, 68
#[derive(Debug, Clone)] pub struct CompiledPolicy { pub(crate) inner: Rc<CompiledPolicyData> }
pub fn eval_with_input(&self, input: Value) -> Result<Value>;   // &self — no lock, no clone
```

`compile` snapshots `init_data` + `strict_builtin_errors` (`interpreter.rs:4412-4418`); each `eval_with_input` runs on a throwaway pre-prepared engine built from the Arc snapshot. One `CompiledPolicy` per (policy, data-revision); swap the shared handle (e.g. `arc_swap`) on bundle update. Caveat: per-engine `ExecutionTimerConfig` is not carried into `eval_with_input` (falls back to the global `regorus::utils::limits::set_fallback_execution_timer_config`).

### 7.7 Concurrency / cost model

- `Engine: Clone`; cloning a prepared engine keeps `prepared: true` (no re-analysis) — cost is Arc refcount bumps + small owned maps (COW via `Rc::make_mut`).
- With default `arc` feature, `Engine`/`Value`/`CompiledPolicy` are `Send + Sync` (proven by shipped `tests/arc.rs`; `Interpreter` holds only owned data). All eval methods take `&mut self` — do **not** share one engine behind a lock; per request either share a `CompiledPolicy` (`&self`) or clone the prepared engine.
- Every eval calls `clean_internal_evaluation_state()` (`interpreter.rs:393-403`): resets data to `init_data`, clears caches, restarts timer — evals are hermetic.

### 7.8 Toggles, builtins, traps

```rust
pub const fn set_rego_v0(&mut self, rego_v0: bool);                            // engine.rs:119 — default is Rego v1; don't call for v1 policies
pub fn set_strict_builtin_errors(&mut self, b: bool);                          // engine.rs:516 — DEFAULT true (builtins raise errors; OPA yields undefined). Set false for OPA parity.
pub fn set_execution_timer_config(&mut self, config: ExecutionTimerConfig);    // DoS guard
// use regorus::utils::limits::ExecutionTimerConfig;  // { pub limit: Duration, pub check_interval: NonZeroU32 }
pub fn add_extension(&mut self, path: String, nargs: u8, extension: Box<dyn Extension>) -> Result<()>;  // engine.rs:1283
// pub trait Extension: FnMut(Vec<Value>) -> anyhow::Result<Value> + Send + Sync (lib.rs:503); cannot be removed once added; cloned with engine
```

Builtins (default `full-opa`): present — `startswith`, `endswith`, `split`, `count`, `contains`, `upper`/`lower`, `sprintf`, `concat`, `indexof(_n)`, `replace`, `strings.*` (`replace_n`, `count`, `any_prefix_match`, `any_suffix_match`), `substring`, `trim*`, `format_int`, `to_number`, `sort`, `sum`/`min`/`max`/`product`, `abs`/`ceil`/`floor`/`round`, `numbers.range(_step)`, `array.concat/reverse/slice`, `object.get/keys/filter/remove/subset/union(_n)`, `json.marshal/unmarshal/filter/remove/is_valid/match_schema/verify_schema`, `intersection`/`union`, `bits.*`, `type_name`/`is_*`, `walk`, `glob.match`/`glob.quote_meta`, `regex.*`, `graph.reachable(_paths)`, `net.cidr_contains/cidr_expand/cidr_is_valid`, `base64.*`, `base64url.*`, `hex.*`, `urlquery.*`, `yaml.*`, `uuid.*`, `semver.*`, `units.parse(_bytes)`, `rand.intn`, `opa.runtime`, `trace`, `time.now_ns` (+ `time.*`; `now_ns` cached per-eval — stable within a request, fresh per request). `some ... in` / `every` / `if` / rule-`contains` are on by default (v1 parser).

Missing: **all `crypto.*`** (by design — use `add_extension`), all `io.jwt.*`, `graphql.*`, `json.patch`, `rego.metadata.*`, `rego.parse_module`, `net.cidr_intersects/merge/overlap/contains_matches`, `net.lookup_ip_addr`, `providers.aws.*`, `strings.render_template`.

Trap: **`http.send` is a registered no-op stub returning `Value::Undefined`** (`builtins/http.rs:17-21`) — never performs I/O, never errors.

---

## 8. Minimal wiring skeleton

Smallest correct gateway shape — `S3Auth` + `S3Access` (general `check` + one typed hook) + an `S3` impl + hyper serving. Every API used is verified above. Deps: `s3s = "0.14.1"`, `async-trait`, `tokio` (rt + net + macros), `hyper-util` (server/auto + tokio helpers), plus `s3s-aws = "0.14.1"` when using the `Proxy` as the `S3` impl.

```rust
use s3s::access::{S3Access, S3AccessContext};
use s3s::auth::{S3Auth, SecretKey};
use s3s::dto::GetObjectInput;
use s3s::service::S3ServiceBuilder;
use s3s::{s3_error, S3, S3Request, S3Result};

// --- Auth: access_key -> SecretKey (pure lookup; never sees the op) ---
struct MyAuth;

#[async_trait::async_trait]
impl S3Auth for MyAuth {
    async fn get_secret_key(&self, access_key: &str) -> S3Result<SecretKey> {
        match access_key {
            "AKIDEXAMPLE" => Ok(SecretKey::from("secret0")),   // From<&str>
            _ => Err(s3_error!(InvalidAccessKeyId)),
        }
    }
}

// --- Access: deny-by-default general gate + one typed hook ---
struct MyAccess;

#[async_trait::async_trait]
impl S3Access for MyAccess {
    // Pre-deserialization gate: op name + path + headers, NO typed input, NO body.
    async fn check(&self, cx: &mut S3AccessContext<'_>) -> S3Result<()> {
        let Some(creds) = cx.credentials() else {
            return Err(s3_error!(AccessDenied, "Signature is required"));
        };
        let op = cx.s3_op().name();                       // e.g. "GetObject" (method, not field)
        let bucket = cx.s3_path().get_bucket_name();      // Option<&str>
        let _ = (&creds.access_key, op, bucket);          // coarse PDP call goes here
        Ok(())
    }

    // Post-deserialization typed hook: full input, mutable — deny AND/OR rewrite here.
    // REMEMBER: default for the other 98 hooks is Ok(()) (fail-open).
    async fn get_object(&self, req: &mut S3Request<GetObjectInput>) -> S3Result<()> {
        let tenant = match &req.credentials {
            Some(c) => c.access_key.clone(),
            None => return Err(s3_error!(AccessDenied, "Signature is required")),
        };
        if req.input.key.starts_with("internal/") {
            return Err(s3_error!(AccessDenied, "denied by policy"));
        }
        req.input.key = format!("tenants/{tenant}/{}", req.input.key);  // in-place rewrite
        Ok(())
    }
}

// --- S3 impl: all 99 ops default to Err(NotImplemented), so an empty impl compiles.
//     Real gateway: use `s3s_aws::Proxy::from(aws_client)` here instead (it impls S3;
//     note it does NOT cover post_object).
struct UpstreamS3;

#[async_trait::async_trait]
impl S3 for UpstreamS3 {}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let service = {
        let mut b = S3ServiceBuilder::new(UpstreamS3);
        b.set_auth(MyAuth);      // REQUIRED — without set_auth the general check is SKIPPED
        b.set_access(MyAccess);  // typed hooks run whenever access is set
        b.build()
    };

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8014").await?;
    let http_server =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    let graceful = hyper_util::server::graceful::GracefulShutdown::new();
    loop {
        let (stream, _) = listener.accept().await?;
        let conn = http_server
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service.clone());
        let conn = graceful.watch(conn.into_owned());
        tokio::spawn(async move { let _ = conn.await; });
    }
}
```

---

## 9. regorus per-request path

```rust
// ---------- startup / per bundle revision ----------
let mut engine = regorus::Engine::new();                     // Rego v1 by default
engine.set_strict_builtin_errors(false);                     // OPA parity: undefined instead of error
engine.add_policy("gateway.rego".to_string(), policy_src.to_string())?;  // -> "data.gateway.authz"
engine.add_data_json(&bundle_json)?;                         // tenants/grants
// optional warm-up so clones never pay prepare:
let _ = engine.eval_rule("data.gateway.authz.decision".to_string());
let prepared = engine;                                       // share as template (Send + Sync)

// ---------- per request — Option A: clone the prepared engine ----------
let mut e = prepared.clone();                                // cheap: Arc bumps + small owned fields
e.set_input_json(&input_json)?;                              // or e.set_input(Value::from(serde_json_value))
let d = e.eval_rule("data.gateway.authz.decision".to_string())?;    // Value (Undefined if rule undefined)
let allow  = matches!(d["allow"], regorus::Value::Bool(true));       // Index is Undefined-safe, never panics
let reason = d["reason"].as_string().map(|s| s.to_string()).unwrap_or_default();
let prefix = d["rewritten_prefix"].as_string().ok().map(|s| s.to_string());

// ---------- per request — Option B (preferred): CompiledPolicy, zero-clone, &self ----------
// once per (policy, data-revision); swap the shared handle (e.g. arc_swap) on bundle update:
let compiled = {
    let mut eng = prepared.clone();
    eng.compile_with_entrypoint(&"data.gateway.authz.decision".into())?   // &Rc<str> = &Arc<str>
};
// hot path — no lock, no engine clone:
let d = compiled.eval_with_input(regorus::Value::from_json_str(&input_json)?)?;
let allow = matches!(d["allow"], regorus::Value::Bool(true));
```

Hot-path rules of thumb: never share one `Engine` behind a lock (`&mut self` evals); `eval_rule` needs the full rule path; treat `Value::Undefined` as deny; `CompiledPolicy` snapshots data at compile time, so rebuild it on every bundle revision; no `crypto.*`/`io.jwt.*` builtins — register `add_extension` if the policy needs them; `http.send` silently returns undefined.
