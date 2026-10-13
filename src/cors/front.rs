//! The service that sits in front of s3s: it answers CORS preflights and decorates the
//! responses to browser requests. See [`super`] for what that does and does not mean.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_ALLOW_ORIGIN,
    ACCESS_CONTROL_EXPOSE_HEADERS, ACCESS_CONTROL_MAX_AGE, ACCESS_CONTROL_REQUEST_HEADERS,
    ACCESS_CONTROL_REQUEST_METHOD, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, ORIGIN, VARY,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, Uri};
use s3s::service::S3Service;
use s3s::{Body, HttpError, HttpRequest, HttpResponse};

use super::lookup::{CorsState, Lookup};
use super::rules::{Grant, PreflightGrant, parse_request_headers};
use super::{CorsMetrics, Denial};
use crate::access::{percent_decode, session_token};
use crate::auth::Identity;
use crate::gateway::Gateway;
use crate::proxy::{BackendRegistry, RouteSnapshot};

/// An `Origin` longer than this is not a browser's. The value is reflected into a response
/// header, so it is bounded rather than trusted to be short.
const MAX_ORIGIN_LEN: usize = 2048;
const MAX_METHOD_LEN: usize = 32;
const MAX_ACCESS_KEY_LEN: usize = 512;

/// What every refused preflight answers, byte for byte.
const FORBIDDEN_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
    <Error><Code>AccessForbidden</Code><Message>CORSResponse: This CORS request is not \
    allowed. This is usually because the evaluation of Origin, request method / \
    Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by \
    the resource's CORS spec.</Message></Error>";

/// The S3 service, wrapped. Cheap to clone: every field is a handle.
///
/// It holds the identity authority and the routing table — what resolving a tenant needs —
/// and nothing that decides access: no policy engine, no audit sink.
#[derive(Clone)]
pub struct CorsFront {
    inner: S3Service,
    identity: Arc<Identity>,
    registry: Arc<BackendRegistry>,
    state: Arc<CorsState>,
}

/// A SigV4 credential as far as a request names one: the access key id, and the STS
/// session token when there is one.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Credential {
    access_key: String,
    session_token: Option<String>,
}

/// What an actual request tells the layer, taken before the request is handed to s3s.
struct Probe {
    origin: String,
    method: String,
    credential: Option<Credential>,
    bucket: Option<String>,
}

impl CorsFront {
    pub fn new(inner: S3Service, gw: &Gateway) -> Self {
        CorsFront {
            inner,
            identity: gw.identity.clone(),
            registry: gw.registry.clone(),
            state: gw.cors.clone(),
        }
    }

    /// Serve one request. `OPTIONS` is never an S3 operation, so it is answered here and
    /// s3s does not see it. Any other request goes to s3s untouched, and its response is
    /// decorated afterwards if the request carried an `Origin` a rule allows.
    pub async fn handle(&self, req: HttpRequest) -> Result<HttpResponse, HttpError> {
        if req.method() == Method::OPTIONS {
            return Ok(self.preflight(req.headers(), req.uri()).await);
        }
        let Some(probe) = Probe::of(&req) else {
            return self.inner.call(req).await;
        };
        let mut resp = self.inner.call(req).await?;
        self.decorate(&mut resp, &probe).await;
        Ok(resp)
    }

    fn metrics(&self) -> Arc<CorsMetrics> {
        self.state.metrics()
    }

    async fn preflight(&self, headers: &HeaderMap, uri: &Uri) -> HttpResponse {
        match self.evaluate_preflight(headers, uri).await {
            Ok(grant) => {
                self.metrics().record_preflight_allowed();
                allowed_preflight(&grant)
            }
            Err(denial) => {
                self.metrics().record_preflight_denied(denial);
                tracing::debug!(reason = denial.reason(), "cors: preflight refused");
                forbidden()
            }
        }
    }

    async fn evaluate_preflight(
        &self,
        headers: &HeaderMap,
        uri: &Uri,
    ) -> Result<PreflightGrant, Denial> {
        let origin = origin_of(headers).ok_or(Denial::Malformed)?;
        let method = request_method_of(headers).ok_or(Denial::Malformed)?;
        let requested = requested_headers_of(headers).ok_or(Denial::Malformed)?;
        let credential = credential_of(headers, uri).ok_or(Denial::NoCredential)?;
        let bucket = bucket_of(uri).ok_or(Denial::InvalidBucket)?;
        let route = self.route_for(&credential)?;
        match self.state.lookup(&self.registry, &route, &bucket).await {
            Lookup::Rules(config) => config
                .preflight(origin, method, &requested)
                .ok_or(Denial::NotAllowed),
            Lookup::Absent => Err(Denial::NoConfiguration),
            Lookup::Unavailable => Err(Denial::LookupFailed),
        }
    }

    /// The tenant's route for a credential, by the identity resolution the data plane
    /// uses. The signature is not verified here; see the module docs for why that is safe.
    fn route_for(&self, credential: &Credential) -> Result<RouteSnapshot, Denial> {
        let principal = self
            .identity
            .resolve(&credential.access_key, credential.session_token.as_deref())
            .map_err(|_| Denial::IdentityRejected)?;
        self.registry
            .route_snapshot(&principal.tenant)
            .ok_or(Denial::TenantNotRoutable)
    }

    async fn decorate(&self, resp: &mut HttpResponse, probe: &Probe) {
        let Some(grant) = self.grant_for(probe).await else {
            return;
        };
        apply_grant(resp.headers_mut(), &grant);
        self.metrics().record_response_decorated();
    }

    async fn grant_for(&self, probe: &Probe) -> Option<Grant> {
        let credential = probe.credential.as_ref()?;
        let bucket = probe.bucket.as_deref()?;
        let route = self.route_for(credential).ok()?;
        match self.state.lookup(&self.registry, &route, bucket).await {
            Lookup::Rules(config) => config.actual(&probe.origin, &probe.method),
            Lookup::Absent | Lookup::Unavailable => None,
        }
    }
}

impl hyper::service::Service<http::Request<hyper::body::Incoming>> for CorsFront {
    type Response = HttpResponse;
    type Error = HttpError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, HttpError>> + Send>>;

    fn call(&self, req: http::Request<hyper::body::Incoming>) -> Self::Future {
        let front = self.clone();
        Box::pin(async move { front.handle(req.map(Body::from)).await })
    }
}

impl Probe {
    /// `None` for a request with no (single) `Origin`: it is not a browser's cross-origin
    /// request and nothing about it is touched.
    fn of(req: &HttpRequest) -> Option<Self> {
        let origin = origin_of(req.headers())?;
        Some(Probe {
            origin: origin.to_string(),
            method: req.method().as_str().to_string(),
            credential: credential_of(req.headers(), req.uri()),
            bucket: bucket_of(req.uri()),
        })
    }
}

/// The one `Origin` of the request. Two of them is not a browser's, and is refused rather
/// than guessed at.
fn origin_of(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(ORIGIN).iter();
    let origin = values.next()?.to_str().ok()?;
    if values.next().is_some() || origin.len() > MAX_ORIGIN_LEN {
        return None;
    }
    Some(origin)
}

fn request_method_of(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(ACCESS_CONTROL_REQUEST_METHOD).iter();
    let method = values.next()?.to_str().ok()?.trim();
    if values.next().is_some() || method.is_empty() || method.len() > MAX_METHOD_LEN {
        return None;
    }
    Some(method)
}

/// The requested headers, or `None` when a value cannot be read: dropping one would let a
/// preflight pass for a header it never checked.
fn requested_headers_of(headers: &HeaderMap) -> Option<Vec<String>> {
    let mut requested = Vec::new();
    for value in headers.get_all(ACCESS_CONTROL_REQUEST_HEADERS) {
        requested.extend(parse_request_headers(value.to_str().ok()?));
    }
    Some(requested)
}

/// The SigV4 credential the request names: the `Authorization` header when it carries
/// one, else the presigned query. SigV2 is not recognised.
fn credential_of(headers: &HeaderMap, uri: &Uri) -> Option<Credential> {
    let access_key = match headers.get(AUTHORIZATION) {
        Some(value) => access_key_from_authorization(value.to_str().ok()?)?,
        None => access_key_from_query(uri.query()?)?,
    };
    Some(Credential {
        access_key,
        session_token: session_token(headers, uri),
    })
}

fn access_key_from_authorization(authorization: &str) -> Option<String> {
    let params = authorization
        .trim_start()
        .strip_prefix("AWS4-HMAC-SHA256")?
        .trim_start();
    params
        .split(',')
        .find_map(|p| p.trim().strip_prefix("Credential="))
        .and_then(access_key_from_scope)
}

fn access_key_from_query(query: &str) -> Option<String> {
    query
        .split('&')
        .find_map(|p| p.strip_prefix("X-Amz-Credential="))
        .and_then(|v| access_key_from_scope(&percent_decode(v)))
}

/// The access key id in `<id>/<date>/<region>/<service>/aws4_request`.
fn access_key_from_scope(scope: &str) -> Option<String> {
    let access_key = scope.split('/').next()?;
    if access_key.is_empty() || access_key.len() > MAX_ACCESS_KEY_LEN {
        return None;
    }
    Some(access_key.to_string())
}

/// The bucket of a path-style request, parsed by the s3s routine that will route it, so
/// the layer and the service cannot disagree about which bucket a URL names.
fn bucket_of(uri: &Uri) -> Option<String> {
    let path = percent_decode(uri.path());
    s3s::path::parse_path_style(&path)
        .ok()?
        .get_bucket_name()
        .map(str::to_string)
}

fn forbidden() -> HttpResponse {
    let mut resp = HttpResponse::new(Body::from(FORBIDDEN_BODY.to_string()));
    *resp.status_mut() = StatusCode::FORBIDDEN;
    let headers = resp.headers_mut();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
    headers.insert(
        CONTENT_LENGTH,
        HeaderValue::from(FORBIDDEN_BODY.len() as u64),
    );
    resp
}

fn allowed_preflight(grant: &PreflightGrant) -> HttpResponse {
    let mut resp = HttpResponse::new(Body::empty());
    let headers = resp.headers_mut();
    headers.insert(CONTENT_LENGTH, HeaderValue::from(0u64));
    insert_text(
        headers,
        ACCESS_CONTROL_ALLOW_ORIGIN,
        grant.grant.allow_origin.as_header_value(),
    );
    insert_list(headers, ACCESS_CONTROL_ALLOW_METHODS, &grant.allow_methods);
    insert_list(headers, ACCESS_CONTROL_ALLOW_HEADERS, &grant.allow_headers);
    insert_list(
        headers,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        &grant.grant.expose_headers,
    );
    if let Some(seconds) = grant.max_age_seconds {
        headers.insert(ACCESS_CONTROL_MAX_AGE, HeaderValue::from(seconds));
    }
    for name in [
        "Origin",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
    ] {
        headers.append(VARY, HeaderValue::from_static(name));
    }
    resp
}

fn apply_grant(headers: &mut HeaderMap, grant: &Grant) {
    insert_text(
        headers,
        ACCESS_CONTROL_ALLOW_ORIGIN,
        grant.allow_origin.as_header_value(),
    );
    insert_list(
        headers,
        ACCESS_CONTROL_EXPOSE_HEADERS,
        &grant.expose_headers,
    );
    headers.append(VARY, HeaderValue::from_static("Origin"));
}

fn insert_text(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

/// A header carrying a list, left out when the list is empty. An entry that cannot be part
/// of a header is dropped alone: the configuration is the bucket owner's, and one bad entry
/// must neither malform the response nor take the good ones with it.
fn insert_list(headers: &mut HeaderMap, name: HeaderName, values: &[String]) {
    let usable: Vec<&str> = values
        .iter()
        .map(String::as_str)
        .filter(|v| HeaderValue::from_str(v).is_ok())
        .collect();
    if !usable.is_empty() {
        insert_text(headers, name, &usable.join(", "));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3s::dto::CORSRule;

    use crate::cors::rules::CorsConfig;

    fn uri(s: &str) -> Uri {
        s.parse().unwrap()
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (k, v) in pairs {
            map.append(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        map
    }

    #[test]
    fn the_access_key_comes_from_the_authorization_header() {
        let h = headers(&[(
            "authorization",
            "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20261012/us-east-1/s3/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature=abcd",
        )]);
        assert_eq!(
            credential_of(&h, &uri("/b/k")),
            Some(Credential {
                access_key: "AKIAEXAMPLE".into(),
                session_token: None,
            })
        );
    }

    #[test]
    fn the_access_key_and_token_come_from_a_presigned_query() {
        let q = "/b/k?X-Amz-Algorithm=AWS4-HMAC-SHA256\
                 &X-Amz-Credential=HFSTk0.sid-1%2F20261012%2Fus-east-1%2Fs3%2Faws4_request\
                 &X-Amz-Security-Token=tok%2Fen&X-Amz-Signature=abcd";
        assert_eq!(
            credential_of(&HeaderMap::new(), &uri(q)),
            Some(Credential {
                access_key: "HFSTk0.sid-1".into(),
                session_token: Some("tok/en".into()),
            })
        );
    }

    #[test]
    fn a_request_without_a_sigv4_credential_names_none() {
        let none = HeaderMap::new();
        assert_eq!(credential_of(&none, &uri("/b/k")), None);
        assert_eq!(credential_of(&none, &uri("/b/k?versionId=3")), None);
        for authorization in [
            "AWS AKIAEXAMPLE:c2lnbmF0dXJl",
            "Bearer abc",
            "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=ab",
            "AWS4-HMAC-SHA256 Credential=/20261012/us-east-1/s3/aws4_request",
        ] {
            let h = headers(&[("authorization", authorization)]);
            assert_eq!(credential_of(&h, &uri("/b/k")), None, "{authorization}");
        }
        // The header is authoritative: a malformed one is not papered over by the query.
        let h = headers(&[("authorization", "Bearer abc")]);
        assert_eq!(
            credential_of(&h, &uri("/b/k?X-Amz-Credential=AKIA%2Fx")),
            None
        );
    }

    #[test]
    fn an_over_long_access_key_is_not_a_credential() {
        let q = format!(
            "/b/k?X-Amz-Credential={}%2Fx",
            "A".repeat(MAX_ACCESS_KEY_LEN + 1)
        );
        assert_eq!(credential_of(&HeaderMap::new(), &uri(&q)), None);
    }

    #[test]
    fn the_bucket_is_the_one_s3s_would_route() {
        assert_eq!(
            bucket_of(&uri("/reports/2024/q1.csv")).as_deref(),
            Some("reports")
        );
        assert_eq!(bucket_of(&uri("/reports")).as_deref(), Some("reports"));
        assert_eq!(bucket_of(&uri("/reports/")).as_deref(), Some("reports"));
        assert_eq!(bucket_of(&uri("/%72eports/k")).as_deref(), Some("reports"));
        assert_eq!(bucket_of(&uri("/")), None);
        assert_eq!(bucket_of(&uri("/Not_A_Bucket/k")), None);
        assert_eq!(bucket_of(&uri("/ab/k")), None);
    }

    #[test]
    fn origin_must_be_present_once_and_short() {
        assert_eq!(origin_of(&HeaderMap::new()), None);
        assert_eq!(
            origin_of(&headers(&[("origin", "https://a.test")])),
            Some("https://a.test")
        );
        assert_eq!(
            origin_of(&headers(&[
                ("origin", "https://a.test"),
                ("origin", "https://b.test")
            ])),
            None
        );
        let long = format!("https://{}.test", "a".repeat(MAX_ORIGIN_LEN));
        assert_eq!(origin_of(&headers(&[("origin", &long)])), None);
    }

    #[test]
    fn requested_headers_are_joined_across_header_lines() {
        let h = headers(&[
            ("access-control-request-headers", "content-type"),
            (
                "access-control-request-headers",
                "X-Amz-Meta-A, x-amz-meta-b",
            ),
        ]);
        assert_eq!(
            requested_headers_of(&h),
            Some(vec![
                "content-type".to_string(),
                "x-amz-meta-a".to_string(),
                "x-amz-meta-b".to_string()
            ])
        );
        assert_eq!(requested_headers_of(&HeaderMap::new()), Some(vec![]));
    }

    #[test]
    fn a_requested_header_that_cannot_be_read_refuses_instead_of_being_skipped() {
        let mut h = HeaderMap::new();
        h.insert(
            ACCESS_CONTROL_REQUEST_HEADERS,
            HeaderValue::from_bytes(b"content-type, \xff").unwrap(),
        );
        assert_eq!(requested_headers_of(&h), None);
    }

    fn put_rule() -> CorsConfig {
        CorsConfig::from_rules(&[CORSRule {
            allowed_origins: vec!["*".into()],
            allowed_methods: vec!["PUT".into()],
            allowed_headers: Some(vec!["content-type".into()]),
            expose_headers: Some(vec!["ETag".into()]),
            max_age_seconds: Some(3000),
            ..Default::default()
        }])
    }

    #[test]
    fn an_allowed_preflight_carries_the_rule_and_varies_on_what_it_read() {
        let granted = put_rule()
            .preflight("https://a.test", "PUT", &["content-type".to_string()])
            .unwrap();
        let resp = allowed_preflight(&granted);
        assert_eq!(resp.status(), StatusCode::OK);
        let h = resp.headers();
        assert_eq!(h[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(h[ACCESS_CONTROL_ALLOW_METHODS], "PUT");
        assert_eq!(h[ACCESS_CONTROL_ALLOW_HEADERS], "content-type");
        assert_eq!(h[ACCESS_CONTROL_EXPOSE_HEADERS], "ETag");
        assert_eq!(h[ACCESS_CONTROL_MAX_AGE], "3000");
        let vary: Vec<_> = h
            .get_all(VARY)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(
            vary,
            [
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers"
            ]
        );
    }

    #[test]
    fn a_preflight_with_nothing_to_list_omits_those_headers() {
        let config = CorsConfig::from_rules(&[CORSRule {
            allowed_origins: vec!["https://a.test".into()],
            allowed_methods: vec!["GET".into()],
            ..Default::default()
        }]);
        let resp = allowed_preflight(&config.preflight("https://a.test", "GET", &[]).unwrap());
        let h = resp.headers();
        assert_eq!(h[ACCESS_CONTROL_ALLOW_ORIGIN], "https://a.test");
        assert!(!h.contains_key(ACCESS_CONTROL_ALLOW_HEADERS));
        assert!(!h.contains_key(ACCESS_CONTROL_EXPOSE_HEADERS));
        assert!(!h.contains_key(ACCESS_CONTROL_MAX_AGE));
    }

    #[test]
    fn a_decorated_response_keeps_the_vary_it_already_had() {
        let mut h = headers(&[("vary", "Accept-Encoding"), ("etag", "\"abc\"")]);
        let grant = put_rule().actual("https://a.test", "PUT").unwrap();
        apply_grant(&mut h, &grant);
        assert_eq!(h[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(h[ACCESS_CONTROL_EXPOSE_HEADERS], "ETag");
        let vary: Vec<_> = h
            .get_all(VARY)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(vary, ["Accept-Encoding", "Origin"]);
        assert_eq!(
            h["etag"], "\"abc\"",
            "the response's own headers are not touched"
        );
    }

    #[test]
    fn a_bad_entry_in_the_bucket_configuration_does_not_break_the_response() {
        let mut h = HeaderMap::new();
        let grant = Grant {
            allow_origin: crate::cors::AllowOrigin::Any,
            expose_headers: vec!["ETag".into(), "bad\nheader".into()],
        };
        apply_grant(&mut h, &grant);
        assert_eq!(h[ACCESS_CONTROL_ALLOW_ORIGIN], "*");
        assert_eq!(h[ACCESS_CONTROL_EXPOSE_HEADERS], "ETag");
    }

    #[test]
    fn every_refusal_is_the_same_bytes() {
        let a = forbidden();
        let b = forbidden();
        assert_eq!(a.status(), StatusCode::FORBIDDEN);
        assert_eq!(a.headers(), b.headers());
        assert_eq!(
            a.headers()[CONTENT_LENGTH],
            FORBIDDEN_BODY.len().to_string()
        );
        assert!(FORBIDDEN_BODY.contains("<Code>AccessForbidden</Code>"));
    }
}
