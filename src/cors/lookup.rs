//! A bucket's CORS configuration as the backend holds it, cached.
//!
//! The control plane writes the rule on the bucket; s0 reads it back with `GetBucketCors`,
//! signed with the tenant's backend credential, and keeps what it read for a short time.
//! The cache is keyed `(backend, tenant, bucket)`, the same identity the client pool uses,
//! so two tenants can never read each other's entry.
//!
//! What was learned is cached for one of two lengths of time:
//!
//! - the rules, or "this bucket has no CORS configuration" (also what a backend that does
//!   not implement bucket CORS says): [`CONFIG_TTL`], so a rule the control plane writes
//!   reaches browsers within about a minute;
//! - "could not find out" (a missing bucket, a refused or failed read, a timeout):
//!   [`UNAVAILABLE_TTL`], long enough to coalesce a burst against a sick backend and short
//!   enough that a bucket created a moment later, or a backend that recovers, is not
//!   penalised for a minute.
//!
//! Concurrent misses for one key share one backend read. The key includes the bucket name
//! the caller chose, so the cache is bounded by entry count: a caller who knows an access
//! key id can fill it with names that do not exist, and the short TTL on those entries is
//! what keeps real buckets from being evicted for long.

use std::sync::Arc;
use std::time::{Duration, Instant};

use http::{Extensions, HeaderMap, Method, Uri};
use moka::Expiry;
use moka::future::Cache;
use s3s::dto::GetBucketCorsInput;
use s3s::{S3, S3ErrorCode, S3Request};

use super::CorsMetrics;
use super::rules::CorsConfig;
use crate::proxy::{BackendRegistry, RouteSnapshot};

/// How long a configuration, or its absence, is trusted.
pub const CONFIG_TTL: Duration = Duration::from_secs(60);
/// How long a failed read is remembered.
pub const UNAVAILABLE_TTL: Duration = Duration::from_secs(5);
/// How long one backend read may take. A browser is waiting on the answer.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(3);
const CACHE_CAPACITY: u64 = 10_000;

/// `(backend id, tenant, bucket)`.
type Key = (String, String, String);

/// What the backend said about one bucket.
#[derive(Debug, Clone)]
pub enum Lookup {
    Rules(Arc<CorsConfig>),
    Absent,
    Unavailable,
}

struct LookupExpiry {
    config_ttl: Duration,
    unavailable_ttl: Duration,
}

impl LookupExpiry {
    fn ttl(&self, lookup: &Lookup) -> Duration {
        match lookup {
            Lookup::Rules(_) | Lookup::Absent => self.config_ttl,
            Lookup::Unavailable => self.unavailable_ttl,
        }
    }
}

impl Expiry<Key, Lookup> for LookupExpiry {
    fn expire_after_create(
        &self,
        _key: &Key,
        value: &Lookup,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(self.ttl(value))
    }
}

/// The cache and the counters. One per gateway, shared by every connection.
pub struct CorsState {
    cache: Cache<Key, Lookup>,
    metrics: Arc<CorsMetrics>,
    lookup_timeout: Duration,
}

impl Default for CorsState {
    fn default() -> Self {
        Self::new()
    }
}

impl CorsState {
    pub fn new() -> Self {
        Self::with_timings(CONFIG_TTL, UNAVAILABLE_TTL, LOOKUP_TIMEOUT)
    }

    /// The same state with other lifetimes. The production values are the constants above;
    /// this exists so a test can watch an entry expire without waiting a minute.
    pub fn with_timings(
        config_ttl: Duration,
        unavailable_ttl: Duration,
        lookup_timeout: Duration,
    ) -> Self {
        CorsState {
            cache: Cache::builder()
                .max_capacity(CACHE_CAPACITY)
                .expire_after(LookupExpiry {
                    config_ttl,
                    unavailable_ttl,
                })
                .build(),
            metrics: Arc::new(CorsMetrics::default()),
            lookup_timeout,
        }
    }

    /// The counters, shared with the admin listener so `/metrics` publishes the numbers
    /// the request path actually keeps.
    pub fn metrics(&self) -> Arc<CorsMetrics> {
        self.metrics.clone()
    }

    /// The configuration for `bucket` on the backend `route` names: from the cache while
    /// it is fresh, from the backend otherwise.
    pub async fn lookup(
        &self,
        registry: &BackendRegistry,
        route: &RouteSnapshot,
        bucket: &str,
    ) -> Lookup {
        let key = (
            route.backend_id.0.clone(),
            route.tenant.clone(),
            bucket.to_string(),
        );
        self.cache
            .get_with(key, self.read_backend(registry, route, bucket))
            .await
    }

    async fn read_backend(
        &self,
        registry: &BackendRegistry,
        route: &RouteSnapshot,
        bucket: &str,
    ) -> Lookup {
        self.metrics.record_backend_lookup();
        let proxy = match registry.proxy_for(route) {
            Ok(proxy) => proxy,
            Err(e) => {
                self.metrics.record_backend_lookup_failure();
                tracing::warn!(tenant = %route.tenant, error = %e, "cors: no backend client");
                return Lookup::Unavailable;
            }
        };
        let req = S3Request {
            input: GetBucketCorsInput {
                bucket: bucket.to_string(),
                expected_bucket_owner: None,
            },
            method: Method::GET,
            uri: Uri::from_static("/"),
            headers: HeaderMap::new(),
            extensions: Extensions::new(),
            credentials: None,
            region: None,
            service: None,
            trailing_headers: None,
        };
        match tokio::time::timeout(self.lookup_timeout, proxy.get_bucket_cors(req)).await {
            Ok(Ok(resp)) => {
                let config = CorsConfig::from_rules(&resp.output.cors_rules.unwrap_or_default());
                if config.is_empty() {
                    Lookup::Absent
                } else {
                    Lookup::Rules(Arc::new(config))
                }
            }
            Ok(Err(e)) => match e.code() {
                S3ErrorCode::NoSuchCORSConfiguration | S3ErrorCode::NotImplemented => {
                    Lookup::Absent
                }
                S3ErrorCode::NoSuchBucket => {
                    tracing::debug!(tenant = %route.tenant, %bucket, "cors: no such bucket");
                    Lookup::Unavailable
                }
                _ => {
                    self.metrics.record_backend_lookup_failure();
                    tracing::warn!(
                        tenant = %route.tenant, %bucket, error = %e,
                        "cors: reading the bucket's CORS configuration failed"
                    );
                    Lookup::Unavailable
                }
            },
            Err(_) => {
                self.metrics.record_backend_lookup_failure();
                tracing::warn!(
                    tenant = %route.tenant, %bucket,
                    "cors: reading the bucket's CORS configuration timed out"
                );
                Lookup::Unavailable
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failed_read_is_remembered_for_less_time_than_an_answer() {
        let expiry = LookupExpiry {
            config_ttl: CONFIG_TTL,
            unavailable_ttl: UNAVAILABLE_TTL,
        };
        assert_eq!(expiry.ttl(&Lookup::Absent), CONFIG_TTL);
        assert_eq!(
            expiry.ttl(&Lookup::Rules(Arc::new(CorsConfig::default()))),
            CONFIG_TTL
        );
        assert_eq!(expiry.ttl(&Lookup::Unavailable), UNAVAILABLE_TTL);
        assert!(UNAVAILABLE_TTL < CONFIG_TTL);
    }
}
