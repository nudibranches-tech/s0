//! CORS for browsers that reach s0 directly, as they do with a presigned URL.
//!
//! A cross-origin `PUT` or `GET` starts with a preflight (`OPTIONS`), and the page can read
//! the response only if it names its origin. CORS stays a property of the managed resource
//! (`GetBucketCors` and `PutBucketCors` remain refused to clients), but s0 is the endpoint
//! the browser reaches, so it honours the rule the control plane set on the backend bucket:
//!
//! 1. [`lookup`] reads the bucket's CORS configuration from the backend with the tenant's
//!    own credential and caches it briefly;
//! 2. [`rules`] evaluates it as S3 does, first matching rule wins;
//! 3. [`front`] wraps the S3 service: it answers `OPTIONS` itself and decorates the
//!    responses to every other request that carries an `Origin`.
//!
//! **A preflight authorizes nothing.** It is answered before s3s sees it, so it reaches
//! neither the policy engine nor the audit trail, and a `200` only tells the browser which
//! headers the real request may carry. The real request is authenticated and authorized as
//! before. CORS headers widen who may *read* a response in a browser, never who may make
//! the request.
//!
//! **Which tenant a preflight is about.** A browser sends no credential of its own, but it
//! sends the preflight to the same URL as the request, and a presigned URL names its access
//! key (and an STS session its token) in the query. The tenant, and so the backend and the
//! credential the rule is read with, come from the identity resolution the data plane uses,
//! applied to those. The signature is not checked: an `OPTIONS` has nothing to check it
//! against, and nothing is granted by it.
//!
//! **What a caller can learn.** Every refusal is the same `403`, so a preflight is not an
//! oracle for bucket existence or for which check failed. A success discloses only the part
//! of the bucket's rule that matched the caller's own origin, which is what S3 and RGW
//! disclose to anyone.
//!
//! **Not audited.** A preflight names no S3 operation and makes no authorization decision,
//! and the audit trail carries one decision record per S3 request. Preflights are counted in
//! [`CorsMetrics`] instead; spending the gate-denial budget on `OPTIONS` would let a scanner
//! suppress the records of real credential failures.
//!
//! Out of scope: browser form uploads (`PostObject`), whose credential is in the multipart
//! body; SigV2; and requests an SDK in the page signs in headers, whose preflight carries no
//! credential at all. None of them gets CORS headers, which is the safe direction.

mod front;
mod lookup;
mod rules;

use std::sync::atomic::{AtomicU64, Ordering};

pub use front::CorsFront;
pub use lookup::{CONFIG_TTL, CorsState, LOOKUP_TIMEOUT, Lookup, UNAVAILABLE_TTL};
pub use rules::{AllowOrigin, CorsConfig, Grant, PreflightGrant, parse_request_headers};

/// Why a preflight was refused. Never shown to the caller — every refusal is the same
/// `403` — but kept apart in the counters, because "browsers cannot upload" has a different
/// cure for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denial {
    /// Not a well-formed preflight: no `Origin`, no `Access-Control-Request-Method`, or a
    /// header that cannot be read.
    Malformed,
    /// No SigV4 credential in the `Authorization` header or the query.
    NoCredential,
    /// The credential did not resolve: an unknown or revoked key, or an expired or forged
    /// session token.
    IdentityRejected,
    /// The credential resolved to a tenant this gateway does not route.
    TenantNotRoutable,
    /// The path names no bucket, or one s3s would refuse.
    InvalidBucket,
    /// The bucket has no CORS configuration, or one with no rules.
    NoConfiguration,
    /// The backend could not say: the bucket does not exist, the read failed, or it timed
    /// out.
    LookupFailed,
    /// The bucket has rules and none of them allows this origin, method and headers.
    NotAllowed,
}

impl Denial {
    pub const ALL: [Denial; 8] = [
        Denial::Malformed,
        Denial::NoCredential,
        Denial::IdentityRejected,
        Denial::TenantNotRoutable,
        Denial::InvalidBucket,
        Denial::NoConfiguration,
        Denial::LookupFailed,
        Denial::NotAllowed,
    ];

    /// The label value the counter is exported under.
    pub const fn reason(self) -> &'static str {
        match self {
            Denial::Malformed => "malformed",
            Denial::NoCredential => "no_credential",
            Denial::IdentityRejected => "identity_rejected",
            Denial::TenantNotRoutable => "tenant_not_routable",
            Denial::InvalidBucket => "invalid_bucket",
            Denial::NoConfiguration => "no_configuration",
            Denial::LookupFailed => "lookup_failed",
            Denial::NotAllowed => "not_allowed",
        }
    }
}

/// Counters for the CORS layer, scraped through the admin listener. The `Arc` is shared
/// with `admin::AdminState`, so `/metrics` publishes what the request path keeps.
#[derive(Debug, Default)]
pub struct CorsMetrics {
    preflight_allowed: AtomicU64,
    preflight_denied: [AtomicU64; Denial::ALL.len()],
    responses_decorated: AtomicU64,
    backend_lookups: AtomicU64,
    backend_lookup_failures: AtomicU64,
}

impl CorsMetrics {
    pub(crate) fn record_preflight_allowed(&self) {
        self.preflight_allowed.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_preflight_denied(&self, denial: Denial) {
        self.preflight_denied[denial as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_response_decorated(&self) {
        self.responses_decorated.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_backend_lookup(&self) {
        self.backend_lookups.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_backend_lookup_failure(&self) {
        self.backend_lookup_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Preflights answered `200`.
    pub fn preflight_allowed(&self) -> u64 {
        self.preflight_allowed.load(Ordering::Relaxed)
    }

    /// Preflights refused for one reason.
    pub fn preflight_denied(&self, denial: Denial) -> u64 {
        self.preflight_denied[denial as usize].load(Ordering::Relaxed)
    }

    /// Preflights refused for any reason.
    pub fn preflight_denied_total(&self) -> u64 {
        Denial::ALL.iter().map(|d| self.preflight_denied(*d)).sum()
    }

    /// Responses to actual requests that were given CORS headers.
    pub fn responses_decorated(&self) -> u64 {
        self.responses_decorated.load(Ordering::Relaxed)
    }

    /// Reads of a bucket's CORS configuration that went to the backend, which is every
    /// cache miss.
    pub fn backend_lookups(&self) -> u64 {
        self.backend_lookups.load(Ordering::Relaxed)
    }

    /// Backend reads that failed for a reason other than "no such bucket" or "no CORS
    /// configuration". Sustained increase usually means the backend credential may not read
    /// bucket CORS.
    pub fn backend_lookup_failures(&self) -> u64 {
        self.backend_lookup_failures.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_counters_are_indexed_by_declaration_order_and_every_reason_is_distinct() {
        // `record_preflight_denied` indexes by the discriminant, so `ALL` must list the
        // variants in the order they are declared.
        for (i, denial) in Denial::ALL.iter().enumerate() {
            assert_eq!(*denial as usize, i, "{denial:?}");
        }
        let mut reasons: Vec<_> = Denial::ALL.iter().map(|d| d.reason()).collect();
        reasons.sort_unstable();
        reasons.dedup();
        assert_eq!(reasons.len(), Denial::ALL.len());
    }

    #[test]
    fn each_refusal_is_counted_under_its_own_reason() {
        let m = CorsMetrics::default();
        m.record_preflight_denied(Denial::NotAllowed);
        m.record_preflight_denied(Denial::NotAllowed);
        m.record_preflight_denied(Denial::Malformed);
        assert_eq!(m.preflight_denied(Denial::NotAllowed), 2);
        assert_eq!(m.preflight_denied(Denial::Malformed), 1);
        assert_eq!(m.preflight_denied(Denial::NoCredential), 0);
        assert_eq!(m.preflight_denied_total(), 3);
        assert_eq!(m.preflight_allowed(), 0);
    }
}
