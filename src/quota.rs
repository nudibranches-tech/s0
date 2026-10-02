//! Byte quotas on a backend that enforces none of its own (ADR-010).
//!
//! A v3 bundle may carry a `quota` — `{ limit_bytes, used_bytes, collected_at }` — on a
//! bucket, on a tenant and on the backend as a whole. `used_bytes` is what the control
//! plane's collector measured at `collected_at`. Everything written since is counted here,
//! so a write is refused as soon as `used + counted + this write` passes a limit, rather
//! than one collection later. A document with no `quota` anywhere enforces nothing: a
//! backend with native quotas (Ceph) keeps them, and this module is never consulted.
//!
//! - **Per replica.** A replica counts only what it accepted itself, so N replicas can
//!   overshoot a limit by what the other N − 1 accepted between two collections. Accepted
//!   for v1 (ADR-010); a backend's own per-bucket limit, where it has one, is the backstop.
//! - **Counted from admission until a collection covers it.** A write is in flight from the
//!   moment it is admitted until the backend answers, and is then stamped with that time.
//!   A newer `collected_at` drops only what completed before it, so a write that lands while
//!   the collection is on its way to the bundle is not forgotten, and an in-flight write is
//!   never dropped.
//! - **Conservative.** Overwrites and deletes are not subtracted, and a write whose outcome
//!   is unknown (a dropped connection, a backend 5xx) stays counted; the next collection
//!   corrects both. A write the backend refused with a 4xx gives its bytes back.
//! - **Atomic.** One lock covers the check and the reservation at every level, so two
//!   writers on one replica can never both take the last bytes of a limit.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use chrono::{DateTime, Utc};
use s3s::{S3Error, S3ErrorCode, s3_error};

/// Bundle field names the quotas are read from. A contract with the control plane's
/// projection, named once so the reader, the fixtures and the drift tests share them.
pub const QUOTA_FIELD: &str = "quota";
pub const BACKEND_QUOTA_FIELD: &str = "backend_quota";
pub const LIMIT_BYTES_FIELD: &str = "limit_bytes";
pub const USED_BYTES_FIELD: &str = "used_bytes";
pub const COLLECTED_AT_FIELD: &str = "collected_at";

/// The S3 error code a write over quota is refused with: RGW's, which S3 clients already
/// surface as a quota problem rather than a permission one.
pub const QUOTA_EXCEEDED: &str = "QuotaExceeded";

/// Committed writes are kept in one-second slots, at most this many per level. Past it the
/// two oldest slots merge under the later timestamp, which can only keep bytes counted
/// longer: memory stays bounded however long a collection is late.
const MAX_SETTLED_SLOTS: usize = 256;

/// One level's limit, as of one collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub limit_bytes: u64,
    /// What the backend held at `collected_at`.
    pub used_bytes: u64,
    /// When `used_bytes` was measured. Every write that completed before it is in
    /// `used_bytes`; the collector reports the start of its measurement, not its end.
    pub collected_at: DateTime<Utc>,
}

impl Quota {
    /// Read a bundle `quota` object: exactly the three fields, typed as the contract pins.
    pub fn from_value(value: &serde_json::Value) -> Result<Quota, String> {
        let Some(object) = value.as_object() else {
            return Err(format!("not an object: {value}"));
        };
        let bytes = |field: &str| {
            object
                .get(field)
                .and_then(serde_json::Value::as_u64)
                .ok_or_else(|| format!("{field} is missing or not an unsigned integer"))
        };
        let limit_bytes = bytes(LIMIT_BYTES_FIELD)?;
        let used_bytes = bytes(USED_BYTES_FIELD)?;
        let collected_at = object
            .get(COLLECTED_AT_FIELD)
            .and_then(serde_json::Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|t| t.with_timezone(&Utc))
            .ok_or_else(|| format!("{COLLECTED_AT_FIELD} is missing or not RFC 3339"))?;
        Ok(Quota {
            limit_bytes,
            used_bytes,
            collected_at,
        })
    }
}

/// A level's quota as the bundle states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaSpec {
    Limit(Quota),
    /// Present but unreadable. Writes the level covers are refused: a limit half-read is a
    /// limit not enforced, and reads stay untouched.
    Unreadable(String),
}

impl QuotaSpec {
    /// The spec a bundle value states, or `None` when there is none. JSON `null` is no
    /// quota, the way a projection that serializes an absent optional writes it.
    #[must_use]
    pub fn read(value: Option<&serde_json::Value>) -> Option<QuotaSpec> {
        match value {
            None | Some(serde_json::Value::Null) => None,
            Some(v) => Some(match Quota::from_value(v) {
                Ok(quota) => QuotaSpec::Limit(quota),
                Err(why) => QuotaSpec::Unreadable(why),
            }),
        }
    }
}

/// The level a quota limits. A write counts against its bucket, its tenant and its backend.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum QuotaScope {
    Bucket(String),
    Tenant(String),
    Backend(String),
}

impl QuotaScope {
    /// The three levels a write to `bucket` by `tenant` on `backend` counts against,
    /// narrowest first: the order a refusal names them in.
    fn of(target: &WriteTarget<'_>) -> [QuotaScope; 3] {
        [
            QuotaScope::Bucket(target.bucket.to_string()),
            QuotaScope::Tenant(target.tenant.to_string()),
            QuotaScope::Backend(target.backend.to_string()),
        ]
    }

    fn describe(&self) -> String {
        match self {
            QuotaScope::Bucket(name) => format!("bucket {name:?}"),
            QuotaScope::Tenant(name) => format!("tenant {name:?}"),
            QuotaScope::Backend(name) => format!("backend {name:?}"),
        }
    }

    /// What the client is told. The level only: the tenant and backend figures add up
    /// other buckets than the one written to, and they stay on the audit record.
    fn client_message(&self) -> &'static str {
        match self {
            QuotaScope::Bucket(_) => "The storage quota for this bucket has been exceeded.",
            QuotaScope::Tenant(_) => "The storage quota for this tenant has been exceeded.",
            QuotaScope::Backend(_) => {
                "The organization's storage quota on this backend has been exceeded."
            }
        }
    }
}

/// Where a write lands.
#[derive(Debug, Clone, Copy)]
pub struct WriteTarget<'a> {
    pub backend: &'a str,
    pub tenant: &'a str,
    pub bucket: &'a str,
}

static NEXT_GENERATION: AtomicU64 = AtomicU64::new(1);

/// The quotas one bundle revision publishes.
#[derive(Debug)]
pub struct BundleQuotas {
    /// Increases with every table built, so the ledger can tell a newer revision from an
    /// older one still pinned by a request in flight across a swap.
    generation: u64,
    specs: HashMap<QuotaScope, QuotaSpec>,
}

impl BundleQuotas {
    #[must_use]
    pub fn new(specs: HashMap<QuotaScope, QuotaSpec>) -> Self {
        BundleQuotas {
            generation: NEXT_GENERATION.fetch_add(1, Ordering::Relaxed),
            specs,
        }
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    #[must_use]
    pub fn get(&self, scope: &QuotaScope) -> Option<&QuotaSpec> {
        self.specs.get(scope)
    }

    /// Whether any level of `target` has a quota, readable or not.
    #[must_use]
    pub fn applies_to(&self, target: &WriteTarget<'_>) -> bool {
        !self.specs.is_empty()
            && QuotaScope::of(target)
                .iter()
                .any(|s| self.specs.contains_key(s))
    }

    /// The levels whose quota cannot be read, with why.
    pub fn unreadable(&self) -> impl Iterator<Item = (&QuotaScope, &str)> {
        self.specs.iter().filter_map(|(scope, spec)| match spec {
            QuotaSpec::Unreadable(why) => Some((scope, why.as_str())),
            QuotaSpec::Limit(_) => None,
        })
    }

    fn applicable(&self, target: &WriteTarget<'_>) -> Vec<(QuotaScope, &QuotaSpec)> {
        QuotaScope::of(target)
            .into_iter()
            .filter_map(|scope| {
                let spec = self.specs.get(&scope)?;
                Some((scope, spec))
            })
            .collect()
    }
}

/// Why a write is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuotaRefusal {
    /// The write would take a level past its limit.
    Exceeded {
        scope: QuotaScope,
        limit_bytes: u64,
        used_bytes: u64,
        collected_at: DateTime<Utc>,
        /// Accepted by this replica since `collected_at`, in flight or completed.
        counted_bytes: u64,
        write_bytes: u64,
    },
    /// The bundle states a quota for this level that cannot be read.
    Unreadable { scope: QuotaScope, why: String },
    /// A quota applies and the request does not say how many bytes it carries.
    UnknownSize { scope: QuotaScope },
}

impl QuotaRefusal {
    /// The audit-facing reason. Unlike [`Self::to_s3_error`] it carries the figures.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            QuotaRefusal::Exceeded {
                scope,
                limit_bytes,
                used_bytes,
                collected_at,
                counted_bytes,
                write_bytes,
            } => format!(
                "deny (gateway): storage quota exceeded: this write adds {write_bytes} bytes \
                 to {}, which held {used_bytes} bytes at {} and has accepted \
                 {counted_bytes} bytes since, against a limit of {limit_bytes} bytes",
                scope.describe(),
                collected_at.to_rfc3339(),
            ),
            QuotaRefusal::Unreadable { scope, why } => format!(
                "deny (gateway): the policy bundle's storage quota for {} cannot be read \
                 ({why}); writes to it are refused until the control plane serves a \
                 readable one",
                scope.describe()
            ),
            QuotaRefusal::UnknownSize { scope } => format!(
                "deny (gateway): a storage quota applies to {}, and the request does not \
                 say how many bytes it writes (no Content-Length)",
                scope.describe()
            ),
        }
    }

    /// What the client is answered: `QuotaExceeded` (403) over a limit, `AccessDenied` for
    /// a quota the bundle cannot state, `MissingContentLength` (411) for a write of
    /// unstated size.
    #[must_use]
    pub fn to_s3_error(&self) -> S3Error {
        match self {
            QuotaRefusal::Exceeded { scope, .. } => {
                let mut err = S3Error::with_message(
                    S3ErrorCode::Custom(QUOTA_EXCEEDED.into()),
                    scope.client_message(),
                );
                err.set_status_code(http::StatusCode::FORBIDDEN);
                err
            }
            QuotaRefusal::Unreadable { .. } => s3_error!(AccessDenied, "{}", self.reason()),
            QuotaRefusal::UnknownSize { .. } => {
                s3_error!(MissingContentLength, "{}", self.reason())
            }
        }
    }
}

/// The ledger's answer to one write.
#[derive(Debug)]
pub enum Admission {
    /// No level of the write has a quota: nothing is counted.
    Unlimited,
    /// Counted as in flight until the reservation is settled.
    Reserved(Arc<QuotaReservation>),
    Refused(QuotaRefusal),
}

/// What this replica has accepted, per level, since the newest collection it has seen.
/// One per gateway process, outliving every bundle revision.
#[derive(Debug, Default)]
pub struct QuotaLedger {
    state: Mutex<LedgerState>,
}

#[derive(Debug, Default)]
struct LedgerState {
    counters: HashMap<QuotaScope, Counter>,
    /// The newest [`BundleQuotas`] generation swept against.
    swept: u64,
}

#[derive(Debug)]
struct Counter {
    /// The newest collection seen for this level. An older one arriving later (a request
    /// pinned to the previous revision) is not allowed to turn it back.
    collected_at: DateTime<Utc>,
    used_bytes: u64,
    in_flight: u64,
    /// Completed writes not yet covered by a collection, oldest first.
    settled: VecDeque<Slot>,
    settled_bytes: u64,
}

/// Bytes whose writes completed in the second ending at `end` (Unix seconds).
#[derive(Debug, Clone, Copy)]
struct Slot {
    end: i64,
    bytes: u64,
}

impl Counter {
    fn new(quota: &Quota) -> Self {
        Counter {
            collected_at: quota.collected_at,
            used_bytes: quota.used_bytes,
            in_flight: 0,
            settled: VecDeque::new(),
            settled_bytes: 0,
        }
    }

    /// Take `quota`'s collection as the basis if it is newer, and drop every completed
    /// write it covers.
    fn observe(&mut self, quota: &Quota) {
        if quota.collected_at <= self.collected_at {
            return;
        }
        self.collected_at = quota.collected_at;
        self.used_bytes = quota.used_bytes;
        let covered = quota.collected_at.timestamp();
        while let Some(slot) = self.settled.front() {
            if slot.end > covered {
                break;
            }
            self.settled_bytes = self.settled_bytes.saturating_sub(slot.bytes);
            self.settled.pop_front();
        }
    }

    fn counted(&self) -> u64 {
        self.in_flight.saturating_add(self.settled_bytes)
    }

    fn is_empty(&self) -> bool {
        self.in_flight == 0 && self.settled_bytes == 0
    }

    fn settle(&mut self, bytes: u64, completed_at: Option<DateTime<Utc>>) {
        self.in_flight = self.in_flight.saturating_sub(bytes);
        let Some(at) = completed_at.filter(|_| bytes > 0) else {
            return;
        };
        // Rounded up to the end of its second: a slot is dropped only once a collection is
        // known to postdate every write in it.
        let end = at.timestamp() + i64::from(at.timestamp_subsec_nanos() > 0);
        self.settled_bytes = self.settled_bytes.saturating_add(bytes);
        match self.settled.back_mut() {
            // Same second, or a clock that stepped back: keep the later stamp.
            Some(last) if last.end >= end => last.bytes = last.bytes.saturating_add(bytes),
            _ => self.settled.push_back(Slot { end, bytes }),
        }
        if self.settled.len() > MAX_SETTLED_SLOTS
            && let Some(oldest) = self.settled.pop_front()
            && let Some(next) = self.settled.front_mut()
        {
            next.bytes = next.bytes.saturating_add(oldest.bytes);
        }
    }
}

impl LedgerState {
    /// Bring every counter up to `quotas` once per newer revision: drop what its collections
    /// cover, and forget levels that no longer have a limit or no longer hold anything.
    /// Without it, a bucket written once and never again would keep its counter for the
    /// life of the process.
    fn sweep(&mut self, quotas: &BundleQuotas) {
        if quotas.generation <= self.swept {
            return;
        }
        self.swept = quotas.generation;
        self.counters.retain(|scope, counter| {
            if let Some(QuotaSpec::Limit(quota)) = quotas.get(scope) {
                counter.observe(quota);
            } else if counter.in_flight == 0 {
                return false;
            }
            !counter.is_empty()
        });
    }
}

impl QuotaLedger {
    #[must_use]
    pub fn new() -> Self {
        QuotaLedger::default()
    }

    fn lock(&self) -> MutexGuard<'_, LedgerState> {
        // The state is plain counters: a panic while it was held cannot have left it
        // inconsistent in a way worse than refusing every write would be.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Check a write of `bytes` (`None`: unstated) to `target` against `quotas`, and count
    /// it as in flight if every level has room. The check and the reservation happen under
    /// one lock, at every level at once.
    pub fn admit(
        self: &Arc<Self>,
        quotas: &BundleQuotas,
        target: &WriteTarget<'_>,
        bytes: Option<u64>,
    ) -> Admission {
        let applicable = quotas.applicable(target);
        let Some((narrowest, _)) = applicable.first() else {
            return Admission::Unlimited;
        };
        let mut limits = Vec::with_capacity(applicable.len());
        for (scope, spec) in &applicable {
            match spec {
                QuotaSpec::Limit(quota) => limits.push((scope.clone(), *quota)),
                QuotaSpec::Unreadable(why) => {
                    return Admission::Refused(QuotaRefusal::Unreadable {
                        scope: scope.clone(),
                        why: why.clone(),
                    });
                }
            }
        }
        let Some(bytes) = bytes else {
            return Admission::Refused(QuotaRefusal::UnknownSize {
                scope: narrowest.clone(),
            });
        };

        let mut state = self.lock();
        state.sweep(quotas);
        for (scope, quota) in &limits {
            let counter = state
                .counters
                .entry(scope.clone())
                .or_insert_with(|| Counter::new(quota));
            counter.observe(quota);
            let counted = counter.counted();
            if counter
                .used_bytes
                .saturating_add(counted)
                .saturating_add(bytes)
                > quota.limit_bytes
            {
                return Admission::Refused(QuotaRefusal::Exceeded {
                    scope: scope.clone(),
                    limit_bytes: quota.limit_bytes,
                    used_bytes: counter.used_bytes,
                    collected_at: counter.collected_at,
                    counted_bytes: counted,
                    write_bytes: bytes,
                });
            }
        }
        let scopes: Vec<QuotaScope> = limits.into_iter().map(|(scope, _)| scope).collect();
        for scope in &scopes {
            if let Some(counter) = state.counters.get_mut(scope) {
                counter.in_flight = counter.in_flight.saturating_add(bytes);
            }
        }
        drop(state);
        Admission::Reserved(Arc::new(QuotaReservation {
            ledger: Arc::clone(self),
            scopes,
            bytes,
            settled: AtomicBool::new(false),
        }))
    }

    /// Bytes this replica counts against `scope` right now: in flight plus completed and
    /// not yet covered by a collection. `None` when it counts nothing there.
    #[must_use]
    pub fn counted(&self, scope: &QuotaScope) -> Option<u64> {
        self.lock().counters.get(scope).map(Counter::counted)
    }

    fn settle(&self, scopes: &[QuotaScope], bytes: u64, completed_at: Option<DateTime<Utc>>) {
        let mut state = self.lock();
        for scope in scopes {
            if let Some(counter) = state.counters.get_mut(scope) {
                counter.settle(bytes, completed_at);
            }
        }
    }
}

/// One admitted write's bytes, held in flight until the backend's answer settles them.
///
/// Stashed in the request extensions by the access layer and settled by the forward path,
/// like the pending audit record. Settling is idempotent, and a reservation dropped
/// unsettled is committed: a write the gateway lost track of may have landed.
#[derive(Debug)]
pub struct QuotaReservation {
    ledger: Arc<QuotaLedger>,
    scopes: Vec<QuotaScope>,
    bytes: u64,
    settled: AtomicBool,
}

impl QuotaReservation {
    /// The write was stored, or may have been: count it as completed now.
    pub fn commit(&self) {
        self.settle(Some(Utc::now()));
    }

    /// The backend refused the write: give its bytes back.
    pub fn release(&self) {
        self.settle(None);
    }

    fn settle(&self, completed_at: Option<DateTime<Utc>>) {
        if self.settled.swap(true, Ordering::AcqRel) {
            return;
        }
        self.ledger.settle(&self.scopes, self.bytes, completed_at);
    }

    #[cfg(test)]
    fn commit_at(&self, at: DateTime<Utc>) {
        self.settle(Some(at));
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        self.commit();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(secs: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(1_790_000_000 + secs, 0)
            .single()
            .expect("a valid timestamp")
    }

    fn quota(limit: u64, used: u64, collected: i64) -> QuotaSpec {
        QuotaSpec::Limit(Quota {
            limit_bytes: limit,
            used_bytes: used,
            collected_at: at(collected),
        })
    }

    const TARGET: WriteTarget<'static> = WriteTarget {
        backend: "garage",
        tenant: "acme",
        bucket: "reports",
    };

    fn bucket() -> QuotaScope {
        QuotaScope::Bucket("reports".into())
    }

    fn tenant() -> QuotaScope {
        QuotaScope::Tenant("acme".into())
    }

    fn backend() -> QuotaScope {
        QuotaScope::Backend("garage".into())
    }

    fn table(specs: &[(QuotaScope, QuotaSpec)]) -> BundleQuotas {
        BundleQuotas::new(specs.iter().cloned().collect())
    }

    fn reserved(admission: Admission) -> Arc<QuotaReservation> {
        match admission {
            Admission::Reserved(r) => r,
            other => panic!("expected a reservation, got {other:?}"),
        }
    }

    fn refused(admission: Admission) -> QuotaRefusal {
        match admission {
            Admission::Refused(r) => r,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_write_up_to_the_limit_is_admitted_and_one_byte_more_is_not() {
        let ledger = Arc::new(QuotaLedger::new());
        let quotas = table(&[(bucket(), quota(100, 40, 0))]);
        let first = reserved(ledger.admit(&quotas, &TARGET, Some(60)));
        assert_eq!(ledger.counted(&bucket()), Some(60));
        // 40 used + 60 in flight: exactly at the limit, so even one byte is too many…
        let over = refused(ledger.admit(&quotas, &TARGET, Some(1)));
        assert_eq!(
            over,
            QuotaRefusal::Exceeded {
                scope: bucket(),
                limit_bytes: 100,
                used_bytes: 40,
                collected_at: at(0),
                counted_bytes: 60,
                write_bytes: 1,
            }
        );
        // …while an empty write adds nothing and still fits.
        drop(reserved(ledger.admit(&quotas, &TARGET, Some(0))));
        let err = over.to_s3_error();
        assert_eq!(err.code().as_str(), QUOTA_EXCEEDED);
        assert_eq!(err.status_code(), Some(http::StatusCode::FORBIDDEN));
        assert_eq!(
            err.message(),
            Some("The storage quota for this bucket has been exceeded.")
        );
        assert!(over.reason().contains("held 40 bytes"), "{}", over.reason());
        drop(first);
    }

    #[test]
    fn every_level_is_checked_and_the_narrowest_exceeded_one_is_named() {
        let ledger = Arc::new(QuotaLedger::new());
        let quotas = table(&[
            (bucket(), quota(1_000, 0, 0)),
            (tenant(), quota(500, 100, 0)),
            (backend(), quota(450, 300, 0)),
        ]);
        // Room in the bucket and the tenant, not on the backend (300 + 200 > 450).
        let over = refused(ledger.admit(&quotas, &TARGET, Some(200)));
        assert!(matches!(&over, QuotaRefusal::Exceeded { scope, .. } if *scope == backend()));
        assert_eq!(
            over.to_s3_error().message(),
            Some("The organization's storage quota on this backend has been exceeded.")
        );
        let ok = reserved(ledger.admit(&quotas, &TARGET, Some(150)));
        // Counted at every level the write touches, in one step.
        for scope in [bucket(), tenant(), backend()] {
            assert_eq!(ledger.counted(&scope), Some(150), "{scope:?}");
        }
        // Another bucket of the same tenant shares the tenant and backend limits.
        let sibling = WriteTarget {
            bucket: "logs",
            ..TARGET
        };
        let over = refused(ledger.admit(&quotas, &sibling, Some(1)));
        assert!(matches!(&over, QuotaRefusal::Exceeded { scope, .. } if *scope == backend()));
        drop(ok);
    }

    #[test]
    fn no_quota_means_no_enforcement_and_nothing_counted() {
        let ledger = Arc::new(QuotaLedger::new());
        let none = table(&[]);
        assert!(none.is_empty());
        assert!(matches!(
            ledger.admit(&none, &TARGET, Some(u64::MAX)),
            Admission::Unlimited
        ));
        // Not even an unstated size is a problem where nothing is limited.
        assert!(matches!(
            ledger.admit(&none, &TARGET, None),
            Admission::Unlimited
        ));
        // A limit on another bucket does not reach this one.
        let elsewhere = table(&[(QuotaScope::Bucket("logs".into()), quota(0, 0, 0))]);
        assert!(!elsewhere.applies_to(&TARGET));
        assert!(matches!(
            ledger.admit(&elsewhere, &TARGET, Some(10)),
            Admission::Unlimited
        ));
        assert_eq!(ledger.counted(&bucket()), None);
    }

    #[test]
    fn an_unreadable_quota_or_an_unstated_size_refuses_the_write() {
        let ledger = Arc::new(QuotaLedger::new());
        let broken = table(&[
            (bucket(), quota(100, 0, 0)),
            (
                tenant(),
                QuotaSpec::Unreadable("used_bytes is negative".into()),
            ),
        ]);
        let refusal = refused(ledger.admit(&broken, &TARGET, Some(1)));
        assert!(matches!(&refusal, QuotaRefusal::Unreadable { scope, .. } if *scope == tenant()));
        assert_eq!(*refusal.to_s3_error().code(), S3ErrorCode::AccessDenied);

        let quotas = table(&[(bucket(), quota(100, 0, 0))]);
        let refusal = refused(ledger.admit(&quotas, &TARGET, None));
        assert_eq!(refusal, QuotaRefusal::UnknownSize { scope: bucket() });
        assert_eq!(
            *refusal.to_s3_error().code(),
            S3ErrorCode::MissingContentLength
        );
        assert_eq!(
            ledger.counted(&bucket()),
            None,
            "a refusal reserves nothing"
        );
    }

    #[test]
    fn a_newer_collection_drops_what_it_covers_and_keeps_what_it_does_not() {
        let ledger = Arc::new(QuotaLedger::new());
        let first = table(&[(bucket(), quota(100, 0, 0))]);
        reserved(ledger.admit(&first, &TARGET, Some(30))).commit_at(at(10));
        reserved(ledger.admit(&first, &TARGET, Some(20))).commit_at(at(20));
        let pending = reserved(ledger.admit(&first, &TARGET, Some(10)));
        assert_eq!(ledger.counted(&bucket()), Some(60));

        // Collected at 15: it saw the 30-byte write (done at 10), not the 20-byte one (done
        // at 20) nor the one still in flight.
        let second = table(&[(bucket(), quota(100, 30, 15))]);
        let refusal = refused(ledger.admit(&second, &TARGET, Some(41)));
        assert!(
            matches!(
                refusal,
                QuotaRefusal::Exceeded {
                    used_bytes: 30,
                    counted_bytes: 30,
                    ..
                }
            ),
            "{refusal:?}"
        );
        assert_eq!(ledger.counted(&bucket()), Some(30));
        let fits = reserved(ledger.admit(&second, &TARGET, Some(40)));
        fits.release();

        // A request still pinned to the older revision does not turn the basis back: it is
        // checked against the newer collection.
        let refusal = refused(ledger.admit(&first, &TARGET, Some(41)));
        assert!(
            matches!(refusal, QuotaRefusal::Exceeded { used_bytes: 30, .. }),
            "{refusal:?}"
        );

        // The in-flight write completes after the next collection, which therefore keeps it.
        pending.commit_at(at(40));
        let third = table(&[(bucket(), quota(100, 50, 30))]);
        drop(reserved(ledger.admit(&third, &TARGET, Some(0))));
        assert_eq!(ledger.counted(&bucket()), Some(10));
    }

    #[test]
    fn a_write_completed_within_the_collections_second_is_kept() {
        let ledger = Arc::new(QuotaLedger::new());
        let first = table(&[(bucket(), quota(100, 0, 0))]);
        let r = reserved(ledger.admit(&first, &TARGET, Some(5)));
        r.commit_at(at(10) + chrono::Duration::milliseconds(300));
        // Collected at 10.000: the write landed 300 ms later, so it must still count.
        let second = table(&[(bucket(), quota(100, 0, 10))]);
        drop(reserved(ledger.admit(&second, &TARGET, Some(0))));
        assert_eq!(ledger.counted(&bucket()), Some(5));
        // Collected at 11: every write of the second ending at 11 is covered.
        let third = table(&[(bucket(), quota(100, 5, 11))]);
        drop(reserved(ledger.admit(&third, &TARGET, Some(0))));
        assert_eq!(ledger.counted(&bucket()), Some(0));
    }

    #[test]
    fn a_release_gives_the_bytes_back_and_a_drop_commits_them() {
        let ledger = Arc::new(QuotaLedger::new());
        let quotas = table(&[(bucket(), quota(100, 0, 0))]);
        let refused_upstream = reserved(ledger.admit(&quotas, &TARGET, Some(70)));
        refused_upstream.release();
        assert_eq!(ledger.counted(&bucket()), Some(0));
        // Idempotent: a later commit, or the drop, does not count it again.
        refused_upstream.commit();
        drop(refused_upstream);
        assert_eq!(ledger.counted(&bucket()), Some(0));

        let lost = reserved(ledger.admit(&quotas, &TARGET, Some(70)));
        drop(lost);
        assert_eq!(
            ledger.counted(&bucket()),
            Some(70),
            "a write nobody settled may have landed, so it stays counted"
        );
        assert!(matches!(
            ledger.admit(&quotas, &TARGET, Some(31)),
            Admission::Refused(QuotaRefusal::Exceeded { .. })
        ));
    }

    #[test]
    fn concurrent_writers_on_one_replica_never_share_the_last_bytes() {
        let ledger = Arc::new(QuotaLedger::new());
        let quotas = Arc::new(table(&[
            (bucket(), quota(1_000, 0, 0)),
            (tenant(), quota(10_000, 0, 0)),
        ]));
        let barrier = Arc::new(std::sync::Barrier::new(64));
        let handles: Vec<_> = (0..64)
            .map(|_| {
                let (ledger, quotas, barrier) = (ledger.clone(), quotas.clone(), barrier.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    (0..10)
                        .filter_map(|_| match ledger.admit(&quotas, &TARGET, Some(7)) {
                            Admission::Reserved(r) => Some(r),
                            _ => None,
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let held: Vec<Arc<QuotaReservation>> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("writer thread"))
            .collect();
        // 1000 / 7 = 142 writes fit, and not one more, however the threads interleaved.
        assert_eq!(held.len(), 142);
        assert_eq!(ledger.counted(&bucket()), Some(142 * 7));
        assert_eq!(ledger.counted(&tenant()), Some(142 * 7));
        drop(held);
    }

    #[test]
    fn settled_slots_stay_bounded_and_only_ever_err_toward_counting() {
        let ledger = Arc::new(QuotaLedger::new());
        let quotas = table(&[(bucket(), quota(u64::MAX, 0, 0))]);
        let n = MAX_SETTLED_SLOTS as i64 + 50;
        for second in 1..=n {
            reserved(ledger.admit(&quotas, &TARGET, Some(1))).commit_at(at(second));
        }
        {
            let state = ledger.lock();
            let counter = state.counters.get(&bucket()).expect("counter");
            assert_eq!(counter.settled.len(), MAX_SETTLED_SLOTS);
            assert_eq!(counter.settled_bytes, n as u64);
        }
        // A collection that covers the first 50 seconds drops nothing that is folded into a
        // later slot: the folded bytes are kept until the later stamp is covered.
        let later = table(&[(bucket(), quota(u64::MAX, 50, 50))]);
        drop(reserved(ledger.admit(&later, &TARGET, Some(0))));
        assert_eq!(ledger.counted(&bucket()), Some(n as u64));
    }

    #[test]
    fn a_newer_revision_forgets_levels_with_no_limit_and_nothing_counted() {
        let ledger = Arc::new(QuotaLedger::new());
        let first = table(&[(bucket(), quota(100, 0, 0)), (tenant(), quota(100, 0, 0))]);
        reserved(ledger.admit(&first, &TARGET, Some(10))).commit_at(at(5));
        let in_flight = reserved(ledger.admit(&first, &TARGET, Some(1)));
        let logs = WriteTarget {
            bucket: "logs",
            ..TARGET
        };
        let logs_only =
            |collected| table(&[(QuotaScope::Bucket("logs".into()), quota(100, 0, collected))]);

        // A revision that limits neither level: both counters survive while a write is in
        // flight against them…
        drop(reserved(ledger.admit(&logs_only(6), &logs, Some(0))));
        assert_eq!(ledger.counted(&bucket()), Some(11));
        assert_eq!(ledger.counted(&tenant()), Some(11));

        // …and are forgotten by the next one once nothing is.
        in_flight.release();
        drop(reserved(ledger.admit(&logs_only(7), &logs, Some(0))));
        assert_eq!(ledger.counted(&bucket()), None);
        assert_eq!(ledger.counted(&tenant()), None);
    }

    #[test]
    fn a_quota_object_is_read_exactly_as_the_contract_pins_it() {
        let ok = serde_json::json!({
            "limit_bytes": 107_374_182_400_u64,
            "used_bytes": 0,
            "collected_at": "2026-10-01T12:00:00Z"
        });
        assert_eq!(
            QuotaSpec::read(Some(&ok)),
            Some(QuotaSpec::Limit(Quota {
                limit_bytes: 107_374_182_400,
                used_bytes: 0,
                collected_at: DateTime::parse_from_rfc3339("2026-10-01T12:00:00Z")
                    .expect("rfc3339")
                    .with_timezone(&Utc),
            }))
        );
        assert_eq!(QuotaSpec::read(None), None);
        assert_eq!(QuotaSpec::read(Some(&serde_json::Value::Null)), None);
        for broken in [
            serde_json::json!(5),
            serde_json::json!({ "used_bytes": 0, "collected_at": "2026-10-01T12:00:00Z" }),
            serde_json::json!({ "limit_bytes": -1, "used_bytes": 0,
                                "collected_at": "2026-10-01T12:00:00Z" }),
            serde_json::json!({ "limit_bytes": 1.5, "used_bytes": 0,
                                "collected_at": "2026-10-01T12:00:00Z" }),
            serde_json::json!({ "limit_bytes": 1, "used_bytes": "0",
                                "collected_at": "2026-10-01T12:00:00Z" }),
            serde_json::json!({ "limit_bytes": 1, "used_bytes": 0 }),
            serde_json::json!({ "limit_bytes": 1, "used_bytes": 0, "collected_at": "yesterday" }),
        ] {
            assert!(
                matches!(
                    QuotaSpec::read(Some(&broken)),
                    Some(QuotaSpec::Unreadable(_))
                ),
                "{broken} must be unreadable, never absent"
            );
        }
    }
}
