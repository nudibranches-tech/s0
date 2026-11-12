//! Limits and abuse resistance for the SFTP front (ADR-012 D12).
//!
//! Everything here is **per replica**. Counters live in memory, so a restart forgets them
//! and an attacker spread across `R` replicas gets `R` times the budget — a bound written
//! down rather than hidden. Fleet-wide blocks travel through the bundle
//! (`data.sftp.denied_source_cidrs`), which every replica already polls.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// An IPv4 or IPv6 network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    addr: IpAddr,
    len: u8,
}

impl Cidr {
    /// `"203.0.113.0/24"`, `"2001:db8::/32"`, or a bare address (a host route).
    pub fn parse(s: &str) -> Result<Self, String> {
        let (a, l) = match s.split_once('/') {
            Some((a, l)) => (a, Some(l)),
            None => (s, None),
        };
        let addr: IpAddr = a
            .trim()
            .parse()
            .map_err(|e| format!("{s:?} is not an address: {e}"))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let len = match l {
            None => max,
            Some(l) => l
                .trim()
                .parse::<u8>()
                .ok()
                .filter(|l| *l <= max)
                .ok_or_else(|| format!("{s:?} has an invalid prefix length"))?,
        };
        Ok(Cidr { addr, len })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        match (self.addr, ip) {
            (IpAddr::V4(n), IpAddr::V4(a)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.len))
                };
                (u32::from(n) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(n), IpAddr::V6(a)) => {
                let mask = if self.len == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.len))
                };
                (u128::from(n) & mask) == (u128::from(a) & mask)
            }
            _ => false,
        }
    }
}

/// An IPv4-mapped IPv6 address is its IPv4 address, so one client cannot be two buckets.
pub fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(IpAddr::V6(v6), IpAddr::V4),
        v4 => v4,
    }
}

/// The per-client bucket: an IPv4 /32, or an IPv6 /64 (one subscriber's allocation).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpBucket {
    V4(u32),
    V6(u64),
}

impl IpBucket {
    pub fn of(ip: IpAddr) -> Self {
        match canonical(ip) {
            IpAddr::V4(a) => IpBucket::V4(u32::from(a)),
            IpAddr::V6(a) => IpBucket::V6((u128::from(a) >> 64) as u64),
        }
    }
}

pub fn any_contains(cidrs: &[Cidr], ip: IpAddr) -> bool {
    cidrs.iter().any(|c| c.contains(ip))
}

/// Process-wide and per-IP connection counts. The guard releases on drop.
#[derive(Default)]
pub struct ConnectionTracker {
    inner: Mutex<(usize, HashMap<IpBucket, usize>)>,
}

pub struct ConnectionGuard {
    tracker: Arc<ConnectionTracker>,
    bucket: IpBucket,
}

impl ConnectionTracker {
    /// Admit one connection, or say which cap refused it.
    pub fn admit(
        self: &Arc<Self>,
        ip: IpAddr,
        max_total: usize,
        max_per_ip: usize,
    ) -> Result<ConnectionGuard, &'static str> {
        let bucket = IpBucket::of(ip);
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.0 >= max_total {
            return Err("connection limit reached");
        }
        let n = g.1.entry(bucket).or_insert(0);
        if *n >= max_per_ip {
            return Err("per-address connection limit reached");
        }
        *n += 1;
        g.0 += 1;
        Ok(ConnectionGuard {
            tracker: self.clone(),
            bucket,
        })
    }

    pub fn active(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).0
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        let mut g = self.tracker.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.0 = g.0.saturating_sub(1);
        if let Some(n) = g.1.get_mut(&self.bucket) {
            *n -= 1;
            if *n == 0 {
                g.1.remove(&self.bucket);
            }
        }
    }
}

/// Authenticated sessions per subject.
#[derive(Default)]
pub struct SubjectSessions {
    inner: Mutex<HashMap<String, usize>>,
}

pub struct SubjectGuard {
    owner: Arc<SubjectSessions>,
    subject: String,
}

impl SubjectSessions {
    pub fn admit(self: &Arc<Self>, subject: &str, max: usize) -> Option<SubjectGuard> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let n = g.entry(subject.to_string()).or_insert(0);
        if *n >= max {
            return None;
        }
        *n += 1;
        Some(SubjectGuard {
            owner: self.clone(),
            subject: subject.to_string(),
        })
    }
}

impl Drop for SubjectGuard {
    fn drop(&mut self) {
        let mut g = self.owner.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = g.get_mut(&self.subject) {
            *n -= 1;
            if *n == 0 {
                g.remove(&self.subject);
            }
        }
    }
}

/// One address's authentication-failure history and ban.
struct BanEntry {
    failures: Vec<Instant>,
    banned_until: Option<Instant>,
    last_seen: Instant,
}

/// Failures-in-a-window ⇒ ban, per /32 or /64, LRU-bounded.
#[derive(Default)]
pub struct BanTable {
    inner: Mutex<HashMap<IpBucket, BanEntry>>,
}

/// The ban-table parameters, read from the hot-reloadable limits at the point of use.
#[derive(Debug, Clone, Copy)]
pub struct BanPolicy {
    pub threshold: u32,
    pub window: Duration,
    pub ban: Duration,
    pub capacity: usize,
}

impl BanTable {
    pub fn is_banned(&self, ip: IpAddr, now: Instant) -> bool {
        let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.get(&IpBucket::of(ip))
            .and_then(|e| e.banned_until)
            .is_some_and(|until| now < until)
    }

    /// Record one failure. Returns true when this failure triggered a new ban.
    pub fn record_failure(&self, ip: IpAddr, now: Instant, policy: BanPolicy) -> bool {
        let bucket = IpBucket::of(ip);
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !g.contains_key(&bucket) && g.len() >= policy.capacity {
            // Evict the least recently seen entry. A full table of live bans evicts the
            // oldest ban — the documented cost of a bounded table under a wide flood.
            if let Some(oldest) = g.iter().min_by_key(|(_, e)| e.last_seen).map(|(k, _)| *k) {
                g.remove(&oldest);
            }
        }
        let e = g.entry(bucket).or_insert_with(|| BanEntry {
            failures: Vec::new(),
            banned_until: None,
            last_seen: now,
        });
        e.last_seen = now;
        e.failures
            .retain(|t| now.duration_since(*t) < policy.window);
        e.failures.push(now);
        let already = e.banned_until.is_some_and(|u| now < u);
        if !already && e.failures.len() as u32 >= policy.threshold {
            e.banned_until = Some(now + policy.ban);
            e.failures.clear();
            return true;
        }
        false
    }
}

/// Per-IP token bucket for pre-authentication connections, LRU-bounded.
#[derive(Default)]
pub struct PreauthRate {
    inner: Mutex<HashMap<IpBucket, (f64, Instant)>>,
}

impl PreauthRate {
    /// Take one token. `per_min` refills, `burst` caps.
    pub fn allow(
        &self,
        ip: IpAddr,
        now: Instant,
        per_min: u32,
        burst: u32,
        capacity: usize,
    ) -> bool {
        let bucket = IpBucket::of(ip);
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if !g.contains_key(&bucket) && g.len() >= capacity {
            if let Some(oldest) = g.iter().min_by_key(|(_, (_, t))| *t).map(|(k, _)| *k) {
                g.remove(&oldest);
            }
        }
        let (tokens, last) = g.entry(bucket).or_insert((f64::from(burst), now));
        let refill = now.duration_since(*last).as_secs_f64() * f64::from(per_min) / 60.0;
        *tokens = (*tokens + refill).min(f64::from(burst));
        *last = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The process-wide transfer-memory budget (ADR-012 D9). A write OPEN reserves its
/// transfer's worst case up front, so a transfer can never run out of memory halfway.
pub struct MemoryBudget {
    sem: Arc<Semaphore>,
}

/// Units of 1 KiB, so a 1 GiB budget fits the semaphore's u32 acquisition width.
const UNIT: usize = 1024;

impl MemoryBudget {
    pub fn new(bytes: usize) -> Self {
        MemoryBudget {
            sem: Arc::new(Semaphore::new(bytes.div_ceil(UNIT))),
        }
    }

    /// Reserve `bytes`, waiting at most `wait`.
    pub async fn reserve(&self, bytes: usize, wait: Duration) -> Option<OwnedSemaphorePermit> {
        let units = u32::try_from(bytes.div_ceil(UNIT)).ok()?;
        tokio::time::timeout(wait, self.sem.clone().acquire_many_owned(units))
            .await
            .ok()?
            .ok()
    }
}

/// The optional process-wide bandwidth cap (ADR-012 D12,
/// `limits.sftp.process_bandwidth_bytes_per_sec`): one bucket per direction, shared by
/// every session of the replica, so uploads and downloads are each held to the rate.
#[derive(Default)]
pub struct ProcessBandwidth {
    pub upload: TokenBucket,
    pub download: TokenBucket,
}

/// A token bucket that is charged **after** the bytes moved and answers how long the
/// caller must wait before moving more.
///
/// The level may go negative: a charge is never refused, it turns into debt, and the
/// caller sleeps until its share of that debt has been repaid at `rate`. Two properties
/// follow, and they are why this shape was chosen over a bucket sessions poll or a
/// semaphore they queue on:
///
/// * **Fair without a scheduler.** Each charge is one reply's worth of bytes (at most
///   `max_sftp_packet_len`), and a session charges only after the reply it is paying for,
///   then sleeps before it reads its next request. So a session holds at most one small
///   grant of debt at a time, and its wait is fixed when it charges: a later charge by
///   another session queues *behind* it and cannot lengthen it. Charges are served in
///   arrival order, every session gets its turn about once per round of the others'
///   small grants, and none can be starved, however many bytes it or the others move.
/// * **Bounded burst.** The level never exceeds one second of `rate`, so an idle stretch
///   banks at most one second of traffic.
///
/// The rate is passed on every charge rather than stored, so a hot reload of the limit
/// takes effect at the next charge: outstanding debt is in bytes and is simply repaid at
/// the new rate, and the burst ceiling follows the new rate. `rate == 0` is unlimited.
#[derive(Default)]
pub struct TokenBucket {
    state: Mutex<BucketState>,
}

#[derive(Default)]
struct BucketState {
    /// Bytes available; negative is debt.
    level: f64,
    /// When `level` was last brought up to date.
    last: Option<Instant>,
    /// The rate `level` was last accrued at; 0 when the cap was off.
    rate: u64,
}

impl TokenBucket {
    /// The most credit an idle stretch can bank.
    pub const MAX_BURST: Duration = Duration::from_secs(1);

    /// Charge `bytes` at `now` against `rate` bytes per second; returns how long the
    /// caller must wait before moving more (zero when within budget).
    pub fn charge(&self, bytes: u64, rate: u64, now: Instant) -> Duration {
        let mut s = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if rate == 0 {
            // Off: forget everything, so switching it back on starts with a full bucket.
            *s = BucketState::default();
            return Duration::ZERO;
        }
        let r = rate as f64;
        let cap = r * Self::MAX_BURST.as_secs_f64();
        match s.last {
            // First use, or the cap was just switched back on: start full.
            None => s.level = cap,
            // Accrue at the rate in force until now (a reload is seen at a charge).
            Some(last) => {
                let elapsed = now.saturating_duration_since(last).as_secs_f64();
                s.level += elapsed * s.rate as f64;
            }
        }
        s.level = s.level.min(cap);
        s.last = Some(s.last.map_or(now, |l| l.max(now)));
        s.rate = rate;
        s.level -= bytes as f64;
        if s.level >= 0.0 {
            Duration::ZERO
        } else {
            Duration::from_secs_f64(-s.level / r)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn cidrs_match_v4_v6_and_mapped() {
        let c = Cidr::parse("203.0.113.0/24").unwrap();
        assert!(c.contains(ip("203.0.113.10")));
        assert!(!c.contains(ip("203.0.114.10")));
        assert!(
            c.contains(ip("::ffff:203.0.113.9")),
            "a v4-mapped v6 is the v4 address"
        );
        let c6 = Cidr::parse("2001:db8::/32").unwrap();
        assert!(c6.contains(ip("2001:db8:1::1")));
        assert!(!c6.contains(ip("203.0.113.10")));
        assert!(Cidr::parse("10.0.0.0/33").is_err());
        assert!(Cidr::parse("nope").is_err());
        assert!(Cidr::parse("0.0.0.0/0").unwrap().contains(ip("8.8.8.8")));
    }

    #[test]
    fn v6_clients_are_bucketed_by_64() {
        assert_eq!(
            IpBucket::of(ip("2001:db8:0:1::1")),
            IpBucket::of(ip("2001:db8:0:1::ffff"))
        );
        assert_ne!(
            IpBucket::of(ip("2001:db8:0:1::1")),
            IpBucket::of(ip("2001:db8:0:2::1"))
        );
    }

    #[test]
    fn connection_caps_release_on_drop() {
        let t = Arc::new(ConnectionTracker::default());
        let a = t.admit(ip("192.0.2.1"), 2, 1).unwrap();
        assert!(t.admit(ip("192.0.2.1"), 2, 1).is_err(), "per-ip");
        let _b = t.admit(ip("192.0.2.2"), 2, 1).unwrap();
        assert!(t.admit(ip("192.0.2.3"), 2, 1).is_err(), "total");
        drop(a);
        assert!(t.admit(ip("192.0.2.1"), 2, 1).is_ok());
    }

    #[test]
    fn failures_in_a_window_ban_and_the_ban_expires() {
        let t = BanTable::default();
        let p = BanPolicy {
            threshold: 3,
            window: Duration::from_secs(300),
            ban: Duration::from_secs(900),
            capacity: 8,
        };
        let now = Instant::now();
        assert!(!t.record_failure(ip("192.0.2.1"), now, p));
        assert!(!t.record_failure(ip("192.0.2.1"), now, p));
        assert!(t.record_failure(ip("192.0.2.1"), now, p));
        assert!(t.is_banned(ip("192.0.2.1"), now));
        assert!(!t.is_banned(ip("192.0.2.2"), now));
        assert!(!t.is_banned(ip("192.0.2.1"), now + Duration::from_secs(901)));
    }

    #[test]
    fn the_preauth_bucket_refills() {
        let r = PreauthRate::default();
        let now = Instant::now();
        assert!(r.allow(ip("192.0.2.1"), now, 60, 2, 8));
        assert!(r.allow(ip("192.0.2.1"), now, 60, 2, 8));
        assert!(!r.allow(ip("192.0.2.1"), now, 60, 2, 8));
        assert!(r.allow(ip("192.0.2.1"), now + Duration::from_secs(1), 60, 2, 8));
    }

    #[tokio::test]
    async fn memory_is_reserved_up_front_and_returned() {
        let b = MemoryBudget::new(10 * 1024);
        let p = b
            .reserve(8 * 1024, Duration::from_millis(10))
            .await
            .unwrap();
        assert!(
            b.reserve(8 * 1024, Duration::from_millis(10))
                .await
                .is_none()
        );
        drop(p);
        assert!(
            b.reserve(8 * 1024, Duration::from_millis(10))
                .await
                .is_some()
        );
    }
    #[test]
    fn the_process_bucket_holds_the_rate_and_bounds_the_burst() {
        let b = TokenBucket::default();
        let t0 = Instant::now();
        // A full bucket: one second of traffic passes unheld, then debt is paced.
        assert_eq!(b.charge(1_000, 1_000, t0), Duration::ZERO);
        assert_eq!(b.charge(500, 1_000, t0), Duration::from_millis(500));
        // A second charge at the same instant queues behind the first.
        assert_eq!(b.charge(500, 1_000, t0), Duration::from_secs(1));
        // An hour idle banks one second, not an hour.
        let later = t0 + Duration::from_secs(3600);
        assert_eq!(b.charge(1_000, 1_000, later), Duration::ZERO);
        assert_eq!(b.charge(2_000, 1_000, later), Duration::from_secs(2));
    }

    #[test]
    fn the_process_bucket_over_time_moves_rate_bytes_per_second() {
        // Many small charges from "several sessions", each sleeping its answer: the
        // total after ten seconds is ten seconds of rate plus the one-second burst.
        let b = TokenBucket::default();
        let t0 = Instant::now();
        let mut ready = [t0; 4];
        let mut moved = 0u64;
        let end = t0 + Duration::from_secs(10);
        loop {
            let (i, &now) = ready.iter().enumerate().min_by_key(|(_, t)| **t).unwrap();
            if now >= end {
                break;
            }
            moved += 100;
            ready[i] = now + b.charge(100, 1_000, now);
        }
        // Up to one 100-byte charge per session may be in flight past the end.
        assert!((11_000..=11_400).contains(&moved), "{moved}");
    }

    #[test]
    fn the_process_bucket_follows_a_hot_reload() {
        let b = TokenBucket::default();
        let t0 = Instant::now();
        assert_eq!(b.charge(3_000, 1_000, t0), Duration::from_secs(2));
        // The rate doubled: the 2,000-byte debt is repaid at the new rate.
        assert_eq!(b.charge(0, 2_000, t0), Duration::from_secs(1));
        // Lowered: the burst ceiling follows (one second of the new rate).
        let later = t0 + Duration::from_secs(60);
        assert_eq!(b.charge(100, 100, later), Duration::ZERO);
        assert_eq!(b.charge(100, 100, later), Duration::from_secs(1));
        // Switched off, then on again: unlimited meanwhile, then a fresh full bucket.
        assert_eq!(b.charge(1_000_000, 0, later), Duration::ZERO);
        assert_eq!(b.charge(100, 100, later), Duration::ZERO);
    }
}
