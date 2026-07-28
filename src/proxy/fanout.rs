//! Multi-prefix list fan-out (ADR-004). A subject scoped to several object prefixes
//! issuing an unbounded `ListObjects` cannot be expressed as one S3 `prefix` param.
//!
//! Key insight: the granted prefixes are **sorted and disjoint**, so every key under
//! `2024/` sorts before every key under `2025/`. The merged listing is therefore a
//! plain **concatenation** in prefix order — no re-sort — and a **single resume key**
//! (S3-native `start_after`/`marker`) is enough to paginate across all of them. That
//! keeps the cursor backend-agnostic and the gateway stateless.
//!
//! This module is the pure, backend-independent core: it drives an injected `lister`
//! (the backend LIST call in production, a fake in tests) and merges + paginates.

use std::future::Future;

/// A gateway-owned continuation cursor. `scope_hash` binds the cursor to the exact
/// granted-prefix set, so a grant change between pages is detected rather than
/// silently serving a stale scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// Lowercase hex SHA-256 of the granted-prefix set — see [`scope_hash`].
    pub scope_hash: String,
    pub last_key: String,
}

impl Cursor {
    pub fn encode(&self) -> String {
        format!("v1.{}.{}", self.scope_hash, hex::encode(&self.last_key))
    }

    pub fn decode(s: &str) -> Option<Cursor> {
        let mut parts = s.splitn(3, '.');
        if parts.next()? != "v1" {
            return None;
        }
        // Validate the shape rather than accepting any token: a cursor whose scope
        // half is not a hash cannot match a real scope, so it must be rejected as
        // malformed instead of silently failing the scope comparison later.
        let scope_hash = parts.next()?;
        if scope_hash.len() != 64 || !scope_hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let last_key = String::from_utf8(hex::decode(parts.next()?).ok()?).ok()?;
        Some(Cursor {
            scope_hash: scope_hash.to_string(),
            last_key,
        })
    }
}

/// Bind a cursor to the exact prefix set it was issued against.
///
/// **SHA-256, not `DefaultHasher`.** `DefaultHasher` is not stable across Rust
/// releases: a rebuild on a different toolchain re-hashes the same grants to a
/// different value, so every outstanding list cursor is rejected mid-rollout — and,
/// while two replicas of a rolling update run different toolchains, whether a cursor
/// survives depends on which pod answers. Pinned by `tests/golden_hash.rs`.
///
/// The encoding is length-prefixed so the prefix set is unambiguous: `["a", "b"]`
/// and `["ab"]` must not hash alike, or a grant change would go undetected.
pub fn scope_hash(prefixes: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"s0.fanout.scope.v1\n");
    h.update((prefixes.len() as u64).to_be_bytes());
    for p in prefixes {
        h.update((p.len() as u64).to_be_bytes());
        h.update(p.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Obligation stashed by the access layer (in the request extensions) when a list is
/// allowed but spans multiple granted prefixes, and read by the dispatcher to fan out.
#[derive(Debug, Clone)]
pub struct ListFanout {
    pub prefixes: Vec<String>,
}

/// One page of a fanned-out listing.
pub struct Page<T> {
    pub items: Vec<T>,
    pub truncated: bool,
    pub next: Option<Cursor>,
}

/// Fan out over sorted, disjoint `prefixes`, resuming after `cursor` if given, and
/// return one page of at most `max_keys` items.
///
/// `lister(prefix, start_after, limit)` returns `(items, sub_truncated)`: up to `limit`
/// items whose key is strictly greater than `start_after`, in ascending key order, plus
/// whether the backend has **more** keys under this prefix beyond what it returned — i.e.
/// exactly S3 `ListObjectsV2(prefix, start_after, max_keys=limit)`'s `Contents` +
/// `IsTruncated`.
///
/// A backend may legally return **fewer** than `limit` keys while still being truncated
/// ("the response might contain fewer keys but will never contain more"). We therefore
/// paginate *within* a prefix on the lister's own `sub_truncated` flag, never inferring
/// exhaustion from a short page — otherwise authorized keys silently vanish from the
/// listing (a backend-agnostic-correctness bug, §6.7).
///
/// Returns `Err` if the cursor's `scope_hash` no longer matches the grants (client
/// must restart the listing).
pub async fn fan_out<T, F, Fut>(
    prefixes: &[String],
    cursor: Option<Cursor>,
    max_keys: usize,
    key_of: impl Fn(&T) -> String,
    mut lister: F,
) -> std::result::Result<Page<T>, &'static str>
where
    F: FnMut(String, Option<String>, usize) -> Fut,
    Fut: Future<Output = (Vec<T>, bool)>,
{
    let hash = scope_hash(prefixes);
    let mut resume = match cursor {
        Some(c) if c.scope_hash != hash => return Err("grant scope changed; restart listing"),
        Some(c) => Some(c.last_key),
        None => None,
    };

    let mut items: Vec<T> = Vec::new();
    let mut truncated = false;

    'outer: for prefix in prefixes {
        // Establish the resume point for this prefix: skip prefixes fully before the
        // resume key; resume the one that contains it.
        let mut start_after = match &resume {
            Some(rk) => {
                if rk.starts_with(prefix.as_str()) {
                    let sa = Some(rk.clone());
                    resume = None;
                    sa
                } else {
                    continue; // resume key is under a later prefix
                }
            }
            None => None,
        };

        // Paginate WITHIN this prefix until the page fills or the prefix is genuinely
        // exhausted (lister reports not-truncated). A short-but-truncated page loops.
        loop {
            let remaining = max_keys - items.len();
            if remaining == 0 {
                truncated = true;
                break 'outer;
            }
            let (batch, sub_truncated) =
                lister(prefix.clone(), start_after.take(), remaining).await;
            let got = batch.len();
            items.extend(batch.into_iter().take(remaining));
            if items.len() >= max_keys {
                // Page is full; there may be more (in this prefix or later ones).
                truncated = true;
                break 'outer;
            }
            // Whole batch consumed and the page is not yet full.
            if sub_truncated && got > 0 {
                // Backend short-paged; continue this prefix after the last key seen.
                start_after = items.last().map(&key_of);
                continue;
            }
            // Prefix exhausted (or returned nothing) ⇒ move to the next prefix.
            break;
        }
    }

    let next = if truncated {
        items.last().map(|last| Cursor {
            scope_hash: hash,
            last_key: key_of(last),
        })
    } else {
        None
    };
    Ok(Page {
        items,
        truncated,
        next,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// A fake backend: prefix -> sorted keys. Returns keys strictly greater than
    /// start_after, capped at limit, plus `is_truncated` — exactly S3 ListObjectsV2
    /// semantics. `page_cap` optionally forces a *short* page (returns at most `page_cap`
    /// keys per call even when more match and `limit` is higher) to exercise the
    /// short-but-truncated backend behavior.
    fn fake_paged(
        store: BTreeMap<&'static str, Vec<&'static str>>,
        page_cap: usize,
    ) -> impl Fn(String, Option<String>, usize) -> std::future::Ready<(Vec<String>, bool)> {
        move |prefix: String, start_after: Option<String>, limit: usize| {
            let keys = store.get(prefix.as_str()).cloned().unwrap_or_default();
            let matching: Vec<String> = keys
                .into_iter()
                .filter(|k| match &start_after {
                    Some(sa) => *k > sa.as_str(),
                    None => true,
                })
                .map(String::from)
                .collect();
            let take = limit.min(page_cap);
            let truncated = matching.len() > take;
            let out: Vec<String> = matching.into_iter().take(take).collect();
            std::future::ready((out, truncated))
        }
    }

    /// A conforming backend that fills `limit` whenever enough keys match.
    fn fake(
        store: BTreeMap<&'static str, Vec<&'static str>>,
    ) -> impl Fn(String, Option<String>, usize) -> std::future::Ready<(Vec<String>, bool)> {
        fake_paged(store, usize::MAX)
    }

    #[tokio::test]
    async fn single_page_concatenates_in_prefix_order() {
        let store = BTreeMap::from([
            ("2024/", vec!["2024/a", "2024/b"]),
            ("2025/", vec!["2025/a"]),
        ]);
        let prefixes = vec!["2024/".to_string(), "2025/".to_string()];
        let page = fan_out(&prefixes, None, 100, |k: &String| k.clone(), fake(store))
            .await
            .unwrap();
        assert_eq!(page.items, vec!["2024/a", "2024/b", "2025/a"]);
        assert!(!page.truncated);
        assert!(page.next.is_none());
    }

    #[tokio::test]
    async fn paginates_across_prefixes_with_single_resume_key() {
        let store = BTreeMap::from([
            ("2024/", vec!["2024/a", "2024/b", "2024/c"]),
            ("2025/", vec!["2025/a", "2025/b"]),
        ]);
        let prefixes = vec!["2024/".to_string(), "2025/".to_string()];

        // Page 1: max 2 -> first two of 2024/, truncated, cursor at 2024/b.
        let p1 = fan_out(
            &prefixes,
            None,
            2,
            |k: &String| k.clone(),
            fake(store.clone()),
        )
        .await
        .unwrap();
        assert_eq!(p1.items, vec!["2024/a", "2024/b"]);
        assert!(p1.truncated);
        let c1 = p1.next.unwrap();
        assert_eq!(c1.last_key, "2024/b");

        // Page 2: resumes mid-2024/, finishes it, crosses into 2025/.
        let p2 = fan_out(
            &prefixes,
            Some(c1),
            2,
            |k: &String| k.clone(),
            fake(store.clone()),
        )
        .await
        .unwrap();
        assert_eq!(p2.items, vec!["2024/c", "2025/a"]);
        assert!(p2.truncated);
        let c2 = p2.next.unwrap();

        // Page 3: the tail of 2025/.
        let p3 = fan_out(&prefixes, Some(c2), 2, |k: &String| k.clone(), fake(store))
            .await
            .unwrap();
        assert_eq!(p3.items, vec!["2025/b"]);
        assert!(!p3.truncated);
        assert!(p3.next.is_none());
    }

    #[tokio::test]
    async fn cursor_round_trips_through_encode_decode() {
        let c = Cursor {
            scope_hash: scope_hash(&["2024/".to_string()]),
            last_key: "2024/report.a.b".into(),
        };
        assert_eq!(Cursor::decode(&c.encode()), Some(c));
        assert!(Cursor::decode("garbage").is_none());
        // A well-formed envelope whose scope half is not a hash is malformed, not a
        // cursor for some other scope.
        assert!(Cursor::decode("v1.notahash.32303234").is_none());
    }

    #[test]
    fn scope_hash_is_unambiguous_across_prefix_boundaries() {
        // Length-prefixed, so a concatenation cannot collide with a split.
        assert_ne!(
            scope_hash(&["a".to_string(), "b".to_string()]),
            scope_hash(&["ab".to_string()])
        );
        // Order is part of the scope: the fan-out concatenates in prefix order.
        assert_ne!(
            scope_hash(&["a/".to_string(), "b/".to_string()]),
            scope_hash(&["b/".to_string(), "a/".to_string()])
        );
    }

    #[tokio::test]
    async fn scope_change_is_rejected() {
        let prefixes = vec!["2024/".to_string()];
        let stale = Cursor {
            // A cursor issued while a *different* prefix set was granted.
            scope_hash: scope_hash(&["2023/".to_string()]),
            last_key: "2024/a".into(),
        };
        let store = BTreeMap::from([("2024/", vec!["2024/a", "2024/b"])]);
        let r = fan_out(
            &prefixes,
            Some(stale),
            10,
            |k: &String| k.clone(),
            fake(store),
        )
        .await;
        assert!(r.is_err());
    }

    #[tokio::test]
    async fn short_backend_page_does_not_lose_keys() {
        // A short-but-truncated page must not be read as prefix-exhausted (else keys
        // are silently dropped).
        let store = BTreeMap::from([("2024/", vec!["2024/a", "2024/b", "2024/c", "2024/d"])]);
        let prefixes = vec!["2024/".to_string()];
        // page_cap=1: one key per backend call, though 4 match and limit is 100.
        let page = fan_out(
            &prefixes,
            None,
            100,
            |k: &String| k.clone(),
            fake_paged(store, 1),
        )
        .await
        .unwrap();
        assert_eq!(
            page.items,
            vec!["2024/a", "2024/b", "2024/c", "2024/d"],
            "short-but-truncated pages must not drop authorized keys"
        );
        assert!(!page.truncated);
        assert!(page.next.is_none());
    }

    #[tokio::test]
    async fn short_pages_cross_prefixes_and_paginate() {
        // Short pages that also span multiple prefixes, with a page limit forcing
        // truncation partway. Proves the within-prefix loop + cross-prefix resume compose.
        let store = BTreeMap::from([
            ("2024/", vec!["2024/a", "2024/b", "2024/c"]),
            ("2025/", vec!["2025/a", "2025/b"]),
        ]);
        let prefixes = vec!["2024/".to_string(), "2025/".to_string()];

        // Page of 4 with a 1-key backend cap: must gather 2024/a..c then 2025/a.
        let p1 = fan_out(
            &prefixes,
            None,
            4,
            |k: &String| k.clone(),
            fake_paged(store.clone(), 1),
        )
        .await
        .unwrap();
        assert_eq!(p1.items, vec!["2024/a", "2024/b", "2024/c", "2025/a"]);
        assert!(p1.truncated);
        let c1 = p1.next.unwrap();
        assert_eq!(c1.last_key, "2025/a");

        // Next page: the tail of 2025/.
        let p2 = fan_out(
            &prefixes,
            Some(c1),
            4,
            |k: &String| k.clone(),
            fake_paged(store, 1),
        )
        .await
        .unwrap();
        assert_eq!(p2.items, vec!["2025/b"]);
        assert!(!p2.truncated);
        assert!(p2.next.is_none());
    }
}
