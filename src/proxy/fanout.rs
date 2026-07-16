//! Multi-prefix list fan-out (ADR-004). A subject scoped to several object prefixes
//! issuing an unbounded `ListObjects` cannot be expressed as one S3 `prefix` param.
//!
//! Key insight: the granted prefixes are **sorted and disjoint**, so every key under
//! `2024/` sorts before every key under `2025/`. The merged listing is therefore a
//! plain **concatenation** in prefix order — no re-sort — and a **single resume key**
//! (S3-native `start_after`/`marker`) is enough to paginate across all of them. That
//! keeps the cursor backend-agnostic (§6.7) and the gateway stateless (§9.3).
//!
//! This module is the pure, backend-independent core: it drives an injected `lister`
//! (the backend LIST call in production, a fake in tests) and merges + paginates.

use std::future::Future;
use std::hash::{Hash, Hasher};

/// A gateway-owned continuation cursor. `scope_hash` binds the cursor to the exact
/// granted-prefix set, so a grant change between pages is detected rather than
/// silently serving a stale scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    pub scope_hash: u64,
    pub last_key: String,
}

impl Cursor {
    pub fn encode(&self) -> String {
        format!(
            "v1.{:016x}.{}",
            self.scope_hash,
            hex::encode(&self.last_key)
        )
    }

    pub fn decode(s: &str) -> Option<Cursor> {
        let mut parts = s.splitn(3, '.');
        if parts.next()? != "v1" {
            return None;
        }
        let scope_hash = u64::from_str_radix(parts.next()?, 16).ok()?;
        let last_key = String::from_utf8(hex::decode(parts.next()?).ok()?).ok()?;
        Some(Cursor {
            scope_hash,
            last_key,
        })
    }
}

pub fn scope_hash(prefixes: &[String]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    prefixes.hash(&mut h);
    h.finish()
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
/// `lister(prefix, start_after, limit)` returns up to `limit` items whose key is
/// strictly greater than `start_after`, in ascending key order — i.e. exactly S3
/// `ListObjectsV2(prefix, start_after, max_keys=limit)`.
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
    Fut: Future<Output = Vec<T>>,
{
    let hash = scope_hash(prefixes);
    let mut resume = match cursor {
        Some(c) if c.scope_hash != hash => return Err("grant scope changed; restart listing"),
        Some(c) => Some(c.last_key),
        None => None,
    };

    let mut items: Vec<T> = Vec::new();
    let mut truncated = false;

    for prefix in prefixes {
        // Skip prefixes fully before the resume key; resume the one that contains it.
        let start_after = match &resume {
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

        let remaining = max_keys - items.len();
        if remaining == 0 {
            truncated = true;
            break;
        }
        let batch = lister(prefix.clone(), start_after, remaining).await;
        let filled = batch.len() >= remaining;
        items.extend(batch.into_iter().take(remaining));
        if filled {
            // Page filled by this prefix; there may be more of it.
            truncated = true;
            break;
        }
        // Fewer than requested ⇒ this prefix is exhausted; fall through to the next.
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
    /// start_after, capped at limit — exactly S3 ListObjectsV2 semantics.
    fn fake(
        store: BTreeMap<&'static str, Vec<&'static str>>,
    ) -> impl Fn(String, Option<String>, usize) -> std::future::Ready<Vec<String>> {
        move |prefix: String, start_after: Option<String>, limit: usize| {
            let keys = store.get(prefix.as_str()).cloned().unwrap_or_default();
            let out: Vec<String> = keys
                .into_iter()
                .filter(|k| match &start_after {
                    Some(sa) => *k > sa.as_str(),
                    None => true,
                })
                .take(limit)
                .map(String::from)
                .collect();
            std::future::ready(out)
        }
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
            scope_hash: 0xdead_beef,
            last_key: "2024/report.a.b".into(),
        };
        assert_eq!(Cursor::decode(&c.encode()), Some(c));
        assert!(Cursor::decode("garbage").is_none());
    }

    #[tokio::test]
    async fn scope_change_is_rejected() {
        let prefixes = vec!["2024/".to_string()];
        let stale = Cursor {
            scope_hash: scope_hash(&prefixes) ^ 1,
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
}
