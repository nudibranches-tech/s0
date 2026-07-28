//! `ListBuckets`: intersect what the backend returned with what the principal was
//! granted, and paginate the result **gateway-side**.
//!
//! ## Why the backend's own pagination cannot be reused
//!
//! Filtering breaks it. `max-buckets` and `continuation-token` describe positions in the
//! backend's list, and once entries are removed from a page those positions no longer
//! mean anything to the client: a page of 1000 comes back with 3 visible buckets, the
//! token points into the backend's sequence, and the client is told "here are 3 of your
//! 1000". So the gateway owns both — it asks the backend for *everything*, filters,
//! sorts, and cuts its own page. The token a client receives is a gateway token
//! (`fanout::Cursor`), and one issued under a different grant set is rejected loudly
//! rather than silently re-based (`Cursor::validate` semantics, same as ADR-004).
//!
//! ## Why the merged listing is explicitly **gateway-ordered**
//!
//! Accepted review defect B-9. The obvious cursor — "skip while name <= last_name" over
//! the backend's pages — is only correct if the backend returns buckets in a stable
//! ascending order across pages, and that is *unverified for RGW*: the S3 API documents
//! no ordering guarantee for `ListBuckets`, and RGW's bucket listing comes off the user's
//! bucket index, not a sorted key namespace. Rather than assume it, this module sorts by
//! name after filtering and pages over the sorted vector. The consequence is stated
//! rather than hidden: **the order of a `ListBuckets` response from this gateway is the
//! gateway's, not the backend's**, and it is byte-stable across replicas because it is a
//! plain lexicographic sort of the names.
//!
//! ## Cost
//!
//! One request drains the tenant's whole bucket list. That is bounded by
//! `limits.max_bucket_list_pages` in the caller, and it is the price of not trusting an
//! ordering the backend does not promise. Bucket counts are per *tenant*, not per
//! object, so this is tens to hundreds of entries in the deployments this targets.

use s3s::dto::Bucket;

use super::fanout::{self, Cursor};
use super::obligations::BucketVisibility;

/// One gateway-owned page of a filtered bucket listing.
#[derive(Debug)]
pub struct BucketPage {
    pub buckets: Vec<Bucket>,
    /// The token to hand the client, or `None` when this is the last page.
    pub next: Option<Cursor>,
}

/// Filter, sort and cut one page.
///
/// `all` is everything the backend reported (already drained across its own pages).
/// `name_prefix` is the client's `prefix` parameter, re-applied here because a backend
/// that ignores it must not be able to widen the answer.
///
/// Fails only on a cursor issued under a different visibility scope — the client must
/// restart the listing, and is told so rather than silently served page 1 again.
pub fn page(
    all: Vec<Bucket>,
    visibility: &BucketVisibility,
    name_prefix: Option<&str>,
    cursor: Option<Cursor>,
    max_buckets: usize,
) -> Result<BucketPage, &'static str> {
    let scope_hash = fanout::scope_hash(&visibility.scope());
    let resume = match cursor {
        Some(c) if c.scope_hash != scope_hash => {
            return Err("bucket visibility changed; restart the listing");
        }
        Some(c) => Some(c.last_key),
        None => None,
    };

    let mut kept: Vec<Bucket> = all
        .into_iter()
        .filter(|b| {
            // A bucket the backend returned with no name is dropped, not forwarded: the
            // decision was made about names, so an entry that has none was never
            // authorized. It is also not a shape RGW produces — this is the fail-closed
            // reading of an impossible response rather than a live concern.
            let Some(name) = b.name.as_deref() else {
                return false;
            };
            visibility.admits(name) && name_prefix.is_none_or(|p| name.starts_with(p))
        })
        .collect();
    // The gateway's own order. See the module docs: the backend promises none.
    kept.sort_by(|a, b| a.name.cmp(&b.name));
    // A duplicate name across two backend pages would otherwise be emitted twice and,
    // worse, make the cursor ambiguous.
    kept.dedup_by(|a, b| a.name == b.name);

    let start = match &resume {
        // `partition_point` over the sorted names: everything at or before the resume
        // key is already delivered. Strictly greater, so a page boundary never repeats
        // an entry and never skips one.
        Some(rk) => kept.partition_point(|b| b.name.as_deref().unwrap_or_default() <= rk.as_str()),
        None => 0,
    };
    let remaining = kept.split_off(start.min(kept.len()));
    let truncated = remaining.len() > max_buckets;
    let buckets: Vec<Bucket> = remaining.into_iter().take(max_buckets).collect();
    let next = truncated
        .then(|| {
            buckets
                .last()
                .and_then(|b| b.name.clone())
                .map(|last_key| Cursor {
                    scope_hash,
                    last_key,
                })
        })
        .flatten();
    Ok(BucketPage { buckets, next })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    fn bucket(name: &str) -> Bucket {
        Bucket {
            bucket_region: None,
            creation_date: None,
            name: Some(name.to_string()),
        }
    }

    fn names(p: &BucketPage) -> Vec<String> {
        p.buckets
            .iter()
            .map(|b| b.name.clone().unwrap_or_default())
            .collect()
    }

    fn only(names: &[&str]) -> BucketVisibility {
        BucketVisibility::only(
            names
                .iter()
                .map(|s| (*s).to_string())
                .collect::<BTreeSet<_>>(),
        )
    }

    /// What the backend hands back for the tenant: everything, in whatever order.
    fn tenant() -> Vec<Bucket> {
        ["zeta", "alpha", "reports", "secrets", "logs"]
            .iter()
            .map(|n| bucket(n))
            .collect()
    }

    #[test]
    fn only_granted_buckets_survive() {
        let page = page(tenant(), &only(&["reports", "logs"]), None, None, 100).unwrap();
        assert_eq!(names(&page), vec!["logs", "reports"]);
        assert!(page.next.is_none());
        // The ungranted ones are not merely last — they are absent.
        assert!(!names(&page).iter().any(|n| n == "secrets"));
    }

    #[test]
    fn nothing_visible_is_an_empty_page_not_an_error() {
        let page = page(tenant(), &BucketVisibility::Nothing, None, None, 100).unwrap();
        assert!(page.buckets.is_empty());
        assert!(page.next.is_none());
    }

    #[test]
    fn all_visible_returns_the_whole_tenant_sorted() {
        let page = page(tenant(), &BucketVisibility::All, None, None, 100).unwrap();
        assert_eq!(
            names(&page),
            vec!["alpha", "logs", "reports", "secrets", "zeta"],
            "the merged listing is gateway-ordered: sorted by name, not backend order"
        );
    }

    #[test]
    fn pagination_across_a_filtered_set_is_correct_and_stable() {
        // The property the whole module exists for: the client pages through exactly the
        // granted buckets, once each, in a stable order — even though the backend's page
        // boundaries and order have nothing to do with the filtered sequence.
        let vis = only(&["alpha", "logs", "reports", "zeta"]);
        let mut seen = Vec::new();
        let mut cursor = None;
        for _ in 0..10 {
            let p = page(tenant(), &vis, None, cursor.clone(), 2).unwrap();
            seen.extend(names(&p));
            match p.next {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        assert_eq!(seen, vec!["alpha", "logs", "reports", "zeta"]);

        // …and the same walk with a backend that shuffles its answer between pages
        // produces the identical sequence, which is what "gateway-ordered" buys.
        let mut shuffled = tenant();
        shuffled.reverse();
        let p1 = page(shuffled.clone(), &vis, None, None, 2).unwrap();
        assert_eq!(names(&p1), vec!["alpha", "logs"]);
        let p2 = page(shuffled, &vis, None, p1.next, 2).unwrap();
        assert_eq!(names(&p2), vec!["reports", "zeta"]);
    }

    #[test]
    fn the_last_page_carries_no_token() {
        let vis = only(&["alpha", "logs"]);
        let p = page(tenant(), &vis, None, None, 2).unwrap();
        assert_eq!(names(&p), vec!["alpha", "logs"]);
        assert!(
            p.next.is_none(),
            "a page that exactly consumed the remainder must not hand out a token; a \
             client would fetch an empty page and, worse, could not tell it was the end"
        );
    }

    #[test]
    fn a_cursor_from_a_different_grant_set_is_refused() {
        // A grant change mid-listing must not silently serve a page from the new scope
        // at an offset computed under the old one.
        let p = page(tenant(), &only(&["alpha", "logs", "zeta"]), None, None, 1).unwrap();
        let cursor = p.next.expect("truncated");
        let err = page(
            tenant(),
            &only(&["alpha", "reports"]),
            None,
            Some(cursor),
            1,
        )
        .expect_err("a cursor bound to another visibility scope must be refused");
        assert!(err.contains("restart"), "{err}");
    }

    #[test]
    fn the_client_prefix_is_re_applied_gateway_side() {
        // Forwarded to the backend as an optimization, but never trusted: a backend that
        // ignores `prefix` must not be able to widen the answer past what was asked for.
        let vis = only(&["reports", "reports-archive", "logs"]);
        let p = page(tenant(), &vis, Some("rep"), None, 100).unwrap();
        assert_eq!(names(&p), vec!["reports"]);
    }

    #[test]
    fn an_unnamed_bucket_is_dropped_rather_than_forwarded() {
        let mut all = tenant();
        all.push(Bucket {
            bucket_region: None,
            creation_date: None,
            name: None,
        });
        let p = page(all, &BucketVisibility::All, None, None, 100).unwrap();
        assert_eq!(
            p.buckets.len(),
            5,
            "the nameless entry was never authorized"
        );
    }

    #[test]
    fn a_duplicate_name_across_backend_pages_is_emitted_once() {
        let mut all = tenant();
        all.push(bucket("reports"));
        let p = page(all, &only(&["reports"]), None, None, 100).unwrap();
        assert_eq!(names(&p), vec!["reports"]);
    }
}
