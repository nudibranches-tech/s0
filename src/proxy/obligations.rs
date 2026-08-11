//! The obligation channel between the access layer and the dispatcher, for obligations
//! that cannot be applied at decision time: what is to be restricted is whatever the
//! backend is about to answer, so the verdict rides across the forward and is applied in
//! `GatewayS3` on the way back. (A *request* obligation — `narrow_prefix`, or dropping
//! refused keys from a multi-delete — is applied by the typed hook and needs no channel.)
//!
//! `ListBuckets` is why: every request is re-signed with the per-`(backend, tenant)`
//! **owner** credential, so the backend answers with the tenant's entire bucket namespace
//! no matter who asked. [`ResponseObligations`] is only ever installed by an access hook,
//! so its **absence** means the hook did not run and must fail closed — see
//! [`GatewayS3::list_buckets`](super::GatewayS3::list_buckets).

use std::collections::BTreeSet;
use std::sync::Arc;

use http::Extensions;
use s3s::S3Request;

use super::fanout::ListFanout;

/// What a `ListBuckets` response may contain.
///
/// Deliberately not `Vec<String>`: the empty vector and "everything" are the two states
/// that must never be confusable, and an enum makes writing one where the other was
/// meant a type error rather than a review question.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BucketVisibility {
    /// Nothing is visible. Answered as an **empty listing**, *without contacting the
    /// backend*.
    ///
    /// The verdict for both "the PDP denied the enumeration" and "the PDP allowed it and
    /// the principal holds no bucket grants". Those must be indistinguishable: a 403 for
    /// one and an empty 200 for the other reports whether a principal holds `list_buckets`
    /// in this tenant, and contacting the backend for only one is the same oracle measured
    /// with a stopwatch.
    Nothing,
    /// Exactly these bucket names, and nothing else. May not be empty — that is
    /// [`Self::Nothing`], which is a different code path.
    Only(BTreeSet<String>),
    /// Unfiltered. Reachable only from an `all_buckets_visible` obligation a policy
    /// author typed out, never from a default or from an empty list.
    All,
}

impl BucketVisibility {
    /// Build from a granted name set, collapsing empty to [`Self::Nothing`] so the
    /// caller cannot accidentally construct an `Only({})` that would forward a request
    /// whose every answer is going to be discarded.
    #[must_use]
    pub fn only(names: BTreeSet<String>) -> Self {
        if names.is_empty() {
            BucketVisibility::Nothing
        } else {
            BucketVisibility::Only(names)
        }
    }

    /// Whether `name` survives the filter.
    #[must_use]
    pub fn admits(&self, name: &str) -> bool {
        match self {
            BucketVisibility::Nothing => false,
            BucketVisibility::Only(set) => set.contains(name),
            BucketVisibility::All => true,
        }
    }

    /// A stable descriptor of this visibility scope, for binding a pagination cursor to
    /// the grants it was issued under (see [`super::bucketfilter`]).
    ///
    /// Each element is prefixed with a character outside the S3 bucket alphabet, so the
    /// unrestricted scope cannot collide with a tenant that happens to contain a bucket
    /// named like the sentinel.
    #[must_use]
    pub fn scope(&self) -> Vec<String> {
        match self {
            BucketVisibility::Nothing => vec![":none".to_string()],
            BucketVisibility::All => vec![":all".to_string()],
            BucketVisibility::Only(set) => set.iter().map(|b| format!("={b}")).collect(),
        }
    }
}

/// Everything an access hook asks the dispatcher to do to a response.
///
/// `Default` is deliberately *not* implemented: an empty `ResponseObligations` reads as
/// "no restrictions", and the one field here is a restriction whose absence is the
/// dangerous state. A hook builds it with the constructor for the transform it means.
#[derive(Debug, Clone)]
pub struct ResponseObligations {
    /// `ListObjectsV2` across several granted prefixes (ADR-004). A request fan-out
    /// whose *merge* is a response transform, which is why it lives here.
    pub list_fanout: Option<ListFanout>,
    /// `ListBuckets`: which of the tenant's buckets this principal may see.
    pub visible_buckets: Option<BucketVisibility>,
}

impl ResponseObligations {
    #[must_use]
    pub fn fanout(prefixes: Vec<String>) -> Self {
        ResponseObligations {
            list_fanout: Some(ListFanout { prefixes }),
            visible_buckets: None,
        }
    }

    #[must_use]
    pub fn buckets(visibility: BucketVisibility) -> Self {
        ResponseObligations {
            list_fanout: None,
            visible_buckets: Some(visibility),
        }
    }

    /// Stash on the in-flight request. Called by the access layer only.
    pub fn install(self, extensions: &mut Extensions) {
        extensions.insert(Arc::new(self));
    }

    /// Read back on the forward path. `None` means no hook imposed anything — which is
    /// indistinguishable from "no hook ran", and is why every caller of this treats
    /// `None` as the fail-closed branch rather than as permission.
    #[must_use]
    pub fn of<T>(req: &S3Request<T>) -> Option<Arc<ResponseObligations>> {
        req.extensions.get::<Arc<ResponseObligations>>().cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_empty_grant_set_is_nothing_visible_not_an_empty_filter() {
        assert_eq!(
            BucketVisibility::only(BTreeSet::new()),
            BucketVisibility::Nothing
        );
        assert!(matches!(
            BucketVisibility::only(BTreeSet::from(["a".to_string()])),
            BucketVisibility::Only(_)
        ));
    }

    #[test]
    fn admits_is_exact_membership_except_under_all() {
        let only = BucketVisibility::only(BTreeSet::from(["reports".to_string()]));
        assert!(only.admits("reports"));
        assert!(!only.admits("report"));
        assert!(!only.admits("reports-private"));
        assert!(!BucketVisibility::Nothing.admits("reports"));
        assert!(BucketVisibility::All.admits("anything"));
    }

    #[test]
    fn the_unrestricted_scope_cannot_collide_with_a_real_bucket_set() {
        // A cursor is bound to the scope it was issued under. If `All` and a tenant
        // holding a bucket literally named ":all" hashed alike, a grant change from one
        // to the other would go undetected mid-listing.
        let named = BucketVisibility::only(BTreeSet::from([":all".to_string()]));
        assert_ne!(BucketVisibility::All.scope(), named.scope());
        assert_ne!(
            BucketVisibility::Nothing.scope(),
            BucketVisibility::All.scope()
        );
        // And the scope of a name set is order-stable: BTreeSet iterates sorted, so two
        // policies emitting the same names in different orders issue the same cursor.
        let a = BucketVisibility::only(BTreeSet::from(["b".to_string(), "a".to_string()]));
        let b = BucketVisibility::only(BTreeSet::from(["a".to_string(), "b".to_string()]));
        assert_eq!(a.scope(), b.scope());
    }
}
