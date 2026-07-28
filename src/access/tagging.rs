//! `reserved_tag_keys` — the guard that stops a tag write from being a privilege
//! escalation.
//!
//! ## The self-elevation the guard exists for
//!
//! [`crate::authz::OpaInput::object_tags`] exists so a policy can key grants on an
//! object's tags (ABAC). The moment any policy does that, a principal holding
//! `write_objects` **and** `write_object_tags` can grant itself whatever the policy keys
//! on: write the object, tag it `tier=public`, and the condition the policy reads is now
//! satisfied by data the attacker supplied. The two verbs are already separate — that is
//! necessary and not sufficient, because a principal legitimately holding both on its own
//! prefix can still elevate *within* it.
//!
//! Two things close it, and this module is the second:
//!
//! 1. the decision is made against the **proposed** tag set
//!    ([`crate::authz::OpaInput::requested_tags`]), never the object's current one, so a
//!    policy sees what the write would install rather than what is already there;
//! 2. the key space a policy is allowed to *depend* on is reserved: no S3 caller may
//!    write it, whatever grants it holds.
//!
//! ## Absence means deny, and that is the shipped default
//!
//! The reserved list is supplied by the control plane in the bundle. **An absent list
//! denies every tag write** (master plan open question 5, resolved to `["*"]`). That
//! ships tagging *inert* — `PutObjectTagging`, `DeleteObjectTagging` and an inline
//! `x-amz-tagging` on a write are all refused — until hyperfluid publishes the list.
//!
//! It has to be this way round. The alternative default (`[]`, nothing reserved) is
//! indistinguishable from a correctly-configured deployment right up to the moment
//! someone writes the first ABAC condition, at which point every tag-writing principal
//! silently gains the ability to satisfy it. A missing security-relevant input must not
//! read as "no restriction"; that is the same fail-open shape as an obligation this
//! binary does not implement being dropped, and this project has a `deny_unknown_fields`
//! and a `must_understand` because of it.
//!
//! A malformed list (present but not an array of strings) is treated as absent, i.e. as
//! deny-all, for the same reason.

use std::collections::BTreeMap;

/// Where in the bundle the control plane publishes the list. Sits next to
/// `freeze_writes`, the other org-global control, rather than per-tenant: a key a policy
/// depends on is an org-wide invariant and a per-tenant carve-out would be a hole in it.
pub const BUNDLE_PATH: &[&str] = &["org_settings", "reserved_tag_keys"];

/// The tag keys no S3 caller may write, as published by the control plane.
///
/// `None` is not "nothing is reserved" — it is "the control plane has not spoken", which
/// denies every tag write. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReservedTagKeys(Option<Vec<String>>);

impl ReservedTagKeys {
    /// Read the list out of the current bundle data.
    ///
    /// Takes the whole `data` document rather than a pre-extracted value so that "where
    /// does this live in the bundle?" has exactly one answer ([`BUNDLE_PATH`]) and a
    /// caller cannot accidentally supply the list from somewhere less trustworthy.
    #[must_use]
    pub fn from_bundle(data: &serde_json::Value) -> Self {
        let mut cursor = data;
        for seg in BUNDLE_PATH {
            match cursor.get(seg) {
                Some(v) => cursor = v,
                None => return ReservedTagKeys(None),
            }
        }
        let Some(items) = cursor.as_array() else {
            tracing::warn!(
                "bundle carries org_settings.reserved_tag_keys but it is not an array; \
                 treating it as absent, which denies every tag write"
            );
            return ReservedTagKeys(None);
        };
        let mut keys = Vec::with_capacity(items.len());
        for item in items {
            let Some(s) = item.as_str() else {
                tracing::warn!(
                    "bundle carries a non-string entry in org_settings.reserved_tag_keys; \
                     treating the whole list as absent, which denies every tag write"
                );
                return ReservedTagKeys(None);
            };
            keys.push(s.to_string());
        }
        ReservedTagKeys(Some(keys))
    }

    /// True when no tag write may proceed at all — the shipped default until hyperfluid
    /// emits the list, and also what an explicit `["*"]` means.
    #[must_use]
    pub fn denies_all_tag_writes(&self) -> bool {
        match &self.0 {
            None => true,
            Some(keys) => keys.iter().any(|k| k == "*"),
        }
    }

    /// The reason a tag write is refused outright, or `None` if tag writes are live.
    ///
    /// Separate from [`Self::check`] because a tag write that names **no** keys —
    /// `DeleteObjectTagging` — still has to be refused while tagging is inert, and there
    /// is nothing for `check` to look at.
    #[must_use]
    pub fn inert_reason(&self) -> Option<String> {
        if !self.denies_all_tag_writes() {
            return None;
        }
        Some(
            match &self.0 {
                None => {
                    "tag writes are refused: the control plane has not published \
                     org_settings.reserved_tag_keys, and an absent list denies every tag \
                     write rather than reserving nothing — a tag can satisfy an ABAC \
                     grant condition, so the key space a policy may depend on has to be \
                     stated before any caller is allowed to write into it"
                }
                Some(_) => {
                    "tag writes are refused: org_settings.reserved_tag_keys reserves the \
                     whole key space (\"*\")"
                }
            }
            .to_string(),
        )
    }

    /// Refuse a proposed tag set that touches a reserved key.
    ///
    /// Matching is exact, or by a single trailing `*` (`hyperfluid/*` reserves every key
    /// under that namespace). Keys are compared case-sensitively, because S3 tag keys are
    /// case-sensitive and a policy reading `tier` is genuinely not satisfied by `Tier`;
    /// pretending otherwise would refuse writes that cannot elevate anything.
    ///
    /// A pattern in a *deny* list widens the denial, so an unvalidated one fails in the
    /// safe direction — which is why a glob is acceptable here and is not in
    /// `Obligations::visible_buckets`, where it would widen an allowlist.
    pub fn check(&self, tags: &BTreeMap<String, String>) -> Result<(), String> {
        if let Some(reason) = self.inert_reason() {
            return Err(reason);
        }
        let Some(reserved) = &self.0 else {
            // Unreachable: `inert_reason` already returned for `None`. Kept explicit
            // rather than unwrapped so a future edit to `denies_all_tag_writes` cannot
            // turn this into a panic or, worse, into an allow.
            return Err("tag writes are refused: no reserved-key list is available".to_string());
        };
        for key in tags.keys() {
            if let Some(pattern) = reserved.iter().find(|p| matches(p, key)) {
                return Err(format!(
                    "the tag key {key:?} is reserved by the control plane (matched \
                     {pattern:?}); a policy may condition grants on it, so a caller that \
                     could write it could grant itself access"
                ));
            }
        }
        Ok(())
    }
}

fn matches(pattern: &str, key: &str) -> bool {
    match pattern.strip_suffix('*') {
        Some(prefix) => key.starts_with(prefix),
        None => pattern == key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn an_absent_list_denies_every_tag_write() {
        // THE shipped default. Tagging is inert until hyperfluid publishes the list.
        let r = ReservedTagKeys::from_bundle(&serde_json::json!({
            "org_settings": { "freeze_writes": false }
        }));
        assert!(r.denies_all_tag_writes());
        let why = r.inert_reason().expect("a reason");
        assert!(why.contains("reserved_tag_keys"), "{why}");
        assert!(r.check(&tags(&[("tier", "internal")])).is_err());
        // Even the empty tag set — a `DeleteObjectTagging`-shaped write — is refused.
        assert!(r.check(&BTreeMap::new()).is_err());
    }

    #[test]
    fn a_malformed_list_is_treated_as_absent() {
        for bad in [
            serde_json::json!({"org_settings": {"reserved_tag_keys": "tier"}}),
            serde_json::json!({"org_settings": {"reserved_tag_keys": {"tier": true}}}),
            serde_json::json!({"org_settings": {"reserved_tag_keys": ["tier", 7]}}),
        ] {
            assert!(
                ReservedTagKeys::from_bundle(&bad).denies_all_tag_writes(),
                "{bad}"
            );
        }
    }

    #[test]
    fn an_explicit_wildcard_denies_every_tag_write() {
        let r = ReservedTagKeys::from_bundle(
            &serde_json::json!({"org_settings": {"reserved_tag_keys": ["*"]}}),
        );
        assert!(r.denies_all_tag_writes());
        assert!(r.inert_reason().unwrap().contains("whole key space"));
    }

    #[test]
    fn a_published_list_makes_tag_writes_live_and_reserves_exactly_its_keys() {
        let r = ReservedTagKeys::from_bundle(&serde_json::json!({
            "org_settings": { "reserved_tag_keys": ["tier", "hyperfluid/*"] }
        }));
        assert!(!r.denies_all_tag_writes());
        assert!(r.inert_reason().is_none());

        r.check(&tags(&[("owner", "team-a")]))
            .expect("not reserved");
        // Exact.
        assert!(r.check(&tags(&[("tier", "public")])).is_err());
        // Namespace glob.
        assert!(
            r.check(&tags(&[("hyperfluid/classification", "phi")]))
                .is_err()
        );
        // Case-sensitive: `Tier` cannot satisfy a policy reading `tier`, so refusing it
        // would only break writes that cannot elevate anything.
        r.check(&tags(&[("Tier", "public")]))
            .expect("case-sensitive");
        // A reserved key anywhere in the set refuses the whole set — the request is one
        // unit and the gateway does not part-apply it.
        assert!(
            r.check(&tags(&[("owner", "team-a"), ("tier", "public")]))
                .is_err()
        );
    }

    #[test]
    fn an_empty_published_list_reserves_nothing_and_is_a_deliberate_choice() {
        // The other half of open question 5: `[]` is expressible, it just is not the
        // default. An operator that publishes it has said "no policy depends on a tag",
        // which is a claim the control plane makes, not one the gateway assumes.
        let r = ReservedTagKeys::from_bundle(&serde_json::json!({"org_settings":
                {"reserved_tag_keys": []}}));
        assert!(!r.denies_all_tag_writes());
        r.check(&tags(&[("tier", "public")]))
            .expect("nothing reserved");
    }
}
