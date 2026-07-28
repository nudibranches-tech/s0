//! The pushed bundle: the policy the gateway enforces. The platform is the source of
//! policy and delivers it as a bundle carrying the projected policy *data* (tenants,
//! grants, denylists, `freeze_writes`) and, optionally, the policy *module* (the rego)
//! itself. When a bundle omits the module the gateway falls back to the compiled-in
//! default ([`GATEWAY_REGO`]).
//!
//! Each fetch is content-hashed into a revision. The revision is the linchpin of cache
//! correctness: a revocation lands as a new revision, so every decision cached under the
//! old revision is unreachable by construction — there is no invalidation logic to get
//! wrong.

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};

/// The default gateway policy, compiled into the binary. In production the platform
/// pushes the authoritative module in the bundle; this is the fallback when a bundle
/// carries data only, the policy used for local development, and the oracle the
/// dual-engine parity gate replays against — so what we test is what we ship by default.
pub const GATEWAY_REGO: &str = include_str!("../../policy/gateway/authz.rego");

/// The rule the engines evaluate.
///
/// **This name is a cross-repo contract.** The platform ships the authoritative module
/// as `package s3.authz` and pins this entrypoint as `S3_AUTHZ_ENTRYPOINT`
/// (`hf_module_console_api/.../vauban/s3_gateway_projection/bundle.rs`). If s0 queries
/// any other rule, a pushed bundle evaluates to **undefined** — which fails closed to a
/// deny on every request, with no error anywhere and every test in both repos green.
/// That is the failure that cost the previous attempt 35 green tests over a deny-all
/// production policy. `tests/cross_repo_contract.rs` holds the two equal.
pub const DECISION_RULE: &str = "data.s3.authz.decision";

/// [`DECISION_RULE`] in OPA's Data API / decision-log path form:
/// `data.s3.authz.decision` → `s3/authz/decision`.
///
/// Derived rather than written out a second time — the sidecar's URL and the audit
/// record's `path` are two places that would otherwise each hold their own copy of the
/// entrypoint and drift from it independently.
pub fn decision_rule_path() -> String {
    DECISION_RULE
        .strip_prefix("data.")
        .unwrap_or(DECISION_RULE)
        .replace('.', "/")
}

/// A parsed bundle: the policy data and, optionally, the policy module pushed with it.
#[derive(Debug, Clone)]
pub struct ParsedBundle {
    /// The rego module the platform pushed, if any. `None` ⇒ use the compiled-in
    /// default ([`GATEWAY_REGO`]).
    pub policy: Option<String>,
    /// The projected policy data (`tenants`, `org_settings`, …), evaluated as `data`.
    pub data: serde_json::Value,
}

/// Parse a fetched bundle. The canonical form wraps the data with an optional module:
/// `{ "policy": "<rego>", "data": { … } }`. A bare object with no `data` key is taken as
/// the data itself (dev convenience), leaving the default policy in force.
pub fn parse_bundle(raw: &str) -> Result<ParsedBundle, String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("parse bundle: {e}"))?;
    if let serde_json::Value::Object(map) = &value {
        if map.contains_key("data") {
            let policy = map
                .get("policy")
                .and_then(|p| p.as_str())
                .map(str::to_string);
            let data = map.get("data").cloned().unwrap_or(serde_json::Value::Null);
            return Ok(ParsedBundle { policy, data });
        }
    }
    Ok(ParsedBundle {
        policy: None,
        data: value,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bundle {
    /// Opaque monotonic revision from the control-plane bundle builder (an etag/version).
    pub revision: String,
    /// The projected policy data (`tenants`, `org_settings`, …).
    pub data: serde_json::Value,
}

impl Bundle {
    pub fn new(revision: impl Into<String>, data: serde_json::Value) -> Self {
        Bundle {
            revision: revision.into(),
            data,
        }
    }
}

/// Stable revision derived from raw bundle content: a content change is a new
/// revision, which is exactly the cache-invalidation signal.
///
/// **SHA-256, not `DefaultHasher`.** `DefaultHasher`'s output is explicitly not
/// guaranteed stable across Rust releases, so a rebuild on a different toolchain
/// would re-hash identical bundle bytes to a different revision — invalidating every
/// cached decision fleet-wide mid-rollout, and (worse) making two replicas of a
/// rolling update disagree about whether they hold the same policy. Pinned by
/// `tests/golden_hash.rs`.
pub fn content_revision(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

/// Hot-swappable current bundle, shared by every engine instance and the decision
/// cache. Swapping is lock-free; readers never block a decision.
pub struct BundleStore {
    current: ArcSwap<Bundle>,
}

impl BundleStore {
    pub fn new(initial: Bundle) -> Self {
        BundleStore {
            current: ArcSwap::from_pointee(initial),
        }
    }

    pub fn current(&self) -> arc_swap::Guard<std::sync::Arc<Bundle>> {
        self.current.load()
    }

    pub fn revision(&self) -> String {
        self.current.load().revision.clone()
    }

    /// Install a newly-fetched bundle. Old cached decisions become unreachable
    /// because their cache keys embed the prior revision.
    pub fn store(&self, bundle: Bundle) {
        self.current.store(std::sync::Arc::new(bundle));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapped_bundle_splits_policy_and_data() {
        let raw = r#"{ "policy": "package s3.authz", "data": { "org_settings": {} } }"#;
        let parsed = parse_bundle(raw).unwrap();
        assert_eq!(parsed.policy.as_deref(), Some("package s3.authz"));
        assert_eq!(parsed.data["org_settings"], serde_json::json!({}));
    }

    #[test]
    fn bare_bundle_is_data_with_default_policy() {
        let raw = r#"{ "org_settings": { "freeze_writes": true } }"#;
        let parsed = parse_bundle(raw).unwrap();
        assert!(parsed.policy.is_none());
        assert_eq!(parsed.data["org_settings"]["freeze_writes"], true);
    }
}
