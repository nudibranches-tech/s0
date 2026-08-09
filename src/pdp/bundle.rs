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
            let parsed = ParsedBundle { policy, data };
            parsed.warn_if_platform_data_without_policy();
            return Ok(parsed);
        }
    }
    let parsed = ParsedBundle {
        policy: None,
        data: value,
    };
    parsed.warn_if_platform_data_without_policy();
    Ok(parsed)
}

impl ParsedBundle {
    /// A platform document that arrives **without its module** is a deny-all, and it
    /// is silent. Say so.
    ///
    /// The fallback in `gateway::build_pdp` / `bundle_refresh::refresh_once` is
    /// `parsed.policy.unwrap_or(GATEWAY_REGO)`, and [`GATEWAY_REGO`] is a
    /// *development* module: it reads `data.tenants[t].s3_grants[input.principal.sub]`
    /// on the RAW subject, while hyperfluid's projection keys those maps
    /// `user:<oidc sub>` / `sa:<client id>`. Measured against the captured platform
    /// bundle with `opa eval` 1.13.1: the pushed module answers
    /// `allow: grant matched`, the compiled-in default answers
    /// `deny: principal not a tenant member` — for the same request, the same data and
    /// a subject holding a real grant.
    ///
    /// So a data-only platform bundle is not "degraded", it is a total data-plane
    /// outage for the whole organization, arrived at by a field going absent. It is
    /// fail-CLOSED, which is why this is a log and not a refusal: refusing to load
    /// would leave the previous data in force, which is a different and quieter lie.
    /// But it must be loud, because every symptom (pod Ready, bundle revision moving,
    /// 403s everywhere) points away from the cause.
    ///
    /// `grant_schema_version` is the discriminator: it is hyperfluid's own D-1 gate,
    /// emitted by `S3GatewayBundle::assemble` and by nothing else. Its presence means
    /// the document came from the platform's serializer, which *always* ships `policy`
    /// — so if it is here and the module is not, something stripped it in transit.
    ///
    /// **Version 0 is excluded, deliberately.** That is the operator's seed bundle
    /// (`s3_gateway/config.rs::seed_bundle`): `tenants: {}`, `freeze_writes: true`,
    /// version `0` so the schema gate hard-denies, and no module because it is *meant*
    /// to authorize nothing until the first real poll. Every pod reads it at boot, so
    /// warning on it would put this line in every gateway's startup log and teach
    /// everyone to ignore it — which is how a real occurrence gets missed.
    ///
    /// The condition itself lives in [`Self::is_platform_data_missing_its_module`] so it
    /// can be asserted without a tracing subscriber: a log line whose condition is
    /// untested is a log line that fires on every boot, or never at all.
    fn warn_if_platform_data_without_policy(&self) {
        if !self.is_platform_data_missing_its_module() {
            return;
        }
        tracing::error!(
            "bundle carries data.grant_schema_version (a platform-projected document) but \
             NO `policy` module. Falling back to the compiled-in default, which keys \
             s3_grants/user_attributes on the RAW principal.sub while the platform keys \
             them `user:<sub>` / `sa:<client id>` — so EVERY request in this organization \
             will be denied `principal not a tenant member` despite valid grants. The \
             control plane always ships its module in this field; something removed it."
        );
    }

    /// True when this is a platform-projected document (`grant_schema_version ≥ 1`) that
    /// arrived without its rego module. See
    /// [`Self::warn_if_platform_data_without_policy`] for what that costs.
    #[must_use]
    pub fn is_platform_data_missing_its_module(&self) -> bool {
        self.policy.is_none()
            && self
                .data
                .get("grant_schema_version")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|version| version > 0)
    }
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

/// The subject key hyperfluid's projection writes for a service account:
/// `sa:<iam_sa_client_id>`.
///
/// **Confirmed against the code that writes it and the document it produces**, not
/// assumed: `org_s3_gateway_bundle::service_account_subject` emits
/// `format!("sa:{iam_sa_client_id}")` keyed on the Keycloak **clientId** (not
/// `iam_sa_id`), and the captured platform bundle in
/// `tests/data/platform/s3_gateway_bundle.json` carries `sa:pipeline` alongside
/// `user:sub-a` in both `user_attributes` and `s3_grants`. The module composes the same
/// string with `sprintf("sa:%s", [input.principal.sub])`, so this is one key space
/// spelled in three places — pinned by
/// `tests::the_service_account_key_shape_is_the_one_the_platform_really_writes`.
pub fn service_account_subject_key(client_id: &str) -> String {
    format!("sa:{client_id}")
}

/// Does this bundle's policy data know `sa:<client_id>` as a **member subject** of
/// `tenant`?
///
/// The predicate is `s3.rego`'s own membership rule, evaluated in Rust:
/// `is_object(data.tenants[<tenant>].user_attributes["sa:<client id>"])`. Nothing looser
/// — a key whose value is not an object is not a member to the policy either, and
/// accepting one would vend a credential denied `principal is not a tenant member` on
/// every request.
///
/// Fails closed on every degenerate input there is: no `tenants`, no such tenant, no
/// `user_attributes`, an empty tenant or client id, or a document that is not an object
/// at all all answer `false`. An empty bundle therefore accepts nothing, which is the
/// direction a bundle-driven check has to fail in.
pub fn bundle_knows_service_account(
    data: &serde_json::Value,
    tenant: &str,
    client_id: &str,
) -> bool {
    if tenant.is_empty() || client_id.is_empty() {
        return false;
    }
    data.get("tenants")
        .and_then(|tenants| tenants.get(tenant))
        .and_then(|tenant| tenant.get("user_attributes"))
        .and_then(|subjects| subjects.get(service_account_subject_key(client_id)))
        .is_some_and(serde_json::Value::is_object)
}

/// Hot-swappable current bundle, shared by every engine instance and the decision
/// cache. Swapping is lock-free; readers never block a decision.
pub struct BundleStore {
    current: ArcSwap<Bundle>,
}

/// The STS door's bundle-driven audience acceptance, answered from **this** store — the
/// same one the PDP decides against and the poller swaps.
///
/// `current()` is loaded per call and dropped before returning, so the answer is always
/// the revision in force at that instant: a subject removed by a poll stops being
/// accepted on the next request, with no cache to invalidate and no snapshot to go
/// stale. See [`crate::webidentity::TenantSubjects`] for why there must not be a second
/// one.
impl crate::webidentity::TenantSubjects for BundleStore {
    fn knows_service_account(&self, tenant: &str, client_id: &str) -> bool {
        bundle_knows_service_account(&self.current().data, tenant, client_id)
    }
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
    use crate::webidentity::TenantSubjects;

    /// The captured platform document — the same bytes `tests/cross_repo_contract.rs`
    /// reads. Compiled into the test binary only.
    const PLATFORM_BUNDLE: &str = include_str!("../../tests/data/platform/s3_gateway_bundle.json");

    /// **The key shape, read off the platform's own document rather than assumed.**
    ///
    /// If hyperfluid ever changed `service_account_subject` — to `iam_sa_id`, to an
    /// unprefixed client id, to `service-account:` — the STS door's bundle route would
    /// look up a key nobody writes and refuse every tenant service account, while every
    /// test that made up its own bundle stayed green. So the assertion is made against
    /// the captured document.
    #[test]
    fn the_service_account_key_shape_is_the_one_the_platform_really_writes() {
        let parsed = parse_bundle(PLATFORM_BUNDLE).expect("the captured bundle parses");
        let subjects = parsed.data["tenants"]["acme-prod"]["user_attributes"]
            .as_object()
            .expect("acme-prod has user_attributes");
        assert!(
            subjects.contains_key("sa:pipeline"),
            "the captured platform bundle no longer keys a service account \
             `sa:<client id>`; keys are {:?}",
            subjects.keys().collect::<Vec<_>>()
        );
        assert_eq!(service_account_subject_key("pipeline"), "sa:pipeline");
        // …and the predicate agrees with the document it was written against.
        assert!(bundle_knows_service_account(
            &parsed.data,
            "acme-prod",
            "pipeline"
        ));
        // The OTHER key space is not reachable through this door: `user:sub-a` is in the
        // very same map, and no client id may select it.
        assert!(!bundle_knows_service_account(
            &parsed.data,
            "acme-prod",
            "user:sub-a"
        ));
        assert!(!bundle_knows_service_account(
            &parsed.data,
            "acme-prod",
            "sub-a"
        ));
    }

    /// Membership is per tenant, and everything degenerate answers `false`.
    #[test]
    fn a_subject_is_known_only_where_the_bundle_says_so_and_absence_fails_closed() {
        let data = serde_json::json!({
            "tenants": {
                "acme": { "user_attributes": {
                    // A subject with NO grant at all: the ordinary state of a
                    // freshly-created service account, and the case `s3_grants` would
                    // have missed.
                    "sa:pipeline-runner": { "groups": [], "attributes": [] },
                    "user:oidc-sub-alice": { "groups": [], "attributes": [] }
                }, "s3_grants": {} },
                "other": { "user_attributes": {} }
            }
        });
        assert!(bundle_knows_service_account(
            &data,
            "acme",
            "pipeline-runner"
        ));
        // Another tenant of the same document does not know it.
        assert!(!bundle_knows_service_account(
            &data,
            "other",
            "pipeline-runner"
        ));
        // Nor does a tenant that is not in the bundle at all.
        assert!(!bundle_knows_service_account(
            &data,
            "absent",
            "pipeline-runner"
        ));
        for (tenant, client) in [
            ("acme", "pipeline-runner-2"),  // not a prefix match
            ("acme", "pipeline"),           // nor the other way round
            ("acme", "PIPELINE-RUNNER"),    // a client id is an exact identifier
            ("acme", "oidc-sub-alice"),     // never the user key space
            ("acme", "sa:pipeline-runner"), // the prefix is ours to compose, not theirs
            ("acme", ""),
            ("", "pipeline-runner"),
        ] {
            assert!(
                !bundle_knows_service_account(&data, tenant, client),
                "{tenant}/{client} must not be known"
            );
        }
        // Every shape of an absent or broken document, all closed.
        for empty in [
            serde_json::json!({}),
            serde_json::json!(null),
            serde_json::json!("not a document"),
            serde_json::json!({ "tenants": {} }),
            serde_json::json!({ "tenants": { "acme": {} } }),
            serde_json::json!({ "tenants": { "acme": { "user_attributes": {} } } }),
            // Present but not an object ⇒ not a member to `s3.rego` either.
            serde_json::json!({ "tenants": { "acme": {
                "user_attributes": { "sa:pipeline-runner": true } } } }),
            serde_json::json!({ "tenants": { "acme": {
                "user_attributes": { "sa:pipeline-runner": null } } } }),
        ] {
            assert!(
                !bundle_knows_service_account(&empty, "acme", "pipeline-runner"),
                "{empty} must know nothing"
            );
        }
    }

    /// **The lookup reads the bundle in force, not the one that was in force.**
    ///
    /// The store is hot-swapped on every poll, and the handle the STS door holds is the
    /// store itself rather than a snapshot of it. A subject added by a poll is accepted
    /// immediately; a subject *removed* by one stops being accepted immediately — which
    /// is the half that matters, because that is a revocation.
    #[test]
    fn the_lookup_follows_the_store_across_a_swap_in_both_directions() {
        let with = |subjects: serde_json::Value| serde_json::json!({ "tenants": { "acme": { "user_attributes": subjects } } });
        let store = BundleStore::new(Bundle::new("rev-1", with(serde_json::json!({}))));
        // The handle is taken ONCE, before either swap, exactly as `main.rs` takes it at
        // boot and holds it for the process's life.
        let subjects: &dyn TenantSubjects = &store;
        assert!(!subjects.knows_service_account("acme", "pipeline-runner"));

        store.store(Bundle::new(
            "rev-2",
            with(serde_json::json!({ "sa:pipeline-runner": { "groups": [] } })),
        ));
        assert!(
            subjects.knows_service_account("acme", "pipeline-runner"),
            "a subject the poller published is not visible to the STS door"
        );

        store.store(Bundle::new("rev-3", with(serde_json::json!({}))));
        assert!(
            !subjects.knows_service_account("acme", "pipeline-runner"),
            "a subject the poller REMOVED is still accepted: the door is holding a stale \
             snapshot"
        );
    }

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

    /// The condition behind the ERROR log, both ways round. A log line that fires on
    /// every boot gets ignored, and an ignored log line is not a control.
    #[test]
    fn a_platform_document_without_its_module_is_recognized_but_the_seed_is_not() {
        // A real platform document stripped of `policy`: the compiled-in default keys
        // grants on the raw sub and would deny the whole organization. Say so.
        let stripped = parse_bundle(
            r#"{ "data": { "grant_schema_version": 2,
                           "org_settings": { "freeze_writes": false },
                           "tenants": { "acme": {} } } }"#,
        )
        .unwrap();
        assert!(stripped.is_platform_data_missing_its_module());

        // The operator's seed bundle (s3_gateway/config.rs::seed_bundle) is version 0,
        // module-less ON PURPOSE, and read by every pod at boot. It must stay quiet.
        let seed = parse_bundle(
            r#"{ "data": { "grant_schema_version": 0,
                           "org_settings": { "freeze_writes": true,
                                             "organization_id": "org",
                                             "bundle_revision": "seed-inert" },
                           "tenants": {} } }"#,
        )
        .unwrap();
        assert!(!seed.is_platform_data_missing_its_module());

        // A document that carries its module is the normal case.
        let complete = parse_bundle(
            r#"{ "policy": "package s3.authz",
                 "data": { "grant_schema_version": 2, "tenants": {} } }"#,
        )
        .unwrap();
        assert!(!complete.is_platform_data_missing_its_module());

        // s0's own dev bundles carry no version field at all and legitimately rely on
        // the compiled-in default.
        let dev = parse_bundle(r#"{ "org_settings": { "freeze_writes": false } }"#).unwrap();
        assert!(!dev.is_platform_data_missing_its_module());
    }
}
