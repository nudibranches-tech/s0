//! The pushed bundle: the policy the gateway enforces. The control plane is the source of
//! policy and delivers a bundle carrying the projected policy *data* (tenants, grants,
//! denylists, `freeze_writes`) and, optionally, the policy *module* (the rego) itself. When
//! a bundle omits the module the gateway falls back to the compiled-in default
//! ([`GATEWAY_REGO`]).
//!
//! Each fetch is content-hashed into a revision, the linchpin of cache correctness: a
//! revocation lands as a new revision, so every decision cached under the old revision is
//! unreachable by construction — there is no invalidation logic to get wrong.
//!
//! From `grant_schema_version` 3 a bundle also **places** buckets: it is filtered to one
//! backend, names that backend, and lists each of its buckets under exactly one tenant.
//! [`BucketPlacement`] is that index, built once per revision on load, together with the
//! byte quotas the document states for those buckets, their tenants and the backend
//! ([`crate::quota`]).

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};

use crate::quota::{BACKEND_QUOTA_FIELD, BundleQuotas, QUOTA_FIELD, QuotaScope, QuotaSpec};

/// The default gateway policy, compiled into the binary. In production the control plane
/// pushes the authoritative module in the bundle; this is the fallback when a bundle
/// carries data only, the policy used for local development, and the oracle the
/// dual-engine parity gate replays against — so what we test is what we ship by default.
pub const GATEWAY_REGO: &str = include_str!("../../policy/gateway/authz.rego");

/// The rule the engines evaluate.
///
/// **This name is a contract with the control plane**, which ships its authoritative
/// module as `package s3.authz`. If s0 queries any other rule, a pushed bundle evaluates
/// to **undefined** — which fails closed to a deny on every request, with no error
/// anywhere and every test green over a deny-all production policy.
pub const DECISION_RULE: &str = "data.s3.authz.decision";

/// [`DECISION_RULE`] in OPA's Data API / decision-log path form:
/// `data.s3.authz.decision` → `s3/authz/decision`.
///
/// Derived rather than written out a second time, so the sidecar's URL and the audit
/// record's `path` cannot drift from the entrypoint independently.
pub fn decision_rule_path() -> String {
    DECISION_RULE
        .strip_prefix("data.")
        .unwrap_or(DECISION_RULE)
        .replace('.', "/")
}

/// A parsed bundle: the policy data and, optionally, the policy module pushed with it.
#[derive(Debug, Clone)]
pub struct ParsedBundle {
    /// The rego module the control plane pushed, if any. `None` ⇒ use the compiled-in
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
    /// A control-plane document that arrives **without its module** is a silent
    /// deny-all: the compiled-in fallback keys grants on the RAW `principal.sub`, while
    /// the projection keys them `user:<oidc sub>` / `sa:<client id>`, so every request in
    /// the organization is denied despite valid grants. It fails closed, which is why
    /// this logs rather than refuses to load — refusing leaves stale data in force.
    ///
    /// `grant_schema_version` is the discriminator, and version 0 is excluded
    /// deliberately: that is the operator's seed bundle, module-less by design and read
    /// by every pod at boot, so warning on it would teach everyone to ignore this line.
    /// The condition lives in [`Self::is_platform_data_missing_its_module`] so it can be
    /// asserted without a tracing subscriber.
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

    /// True when this is a control-plane-projected document (`grant_schema_version ≥ 1`)
    /// that arrived without its rego module. See
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

/// One installed revision: the policy data, and the bucket placement derived from it.
///
/// Not `Deserialize`, deliberately: [`Bundle::new`] is the only constructor, so the
/// placement can never be absent from a v3 document — a decoded `Bundle` would carry
/// [`BucketPlacement::Unplaced`] for one and silently switch the placement gate off.
#[derive(Debug, Clone)]
pub struct Bundle {
    /// Opaque monotonic revision from the control-plane bundle builder (an etag/version).
    pub revision: String,
    /// The projected policy data (`tenants`, `org_settings`, …).
    pub data: serde_json::Value,
    placement: Arc<BucketPlacement>,
}

impl Bundle {
    pub fn new(revision: impl Into<String>, data: serde_json::Value) -> Self {
        let placement = Arc::new(BucketPlacement::from_data(&data));
        Bundle {
            revision: revision.into(),
            data,
            placement,
        }
    }

    /// The placement this revision publishes. An `Arc` so a request can hold the one it
    /// was admitted under for its whole life, the way it holds its route.
    #[must_use]
    pub fn placement(&self) -> &Arc<BucketPlacement> {
        &self.placement
    }
}

/// The `grant_schema_version` from which a bundle places buckets. Below it the request
/// path is today's, byte for byte: no index, and `ListBuckets` is the backend's answer.
pub const PLACEMENT_SCHEMA_VERSION: u64 = 3;

/// Bundle field names the placement is read from. A contract with the control plane's
/// projection, named once so the reader, the fixtures and the drift tests share them.
pub const GRANT_SCHEMA_VERSION_FIELD: &str = "grant_schema_version";
pub const BACKEND_FIELD: &str = "backend";
pub const BUCKET_ATTRIBUTES_FIELD: &str = "bucket_attributes";
pub const OBJECT_NAME_FIELD: &str = "object_name";
pub const CREATED_AT_FIELD: &str = "created_at";

/// How the bundle in force places buckets on this gateway's backend.
///
/// On a backend whose upstream identity is shared by every tenant of an organization,
/// this is what keeps one tenant out of another's bucket: the backend would serve either.
#[derive(Debug)]
pub enum BucketPlacement {
    /// A document below [`PLACEMENT_SCHEMA_VERSION`], or one with no version at all. No
    /// placement is published and nothing about the request path changes.
    Unplaced,
    /// A placing document this gateway cannot read. Every request is refused with this
    /// reason: a placement half-understood is a placement not enforced.
    Unusable(String),
    Placed(PlacementIndex),
}

/// A v3 bundle's placement: the backend it was projected for, and `S3 name → owning
/// tenant` for every bucket on it.
#[derive(Debug)]
pub struct PlacementIndex {
    backend_id: String,
    buckets: HashMap<String, PlacedBucket>,
    /// Each tenant's buckets, the `ListBuckets` answer before visibility is applied.
    /// A contested bucket is in no tenant's list.
    listings: HashMap<String, Vec<String>>,
    /// Set by the first request refused for a backend mismatch, so the error is logged
    /// once per revision rather than once per request.
    mismatch_logged: AtomicBool,
    /// The byte quotas this revision states. Empty for a backend with native quotas.
    quotas: BundleQuotas,
}

#[derive(Debug)]
struct PlacedBucket {
    owner: BucketOwner,
    object_name: Option<String>,
    created_at: Option<DateTime<Utc>>,
}

#[derive(Debug)]
enum BucketOwner {
    Tenant(String),
    /// Listed under more than one tenant: the projection broke its own contract, and no
    /// tenant may use the bucket until it says which one owns it.
    Contested,
}

/// One bucket of a tenant's bundle listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedBucket {
    pub name: String,
    /// `created_at`, when the bundle carried a parseable one.
    pub created_at: Option<DateTime<Utc>>,
}

/// Why the placement refuses a decision. Asked before the PDP, so a refused question is
/// never posed to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlacementRefusal {
    /// The bundle in force places buckets but cannot be read.
    Unusable(String),
    /// The bundle was projected for another backend than the one this request routes to.
    BackendMismatch { bundle: String, route: String },
    /// The bucket is placed under a different tenant than the requester's.
    AnotherTenant,
    /// The bucket is placed under more than one tenant.
    Contested,
    /// No tenant has the bucket on this backend.
    NotOnBackend,
}

impl PlacementRefusal {
    /// The audit-facing reason, which is also what the client is told: like every other
    /// gateway refusal it names the layer that refused. Telling "another tenant" from "not
    /// here" discloses that the name is taken on this backend, which a bucket creation
    /// refused as "name already used" discloses anyway.
    #[must_use]
    pub fn reason(&self) -> String {
        match self {
            PlacementRefusal::Unusable(why) => format!(
                "deny (gateway): the policy bundle in force cannot be used ({why}); every \
                 request is refused until the control plane serves a readable one"
            ),
            PlacementRefusal::BackendMismatch { bundle, route } => format!(
                "deny (gateway): the policy bundle in force was projected for backend \
                 {bundle:?}, but this request routes to backend {route:?}; every request \
                 is refused until the control plane serves this backend's bundle"
            ),
            PlacementRefusal::AnotherTenant => BUCKET_OF_ANOTHER_TENANT.to_string(),
            PlacementRefusal::Contested => format!(
                "{BUCKET_OF_ANOTHER_TENANT}: the policy bundle places it under more than \
                 one tenant"
            ),
            PlacementRefusal::NotOnBackend => BUCKET_NOT_ON_THIS_BACKEND.to_string(),
        }
    }
}

/// The refusal reason for a bucket the bundle places under another tenant.
pub const BUCKET_OF_ANOTHER_TENANT: &str = "deny (gateway): bucket belongs to another tenant";

/// The refusal reason for a bucket no tenant has on this backend.
pub const BUCKET_NOT_ON_THIS_BACKEND: &str = "deny (gateway): bucket not on this backend";

impl BucketPlacement {
    /// Read the placement a document publishes. Logs at `error!` for a placing document
    /// that cannot be used, or that lists a bucket under several tenants: each is a
    /// control-plane defect that denies requests, and a denial with no log is undebuggable.
    #[must_use]
    pub fn from_data(data: &serde_json::Value) -> Self {
        let placement = Self::read(data);
        match &placement {
            BucketPlacement::Unusable(why) => tracing::error!(
                reason = %why,
                "the policy bundle places buckets but cannot be read; EVERY request is \
                 refused until the control plane serves a readable one"
            ),
            BucketPlacement::Placed(index) => index.log_load_defects(),
            BucketPlacement::Unplaced => {}
        }
        placement
    }

    fn read(data: &serde_json::Value) -> Self {
        let Some(version) = data.get(GRANT_SCHEMA_VERSION_FIELD) else {
            return BucketPlacement::Unplaced;
        };
        let version = match version.as_u64() {
            Some(v) if v < PLACEMENT_SCHEMA_VERSION => return BucketPlacement::Unplaced,
            Some(v) => v,
            // A version at or past the placing one that is not an integer cannot be told
            // apart from a placing document, so it is refused rather than taken as old.
            None if version
                .as_f64()
                .is_some_and(|v| v >= PLACEMENT_SCHEMA_VERSION as f64) =>
            {
                return BucketPlacement::Unusable(format!(
                    "data.{GRANT_SCHEMA_VERSION_FIELD} is {version}, not an integer"
                ));
            }
            // No version was ever anything but a number, so one that is not (`"3"`, `null`)
            // is a projection defect. Read as "old", it would switch the placement gate off.
            None if !version.is_number() => {
                return BucketPlacement::Unusable(format!(
                    "data.{GRANT_SCHEMA_VERSION_FIELD} is {version}, not a number"
                ));
            }
            None => return BucketPlacement::Unplaced,
        };

        let backend_id = match data
            .get(BACKEND_FIELD)
            .and_then(|b| b.get("id"))
            .and_then(serde_json::Value::as_str)
        {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => {
                return BucketPlacement::Unusable(format!(
                    "a version {version} bundle must name its backend in \
                     data.{BACKEND_FIELD}.id"
                ));
            }
        };

        let tenants = match data.get("tenants") {
            None => None,
            Some(serde_json::Value::Object(tenants)) => Some(tenants),
            Some(_) => {
                return BucketPlacement::Unusable("data.tenants is not an object".to_string());
            }
        };
        let mut quotas: HashMap<QuotaScope, QuotaSpec> = HashMap::new();
        if let Some(spec) = QuotaSpec::read(data.get(BACKEND_QUOTA_FIELD)) {
            quotas.insert(QuotaScope::Backend(backend_id.clone()), spec);
        }
        // Every tenant claiming each bucket, so a bucket listed twice is seen as such
        // rather than silently won by whichever tenant iterates last.
        let mut claims: BTreeMap<&str, Vec<(&str, &serde_json::Value)>> = BTreeMap::new();
        for (tenant, tenant_data) in tenants.into_iter().flatten() {
            if let Some(spec) = QuotaSpec::read(tenant_data.get(QUOTA_FIELD)) {
                quotas.insert(QuotaScope::Tenant(tenant.clone()), spec);
            }
            let attributes = match tenant_data.get(BUCKET_ATTRIBUTES_FIELD) {
                None => continue,
                Some(serde_json::Value::Object(attributes)) => attributes,
                Some(_) => {
                    return BucketPlacement::Unusable(format!(
                        "data.tenants.{tenant}.{BUCKET_ATTRIBUTES_FIELD} is not an object"
                    ));
                }
            };
            for (bucket, attrs) in attributes {
                // The empty name is the account scope, never a bucket.
                if !bucket.is_empty() {
                    claims.entry(bucket).or_default().push((tenant, attrs));
                }
            }
        }

        let mut buckets = HashMap::with_capacity(claims.len());
        let mut listings: HashMap<String, Vec<String>> = HashMap::new();
        for (bucket, claimants) in claims {
            let placed = match claimants.as_slice() {
                [(tenant, attrs)] => {
                    listings
                        .entry((*tenant).to_string())
                        .or_default()
                        .push(bucket.to_string());
                    // Only a placed bucket's: a contested one is refused before any write.
                    if let Some(spec) = QuotaSpec::read(attrs.get(QUOTA_FIELD)) {
                        quotas.insert(QuotaScope::Bucket(bucket.to_string()), spec);
                    }
                    PlacedBucket {
                        owner: BucketOwner::Tenant((*tenant).to_string()),
                        object_name: attrs
                            .get(OBJECT_NAME_FIELD)
                            .and_then(serde_json::Value::as_str)
                            .map(str::to_string),
                        created_at: attrs
                            .get(CREATED_AT_FIELD)
                            .and_then(serde_json::Value::as_str)
                            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                            .map(|t| t.with_timezone(&Utc)),
                    }
                }
                _ => PlacedBucket {
                    owner: BucketOwner::Contested,
                    object_name: None,
                    created_at: None,
                },
            };
            buckets.insert(bucket.to_string(), placed);
        }
        BucketPlacement::Placed(PlacementIndex {
            backend_id,
            buckets,
            listings,
            mismatch_logged: AtomicBool::new(false),
            quotas: BundleQuotas::new(quotas),
        })
    }

    /// Whether this revision places buckets, readable or not. `false` is the pre-v3 path.
    #[must_use]
    pub fn places_buckets(&self) -> bool {
        !matches!(self, BucketPlacement::Unplaced)
    }

    /// Why a decision about `bucket` (`""` for the account scope) by `tenant`, on a
    /// request routed to `backend_id`, must be refused — or `None` to ask the PDP.
    #[must_use]
    pub fn refusal(
        &self,
        backend_id: &str,
        tenant: &str,
        bucket: &str,
    ) -> Option<PlacementRefusal> {
        match self {
            BucketPlacement::Unplaced => None,
            BucketPlacement::Unusable(why) => Some(PlacementRefusal::Unusable(why.clone())),
            BucketPlacement::Placed(index) => index.refusal(backend_id, tenant, bucket),
        }
    }

    /// `tenant`'s buckets, for a `ListBuckets` routed to `backend_id`: `None` when this
    /// revision places nothing (the backend is asked, as before), empty when it cannot be
    /// used for that backend.
    #[must_use]
    pub fn listing(&self, backend_id: &str, tenant: &str) -> Option<Vec<ListedBucket>> {
        match self {
            BucketPlacement::Unplaced => None,
            BucketPlacement::Unusable(_) => Some(Vec::new()),
            BucketPlacement::Placed(index) if index.backend_id != backend_id => Some(Vec::new()),
            BucketPlacement::Placed(index) => Some(
                index
                    .listings
                    .get(tenant)
                    .into_iter()
                    .flatten()
                    .map(|name| ListedBucket {
                        name: name.clone(),
                        created_at: index.buckets.get(name).and_then(|b| b.created_at),
                    })
                    .collect(),
            ),
        }
    }

    /// The `object_name` the bundle gives `bucket`, the control plane's own name for it.
    #[must_use]
    pub fn object_name(&self, bucket: &str) -> Option<&str> {
        match self {
            BucketPlacement::Placed(index) => index.buckets.get(bucket)?.object_name.as_deref(),
            _ => None,
        }
    }

    /// The byte quotas this revision states, or `None` when it states none: below v3, or a
    /// placing document with no `quota` anywhere (a backend with native quotas).
    #[must_use]
    pub fn quotas(&self) -> Option<&BundleQuotas> {
        match self {
            BucketPlacement::Placed(index) if !index.quotas.is_empty() => Some(&index.quotas),
            _ => None,
        }
    }
}

impl PlacementIndex {
    fn refusal(&self, backend_id: &str, tenant: &str, bucket: &str) -> Option<PlacementRefusal> {
        if self.backend_id != backend_id {
            if !self.mismatch_logged.swap(true, Ordering::Relaxed) {
                tracing::error!(
                    bundle_backend = %self.backend_id,
                    gateway_backend = %backend_id,
                    "the policy bundle in force was projected for another backend; EVERY \
                     request is refused until the control plane serves this backend's bundle"
                );
            }
            return Some(PlacementRefusal::BackendMismatch {
                bundle: self.backend_id.clone(),
                route: backend_id.to_string(),
            });
        }
        if bucket.is_empty() {
            return None;
        }
        let Some(placed) = self.buckets.get(bucket) else {
            return Some(PlacementRefusal::NotOnBackend);
        };
        match &placed.owner {
            BucketOwner::Tenant(owner) if owner == tenant => None,
            BucketOwner::Tenant(_) => Some(PlacementRefusal::AnotherTenant),
            BucketOwner::Contested => Some(PlacementRefusal::Contested),
        }
    }

    fn log_load_defects(&self) {
        let contested: Vec<&str> = self
            .buckets
            .iter()
            .filter(|(_, b)| matches!(b.owner, BucketOwner::Contested))
            .map(|(name, _)| name.as_str())
            .collect();
        if !contested.is_empty() {
            tracing::error!(
                count = contested.len(),
                buckets = ?contested,
                "the policy bundle places these buckets under more than one tenant; every \
                 request naming one is refused"
            );
        }
        let undated = self
            .buckets
            .values()
            .filter(|b| matches!(b.owner, BucketOwner::Tenant(_)) && b.created_at.is_none())
            .count();
        if undated > 0 {
            tracing::warn!(
                count = undated,
                "buckets without a readable {CREATED_AT_FIELD}; they are listed without a \
                 creation date"
            );
        }
        let unreadable: Vec<String> = self
            .quotas
            .unreadable()
            .map(|(scope, why)| format!("{scope:?}: {why}"))
            .collect();
        if !unreadable.is_empty() {
            tracing::error!(
                count = unreadable.len(),
                quotas = ?unreadable,
                "the policy bundle states storage quotas that cannot be read; every write \
                 they cover is refused"
            );
        }
    }
}

/// Stable revision derived from raw bundle content: a content change is a new
/// revision, which is exactly the cache-invalidation signal.
///
/// **SHA-256, not `DefaultHasher`**, whose output is explicitly not stable across Rust
/// releases: a rebuild on a different toolchain would re-hash identical bytes to a new
/// revision, and two replicas of a rolling update would disagree about whether they hold
/// the same policy.
pub fn content_revision(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(raw.as_bytes());
    hex::encode(h.finalize())
}

/// The subject key the control plane's projection writes for a service account:
/// `sa:<client id>`, keyed on the identity provider's **client id** rather than any
/// internal identifier. The rego module composes the same string, so this is one key
/// space spelled in several places — pinned against the captured bundle in
/// `tests/data/platform/s3_gateway_bundle.json`.
pub fn service_account_subject_key(client_id: &str) -> String {
    format!("sa:{client_id}")
}

/// The bundle's subject key for either principal class: `sa:<client id>` for a service
/// account, `user:<oidc sub>` for a human.
///
/// Both spellings are the projection's, read off the captured document rather than
/// assumed. One function, so the two key spaces cannot drift apart at a new call site.
pub fn principal_subject_key(principal_type: crate::model::PrincipalType, sub: &str) -> String {
    match principal_type {
        crate::model::PrincipalType::ServiceAccount => service_account_subject_key(sub),
        crate::model::PrincipalType::User => format!("user:{sub}"),
    }
}

/// The bundle field publishing a tenant's **key epoch floor** — the lowest epoch a
/// derived long-lived key ([`crate::auth::derived`]) may carry and still be honoured.
///
/// A contract with the control plane: its projection writes the field, s0 reads it, and
/// nothing negotiates. Named here once so reader and writer point at the same string.
pub const KEY_EPOCH_FIELD: &str = "s3_key_epoch";

/// The optional per-subject override map, keyed by [`principal_subject_key`]. See
/// [`KEY_EPOCH_FIELD`].
pub const KEY_EPOCHS_FIELD: &str = "s3_key_epochs";

/// The effective key-epoch floor for `(tenant, subject_key)`: the greater of the tenant's
/// published epoch and the subject's override, or `None` when the tenant publishes none.
///
/// **`None` denies** — see [`crate::auth::KeyEpochFloor`] for the full argument. Every
/// degenerate input lands there, so an empty bundle, the operator's seed bundle, and a
/// control plane that does not publish this field all mean "no derived key works here",
/// the only direction a revocation channel may fail in.
///
/// A malformed **per-subject** entry is likewise ignored rather than defaulted, leaving
/// the tenant floor in force: an override can only raise the floor, so discarding a broken
/// one can never admit a key the tenant epoch already refuses.
pub fn bundle_key_epoch_floor(
    data: &serde_json::Value,
    tenant: &str,
    subject_key: &str,
) -> Option<u32> {
    if tenant.is_empty() {
        return None;
    }
    let tenant_data = data.get("tenants")?.get(tenant)?;
    let as_epoch = |v: &serde_json::Value| u32::try_from(v.as_u64()?).ok();
    let floor = as_epoch(tenant_data.get(KEY_EPOCH_FIELD)?)?;
    let per_subject = tenant_data
        .get(KEY_EPOCHS_FIELD)
        .and_then(|m| m.get(subject_key))
        .and_then(as_epoch)
        .unwrap_or(0);
    Some(floor.max(per_subject))
}

/// Does this bundle's policy data know `sa:<client_id>` as a **member subject** of
/// `tenant`?
///
/// The predicate is the policy's own membership rule, evaluated in Rust:
/// `is_object(data.tenants[<tenant>].user_attributes["sa:<client id>"])`. Nothing looser —
/// a key whose value is not an object is not a member to the policy either, and accepting
/// one would vend a credential denied on every request.
///
/// Every degenerate input answers `false`, so an empty bundle accepts nothing — the
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
/// `current()` is loaded per call, so the answer is always the revision in force at that
/// instant: a subject removed by a poll stops being accepted on the next request. See
/// [`crate::webidentity::TenantSubjects`] for why there must not be a second one.
impl crate::webidentity::TenantSubjects for BundleStore {
    fn knows_service_account(&self, tenant: &str, client_id: &str) -> bool {
        bundle_knows_service_account(&self.current().data, tenant, client_id)
    }
}

/// Derived-key revocation, answered from **this** store — the same one the PDP decides
/// against and the poller swaps. `current()` is loaded per call, so a key epoch raised by
/// a poll revokes on the very next request, with no cache to invalidate: revocation lands
/// at normal bundle latency.
impl crate::auth::KeyEpochFloor for BundleStore {
    fn key_epoch_floor(&self, tenant: &str, subject_key: &str) -> Option<u32> {
        bundle_key_epoch_floor(&self.current().data, tenant, subject_key)
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

    /// A captured control-plane document. Compiled into the test binary only.
    const PLATFORM_BUNDLE: &str = include_str!("../../tests/data/platform/s3_gateway_bundle.json");

    /// **The key shape, read off a real projected document rather than assumed.**
    ///
    /// If the control plane ever changed the spelling — an unprefixed client id, an
    /// internal id, `service-account:` — the STS door would look up a key nobody writes
    /// and refuse every tenant service account, while every test that made up its own
    /// bundle stayed green.
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
    /// The STS door holds the store itself, not a snapshot. A subject added by a poll is
    /// accepted immediately; a subject *removed* by one stops being accepted immediately,
    /// which is the half that matters, because that is a revocation.
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

    /// **The revocation channel for derived long-lived keys, and the direction absence
    /// fails in.** This is what makes the credential class safe, so the degenerate cases
    /// are the point rather than an afterthought.
    #[test]
    fn the_key_epoch_floor_is_published_per_tenant_and_its_absence_denies() {
        let data = serde_json::json!({
            "tenants": {
                "acme": {
                    "s3_key_epoch": 3,
                    // The surgical lever: one consumer cut off without touching the
                    // other four.
                    "s3_key_epochs": { "sa:leaked-registry": 9, "user:alice": 4 }
                },
                // A tenant that publishes no epoch at all.
                "quiet": { "user_attributes": {} }
            }
        });
        assert_eq!(
            bundle_key_epoch_floor(&data, "acme", "sa:trino-background"),
            Some(3),
            "the tenant floor applies to a subject with no override"
        );
        assert_eq!(
            bundle_key_epoch_floor(&data, "acme", "sa:leaked-registry"),
            Some(9),
            "a subject override must raise the floor for that subject alone"
        );
        // An override BELOW the tenant floor cannot loosen it — the floor is the max.
        assert_eq!(bundle_key_epoch_floor(&data, "acme", "user:alice"), Some(4));
        let lowered = serde_json::json!({ "tenants": { "acme": {
            "s3_key_epoch": 7, "s3_key_epochs": { "user:alice": 1 } } } });
        assert_eq!(
            bundle_key_epoch_floor(&lowered, "acme", "user:alice"),
            Some(7)
        );

        // Every shape of absent, unknown or broken denies.
        for (label, doc, tenant) in [
            ("tenant publishes nothing", data.clone(), "quiet"),
            ("tenant not in the bundle", data.clone(), "absent"),
            ("empty tenant name", data.clone(), ""),
            ("no document", serde_json::json!(null), "acme"),
            ("not an object", serde_json::json!("nope"), "acme"),
            ("no tenants map", serde_json::json!({}), "acme"),
            (
                "the operator's seed bundle",
                serde_json::json!({ "tenants": {}, "org_settings": { "freeze_writes": true } }),
                "acme",
            ),
            (
                "epoch is not a number",
                serde_json::json!({ "tenants": { "acme": { "s3_key_epoch": "3" } } }),
                "acme",
            ),
            (
                "epoch is negative",
                serde_json::json!({ "tenants": { "acme": { "s3_key_epoch": -1 } } }),
                "acme",
            ),
            (
                "epoch overflows u32",
                serde_json::json!({ "tenants": { "acme": { "s3_key_epoch": 4294967296u64 } } }),
                "acme",
            ),
            (
                "epoch is null",
                serde_json::json!({ "tenants": { "acme": { "s3_key_epoch": null } } }),
                "acme",
            ),
        ] {
            assert_eq!(
                bundle_key_epoch_floor(&doc, tenant, "sa:x"),
                None,
                "{label} must deny"
            );
        }

        // A malformed per-subject entry is discarded, leaving the tenant floor — which
        // can only ever be the stricter of the two, so this cannot admit anything.
        let broken_override = serde_json::json!({ "tenants": { "acme": {
            "s3_key_epoch": 5, "s3_key_epochs": { "sa:x": "nine", "sa:y": null } } } });
        assert_eq!(
            bundle_key_epoch_floor(&broken_override, "acme", "sa:x"),
            Some(5)
        );
        assert_eq!(
            bundle_key_epoch_floor(&broken_override, "acme", "sa:y"),
            Some(5)
        );

        // The field names are a contract with the control plane; assert them rather than
        // trust the literals above.
        assert_eq!(KEY_EPOCH_FIELD, "s3_key_epoch");
        assert_eq!(KEY_EPOCHS_FIELD, "s3_key_epochs");
    }

    /// The floor is read from the bundle **in force**, through the same store the PDP
    /// decides against — which is what makes revocation land at normal bundle latency.
    #[test]
    fn the_key_epoch_floor_follows_the_store_across_a_swap() {
        use crate::auth::KeyEpochFloor;
        let with = |epoch: serde_json::Value| serde_json::json!({ "tenants": { "acme": { "s3_key_epoch": epoch } } });
        let store = BundleStore::new(Bundle::new("rev-1", with(serde_json::json!(1))));
        // The handle is taken ONCE, as `Gateway::build` takes it at boot.
        let floors: &dyn KeyEpochFloor = &store;
        assert_eq!(floors.key_epoch_floor("acme", "sa:x"), Some(1));

        store.store(Bundle::new("rev-2", with(serde_json::json!(2))));
        assert_eq!(
            floors.key_epoch_floor("acme", "sa:x"),
            Some(2),
            "a revocation the poller published is not visible to the credential layer"
        );

        // And the tenant disappearing from the bundle denies, rather than freezing the
        // last floor it published.
        store.store(Bundle::new("rev-3", serde_json::json!({ "tenants": {} })));
        assert_eq!(floors.key_epoch_floor("acme", "sa:x"), None);
    }

    /// Both subject key spaces, composed in one place so a new call site cannot invent a
    /// third spelling. Asserted against the captured document, like the key shape above.
    #[test]
    fn the_subject_key_is_the_platforms_own_for_both_principal_classes() {
        use crate::model::PrincipalType;
        assert_eq!(
            principal_subject_key(PrincipalType::ServiceAccount, "pipeline"),
            "sa:pipeline"
        );
        assert_eq!(
            principal_subject_key(PrincipalType::User, "sub-a"),
            "user:sub-a"
        );

        let parsed = parse_bundle(PLATFORM_BUNDLE).expect("the captured bundle parses");
        let subjects = parsed.data["tenants"]["acme-prod"]["user_attributes"]
            .as_object()
            .expect("acme-prod has user_attributes");
        for key in [
            principal_subject_key(PrincipalType::ServiceAccount, "pipeline"),
            principal_subject_key(PrincipalType::User, "sub-a"),
        ] {
            assert!(
                subjects.contains_key(&key),
                "the captured platform bundle does not key {key}; keys are {:?}",
                subjects.keys().collect::<Vec<_>>()
            );
        }
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
        // A real projected document stripped of `policy`: the compiled-in default keys
        // grants on the raw sub and would deny the whole organization. Say so.
        let stripped = parse_bundle(
            r#"{ "data": { "grant_schema_version": 2,
                           "org_settings": { "freeze_writes": false },
                           "tenants": { "acme": {} } } }"#,
        )
        .unwrap();
        assert!(stripped.is_platform_data_missing_its_module());

        // The operator's seed bundle is version 0, module-less ON PURPOSE, and read by
        // every pod at boot. It must stay quiet.
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

    // ── bucket placement (grant_schema_version ≥ 3) ─────────────────────────────

    /// A v3 document on backend `archive`: `acme` owns `reports` and `logs`, `globex` owns
    /// `ledger`, and `shared` is claimed by both — the projection defect.
    fn v3() -> serde_json::Value {
        serde_json::json!({
            "grant_schema_version": 3,
            "backend": { "id": "archive", "kind": "s3" },
            "tenants": {
                "acme": { "bucket_attributes": {
                    "reports": { "denylist": {}, "object_name": "reports.archive",
                                 "created_at": "2026-01-02T03:04:05Z" },
                    "logs": { "denylist": {}, "object_name": "logs.archive",
                              "created_at": "not a date" },
                    "shared": { "denylist": {} }
                } },
                "globex": { "bucket_attributes": {
                    "ledger": { "denylist": {}, "object_name": "ledger.archive",
                                "created_at": "2026-02-03T04:05:06.789+02:00" },
                    "shared": { "denylist": {} }
                } },
                // A tenant with no buckets on this backend.
                "quiet": { "user_attributes": {} }
            }
        })
    }

    fn placed(data: &serde_json::Value) -> BucketPlacement {
        let placement = BucketPlacement::from_data(data);
        assert!(
            matches!(placement, BucketPlacement::Placed(_)),
            "expected a readable placement, got {placement:?}"
        );
        placement
    }

    /// The gate is version-driven, and below 3 it does not exist: today's documents — the
    /// operator's seed (v0), the platform's v2 and s0's own unversioned dev bundles — must
    /// keep today's request path exactly, forwarding included.
    #[test]
    fn placement_starts_at_version_3_and_nothing_older_is_placed() {
        let with = |v: serde_json::Value| {
            let mut doc = v3();
            doc["grant_schema_version"] = v;
            BucketPlacement::from_data(&doc)
        };
        let mut unversioned = v3();
        unversioned
            .as_object_mut()
            .expect("object")
            .remove("grant_schema_version");
        for (label, placement) in [
            ("no version", BucketPlacement::from_data(&unversioned)),
            ("v0 seed", with(serde_json::json!(0))),
            ("v1", with(serde_json::json!(1))),
            ("v2", with(serde_json::json!(2))),
            ("negative", with(serde_json::json!(-3))),
            ("below 3, fractional", with(serde_json::json!(2.5))),
        ] {
            assert!(
                matches!(placement, BucketPlacement::Unplaced),
                "{label}: {placement:?}"
            );
            assert!(!placement.places_buckets());
            // Unplaced refuses nothing and lists nothing: the backend is asked, as before.
            assert_eq!(placement.refusal("archive", "acme", "ledger"), None);
            assert_eq!(placement.listing("archive", "acme"), None);
        }
        for version in [3, 4, 99] {
            let placement = with(serde_json::json!(version));
            assert!(
                matches!(placement, BucketPlacement::Placed(_)),
                "v{version} must place: {placement:?}"
            );
        }
        // Not an integer, yet not below the placing version: unreadable, not old.
        let fractional = with(serde_json::json!(3.0));
        assert!(
            matches!(&fractional, BucketPlacement::Unusable(why) if why.contains("not an integer")),
            "{fractional:?}"
        );
        // Present but not a number at all: a projection defect, never an old document.
        for (label, version) in [
            ("a string", serde_json::json!("3")),
            ("a string below 3", serde_json::json!("2")),
            ("null", serde_json::Value::Null),
            ("a boolean", serde_json::json!(true)),
            ("an object", serde_json::json!({ "version": 3 })),
        ] {
            let placement = with(version);
            assert!(
                matches!(&placement, BucketPlacement::Unusable(why) if why.contains("not a number")),
                "{label}: {placement:?}"
            );
            assert!(placement.places_buckets(), "{label}");
            assert!(
                matches!(
                    placement.refusal("archive", "acme", "reports"),
                    Some(PlacementRefusal::Unusable(_))
                ),
                "{label}"
            );
            assert_eq!(
                placement.listing("archive", "acme"),
                Some(Vec::new()),
                "{label}"
            );
        }
        assert_eq!(PLACEMENT_SCHEMA_VERSION, 3);
    }

    /// The owning-tenant index: a bucket is usable by its owner only, and a bucket no
    /// tenant has is on no tenant of this backend.
    #[test]
    fn every_bucket_is_usable_by_its_owning_tenant_alone() {
        let placement = placed(&v3());
        assert_eq!(placement.refusal("archive", "acme", "reports"), None);
        assert_eq!(placement.refusal("archive", "globex", "ledger"), None);
        assert_eq!(
            placement.refusal("archive", "acme", "ledger"),
            Some(PlacementRefusal::AnotherTenant)
        );
        assert_eq!(
            placement.refusal("archive", "globex", "reports"),
            Some(PlacementRefusal::AnotherTenant)
        );
        // A tenant the bundle knows but that has nothing here, and one it does not know.
        assert_eq!(
            placement.refusal("archive", "quiet", "reports"),
            Some(PlacementRefusal::AnotherTenant)
        );
        assert_eq!(
            placement.refusal("archive", "nobody", "reports"),
            Some(PlacementRefusal::AnotherTenant)
        );
        for bucket in ["elsewhere", "Reports", "reports.archive", "report"] {
            assert_eq!(
                placement.refusal("archive", "acme", bucket),
                Some(PlacementRefusal::NotOnBackend),
                "{bucket} is an S3 name no tenant has here (object names do not count)"
            );
        }
        // The account scope names no bucket, so only a bundle-wide refusal applies.
        assert_eq!(placement.refusal("archive", "acme", ""), None);
        assert_eq!(placement.refusal("archive", "nobody", ""), None);
    }

    #[test]
    fn a_bucket_placed_under_two_tenants_is_refused_to_both() {
        let placement = placed(&v3());
        for tenant in ["acme", "globex", "quiet"] {
            assert_eq!(
                placement.refusal("archive", tenant, "shared"),
                Some(PlacementRefusal::Contested),
                "{tenant}"
            );
        }
        // …and it is listed for neither.
        for tenant in ["acme", "globex"] {
            let names: Vec<String> = placement
                .listing("archive", tenant)
                .expect("placed")
                .into_iter()
                .map(|b| b.name)
                .collect();
            assert!(
                !names.contains(&"shared".to_string()),
                "{tenant}: {names:?}"
            );
        }
    }

    /// `data.backend.id` must be the backend the request routes to. A bundle served to the
    /// wrong instance places buckets that are not there, so it refuses everything —
    /// including the account scope — and lists nothing.
    #[test]
    fn a_bundle_projected_for_another_backend_refuses_every_request() {
        let placement = placed(&v3());
        let mismatch = Some(PlacementRefusal::BackendMismatch {
            bundle: "archive".into(),
            route: "default".into(),
        });
        for bucket in ["reports", "ledger", "elsewhere", ""] {
            assert_eq!(
                placement.refusal("default", "acme", bucket),
                mismatch,
                "{bucket:?}"
            );
        }
        assert_eq!(placement.listing("default", "acme"), Some(Vec::new()));
        // A second refusal still refuses; only the log line is latched.
        assert_eq!(placement.refusal("default", "acme", "reports"), mismatch);
    }

    /// A placing document that cannot be read refuses everything rather than falling back
    /// to the unplaced path, which would switch the gate off for exactly the bundles that
    /// need it.
    #[test]
    fn an_unreadable_placing_bundle_refuses_every_request() {
        let mut no_backend = v3();
        no_backend
            .as_object_mut()
            .expect("object")
            .remove("backend");
        let mut no_id = v3();
        no_id["backend"] = serde_json::json!({ "kind": "s3" });
        let mut empty_id = v3();
        empty_id["backend"]["id"] = serde_json::json!("");
        let mut numeric_id = v3();
        numeric_id["backend"]["id"] = serde_json::json!(7);
        let mut tenants_not_object = v3();
        tenants_not_object["tenants"] = serde_json::json!(["acme"]);
        let mut attributes_not_object = v3();
        attributes_not_object["tenants"]["globex"]["bucket_attributes"] =
            serde_json::json!(["ledger"]);

        for (label, doc) in [
            ("no data.backend", no_backend),
            ("no backend id", no_id),
            ("empty backend id", empty_id),
            ("backend id not a string", numeric_id),
            ("tenants not an object", tenants_not_object),
            ("bucket_attributes not an object", attributes_not_object),
        ] {
            let placement = BucketPlacement::from_data(&doc);
            assert!(
                matches!(placement, BucketPlacement::Unusable(_)),
                "{label}: {placement:?}"
            );
            assert!(placement.places_buckets(), "{label}");
            for (tenant, bucket) in [("acme", "reports"), ("globex", "ledger"), ("acme", "")] {
                assert!(
                    matches!(
                        placement.refusal("archive", tenant, bucket),
                        Some(PlacementRefusal::Unusable(_))
                    ),
                    "{label}: {tenant}/{bucket:?} must be refused"
                );
            }
            assert_eq!(
                placement.listing("archive", "acme"),
                Some(Vec::new()),
                "{label}"
            );
        }

        // An absent tenants map is not malformed: nothing is placed, so every bucket is
        // simply not on this backend.
        let mut no_tenants = v3();
        no_tenants
            .as_object_mut()
            .expect("object")
            .remove("tenants");
        let placement = placed(&no_tenants);
        assert_eq!(
            placement.refusal("archive", "acme", "reports"),
            Some(PlacementRefusal::NotOnBackend)
        );
        assert_eq!(placement.listing("archive", "acme"), Some(Vec::new()));
    }

    /// The `ListBuckets` source: the tenant's own uncontested buckets, with `created_at`
    /// as the creation date when it parses — and nothing of any other tenant's.
    #[test]
    fn the_listing_is_the_tenants_own_buckets_with_their_creation_dates() {
        let placement = placed(&v3());
        let acme = placement.listing("archive", "acme").expect("placed");
        assert_eq!(
            acme,
            vec![
                ListedBucket {
                    name: "logs".into(),
                    // "not a date" is listed, undated, rather than dropped.
                    created_at: None,
                },
                ListedBucket {
                    name: "reports".into(),
                    created_at: Some(
                        DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                            .expect("date")
                            .with_timezone(&Utc)
                    ),
                },
            ]
        );
        let globex = placement.listing("archive", "globex").expect("placed");
        assert_eq!(globex.len(), 1);
        assert_eq!(globex[0].name, "ledger");
        assert_eq!(
            globex[0].created_at.map(|t| t.to_rfc3339()),
            Some("2026-02-03T02:05:06.789+00:00".to_string()),
            "an offset timestamp is normalized to UTC, not misread"
        );
        assert_eq!(placement.listing("archive", "quiet"), Some(Vec::new()));
        assert_eq!(placement.listing("archive", "nobody"), Some(Vec::new()));
    }

    #[test]
    fn the_object_name_is_the_bundles_own_and_only_for_a_placed_bucket() {
        let placement = placed(&v3());
        assert_eq!(placement.object_name("reports"), Some("reports.archive"));
        assert_eq!(placement.object_name("ledger"), Some("ledger.archive"));
        assert_eq!(placement.object_name("shared"), None);
        assert_eq!(placement.object_name("elsewhere"), None);
        assert_eq!(BucketPlacement::Unplaced.object_name("reports"), None);
    }

    /// The placement is derived once, on load, and travels with its revision: swapping
    /// the store swaps it, in both directions.
    #[test]
    fn the_placement_is_computed_on_load_and_follows_the_store() {
        let store = BundleStore::new(Bundle::new(
            "rev-v2",
            serde_json::json!({
                "grant_schema_version": 2, "tenants": {}
            }),
        ));
        assert!(!store.current().placement().places_buckets());

        store.store(Bundle::new("rev-v3", v3()));
        let pinned = store.current().placement().clone();
        assert_eq!(pinned.refusal("archive", "acme", "reports"), None);

        store.store(Bundle::new(
            "rev-v2b",
            serde_json::json!({ "grant_schema_version": 2 }),
        ));
        assert!(!store.current().placement().places_buckets());
        // A request that pinned the v3 placement keeps deciding under it.
        assert_eq!(
            pinned.refusal("archive", "acme", "ledger"),
            Some(PlacementRefusal::AnotherTenant)
        );
    }

    // ── byte quotas (ADR-010) ───────────────────────────────────────────────────

    fn quota_json(limit: u64, used: u64) -> serde_json::Value {
        serde_json::json!({
            "limit_bytes": limit, "used_bytes": used, "collected_at": "2026-10-01T12:00:00Z"
        })
    }

    fn limit_of(placement: &BucketPlacement, scope: QuotaScope) -> Option<u64> {
        match placement.quotas()?.get(&scope)? {
            QuotaSpec::Limit(quota) => Some(quota.limit_bytes),
            QuotaSpec::Unreadable(why) => panic!("{scope:?} is unreadable: {why}"),
        }
    }

    /// Each of the three levels is read from where the contract puts it, keyed the way a
    /// write names it: the S3 name, the tenant, and the backend the bundle names.
    #[test]
    fn quotas_are_read_from_the_bucket_the_tenant_and_the_backend() {
        let mut doc = v3();
        doc["backend_quota"] = quota_json(1_000, 10);
        doc["tenants"]["acme"]["quota"] = quota_json(500, 10);
        doc["tenants"]["acme"]["bucket_attributes"]["reports"]["quota"] = quota_json(100, 10);
        // A tenant with no bucket here can still carry its ceiling.
        doc["tenants"]["quiet"]["quota"] = quota_json(50, 0);
        // A contested bucket's quota is never consulted: it is refused before any write.
        doc["tenants"]["acme"]["bucket_attributes"]["shared"]["quota"] = quota_json(1, 0);
        let placement = placed(&doc);
        assert_eq!(
            limit_of(&placement, QuotaScope::Backend("archive".into())),
            Some(1_000)
        );
        assert_eq!(
            limit_of(&placement, QuotaScope::Tenant("acme".into())),
            Some(500)
        );
        assert_eq!(
            limit_of(&placement, QuotaScope::Tenant("quiet".into())),
            Some(50)
        );
        assert_eq!(
            limit_of(&placement, QuotaScope::Bucket("reports".into())),
            Some(100)
        );
        assert_eq!(
            limit_of(&placement, QuotaScope::Bucket("logs".into())),
            None
        );
        assert_eq!(
            limit_of(&placement, QuotaScope::Bucket("shared".into())),
            None
        );
        assert_eq!(
            limit_of(&placement, QuotaScope::Tenant("globex".into())),
            None
        );
    }

    /// No `quota` anywhere is no enforcement at all — the Ceph shape, where the backend
    /// keeps its native quotas — and below v3 a `quota` key means nothing.
    #[test]
    fn a_document_without_quotas_or_below_v3_states_none() {
        assert!(placed(&v3()).quotas().is_none());
        let mut nulls = v3();
        nulls["backend_quota"] = serde_json::Value::Null;
        nulls["tenants"]["acme"]["quota"] = serde_json::Value::Null;
        assert!(placed(&nulls).quotas().is_none(), "null is no quota");

        let mut v2 = v3();
        v2["grant_schema_version"] = serde_json::json!(2);
        v2["backend_quota"] = quota_json(0, 0);
        v2["tenants"]["acme"]["bucket_attributes"]["reports"]["quota"] = quota_json(0, 0);
        assert!(BucketPlacement::from_data(&v2).quotas().is_none());
    }

    /// A quota the document states but the gateway cannot read is kept as unreadable, so
    /// the writes it covers are refused rather than left unlimited.
    #[test]
    fn an_unreadable_quota_is_kept_as_such_never_dropped() {
        let mut doc = v3();
        doc["tenants"]["acme"]["bucket_attributes"]["reports"]["quota"] = serde_json::json!({ "limit_bytes": "100", "used_bytes": 0,
                                "collected_at": "2026-10-01T12:00:00Z" });
        let placement = placed(&doc);
        let quotas = placement.quotas().expect("a stated quota");
        assert!(matches!(
            quotas.get(&QuotaScope::Bucket("reports".into())),
            Some(QuotaSpec::Unreadable(why)) if why.contains("limit_bytes")
        ));
        assert_eq!(quotas.unreadable().count(), 1);
    }

    /// The two bucket-level reasons are the audited contract the control plane reads.
    #[test]
    fn the_placement_reasons_name_the_gateway_and_the_cause() {
        assert_eq!(
            PlacementRefusal::AnotherTenant.reason(),
            "deny (gateway): bucket belongs to another tenant"
        );
        assert_eq!(
            PlacementRefusal::NotOnBackend.reason(),
            "deny (gateway): bucket not on this backend"
        );
        assert!(
            PlacementRefusal::Contested
                .reason()
                .starts_with("deny (gateway): bucket belongs to another tenant")
        );
        let mismatch = PlacementRefusal::BackendMismatch {
            bundle: "archive".into(),
            route: "default".into(),
        }
        .reason();
        assert!(
            mismatch.starts_with("deny (gateway):")
                && mismatch.contains("\"archive\"")
                && mismatch.contains("\"default\""),
            "{mismatch}"
        );
        assert!(
            PlacementRefusal::Unusable("why".into())
                .reason()
                .starts_with("deny (gateway):")
        );
    }
}
