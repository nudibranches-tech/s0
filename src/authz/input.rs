//! The OPA input contract — the core interface of the gateway.
//!
//! This is a *superset* of a typical in-backend authorization input: the gateway sees
//! the full parsed request (multi-delete keys, copy source, list prefix, object tags)
//! that an in-RGW hook cannot. The field names here are load-bearing — the rego reads
//! them by name — so treat this struct as a stable wire schema, not an internal type.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::{Action, BackendKind, PrincipalType};

/// Every field of [`OpaInput`] as it appears on the wire, in declaration order.
///
/// Kept in step with the struct by `opa_input_fields_is_exhaustive`, which
/// destructures an `OpaInput` **without** `..` — so adding a field is a *compile*
/// error until this list is updated. That matters because this list is what
/// `tests/fixture_drift.rs` checks the rego's own `input.<field>` references against:
/// the failure that produced 35 green tests over a deny-all production was a policy
/// reading a field (`input.op`) no producer ever emitted.
pub const OPA_INPUT_FIELDS: &[&str] = &[
    "principal",
    "backend",
    "tenant",
    "organization_id",
    "action",
    "bucket",
    "object",
    "prefix",
    "copy_source",
    "delete_keys",
    "object_tags",
    "request",
];

/// One authorization question posed to the PDP for one parsed request (or, for
/// blind-spot ops, one sub-decision — e.g. one key of a multi-delete, or the
/// source-read half of a copy).
///
/// `deny_unknown_fields` is load-bearing, not tidiness: it is what makes
/// [`crate::authz::capture::round_trip`] able to detect a renamed or dropped field.
/// Without it a captured document carrying `op` would deserialize happily, the field
/// would vanish on re-serialization, and the drift gate would be blind to exactly the
/// mismatch it exists to find. Not applied to [`PrincipalAttributes`], which uses
/// `#[serde(flatten)]` — the two are incompatible by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaInput {
    pub principal: Principal,
    pub backend: Backend,
    /// Tenant slug == Ceph tenant.
    pub tenant: String,
    /// Organization owning the tenant. Trusted org attribution for org-global
    /// deny rules and for fail-closed audit.
    pub organization_id: String,
    pub action: Action,
    pub bucket: String,
    /// Full object key — present for object ops, `None` for bucket/list ops.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object: Option<String>,
    /// List prefix — present for `ListObjects*`. May be rewritten by an obligation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// CopyObject source (blind spot #1 — from the `x-amz-copy-source` header).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_source: Option<CopySource>,
    /// Multi-delete keys (blind spot #2 — from the XML body). Present only when a
    /// single decision covers the whole batch; per-key decisions set `object`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delete_keys: Option<Vec<String>>,
    /// Object tags fetched on demand for ABAC. Gated behind a future opt-in — never
    /// populated until the on-demand tag fetch is wired.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_tags: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub request: RequestMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Principal {
    pub sub: String,
    #[serde(rename = "type")]
    pub kind: PrincipalType,
    pub attributes: PrincipalAttributes,
}

/// Principal attributes: `groups` is first-class (grants expand through groups),
/// any remaining OIDC/claim attributes flow through `extra` for ABAC.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PrincipalAttributes {
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(flatten, default)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    pub id: String,
    pub kind: BackendKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CopySource {
    pub bucket: String,
    pub key: String,
}

/// Non-authoritative request context surfaced to policy for ABAC / logging.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestMeta {
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers_subset: BTreeMap<String, String>,
}

/// Fields deliberately *absent* from [`OpaInput::resource_key`], with the reason each
/// one is safe to omit. Anything not listed here is in the key by construction.
///
/// Pinned by `opa_input_fields_is_exhaustive` (every entry must be a real field, and
/// the list itself is asserted verbatim) so a future field cannot join it by accident,
/// and exercised field-by-field by
/// `resource_key_covers_every_field_that_is_not_deliberately_excluded`.
const RESOURCE_KEY_EXCLUDED: &[&str] = &[
    // Already the other half of the cache key (`pdp/cache.rs`), verbatim.
    "principal",
    // On-demand ⇒ `has_on_demand_data()` ⇒ the decision is never cached at all.
    "object_tags",
];

impl OpaInput {
    /// Stable cache identity for the resource half of the decision-cache key: a
    /// SHA-256 over the canonical JSON of the whole input minus
    /// [`RESOURCE_KEY_EXCLUDED`].
    ///
    /// **Derived, not enumerated** (plan B-4). The previous version listed six fields
    /// by hand and so omitted `copy_source` and `request` — two `CopyObject`s to the
    /// same destination from *different* sources collided on one cache entry, and a
    /// bundle-pushed policy reading `input.copy_source` would have been served a stale
    /// verdict with nothing failing. A digest over the serialized document cannot
    /// develop that hole: a new field is in the key the moment it is on the wire.
    pub fn resource_key(&self) -> crate::error::Result<String> {
        use sha2::{Digest, Sha256};

        let mut v = serde_json::to_value(self)?;
        let obj = v
            .as_object_mut()
            .expect("OpaInput serializes to a JSON object");
        for field in RESOURCE_KEY_EXCLUDED {
            obj.remove(*field);
        }
        // `serde_json::Map` is a `BTreeMap` here (the `preserve_order` feature is off),
        // so `to_string` is key-sorted and the digest is stable across runs, machines
        // and replicas.
        let mut h = Sha256::new();
        h.update(b"s0.authz.resource_key.v1\n");
        h.update(v.to_string().as_bytes());
        Ok(hex::encode(h.finalize()))
    }

    /// True when the input carries on-demand data whose freshness the
    /// revision-keyed cache cannot guarantee.
    pub fn has_on_demand_data(&self) -> bool {
        self.object_tags.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::BackendKind;

    fn sample() -> OpaInput {
        OpaInput {
            principal: Principal {
                sub: "alice".into(),
                kind: PrincipalType::User,
                attributes: PrincipalAttributes::default(),
            },
            backend: Backend {
                id: "bay-1".into(),
                kind: BackendKind::Ceph,
            },
            tenant: "acme".into(),
            organization_id: "org-acme".into(),
            action: Action::ReadObjects,
            bucket: "reports".into(),
            object: Some("2024/q1.csv".into()),
            prefix: None,
            copy_source: None,
            delete_keys: None,
            object_tags: None,
            request: RequestMeta::default(),
        }
    }

    #[test]
    fn opa_input_fields_is_exhaustive() {
        // Written WITHOUT `..` on purpose. serde has no reflection, so nothing else can
        // tell `OPA_INPUT_FIELDS` that a field was added; this destructuring can, and
        // it does it at compile time. If you are here because the compiler complained
        // about a missing binding: add the field to `OPA_INPUT_FIELDS` and to the
        // `names` list below, then decide whether it belongs in `resource_key` and in
        // `has_on_demand_data` — a field that is neither is silently outside the
        // decision cache key.
        let OpaInput {
            principal,
            backend,
            tenant,
            organization_id,
            action,
            bucket,
            object,
            prefix,
            copy_source,
            delete_keys,
            object_tags,
            request,
        } = sample();
        let names = [
            stringify!(principal),
            stringify!(backend),
            stringify!(tenant),
            stringify!(organization_id),
            stringify!(action),
            stringify!(bucket),
            stringify!(object),
            stringify!(prefix),
            stringify!(copy_source),
            stringify!(delete_keys),
            stringify!(object_tags),
            stringify!(request),
        ];
        // Bind every destructured value so an unused-variable warning cannot be the
        // reason someone reaches for `..`.
        let _ = (principal, backend, tenant, organization_id, action, bucket);
        let _ = (
            object,
            prefix,
            copy_source,
            delete_keys,
            object_tags,
            request,
        );
        assert_eq!(names.as_slice(), OPA_INPUT_FIELDS);

        // The membership assertion this doc comment asks for. `resource_key` is now a
        // digest over the serialized input minus `RESOURCE_KEY_EXCLUDED`, so "is this
        // field in the decision-cache key?" reduces to "is it off that list?" — which
        // is checkable here, statically, for the whole field set.
        for field in RESOURCE_KEY_EXCLUDED {
            assert!(
                OPA_INPUT_FIELDS.contains(field),
                "{field} is excluded from resource_key but is not an OpaInput field"
            );
        }
        assert_eq!(
            RESOURCE_KEY_EXCLUDED,
            ["principal", "object_tags"],
            "a field left out of the decision-cache key needs a reason at \
             RESOURCE_KEY_EXCLUDED and a case in \
             resource_key_covers_every_field_that_is_not_deliberately_excluded"
        );
    }

    #[test]
    fn resource_key_covers_every_field_that_is_not_deliberately_excluded() {
        // Proves the derivation empirically, field by field: mutate one field, the key
        // must move. This is what makes the copy_source hole (two CopyObjects to the
        // same destination from different sources sharing a cache entry) impossible to
        // reintroduce, and it extends to `request.params` for free.
        let base = sample().resource_key().expect("key");

        let mut m = sample();
        m.backend.id = "bay-2".into();
        assert_ne!(base, m.resource_key().unwrap(), "backend");

        let mut m = sample();
        m.tenant = "other".into();
        assert_ne!(base, m.resource_key().unwrap(), "tenant");

        let mut m = sample();
        m.organization_id = "org-other".into();
        assert_ne!(base, m.resource_key().unwrap(), "organization_id");

        let mut m = sample();
        m.action = Action::WriteObjects;
        assert_ne!(base, m.resource_key().unwrap(), "action");

        let mut m = sample();
        m.bucket = "other".into();
        assert_ne!(base, m.resource_key().unwrap(), "bucket");

        let mut m = sample();
        m.object = Some("2024/q2.csv".into());
        assert_ne!(base, m.resource_key().unwrap(), "object");

        let mut m = sample();
        m.prefix = Some("2024/".into());
        assert_ne!(base, m.resource_key().unwrap(), "prefix");

        let mut m = sample();
        m.delete_keys = Some(vec!["a".into()]);
        assert_ne!(base, m.resource_key().unwrap(), "delete_keys");

        let mut m = sample();
        m.request.params = Some("list-type=2".into());
        assert_ne!(base, m.resource_key().unwrap(), "request");

        // The regression this defect was filed for: same destination, different source.
        let mut a = sample();
        a.action = Action::WriteObjects;
        a.copy_source = Some(CopySource {
            bucket: "secrets".into(),
            key: "k".into(),
        });
        let mut b = a.clone();
        b.copy_source = Some(CopySource {
            bucket: "public".into(),
            key: "k".into(),
        });
        assert_ne!(
            a.resource_key().unwrap(),
            b.resource_key().unwrap(),
            "two copies to the same destination from different sources must not share a \
             cache entry"
        );

        // And the excluded half really is excluded: the principal is the *other* half
        // of the cache key, so folding it in twice would only cost entropy.
        let mut m = sample();
        m.principal.sub = "bob".into();
        assert_eq!(
            base,
            m.resource_key().unwrap(),
            "principal must be excluded"
        );
        let mut m = sample();
        m.object_tags = Some(BTreeMap::from([("tier".into(), "public".into())]));
        assert_eq!(
            base,
            m.resource_key().unwrap(),
            "object_tags must be excluded (has_on_demand_data bypasses the cache)"
        );
        assert!(m.has_on_demand_data());
    }

    #[test]
    fn opa_input_fields_matches_what_is_actually_serialized() {
        // The list above is a claim about the *wire*; this holds it to serde. Only the
        // always-serialized fields are asserted present — the rest are
        // `skip_serializing_if`, which is why sample-serialization alone cannot derive
        // the field set and the destructuring above has to exist.
        let v = serde_json::to_value(sample()).expect("serialize");
        let obj = v.as_object().expect("an object");
        for key in obj.keys() {
            assert!(
                OPA_INPUT_FIELDS.contains(&key.as_str()),
                "OpaInput serializes {key:?}, which is not in OPA_INPUT_FIELDS"
            );
        }
    }

    #[test]
    fn an_unknown_field_is_a_deserialization_error() {
        // The guard the round-trip gate is built on. Without `deny_unknown_fields` this
        // parses, `op` is dropped on re-serialization, and a policy reading `input.op`
        // looks satisfied by a corpus that never carried it.
        let mut v = serde_json::to_value(sample()).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("op".into(), serde_json::json!("GetObject"));
        let err = serde_json::from_value::<OpaInput>(v).expect_err("unknown field must fail");
        assert!(format!("{err}").contains("op"), "{err}");
    }
}
