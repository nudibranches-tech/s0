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
/// Kept in step with the struct by `opa_input_fields_is_exhaustive`, which destructures
/// an `OpaInput` **without** `..` — so adding a field is a *compile* error until this
/// list is updated. `tests/fixture_drift.rs` checks the rego's own `input.<field>`
/// references against it: a policy reading a field no producer emits is a silent
/// deny-all that every other test passes over.
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
    "requested_tags",
    "acl_grants",
    "bypass_governance",
    "request",
];

/// One authorization question posed to the PDP for one parsed request (or, for
/// blind-spot ops, one sub-decision — e.g. one key of a multi-delete, or the
/// source-read half of a copy).
///
/// `deny_unknown_fields` is load-bearing: it is what lets
/// [`crate::authz::capture::round_trip`] detect a renamed or dropped field. Without it a
/// captured document carrying a stale field deserializes happily, loses it on
/// re-serialization, and the drift gate is blind. Not applied to
/// [`PrincipalAttributes`]: `#[serde(flatten)]` is incompatible with it.
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
    /// The tag set a `write_object_tags` request is asking to **install** — the parsed
    /// body, not the object's current tags (that is `object_tags`).
    ///
    /// Emitted so a pushed policy can refuse a tag write that would set a key its own
    /// ABAC conditions read (self-elevation). Neither policy module reads it: the
    /// reserved-key screen is PEP-side in [`crate::access::tagging`] so a pushed policy
    /// cannot forget it, and it denies unless the bundle carries
    /// `org_settings.reserved_tag_keys`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_tags: Option<BTreeMap<String, String>>,
    /// The access-control grants this request asks the backend to install: the canned
    /// `x-amz-acl` and the five `x-amz-grant-*` headers, normalized (see
    /// [`crate::access::headers`]).
    ///
    /// **Always serialized, and `[]` is a real assertion**, not an absence: a policy says
    /// "this write may carry no ACL" as `count(input.acl_grants) == 0`, and a rego
    /// reference to an *undefined* field is a silent deny-all.
    #[serde(default)]
    pub acl_grants: Vec<AclGrant>,
    /// `x-amz-bypass-governance-retention` — the WORM defeat.
    ///
    /// Always serialized, for the same reason as [`Self::acl_grants`]. No verb expresses
    /// "may override object-lock retention", so the gateway refuses a request carrying
    /// this outright; it is on the wire so the *attempt* is on the record.
    #[serde(default)]
    pub bypass_governance: bool,
    #[serde(default)]
    pub request: RequestMeta,
}

/// One access-control grant a request asks the backend to install, normalized out of
/// the canned ACL field and the `x-amz-grant-*` headers.
///
/// Two strings rather than a parsed grantee: the expression is backend-defined (`id=`,
/// `uri=`, `emailAddress=`, comma-separated lists), and a partial parse the gateway and
/// the backend disagree about is worse than none. The classification that matters — does
/// this reach a *public* grantee? — is made in [`crate::access::headers`] on the raw
/// text, over-matching rather than under.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AclGrant {
    /// Where it came from: `"acl"` for the canned ACL, or the header name with the
    /// `x-amz-` stripped — `"grant-read"`, `"grant-write"`, `"grant-read-acp"`,
    /// `"grant-write-acp"`, `"grant-full-control"`.
    pub source: String,
    /// The canned ACL name (`"public-read"`), or the grantee expression verbatim.
    pub value: String,
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
/// Pinned by `opa_input_fields_is_exhaustive` (the list is asserted verbatim) so a
/// future field cannot join it by accident, and exercised field-by-field by
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
    /// **Derived, not enumerated.** A hand-listed field set develops holes: omit
    /// `copy_source` and two `CopyObject`s to the same destination from *different*
    /// sources collide on one entry, silently. A digest cannot — a new field is in the
    /// key the moment it is on the wire.
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
            requested_tags: None,
            acl_grants: vec![],
            bypass_governance: false,
            request: RequestMeta::default(),
        }
    }

    #[test]
    fn opa_input_fields_is_exhaustive() {
        // Written WITHOUT `..` on purpose: serde has no reflection, so this
        // destructuring is the only thing that can tell `OPA_INPUT_FIELDS` at compile
        // time that a field was added. If the compiler sent you here, add the field to
        // `OPA_INPUT_FIELDS` and to `names`, then decide whether it belongs in
        // `resource_key` and `has_on_demand_data` — a field that is in neither is
        // silently outside the decision-cache key.
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
            requested_tags,
            acl_grants,
            bypass_governance,
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
            stringify!(requested_tags),
            stringify!(acl_grants),
            stringify!(bypass_governance),
            stringify!(request),
        ];
        // Bind every destructured value so an unused-variable warning cannot be the
        // reason someone reaches for `..`.
        let _ = (principal, backend, tenant, organization_id, action, bucket);
        let _ = (object, prefix, copy_source, delete_keys, object_tags);
        let _ = (requested_tags, request);
        let _ = (acl_grants, bypass_governance);
        assert_eq!(names.as_slice(), OPA_INPUT_FIELDS);

        // `resource_key` is a digest over the serialized input minus
        // `RESOURCE_KEY_EXCLUDED`, so "is this field in the decision-cache key?" reduces
        // to "is it off that list?" — checkable here, statically, for every field.
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
        // must move.
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

        // The two shapes of the ONE existence verb. `HeadBucket` names a bucket and
        // `ListBuckets` does not, and they are the same `Action`, so the bucket field is
        // the only thing keeping one cached verdict from serving both — which would let
        // an account-scope allow answer a per-bucket question.
        let mut head = sample();
        head.action = Action::Read;
        head.object = None;
        let mut list = head.clone();
        list.bucket = String::new();
        assert_ne!(
            head.resource_key().unwrap(),
            list.resource_key().unwrap(),
            "a HeadBucket and a ListBuckets must not share a decision-cache entry"
        );

        let mut m = sample();
        m.requested_tags = Some(BTreeMap::from([("tier".into(), "public".into())]));
        assert_ne!(base, m.resource_key().unwrap(), "requested_tags");

        let mut m = sample();
        m.acl_grants = vec![AclGrant {
            source: "acl".into(),
            value: "public-read".into(),
        }];
        assert_ne!(base, m.resource_key().unwrap(), "acl_grants");

        let mut m = sample();
        m.bypass_governance = true;
        assert_ne!(base, m.resource_key().unwrap(), "bypass_governance");

        // Same destination, different source.
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
    fn the_acl_retrofit_fields_enter_the_decision_cache_key_by_construction() {
        // If `acl_grants` were outside the key, a `PutObject` with
        // `x-amz-acl: public-read` and a plain `PutObject` to the same bucket+key would
        // share one decision-cache entry: the plain write caches an allow and the
        // ACL-bearing write is served it without the PDP ever seeing the header.
        // Asserted against the derivation (is the field excluded?) and empirically,
        // because a future field is only safe if both stay true.
        for field in ["acl_grants", "bypass_governance", "requested_tags"] {
            assert!(
                !RESOURCE_KEY_EXCLUDED.contains(&field),
                "{field} must not be excluded from the decision-cache key"
            );
            assert!(OPA_INPUT_FIELDS.contains(&field));
        }

        let plain = {
            let mut m = sample();
            m.action = Action::WriteObjects;
            m
        };
        let with_acl = {
            let mut m = plain.clone();
            m.acl_grants = vec![AclGrant {
                source: "acl".into(),
                value: "public-read".into(),
            }];
            m
        };
        assert_ne!(
            plain.resource_key().unwrap(),
            with_acl.resource_key().unwrap(),
            "a write carrying an ACL must not share a decision-cache entry with the same \
             write carrying none"
        );

        // And two *different* ACLs are two different questions.
        let other_acl = {
            let mut m = with_acl.clone();
            m.acl_grants = vec![AclGrant {
                source: "grant-read".into(),
                value: "uri=\"http://acs.amazonaws.com/groups/global/AllUsers\"".into(),
            }];
            m
        };
        assert_ne!(
            with_acl.resource_key().unwrap(),
            other_acl.resource_key().unwrap()
        );

        let bypass = {
            let mut m = plain.clone();
            m.action = Action::DeleteObjects;
            m
        };
        let mut bypass_on = bypass.clone();
        bypass_on.bypass_governance = true;
        assert_ne!(
            bypass.resource_key().unwrap(),
            bypass_on.resource_key().unwrap(),
            "a governance-bypassing delete must not share a decision-cache entry with an \
             ordinary delete of the same key"
        );
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
