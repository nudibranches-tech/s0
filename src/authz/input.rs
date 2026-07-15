//! The OPA input contract (PROMPT §5) — the core interface of the gateway.
//!
//! This is a *superset* of today's `ceph.authz` input: the gateway sees the full
//! parsed request (multi-delete keys, copy source, list prefix, object tags) that
//! the in-RGW hook cannot. The field names here are load-bearing — the rego reads
//! them by name — so treat this struct as a stable wire schema, not an internal type.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::model::{Action, BackendKind, PrincipalType};

/// One authorization question posed to the PDP for one parsed request (or, for
/// blind-spot ops, one sub-decision — e.g. one key of a multi-delete, or the
/// source-read half of a copy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpaInput {
    pub principal: Principal,
    pub backend: Backend,
    /// Harbor slug == Ceph tenant.
    pub tenant: String,
    /// Organization owning the tenant. Trusted org attribution for org-global
    /// deny rules and for fail-closed audit (§3.6, §4.5).
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
    /// Object tags fetched on demand for ABAC (§5.2). Gated behind §7.1 — never
    /// populated until the direct-path question resolves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_tags: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub request: RequestMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
pub struct Backend {
    pub id: String,
    pub kind: BackendKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CopySource {
    pub bucket: String,
    pub key: String,
}

/// Non-authoritative request context surfaced to policy for ABAC / logging.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RequestMeta {
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers_subset: BTreeMap<String, String>,
}

impl OpaInput {
    /// Stable cache identity for the resource half of the §4.3.2 key. Excludes
    /// on-demand data (`object_tags`): the cache layer refuses to cache tag-bearing
    /// decisions unless a tag version is folded in.
    pub fn resource_key(&self) -> String {
        let obj = self.object.as_deref().unwrap_or("");
        let pfx = self.prefix.as_deref().unwrap_or("");
        format!(
            "{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}\u{1f}{}",
            self.backend.id,
            self.tenant,
            self.bucket,
            self.action.as_str(),
            obj,
            pfx
        )
    }

    /// True when the input carries on-demand data whose freshness the
    /// revision-keyed cache cannot guarantee (§4.3.2, §5.2).
    pub fn has_on_demand_data(&self) -> bool {
        self.object_tags.is_some()
    }
}
