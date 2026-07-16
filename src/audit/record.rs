//! The audit record — OPA's native decision-log shape (§3.6), the format the
//! console sink already ingests. Org attribution rides in a **trusted label**
//! (mirroring the Trino extractor) so the companion Ceph/S3 extractor can attribute
//! fail-closed (§4.5). Exactly one record is emitted per S3 request (§6.6): for
//! blind-spot ops the request-level `input` carries the full detail (delete_keys,
//! copy_source) and `result` is the aggregate verdict.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::authz::{Decision, OpaInput};

/// Label keys. `data-dock-type` mirrors the Trino record's discriminator so the
/// console can route gateway records to the (companion) Ceph/S3 extractor; the
/// org-id label is the trusted, fail-closed org attribution.
pub const LABEL_DOCK_TYPE: &str = "s0.dev/data-dock-type";
pub const LABEL_ORG_ID: &str = "s0.dev/organization-id";
pub const DOCK_TYPE_VALUE: &str = "s3-gateway";

pub const DECISION_PATH: &str = "s0/gateway/decision";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub decision_id: String,
    /// The policy path evaluated — OPA decision-log convention.
    pub path: String,
    /// The full parsed request that was authorized (the §5 superset).
    pub input: OpaInput,
    /// The PDP verdict.
    pub result: Decision,
    /// Principal subject — the end-user identity (§6.6), never a service identity.
    pub requested_by: String,
    /// RFC3339 UTC.
    pub timestamp: String,
    /// Trusted attribution + routing labels.
    pub labels: BTreeMap<String, String>,
    /// S3-specific fields the Ceph/S3 extractor consumes beyond the OPA envelope.
    pub gateway: GatewayMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayMeta {
    pub backend_id: String,
    pub backend_kind: String,
    /// The POLICY disposition (`allowed`/`denied`), emitted at decision time — this is
    /// a decision log, so it records the authorization outcome, not whether the backend
    /// forward later succeeded.
    pub outcome: Outcome,
    /// Keys the PEP stripped from a multi-delete because they were unauthorized
    /// (§5, per-key filtering). Empty for non-multi-delete ops.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_keys: Vec<String>,
    /// Backend HTTP status. Populated only once post-forward audit enrichment is wired
    /// (emit the record from the dispatcher after the backend responds); absent today.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_status: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Denied,
    Error,
}

impl AuditRecord {
    /// Build a request-level record. `decision_id`/`timestamp` are injected by the
    /// caller so this stays pure and unit-testable.
    pub fn new(
        decision_id: String,
        timestamp: String,
        input: OpaInput,
        result: Decision,
        gateway: GatewayMeta,
    ) -> Self {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_DOCK_TYPE.to_string(), DOCK_TYPE_VALUE.to_string());
        labels.insert(LABEL_ORG_ID.to_string(), input.organization_id.clone());
        AuditRecord {
            decision_id,
            path: DECISION_PATH.to_string(),
            requested_by: input.principal.sub.clone(),
            timestamp,
            labels,
            gateway,
            input,
            result,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Backend, OpaInput, Principal, PrincipalAttributes, RequestMeta};
    use crate::model::{Action, BackendKind, PrincipalType};

    fn sample_input() -> OpaInput {
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
    fn record_carries_trusted_org_label_and_principal() {
        let meta = GatewayMeta {
            backend_id: "bay-1".into(),
            backend_kind: "ceph".into(),
            outcome: Outcome::Allowed,
            denied_keys: vec![],
            backend_status: None,
        };
        let rec = AuditRecord::new(
            "dec-1".into(),
            "2026-07-15T00:00:00Z".into(),
            sample_input(),
            Decision::allow("grant matched"),
            meta,
        );
        assert_eq!(rec.requested_by, "alice");
        assert_eq!(rec.path, DECISION_PATH);
        assert_eq!(
            rec.labels.get(LABEL_ORG_ID).map(String::as_str),
            Some("org-acme")
        );
        assert_eq!(
            rec.labels.get(super::LABEL_DOCK_TYPE).map(String::as_str),
            Some(DOCK_TYPE_VALUE)
        );
        // Round-trips through the spill format.
        let json = serde_json::to_string(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.requested_by, "alice");
    }

    #[test]
    fn multi_delete_denied_keys_serialize() {
        let meta = GatewayMeta {
            backend_id: "bay-1".into(),
            backend_kind: "ceph".into(),
            outcome: Outcome::Allowed,
            denied_keys: vec!["secret/x".into()],
            backend_status: None,
        };
        let rec = AuditRecord::new(
            "dec-2".into(),
            "2026-07-15T00:00:00Z".into(),
            sample_input(),
            Decision::allow("2 allowed, 1 denied"),
            meta,
        );
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["gateway"]["denied_keys"][0], "secret/x");
    }
}
