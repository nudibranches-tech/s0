//! The audit record — OPA's native decision-log shape, the format the control-plane
//! sink ingests. Org attribution rides in a **trusted label** so the downstream
//! extractor can attribute fail-closed. Exactly one record is emitted per S3 request:
//! for blind-spot ops the request-level `input` carries the full detail (delete_keys,
//! copy_source) and `result` is the aggregate verdict.
//!
//! Two shapes share the type, because two genuinely different things happen:
//!
//! - a **decision** record (`input` present) — the gate admitted the request, a policy
//!   question was formed and answered;
//! - a **gate** record (`gate` present) — the request was refused *before* any policy
//!   question existed: unsigned, an operation this build does not enforce, a credential
//!   that resolves to nothing, a tenant with no route. There is no `action`, no
//!   `bucket` and often no principal at that point, and inventing them would put claims
//!   in a regulated record that the gateway never made. So the halves are optional and
//!   exactly one of them is present.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::authz::{Decision, OpaInput};

/// Label keys. The record-type label lets the control plane route gateway records to
/// the right decision-log extractor; the org-id label is the trusted, fail-closed org
/// attribution.
pub const LABEL_RECORD_TYPE: &str = "s0.dev/record-type";
pub const LABEL_ORG_ID: &str = "s0.dev/organization-id";
pub const RECORD_TYPE_VALUE: &str = "s3-gateway";

pub const DECISION_PATH: &str = "s0/gateway/decision";

/// The `path` of a gate record. Deliberately **not** [`DECISION_PATH`]: no policy was
/// evaluated, so claiming the decision entrypoint ran would be false.
pub const GATE_PATH: &str = "s0/gateway/gate";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub decision_id: String,
    /// The policy path evaluated — OPA decision-log convention. [`GATE_PATH`] when no
    /// policy ran.
    pub path: String,
    /// The full parsed request that was authorized (the input superset). Absent on a
    /// gate record — see the module doc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<OpaInput>,
    /// Present exactly when `input` is absent: what the pre-policy gate refused, and
    /// the little it knew when it did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gate: Option<GateContext>,
    /// The verdict. For a gate record this is the gate's own deny, not a PDP answer.
    pub result: Decision,
    /// Principal subject — the end-user identity, never a service identity. Empty on a
    /// gate record that was refused before the identity was resolved.
    pub requested_by: String,
    /// RFC3339 UTC.
    pub timestamp: String,
    /// Trusted attribution + routing labels.
    pub labels: BTreeMap<String, String>,
    /// S3-specific fields the decision-log extractor consumes beyond the OPA envelope.
    pub gateway: GatewayMeta,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayMeta {
    pub backend_id: String,
    pub backend_kind: String,
    /// The disposition of the request as a whole: `denied` when the gate or the policy
    /// refused it, `error` when it was allowed and the forward then failed, `allowed`
    /// otherwise. The *policy* verdict is always independently readable from
    /// `result.allow`, so folding the forward failure in here loses nothing.
    pub outcome: Outcome,
    /// Keys the PEP stripped from a multi-delete because they were unauthorized
    /// (per-key filtering). Empty for non-multi-delete ops.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub denied_keys: Vec<String>,
    /// What the gateway knows about the backend leg. Filled in post-forward
    /// ([`crate::audit::PendingAudit`]), which is why the record is emitted when the
    /// request finishes rather than when the decision is made.
    #[serde(default)]
    pub backend: BackendOutcome,
    /// Backend HTTP status. Populated **only** when the backend itself named the
    /// status; never synthesized. See [`BackendOutcome::SucceededStatusUnknown`] for
    /// why the success path cannot fill this in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_status: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Allowed,
    Denied,
    Error,
}

/// What the gateway observed on the backend leg of the request.
///
/// This exists because "we forwarded it and it worked" and "we forwarded it and got a
/// 200" are different facts, and only the first one is available. Collapsing them would
/// put a status code nobody observed into a regulated record.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendOutcome {
    /// No backend leg was attempted: the request was refused (by the gate or by
    /// policy), or it failed inside the gateway before the forward path.
    #[default]
    NotAttempted,
    /// The forward was attempted and returned success. **Which** 2xx is genuinely
    /// unknown: `s3s_aws::Proxy` builds every success response with
    /// `S3Response::with_headers` and never assigns `S3Response.status` (98 call sites,
    /// zero assignments — plan defect E-1), so the status the client eventually sees is
    /// the one s3s implies from the output type, not one the backend reported.
    /// Synthesizing `200` here would be asserting something nobody observed.
    SucceededStatusUnknown,
    /// The forward was attempted and failed. `backend_status` carries the status if,
    /// and only if, the backend itself named it.
    Failed,
}

/// Which pre-policy check refused the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateStage {
    /// No credential at all — an unsigned request.
    Anonymous,
    /// The operation is not marked `Enforced` in `OP_TABLE`, or is structurally
    /// unauthorizable. This is the entire deny-by-default surface.
    OperationNotEnforced,
    /// A credential was presented and resolved to no principal — an expired or forged
    /// session token, an unknown access key. The credential-forgery signal.
    IdentityRejected,
    /// The principal's tenant has no route in this gateway's registry.
    TenantNotRoutable,
}

/// The half of an audit record that exists when the request never became a policy
/// question. Everything here is what the gate actually knew at the moment it refused.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateContext {
    /// The s3s operation name the request resolved to.
    pub operation: String,
    pub stage: GateStage,
    /// The access-key id presented. A semi-public identifier — never the secret.
    /// Absent for [`GateStage::Anonymous`]: there was no credential to name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_key_id: Option<String>,
    /// The tenant the principal claimed, when identity resolution got that far.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant: Option<String>,
    /// Gate denials this replica deliberately did **not** record since the last one it
    /// did. An unauthenticated caller can produce gate denials without limit, so they
    /// are rate-limited; non-zero here means the gate stream is being sampled, and the
    /// running total is exported as `s0_audit_gate_suppressed_total`. The per-request
    /// detail is gone; the fact and the count are not.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub suppressed_since_last: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

impl AuditRecord {
    /// Build a request-level decision record. `decision_id`/`timestamp` are injected by
    /// the caller so this stays pure and unit-testable.
    pub fn new(
        decision_id: String,
        timestamp: String,
        input: OpaInput,
        result: Decision,
        gateway: GatewayMeta,
    ) -> Self {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_RECORD_TYPE.to_string(), RECORD_TYPE_VALUE.to_string());
        labels.insert(LABEL_ORG_ID.to_string(), input.organization_id.clone());
        AuditRecord {
            decision_id,
            path: DECISION_PATH.to_string(),
            requested_by: input.principal.sub.clone(),
            timestamp,
            labels,
            gateway,
            input: Some(input),
            gate: None,
            result,
        }
    }

    /// Build a gate record: a denial from before the policy question existed.
    ///
    /// The org-id label is **omitted**, not emptied. The organization is resolved from
    /// the routing registry, and every stage this record can describe is upstream of
    /// that resolution — so the org is genuinely unknown, and a `""` org would be a
    /// claim rather than an absence. A consumer must treat a gate record as an
    /// unattributed access attempt against the *gateway*, not against an org.
    pub fn gate_denial(
        decision_id: String,
        timestamp: String,
        gate: GateContext,
        reason: impl Into<String>,
        requested_by: String,
    ) -> Self {
        let mut labels = BTreeMap::new();
        labels.insert(LABEL_RECORD_TYPE.to_string(), RECORD_TYPE_VALUE.to_string());
        AuditRecord {
            decision_id,
            path: GATE_PATH.to_string(),
            input: None,
            gate: Some(gate),
            result: Decision::deny(reason),
            requested_by,
            timestamp,
            labels,
            gateway: GatewayMeta {
                // The gate refuses upstream of route resolution, so there is no backend
                // to name. Empty means "no backend was selected", which is the truth.
                backend_id: String::new(),
                backend_kind: String::new(),
                outcome: Outcome::Denied,
                denied_keys: vec![],
                backend: BackendOutcome::NotAttempted,
                backend_status: None,
            },
        }
    }

    /// Record what the forward leg did. Called once, post-forward, by
    /// [`crate::audit::PendingAudit`].
    pub fn settle(&mut self, backend: BackendOutcome, backend_status: Option<u16>) {
        self.gateway.backend = backend;
        self.gateway.backend_status = backend_status;
        if backend == BackendOutcome::Failed {
            // The policy verdict stays readable in `result.allow`; `outcome` is the
            // disposition of the request, and a request that errored was not "allowed"
            // in any sense a reader of the audit trail cares about.
            self.gateway.outcome = Outcome::Error;
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
                id: "backend-1".into(),
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
            config_kind: None,
            requested_tags: None,
            acl_grants: vec![],
            bypass_governance: false,
            request: RequestMeta::default(),
        }
    }

    fn meta(outcome: Outcome, denied_keys: Vec<String>) -> GatewayMeta {
        GatewayMeta {
            backend_id: "backend-1".into(),
            backend_kind: "ceph".into(),
            outcome,
            denied_keys,
            backend: BackendOutcome::NotAttempted,
            backend_status: None,
        }
    }

    #[test]
    fn record_carries_trusted_org_label_and_principal() {
        let rec = AuditRecord::new(
            "dec-1".into(),
            "2026-07-15T00:00:00Z".into(),
            sample_input(),
            Decision::allow("grant matched"),
            meta(Outcome::Allowed, vec![]),
        );
        assert_eq!(rec.requested_by, "alice");
        assert_eq!(rec.path, DECISION_PATH);
        assert_eq!(
            rec.labels.get(LABEL_ORG_ID).map(String::as_str),
            Some("org-acme")
        );
        assert_eq!(
            rec.labels.get(super::LABEL_RECORD_TYPE).map(String::as_str),
            Some(RECORD_TYPE_VALUE)
        );
        // Round-trips through the spill format.
        let json = serde_json::to_string(&rec).unwrap();
        let back: AuditRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.requested_by, "alice");
        assert!(back.input.is_some() && back.gate.is_none());
    }

    #[test]
    fn multi_delete_denied_keys_serialize() {
        let rec = AuditRecord::new(
            "dec-2".into(),
            "2026-07-15T00:00:00Z".into(),
            sample_input(),
            Decision::allow("2 allowed, 1 denied"),
            meta(Outcome::Allowed, vec!["secret/x".into()]),
        );
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["gateway"]["denied_keys"][0], "secret/x");
    }

    #[test]
    fn a_gate_record_invents_no_policy_question() {
        // The whole point of the second shape: a request refused before the gate could
        // form a question has no action, no bucket and no org. A record that filled
        // those in with defaults would read as "alice read reports" for a request that
        // was an unsigned DeleteBucket.
        let rec = AuditRecord::gate_denial(
            "dec-3".into(),
            "2026-07-15T00:00:00Z".into(),
            GateContext {
                operation: "DeleteBucket".into(),
                stage: GateStage::OperationNotEnforced,
                access_key_id: Some("AKIAEXAMPLE".into()),
                tenant: None,
                suppressed_since_last: 0,
            },
            "operation is not enforced by this gateway: DeleteBucket",
            String::new(),
        );
        let json = serde_json::to_value(&rec).unwrap();
        assert!(
            json.get("input").is_none(),
            "a gate record must carry no OpaInput at all: {json}"
        );
        assert_eq!(json["path"], GATE_PATH);
        assert_eq!(json["gate"]["stage"], "operation_not_enforced");
        assert_eq!(json["gate"]["access_key_id"], "AKIAEXAMPLE");
        assert_eq!(json["gateway"]["outcome"], "denied");
        assert_eq!(json["result"]["allow"], false);
        // Unknown org: the label is absent, never an empty string that reads as a real
        // organization whose id happens to be "".
        assert!(
            json["labels"].get(LABEL_ORG_ID).is_none(),
            "an unattributable request must not claim an organization: {json}"
        );
        assert_eq!(json["labels"][LABEL_RECORD_TYPE], RECORD_TYPE_VALUE);
        // Rate-limit bookkeeping is omitted when nothing was suppressed.
        assert!(json["gate"].get("suppressed_since_last").is_none());

        let back: AuditRecord = serde_json::from_str(&json.to_string()).unwrap();
        assert!(back.input.is_none() && back.gate.is_some());
    }

    #[test]
    fn settling_a_failed_forward_turns_the_outcome_into_an_error() {
        let mut rec = AuditRecord::new(
            "dec-4".into(),
            "2026-07-15T00:00:00Z".into(),
            sample_input(),
            Decision::allow("grant matched"),
            meta(Outcome::Allowed, vec![]),
        );
        rec.settle(BackendOutcome::Failed, Some(503));
        assert!(matches!(rec.gateway.outcome, Outcome::Error));
        assert_eq!(rec.gateway.backend_status, Some(503));
        // The policy verdict is not overwritten — it is still readable.
        assert!(rec.result.allow);

        // A success carries no status, and must not acquire one.
        let mut rec = AuditRecord::new(
            "dec-5".into(),
            "2026-07-15T00:00:00Z".into(),
            sample_input(),
            Decision::allow("grant matched"),
            meta(Outcome::Allowed, vec![]),
        );
        rec.settle(BackendOutcome::SucceededStatusUnknown, None);
        assert!(matches!(rec.gateway.outcome, Outcome::Allowed));
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["gateway"]["backend"], "succeeded_status_unknown");
        assert!(
            json["gateway"].get("backend_status").is_none(),
            "a 200 nobody observed must not be synthesized: {json}"
        );
    }
}
