//! The audit record — OPA's native decision-log shape. Org attribution rides in a
//! **trusted label** so a downstream extractor can attribute fail-closed. Exactly one
//! record is emitted per S3 request.
//!
//! Three shapes share the type, and exactly one half is present:
//!
//! - a **decision** record (`input`) — the gate admitted the request, a policy question
//!   was formed and answered;
//! - a **gate** record (`gate`) — the request was refused *before* any policy question
//!   existed. There is no `action`, no `bucket` and often no principal at that point,
//!   and inventing them would put claims in a regulated record that was never made;
//! - a **delegated** record (`delegated`) — a control backend answered the request and no
//!   policy question was asked, so there is neither an `input` nor an `action` to claim
//!   (ADR-011, amending ADR-002). A consumer dispatches on `path` first.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::authz::{Decision, OpaInput};

/// The label key carrying org attribution when the operator configures none.
///
/// The key is configurable ([`crate::config::AuditFileConfig`]) because a decision-log
/// consumer dispatches on the key it already uses, and one reading a different key drops
/// every record while still answering `201` — silent loss of a regulated trail. The
/// *value* is never configurable: it is the request's `organization_id`, resolved from
/// the routing table and never from a claim.
pub const DEFAULT_ORG_LABEL_KEY: &str = "s0/organization-id";

pub const DECISION_PATH: &str = "s3/authz/decision";

/// The `path` of a gate record. Deliberately **not** [`DECISION_PATH`]: no policy was
/// evaluated, so claiming the decision entrypoint ran would be false.
pub const GATE_PATH: &str = "s3/authz/gate";

const CONTROL_UNREACHABLE: &str = "control backend unreachable";

const NOT_DELEGATED: &str = "request ended before the control backend was called";

const NO_CONTROL_ANSWER: &str = "request ended before the control backend answered";

/// The `path` of a delegated record. Not [`DECISION_PATH`]: the control backend, not the
/// policy engine, answered.
pub const DELEGATED_PATH: &str = "s3/authz/delegated";

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
    /// Present exactly when the request was delegated to a control backend, in which case
    /// `input` and `gate` are both absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated: Option<DelegationContext>,
    /// The verdict. For a gate record this is the gate's own deny, not a PDP answer. For a
    /// delegated record `allow` is the control backend's authorization answer.
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
    /// The control plane's own name for `input.bucket` (`object_name`), as published by a
    /// bundle that places buckets: an S3 name is unique only per backend, so this is what
    /// the record joins to. Absent below bundle v3 and for a bucket the bundle does not
    /// place — never derived from the S3 name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_name: Option<String>,
    /// The same, for a copy's source bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub copy_source_object_name: Option<String>,
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
    /// unknown: `s3s_aws::Proxy` never assigns `S3Response.status`, so the status the
    /// client sees is the one s3s implies from the output type, not one the backend
    /// reported. Synthesizing `200` here would assert something nobody observed.
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

/// What a delegated request knew: the operation, whom it was for, and what the control
/// backend answered. Everything here was observed, never inferred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationContext {
    /// The s3s operation name.
    pub operation: String,
    /// The bucket named by the request path; empty when the path names none.
    pub bucket: String,
    pub tenant: String,
    /// The caller's subject key (`user:<sub>` or `sa:<client id>`), as sent in
    /// `x-s0-caller-subject`.
    pub subject: String,
    /// The HTTP status the control backend answered; absent when none was received.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_status: Option<u16>,
    /// The error code the control backend answered; absent on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_error: Option<String>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// How records are labelled for the consumer that ingests them: the key org attribution
/// rides under, plus any static labels the deployment's ingest dispatches on.
#[derive(Debug, Clone)]
pub struct LabelPolicy {
    organization_key: String,
    extra: BTreeMap<String, String>,
}

impl LabelPolicy {
    pub fn new(organization_key: impl Into<String>, extra: BTreeMap<String, String>) -> Self {
        LabelPolicy {
            organization_key: organization_key.into(),
            extra,
        }
    }

    fn labels(&self, organization_id: Option<&str>) -> BTreeMap<String, String> {
        let mut labels = self.extra.clone();
        if let Some(org) = organization_id {
            labels.insert(self.organization_key.clone(), org.to_string());
        }
        labels
    }
}

impl Default for LabelPolicy {
    fn default() -> Self {
        LabelPolicy::new(DEFAULT_ORG_LABEL_KEY, BTreeMap::new())
    }
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
        labels: &LabelPolicy,
    ) -> Self {
        let labels = labels.labels(Some(&input.organization_id));
        AuditRecord {
            decision_id,
            path: DECISION_PATH.to_string(),
            requested_by: input.principal.sub.clone(),
            timestamp,
            labels,
            gateway,
            input: Some(input),
            gate: None,
            delegated: None,
            result,
        }
    }

    /// Build a gate record: a denial from before the policy question existed.
    ///
    /// The org-id label is **omitted**, not emptied — every stage this record can
    /// describe is upstream of route resolution, so the org is genuinely unknown and a
    /// `""` would be a claim rather than an absence. A consumer must read a gate record
    /// as an unattributed access attempt against the *gateway*, not against an org.
    pub fn gate_denial(
        decision_id: String,
        timestamp: String,
        gate: GateContext,
        reason: impl Into<String>,
        requested_by: String,
        labels: &LabelPolicy,
    ) -> Self {
        let labels = labels.labels(None);
        AuditRecord {
            decision_id,
            path: GATE_PATH.to_string(),
            input: None,
            gate: Some(gate),
            delegated: None,
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
                object_name: None,
                copy_source_object_name: None,
            },
        }
    }

    /// Build the record of a request delegated to a control backend, in the state of one
    /// that ended before the control backend was called: `allow` is `false` because no
    /// answer was observed. [`Self::settle_delegated`] says what happened once a call was
    /// made.
    /// The organization label comes from the route, like every other shape.
    #[allow(clippy::too_many_arguments)]
    pub fn delegated(
        decision_id: String,
        timestamp: String,
        delegated: DelegationContext,
        requested_by: String,
        organization_id: &str,
        backend_id: String,
        backend_kind: String,
        object_name: Option<String>,
        labels: &LabelPolicy,
    ) -> Self {
        AuditRecord {
            decision_id,
            path: DELEGATED_PATH.to_string(),
            input: None,
            gate: None,
            delegated: Some(delegated),
            result: Decision::deny(NOT_DELEGATED),
            requested_by,
            timestamp,
            labels: labels.labels(Some(organization_id)),
            gateway: GatewayMeta {
                backend_id,
                backend_kind,
                outcome: Outcome::Error,
                denied_keys: vec![],
                backend: BackendOutcome::NotAttempted,
                backend_status: None,
                object_name,
                copy_source_object_name: None,
            },
        }
    }

    /// The control backend call is about to start. A record still unsettled when the
    /// request ends from here on says the call's answer was never observed, not that the
    /// call was never made. `allow` stays `false` and `control_status` absent.
    pub fn mark_delegation_dispatched(&mut self) {
        if self.delegated.is_some() {
            self.result = Decision::deny(NO_CONTROL_ANSWER);
        }
    }

    /// Record what the control backend answered. Called once, when the request finishes,
    /// by [`crate::audit::PendingAudit`]. `gateway.backend` stays `not_attempted`: the
    /// storage backend was never contacted.
    ///
    /// `allow` is the control backend's authorization answer, not an s0 verdict: `false`
    /// only for `403 AccessDenied`. Any other answered status leaves it `true` and names
    /// the control backend and its error code in the reason.
    pub fn settle_delegated(&mut self, status: Option<u16>, error_code: Option<String>) {
        let Some(delegated) = self.delegated.as_mut() else {
            return;
        };
        delegated.control_status = status;
        delegated.control_error = error_code.clone();
        let (outcome, result) = match (status, error_code.as_deref()) {
            (None, _) => (Outcome::Error, Decision::allow(CONTROL_UNREACHABLE)),
            (Some(s), Some(code)) if (200..300).contains(&s) => (
                Outcome::Error,
                Decision::allow(format!(
                    "control backend answered {s}, then the answer failed: {code}"
                )),
            ),
            (Some(s), None) if (200..300).contains(&s) => (
                Outcome::Allowed,
                Decision::allow("delegated to the control backend"),
            ),
            (Some(403), Some("AccessDenied")) => (
                Outcome::Denied,
                Decision::deny("control backend denied the request: AccessDenied"),
            ),
            (Some(_), code) => (
                Outcome::Error,
                Decision::allow(format!(
                    "control backend answered {}",
                    code.unwrap_or("an error")
                )),
            ),
        };
        self.gateway.outcome = outcome;
        self.result = result;
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
            object_name: None,
            copy_source_object_name: None,
        }
    }

    fn labels() -> LabelPolicy {
        LabelPolicy::new(
            DEFAULT_ORG_LABEL_KEY,
            BTreeMap::from([("example/log-type".to_string(), "s3-gateway".to_string())]),
        )
    }

    #[test]
    fn record_carries_trusted_org_label_and_principal() {
        let rec = AuditRecord::new(
            "dec-1".into(),
            "2026-07-15T00:00:00Z".into(),
            sample_input(),
            Decision::allow("grant matched"),
            meta(Outcome::Allowed, vec![]),
            &labels(),
        );
        assert_eq!(rec.requested_by, "alice");
        assert_eq!(rec.path, DECISION_PATH);
        assert_eq!(
            rec.labels.get(DEFAULT_ORG_LABEL_KEY).map(String::as_str),
            Some("org-acme")
        );
        // Configured static labels ride on every record.
        assert_eq!(
            rec.labels.get("example/log-type").map(String::as_str),
            Some("s3-gateway")
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
            &labels(),
        );
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["gateway"]["denied_keys"][0], "secret/x");
    }

    #[test]
    fn object_names_are_recorded_when_published_and_absent_otherwise() {
        let mut named = meta(Outcome::Allowed, vec![]);
        named.object_name = Some("reports.archive".into());
        named.copy_source_object_name = Some("raw.archive".into());
        let rec = AuditRecord::new(
            "dec-6".into(),
            "2026-07-15T00:00:00Z".into(),
            sample_input(),
            Decision::allow("grant matched"),
            named,
            &labels(),
        );
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["gateway"]["object_name"], "reports.archive");
        assert_eq!(json["gateway"]["copy_source_object_name"], "raw.archive");
        let back: AuditRecord = serde_json::from_value(json).unwrap();
        assert_eq!(back.gateway.object_name.as_deref(), Some("reports.archive"));

        // Unpublished: omitted, so a record from a bundle that places nothing is the
        // record it always was.
        let rec = AuditRecord::new(
            "dec-7".into(),
            "2026-07-15T00:00:00Z".into(),
            sample_input(),
            Decision::allow("grant matched"),
            meta(Outcome::Allowed, vec![]),
            &labels(),
        );
        let json = serde_json::to_value(&rec).unwrap();
        assert!(json["gateway"].get("object_name").is_none(), "{json}");
        assert!(
            json["gateway"].get("copy_source_object_name").is_none(),
            "{json}"
        );
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
            &labels(),
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
            json["labels"].get(DEFAULT_ORG_LABEL_KEY).is_none(),
            "an unattributable request must not claim an organization: {json}"
        );
        // …but the routing labels are still there, so the record reaches its consumer.
        assert_eq!(json["labels"]["example/log-type"], "s3-gateway");
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
            &labels(),
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
            &labels(),
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

    fn delegated_record() -> AuditRecord {
        AuditRecord::delegated(
            "dec-7".into(),
            "2026-11-02T00:00:00Z".into(),
            DelegationContext {
                operation: "PutBucketCors".into(),
                bucket: "reports".into(),
                tenant: "acme".into(),
                subject: "user:alice".into(),
                control_status: None,
                control_error: None,
            },
            "alice".into(),
            "org-acme",
            "backend-1".into(),
            "ceph".into(),
            None,
            &labels(),
        )
    }

    #[test]
    fn a_delegated_record_asks_no_policy_question() {
        let rec = delegated_record();
        assert_eq!(rec.path, DELEGATED_PATH);
        assert_ne!(rec.path, DECISION_PATH);
        assert!(rec.input.is_none() && rec.gate.is_none());
        let json = serde_json::to_value(&rec).unwrap();
        assert!(json.get("input").is_none() && json.get("gate").is_none());
        assert_eq!(json["delegated"]["operation"], "PutBucketCors");
        assert_eq!(json["labels"][DEFAULT_ORG_LABEL_KEY], "org-acme");
        assert_eq!(rec.gateway.backend, BackendOutcome::NotAttempted);
    }

    #[test]
    fn an_unsettled_delegated_record_says_the_control_backend_was_not_called() {
        let rec = delegated_record();
        assert_eq!(rec.gateway.outcome, Outcome::Error);
        assert!(!rec.result.allow);
        assert_eq!(
            rec.result.reason,
            "request ended before the control backend was called"
        );
    }

    #[test]
    fn settling_a_delegated_record_maps_the_control_answer_to_the_outcome() {
        let settle = |status: Option<u16>, code: Option<&str>| {
            let mut rec = delegated_record();
            rec.settle_delegated(status, code.map(str::to_string));
            rec
        };
        let ok = settle(Some(200), None);
        assert_eq!(ok.gateway.outcome, Outcome::Allowed);
        assert!(ok.result.allow);
        assert_eq!(ok.delegated.as_ref().unwrap().control_status, Some(200));

        let denied = settle(Some(403), Some("AccessDenied"));
        assert_eq!(denied.gateway.outcome, Outcome::Denied);
        assert!(!denied.result.allow);

        let other_403 = settle(Some(403), Some("SignatureDoesNotMatch"));
        assert_eq!(other_403.gateway.outcome, Outcome::Error);
        assert!(other_403.result.allow);

        let conflict = settle(Some(409), Some("OperationAborted"));
        assert_eq!(conflict.gateway.outcome, Outcome::Error);
        assert!(conflict.result.allow);
        assert!(conflict.result.reason.contains("OperationAborted"));
        let d = conflict.delegated.as_ref().unwrap();
        assert_eq!(
            (d.control_status, d.control_error.as_deref()),
            (Some(409), Some("OperationAborted"))
        );

        let broken_body = settle(Some(200), Some("InternalError"));
        assert_eq!(broken_body.gateway.outcome, Outcome::Error);
        assert!(broken_body.result.reason.contains("InternalError"));

        let down = settle(None, None);
        assert_eq!(down.gateway.outcome, Outcome::Error);
        assert_eq!(down.result.reason, "control backend unreachable");
        assert!(down.delegated.as_ref().unwrap().control_status.is_none());
        assert_eq!(down.gateway.backend, BackendOutcome::NotAttempted);
    }
}
