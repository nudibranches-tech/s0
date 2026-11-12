//! The protocol-neutral half of the enforce path (ADR-012 D2).
//!
//! Everything here is independent of how a request arrived: the single PDP call site with
//! its golden-capture tap, the `must_understand` check, audit-record assembly, the
//! [`PendingAudit`] hand-off, and minting the proofs the forward paths require. The S3
//! front ([`super::GatewayAccess`]) and the SFTP front ([`crate::sftp`]) are its two
//! callers. Neither may reach the PDP, the audit sink or a proof constructor any other
//! way, which is what keeps "every question is captured, every decision is audited, every
//! forward is proven" a property of one file.

use std::sync::Arc;

use crate::audit::{
    AuditRecord, BackendOutcome, GateContext, GateStage, GatewayMeta, Outcome, PendingAudit,
};
use crate::authz::{Decision, OpaInput};
use crate::gateway::Gateway;

use super::proof::{AuthzProof, SftpLicense, SftpProof};

/// The decision funnel shared by every protocol front.
#[derive(Clone)]
pub struct Enforcer {
    gw: Arc<Gateway>,
}

impl Enforcer {
    pub fn new(gw: Arc<Gateway>) -> Self {
        Enforcer { gw }
    }

    /// The gateway this enforcer decides for.
    pub fn gateway(&self) -> &Arc<Gateway> {
        &self.gw
    }

    /// Any PDP error fails closed to a deny — never allow on error.
    ///
    /// **The single funnel**: every `Pdp::decide` on a request path, for every protocol,
    /// goes through here, so the golden-capture tap sees 100% of emitted inputs without
    /// instrumenting a hook. A second call site would silently make the corpus incomplete;
    /// `tests/golden_capture.rs::decide_is_the_only_pdp_call_site_and_every_capture_round_trips`
    /// is the guard.
    pub async fn decide(&self, operation: &str, input: &OpaInput) -> Decision {
        if let Some(capture) = &self.gw.capture {
            capture.record(operation, input);
        }
        match self.gw.pdp.decide(input).await {
            Ok(d) => d,
            Err(e) => {
                tracing::error!(%e, "pdp error; failing closed");
                Decision::deny("pdp evaluation error")
            }
        }
    }

    /// The deny reason for a decision carrying a `must_understand` this binary cannot
    /// honor, or `None` when every named obligation is implemented.
    ///
    /// An obligation the policy declared mandatory and this binary cannot apply is a
    /// denial, not a warning: a restriction that silently did not happen is the fail-open
    /// shape this project exists to avoid.
    #[must_use]
    pub fn unimplemented_obligations(decision: &Decision) -> Option<String> {
        let missing = decision.obligations.unimplemented();
        if missing.is_empty() {
            return None;
        }
        Some(format!(
            "deny (gateway): the policy requires obligation(s) {} which this gateway does \
             not implement; upgrade the gateway before pushing a policy that depends on them",
            missing.join(", ")
        ))
    }

    /// Assemble a decision record in the ADR-002 shape.
    pub fn record(
        &self,
        input: OpaInput,
        decision: &Decision,
        outcome: Outcome,
        denied_keys: Vec<String>,
    ) -> AuditRecord {
        let meta = GatewayMeta {
            backend_id: input.backend.id.clone(),
            backend_kind: input.backend.kind.as_str().to_string(),
            outcome,
            denied_keys,
            backend: BackendOutcome::NotAttempted,
            backend_status: None,
            session: None,
        };
        AuditRecord::new(
            new_decision_id(),
            now_rfc3339(),
            input,
            decision.clone(),
            meta,
            self.gw.audit.labels(),
        )
    }

    /// Emit a denial now: the request is refused and there is no forward leg to wait for.
    pub fn audit_denied(&self, input: OpaInput, decision: &Decision, denied_keys: Vec<String>) {
        self.gw
            .audit
            .emit(self.record(input, decision, Outcome::Denied, denied_keys));
    }

    /// Emit a fully-formed record (one the caller enriched, e.g. with an SFTP session
    /// block).
    pub fn emit(&self, record: AuditRecord) {
        self.gw.audit.emit(record);
    }

    /// Hold an allowed record until the forward leg reports back. If nothing settles it,
    /// `PendingAudit`'s `Drop` emits it unenriched — the record is deferred, never
    /// conditional.
    pub fn pending(
        &self,
        input: OpaInput,
        decision: &Decision,
        denied_keys: Vec<String>,
    ) -> Arc<PendingAudit> {
        let record = self.record(input, decision, Outcome::Allowed, denied_keys);
        self.pending_record(record)
    }

    /// Hold an already-assembled record.
    pub fn pending_record(&self, record: AuditRecord) -> Arc<PendingAudit> {
        Arc::new(PendingAudit::new(self.gw.audit.clone(), record))
    }

    /// Record a denial from a pre-policy gate.
    ///
    /// Rate-limited inside the sink (`AuditSink::emit_gate_denial`): this is the audit
    /// stream an unauthenticated caller controls the rate of.
    pub fn audit_gate_denial(
        &self,
        op: &str,
        stage: GateStage,
        access_key_id: Option<&str>,
        tenant: Option<&str>,
        principal_sub: Option<&str>,
        reason: String,
    ) {
        self.gw.audit.emit_gate_denial(AuditRecord::gate_denial(
            new_decision_id(),
            now_rfc3339(),
            GateContext {
                operation: op.to_string(),
                stage,
                access_key_id: access_key_id.map(str::to_string),
                tenant: tenant.map(str::to_string),
                suppressed_since_last: 0,
            },
            reason,
            principal_sub.unwrap_or_default().to_string(),
            self.gw.audit.labels(),
        ));
    }

    /// Mint the S3 forward proof for `operation`. Only the enforce path calls this, on
    /// the allow side of an audited decision.
    pub(super) fn prove_s3(&self, operation: Arc<str>) -> AuthzProof {
        AuthzProof::mint(operation)
    }

    /// Mint an SFTP forward proof licensing exactly `licenses` (ADR-012 D2).
    ///
    /// Takes the [`Decision`]s that justify it and refuses unless **every one** is an
    /// allow carrying no unimplemented obligation: a proof cannot be produced from a
    /// denial, and cannot be produced from nothing. The SFTP front audits those same
    /// decisions through [`Self::pending`] / [`Self::audit_denied`] in the same branch.
    pub fn prove_sftp(
        &self,
        decisions: &[&Decision],
        licenses: Vec<SftpLicense>,
    ) -> Option<SftpProof> {
        if decisions.is_empty() {
            return None;
        }
        decisions
            .iter()
            .all(|d| d.allow && Self::unimplemented_obligations(d).is_none())
            .then(|| SftpProof::mint(licenses))
    }
}

pub(crate) fn new_decision_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub(crate) fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}
