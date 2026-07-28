//! Unified audit trail. One reasoned decision record per S3
//! request, in OPA's native decision-log shape, attributed to the end-user identity
//! and shipped asynchronously so audit never blocks the data path.
//!
//! - [`record`] — the wire shape: a decision record, or a gate record for a denial
//!   that happened before any policy question existed.
//! - [`pending`] — the record held across the forward, so `backend_status` and
//!   `outcome: "error"` describe what actually happened.
//! - [`backend`] — where a batch goes; the one retargetable seam.
//! - [`sink`] — queueing, batching, disk spill and the loss counters.

mod backend;
mod pending;
mod record;
mod sink;

pub use backend::{AuditBackend, ControlPlaneBackend, HF_EVENT, StdoutNdjsonBackend};
pub use pending::PendingAudit;
pub use record::{
    AuditRecord, BackendOutcome, DATA_DOCK_TYPE_VALUE, DECISION_PATH, GATE_PATH, GateContext,
    GateStage, GatewayMeta, LABEL_DATA_DOCK_TYPE, LABEL_ORG_ID, Outcome,
};
pub use sink::{
    AuditBackendKind, AuditConfig, AuditHandle, AuditMetrics, AuditSink, spawn, spawn_with_backend,
};
