//! Unified audit trail. One reasoned decision record per S3
//! request, in OPA's native decision-log shape, attributed to the end-user identity
//! and shipped asynchronously so audit never blocks the data path.

mod record;
mod sink;

pub use record::{AuditRecord, GatewayMeta, LABEL_ORG_ID, Outcome, RECORD_TYPE_VALUE};
pub use sink::{AuditConfig, AuditHandle, AuditSink, spawn};
