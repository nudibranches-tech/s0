//! Unified audit trail (§3.6, §4.5, §6.6). One reasoned decision record per S3
//! request, in OPA's native decision-log shape, attributed to the end-user identity
//! and shipped asynchronously so audit never blocks the data path (§9.2).

mod record;
mod sink;

pub use record::{AuditRecord, DOCK_TYPE_VALUE, GatewayMeta, LABEL_ORG_ID, Outcome};
pub use sink::{AuditConfig, AuditSink, spawn};
