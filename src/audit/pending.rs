//! The decision record between the decision and the forward.
//!
//! An audit record used to be emitted the instant the PDP answered, which made
//! `gateway.backend_status` permanently `None` and `Outcome::Error` a variant with no
//! producer: at decision time the forward has not happened yet. Post-forward
//! enrichment (plan task 18) requires holding the record across the forward, and this
//! is the thing that holds it.
//!
//! Two properties are non-negotiable, and the type is built around them:
//!
//! 1. **Exactly one record per request.** [`PendingAudit::settle`] takes the record out
//!    from behind a mutex, so a second settle (or a settle racing the drop) finds
//!    nothing and does nothing.
//! 2. **A record is never lost by being forgotten.** If nothing ever settles it — a
//!    hook that allowed the request and then failed before forwarding, an operation
//!    with no dispatch arm, a `post_object` that 501s — `Drop` emits it unenriched,
//!    with [`BackendOutcome::NotAttempted`]. Losing the enrichment is acceptable;
//!    losing the record is not.
//!
//! The cost of deferral: on a hard kill (SIGKILL, OOM) the records of requests still
//! in flight are gone, where before they would have been queued. That window is bounded
//! by the forward duration, it is strictly smaller than the loss the in-memory queue
//! already carries on the same event, and it is zero on graceful shutdown — `main`
//! drains the S3 front (so in-flight requests finish and settle) *before* it drains the
//! audit worker.

use std::sync::Mutex;

use super::record::{AuditRecord, BackendOutcome};
use super::sink::AuditSink;

/// A record that has been decided but not yet emitted, stashed in the request
/// extensions by the access layer and settled by the forward path.
///
/// Held as `Arc<PendingAudit>`: the forward path clones the handle out of the
/// extensions *before* the request (and its extensions) are moved into the backend
/// call, which is what keeps the record alive long enough to learn the outcome.
pub struct PendingAudit {
    sink: AuditSink,
    /// `None` once emitted. The mutex is uncontended in practice — one settle, one drop
    /// — and exists to make "emitted at most once" a property of the type rather than
    /// of the call order.
    record: Mutex<Option<AuditRecord>>,
}

impl PendingAudit {
    pub fn new(sink: AuditSink, record: AuditRecord) -> Self {
        PendingAudit {
            sink,
            record: Mutex::new(Some(record)),
        }
    }

    /// Emit the record, enriched with what the forward leg did. Idempotent: the second
    /// call is a no-op.
    pub fn settle(&self, backend: BackendOutcome, backend_status: Option<u16>) {
        let Some(mut record) = self.take() else {
            return;
        };
        record.settle(backend, backend_status);
        self.sink.emit(record);
    }

    fn take(&self) -> Option<AuditRecord> {
        // A poisoned lock here would mean a panic while holding the record; recovering
        // is strictly better than dropping an audit record on the floor.
        self.record.lock().unwrap_or_else(|e| e.into_inner()).take()
    }
}

impl Drop for PendingAudit {
    fn drop(&mut self) {
        if let Some(record) = self.take() {
            // The request was authorized and then never forwarded. That is not
            // necessarily a bug (a `NotImplemented` arm, a hook error after the
            // decision), but the decision was still made and must still be on the
            // record.
            tracing::debug!(
                decision_id = %record.decision_id,
                "audit record settled by drop: the request was decided but never forwarded"
            );
            self.sink.emit(record);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use crate::audit::{AuditBackend, AuditConfig, GatewayMeta, Outcome, spawn_with_backend};
    use crate::authz::{Backend, Decision, OpaInput, Principal, PrincipalAttributes, RequestMeta};
    use crate::model::{Action, BackendKind, PrincipalType};

    #[derive(Default)]
    struct Collector(Mutex<Vec<AuditRecord>>);

    #[async_trait::async_trait]
    impl AuditBackend for Collector {
        fn name(&self) -> &'static str {
            "test-collector"
        }
        async fn ship(&self, batch: &[AuditRecord]) -> Result<(), String> {
            self.0.lock().unwrap().extend_from_slice(batch);
            Ok(())
        }
    }

    fn record() -> AuditRecord {
        AuditRecord::new(
            "dec-1".into(),
            "2026-07-27T00:00:00Z".into(),
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
                config_kind: None,
                requested_tags: None,
                acl_grants: vec![],
                bypass_governance: false,
                request: RequestMeta::default(),
            },
            Decision::allow("grant matched"),
            GatewayMeta {
                backend_id: "bay-1".into(),
                backend_kind: "ceph".into(),
                outcome: Outcome::Allowed,
                denied_keys: vec![],
                backend: BackendOutcome::NotAttempted,
                backend_status: None,
            },
        )
    }

    async fn drain(collector: Arc<Collector>) -> Vec<AuditRecord> {
        for _ in 0..200 {
            if !collector.0.lock().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        collector.0.lock().unwrap().clone()
    }

    /// `batch_max: 1` so a record ships on the worker's very next poll rather than on
    /// the flush ticker. Dropping the returned `AuditHandle` detaches the worker rather
    /// than stopping it, so the caller does not have to hold it.
    fn sink(collector: Arc<Collector>) -> AuditSink {
        let spill =
            std::env::temp_dir().join(format!("s0-pending-{}.ndjson", uuid::Uuid::new_v4()));
        let (sink, _handle) = spawn_with_backend(
            AuditConfig {
                batch_max: 1,
                spill_path: spill,
                ..AuditConfig::default()
            },
            collector,
        );
        sink
    }

    #[tokio::test]
    async fn settling_emits_exactly_one_record_even_though_drop_also_runs() {
        let collector = Arc::new(Collector::default());
        let pending = Arc::new(PendingAudit::new(sink(collector.clone()), record()));
        pending.settle(BackendOutcome::SucceededStatusUnknown, None);
        // The Drop that follows must not produce a second record: a duplicated decision
        // record is as bad for an audit trail as a missing one.
        drop(pending);
        let records = drain(collector).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(records.len(), 1);
        assert_eq!(
            records[0].gateway.backend,
            BackendOutcome::SucceededStatusUnknown
        );
    }

    #[tokio::test]
    async fn a_record_nobody_settled_is_still_emitted() {
        // The safety net: an allow that never reaches the forward path (a hook error, a
        // NotImplemented arm) must not silently vanish from the decision log.
        let collector = Arc::new(Collector::default());
        let pending = PendingAudit::new(sink(collector.clone()), record());
        drop(pending);
        let records = drain(collector).await;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].gateway.backend, BackendOutcome::NotAttempted);
        assert!(matches!(records[0].gateway.outcome, Outcome::Allowed));
    }
}
