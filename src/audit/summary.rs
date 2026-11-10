//! Summaries (ADR-011): the allowed reads and lists of a service account the bundle
//! names in `org_settings.audit_summary_subjects`, folded into one record per operation,
//! session, bucket and window. A denial, a failed forward and every other verb keep
//! their own record.
//!
//! Summaries never pass through the audit queue: a window that closes, by age or by
//! reaching its request cap, waits here for the worker's next flush tick. Once the
//! worker has taken the last of them on its way out, nothing is folded any more, so a
//! late request keeps its own record and its loss is counted like any other.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::record::{AuditRecord, BackendOutcome, Outcome, SummaryScope};

/// Who, where, which operation and which session: the fields a reader of the trail
/// filters on, and the ones that tell a job's own session from another use of its key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WindowKey {
    subject: String,
    organization_id: String,
    tenant: String,
    backend_id: String,
    bucket: String,
    action: &'static str,
    method: String,
    scope: SummaryScope,
}

impl WindowKey {
    fn of(record: &AuditRecord, scope: &SummaryScope) -> Option<Self> {
        let input = record.input.as_ref()?;
        Some(WindowKey {
            subject: crate::pdp::principal_subject_key(input.principal.kind, &input.principal.sub),
            organization_id: input.organization_id.clone(),
            tenant: input.tenant.clone(),
            backend_id: input.backend.id.clone(),
            bucket: input.bucket.clone(),
            action: input.action.as_str(),
            method: input.request.method.clone(),
            scope: scope.clone(),
        })
    }
}

struct Window {
    record: AuditRecord,
    opened: Instant,
}

#[derive(Default)]
struct State {
    open: HashMap<WindowKey, Window>,
    /// Windows that reached their request cap, waiting for the worker.
    full: Vec<AuditRecord>,
    /// The worker has taken its last summaries: fold nothing more.
    closed: bool,
}

pub(crate) struct Summaries {
    window: Duration,
    max_requests: u64,
    state: Mutex<State>,
}

impl Summaries {
    pub(crate) fn new(window: Duration, max_requests: u64) -> Self {
        Summaries {
            window,
            max_requests: max_requests.max(1),
            state: Mutex::new(State::default()),
        }
    }

    /// Folds a scoped request that was allowed and that the backend served into its
    /// summary, and returns `None`; hands every other record back, before the lock.
    pub(crate) fn fold(&self, mut record: AuditRecord) -> Option<AuditRecord> {
        let summarisable = record.gateway.outcome == Outcome::Allowed
            && record.gateway.backend == BackendOutcome::SucceededStatusUnknown;
        let Some(scope) = record.summary_scope.take().filter(|_| summarisable) else {
            return Some(record);
        };
        let Some(key) = WindowKey::of(&record, &scope) else {
            return Some(record);
        };
        let mut state = self.lock();
        if state.closed {
            return Some(record);
        }
        let reached_cap = match state.open.get_mut(&key) {
            Some(window) => window
                .record
                .gateway
                .summary
                .as_mut()
                .is_some_and(|summary| {
                    summary.requests += 1;
                    if earlier(&record.timestamp, &summary.first_at) {
                        summary.first_at.clone_from(&record.timestamp);
                    }
                    if earlier(&summary.last_at, &record.timestamp) {
                        summary.last_at.clone_from(&record.timestamp);
                    }
                    summary.requests >= self.max_requests
                }),
            None => {
                state.open.insert(
                    key.clone(),
                    Window {
                        record: record.into_summary(scope),
                        opened: Instant::now(),
                    },
                );
                self.max_requests == 1
            }
        };
        if reached_cap && let Some(window) = state.open.remove(&key) {
            state.full.push(window.record);
        }
        None
    }

    /// The windows that reached their cap, and those opened at least a window ago.
    pub(crate) fn take_due(&self, now: Instant) -> Vec<AuditRecord> {
        let mut state = self.lock();
        let mut due = std::mem::take(&mut state.full);
        let aged: Vec<WindowKey> = state
            .open
            .iter()
            .filter(|(_, w)| now.duration_since(w.opened) >= self.window)
            .map(|(k, _)| k.clone())
            .collect();
        due.extend(
            aged.into_iter()
                .filter_map(|key| state.open.remove(&key).map(|w| w.record)),
        );
        due
    }

    /// Every summary still held, on the worker's way out. Nothing is folded afterwards.
    pub(crate) fn close(&self) -> Vec<AuditRecord> {
        let mut state = self.lock();
        state.closed = true;
        let mut all = std::mem::take(&mut state.full);
        all.extend(state.open.drain().map(|(_, w)| w.record));
        all
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        // A panic while folding leaves counts, never a half-built record: keep going.
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Whether RFC 3339 time `a` is before `b`. Compared as instants; two the parser cannot
/// read are compared as text, which orders `to_rfc3339` output in UTC correctly.
fn earlier(a: &str, b: &str) -> bool {
    match (
        chrono::DateTime::parse_from_rfc3339(a),
        chrono::DateTime::parse_from_rfc3339(b),
    ) {
        (Ok(a), Ok(b)) => a < b,
        _ => a < b,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{GatewayMeta, LabelPolicy, SUMMARY_PATH};
    use crate::authz::{
        Backend, Decision, Obligations, OpaInput, Principal, PrincipalAttributes, RequestMeta,
    };
    use crate::model::{Action, BackendKind, PrincipalType};

    fn scope(operation: &str) -> SummaryScope {
        SummaryScope {
            operation: operation.into(),
            access_key_id: Some("HFST0.session-a".into()),
            presigned: false,
        }
    }

    fn record(sub: &str, bucket: &str, action: Action, at: &str) -> AuditRecord {
        let mut decision = Decision::allow("grant matched");
        decision.obligations = Obligations {
            narrow_prefix: Some("2024/".into()),
            ..Default::default()
        };
        let mut record = AuditRecord::new(
            uuid::Uuid::new_v4().to_string(),
            at.into(),
            OpaInput {
                principal: Principal {
                    sub: sub.into(),
                    kind: PrincipalType::ServiceAccount,
                    attributes: PrincipalAttributes::default(),
                },
                backend: Backend {
                    id: "bay-1".into(),
                    kind: BackendKind::Ceph,
                },
                tenant: "acme".into(),
                organization_id: "org-acme".into(),
                action,
                bucket: bucket.into(),
                object: Some(format!("data/{at}.parquet")),
                prefix: Some("2024/".into()),
                copy_source: None,
                delete_keys: None,
                object_tags: None,
                requested_tags: None,
                acl_grants: vec![],
                bypass_governance: false,
                request: RequestMeta {
                    method: "GET".into(),
                    params: Some("partNumber=1".into()),
                    headers_subset: [("range".to_string(), "bytes=0-9".to_string())].into(),
                },
            },
            decision,
            GatewayMeta {
                backend_id: "bay-1".into(),
                backend_kind: "ceph".into(),
                outcome: Outcome::Allowed,
                denied_keys: vec![],
                backend: BackendOutcome::SucceededStatusUnknown,
                backend_status: None,
                object_name: None,
                copy_source_object_name: None,
                summary: None,
            },
            &LabelPolicy::default(),
        );
        record.summary_scope = Some(scope("GetObject"));
        record
    }

    fn kept(folded: Option<AuditRecord>) -> bool {
        folded.is_none()
    }

    #[test]
    fn requests_of_one_window_become_one_record_without_their_details() {
        let summaries = Summaries::new(Duration::ZERO, 100);
        for at in [
            "2026-11-10T12:00:02+00:00",
            "2026-11-10T12:00:01.5+00:00",
            "2026-11-10T12:00:03+00:00",
        ] {
            assert!(kept(summaries.fold(record(
                "rm",
                "bronze",
                Action::ReadObjects,
                at
            ))));
        }

        let due = summaries.take_due(Instant::now());

        assert_eq!(due.len(), 1);
        let shipped = &due[0];
        assert_eq!(shipped.path, SUMMARY_PATH);
        let summary = shipped.gateway.summary.as_ref().expect("a summary");
        assert_eq!(summary.operation, "GetObject");
        assert_eq!(summary.requests, 3);
        assert_eq!(
            (summary.first_at.as_str(), summary.last_at.as_str()),
            ("2026-11-10T12:00:01.5+00:00", "2026-11-10T12:00:03+00:00"),
            "earliest and latest, whatever order the requests settled in"
        );
        assert_eq!(summary.access_key_id.as_deref(), Some("HFST0.session-a"));
        let input = shipped.input.as_ref().expect("input");
        assert_eq!(
            (input.object.as_deref(), input.prefix.as_deref()),
            (None, None)
        );
        assert_eq!(input.request.params, None);
        assert!(input.request.headers_subset.is_empty());
        assert_eq!(shipped.result.obligations, Obligations::default());
        assert!(summaries.close().is_empty());
    }

    #[test]
    fn each_operation_method_session_and_bucket_has_its_own_window() {
        let summaries = Summaries::new(Duration::from_secs(3600), 100);
        let base = || record("rm", "bronze", Action::ReadObjects, "t1");
        let mut head = base();
        head.summary_scope = Some(scope("HeadObject"));
        head.input.as_mut().expect("input").request.method = "HEAD".into();
        let mut other_session = base();
        other_session.summary_scope = Some(SummaryScope {
            access_key_id: Some("HFST0.session-b".into()),
            ..scope("GetObject")
        });
        let mut presigned = base();
        presigned.summary_scope = Some(SummaryScope {
            presigned: true,
            ..scope("GetObject")
        });
        for record in [
            base(),
            base(),
            head,
            other_session,
            presigned,
            record("rm", "silver", Action::ReadObjects, "t2"),
            record("other", "bronze", Action::ReadObjects, "t3"),
        ] {
            assert!(kept(summaries.fold(record)));
        }

        assert!(
            summaries.take_due(Instant::now()).is_empty(),
            "the hour is not over"
        );
        let all = summaries.close();
        assert_eq!(all.len(), 6, "the two plain reads share one window");
    }

    #[test]
    fn a_window_at_its_cap_waits_for_the_worker_and_the_next_request_opens_another() {
        let summaries = Summaries::new(Duration::from_secs(3600), 2);
        for at in ["t1", "t2", "t3"] {
            assert!(kept(summaries.fold(record(
                "rm",
                "bronze",
                Action::ReadObjects,
                at
            ))));
        }

        let due = summaries.take_due(Instant::now());

        assert_eq!(due.len(), 1, "only the full window is due within the hour");
        assert_eq!(due[0].gateway.summary.as_ref().map(|s| s.requests), Some(2));
        let rest = summaries.close();
        assert_eq!(rest.len(), 1);
        assert_eq!(
            rest[0].gateway.summary.as_ref().map(|s| s.requests),
            Some(1)
        );
    }

    #[test]
    fn nothing_is_folded_once_the_worker_has_taken_its_last_summaries() {
        let summaries = Summaries::new(Duration::from_secs(3600), 100);
        assert!(kept(summaries.fold(record(
            "rm",
            "bronze",
            Action::ReadObjects,
            "t1"
        ))));
        assert_eq!(summaries.close().len(), 1);

        let late = summaries.fold(record("rm", "bronze", Action::ReadObjects, "t2"));

        let Some(own) = late else {
            panic!("a late request must keep its own record");
        };
        assert!(own.gateway.summary.is_none());
        assert!(
            own.summary_scope.is_none(),
            "the scope never reaches the wire"
        );
        assert!(summaries.close().is_empty());
    }

    #[test]
    fn a_denial_a_failure_and_an_unscoped_request_keep_their_own_record() {
        let summaries = Summaries::new(Duration::ZERO, 100);
        let mut denied = record("rm", "bronze", Action::ReadObjects, "t1");
        denied.gateway.outcome = Outcome::Denied;
        let mut failed = record("rm", "bronze", Action::ReadObjects, "t2");
        failed.settle(BackendOutcome::Failed, Some(503));
        let mut never_forwarded = record("rm", "bronze", Action::ReadObjects, "t3");
        never_forwarded.gateway.backend = BackendOutcome::NotAttempted;
        let mut unscoped = record("rm", "bronze", Action::ReadObjects, "t4");
        unscoped.summary_scope = None;

        for record in [denied, failed, never_forwarded, unscoped] {
            let Some(own) = summaries.fold(record) else {
                panic!("folded a record that must keep its own");
            };
            assert!(own.gateway.summary.is_none() && own.path != SUMMARY_PATH);
        }
        assert!(summaries.close().is_empty());
    }
}
