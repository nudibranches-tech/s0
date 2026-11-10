//! Summaries (ADR-011): the allowed reads and lists of a subject the bundle names in
//! `org_settings.audit_summary_subjects`, folded into one record per verb, bucket and
//! window. A denial, a failed forward and every other verb keep their own record.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::record::{AuditRecord, BackendOutcome, Outcome};

/// Who, where and which verb: the fields a reader of the trail filters on.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct WindowKey {
    subject: String,
    organization_id: String,
    tenant: String,
    backend_id: String,
    bucket: String,
    action: String,
}

impl WindowKey {
    fn of(record: &AuditRecord) -> Option<Self> {
        let input = record.input.as_ref()?;
        Some(WindowKey {
            subject: crate::pdp::principal_subject_key(input.principal.kind, &input.principal.sub),
            organization_id: input.organization_id.clone(),
            tenant: input.tenant.clone(),
            backend_id: input.backend.id.clone(),
            bucket: input.bucket.clone(),
            action: input.action.as_str().to_string(),
        })
    }
}

struct Window {
    record: AuditRecord,
    opened: Instant,
}

/// What the sink does with a record it offered to [`Summaries::fold`].
pub(crate) enum Folded {
    /// Counted in an open window; nothing to ship yet.
    Kept,
    /// A window reached its request cap: ship this summary now.
    Full(AuditRecord),
    /// Not summarised: ship the record as it is.
    Own(AuditRecord),
}

pub(crate) struct Summaries {
    window: Duration,
    max_requests: u64,
    open: Mutex<HashMap<WindowKey, Window>>,
}

impl Summaries {
    pub(crate) fn new(window: Duration, max_requests: u64) -> Self {
        Summaries {
            window,
            max_requests: max_requests.max(1),
            open: Mutex::new(HashMap::new()),
        }
    }

    /// Only a marked request that was allowed and reached the backend successfully is
    /// folded in.
    pub(crate) fn fold(&self, record: AuditRecord) -> Folded {
        let summarisable = record.summarise
            && record.gateway.outcome == Outcome::Allowed
            && record.gateway.backend == BackendOutcome::SucceededStatusUnknown;
        let Some(key) = summarisable.then(|| WindowKey::of(&record)).flatten() else {
            return Folded::Own(record);
        };
        let mut open = self.lock();
        let Some(window) = open.get_mut(&key) else {
            let first = record.into_summary();
            if self.max_requests == 1 {
                return Folded::Full(first);
            }
            open.insert(
                key,
                Window {
                    record: first,
                    opened: Instant::now(),
                },
            );
            return Folded::Kept;
        };
        let full = window
            .record
            .gateway
            .summary
            .as_mut()
            .is_some_and(|summary| {
                summary.requests += 1;
                summary.last_at = record.timestamp;
                summary.requests >= self.max_requests
            });
        if !full {
            return Folded::Kept;
        }
        match open.remove(&key) {
            Some(window) => Folded::Full(window.record),
            None => Folded::Kept,
        }
    }

    /// The summaries whose window has closed by `now`.
    pub(crate) fn take_due(&self, now: Instant) -> Vec<AuditRecord> {
        let mut open = self.lock();
        let due: Vec<WindowKey> = open
            .iter()
            .filter(|(_, w)| now.duration_since(w.opened) >= self.window)
            .map(|(k, _)| k.clone())
            .collect();
        due.into_iter()
            .filter_map(|key| open.remove(&key).map(|w| w.record))
            .collect()
    }

    /// Every open summary, on shutdown.
    pub(crate) fn take_all(&self) -> Vec<AuditRecord> {
        self.lock().drain().map(|(_, w)| w.record).collect()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<WindowKey, Window>> {
        // A panic while folding leaves counts, never a half-built record: keep going.
        self.open.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{GatewayMeta, LabelPolicy};
    use crate::authz::{Backend, Decision, OpaInput, Principal, PrincipalAttributes, RequestMeta};
    use crate::model::{Action, BackendKind, PrincipalType};

    fn record(sub: &str, bucket: &str, action: Action, at: &str) -> AuditRecord {
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
                prefix: None,
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
            Decision::allow("grant matched"),
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
        record.summarise = true;
        record
    }

    fn kept(folded: Folded) -> bool {
        matches!(folded, Folded::Kept)
    }

    #[test]
    fn requests_of_one_window_become_one_record_without_their_details() {
        let summaries = Summaries::new(Duration::ZERO, 100);
        for at in ["t1", "t2", "t3"] {
            assert!(kept(summaries.fold(record(
                "rm",
                "bronze",
                Action::ReadObjects,
                at
            ))));
        }

        let due = summaries.take_due(Instant::now());

        assert_eq!(due.len(), 1);
        let summary = due[0].gateway.summary.as_ref().expect("a summary");
        assert_eq!(
            (
                summary.requests,
                summary.first_at.as_str(),
                summary.last_at.as_str()
            ),
            (3, "t1", "t3")
        );
        let input = due[0].input.as_ref().expect("input");
        assert_eq!(input.object, None, "a summary names no single object");
        assert_eq!(input.request.params, None);
        assert!(input.request.headers_subset.is_empty());
        assert!(summaries.take_all().is_empty());
    }

    #[test]
    fn each_subject_bucket_and_verb_has_its_own_window() {
        let summaries = Summaries::new(Duration::from_secs(3600), 100);
        summaries.fold(record("rm", "bronze", Action::ReadObjects, "t1"));
        summaries.fold(record("rm", "bronze", Action::ListObjects, "t2"));
        summaries.fold(record("rm", "silver", Action::ReadObjects, "t3"));
        summaries.fold(record("other", "bronze", Action::ReadObjects, "t4"));

        assert!(
            summaries.take_due(Instant::now()).is_empty(),
            "the hour is not over"
        );
        assert_eq!(summaries.take_all().len(), 4);
    }

    #[test]
    fn a_window_at_its_cap_ships_at_once() {
        let summaries = Summaries::new(Duration::from_secs(3600), 2);
        assert!(kept(summaries.fold(record(
            "rm",
            "bronze",
            Action::ReadObjects,
            "t1"
        ))));
        let Folded::Full(full) = summaries.fold(record("rm", "bronze", Action::ReadObjects, "t2"))
        else {
            panic!("the second request fills a window of two");
        };
        assert_eq!(full.gateway.summary.map(|s| s.requests), Some(2));
        assert!(summaries.take_all().is_empty());
    }

    #[test]
    fn a_denial_a_failure_and_an_unlisted_subject_keep_their_own_record() {
        let summaries = Summaries::new(Duration::ZERO, 100);
        let mut denied = record("rm", "bronze", Action::ReadObjects, "t1");
        denied.gateway.outcome = Outcome::Denied;
        let mut failed = record("rm", "bronze", Action::ReadObjects, "t2");
        failed.settle(BackendOutcome::Failed, Some(503));
        let mut never_forwarded = record("rm", "bronze", Action::ReadObjects, "t3");
        never_forwarded.gateway.backend = BackendOutcome::NotAttempted;
        let mut unlisted = record("rm", "bronze", Action::ReadObjects, "t4");
        unlisted.summarise = false;

        for record in [denied, failed, never_forwarded, unlisted] {
            assert!(matches!(summaries.fold(record), Folded::Own(_)));
        }
        assert!(summaries.take_all().is_empty());
    }
}
