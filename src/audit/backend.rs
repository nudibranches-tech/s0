//! Where a batch of audit records actually goes. **A backend must never fail the
//! request**: `ship` returns `Err(String)` and the worker spills.
//!
//! The worker in [`super::sink`] owns batching, spilling, replay and the drop counters,
//! all of which are transport-independent. This trait is the one seam that is not, so
//! retargeting the destination never means reopening the spill state machine.
//!
//! - [`ControlPlaneBackend`] — batched POST to the decision-log endpoint. Default.
//! - [`StdoutNdjsonBackend`] — one flat JSON line per record on stdout, for whatever log
//!   agent already tails the pod.

use std::io::Write;

use serde::Serialize;

use super::record::AuditRecord;

/// The `event` discriminator on every stdout line. A log-query language selects the
/// gateway decision stream out of a namespace's combined firehose with this literal, so
/// it is a consumer contract: do not rename it without the query that reads it.
pub const EVENT_KIND: &str = "s3_gateway_decision";

/// A destination for assembled batches of audit records.
///
/// Implementations must be cheap to clone-by-`Arc` and safe to call concurrently: the
/// worker calls `ship` from its own task, but replay and flush can both be in flight.
#[async_trait::async_trait]
pub trait AuditBackend: Send + Sync + 'static {
    /// Stable name, for logs and for the startup line that tells an operator where their
    /// audit trail is going.
    fn name(&self) -> &'static str;

    /// Ship a whole batch, atomically from the worker's point of view: on `Err` the
    /// entire batch is spilled and retried later, so a partial success must be reported
    /// as `Ok` only if every record is durable at the destination.
    async fn ship(&self, batch: &[AuditRecord]) -> Result<(), String>;
}

/// The control-plane decision-log endpoint: one batched JSON POST.
pub struct ControlPlaneBackend {
    client: reqwest::Client,
    url: String,
}

impl ControlPlaneBackend {
    pub fn new(client: reqwest::Client, url: String) -> Self {
        ControlPlaneBackend { client, url }
    }
}

#[async_trait::async_trait]
impl AuditBackend for ControlPlaneBackend {
    fn name(&self) -> &'static str {
        "control-plane"
    }

    async fn ship(&self, batch: &[AuditRecord]) -> Result<(), String> {
        let resp = self
            .client
            .post(&self.url)
            .json(&batch)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(format!("status {}", resp.status()))
        }
    }
}

/// One record per line on stdout, as a flat top-level JSON object carrying the
/// [`EVENT_KIND`] discriminator.
///
/// Written **directly** to stdout rather than through `tracing::info!`, whose JSON
/// formatter wraps a message in `{"timestamp":…,"fields":{"message":"…"}}` — the record
/// would arrive as a string nested two levels down, and a log query would see one opaque
/// field.
pub struct StdoutNdjsonBackend;

/// The wire line: the discriminator, then the record's own fields flattened up to the
/// top level, so a log query yields queryable fields rather than one opaque blob.
#[derive(Serialize)]
struct NdjsonLine<'a> {
    event: &'static str,
    #[serde(flatten)]
    record: &'a AuditRecord,
}

impl StdoutNdjsonBackend {
    /// The exact bytes this backend writes for a batch. Separated from the write so it
    /// is testable without capturing the process's stdout.
    fn render(batch: &[AuditRecord]) -> Result<String, String> {
        let mut out = String::with_capacity(batch.len() * 512);
        for record in batch {
            let line = serde_json::to_string(&NdjsonLine {
                event: EVENT_KIND,
                record,
            })
            .map_err(|e| e.to_string())?;
            out.push_str(&line);
            out.push('\n');
        }
        Ok(out)
    }
}

#[async_trait::async_trait]
impl AuditBackend for StdoutNdjsonBackend {
    fn name(&self) -> &'static str {
        "stdout-ndjson"
    }

    async fn ship(&self, batch: &[AuditRecord]) -> Result<(), String> {
        let rendered = Self::render(batch)?;
        // One locked write per batch: interleaving with the tracing writer mid-line
        // corrupts both streams, and a partial line is an unparseable record. On
        // `spawn_blocking` because a slow log consumer blocks the write, and
        // `block_in_place` panics on the current-thread runtime `#[tokio::test]` uses.
        tokio::task::spawn_blocking(move || {
            let stdout = std::io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(rendered.as_bytes())
                .and_then(|()| lock.flush())
                .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| format!("stdout writer task failed: {e}"))?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{BackendOutcome, GatewayMeta, Outcome};
    use crate::authz::{Backend, Decision, OpaInput, Principal, PrincipalAttributes, RequestMeta};
    use crate::model::{Action, BackendKind, PrincipalType};

    fn record(id: &str) -> AuditRecord {
        AuditRecord::new(
            id.into(),
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
            &crate::audit::LabelPolicy::default(),
        )
    }

    #[test]
    fn ndjson_is_one_flat_line_per_record_with_the_discriminator() {
        let rendered = StdoutNdjsonBackend::render(&[record("a"), record("b")]).unwrap();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines.len(), 2, "one line per record");
        assert!(
            rendered.ends_with('\n'),
            "the last record is terminated too"
        );

        for (line, id) in lines.iter().zip(["a", "b"]) {
            // Each line must be a complete, bare JSON object — nothing before it, no
            // continuation after it. A wrapped or split line is unparseable on the
            // ingest side, which is a silently lost record.
            let v: serde_json::Value = serde_json::from_str(line).expect("a bare JSON object");
            assert_eq!(v["event"], EVENT_KIND);
            // The record's own fields are at the TOP level, not nested under a key.
            assert_eq!(v["decision_id"], id);
            assert_eq!(v["requested_by"], "alice");
            assert_eq!(v["gateway"]["outcome"], "allowed");
            assert!(!line.contains('\n'));
        }
    }

    #[test]
    fn a_record_carrying_a_newline_cannot_break_the_line_framing() {
        // Object keys are attacker-influenced (a client picks them), and NDJSON framing
        // is by newline. `serde_json` escapes control characters, so a key containing a
        // newline stays inside one line — this asserts that rather than assuming it.
        let mut rec = record("nl");
        if let Some(input) = rec.input.as_mut() {
            input.object = Some("evil\n{\"event\":\"forged\"}".into());
        }
        let rendered = StdoutNdjsonBackend::render(&[rec]).unwrap();
        assert_eq!(rendered.lines().count(), 1, "{rendered}");
        let v: serde_json::Value = serde_json::from_str(rendered.trim_end()).unwrap();
        assert_eq!(v["input"]["object"], "evil\n{\"event\":\"forged\"}");
    }
}
