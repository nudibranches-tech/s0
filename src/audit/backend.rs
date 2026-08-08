//! Where a batch of audit records actually goes.
//!
//! The worker in [`super::sink`] owns batching, spilling, replay and the drop counters
//! — all of which are transport-independent. This trait is the one seam that is not:
//! it exists so the destination can be retargeted without reopening any of that.
//!
//! That is not speculative. The audit trail is scheduled to move to Kafka → Iceberg,
//! and the control-plane HTTP endpoint it POSTs to today is a decision-log ingest that
//! predates this gateway. A `KafkaBackend` must be a new file, not a rewrite of the
//! spill state machine — the part of the pipeline whose failure mode is silent record
//! loss is the part that must stop being edited.
//!
//! Two backends ship:
//!
//! - [`ControlPlaneBackend`] — the batched POST that exists today. Default.
//! - [`StdoutNdjsonBackend`] — one flat JSON line per record on stdout, which the
//!   `vlagent` already tailing every pod ships to VictoriaLogs for free. This is the
//!   pattern hyperfluid's Bifrost access events use
//!   (`rust/hf_module_bifrost/src/access_event.rs`), down to the `hf_event`
//!   discriminator LogsQL filters on.
//!
//! **A backend must never fail the request.** `ship` returns `Err(String)` and the
//! worker spills; nothing here is on the data path.

use std::io::Write;

use serde::Serialize;

use super::record::AuditRecord;

/// The `hf_event` discriminator on every stdout line. LogsQL selects the gateway
/// decision stream out of the namespace's combined log firehose with this literal, so
/// it is a cross-service contract: do not rename it without the Console-side query.
pub const HF_EVENT: &str = "s3_gateway_decision";

/// A destination for assembled batches of audit records.
///
/// Implementations must be cheap to clone-by-`Arc` and safe to call concurrently: the
/// worker calls `ship` from its own task, but replay and flush can both be in flight.
#[async_trait::async_trait]
pub trait AuditBackend: Send + Sync + 'static {
    /// Stable name, for logs and for the startup line that tells an operator where
    /// their audit trail is going. A gateway whose audit destination is a mystery is
    /// the same problem as one with no audit at all.
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
/// [`HF_EVENT`] discriminator.
///
/// Written **directly** to stdout rather than through `tracing::info!`, for the same
/// reason Bifrost does: `main` installs `tracing_subscriber::fmt().json()`, which wraps
/// a message inside `{"timestamp":…,"fields":{"message":"…"}}`. The record would arrive
/// as a JSON *string* nested two levels down, and `unpack_json` on the query side would
/// see one opaque field. A direct write guarantees the printed line is byte-for-byte
/// the object the contract promises.
pub struct StdoutNdjsonBackend;

/// The wire line: the discriminator, then the record's own fields flattened up to the
/// top level so LogsQL's `unpack_json` yields queryable fields rather than one blob.
#[derive(Serialize)]
struct NdjsonLine<'a> {
    hf_event: &'static str,
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
                hf_event: HF_EVENT,
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
        // One locked write for the whole batch: interleaving with the tracing writer
        // mid-line would corrupt both streams, and a partial line is an unparseable
        // record on the ingest side.
        //
        // On `spawn_blocking` rather than a bare write or `block_in_place`: writing to
        // stdout blocks when the consumer (the container runtime's log pipe) is slow,
        // and `block_in_place` panics outright on a current-thread runtime, which is
        // what every `#[tokio::test]` uses. This shape works on both flavours.
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
            // continuation after it. A wrapped or split line is unparseable by
            // `unpack_json` on the ingest side, which is a silently lost record.
            let v: serde_json::Value = serde_json::from_str(line).expect("a bare JSON object");
            assert_eq!(v["hf_event"], HF_EVENT);
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
            input.object = Some("evil\n{\"hf_event\":\"forged\"}".into());
        }
        let rendered = StdoutNdjsonBackend::render(&[rec]).unwrap();
        assert_eq!(rendered.lines().count(), 1, "{rendered}");
        let v: serde_json::Value = serde_json::from_str(rendered.trim_end()).unwrap();
        assert_eq!(v["input"]["object"], "evil\n{\"hf_event\":\"forged\"}");
    }
}
