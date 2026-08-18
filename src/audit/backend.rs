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

    /// What the control plane actually received.
    #[derive(Debug)]
    struct Received {
        method: String,
        path: String,
        content_type: String,
        body: String,
    }

    /// A stand-in for the decision-log endpoint that records every request and answers
    /// with `status`. Returns its URL and the shared log.
    ///
    /// On a real socket rather than against a mocked client: the thing under test is what
    /// goes on the wire, and a fake that agrees with the code by construction cannot
    /// catch a shape the ingest side will reject.
    async fn recording_control_plane(
        status: u16,
    ) -> (String, std::sync::Arc<std::sync::Mutex<Vec<Received>>>) {
        use std::sync::{Arc, Mutex};

        let seen: Arc<Mutex<Vec<Received>>> = Arc::new(Mutex::new(Vec::new()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let served = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let served = served.clone();
                tokio::spawn(async move {
                    let svc = hyper::service::service_fn(
                        move |req: hyper::Request<hyper::body::Incoming>| {
                            let served = served.clone();
                            async move {
                                let method = req.method().to_string();
                                let path = req.uri().path().to_string();
                                let content_type = req
                                    .headers()
                                    .get(hyper::header::CONTENT_TYPE)
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or_default()
                                    .to_string();
                                let body = http_body_util::BodyExt::collect(req.into_body())
                                    .await
                                    .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
                                    .unwrap_or_default();
                                served.lock().unwrap().push(Received {
                                    method,
                                    path,
                                    content_type,
                                    body,
                                });
                                Ok::<_, std::convert::Infallible>(
                                    hyper::Response::builder()
                                        .status(status)
                                        .body(http_body_util::Full::new(bytes::Bytes::new()))
                                        .unwrap(),
                                )
                            }
                        },
                    );
                    let _ = hyper_util::server::conn::auto::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), svc)
                    .await;
                });
            }
        });
        (format!("http://{addr}/api/v1/decision-logs"), seen)
    }

    #[tokio::test]
    async fn a_batch_reaches_the_control_plane_as_one_flat_json_array() {
        let (url, seen) = recording_control_plane(200).await;
        ControlPlaneBackend::new(reqwest::Client::new(), url)
            .ship(&[record("a"), record("b")])
            .await
            .expect("a 2xx is success");

        let seen = seen.lock().unwrap();
        assert_eq!(
            seen.len(),
            1,
            "a batch is ONE request; one POST per record would multiply ingest load by \
             the batch size"
        );
        let req = &seen[0];
        assert_eq!(req.method, "POST");
        assert_eq!(
            req.path, "/api/v1/decision-logs",
            "the configured URL is used verbatim — no path is appended or rewritten"
        );
        assert!(
            req.content_type.starts_with("application/json"),
            "content-type was {:?}",
            req.content_type
        );

        // The consumer contract. Every assertion below is something the ingest side
        // parses by, so a change here is a change to a published wire format, not an
        // implementation detail: a batch is a bare JSON array whose elements are the
        // records themselves, with their fields at the top level rather than nested
        // under a wrapper key.
        let body: serde_json::Value = serde_json::from_str(&req.body).expect("a JSON body");
        let batch = body.as_array().expect("a batch is a JSON array");
        assert_eq!(batch.len(), 2, "one element per record, in order");
        assert_eq!(batch[0]["decision_id"], "a");
        assert_eq!(batch[1]["decision_id"], "b");
        assert_eq!(batch[0]["requested_by"], "alice");
        assert_eq!(batch[0]["gateway"]["outcome"], "allowed");
        // Unlike the NDJSON line, the POST carries no `event` discriminator: the endpoint
        // is dedicated, so there is no combined firehose to select out of. Asserted so
        // the asymmetry with `EVENT_KIND` is deliberate and visible rather than a
        // difference someone discovers from an ingest-side parse failure.
        assert!(batch[0].get("event").is_none());
    }

    #[tokio::test]
    async fn a_control_plane_error_status_is_a_failure_not_a_silent_success() {
        // `ship` returning Ok means the worker counts the batch shipped and forgets it.
        // For any answer that is not a success the records are NOT durable at the
        // destination, so Ok would turn a control-plane outage — or a rejected payload,
        // or a revoked credential — into audit records that no one holds and no counter
        // reports. Err spills them instead.
        for status in [400u16, 403, 429, 500, 503] {
            let (url, seen) = recording_control_plane(status).await;
            let err = ControlPlaneBackend::new(reqwest::Client::new(), url)
                .ship(&[record("a")])
                .await
                .expect_err(&format!("HTTP {status} must not be reported as shipped"));
            assert!(
                err.contains(&status.to_string()),
                "the failure must name the status an operator has to act on; got {err:?}"
            );
            assert_eq!(seen.lock().unwrap().len(), 1, "the batch was actually sent");
        }
    }

    /// The whole default path, as configured rather than as injected: `spawn` picks the
    /// backend from [`AuditBackendKind`], builds the HTTP client, and the records land at
    /// a real endpoint. Every other sink test substitutes its own backend or an
    /// unroutable URL, so without this the selection itself — the one step a deployment
    /// cannot override — is never exercised against a server that answers.
    #[tokio::test]
    async fn the_config_selected_default_backend_ships_to_the_endpoint() {
        use crate::audit::{AuditBackendKind, AuditConfig, spawn};

        let (url, seen) = recording_control_plane(200).await;
        let dir = std::env::temp_dir().join(format!("s0-cp-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("tmpdir");

        let (sink, handle) = spawn(AuditConfig {
            sink_url: url,
            backend: AuditBackendKind::ControlPlane,
            spill_path: dir.join("audit-spill.ndjson"),
            instance: "pod-cp".into(),
            batch_max: 2,
            flush_interval: std::time::Duration::from_millis(20),
            ..AuditConfig::default()
        });
        sink.emit(record("a"));
        sink.emit(record("b"));
        handle.drain(std::time::Duration::from_secs(5)).await;

        let m = sink.metrics();
        assert_eq!(
            m.shipped.load(std::sync::atomic::Ordering::Relaxed),
            2,
            "both records must be accounted shipped by the default backend"
        );
        assert_eq!(
            m.spilled.load(std::sync::atomic::Ordering::Relaxed),
            0,
            "a healthy endpoint must not spill"
        );
        assert_eq!(sink.dropped_total(), 0);

        // How the two records divide between POSTs is batching timing; that they all
        // arrived, once each, is not.
        let ids: Vec<String> = seen
            .lock()
            .unwrap()
            .iter()
            .flat_map(|r| {
                serde_json::from_str::<serde_json::Value>(&r.body)
                    .expect("a JSON body")
                    .as_array()
                    .expect("a batch is a JSON array")
                    .iter()
                    .map(|rec| rec["decision_id"].as_str().unwrap_or_default().to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        let mut ids = ids;
        ids.sort();
        assert_eq!(ids, vec!["a", "b"]);

        let _ = std::fs::remove_dir_all(dir);
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
