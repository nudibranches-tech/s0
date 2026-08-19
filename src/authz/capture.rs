//! Golden capture — what makes a policy fixture a *record* of what the gateway emits
//! rather than a guess at it. A fixture written by hand can carry fields no producer
//! sends, leaving the policy correct about a request that does not exist.
//!
//! The tap sits at [`crate::access::GatewayAccess::decide`], the sole caller of
//! `Pdp::decide` on the request path, so it sees both halves of a copy and every key of
//! a multi-delete. It records the emitted `&OpaInput`, and [`round_trip`] re-checks it
//! at record time so a renamed or dropped field cannot reach a fixture. A sink retains
//! principal identifiers and object keys, so it is reachable only through
//! [`crate::gateway::Gateway::capture`], which `Gateway::build` always sets to `None`.

use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;

use super::OpaInput;

/// One authorization question exactly as it was handed to the PDP.
#[derive(Debug, Clone)]
pub struct CapturedInput {
    /// `<operation>-<12 hex of the sha256 of the canonical JSON>`. Deterministic, so
    /// re-capturing the same wire shape yields the same id and a corpus reference does
    /// not churn on every run.
    pub id: String,
    /// The s3s operation name the request resolved to. Not a field of `OpaInput`, so it
    /// is captured alongside: "which op emitted this?" is the first question a corpus
    /// reader has.
    pub operation: String,
    /// The emitted document. Never rebuilt from parts.
    pub raw: Value,
    /// `Some` when this document does not survive [`round_trip`]. Recorded rather than
    /// panicked so the harness can report *every* offender in one run.
    pub round_trip_error: Option<String>,
}

/// The round-trip gate: `to_value(from_value::<OpaInput>(raw)?) == raw`.
///
/// Catches a field the producer emits and the type no longer has, or vice versa. It only
/// works because [`OpaInput`] and its nested structs carry
/// `#[serde(deny_unknown_fields)]` — otherwise an extra key parses, vanishes on the way
/// back out, and the comparison holds.
pub fn round_trip(raw: &Value) -> Result<(), String> {
    let typed: OpaInput = serde_json::from_value(raw.clone())
        .map_err(|e| format!("captured input does not parse back into OpaInput: {e}"))?;
    let back = serde_json::to_value(&typed).map_err(|e| format!("re-serialize: {e}"))?;
    if back == *raw {
        return Ok(());
    }
    Err(format!(
        "round-trip changed the document — the emitted wire shape and OpaInput disagree\n  \
         emitted:       {raw}\n  re-serialized: {back}"
    ))
}

/// Collects captured inputs for the duration of a test run. Bounded so a runaway
/// harness drops records loudly instead of growing without limit.
#[derive(Debug)]
pub struct CaptureSink {
    records: Mutex<Vec<CapturedInput>>,
    capacity: usize,
    dropped: AtomicUsize,
    round_trip_failures: AtomicUsize,
}

impl CaptureSink {
    #[must_use]
    pub fn new(capacity: usize) -> Self {
        CaptureSink {
            records: Mutex::new(Vec::new()),
            capacity,
            dropped: AtomicUsize::new(0),
            round_trip_failures: AtomicUsize::new(0),
        }
    }

    /// Record the document about to be handed to the PDP.
    ///
    /// `pub(crate)` so the only producer is the tap in `GatewayAccess::decide`: a test
    /// able to push a hand-made document into the sink would reintroduce the class of
    /// fixture this module exists to abolish.
    pub(crate) fn record(&self, operation: &str, input: &OpaInput) {
        let raw = match serde_json::to_value(input) {
            Ok(v) => v,
            Err(e) => {
                // An OpaInput that will not serialize cannot have reached the PDP
                // either, so this is a defect, not a capture problem.
                tracing::error!(%e, "capture: OpaInput failed to serialize");
                self.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        let round_trip_error = round_trip(&raw).err();
        if round_trip_error.is_some() {
            self.round_trip_failures.fetch_add(1, Ordering::Relaxed);
        }
        let id = format!("{operation}-{}", &digest(&raw)[..12]);
        let mut records = self.records.lock().expect("capture sink poisoned");
        if records.len() >= self.capacity {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        records.push(CapturedInput {
            id,
            operation: operation.to_string(),
            raw,
            round_trip_error,
        });
    }

    /// Everything captured so far, in emission order.
    #[must_use]
    pub fn snapshot(&self) -> Vec<CapturedInput> {
        self.records.lock().expect("capture sink poisoned").clone()
    }

    /// Captured inputs deduplicated by [`CapturedInput::id`] and sorted by it — the
    /// form a checked-in corpus takes, so a re-run produces the same files.
    #[must_use]
    pub fn corpus(&self) -> Vec<CapturedInput> {
        let mut seen = std::collections::BTreeMap::new();
        for r in self.snapshot() {
            seen.entry(r.id.clone()).or_insert(r);
        }
        seen.into_values().collect()
    }

    /// Records that never made it into the sink (serialization failure, or the
    /// capacity bound). A corpus built while this is non-zero is incomplete.
    #[must_use]
    pub fn dropped(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Captured documents that do not survive [`round_trip`]. Must be zero.
    #[must_use]
    pub fn round_trip_failures(&self) -> usize {
        self.round_trip_failures.load(Ordering::Relaxed)
    }
}

/// Hex sha256 over the canonical JSON encoding. `serde_json::Map` is a `BTreeMap` here
/// (the `preserve_order` feature is off), so `to_string` is key-sorted and the digest is
/// stable across runs and across machines.
fn digest(v: &Value) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(v.to_string().as_bytes());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authz::{Backend, Principal, PrincipalAttributes, RequestMeta};
    use crate::model::{Action, BackendKind, PrincipalType};

    fn input() -> OpaInput {
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
        }
    }

    #[test]
    fn a_real_emitted_input_round_trips() {
        let raw = serde_json::to_value(input()).unwrap();
        round_trip(&raw).expect("what the gateway emits must parse back into what emits it");
    }

    #[test]
    fn an_injected_field_fails_the_round_trip() {
        // A field no producer ever sends: exactly what the gate exists to catch.
        let mut raw = serde_json::to_value(input()).unwrap();
        raw.as_object_mut()
            .unwrap()
            .insert("op".into(), serde_json::json!("GetObject"));
        let err = round_trip(&raw).expect_err("an injected field must fail the gate");
        assert!(err.contains("op"), "{err}");
    }

    #[test]
    fn a_dropped_field_fails_the_round_trip() {
        // The other direction: a document missing a field the type serializes
        // unconditionally. `from_value` fills nothing in for `bucket`, so this is
        // caught as a parse failure rather than a silent default.
        let mut raw = serde_json::to_value(input()).unwrap();
        raw.as_object_mut().unwrap().remove("bucket");
        assert!(round_trip(&raw).is_err());
    }

    #[test]
    fn capture_ids_are_deterministic_and_shape_sensitive() {
        let sink = CaptureSink::new(16);
        sink.record("GetObject", &input());
        sink.record("GetObject", &input());
        let mut other = input();
        other.object = Some("2024/q2.csv".into());
        sink.record("GetObject", &other);

        assert_eq!(sink.snapshot().len(), 3);
        assert_eq!(sink.round_trip_failures(), 0);
        assert_eq!(sink.dropped(), 0);
        // Two identical emissions collapse to one corpus entry; a different key does
        // not — a corpus that collapsed distinct questions would hide coverage gaps.
        let corpus = sink.corpus();
        assert_eq!(corpus.len(), 2, "{:?}", corpus);
        assert!(corpus.iter().all(|c| c.id.starts_with("GetObject-")));
    }

    #[test]
    fn the_sink_is_bounded_and_says_so() {
        let sink = CaptureSink::new(2);
        for _ in 0..5 {
            sink.record("GetObject", &input());
        }
        assert_eq!(sink.snapshot().len(), 2);
        assert_eq!(sink.dropped(), 3, "a truncated corpus must be visible");
    }
}
