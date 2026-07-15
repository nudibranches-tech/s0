//! Golden decision corpus replayed through the embedded regorus engine (§4.3.1).
//! This is the executable specification of `policy/gateway/authz.rego`: every branch
//! of the grant/prefix/deny logic has a case in `policy/testdata/corpus.json`.
//!
//! The same corpus is the seed of the dual-engine parity gate — once the sidecar
//! test harness exists, OPA replays these and must produce identical decisions.

use std::collections::HashMap;

use hyperfluid_s3_gateway::authz::{Decision, OpaInput};
use hyperfluid_s3_gateway::pdp::{GATEWAY_REGO, Pdp, RegorusPdp};
use serde::Deserialize;

const CORPUS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/policy/testdata/corpus.json"
));

#[derive(Deserialize)]
struct Corpus {
    bundles: HashMap<String, serde_json::Value>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    name: String,
    bundle: String,
    input: OpaInput,
    expect: Expect,
}

#[derive(Deserialize)]
struct Expect {
    allow: bool,
    #[serde(default)]
    reason_contains: Option<String>,
    #[serde(default)]
    narrow_prefix: Option<String>,
    #[serde(default)]
    allowed_prefixes: Option<Vec<String>>,
    #[serde(default)]
    no_obligations: bool,
}

#[tokio::test]
async fn golden_corpus_matches_rego() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("parse corpus.json");

    let engines: HashMap<String, RegorusPdp> = corpus
        .bundles
        .iter()
        .map(|(name, data)| {
            (
                name.clone(),
                RegorusPdp::new(GATEWAY_REGO, data).expect("build regorus engine"),
            )
        })
        .collect();

    let mut failures = Vec::new();
    for case in &corpus.cases {
        let pdp = engines.get(&case.bundle).expect("unknown bundle in case");
        let decision: Decision = pdp.decide(&case.input).await.expect("decision");
        for f in check_case(case, &decision) {
            failures.push(f);
        }
    }

    assert!(
        failures.is_empty(),
        "{} corpus case(s) failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
}

fn check_case(case: &Case, d: &Decision) -> Vec<String> {
    let mut out = Vec::new();
    let tag = &case.name;
    if d.allow != case.expect.allow {
        out.push(format!(
            "[{tag}] allow = {} expected {} (reason: {})",
            d.allow, case.expect.allow, d.reason
        ));
        return out; // allow mismatch subsumes obligation checks
    }
    if let Some(rc) = &case.expect.reason_contains {
        if !d.reason.contains(rc.as_str()) {
            out.push(format!("[{tag}] reason {:?} does not contain {:?}", d.reason, rc));
        }
    }
    if let Some(np) = &case.expect.narrow_prefix {
        if d.obligations.narrow_prefix.as_deref() != Some(np.as_str()) {
            out.push(format!(
                "[{tag}] narrow_prefix = {:?} expected {:?}",
                d.obligations.narrow_prefix, np
            ));
        }
    }
    if let Some(ap) = &case.expect.allowed_prefixes {
        let mut got = d.obligations.allowed_prefixes.clone();
        got.sort();
        let mut want = ap.clone();
        want.sort();
        if got != want {
            out.push(format!(
                "[{tag}] allowed_prefixes = {:?} expected {:?}",
                got, want
            ));
        }
    }
    if case.expect.no_obligations
        && (d.obligations.narrow_prefix.is_some() || !d.obligations.allowed_prefixes.is_empty())
    {
        out.push(format!("[{tag}] expected no obligations, got {:?}", d.obligations));
    }
    out
}
