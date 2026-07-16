//! Dual-engine parity gate. Replays the golden decision corpus through
//! BOTH the embedded regorus engine and a real OPA (`opa eval`) and requires
//! identical decisions. The regorus fast path is only allowed to serve traffic
//! behind this gate.
//!
//! Runs for real in CI (where `opa` is installed). Locally, when `opa` is not on
//! PATH, it prints a skip notice and passes so `cargo test` stays green off-CI.

use std::io::Write;
use std::process::Command;

use s0::authz::{Decision, OpaInput};
use s0::pdp::{GATEWAY_REGO, Pdp, RegorusPdp};

const CORPUS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/policy/testdata/corpus.json"
));
const REGO_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/policy/gateway/authz.rego");

fn opa_available() -> bool {
    Command::new("opa")
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Normalize a decision to the comparable core: allow + obligations (order-insensitive
/// on allowed_prefixes). Reason strings are engine-formatted and excluded.
fn core(d: &Decision) -> (bool, Option<String>, Vec<String>) {
    let mut prefixes = d.obligations.allowed_prefixes.clone();
    prefixes.sort();
    (d.allow, d.obligations.narrow_prefix.clone(), prefixes)
}

fn opa_decision(bundle: &serde_json::Value, input: &serde_json::Value) -> Decision {
    let dir = std::env::temp_dir();
    let bundle_path = dir.join(format!("parity-bundle-{}.json", std::process::id()));
    let input_path = dir.join(format!("parity-input-{}.json", std::process::id()));
    std::fs::write(&bundle_path, bundle.to_string()).unwrap();
    let mut f = std::fs::File::create(&input_path).unwrap();
    f.write_all(input.to_string().as_bytes()).unwrap();

    let out = Command::new("opa")
        .args(["eval", "--format", "json", "-d", REGO_PATH, "-d"])
        .arg(&bundle_path)
        .arg("-i")
        .arg(&input_path)
        .arg("data.s0.gateway.decision")
        .output()
        .expect("run opa eval");
    assert!(
        out.status.success(),
        "opa eval failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("opa json");
    let value = &v["result"][0]["expressions"][0]["value"];
    serde_json::from_value(value.clone()).unwrap_or_else(|_| Decision::deny("opa undefined"))
}

#[tokio::test]
async fn regorus_matches_opa_over_corpus() {
    if !opa_available() {
        eprintln!("SKIP parity: `opa` not on PATH (installed in CI)");
        return;
    }
    let corpus: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
    let bundles = corpus["bundles"].as_object().unwrap();
    let cases = corpus["cases"].as_array().unwrap();

    let mut mismatches = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let bundle = &bundles[case["bundle"].as_str().unwrap()];
        let raw_input = &case["input"];
        let input: OpaInput = serde_json::from_value(raw_input.clone()).unwrap();

        let regorus = RegorusPdp::new(GATEWAY_REGO, bundle).unwrap();
        let r = regorus.decide(&input).await.unwrap();
        let o = opa_decision(bundle, raw_input);

        if core(&r) != core(&o) {
            mismatches.push(format!(
                "[{name}] regorus={:?} opa={:?}",
                core(&r),
                core(&o)
            ));
        }
    }
    assert!(
        mismatches.is_empty(),
        "dual-engine parity FAILED on {} case(s):\n  {}",
        mismatches.len(),
        mismatches.join("\n  ")
    );
}
