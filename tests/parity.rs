//! Dual-engine parity gate. Replays the golden decision corpus through
//! BOTH the embedded regorus engine and a real OPA (`opa eval`) and requires
//! identical decisions. The regorus fast path is only allowed to serve traffic
//! behind this gate.
//!
//! ## The gate must not be able to pass by accident
//!
//! This file used to `return` green whenever `opa` was not on `PATH`. On a machine
//! without `opa` — which was every developer machine — the single check licensing the
//! embedded engine reported success without ever running. So:
//!
//! - a missing oracle is a **hard failure**, not a skip. Opting out is explicit and
//!   loud ([`ALLOW_NO_OPA`]), and the opt-out is never set in CI;
//! - the oracle's **version** is pinned to the one production runs
//!   ([`EXPECTED_OPA_VERSION`]) and cross-checked against every file that installs it,
//!   by [`the_opa_oracle_is_pinned_to_the_production_version_everywhere`], which needs
//!   no `opa` and therefore always runs.
//!
//! The version is not cosmetic. OPA ≥ 1.0 parses rego **v1**; 0.x parses **v0**. The
//! previous CI pin (`0.70.0`) was answering v0 questions about a policy production
//! evaluates as v1 — a different oracle, not a weaker one (plan §0.1 C-6).

use std::io::Write;
use std::process::Command;

use s0::authz::{Decision, OpaInput};
use s0::pdp::{GATEWAY_REGO, Pdp, RegorusPdp};

const CORPUS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/policy/testdata/corpus.json"
));
const REGO_PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/policy/gateway/authz.rego");

/// The `opa` build this gate is allowed to trust as an oracle: the version the
/// platform actually deploys (`openpolicyagent/opa:1.13.1`). Changing it means
/// changing `.github/workflows/ci.yml` and `e2e/docker-compose.yml` in the same
/// commit — enforced below.
const EXPECTED_OPA_VERSION: &str = "1.13.1";

/// Explicit, documented opt-out for a machine with no `opa`. Set it to `1` and the
/// gate degrades to "regorus alone", which is exactly the state this milestone is
/// meant to abolish — so it prints why on the way past, and CI never sets it.
const ALLOW_NO_OPA: &str = "S0_ALLOW_NO_OPA";

/// The oracle's version string (`Version: x.y.z` on the first line of `opa version`),
/// or `None` when `opa` cannot be run at all.
fn opa_version() -> Option<String> {
    let out = Command::new("opa").arg("version").output().ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.strip_prefix("Version:"))
        .map(|v| v.trim().to_string())
}

/// Resolve the oracle, or explain — at the top of a panic — exactly what is not being
/// checked. `None` means the caller opted out and the parity comparison is skipped.
fn require_opa() -> Option<String> {
    let Some(version) = opa_version() else {
        assert!(
            std::env::var(ALLOW_NO_OPA).as_deref() == Ok("1"),
            "the dual-engine parity gate has no oracle: `opa` is not on PATH.\n\
             This test is the ONLY check that licenses the embedded regorus engine to \
             serve traffic; passing it without an oracle would assert nothing.\n\
             Install OPA {EXPECTED_OPA_VERSION} (see CONTRIBUTING.md), or run with \
             {ALLOW_NO_OPA}=1 to acknowledge that regorus is going unverified."
        );
        eprintln!(
            "SKIP parity: `opa` absent and {ALLOW_NO_OPA}=1 — the embedded engine is \
             UNVERIFIED in this run"
        );
        return None;
    };

    // The dialect is the load-bearing half of the pin. A 0.x oracle parses rego v0 and
    // would happily agree with regorus about a policy neither is reading the way
    // production does.
    let major: u32 = version
        .split('.')
        .next()
        .and_then(|m| m.parse().ok())
        .unwrap_or_else(|| panic!("cannot parse an OPA major version from {version:?}"));
    assert!(
        major >= 1,
        "opa {version} parses rego v0; production runs opa {EXPECTED_OPA_VERSION} \
         (rego v1). A v0 oracle is a different gate, not a weaker one — plan §0.1 C-6."
    );
    if version != EXPECTED_OPA_VERSION {
        eprintln!(
            "WARNING parity: local opa {version} != the pinned oracle \
             {EXPECTED_OPA_VERSION}; same dialect, so the gate still runs, but CI is \
             the authority."
        );
    }
    Some(version)
}

/// Normalize a decision to the comparable core: allow + **every** obligation
/// (order-insensitive on the two set-valued ones, which the PEP sorts anyway). Reason
/// strings are engine-formatted and excluded.
///
/// Every obligation has to be in here. An obligation the two engines could disagree
/// about without this gate noticing is an obligation the gate does not cover — and for
/// `visible_buckets` a disagreement is a difference in which buckets a principal is shown.
fn core(d: &Decision) -> (bool, Option<String>, Vec<String>, Vec<String>, bool) {
    let mut prefixes = d.obligations.allowed_prefixes.clone();
    prefixes.sort();
    let mut buckets = d.obligations.visible_buckets.clone();
    buckets.sort();
    (
        d.allow,
        d.obligations.narrow_prefix.clone(),
        prefixes,
        buckets,
        d.obligations.all_buckets_visible,
    )
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
        .arg("data.s3.authz.decision")
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
    let Some(version) = require_opa() else { return };
    eprintln!("parity oracle: opa {version}");
    let corpus: serde_json::Value = serde_json::from_str(CORPUS).unwrap();
    let bundles = corpus["bundles"].as_object().unwrap();
    let cases = corpus["cases"].as_array().unwrap();

    assert!(!cases.is_empty(), "the parity corpus is empty");

    let mut mismatches = Vec::new();
    let mut opa_allowed = 0usize;
    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let bundle = &bundles[case["bundle"].as_str().unwrap()];
        let raw_input = &case["input"];
        let input: OpaInput = serde_json::from_value(raw_input.clone())
            .unwrap_or_else(|e| panic!("[{name}] corpus input is not an OpaInput: {e}"));
        // Feed BOTH engines the same bytes. Previously regorus got the typed value and
        // OPA got the raw JSON, so a field the type silently dropped or renamed would
        // change what one engine saw and not the other — a parity gate that is not
        // comparing engines. `tests/fixture_drift.rs` is the rename guard that this
        // symmetry gives up; the two must land together.
        let normalized = serde_json::to_value(&input).expect("serialize OpaInput");

        let regorus = RegorusPdp::new(GATEWAY_REGO, bundle).unwrap();
        let r = regorus.decide(&input).await.unwrap();
        let o = opa_decision(bundle, &normalized);
        opa_allowed += usize::from(o.allow);

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
    // The oracle must have *evaluated* something. `opa_decision` degrades an
    // undefined result to a deny, so if the entrypoint path ever stops resolving —
    // `data.s3.authz.decision` moves, or the module's `package` line does — every case
    // would answer deny and parity would hold trivially against a regorus that is
    // denying for real reasons. That failure is invisible without this line.
    // `cross_repo_contract.rs` is the other half: it holds this name equal to the one
    // the platform actually ships.
    assert!(
        opa_allowed > 0,
        "opa allowed 0 of {} corpus cases: the oracle is answering `undefined`, most \
         likely because the decision entrypoint no longer resolves",
        cases.len()
    );
}

/// Every place that installs the oracle names [`EXPECTED_OPA_VERSION`].
///
/// This is the half of the fix that runs without `opa` and therefore runs everywhere.
/// The original defect was not that the pin was wrong — it was that nothing related
/// the pin to anything, so `0.70.0` sat next to a production `1.13.1` for as long as
/// nobody happened to look.
#[test]
fn the_opa_oracle_is_pinned_to_the_production_version_everywhere() {
    let ci = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/ci.yml"
    ));
    let compose = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/e2e/docker-compose.yml"
    ));

    // CI: the `version:` belonging to the setup-opa step, not any other `version:`.
    let lines: Vec<&str> = ci.lines().collect();
    let step = lines
        .iter()
        .position(|l| l.contains("open-policy-agent/setup-opa"))
        .expect("ci.yml no longer installs OPA — the parity gate would skip in CI too");
    let pin = lines[step..step + 5]
        .iter()
        .find_map(|l| l.trim().strip_prefix("version:"))
        .expect("the setup-opa step pins no version — it would float");
    assert_eq!(
        pin.trim().trim_matches('"'),
        EXPECTED_OPA_VERSION,
        "ci.yml installs a different OPA than the parity gate expects"
    );

    // The e2e stack's sidecar OPA is the same oracle in a different costume; a v0
    // image there means the real-stack suite is exercising a dialect production does
    // not run.
    let image = compose
        .lines()
        .find_map(|l| l.trim().strip_prefix("image: openpolicyagent/opa:"))
        .expect("e2e/docker-compose.yml no longer runs an OPA sidecar");
    assert!(
        image.starts_with(EXPECTED_OPA_VERSION),
        "e2e docker-compose runs openpolicyagent/opa:{image}, but the pinned oracle is \
         {EXPECTED_OPA_VERSION}"
    );
}
