//! Golden decision corpus replayed through the embedded regorus engine.
//! This is the executable specification of `policy/gateway/authz.rego`: every branch
//! of the grant/prefix/deny logic has a case in `policy/testdata/corpus.json`.
//!
//! `tests/parity.rs` replays the same corpus through a real OPA and requires identical
//! decisions.

use std::collections::HashMap;

use s0::authz::{Decision, OpaInput};
use s0::pdp::{BucketPlacement, GATEWAY_REGO, Pdp, RegorusPdp};
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
    /// `ListBuckets`. Asserted as a **set**, and `Some(vec![])` is a real assertion —
    /// "allowed to enumerate, nothing visible" is a distinct outcome from "denied", and
    /// the corpus has to be able to say so.
    #[serde(default)]
    visible_buckets: Option<Vec<String>>,
    #[serde(default)]
    all_buckets_visible: Option<bool>,
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

/// The reasons the default policy gives for refusing on placement. Each names the layer
/// that refused, as the gateway's own refusal does.
const PLACEMENT_REASONS: [&str; 4] = [
    "deny: bucket belongs to another tenant",
    "deny: bucket not on this backend",
    "deny: bundle projected for another backend",
    "deny: bundle grant_schema_version is not a number",
];

/// Default-policy parity with the gateway (ADR-009): for every corpus case, the default
/// module refuses on placement exactly when the gateway's own pre-PDP screen would, so a
/// data-only v3 bundle is safe whichever of the two looks first.
///
/// The gateway screen is asked the way `GatewayAccess::decide` asks it: the decision's
/// bucket, then a copy's source, against the backend the decision names.
#[tokio::test]
async fn default_policy_refuses_on_placement_exactly_when_the_gateway_does() {
    let corpus: Corpus = serde_json::from_str(CORPUS).expect("parse corpus.json");

    let mut failures = Vec::new();
    let mut gateway_refusals = 0usize;
    for case in &corpus.cases {
        let data = corpus
            .bundles
            .get(&case.bundle)
            .expect("unknown bundle in case");
        let placement = BucketPlacement::from_data(data);
        let input = &case.input;
        let refusal = placement
            .refusal(&input.backend.id, &input.tenant, &input.bucket)
            .or_else(|| {
                let source = input.copy_source.as_ref()?;
                placement.refusal(&input.backend.id, &input.tenant, &source.bucket)
            });
        let pdp = RegorusPdp::new(GATEWAY_REGO, data).expect("build regorus engine");
        let decision = pdp.decide(input).await.expect("decision");
        let rego_refused = PLACEMENT_REASONS.contains(&decision.reason.as_str());

        match (&refusal, rego_refused) {
            (Some(why), false) => failures.push(format!(
                "[{}] the gateway refuses ({why:?}) but the default policy answers \
                 allow={} reason={:?}",
                case.name, decision.allow, decision.reason
            )),
            (None, true) => failures.push(format!(
                "[{}] the default policy refuses on placement ({:?}) but the gateway does not",
                case.name, decision.reason
            )),
            (Some(_), true) if decision.allow => {
                failures.push(format!("[{}] a placement reason on an allow", case.name));
            }
            _ => {}
        }
        gateway_refusals += usize::from(refusal.is_some());
    }

    assert!(
        failures.is_empty(),
        "{} case(s) where the default policy and the gateway disagree on placement:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    // Over a corpus with no placing bundle this would hold vacuously.
    assert!(
        gateway_refusals >= 5,
        "only {gateway_refusals} corpus case(s) are refused on placement; the v3 cases are \
         missing"
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
    if let Some(rc) = &case.expect.reason_contains
        && !d.reason.contains(rc.as_str())
    {
        out.push(format!(
            "[{tag}] reason {:?} does not contain {:?}",
            d.reason, rc
        ));
    }
    if let Some(np) = &case.expect.narrow_prefix
        && d.obligations.narrow_prefix.as_deref() != Some(np.as_str())
    {
        out.push(format!(
            "[{tag}] narrow_prefix = {:?} expected {:?}",
            d.obligations.narrow_prefix, np
        ));
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
    if let Some(vb) = &case.expect.visible_buckets {
        let mut got = d.obligations.visible_buckets.clone();
        got.sort();
        let mut want = vb.clone();
        want.sort();
        if got != want {
            out.push(format!(
                "[{tag}] visible_buckets = {got:?} expected {want:?}"
            ));
        }
    }
    if let Some(all) = case.expect.all_buckets_visible
        && d.obligations.all_buckets_visible != all
    {
        out.push(format!(
            "[{tag}] all_buckets_visible = {} expected {all}",
            d.obligations.all_buckets_visible
        ));
    }
    if case.expect.no_obligations
        && (d.obligations.narrow_prefix.is_some()
            || !d.obligations.allowed_prefixes.is_empty()
            || !d.obligations.visible_buckets.is_empty()
            || d.obligations.all_buckets_visible)
    {
        out.push(format!(
            "[{tag}] expected no obligations, got {:?}",
            d.obligations
        ));
    }
    out
}
