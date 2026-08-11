//! The drift gate: the policy, the fixtures and the producer must all be talking about the
//! same document. A hand-written fixture carrying a field the gateway never emits leaves
//! the policy correct about a request that does not exist — every rego test green while
//! production is deny-all. Four checks close that gap:
//!
//! 1. every captured document re-parses into `OpaInput` and re-serializes identically;
//! 2. captured keys are contained in `OPA_INPUT_FIELDS`;
//! 3. every `input.<path>` the shipped policy reads resolves in at least one *captured*
//!    input;
//! 4. `policy/testdata/corpus.json` may only use fields the producer is observed to emit.

use std::collections::BTreeSet;
use std::path::PathBuf;

use s0::authz::capture::round_trip;
use s0::authz::{OPA_INPUT_FIELDS, OpaInput};

const REGO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/policy/gateway/authz.rego"
));
const CORPUS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/policy/testdata/corpus.json"
));

fn captured_inputs() -> Vec<(String, serde_json::Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/captured_inputs");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("no captured corpus at {dir:?} ({e}); see golden_capture.rs"))
    {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|s| s.to_str())
            .expect("file name")
            .to_string();
        let raw = serde_json::from_str(&std::fs::read_to_string(&path).expect("read"))
            .unwrap_or_else(|e| panic!("{name} is not JSON: {e}"));
        out.push((name, raw));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    assert!(!out.is_empty(), "the captured corpus is empty");
    out
}

/// Every `input.<a>.<b>…` reference in the rego, deduplicated. Comment lines are
/// skipped: the module header documents the contract in prose and would otherwise
/// contribute references the policy does not actually evaluate.
fn rego_input_references() -> BTreeSet<String> {
    let mut refs = BTreeSet::new();
    for line in REGO.lines() {
        let code = line.split('#').next().unwrap_or("");
        let bytes = code.as_bytes();
        let mut i = 0;
        while let Some(pos) = code[i..].find("input.") {
            let start = i + pos;
            // `input` must be a whole word, not the tail of `some_input.`
            let preceded_by_ident =
                start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'_');
            i = start + "input.".len();
            if preceded_by_ident {
                continue;
            }
            let mut end = i;
            while end < bytes.len()
                && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_' || bytes[end] == b'.')
            {
                end += 1;
            }
            let path = code[start + "input.".len()..end].trim_end_matches('.');
            if !path.is_empty() {
                refs.insert(path.to_string());
            }
            i = end;
        }
    }
    assert!(
        !refs.is_empty(),
        "no input references found in the rego — the extractor is broken, which would \
         make this whole file vacuous"
    );
    refs
}

fn resolve<'a>(doc: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    path.split('.').try_fold(doc, |v, seg| v.get(seg))
}

/// Every key present in a document, as dotted paths one level deep into objects — the
/// depth the rego actually reaches.
fn field_paths(doc: &serde_json::Value, out: &mut BTreeSet<String>) {
    let Some(obj) = doc.as_object() else { return };
    for (k, v) in obj {
        out.insert(k.clone());
        if let Some(inner) = v.as_object() {
            for ik in inner.keys() {
                out.insert(format!("{k}.{ik}"));
            }
        }
    }
}

#[test]
fn every_captured_input_round_trips_through_opa_input() {
    for (name, raw) in captured_inputs() {
        round_trip(&raw).unwrap_or_else(|e| {
            panic!(
                "{name} does not round-trip.\n{e}\n\
                 A captured document that the type cannot reproduce means the wire shape \
                 and `OpaInput` have diverged. Do NOT re-record the corpus to make this \
                 pass — find which field moved."
            )
        });
    }
}

#[test]
fn the_captured_corpus_uses_only_declared_fields() {
    let mut seen = BTreeSet::new();
    for (_, raw) in captured_inputs() {
        for key in raw.as_object().expect("an object").keys() {
            seen.insert(key.clone());
        }
    }
    for key in &seen {
        assert!(
            OPA_INPUT_FIELDS.contains(&key.as_str()),
            "the gateway emits {key:?}, which is not in OPA_INPUT_FIELDS"
        );
    }
    // The reverse is deliberately NOT asserted: `object_tags` and `delete_keys` are
    // legitimately absent from every capture, so requiring full coverage would force
    // either fictional captures or deleting fields the contract needs.
    assert!(
        seen.contains("principal") && seen.contains("action") && seen.contains("bucket"),
        "the corpus is missing the fields every decision turns on: {seen:?}"
    );
}

#[test]
fn every_rego_input_reference_appears_in_a_captured_input() {
    // THE test. A policy that reads a field no producer sends evaluates to undefined,
    // and `default allow := false` turns that into a silent deny-all — with every
    // hand-written fixture still green, because the fixtures were written to match the
    // policy rather than the producer.
    let captured = captured_inputs();
    let mut unsatisfied = Vec::new();
    for path in rego_input_references() {
        let satisfied = captured
            .iter()
            .any(|(_, raw)| resolve(raw, &path).is_some_and(|v| !v.is_null()));
        if !satisfied {
            unsatisfied.push(path);
        }
    }
    assert!(
        unsatisfied.is_empty(),
        "the shipped policy reads {unsatisfied:?}, which the gateway has never been \
         observed to emit. Either the producer stopped sending it (the field was renamed \
         or dropped) or the policy invented it. This is the shape of the deny-all bug: \
         every rule that depends on such a reference is permanently undefined."
    );
}

#[test]
fn the_hand_written_corpus_matches_the_captured_wire_shape() {
    // `policy/testdata/corpus.json` is hand-authored — it encodes *expected decisions* for
    // bundles the gateway has never run against. What it may not do is invent input fields:
    // each case must parse and may only use fields observed in a real capture.
    let mut observed = BTreeSet::new();
    for (_, raw) in captured_inputs() {
        field_paths(&raw, &mut observed);
    }

    let corpus: serde_json::Value = serde_json::from_str(CORPUS).expect("parse corpus.json");
    let cases = corpus["cases"].as_array().expect("cases array");
    assert!(!cases.is_empty());
    for case in cases {
        let name = case["name"].as_str().unwrap_or("?");
        let raw = &case["input"];
        serde_json::from_value::<OpaInput>(raw.clone())
            .unwrap_or_else(|e| panic!("corpus case {name:?} is not a valid OpaInput: {e}"));
        // The corpus must also round-trip: `tests/parity.rs` feeds BOTH engines the
        // re-serialized value, so a normalization change would leave regorus and OPA
        // agreeing with each other while both disagree with the gateway. Spell the case
        // out in full rather than relaxing this.
        round_trip(raw).unwrap_or_else(|e| panic!("corpus case {name:?}: {e}"));
        let mut used = BTreeSet::new();
        field_paths(raw, &mut used);
        let invented: Vec<&String> = used.difference(&observed).collect();
        assert!(
            invented.is_empty(),
            "corpus case {name:?} uses {invented:?}, which no captured input contains — \
             a fixture field the producer does not emit is exactly the `input.op` failure"
        );
    }
}

#[test]
fn the_reference_extractor_would_catch_an_invented_field() {
    // A guard on the guard. If `rego_input_references` silently stopped finding
    // references, `every_rego_input_reference_appears_in_a_captured_input` would pass
    // over an empty set and the whole file would be theatre.
    let refs = rego_input_references();
    for expected in ["action", "bucket", "principal.sub", "object", "prefix"] {
        assert!(
            refs.contains(expected),
            "the extractor missed input.{expected}, which the shipped rego plainly reads: \
             {refs:?}"
        );
    }
    // And it must not be fooled by prose in comments.
    assert!(
        !refs.contains("op"),
        "the shipped policy references input.op — the field the previous attempt's \
         fixtures injected and no producer ever sent"
    );
}
