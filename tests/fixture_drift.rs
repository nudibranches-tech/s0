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
//!
//! The same argument runs the other way for the **bundle**, whose producer is the control
//! plane: the v3 fixture must carry every field the gateway reads from a placing bundle,
//! in the shape it reads it, and be the v2 capture plus exactly those fields — so the
//! placement is tested against the document the projection is pinned to, not against one
//! written to suit the reader.

use std::collections::BTreeSet;
use std::path::PathBuf;

use s0::authz::capture::round_trip;
use s0::authz::{OPA_INPUT_FIELDS, OpaInput};
use s0::model::BackendKind;
use s0::pdp::{
    BACKEND_FIELD, BUCKET_ATTRIBUTES_FIELD, BucketPlacement, CREATED_AT_FIELD,
    GRANT_SCHEMA_VERSION_FIELD, OBJECT_NAME_FIELD, PLACEMENT_SCHEMA_VERSION, parse_bundle,
};

const REGO: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/policy/gateway/authz.rego"
));
const CORPUS: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/policy/testdata/corpus.json"
));
/// The control plane's v2 document, captured verbatim (see `tests/external_bundle.rs`).
const V2_BUNDLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/platform/s3_gateway_bundle.json"
));
/// The v3 document, written by hand from the pinned contract: the v2 capture filtered to
/// one `s3` backend (`archive`), with bucket attributes and grants keyed by S3 name, and
/// the v3 fields added. It is the data half only; the module arrives with the control
/// plane's own capture of a v3 projection, which replaces this file and must still pass
/// every check below.
const V3_BUNDLE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/platform/s3_gateway_bundle_v3.json"
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

// ── the bundle: v3 is the v2 document plus the placement ────────────────────────

fn bundle_data(raw: &str) -> serde_json::Value {
    parse_bundle(raw).expect("the fixture parses").data
}

fn keys(v: &serde_json::Value) -> BTreeSet<String> {
    v.as_object()
        .unwrap_or_else(|| panic!("expected an object, got {v}"))
        .keys()
        .cloned()
        .collect()
}

fn set(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|s| (*s).to_string()).collect()
}

fn assert_rfc3339(label: &str, v: &serde_json::Value) {
    let s = v
        .as_str()
        .unwrap_or_else(|| panic!("{label} must be an RFC 3339 string, got {v}"));
    chrono::DateTime::parse_from_rfc3339(s)
        .unwrap_or_else(|e| panic!("{label} = {s:?} is not RFC 3339: {e}"));
}

/// `{ limit_bytes: u64, used_bytes: u64, collected_at: RFC 3339 }`, and nothing else.
fn assert_quota_shape(label: &str, quota: &serde_json::Value) {
    assert_eq!(
        keys(quota),
        set(&["limit_bytes", "used_bytes", "collected_at"]),
        "{label}"
    );
    for field in ["limit_bytes", "used_bytes"] {
        assert!(
            quota[field].as_u64().is_some(),
            "{label}.{field} must be an unsigned integer, got {}",
            quota[field]
        );
    }
    assert_rfc3339(&format!("{label}.collected_at"), &quota["collected_at"]);
}

/// Every field the gateway reads from a placing bundle is present, in the shape it reads
/// it, and the placement built from it places every bucket under its own tenant.
#[test]
fn the_v3_fixture_carries_every_field_the_placement_reads() {
    let data = bundle_data(V3_BUNDLE);
    assert_eq!(
        data[GRANT_SCHEMA_VERSION_FIELD].as_u64(),
        Some(PLACEMENT_SCHEMA_VERSION),
        "the v3 fixture must be a placing document"
    );
    let backend = &data[BACKEND_FIELD];
    assert_eq!(
        keys(backend),
        set(&["id", "kind"]),
        "data.backend is {{id, kind}}"
    );
    let backend_id = backend["id"].as_str().expect("data.backend.id is a string");
    assert!(!backend_id.is_empty());
    let kind = backend["kind"]
        .as_str()
        .expect("data.backend.kind is a string");
    assert!(
        ["ceph", "s3"].contains(&kind),
        "data.backend.kind is the canonical spelling, never the 0.3.x alias: {kind:?}"
    );
    serde_json::from_value::<BackendKind>(backend["kind"].clone())
        .expect("data.backend.kind is a backend kind this gateway knows");

    let placement = BucketPlacement::from_data(&data);
    assert!(
        matches!(placement, BucketPlacement::Placed(_)),
        "the v3 fixture does not build a placement: {placement:?}"
    );
    let mut total = 0;
    for (tenant, tenant_data) in data["tenants"].as_object().expect("tenants") {
        let buckets = tenant_data[BUCKET_ATTRIBUTES_FIELD]
            .as_object()
            .unwrap_or_else(|| panic!("{tenant} has no {BUCKET_ATTRIBUTES_FIELD}"));
        for (bucket, attrs) in buckets {
            let label = format!("tenants.{tenant}.{BUCKET_ATTRIBUTES_FIELD}.{bucket}");
            let object_name = attrs[OBJECT_NAME_FIELD]
                .as_str()
                .unwrap_or_else(|| panic!("{label}.{OBJECT_NAME_FIELD} must be a string"));
            assert!(
                object_name == bucket || object_name == format!("{bucket}.{backend_id}"),
                "{label}: the object name is the S3 name, or `<S3 name>.<backend>` off the \
                 default backend; got {object_name:?}"
            );
            assert_rfc3339(
                &format!("{label}.{CREATED_AT_FIELD}"),
                &attrs[CREATED_AT_FIELD],
            );
            if let Some(quota) = attrs.get("quota") {
                assert_quota_shape(&format!("{label}.quota"), quota);
            }
            assert_eq!(
                placement.refusal(backend_id, tenant, bucket),
                None,
                "{label} is not usable by its own tenant"
            );
            assert_eq!(placement.object_name(bucket), Some(object_name), "{label}");
            total += 1;
        }
        let listed: BTreeSet<String> = placement
            .listing(backend_id, tenant)
            .expect("placed")
            .into_iter()
            .map(|b| {
                assert!(b.created_at.is_some(), "{tenant}/{} lost its date", b.name);
                b.name
            })
            .collect();
        assert_eq!(
            listed,
            keys(&tenant_data[BUCKET_ATTRIBUTES_FIELD]),
            "{tenant}"
        );
        if let Some(quota) = tenant_data.get("quota") {
            assert_quota_shape(&format!("tenants.{tenant}.quota"), quota);
        }
    }
    assert!(
        total >= 2,
        "the fixture must place buckets under more than one tenant"
    );
    if let Some(quota) = data.get("backend_quota") {
        assert_quota_shape("backend_quota", quota);
    }

    // The data half only, so it is recognized as a platform document missing its module.
    assert!(
        parse_bundle(V3_BUNDLE)
            .expect("parses")
            .is_platform_data_missing_its_module()
    );
}

/// v3 is backward compatible: the v2 document with the same shape everywhere, plus the
/// v3 fields and nothing else. A field renamed or dropped on the way is what this catches.
#[test]
fn the_v3_fixture_is_the_v2_capture_plus_the_v3_fields() {
    let v2 = bundle_data(V2_BUNDLE);
    let v3 = bundle_data(V3_BUNDLE);

    let mut expected = keys(&v2);
    expected.extend(set(&[BACKEND_FIELD, "backend_quota"]));
    assert_eq!(keys(&v3), expected, "top-level data keys");
    assert_eq!(keys(&v2["org_settings"]), keys(&v3["org_settings"]));
    assert_eq!(
        keys(&v2["tenants"]),
        keys(&v3["tenants"]),
        "the same tenants"
    );

    let v2_bucket_keys: BTreeSet<String> = v2["tenants"]
        .as_object()
        .expect("tenants")
        .values()
        .flat_map(|t| t[BUCKET_ATTRIBUTES_FIELD].as_object().into_iter().flatten())
        .flat_map(|(_, attrs)| keys(attrs))
        .collect();
    let mut allowed_bucket_keys = v2_bucket_keys.clone();
    allowed_bucket_keys.extend(set(&[OBJECT_NAME_FIELD, CREATED_AT_FIELD, "quota"]));

    for (tenant, t3) in v3["tenants"].as_object().expect("tenants") {
        let t2 = &v2["tenants"][tenant];
        let mut tenant_keys = keys(t2);
        let v3_only: BTreeSet<String> = keys(t3).difference(&tenant_keys).cloned().collect();
        assert!(
            v3_only.is_subset(&set(&["quota"])),
            "{tenant} gained {v3_only:?}, which the contract does not pin"
        );
        tenant_keys.extend(v3_only);
        assert_eq!(keys(t3), tenant_keys, "{tenant} lost a v2 field");
        // What v3 does not touch is byte-identical.
        for field in ["user_attributes", "group_grants", "s3_key_epoch"] {
            assert_eq!(t2[field], t3[field], "{tenant}.{field}");
        }
        for (bucket, attrs) in t3[BUCKET_ATTRIBUTES_FIELD].as_object().expect("buckets") {
            let k = keys(attrs);
            assert!(
                k.is_subset(&allowed_bucket_keys) && k.contains("denylist"),
                "{tenant}/{bucket} has keys {k:?}; allowed are {allowed_bucket_keys:?}"
            );
        }
        for field in ["s3_grants", "s3_deny"] {
            assert_eq!(
                keys(&t2[field]),
                keys(&t3[field]),
                "{tenant}.{field} subjects"
            );
        }
    }
}

/// Grant scopes are projected from object names to S3 names: every bucket a v3 grant
/// names is an S3 name its own tenant has on this backend (or `*`). A grant still naming
/// an object name would match nothing the gateway lets through.
#[test]
fn every_grant_in_the_v3_fixture_names_its_tenants_s3_name() {
    let v3 = bundle_data(V3_BUNDLE);
    for (tenant, t) in v3["tenants"].as_object().expect("tenants") {
        let owned = keys(&t[BUCKET_ATTRIBUTES_FIELD]);
        for field in ["s3_grants", "s3_deny", "group_grants"] {
            for (subject, grants) in t[field].as_object().expect("grant map") {
                for grant in grants.as_array().expect("grant list") {
                    let bucket = grant["bucket"].as_str().expect("grant bucket");
                    assert!(
                        bucket == "*" || owned.contains(bucket),
                        "{tenant}.{field}.{subject} names {bucket:?}, not an S3 name of \
                         {tenant} on this backend ({owned:?})"
                    );
                }
            }
        }
    }
}
