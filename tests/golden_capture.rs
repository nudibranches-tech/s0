//! The golden-capture harness: the corpus in `tests/data/captured_inputs/` is a
//! **recording** of what the gateway emits, not a description of it.
//!
//! Why this file exists is on record. The previous attempt had 35 green rego tests
//! while production authorized nothing, because every fixture injected an `input.op`
//! field the real producer never sent. Hand-written fixtures make the policy correct
//! about a request that does not exist. So:
//!
//! - every fixture here comes out of `GatewayAccess::decide` — the single funnel every
//!   PDP question passes through — driven by the real typed hooks;
//! - every captured document must survive the round-trip gate
//!   (`to_value(from_value::<OpaInput>(raw)?) == raw`), which is what actually catches a
//!   renamed or dropped field;
//! - every `Coverage::Enforced` operation must contribute at least one capture, so an
//!   op cannot be enforced and unrepresented in the corpus.
//!
//! Regenerate with `S0_CAPTURE_REGENERATE=1 cargo test --test golden_capture`. Read the
//! resulting diff as a wire-contract change: it is the artifact a policy reviewer needs.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use s0::access::GatewayAccess;
use s0::access::optable::enforced_ops;
use s0::authz::capture::round_trip;
use s3s::access::S3Access;

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/captured_inputs")
}

/// Drive every enforced operation through its real hook and return what the PDP was
/// asked, keyed by capture id.
///
/// The request carries the method and URI the operation really arrives with (from the
/// s3s route table), because `RequestMeta` is derived from both: a corpus built from
/// `GET /` would record a method no client sends and a query string that never existed.
async fn capture_enforced_ops() -> (BTreeMap<String, serde_json::Value>, Vec<&'static str>) {
    let fx = common::fixture("golden-capture", common::alice_bundle());
    let access = GatewayAccess::new(fx.gw.clone());
    let mut seen = Vec::new();
    macro_rules! probe {
        ($m:ident, $name:literal, $input:expr) => {{
            let mut req = fx.request_on_route($name, $input);
            access
                .$m(&mut req)
                .await
                .unwrap_or_else(|e| panic!("{} must be allowed by the fixture grant: {e}", $name));
            seen.push($name);
        }};
    }
    crate::each_enforced_op!(probe);
    common::ops::assert_matches_enforced_set(seen.clone());

    // A denial is as much a wire shape as an allow, and it is the one a policy author
    // gets wrong. Capture the deny side of each request shape too.
    let mut req = fx.request_on_route(
        "GetObject",
        s3s::dto::GetObjectInput {
            bucket: "reports".into(),
            key: "2023/outside-the-grant.csv".into(),
            ..Default::default()
        },
    );
    assert!(access.get_object(&mut req).await.is_err());

    let mut req = fx.request_on_route(
        "ListObjectsV2",
        s3s::dto::ListObjectsV2Input {
            bucket: "reports".into(),
            // No prefix at all — the shape a bare `aws s3 ls s3://reports/` sends, and
            // one a policy author has to be able to see in the corpus. It used to
            // produce the narrowing obligation; since 2026-08-09 it is a DENY for this
            // prefix-scoped fixture (AWS parity — see `policy/gateway/authz.rego`
            // `narrowed`). The *wire shape* recorded here is unchanged either way, which
            // is what this harness records: the absence of `prefix` on the document.
            prefix: None,
            ..Default::default()
        },
    );
    assert!(access.list_objects_v2(&mut req).await.is_err());

    let mut req = fx.request_on_route(
        "DeleteObjects",
        s3s::dto::DeleteObjectsInput {
            bucket: "reports".into(),
            bypass_governance_retention: None,
            checksum_algorithm: None,
            delete: s3s::dto::Delete {
                objects: vec![
                    s3s::dto::ObjectIdentifier {
                        key: "2024/a.csv".into(),
                        e_tag: None,
                        last_modified_time: None,
                        size: None,
                        version_id: None,
                    },
                    s3s::dto::ObjectIdentifier {
                        key: "2023/b.csv".into(),
                        e_tag: None,
                        last_modified_time: None,
                        size: None,
                        version_id: None,
                    },
                ],
                ..Default::default()
            },
            expected_bucket_owner: None,
            mfa: None,
            request_payer: None,
        },
    );
    assert!(access.delete_objects(&mut req).await.is_ok());

    // A write carrying **riders** — the M4 ACL/tag retrofit's wire shape. Without this
    // the corpus would contain no document with a non-empty `acl_grants` or a
    // header-derived `requested_tags`, so a policy author would never see either, and the
    // drift gate could not tell that a canned ACL is emitted as `{source, value}`.
    //
    // Deliberately the *allowed* combination: `private` is the one canned ACL that
    // confers nothing, and `tier` is outside the fixture's reserved namespace. The
    // refusals this stage adds are screened in code before `decide`, so they emit no
    // capture at all — which is itself the property being relied on.
    let mut req = fx.request_on_route(
        "PutObject",
        s3s::dto::PutObjectInput {
            bucket: "reports".into(),
            key: "2024/x".into(),
            acl: Some(s3s::dto::ObjectCannedACL::from_static(
                s3s::dto::ObjectCannedACL::PRIVATE,
            )),
            tagging: Some("tier=internal".into()),
            ..Default::default()
        },
    );
    access
        .put_object(&mut req)
        .await
        .expect("a no-op canned ACL and an unreserved tag key must still be allowed");

    assert_eq!(
        fx.capture.dropped(),
        0,
        "the capture sink dropped records; the corpus would be incomplete"
    );
    assert_eq!(
        fx.capture.round_trip_failures(),
        0,
        "a captured input does not round-trip through OpaInput — the emitted wire shape \
         and the type have diverged, which is the exact failure this harness exists to \
         catch. Run with --nocapture and read the recorded error."
    );

    // THE structural invariant: the number of questions the PDP was asked equals the
    // number of documents captured. `GatewayAccess::decide` is the only place a capture
    // is taken, so a second `pdp.decide` call site anywhere on the request path shows up
    // here as a shortfall — and the corpus would silently stop being 100% of what is
    // emitted. The counter sits OUTSIDE the decision cache, so cache hits count too.
    let captured = fx.capture.snapshot();
    assert_eq!(
        captured.len(),
        fx.pdp_calls(),
        "the PDP was asked {} questions but only {} were captured — \
         `GatewayAccess::decide` is no longer the only call site",
        fx.pdp_calls(),
        captured.len()
    );

    let corpus = fx
        .capture
        .corpus()
        .into_iter()
        .map(|c| (c.id, c.raw))
        .collect();
    (corpus, seen)
}

#[tokio::test]
async fn decide_is_the_only_pdp_call_site_and_every_capture_round_trips() {
    // The assertions all live in the helper because the same run has to satisfy them
    // before its output may be written to disk.
    let (corpus, _) = capture_enforced_ops().await;
    assert!(!corpus.is_empty());
    for (id, raw) in &corpus {
        round_trip(raw).unwrap_or_else(|e| panic!("{id}: {e}"));
    }
}

#[tokio::test]
async fn every_enforced_op_contributes_at_least_one_captured_input() {
    // An operation that is enforced but never appears in the corpus is one the policy
    // has never been tested against with a real input.
    let (corpus, _) = capture_enforced_ops().await;
    let ops: BTreeSet<&str> = corpus
        .keys()
        .map(|id| id.rsplit_once('-').expect("capture id shape").0)
        .collect();
    for op in enforced_ops() {
        assert!(
            ops.contains(op),
            "{op} is Coverage::Enforced but emitted no captured input — either its hook \
             does not call the PDP, or it is missing from each_enforced_op!"
        );
    }
}

#[tokio::test]
async fn the_checked_in_corpus_is_what_the_gateway_emits_today() {
    // The drift gate proper. A field rename, a dropped field, a changed default or a
    // hook that stops asking a question all land here as a diff — which is the point:
    // the corpus is the reviewable artifact, not a cache.
    let (corpus, _) = capture_enforced_ops().await;
    let dir = corpus_dir();

    if std::env::var("S0_CAPTURE_REGENERATE").is_ok() {
        if dir.exists() {
            std::fs::remove_dir_all(&dir).expect("clear corpus");
        }
        std::fs::create_dir_all(&dir).expect("create corpus dir");
        for (id, raw) in &corpus {
            let pretty = serde_json::to_string_pretty(raw).expect("serialize");
            std::fs::write(dir.join(format!("{id}.json")), format!("{pretty}\n"))
                .expect("write capture");
        }
        eprintln!("regenerated {} captured inputs in {dir:?}", corpus.len());
        return;
    }

    let mut on_disk = BTreeMap::new();
    let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!("no captured corpus at {dir:?} ({e}); run with S0_CAPTURE_REGENERATE=1")
    });
    for entry in entries {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .expect("file stem")
            .to_string();
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read capture"))
                .unwrap_or_else(|e| panic!("{path:?} is not JSON: {e}"));
        on_disk.insert(id, raw);
    }

    let emitted_ids: BTreeSet<&String> = corpus.keys().collect();
    let stored_ids: BTreeSet<&String> = on_disk.keys().collect();
    let added: Vec<_> = emitted_ids.difference(&stored_ids).collect();
    let removed: Vec<_> = stored_ids.difference(&emitted_ids).collect();
    assert!(
        added.is_empty() && removed.is_empty(),
        "the captured corpus is out of date.\n  now emitted but not checked in: {added:?}\n  \
         checked in but no longer emitted: {removed:?}\n\
         Regenerate with S0_CAPTURE_REGENERATE=1 and review the diff as a change to the \
         OPA input contract."
    );
    for (id, raw) in &corpus {
        assert_eq!(
            on_disk.get(id),
            Some(raw),
            "captured input {id} differs from the checked-in corpus"
        );
    }
}

#[tokio::test]
async fn a_corpus_input_is_a_real_decision_when_replayed() {
    // The corpus is only worth having if the PDP accepts it verbatim. Replaying every
    // checked-in document through the same engine the gateway runs proves the files are
    // still valid `OpaInput`s and not just well-formed JSON.
    use s0::pdp::{GATEWAY_REGO, Pdp, RegorusPdp};
    let engine = RegorusPdp::new(GATEWAY_REGO, &common::alice_bundle()).expect("regorus");
    let dir = corpus_dir();
    let mut replayed = 0;
    for entry in std::fs::read_dir(&dir).expect("corpus dir") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let raw: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read")).expect("json");
        let input: s0::authz::OpaInput = serde_json::from_value(raw)
            .unwrap_or_else(|e| panic!("{path:?} is no longer a valid OpaInput: {e}"));
        engine
            .decide(&input)
            .await
            .unwrap_or_else(|e| panic!("{path:?} failed to evaluate: {e}"));
        replayed += 1;
    }
    assert!(replayed > 0, "the corpus is empty");
}
