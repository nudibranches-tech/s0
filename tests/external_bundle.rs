//! s0 against a real, externally-produced policy bundle.
//!
//! s0 is policy-content-agnostic: a control plane pushes a bundle carrying grant data
//! and, optionally, the rego module itself. That claim is not provable against a bundle
//! s0 wrote for itself, which shares every assumption with the engine loading it, so
//! [`tests/data/platform/s3_gateway_bundle.json`] is the byte output of a third-party
//! control plane's own projection, module included, replayed through s0's production
//! `parse_bundle` → `reload` → `decide` path. Each property below is *measured*: a rego
//! package name that matches while the module still evaluates to `undefined` is exactly
//! the deny-all bug, and only an allow rules it out.

use std::sync::Arc;

use s0::access::optable::{GATEWAY_VERBS, NON_GATEWAY_VERBS};
use s0::model::Action;
use s0::pdp::{
    Bundle, BundleStore, CachingPdp, DECISION_RULE, GATEWAY_REGO, Pdp, RegorusPdp,
    content_revision, parse_bundle,
};

const BUNDLE: &str = include_str!("data/platform/s3_gateway_bundle.json");
const BUNDLE_ORG: &str = "00000000-0000-0000-0000-000000000000";

/// The package the captured module declares, and which [`DECISION_RULE`] must address.
const BUNDLE_REGO_PACKAGE: &str = "s3.authz";

/// A request the captured bundle grants: `sa:pipeline` holds `read_objects` on
/// `acme-prod/warehouse` under `team-a/`.
fn input(object: &str) -> s0::authz::OpaInput {
    use s0::authz::{Backend, OpaInput, Principal, PrincipalAttributes, RequestMeta};
    use s0::model::{BackendKind, PrincipalType};

    OpaInput {
        principal: Principal {
            // The module derives `sa:<sub>` itself, so a key-space mismatch cannot be
            // papered over here.
            sub: "pipeline".into(),
            kind: PrincipalType::ServiceAccount,
            attributes: PrincipalAttributes::default(),
        },
        backend: Backend {
            id: "default-rgw".into(),
            kind: BackendKind::Ceph,
        },
        tenant: "acme-prod".into(),
        organization_id: BUNDLE_ORG.into(),
        action: Action::ReadObjects,
        bucket: "warehouse".into(),
        object: Some(object.into()),
        prefix: None,
        copy_source: None,
        delete_keys: None,
        object_tags: None,
        requested_tags: None,
        acl_grants: vec![],
        bypass_governance: false,
        request: RequestMeta {
            method: "GET".into(),
            params: None,
            headers_subset: Default::default(),
        },
    }
}

/// The headline: a bundle s0 did not write decides correctly through s0's real path.
///
/// A `reason` of "regorus: undefined decision" means [`DECISION_RULE`] does not resolve
/// in the pushed module — a deny-all gateway that looks perfectly healthy. Any other
/// failure means the module and s0's `OpaInput` disagree about the document shape.
#[tokio::test]
async fn an_external_bundle_decides_through_s0s_real_loading_path() {
    let parsed = parse_bundle(BUNDLE).expect("the external bundle parses");
    let pushed = parsed
        .policy
        .as_deref()
        .expect("the fixture ships its rego module in the bundle's `policy` field");
    assert_ne!(
        pushed, GATEWAY_REGO,
        "the fixture is s0's own compiled-in policy, so this test would prove nothing \
         about an externally-authored module"
    );

    // Exactly `gateway.rs::build_pdp`'s embedded branch: the pushed module is
    // authoritative, the compiled-in default is only the fallback.
    let bundles = Arc::new(BundleStore::new(Bundle::new(
        content_revision(BUNDLE),
        parsed.data.clone(),
    )));
    let engine: Arc<dyn Pdp> = Arc::new(
        RegorusPdp::new(pushed, &parsed.data).expect("s0's engine compiles the pushed module"),
    );
    let pdp = CachingPdp::new(engine, bundles, 64);

    // …and `bundle_refresh.rs::refresh_once`: the poll path reinstalls module and data
    // on every new revision, so it must work too.
    pdp.reload(parsed.policy.as_deref(), &parsed.data)
        .await
        .expect("the refresh path reloads the pushed module");

    let allowed = pdp.decide(&input("team-a/report.csv")).await.unwrap();
    assert!(
        allowed.allow,
        "s0 loaded an external bundle through its production path and DENIED a request \
         that bundle grants. reason: {:?}",
        allowed.reason
    );
    assert_eq!(allowed.reason, "allow: grant matched");

    // A key outside every granted prefix.
    let denied = pdp.decide(&input("team-b/report.csv")).await.unwrap();
    assert!(!denied.allow, "a key outside every grant was allowed");
    assert_eq!(denied.reason, "deny: no grant matches action and scope");

    // An explicit deny grant overrides the allow inside its own prefix.
    let revoked = pdp
        .decide(&input("team-a/secret/payroll.csv"))
        .await
        .unwrap();
    assert!(!revoked.allow, "a projected deny grant did not fire");
    assert_eq!(revoked.reason, "deny: explicit deny grant");
}

/// What an entrypoint/package disagreement actually does — measured, not assumed.
///
/// Embedded regorus rejects the entrypoint at compile time, so `build_pdp` returns `Err`
/// and the process never serves: loud, at boot. A sidecar OPA instead answers 200 with no
/// `result`, which `SidecarPdp` maps to a fail-closed deny — correct, but silent, and a
/// healthy process that denies every request is the failure this file exists to prevent.
#[tokio::test]
async fn a_module_the_entrypoint_does_not_address_can_never_produce_an_allow() {
    let parsed = parse_bundle(BUNDLE).expect("the fixture parses");
    let shipped = parsed
        .policy
        .as_deref()
        .expect("the fixture ships a module");
    let renamed = shipped.replacen(
        &format!("package {BUNDLE_REGO_PACKAGE}"),
        "package s3.authz_renamed",
        1,
    );
    assert_ne!(
        shipped, renamed,
        "could not inject a package mismatch — `package {BUNDLE_REGO_PACKAGE}` is no \
         longer spelled that way in the captured module, so this test proved nothing"
    );

    match RegorusPdp::new(&renamed, &parsed.data) {
        Err(e) => assert!(
            e.to_string().contains("compile"),
            "the engine refused the module for an unexpected reason: {e}"
        ),
        Ok(pdp) => {
            // If a future regorus accepts it, the only tolerable outcome is a deny.
            let decision = pdp.decide(&input("team-a/report.csv")).await.unwrap();
            assert!(
                !decision.allow,
                "a module that does not declare the package {DECISION_RULE} addresses \
                 produced an ALLOW: {decision:?}"
            );
        }
    }
}

/// **A bundle stripped of its module is a whole-organization outage.**
///
/// `build_pdp` and `refresh_once` both fall back to [`GATEWAY_REGO`] when `policy` is
/// absent, and that module keys `s3_grants` / `user_attributes` on the RAW
/// `input.principal.sub` — a control plane keying them `user:<sub>` / `sa:<client id>`
/// does not. The fallback therefore does not degrade: it denies everyone, on a document
/// full of valid grants. Fail-closed, so a reliability defect rather than a vulnerability.
#[tokio::test]
async fn a_bundle_without_its_module_denies_the_whole_organization() {
    let parsed = parse_bundle(BUNDLE).expect("the fixture parses");
    let req = input("team-a/report.csv");

    let pushed = RegorusPdp::new(
        parsed
            .policy
            .as_deref()
            .expect("the fixture ships a module"),
        &parsed.data,
    )
    .expect("the pushed module compiles");
    let allowed = pushed.decide(&req).await.unwrap();
    assert!(
        allowed.allow,
        "control: the PUSHED module must allow this request, or the rest of this test \
         measures nothing — {allowed:?}"
    );

    let fallback = RegorusPdp::new(GATEWAY_REGO, &parsed.data).expect("the default compiles");
    let denied = fallback.decide(&req).await.unwrap();
    assert!(
        !denied.allow,
        "the compiled-in default allowed a bundle it does not understand"
    );
    assert!(
        denied.reason.contains("not a tenant member"),
        "the deny should come from the subject-key mismatch, not elsewhere: {denied:?}"
    );
}

/// `reserved_tag_keys` must arrive populated, or `write_object_tags` is a verb that can
/// never succeed. An absent or `["*"]` list denies every tag write, PEP-side.
#[test]
fn an_external_bundle_makes_tag_writes_live_and_still_screens_reserved_keys() {
    use std::collections::BTreeMap;

    let parsed = parse_bundle(BUNDLE).expect("the fixture parses");
    let reserved = s0::access::tagging::ReservedTagKeys::from_bundle(&parsed.data);

    assert!(
        !reserved.denies_all_tag_writes(),
        "the bundle must make tagging live; an absent or `[\"*\"]` list leaves \
         write_object_tags unusable"
    );
    assert!(reserved.inert_reason().is_none());

    let ordinary = BTreeMap::from([("owner".to_string(), "team-a".to_string())]);
    reserved
        .check(&ordinary)
        .expect("an unreserved key is writable");

    // The reserved namespace is refused whatever the grants say — AWS reserves the
    // `aws:` tag prefix the same way.
    // The namespace the captured bundle actually reserves. This fixture is a verbatim
    // capture of a third-party control plane's output, so the key is read from it rather
    // than chosen here — editing the capture to suit the test would defeat its purpose.
    let reserved_key =
        BTreeMap::from([("hyperfluid/classification".to_string(), "phi".to_string())]);
    assert!(
        reserved.check(&reserved_key).is_err(),
        "a reserved tag namespace must be refused in every bundle"
    );
}

/// The grant vocabulary is one set with three spellings — the enum, the table's string
/// column, and whatever a control plane projects. A verb s0 sends that no projection
/// emits matches no grant and denies every request using it; a verb a projection emits
/// that s0 never sends is a grant an administrator can create which authorizes nothing.
/// Neither logs an error on either side.
#[test]
fn the_grant_vocabulary_has_exactly_one_spelling() {
    let mut from_table: Vec<&str> = GATEWAY_VERBS.to_vec();
    from_table.sort_unstable();
    let mut from_enum: Vec<&str> = Action::ALL.iter().map(|a| a.as_str()).collect();
    from_enum.sort_unstable();
    assert_eq!(from_table, from_enum);

    // A control-plane label must never be expressible as an `Action`, whatever it still
    // classifies in `OP_TABLE`. This is what stops one being promoted back into the
    // grant vocabulary by a one-line edit.
    for verb in NON_GATEWAY_VERBS {
        assert!(
            Action::ALL.iter().all(|a| a.as_str() != *verb),
            "{verb} is a control-plane label but `Action` still expresses it — s0 would \
             send a verb no grant can carry"
        );
    }
}
