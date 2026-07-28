//! Cross-repo contract gate: the strings s0 shares with the hyperfluid platform.
//!
//! ## The failure class this exists for
//!
//! Three production defects shipped at once, all of the same shape: s0 and the platform
//! disagreed about a **string**, and the disagreement was invisible to every test in
//! either repo because each side only ever tested itself.
//!
//! 1. **The decision entrypoint.** s0 evaluated `data.s0.gateway.decision`; the platform
//!    ships `package s3.authz` and pins `data.s3.authz.decision`. A gateway that polls a
//!    real bundle loads the platform's module and asks for a rule that is not in it. On
//!    the shipping sidecar engine that is **undefined**, which — correctly, by design —
//!    fails closed: a deny-all production authorization gateway on a healthy-looking
//!    pod, reported by nothing. (On the embedded engine it is a boot failure instead;
//!    both outcomes are measured by
//!    `a_module_the_entrypoint_does_not_address_can_never_produce_an_allow`.) It is the
//!    same failure that once cost this project 35 green tests over a deny-all policy.
//! 2. **The audit labels.** s0 emitted `s0.dev/record-type` and `s0.dev/organization-id`;
//!    the ingest extractor dispatches on `hyperfluid.nudibranches.tech/data-dock-type ==
//!    "s3-gateway"` and reads `hyperfluid.nudibranches.tech/organization-id`. Every
//!    gateway record fell off the end of the dispatch chain, was warn-logged and dropped
//!    — and the ingest endpoint answered **201 regardless**, so the producer could never
//!    find out. In a hospital or government tenancy a silently empty audit trail is worse
//!    than a loud outage.
//! 3. The record `path` (`s3/authz/decision`), which the platform's own fixture asserts.
//!
//! Fixing the three strings is not the point. **The point is that a string agreed in
//! prose across two repositories, with nothing checking it, will drift again.**
//!
//! ## The two halves, and why it is built this way
//!
//! Every literal is pinned once, below, in the `platform` module, with the hyperfluid
//! file it came from named next to it. Then:
//!
//! - **The always-on half** (`s0_agrees_with_the_pinned_platform_contract`, and friends)
//!   holds s0's own constants equal to those pins. It needs no sibling checkout, so it
//!   runs on every developer machine and in the public s0 CI, and it catches every
//!   drift introduced *from the s0 side* — which is the direction s0's own commits can
//!   actually move.
//! - **The cross-repo half** (`the_pinned_platform_contract_matches_the_real_hyperfluid_*`)
//!   reads the real hyperfluid sources and holds the pins equal to what the platform
//!   *actually ships*. It catches drift introduced from the platform side.
//!
//! ### The skip, stated explicitly
//!
//! `s0-gas` is a standalone repository; its CI cannot check out the private platform
//! repo. So when hyperfluid is absent the cross-repo half **skips, loudly** — it prints
//! a banner naming the repo, the branch-relative paths it wanted, and the environment
//! variables that control it. It is never a silent pass, and it is never the only thing
//! standing between an s0 edit and a broken contract: the pins are re-asserted by the
//! always-on half in the same file, so a developer who "fixes" a red cross-repo test by
//! editing a pin immediately turns the always-on test red instead.
//!
//! Set `S0_REQUIRE_HYPERFLUID=1` to turn the skip into a hard failure. Any pipeline that
//! *does* have both checkouts (the integration/release gate) must set it, or it is
//! running the same green-by-absence gate this file was written to abolish.
//!
//! This mirrors `tests/parity.rs` exactly, where a missing `opa` oracle is compensated
//! for by `the_opa_oracle_is_pinned_to_the_production_version_everywhere`, which needs
//! no oracle and therefore always runs.
//!
//! ## The third half: the strings are not the contract, the DECISION is
//!
//! Everything above compares *text*. Text that matches and still evaluates to
//! `undefined` is precisely the bug — so
//! `the_platforms_real_bundle_decides_through_s0s_real_loading_path` does not compare
//! anything: it takes the platform's **real serialized bundle**, pushes it through the
//! same `parse_bundle` → `Pdp::reload` → `Pdp::decide` path `bundle_refresh.rs` runs in
//! production, and asserts a granted request comes back **ALLOW**. An allow is the only
//! observation a deny-all cannot fake.
//!
//! The fixture (`tests/data/platform/s3_gateway_bundle.json`) is not hand-written: it
//! is the byte output of hyperfluid's own `compile_s3_projection` → `S3GatewayBundle::assemble`
//! → `seal` → `to_canonical_bytes`, and its `policy` field is byte-identical to
//! `hf_lib_vauban_rules/src/s3/authz/s3.rego` — which
//! `the_captured_platform_bundle_still_carries_the_module_hyperfluid_ships` re-checks
//! against the real checkout so the capture cannot rot.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use s0::audit::{DATA_DOCK_TYPE_VALUE, DECISION_PATH, LABEL_DATA_DOCK_TYPE, LABEL_ORG_ID};
use s0::pdp::{
    Bundle, BundleStore, CachingPdp, DECISION_RULE, GATEWAY_REGO, Pdp, RegorusPdp, SidecarPdp,
    content_revision, decision_rule_path, parse_bundle,
};

/// The other repository, by name. Every failure message in this file says it, because
/// the whole cost of these defects was a person not knowing where to look.
const OTHER_REPO: &str = "hyperfluid (branch feat/s3-gateway-integration)";

/// The contract, pinned. Each constant names the hyperfluid file that owns it.
mod platform {
    /// `package s3.authz` — `rust/hf_lib_vauban_rules/src/s3/authz/s3.rego`, and
    /// `S3_AUTHZ_PACKAGE` in
    /// `rust/hf_module_console_api/src/hf_console/inbound/http/handlers/vauban/s3_gateway_projection/bundle.rs`.
    pub const REGO_PACKAGE: &str = "s3.authz";

    /// `S3_AUTHZ_ENTRYPOINT` — same `bundle.rs`. The single rule the gateway evaluates.
    pub const ENTRYPOINT: &str = "data.s3.authz.decision";

    /// The entrypoint in decision-log `path` form. Asserted by hyperfluid's own
    /// `rust/hf_module_console_api/src/hf_console/domain/audit_logs/models/decision_log.rs`
    /// fixture.
    pub const DECISION_LOG_PATH: &str = "s3/authz/decision";

    /// `S3GatewayDecisionLogMetadataExtractor::is_handled` — `decision_log.rs`.
    pub const DATA_DOCK_TYPE_LABEL: &str = "hyperfluid.nudibranches.tech/data-dock-type";
    /// The value `is_handled` compares that label against.
    pub const DATA_DOCK_TYPE_VALUE: &str = "s3-gateway";

    /// `ORGANIZATION_ID_LABEL` — `rust/hf_lib_domain_core/src/labels.rs`, read by
    /// `S3GatewayDecisionLogMetadataExtractor::get_organization_id`.
    pub const ORGANIZATION_ID_LABEL: &str = "hyperfluid.nudibranches.tech/organization-id";
}

/// Paths inside the hyperfluid checkout, so a failure can quote one.
mod hf_path {
    pub const RULES_REGO: &str = "rust/hf_lib_vauban_rules/src/s3/authz/s3.rego";
    pub const BUNDLE_RS: &str = "rust/hf_module_console_api/src/hf_console/inbound/http/\
                                 handlers/vauban/s3_gateway_projection/bundle.rs";
    pub const DECISION_LOG_RS: &str =
        "rust/hf_module_console_api/src/hf_console/domain/audit_logs/models/decision_log.rs";
    pub const LABELS_RS: &str = "rust/hf_lib_domain_core/src/labels.rs";
}

// ── the always-on half: s0's own constants against the pins ─────────────────────

/// s0 must ask the question the platform answers.
#[test]
fn s0_evaluates_the_entrypoint_the_platform_ships() {
    assert_eq!(
        DECISION_RULE,
        platform::ENTRYPOINT,
        "\ns0 evaluates {DECISION_RULE:?} but {OTHER_REPO} ships {:?} \
         ({}, S3_AUTHZ_ENTRYPOINT).\n\
         A bundle whose module declares a different package evaluates to UNDEFINED, and \
         this gateway fails closed on undefined — so this disagreement is a DENY-ALL \
         production authorization gateway with no error and no failing test anywhere.\n\
         Fix `DECISION_RULE` in src/pdp/bundle.rs, not this test.\n",
        platform::ENTRYPOINT,
        hf_path::BUNDLE_RS,
    );

    // The compiled-in default module must declare the same package, or the fallback
    // policy (what runs when a bundle carries data only) answers a different question
    // than a pushed one.
    let declared =
        rego_package(GATEWAY_REGO).expect("policy/gateway/authz.rego has a package line");
    assert_eq!(
        declared,
        platform::REGO_PACKAGE,
        "\npolicy/gateway/authz.rego declares `package {declared}` but {OTHER_REPO} \
         ships `package {}` ({}).\n\
         The compiled-in default is the fallback for a data-only bundle and the oracle \
         the parity gate replays against; if it declares a different package than the \
         pushed module, the two disagree about what is being evaluated.\n",
        platform::REGO_PACKAGE,
        hf_path::RULES_REGO,
    );

    // …and the entrypoint must actually address that package, which is the join between
    // the two assertions above.
    assert_eq!(
        DECISION_RULE,
        format!("data.{declared}.decision"),
        "\nthe entrypoint {DECISION_RULE:?} does not address `package {declared}`\n"
    );
}

/// Every place that spells the entrypoint out is derived from the one constant.
#[test]
fn nothing_holds_a_second_copy_of_the_entrypoint() {
    let path = decision_rule_path();
    assert_eq!(path, platform::DECISION_LOG_PATH);

    // The audit record's `path` field. hyperfluid's own decision-log fixture asserts
    // this literal, and a mismatch makes every s0 record look like it came from a rule
    // the platform has never heard of.
    assert_eq!(
        DECISION_PATH,
        platform::DECISION_LOG_PATH,
        "\ns0 stamps audit records with path {DECISION_PATH:?}; {OTHER_REPO} expects {:?} \
         ({}).\n",
        platform::DECISION_LOG_PATH,
        hf_path::DECISION_LOG_RS,
    );

    // The sidecar OPA URL. A sidecar posting to a path OPA does not resolve gets an
    // undefined result, which this PDP turns into a deny — the same silent deny-all,
    // reached by a different route.
    let pdp = SidecarPdp::new("http://127.0.0.1:8181", std::time::Duration::from_secs(1))
        .expect("build sidecar pdp");
    assert_eq!(
        pdp.decision_url(),
        format!(
            "http://127.0.0.1:8181/v1/data/{}",
            platform::DECISION_LOG_PATH
        ),
        "\nthe sidecar posts to a path that is not the slash form of {DECISION_RULE:?}\n"
    );
}

/// s0 must label records the way the ingest extractor dispatches.
#[test]
fn s0_labels_audit_records_the_way_the_extractor_routes() {
    assert_eq!(
        LABEL_DATA_DOCK_TYPE,
        platform::DATA_DOCK_TYPE_LABEL,
        "\ns0 emits the discriminator label {LABEL_DATA_DOCK_TYPE:?}; \
         S3GatewayDecisionLogMetadataExtractor::is_handled in {OTHER_REPO} matches {:?} \
         ({}).\n\
         A record that does not match falls off the end of the dispatch chain with \
         \"No metadata extractor found for decision log\": warn-logged, DROPPED, and \
         answered 201 — so the gateway never learns its audit trail is empty.\n",
        platform::DATA_DOCK_TYPE_LABEL,
        hf_path::DECISION_LOG_RS,
    );
    assert_eq!(
        DATA_DOCK_TYPE_VALUE,
        platform::DATA_DOCK_TYPE_VALUE,
        "\ns0 labels its records {DATA_DOCK_TYPE_VALUE:?}; the extractor in {OTHER_REPO} \
         routes on {:?} ({}).\n",
        platform::DATA_DOCK_TYPE_VALUE,
        hf_path::DECISION_LOG_RS,
    );
    assert_eq!(
        LABEL_ORG_ID,
        platform::ORGANIZATION_ID_LABEL,
        "\ns0 attributes records with {LABEL_ORG_ID:?}; \
         S3GatewayDecisionLogMetadataExtractor::get_organization_id in {OTHER_REPO} reads \
         ORGANIZATION_ID_LABEL = {:?} ({}).\n\
         An unreadable org is dropped fail-closed on ingest, so this mismatch also \
         deletes the trail rather than misattributing it.\n",
        platform::ORGANIZATION_ID_LABEL,
        hf_path::LABELS_RS,
    );

    // And a real record actually carries them — the constants being right is not the
    // same claim as them being used.
    let labels = sample_record_labels();
    assert_eq!(
        labels
            .get(platform::DATA_DOCK_TYPE_LABEL)
            .map(String::as_str),
        Some(platform::DATA_DOCK_TYPE_VALUE),
        "an emitted record does not carry the discriminator the extractor routes on: \
         {labels:?}"
    );
    assert!(
        labels.contains_key(platform::ORGANIZATION_ID_LABEL),
        "an emitted decision record carries no trusted org attribution: {labels:?}"
    );
}

/// Not "the label constants are right" — **run the extractor's conditions against a
/// record s0 actually emits.**
///
/// The three predicates below are transcribed from
/// `S3GatewayDecisionLogMetadataExtractor` and
/// `OPADecisionLog::try_into_create_audit_log_request` in the platform's
/// `domain/audit_logs/models/decision_log.rs` (see `hf_path::DECISION_LOG_RS`). Each one
/// is a silent drop when it fails: the ingest endpoint answers 201 either way, so the
/// gateway can never learn that its regulated trail is empty. A constant that spells
/// the label correctly but is attached to a record that fails one of the *other*
/// predicates loses exactly as much data.
#[test]
fn a_real_audit_record_passes_the_platforms_ingest_predicates() {
    let record = sample_decision_record();
    let json = serde_json::to_value(&record).expect("a record serializes");

    // 1. `is_handled` — labels.get(<label>).map(|v| v == "s3-gateway").unwrap_or(false)
    let dock_type = json["labels"][platform::DATA_DOCK_TYPE_LABEL].as_str();
    assert_eq!(
        dock_type,
        Some(platform::DATA_DOCK_TYPE_VALUE),
        "is_handled would be false: the record falls off the end of the dispatch chain \
         and is warn-logged and DROPPED behind a 201. labels = {}",
        json["labels"]
    );

    // 2. `get_organization_id` — labels.get(ORGANIZATION_ID_LABEL)?.parse::<Uuid>().ok()
    //    `?` and `.ok()` both mean None, and None here is
    //    `Err("...trusted organization_id not found — dropping")`. Note the PARSE: an
    //    org id that is not a UUID drops the record just as surely as a missing label.
    let org = json["labels"][platform::ORGANIZATION_ID_LABEL]
        .as_str()
        .expect("a decision record must carry the trusted org attribution");
    uuid::Uuid::parse_str(org).unwrap_or_else(|e| {
        panic!(
            "the org label {org:?} is not a UUID ({e}); \
             get_organization_id returns None and the record is DROPPED"
        )
    });

    // 3. `self.timestamp.parse::<DateTime<Utc>>()` — a parse failure is
    //    `Err("Failed to parse timestamp")`, i.e. dropped.
    let ts = json["timestamp"]
        .as_str()
        .expect("a record has a timestamp");
    ts.parse::<chrono::DateTime<chrono::Utc>>()
        .unwrap_or_else(|e| panic!("the record's timestamp {ts:?} does not parse: {e}"));

    // 4. `requested_by` is the field the extractor takes the end-user identity from,
    //    and ADR-002 requires it to equal `input.principal.sub`.
    assert_eq!(json["requested_by"], json["input"]["principal"]["sub"]);
}

/// **OPEN DEFECT, pinned here so it cannot be rediscovered by an auditor.**
///
/// The platform's ingest is `Json(body): Json<Vec<OPADecisionLog>>`
/// (`handlers/audit_logs/create_opa_decision_logs.rs`). `OPADecisionLog::input` is a
/// bare `serde_json::Value` — **not** `Option`, and with no `#[serde(default)]` — so a
/// record that omits `input` fails to deserialize. Axum rejects the request body as a
/// whole, which means **one gate record poisons the entire batch**: every good decision
/// record shipped alongside it is lost too, `ControlPlaneBackend::ship` sees the non-2xx
/// and spills, and the retry fails identically forever.
///
/// s0's gate records omit `input` by design (`AuditRecord::gate_denial`, ADR-002 §D3:
/// no policy ran, so there is no input to report), and they are emitted on exactly the
/// traffic a regulated tenancy most wants recorded — unauthenticated and malformed
/// requests.
///
/// This test asserts the CURRENT state on both sides. It fails the moment either side
/// moves, which is the point: whoever fixes it (s0 emitting `input: {}`, or the platform
/// defaulting the field) has to come here and say so.
#[test]
fn a_gate_record_omits_a_field_the_platforms_ingest_type_requires() {
    use s0::audit::{AuditRecord, GateContext, GateStage};

    let gate = AuditRecord::gate_denial(
        "gate-contract".into(),
        "2026-07-28T00:00:00Z".into(),
        GateContext {
            operation: "GetObject".into(),
            stage: GateStage::Anonymous,
            access_key_id: None,
            tenant: None,
            suppressed_since_last: 0,
        },
        "anonymous request",
        String::new(),
    );
    let json = serde_json::to_value(&gate).expect("a gate record serializes");
    assert!(
        json.get("input").is_none(),
        "gate records now carry `input`; if that was the fix for the batch-poisoning \
         defect, delete this test and say so in ADR-002"
    );
    // It would be handled — the dispatch label is there — but it never gets that far.
    assert_eq!(
        json["labels"][platform::DATA_DOCK_TYPE_LABEL],
        serde_json::json!(platform::DATA_DOCK_TYPE_VALUE)
    );
}

// ── the cross-repo half: the pins against the real hyperfluid tree ──────────────

#[test]
fn the_pinned_platform_contract_matches_the_real_hyperfluid_policy_bundle() {
    let Some(repo) = hyperfluid_repo("the rego package and the decision entrypoint") else {
        return;
    };

    let rego = read(&repo, hf_path::RULES_REGO);
    let declared = rego_package(&rego).unwrap_or_else(|| {
        panic!("{} declares no `package` line", hf_path::RULES_REGO);
    });
    assert_eq!(
        declared,
        platform::REGO_PACKAGE,
        "{}",
        drifted(
            hf_path::RULES_REGO,
            "package",
            platform::REGO_PACKAGE,
            &declared
        )
    );

    let bundle_rs = read(&repo, hf_path::BUNDLE_RS);
    let pkg = rust_str_const(&bundle_rs, "S3_AUTHZ_PACKAGE").unwrap_or_else(|| {
        panic!("{} no longer defines S3_AUTHZ_PACKAGE", hf_path::BUNDLE_RS);
    });
    assert_eq!(
        pkg,
        platform::REGO_PACKAGE,
        "{}",
        drifted(
            hf_path::BUNDLE_RS,
            "S3_AUTHZ_PACKAGE",
            platform::REGO_PACKAGE,
            &pkg
        )
    );

    let entry = rust_str_const(&bundle_rs, "S3_AUTHZ_ENTRYPOINT").unwrap_or_else(|| {
        panic!(
            "{} no longer defines S3_AUTHZ_ENTRYPOINT",
            hf_path::BUNDLE_RS
        );
    });
    assert_eq!(
        entry,
        platform::ENTRYPOINT,
        "{}",
        drifted(
            hf_path::BUNDLE_RS,
            "S3_AUTHZ_ENTRYPOINT",
            platform::ENTRYPOINT,
            &entry
        )
    );
}

#[test]
fn the_pinned_platform_contract_matches_the_real_hyperfluid_audit_extractor() {
    let Some(repo) = hyperfluid_repo("the decision-log label literals") else {
        return;
    };

    let src = read(&repo, hf_path::DECISION_LOG_RS);
    let extractor = s3_gateway_extractor(&src).unwrap_or_else(|| {
        panic!(
            "{} no longer contains `impl DecisionLogMetadataExtractor for \
             S3GatewayDecisionLogMetadataExtractor` — the S3 gateway's audit records may \
             have no consumer at all",
            hf_path::DECISION_LOG_RS
        );
    });

    let is_handled = fn_body(extractor, "is_handled").unwrap_or_else(|| {
        panic!("{}: is_handled not found", hf_path::DECISION_LOG_RS);
    });
    let label = str_literal_after(is_handled, ".get(").unwrap_or_else(|| {
        panic!(
            "{}: is_handled reads no label literal",
            hf_path::DECISION_LOG_RS
        );
    });
    assert_eq!(
        label,
        platform::DATA_DOCK_TYPE_LABEL,
        "{}",
        drifted(
            hf_path::DECISION_LOG_RS,
            "is_handled's dispatch label",
            platform::DATA_DOCK_TYPE_LABEL,
            &label
        )
    );
    let value = str_literal_after(is_handled, "==").unwrap_or_else(|| {
        panic!(
            "{}: is_handled compares against no literal",
            hf_path::DECISION_LOG_RS
        );
    });
    assert_eq!(
        value,
        platform::DATA_DOCK_TYPE_VALUE,
        "{}",
        drifted(
            hf_path::DECISION_LOG_RS,
            "is_handled's dock-type value",
            platform::DATA_DOCK_TYPE_VALUE,
            &value
        )
    );

    // The org attribution is read through a shared constant rather than a literal, so
    // check both ends: that the extractor still uses it, and what it resolves to.
    let get_org = fn_body(extractor, "get_organization_id").unwrap_or_else(|| {
        panic!(
            "{}: get_organization_id not found",
            hf_path::DECISION_LOG_RS
        );
    });
    assert!(
        get_org.contains("ORGANIZATION_ID_LABEL"),
        "{}: get_organization_id no longer reads ORGANIZATION_ID_LABEL — s0's org label \
         is pinned to that constant and this test can no longer see what it reads:\n{get_org}",
        hf_path::DECISION_LOG_RS,
    );
    let labels_rs = read(&repo, hf_path::LABELS_RS);
    let org_label = rust_str_const(&labels_rs, "ORGANIZATION_ID_LABEL").unwrap_or_else(|| {
        panic!(
            "{} no longer defines ORGANIZATION_ID_LABEL",
            hf_path::LABELS_RS
        );
    });
    assert_eq!(
        org_label,
        platform::ORGANIZATION_ID_LABEL,
        "{}",
        drifted(
            hf_path::LABELS_RS,
            "ORGANIZATION_ID_LABEL",
            platform::ORGANIZATION_ID_LABEL,
            &org_label
        )
    );

    // The decision-log `path` the platform expects from s0.
    assert!(
        src.contains(&format!("{:?}", platform::DECISION_LOG_PATH)),
        "{}",
        drifted(
            hf_path::DECISION_LOG_RS,
            "the expected s0 decision-log path",
            platform::DECISION_LOG_PATH,
            "not present anywhere in the file",
        )
    );
}

/// The record s0 emits must **deserialize** into the platform's `OPADecisionLog`, or
/// nothing downstream of that ever runs.
///
/// Read from the real struct rather than transcribed: a field that is neither
/// `Option<…>` nor `#[serde(default)]` is required, and a batch containing one record
/// that omits it is rejected whole (`Json<Vec<OPADecisionLog>>`).
#[test]
fn the_platforms_decision_log_type_still_requires_only_fields_s0_sends() {
    let Some(repo) = hyperfluid_repo("the decision-log wire type") else {
        return;
    };
    let src = read(&repo, hf_path::DECISION_LOG_RS);
    let required = required_fields_of_struct(&src, "OPADecisionLog").unwrap_or_else(|| {
        panic!(
            "{} no longer declares `pub struct OPADecisionLog`",
            hf_path::DECISION_LOG_RS
        )
    });
    assert!(
        required.contains("labels") && required.contains("timestamp"),
        "the struct parser found nothing meaningful — this test would be vacuous: \
         {required:?}"
    );

    let record = serde_json::to_value(sample_decision_record()).expect("serializes");
    let obj = record.as_object().expect("a record is an object");
    let missing: Vec<&String> = required.iter().filter(|f| !obj.contains_key(*f)).collect();
    assert!(
        missing.is_empty(),
        "{}",
        drifted(
            hf_path::DECISION_LOG_RS,
            "OPADecisionLog's required fields",
            "every one present in s0's AuditRecord",
            &format!("s0 omits {missing:?}"),
        )
    );

    // The other half of `a_gate_record_omits_a_field_the_platforms_ingest_type_requires`:
    // this is the platform-side fact that makes a gate record poison its batch. When it
    // stops being true, both tests must be revisited together.
    assert!(
        required.contains("input"),
        "`OPADecisionLog::input` is no longer required — the gate-record batch-poisoning \
         defect recorded in `a_gate_record_omits_a_field_the_platforms_ingest_type_requires` \
         is fixed on the platform side; update both tests"
    );
}

/// Field names of `pub struct <name>` that serde requires on the wire: not `Option<…>`
/// and not carrying `#[serde(default)]`.
fn required_fields_of_struct(src: &str, name: &str) -> Option<std::collections::BTreeSet<String>> {
    let at = src.find(&format!("pub struct {name} {{"))?;
    let body = &src[at..];
    let end = body.find("\n}")?;
    let mut out = std::collections::BTreeSet::new();
    let mut defaulted = false;
    for line in body[..end].lines().skip(1) {
        let line = line.trim();
        if line.starts_with("#[serde(") && line.contains("default") {
            defaulted = true;
            continue;
        }
        if line.starts_with('#') || line.starts_with("//") || line.is_empty() {
            continue;
        }
        let Some(field) = line.strip_prefix("pub ") else {
            continue;
        };
        let Some((ident, ty)) = field.split_once(':') else {
            continue;
        };
        let optional = ty.trim().starts_with("Option<");
        if !defaulted && !optional {
            out.insert(ident.trim().to_string());
        }
        defaulted = false;
    }
    Some(out)
}

// ── the integration proof: a real bundle, decided through s0's real path ────────

/// The platform's bundle, verbatim.
///
/// Produced by executing hyperfluid's own projection and serializer — the same
/// `compile_s3_projection` / `S3GatewayBundle::assemble` / `seal` /
/// `to_canonical_bytes` chain behind
/// `GET /organizations/{organization_id}/s3-gateway-bundle` — over the grant rows in
/// `bundle.rs::tests::sample_bundle`, plus one deny grant so `s3_deny` is populated
/// rather than `{}`. Nothing about it is hand-typed; it is a capture, and
/// [`the_captured_platform_bundle_still_carries_the_module_hyperfluid_ships`] holds it
/// against the live checkout.
const PLATFORM_BUNDLE: &str = include_str!("data/platform/s3_gateway_bundle.json");

/// The org the captured bundle is published for. `s3.rego`'s `org_matches` gate
/// compares this against `input.organization_id` and denies on any mismatch, so it is
/// part of the input contract, not decoration.
const PLATFORM_BUNDLE_ORG: &str = "00000000-0000-0000-0000-000000000000";

/// **The proof that the two repositories agree.**
///
/// Every other test in this file compares strings. This one runs the thing. It takes
/// the platform's real bundle bytes and drives them through the exact sequence
/// `src/bundle_refresh.rs::refresh_once` and `src/gateway.rs::build_pdp` run in
/// production — `parse_bundle`, engine construction over the *pushed* module,
/// `Pdp::reload`, `Pdp::decide` on a real `OpaInput` — and asserts:
///
/// * a granted read comes back **ALLOW**, and
/// * a read one prefix outside the grant comes back **DENY**.
///
/// The allow is the load-bearing half. A wrong entrypoint, a package the module does
/// not declare, a `data` shape the rego cannot read, a regorus version that will not
/// compile the module — every one of those failures produces `undefined`, which this
/// gateway *correctly* turns into a deny. So a suite that only ever asserts denies is
/// green on a deny-all production gateway; that is the exact failure this project has
/// already paid for once. Only an allow distinguishes "enforcing" from "broken".
///
/// The deny is the control: it proves the allow came from a grant that matched, not
/// from a module that says yes to everything.
#[tokio::test]
async fn the_platforms_real_bundle_decides_through_s0s_real_loading_path() {
    let parsed = parse_bundle(PLATFORM_BUNDLE).expect("the platform's bundle parses");
    let pushed = parsed
        .policy
        .as_deref()
        .expect("the platform ships its rego module in the bundle's `policy` field");
    assert_ne!(
        pushed, GATEWAY_REGO,
        "the fixture is s0's own compiled-in policy, so this test would prove nothing \
         about the platform's module"
    );

    // Exactly `gateway.rs::build_pdp`'s embedded branch: the pushed module is
    // authoritative, the compiled-in default is only the fallback.
    let bundles = Arc::new(BundleStore::new(Bundle::new(
        content_revision(PLATFORM_BUNDLE),
        parsed.data.clone(),
    )));
    let engine: Arc<dyn Pdp> = Arc::new(
        RegorusPdp::new(pushed, &parsed.data)
            .expect("s0's engine compiles the module the platform ships"),
    );
    let pdp = CachingPdp::new(engine, bundles.clone(), 64);

    // …and `bundle_refresh.rs::refresh_once`: the poll path reinstalls the module and
    // the data on every new revision, so it must work too.
    pdp.reload(parsed.policy.as_deref(), &parsed.data)
        .await
        .expect("the refresh path reloads the platform's module");

    // GRANTED: `sa:pipeline` holds read_objects on acme-prod/warehouse under `team-a/`.
    let allowed = pdp
        .decide(&platform_input("team-a/report.csv"))
        .await
        .expect("the PDP answers");
    assert!(
        allowed.allow,
        "\nTHE TWO REPOSITORIES DO NOT AGREE.\n\
         s0 loaded {OTHER_REPO}'s real bundle through its own production path and \
         DENIED a request the bundle grants.\n\
         reason: {:?}\n\
         A reason of \"regorus: undefined decision\" means the entrypoint {DECISION_RULE} \
         does not resolve in the module the platform ships — i.e. a deny-all gateway. \
         Any other reason means the module and s0's `OpaInput` disagree about the \
         document.\n",
        allowed.reason,
    );
    assert_eq!(allowed.reason, "allow: grant matched");

    // NOT GRANTED: same principal, same bucket, a key outside the granted prefix.
    let denied = pdp
        .decide(&platform_input("team-b/report.csv"))
        .await
        .expect("the PDP answers");
    assert!(
        !denied.allow,
        "a key outside every granted prefix was allowed: {denied:?}"
    );
    assert_eq!(denied.reason, "deny: no grant matches action and scope");

    // …and the projected DENY grant overrides the allow inside its own prefix, which is
    // the half a v1 module would have read as an allow.
    let revoked = pdp
        .decide(&platform_input("team-a/secret/payroll.csv"))
        .await
        .expect("the PDP answers");
    assert!(!revoked.allow, "a projected deny grant did not fire");
    assert_eq!(revoked.reason, "deny: explicit deny grant");
}

/// What a package/entrypoint disagreement actually does — **measured**, not assumed.
///
/// The claim this whole file rests on is "a mismatch cannot produce an allow". That is
/// worth executing rather than believing, and the two engines get there differently:
///
/// * **embedded (regorus 0.10.1)** — `compile_with_entrypoint` rejects the entrypoint
///   outright (`compile: not a valid rule path`), so `build_pdp` returns `Err` and the
///   process never serves. Loud, at boot. Asserted below.
/// * **sidecar OPA (the shipping default, ADR-005)** — the Data API answers 200 with no
///   `result`, which `SidecarPdp` maps to an explicit
///   `Decision::deny("opa: undefined decision")`. Fail-closed, but **silent**: a healthy
///   pod that denies every request. That is the one this file exists to prevent, and it
///   is why the proof above asserts an ALLOW rather than the absence of an error.
#[tokio::test]
async fn a_module_the_entrypoint_does_not_address_can_never_produce_an_allow() {
    let parsed = parse_bundle(PLATFORM_BUNDLE).expect("the fixture parses");
    let shipped = parsed
        .policy
        .as_deref()
        .expect("the fixture carries a module");
    let renamed = shipped.replacen(
        &format!("package {}", platform::REGO_PACKAGE),
        "package s3.authz_renamed",
        1,
    );
    assert_ne!(
        shipped,
        renamed,
        "could not inject a package mismatch — `package {}` is no longer spelled that \
         way in the module the platform ships, so this test proved nothing",
        platform::REGO_PACKAGE
    );

    match RegorusPdp::new(&renamed, &parsed.data) {
        Err(e) => assert!(
            e.to_string().contains("compile"),
            "the engine refused the module for an unexpected reason: {e}"
        ),
        Ok(pdp) => {
            // If a future regorus accepts it, the only tolerable outcome is a deny.
            let decision = pdp
                .decide(&platform_input("team-a/report.csv"))
                .await
                .expect("the PDP answers");
            assert!(
                !decision.allow,
                "a module that does not declare the package {DECISION_RULE} addresses \
                 produced an ALLOW: {decision:?}"
            );
        }
    }
}

/// The capture must not rot into a fossil of a module the platform no longer ships.
#[test]
fn the_captured_platform_bundle_still_carries_the_module_hyperfluid_ships() {
    let parsed = parse_bundle(PLATFORM_BUNDLE).expect("the fixture parses");
    let captured = parsed.policy.expect("the fixture carries a module");

    let Some(repo) = hyperfluid_repo("the captured bundle's rego module") else {
        return;
    };
    let live = read(&repo, hf_path::RULES_REGO);
    assert_eq!(
        captured,
        live,
        "\ntests/data/platform/s3_gateway_bundle.json carries a rego module that is no \
         longer byte-identical to {} in {OTHER_REPO}.\n\
         The integration proof \
         (`the_platforms_real_bundle_decides_through_s0s_real_loading_path`) is \
         therefore evaluating a module the platform does not serve. Re-capture the \
         bundle from the platform's serializer rather than editing the fixture by \
         hand.\n",
        hf_path::RULES_REGO,
    );
}

/// `input.<path>` references the PLATFORM's module makes that s0 has never been
/// observed to emit — recorded, with the reason each is tolerated, rather than left
/// invisible.
///
/// Anything on this list is **inert**: the rego reference is undefined, so the rule it
/// appears in never matches. That is fail-closed, which is why it is a capability gap
/// and not a vulnerability — but "a restriction that silently never applies" is exactly
/// the thing an auditor must not discover on their own.
const PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT: &[(&str, &str)] = &[(
    "request.attributes",
    "request-context ABAC. `s3.rego`'s `request_attributes` rule reads it and carries \
     `default request_attributes := {}`, so a grant conditioned on a REQUEST attribute \
     (`Condition::RequestAttributeEquals`, projected by the platform's serializer) can \
     never match: such a grant is inert end to end. s0's `RequestMeta` \
     (src/authz/input.rs) emits only `method`, `params` and `headers_subset`. Allow \
     grants so conditioned under-grant (fail-closed); DENY grants so conditioned are \
     the real cost — a revocation that does not revoke. Owed: an `attributes` field on \
     `RequestMeta`, populated from the parsed request.",
)];

/// The input half of the same contract: every `input.<path>` the PLATFORM's module
/// reads must be a path s0 has actually been observed to emit.
///
/// `tests/fixture_drift.rs::every_rego_input_reference_appears_in_a_captured_input`
/// enforces this for s0's own shipped rego, against the captured corpus. This is the
/// same check aimed across the repository boundary, which is the version that matters:
/// in production s0 evaluates the PLATFORM's module, not its own. A field that module
/// reads and s0 never sends is **undefined**, and undefined is not false — it is the
/// precise shape of the failure that produced 35 green tests over a deny-all policy.
#[test]
fn the_platform_module_reads_no_input_path_s0_never_sends() {
    let Some(repo) = hyperfluid_repo("the platform module's input references") else {
        return;
    };
    let rego = read(&repo, hf_path::RULES_REGO);
    let referenced = rego_input_references(&rego);
    assert!(
        referenced.contains("action") && referenced.contains("principal.sub"),
        "the reference extractor found nothing meaningful in {} — this test would be \
         vacuous: {referenced:?}",
        hf_path::RULES_REGO,
    );

    let corpus = captured_inputs();
    let tolerated: std::collections::BTreeMap<&str, &str> = PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT
        .iter()
        .copied()
        .collect();

    let mut unsatisfied = Vec::new();
    for path in &referenced {
        let emitted = corpus
            .iter()
            .any(|doc| resolve(doc, path).is_some_and(|v| !v.is_null()));
        if !emitted && !tolerated.contains_key(path.as_str()) {
            unsatisfied.push(path.clone());
        }
    }
    assert!(
        unsatisfied.is_empty(),
        "\n{} in {OTHER_REPO} reads input.{unsatisfied:?}, which s0 has never been \
         observed to emit.\n\
         A rego reference to a field no producer sends is UNDEFINED, not false, so every \
         rule that depends on it is permanently inert. Either add the field to \
         `src/authz/input.rs` and re-record the capture corpus \
         (`S0_CAPTURE_REGENERATE=1 cargo test --test golden_capture`), or — if the gap \
         is deliberate and fail-closed — record it in \
         PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT with the reason.\n",
        hf_path::RULES_REGO,
    );

    // The tolerated list must not outlive the gap it documents. Once s0 emits the
    // field, the entry has to go, or it would mask the *next* regression at that path.
    for (path, _) in PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT {
        assert!(
            referenced.contains(*path),
            "PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT records input.{path}, but {} no \
             longer reads it — delete the entry",
            hf_path::RULES_REGO,
        );
        assert!(
            !corpus
                .iter()
                .any(|doc| resolve(doc, path).is_some_and(|v| !v.is_null())),
            "s0 now emits input.{path}: delete its entry from \
             PLATFORM_INPUT_PATHS_S0_DOES_NOT_EMIT so the path is enforced again"
        );
    }
}

/// Every `input.<a>.<b>…` reference in a rego module, comments stripped. Same
/// extractor as `tests/fixture_drift.rs::rego_input_references`, which is deliberate:
/// the two tests must agree about what "the policy reads this" means.
fn rego_input_references(rego: &str) -> std::collections::BTreeSet<String> {
    let mut refs = std::collections::BTreeSet::new();
    for line in rego.lines() {
        let code = line.split('#').next().unwrap_or("");
        let bytes = code.as_bytes();
        let mut i = 0;
        while let Some(pos) = code[i..].find("input.") {
            let start = i + pos;
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
    refs
}

fn resolve<'a>(doc: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    path.split('.').try_fold(doc, |v, seg| v.get(seg))
}

/// The recorded corpus of inputs the gateway has actually emitted, plus the input this
/// file drives the platform's module with — so "s0 emits this" means observed, not
/// claimed.
fn captured_inputs() -> Vec<serde_json::Value> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/captured_inputs");
    let mut out = vec![
        serde_json::to_value(platform_input("team-a/report.csv")).expect("OpaInput serializes"),
    ];
    for entry in std::fs::read_dir(&dir).unwrap_or_else(|e| {
        panic!("no captured corpus at {dir:?} ({e}); see tests/golden_capture.rs")
    }) {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        out.push(
            serde_json::from_str(&std::fs::read_to_string(&path).expect("read"))
                .unwrap_or_else(|e| panic!("{path:?} is not JSON: {e}")),
        );
    }
    assert!(out.len() > 1, "the captured corpus is empty");
    out
}

/// A real `OpaInput`, built through s0's own types, for the captured bundle's
/// `sa:pipeline` grant on `acme-prod` / `warehouse`.
fn platform_input(object: &str) -> s0::authz::OpaInput {
    use s0::authz::{Backend, OpaInput, Principal, PrincipalAttributes, RequestMeta};
    use s0::model::{Action, BackendKind, PrincipalType};

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
        organization_id: PLATFORM_BUNDLE_ORG.into(),
        action: Action::ReadObjects,
        bucket: "warehouse".into(),
        object: Some(object.into()),
        prefix: None,
        copy_source: None,
        delete_keys: None,
        object_tags: None,
        config_kind: None,
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

// ── helpers ────────────────────────────────────────────────────────────────────

fn drifted(file: &str, what: &str, pinned: &str, found: &str) -> String {
    format!(
        "\nCROSS-REPO CONTRACT DRIFT\n\
         \x20 repo    {OTHER_REPO}\n\
         \x20 file    {file}\n\
         \x20 item    {what}\n\
         \x20 pinned  {pinned:?}   (tests/cross_repo_contract.rs, mod `platform`)\n\
         \x20 found   {found:?}\n\n\
         The platform moved and s0 did not. Change s0 to match, then update the pin — \
         updating the pin alone will make the always-on tests in this same file fail, \
         which is the point.\n"
    )
}

/// Locate the sibling checkout. `None` ⇒ skip, loudly.
fn hyperfluid_repo(checking: &str) -> Option<PathBuf> {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // An explicit `HYPERFLUID_REPO` is authoritative: if someone says where the platform
    // is, silently verifying a *different* checkout found by the sibling walk would be
    // worse than not verifying at all.
    let candidates: Vec<PathBuf> = match std::env::var("HYPERFLUID_REPO") {
        Ok(explicit) => vec![PathBuf::from(explicit)],
        Err(_) => {
            let mut v = Vec::new();
            let mut dir = manifest.as_path();
            while let Some(parent) = dir.parent() {
                v.push(parent.join("hyperfluid"));
                dir = parent;
            }
            v
        }
    };
    for c in &candidates {
        if c.join(hf_path::RULES_REGO).is_file() {
            return Some(c.clone());
        }
    }

    let required = std::env::var("S0_REQUIRE_HYPERFLUID").is_ok_and(|v| v != "0");
    let looked = candidates
        .iter()
        .map(|c| format!("      {}", c.display()))
        .collect::<Vec<_>>()
        .join("\n");
    let message = format!(
        "cross-repo contract NOT VERIFIED against {OTHER_REPO} — {checking}\n\
         \x20   looked for {} under:\n{looked}\n\
         \x20   set HYPERFLUID_REPO=/path/to/hyperfluid to point at a checkout;\n\
         \x20   set S0_REQUIRE_HYPERFLUID=1 to make this a hard failure (any pipeline \
         that has both checkouts MUST set it).\n\
         \x20   The pins in `mod platform` are still enforced against s0 by the \
         always-on tests in this file.",
        hf_path::RULES_REGO,
    );
    assert!(!required, "S0_REQUIRE_HYPERFLUID is set: {message}");
    eprintln!("\n!!! SKIPPED: {message}\n");
    None
}

fn read(repo: &Path, rel: &str) -> String {
    let p = repo.join(rel);
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!(
            "cannot read {} from {OTHER_REPO} at {}: {e}\n\
             The file the contract is pinned against has moved or been deleted; s0's \
             {} may now be talking to nothing.",
            rel,
            p.display(),
            if rel.ends_with(".rego") {
                "decision entrypoint"
            } else {
                "audit labels"
            }
        )
    })
}

/// The `package …` line of a rego module, ignoring the comment header.
fn rego_package(src: &str) -> Option<String> {
    src.lines()
        .map(str::trim)
        .find(|l| l.starts_with("package "))
        .map(|l| l["package ".len()..].trim().to_string())
}

/// `pub const NAME: &str = "value";` → `value`.
fn rust_str_const(src: &str, name: &str) -> Option<String> {
    let needle = format!("const {name}:");
    let at = src.find(&needle)?;
    str_literal_after(&src[at..], "=")
}

/// The `impl DecisionLogMetadataExtractor` block for the S3 gateway extractor.
fn s3_gateway_extractor(src: &str) -> Option<&str> {
    let start =
        src.find("impl DecisionLogMetadataExtractor for S3GatewayDecisionLogMetadataExtractor")?;
    let rest = &src[start..];
    // The impl block ends at the first `}` in column 0.
    let end = rest.find("\n}\n").map(|i| i + 3).unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The body of `fn <name>` inside an already-narrowed block, up to the next `fn ` or
/// the end.
fn fn_body<'a>(block: &'a str, name: &str) -> Option<&'a str> {
    let at = block.find(&format!("fn {name}("))?;
    let rest = &block[at..];
    let end = rest[1..]
        .find("\n    fn ")
        .map(|i| i + 1)
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// The first double-quoted string literal appearing after `needle`.
fn str_literal_after(hay: &str, needle: &str) -> Option<String> {
    let at = hay.find(needle)? + needle.len();
    let rest = &hay[at..];
    let open = rest.find('"')?;
    let after = &rest[open + 1..];
    let close = after.find('"')?;
    Some(after[..close].to_string())
}

/// The labels a real decision record carries, built through the production
/// constructor so this test cannot pass on constants nobody uses.
fn sample_record_labels() -> std::collections::BTreeMap<String, String> {
    sample_decision_record().labels
}

/// A real decision record, built through the production constructor.
fn sample_decision_record() -> s0::audit::AuditRecord {
    use s0::audit::{AuditRecord, BackendOutcome, GatewayMeta, Outcome};
    use s0::authz::{Backend, Decision, OpaInput, Principal, PrincipalAttributes, RequestMeta};
    use s0::model::{Action, BackendKind, PrincipalType};

    let input = OpaInput {
        principal: Principal {
            sub: "alice".into(),
            kind: PrincipalType::User,
            attributes: PrincipalAttributes::default(),
        },
        backend: Backend {
            id: "backend-1".into(),
            kind: BackendKind::Ceph,
        },
        tenant: "acme".into(),
        organization_id: "3f8e2c1a-9d4b-4f6e-8a2d-7c5b9e0f1a2b".into(),
        action: Action::ReadObjects,
        bucket: "reports".into(),
        object: Some("2024/q1.csv".into()),
        prefix: None,
        copy_source: None,
        delete_keys: None,
        object_tags: None,
        config_kind: None,
        requested_tags: None,
        acl_grants: vec![],
        bypass_governance: false,
        request: RequestMeta::default(),
    };
    AuditRecord::new(
        "dec-contract".into(),
        "2026-07-28T00:00:00Z".into(),
        input,
        Decision::allow("grant matched"),
        GatewayMeta {
            backend_id: "backend-1".into(),
            backend_kind: "ceph".into(),
            outcome: Outcome::Allowed,
            denied_keys: vec![],
            backend: BackendOutcome::NotAttempted,
            backend_status: None,
        },
    )
}
